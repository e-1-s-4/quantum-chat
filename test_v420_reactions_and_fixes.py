#!/usr/bin/env python3
"""v4.2.0 regression suite: bidirectional 1:1 & group reactions, live UI ids,
load_more cursor hardening, and --no-http-auth / --allow-iframe HTTP behavior."""

from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.resolve()))
import chat


async def _wait_until(pred, timeout: float = 10.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.05)
    return False


class _RecordingWS:
    def __init__(self) -> None:
        self.sent: list[dict] = []

    async def send(self, raw: str) -> None:
        self.sent.append(json.loads(raw))


async def _boot_node(workdir: Path, name: str, port_base: int, signaling_port: int):
    direct_url = f"ws://127.0.0.1:{port_base + 2}"
    node = chat.QuantumNode(
        str(workdir / f"{name}.db"),
        f"ws://127.0.0.1:{signaling_port}",
        direct_url=direct_url,
        enable_direct=True,
    )
    node.allow_remote_ui = False
    tasks = [
        asyncio.create_task(chat.start_direct_peer(node, "127.0.0.1", port_base + 2)),
        asyncio.create_task(node.connect_signaling_loop()),
    ]
    assert await _wait_until(lambda: node.signaling_ws is not None, timeout=10.0)
    return node, tasks


async def _stop_nodes(nodes, tasks, signaling_task):
    for n in nodes:
        n._shutting_down = True
    for t in [*tasks, signaling_task]:
        t.cancel()
    await asyncio.gather(*tasks, signaling_task, return_exceptions=True)
    for n in nodes:
        await n.close_direct_pool()
        n.db.close()


def test_bidirectional_1on1_and_group_reactions():
    async def run():
        with tempfile.TemporaryDirectory() as tmp:
            workdir = Path(tmp)
            sig_port = 28500
            sig_task = asyncio.create_task(chat.start_signaling("127.0.0.1", sig_port))
            await asyncio.sleep(0.3)

            alice, a_tasks = await _boot_node(workdir, "alice", 28510, sig_port)
            bob, b_tasks = await _boot_node(workdir, "bob", 28520, sig_port)
            carol, c_tasks = await _boot_node(workdir, "carol", 28530, sig_port)
            nodes = [alice, bob, carol]
            tasks = [*a_tasks, *b_tasks, *c_tasks]

            try:
                # Mesh friendships across Alice, Bob, Carol
                alice.db.add_friend(bob.public_key, "Bob")
                alice.db.add_friend(carol.public_key, "Carol")
                bob.db.add_friend(alice.public_key, "Alice")
                bob.db.add_friend(carol.public_key, "Carol")
                carol.db.add_friend(alice.public_key, "Alice")
                carol.db.add_friend(bob.public_key, "Bob")

                # Establish pairwise sessions
                await alice.connect_peer(bob.public_key)
                await alice.connect_peer(carol.public_key)
                await bob.connect_peer(carol.public_key)
                assert await _wait_until(
                    lambda: bob.public_key in alice.sessions
                    and alice.public_key in bob.sessions
                    and carol.public_key in alice.sessions
                    and alice.public_key in carol.sessions
                    and carol.public_key in bob.sessions
                    and bob.public_key in carol.sessions
                )

                # Attach dummy UI websocket to Alice to verify live broadcast DB id
                alice_ui_ws = _RecordingWS()
                alice.ui_clients.add(alice_ui_ws)

                # 1:1 Messages both ways
                await alice.send_chat(bob.public_key, "Alice to Bob M1")
                assert await _wait_until(
                    lambda: any(m["body"] == "Alice to Bob M1" for m in bob.db.recent_messages())
                )
                m1 = next(m for m in alice.db.recent_messages() if m["body"] == "Alice to Bob M1")

                # Live UI broadcast for M1 must include numeric DB row id
                msg_events = [e for e in alice_ui_ws.sent if e.get("type") == "message"]
                assert msg_events and isinstance(msg_events[-1]["message"].get("id"), int)
                assert msg_events[-1]["message"]["id"] == alice.db.get_message_row_id(m1["msg_id"])
                assert msg_events[-1]["message"]["id"] > 0

                await bob.send_chat(alice.public_key, "Bob to Alice M2")
                assert await _wait_until(
                    lambda: any(m["body"] == "Bob to Alice M2" for m in alice.db.recent_messages())
                )
                m2 = next(m for m in bob.db.recent_messages() if m["body"] == "Bob to Alice M2")

                # Receiver Bob reacts to Alice's M1 AND Bob reacts to his own M2
                await bob.send_reaction(alice.public_key, m1["msg_id"], "👍", "add")
                await bob.send_reaction(alice.public_key, m2["msg_id"], "❤️", "add")
                # Sender Alice reacts to Bob's M2 AND Alice reacts to her own M1
                await alice.send_reaction(bob.public_key, m2["msg_id"], "🔥", "add")
                await alice.send_reaction(bob.public_key, m1["msg_id"], "😂", "add")

                assert await _wait_until(
                    lambda: len(alice.db.get_reactions([m1["msg_id"], m2["msg_id"]]).get(m1["msg_id"], [])) == 2
                    and len(bob.db.get_reactions([m1["msg_id"], m2["msg_id"]]).get(m1["msg_id"], [])) == 2
                    and len(alice.db.get_reactions([m1["msg_id"], m2["msg_id"]]).get(m2["msg_id"], [])) == 2
                    and len(bob.db.get_reactions([m1["msg_id"], m2["msg_id"]]).get(m2["msg_id"], [])) == 2
                )

                # Toggle removal works in both directions
                await bob.send_reaction(alice.public_key, m1["msg_id"], "👍", "remove")
                assert await _wait_until(
                    lambda: len(alice.db.get_reactions([m1["msg_id"]]).get(m1["msg_id"], [])) == 1
                )

                # 1:1 reaction to self public key is rejected
                with pytest.raises(ValueError, match="own public key"):
                    await alice.send_reaction(alice.public_key, m1["msg_id"], "👍", "add")

                # Group creation & fan-out reaction on OWN and PEER messages
                group_id = str(uuid.uuid4())
                alice.db.create_group(group_id, "PQ Trio", alice.public_key)
                alice.db.add_group_member(group_id, bob.public_key)
                alice.db.add_group_member(group_id, carol.public_key)
                gkey = b"k" * 32
                alice.db.save_group_key(group_id, 1, gkey, alice.public_key)
                for peer in (bob.public_key, carol.public_key):
                    await alice.send_group_invite(peer, {
                        "group_id": group_id,
                        "name": "PQ Trio",
                        "members": alice.db.group_members(group_id),
                        "from": alice.public_key,
                        "to": peer,
                        "epoch": 1,
                    }, gkey)

                assert await _wait_until(
                    lambda: any(g["group_id"] == group_id for g in bob.db.groups_for(bob.public_key))
                    and any(g["group_id"] == group_id for g in carol.db.groups_for(carol.public_key))
                )

                await alice.send_group_chat(group_id, "Group hello everyone!")
                assert await _wait_until(
                    lambda: any(m["body"] == "Group hello everyone!" for m in bob.db.recent_messages())
                    and any(m["body"] == "Group hello everyone!" for m in carol.db.recent_messages())
                )
                gm1 = next(m for m in alice.db.recent_messages() if m["body"] == "Group hello everyone!")

                # Sender Alice reacts to her own group message -> Bob and Carol both receive
                await alice.send_reaction(None, gm1["msg_id"], "👍", "add", group_id=group_id)
                # Receiver Bob reacts to Alice's group message -> Alice and Carol both receive
                await bob.send_reaction(None, gm1["msg_id"], "🔥", "add", group_id=group_id)

                assert await _wait_until(
                    lambda: len(alice.db.get_reactions([gm1["msg_id"]]).get(gm1["msg_id"], [])) == 2
                    and len(bob.db.get_reactions([gm1["msg_id"]]).get(gm1["msg_id"], [])) == 2
                    and len(carol.db.get_reactions([gm1["msg_id"]]).get(gm1["msg_id"], [])) == 2
                )

                # Reject applying a 1:1 reaction onto a group message
                bad_1on1 = bob.signed_payload("reaction", {
                    "from": bob.public_key,
                    "to": alice.public_key,
                    "msg_id": gm1["msg_id"],
                    "emoji": "❤️",
                    "action": "add",
                })
                with pytest.raises(ValueError, match="group message"):
                    await alice.handle_reaction(bob.public_key, bad_1on1)

                # Reject reaction from non-member group
                bad_grp = bob.signed_payload("reaction", {
                    "from": bob.public_key,
                    "to": alice.public_key,
                    "group_id": str(uuid.uuid4()),
                    "msg_id": gm1["msg_id"],
                    "emoji": "❤️",
                    "action": "add",
                })
                with pytest.raises(ValueError, match="unknown or non-member"):
                    await alice.handle_reaction(bob.public_key, bad_grp)

                # Reject reaction to tombstoned message
                await alice.send_message_delete_everywhere(m1["msg_id"])
                assert await _wait_until(
                    lambda: bool((bob.db.get_message(m1["msg_id"]) or {}).get("deleted_at"))
                )
                with pytest.raises(ValueError, match="deleted message"):
                    await alice.send_reaction(bob.public_key, m1["msg_id"], "👍", "add")

                # load_more_messages edge cases via _dispatch_ui
                ui_ws = _RecordingWS()
                await alice._dispatch_ui(ui_ws, {"type": "load_more_messages", "before_id": None})
                assert ui_ws.sent[-1] == {"type": "history", "messages": [], "has_more_messages": False}
                with pytest.raises(ValueError, match="Valid message cursor"):
                    await alice._dispatch_ui(ui_ws, {"type": "load_more_messages", "before_id": "abc"})
            finally:
                await _stop_nodes(nodes, tasks, sig_task)

    asyncio.run(run())


def test_http_no_auth_and_allow_iframe_flags():
    ns = chat.parse_args(["--allow-remote-ui", "--no-http-auth", "--allow-iframe",
                          "--with-signaling", "--signaling-port", "3002"])
    assert ns.allow_remote_ui is True
    assert ns.no_http_auth is True
    assert ns.allow_iframe is True
    assert ns.signaling_url == "ws://127.0.0.1:3002"
    ns_default = chat.parse_args([])
    assert ns_default.signaling_url == chat.DEFAULT_SIGNALING_URL

    with tempfile.TemporaryDirectory() as tmp:
        node = chat.QuantumNode(str(Path(tmp) / "http.db"), "ws://127.0.0.1:8765")
        node.allow_remote_ui = True
        httpd_preview = chat.start_http(
            node, "127.0.0.1", 0, 3001, require_http_auth=False, allow_iframe=True
        )
        port_preview = httpd_preview.server_address[1]
        httpd_strict = chat.start_http(
            node, "127.0.0.1", 0, 3001, require_http_auth=True, allow_iframe=False
        )
        port_strict = httpd_strict.server_address[1]
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port_preview}/") as resp:
                assert resp.status == 200
                hdrs = {k.lower(): v for k, v in resp.headers.items()}
                assert "x-frame-options" not in hdrs
                assert "frame-ancestors 'self' https: http:" in hdrs["content-security-policy"]

            with pytest.raises(urllib.error.HTTPError) as exc:
                urllib.request.urlopen(f"http://127.0.0.1:{port_strict}/")
            assert exc.value.code == 401

            with urllib.request.urlopen(
                f"http://127.0.0.1:{port_strict}/?token={node.ui_token}"
            ) as resp_strict:
                assert resp_strict.status == 200
                hdrs_strict = {k.lower(): v for k, v in resp_strict.headers.items()}
                assert hdrs_strict.get("x-frame-options") == "DENY"
                assert "frame-ancestors 'none'" in hdrs_strict["content-security-policy"]
        finally:
            httpd_preview.shutdown()
            httpd_preview.server_close()
            httpd_strict.shutdown()
            httpd_strict.server_close()
            node.db.close()


def test_ui_reaction_and_accessibility_contracts():
    html = chat.HTML
    # Bidirectional 1:1 & group reaction resolution
    assert "m.sender_pubkey === state.public_key" in html
    assert "state.groups.some(g => g.group_id === m.group_id)" in html
    assert "send({type:'reaction', group_id:m.group_id, msg_id, emoji, action});" in html
    assert "reaction-btn${reactMap[e]?.mine?' mine':''}" in html
    # Native button for sidebar conversations, group friend picker, draft restore on error
    assert "btn.className = 'friend-item'" in html
    assert 'id="groupFriendPicker"' in html
    assert 'id="addMemberSelect"' in html
    assert "pendingFailedDraft" in html
    assert "state.messages.filter(x => x.reply_to === d.msg_id)" in html


if __name__ == "__main__":
    test_bidirectional_1on1_and_group_reactions()
    test_http_no_auth_and_allow_iframe_flags()
    test_ui_reaction_and_accessibility_contracts()
    print("All v4.2.0 regression checks passed.")
