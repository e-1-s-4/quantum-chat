#!/usr/bin/env python3
"""Two-node demo driver for Quantum Chat v4.

Starts one signaling server and two nodes (Alice, Bob), performs the full
friend/session handshake over the real relay path, then exchanges a
conversation that exercises the new v4 features: replies with quotes, an
edit, a delete-for-everyone, reactions, and a read receipt.

Stays running afterwards so a browser can connect to either node's UI.
"""
from __future__ import annotations

import asyncio
import json
import logging
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(ROOT))

import chat  # noqa: E402

logging.basicConfig(level=logging.WARNING, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

WORKDIR = ROOT / "scripts" / "demo"
WORKDIR.mkdir(parents=True, exist_ok=True)

PORTS = {
    "signaling": 28100,
    "alice_http": 28101, "alice_ui": 28102, "alice_direct": 28103,
    "bob_http": 28111, "bob_ui": 28112, "bob_direct": 28113,
}

nodes: dict[str, chat.QuantumNode] = {}
node_tasks: list[asyncio.Task] = []
server_task = None


async def wait_until(pred, timeout=15.0, what="condition"):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        await asyncio.sleep(0.25)
    raise TimeoutError(f"Timed out waiting for {what}")


async def run_node(name, db_path, http_port, ui_port, direct_port):
    direct_url = f"ws://127.0.0.1:{direct_port}"
    node = chat.QuantumNode(
        db_path,
        f"ws://127.0.0.1:{PORTS['signaling']}",
        direct_url=direct_url,
        enable_direct=True,
    )
    node.allow_remote_ui = False
    chat.start_http(node, "127.0.0.1", http_port, ui_port, require_http_auth=False)
    node_tasks.extend([
        asyncio.create_task(chat.start_ui_ws(node, "127.0.0.1", ui_port)),
        asyncio.create_task(chat.start_direct_peer(node, "127.0.0.1", direct_port)),
        asyncio.create_task(node.connect_signaling_loop()),
    ])
    await wait_until(lambda: node.signaling_ws is not None, what=f"{name} signaling")
    nodes[name] = node
    return node


async def main() -> None:
    global server_task
    server_task = asyncio.create_task(chat.start_signaling("127.0.0.1", PORTS["signaling"]))
    await asyncio.sleep(0.5)
    print(f"[demo] signaling on :{PORTS['signaling']}")

    for f in WORKDIR.glob("*.db*"):
        f.unlink()

    alice = await run_node("alice", str(WORKDIR / "alice.db"),
                           PORTS["alice_http"], PORTS["alice_ui"], PORTS["alice_direct"])
    bob = await run_node("bob", str(WORKDIR / "bob.db"),
                         PORTS["bob_http"], PORTS["bob_ui"], PORTS["bob_direct"])
    print(f"[demo] alice {alice.public_key[:16]}…  bob {bob.public_key[:16]}…")

    # Nickname each other for a friendlier UI
    alice.db.add_friend(bob.public_key, "Bob")
    bob.db.add_friend(alice.public_key, "Alice")
    await alice.broadcast_ui({"type": "friends", "friends": alice.db.get_friends()})
    await bob.broadcast_ui({"type": "friends", "friends": bob.db.get_friends()})

    # Session handshake over the real relay
    await alice.connect_peer(bob.public_key)
    await wait_until(lambda: bob.public_key in alice.sessions and alice.public_key in bob.sessions,
                     what="session establishment")
    print("[demo] session established")

    # Seed a conversation that shows off v4 features
    await bob.send_chat(alice.public_key, "Hey! This chat is looking sharp today ⚛")
    await wait_until(lambda: any("looking sharp" in m["body"] for m in alice.db.recent_messages()),
                     what="opener delivery")

    reply_target = None
    for m in alice.db.recent_messages():
        if "looking sharp" in m["body"]:
            reply_target = m["msg_id"]
            break

    # Alice replies (quotes Bob's message)
    await alice.send_chat(bob.public_key, "Right? The new dark-glass theme is so much easier on the eyes 😎",
                          reply_to=reply_target)
    await wait_until(lambda: any(m.get("reply_to") == reply_target for m in bob.db.recent_messages()),
                     what="reply delivery")

    # Bob sends something Alice will later EDIT... no wait, edits are own-only.
    # Alice sends a message she then edits.
    await alice.send_chat(bob.public_key, "Lets ship v4 tomoorrow")
    edit_id = None
    await wait_until(lambda: any("tomoorrow" in m["body"] for m in bob.db.recent_messages()),
                     what="typo delivery")
    for m in alice.db.recent_messages():
        if "tomoorrow" in m["body"]:
            edit_id = m["msg_id"]
            break
    await alice.send_message_edit(edit_id, "Let's ship v4 tomorrow 🚀 (typo fixed)")
    await wait_until(lambda: any("typo fixed" in m["body"] and m.get("edited_at")
                                 for m in bob.db.recent_messages()),
                     what="edit delivery")

    # Bob replies to Alice's edited message
    bob_reply_target = None
    for m in bob.db.recent_messages():
        if "typo fixed" in m["body"]:
            bob_reply_target = m["msg_id"]
            break
    await bob.send_chat(alice.public_key, "Agreed — replies, edits and the new UI all feel great 👌",
                        reply_to=bob_reply_target)
    await wait_until(lambda: any(m.get("reply_to") == bob_reply_target for m in alice.db.recent_messages()),
                     what="bob reply delivery")

    # Alice deletes one of her messages for everyone
    await alice.send_chat(bob.public_key, "oops wrong window, deleting this one...")
    del_id = None
    await wait_until(lambda: any("wrong window" in m["body"] for m in bob.db.recent_messages()),
                     what="deletable delivery")
    for m in alice.db.recent_messages():
        if "wrong window" in m["body"]:
            del_id = m["msg_id"]
            break
    await alice.send_message_delete_everywhere(del_id)
    await wait_until(lambda: (bob.db.get_message(del_id) or {}).get("deleted_at") is not None,
                     what="tombstone delivery")

    # Reactions both ways
    react_id = bob_reply_target
    await bob.send_reaction(alice.public_key, react_id, "🔥", "add")
    await alice.send_reaction(bob.public_key, reply_target, "❤️", "add")

    # A few more plain messages so the timeline looks alive
    await bob.send_chat(alice.public_key, "BTW the hover toolbar with Reply / Edit / Delete is right above each bubble ↩")
    await alice.send_chat(bob.public_key, "Try ↑ in an empty composer to edit your last message, or Ctrl+F to search")

    # Verify final state
    a = alice.db.recent_messages()
    print(f"[demo] alice sees {len(a)} messages; "
          f"replies={sum(1 for m in a if m.get('reply_to'))}, "
          f"edited={sum(1 for m in a if m.get('edited_at'))}, "
          f"tombstones={sum(1 for m in a if m.get('deleted_at'))}")
    assert any(m.get("reply_to") for m in a), "alice should hold a reply"
    assert any(m.get("edited_at") for m in a), "alice should hold an edit"
    assert any(m.get("deleted_at") for m in a), "alice should hold a tombstone"

    print(json.dumps({
        "alice": {"http": f"http://127.0.0.1:{PORTS['alice_http']}/", "token": alice.ui_token},
        "bob": {"http": f"http://127.0.0.1:{PORTS['bob_http']}/", "token": bob.ui_token},
    }))
    sys.stdout.flush()

    # Keep both nodes alive for browser inspection
    try:
        while True:
            await asyncio.sleep(3600)
    except asyncio.CancelledError:
        pass
    finally:
        for t in node_tasks:
            t.cancel()
        if server_task:
            server_task.cancel()
        await asyncio.sleep(0.5)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
