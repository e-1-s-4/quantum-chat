"""Tests for Quantum Chat v4.1 enhancements, hardening, and UI contracts."""

from __future__ import annotations

import asyncio
import json
import re
import uuid

import pytest

import chat as chat_module
from chat import (
    VERSION,
    QuantumNode,
    SignalingServer,
    canonical_json,
    pad_plaintext,
    safe_filename,
)


def make_node(tmp_path, name, **kwargs):
    node = QuantumNode(
        str(tmp_path / f"{name}.db"),
        "ws://127.0.0.1:65535",
        direct_url=None,
        enable_direct=False,
        **kwargs,
    )
    node.allow_remote_ui = False
    return node


def befriend(a, b):
    a.db.add_friend(b.public_key, "peer")
    b.db.add_friend(a.public_key, "peer")


def link(*nodes):
    by_key = {}
    for node in nodes:
        by_key.setdefault(node.public_key, []).append(node)

    for node in nodes:
        async def send_relay(peer_pubkey, payload, queue_on_failure=False, ephemeral=False, _self=node):
            targets = [t for t in by_key.get(peer_pubkey, []) if t is not _self]
            for target in targets:
                await target.handle_relay_payload(_self.public_key, payload)

        node.send_relay = send_relay


@pytest.fixture
def pair(tmp_path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    befriend(alice, bob)
    link(alice, bob)
    try:
        yield alice, bob
    finally:
        alice.db.close()
        bob.db.close()


# ─── Filename & payload validation hardening ─────────────────────────────────


def test_safe_filename_strips_control_characters():
    assert safe_filename("re\x00port\n\t.pdf") == "report.pdf"
    assert safe_filename("\x1b[31mevil\x7f.txt") == "[31mevil.txt"
    assert safe_filename("\x00\x01\r\n") == "download.bin"


def test_handle_chat_validates_msg_id_without_burning_counter(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    counter = alice.db.next_send_counter(bob.public_key)
    session_key = alice.sessions[bob.public_key]

    bad_payload = {
        "msg_id": "not-a-uuid",
        "from": alice.public_key,
        "to": bob.public_key,
        "counter": counter,
    }
    bad_key = alice.crypto.derive_message_key(
        session_key, alice.public_key, bob.public_key, counter, "chat"
    )
    bad_packet = alice.crypto.encrypt(
        bad_key, pad_plaintext(b"hello"), canonical_json(bad_payload)
    )
    with pytest.raises(ValueError, match="UUID"):
        asyncio.run(bob.handle_chat(alice.public_key, {"kind": "chat", "payload": bad_payload, "packet": bad_packet}))

    # Counter must still be unused so a valid retransmission succeeds.
    good_id = str(uuid.uuid4())
    good_payload = {
        "msg_id": good_id,
        "from": alice.public_key,
        "to": bob.public_key,
        "counter": counter,
    }
    good_packet = alice.crypto.encrypt(
        bad_key, pad_plaintext(b"valid after reject"), canonical_json(good_payload)
    )
    asyncio.run(bob.handle_chat(alice.public_key, {"kind": "chat", "payload": good_payload, "packet": good_packet}))
    assert any(m["msg_id"] == good_id for m in bob.db.recent_messages())


def test_handle_group_chat_validates_ids_and_group_invite_enforces_key_length(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    gid = str(uuid.uuid4())
    for n in (alice, bob):
        n.db.create_group(gid, "Team", alice.public_key)
        n.db.add_group_member(gid, alice.public_key, role="owner")
        n.db.add_group_member(gid, bob.public_key)
        n.db.save_group_key(gid, 1, b"k" * 32, alice.public_key)

    meta = {
        "msg_id": "non-uuid-msg-id",
        "from": alice.public_key,
        "group_id": gid,
        "epoch": 1,
        "sent_at": 1700000000,
    }
    packet = alice.crypto.encrypt(b"k" * 32, pad_plaintext(b"hi"), canonical_json(meta))
    frame = alice.signed_payload("group_chat", {"meta": meta, "packet": packet})
    with pytest.raises(ValueError, match="UUID"):
        asyncio.run(bob.handle_group_chat(alice.public_key, frame))

    # Group invite with non-32-byte key must be rejected before saving.
    gid2 = str(uuid.uuid4())
    bad_invite = {
        "group_id": gid2,
        "name": "Bad Key",
        "members": [alice.public_key, bob.public_key],
        "from": alice.public_key,
        "to": bob.public_key,
        "epoch": 1,
    }
    with pytest.raises(ValueError, match="key length"):
        asyncio.run(alice.send_group_invite(bob.public_key, bad_invite, b"short"))


def test_device_sync_validates_reaction_and_read_local(pair):
    alice, _ = pair
    bad_reaction = alice.signed_payload("device_sync", {
        "packet": alice.crypto.encrypt(
            alice.crypto.derive_device_sync_key(alice.secret_key),
            canonical_json({"event": "reaction", "data": {
                "msg_id": "m1", "peer": "bad-key", "emoji": "👍", "action": "add",
            }}),
        )
    })
    with pytest.raises(ValueError):
        asyncio.run(alice._handle_device_sync(alice.public_key, bad_reaction))

    bad_action = alice.signed_payload("device_sync", {
        "packet": alice.crypto.encrypt(
            alice.crypto.derive_device_sync_key(alice.secret_key),
            canonical_json({"event": "reaction", "data": {
                "msg_id": "m1", "peer": alice.public_key, "emoji": "👍", "action": "nuke",
            }}),
        )
    })
    with pytest.raises(ValueError, match="add.*remove"):
        asyncio.run(alice._handle_device_sync(alice.public_key, bad_action))

    bad_read_local = alice.signed_payload("device_sync", {
        "packet": alice.crypto.encrypt(
            alice.crypto.derive_device_sync_key(alice.secret_key),
            canonical_json({"event": "read_local", "data": {"peer_pubkey": "not-a-key"}}),
        )
    })
    with pytest.raises(ValueError):
        asyncio.run(alice._handle_device_sync(alice.public_key, bad_read_local))


# ─── Outbox & fan-out resilience ─────────────────────────────────────────────


def test_flush_outbox_isolates_failures_across_peers(tmp_path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    carol = make_node(tmp_path, "carol")
    try:
        alice.db.queue_outbox(bob.public_key, {"type": "relay", "to": bob.public_key, "payload": {"id": 1}})
        alice.db.queue_outbox(carol.public_key, {"type": "relay", "to": carol.public_key, "payload": {"id": 2}})
        sent = []

        class FlakyWS:
            async def send(self, raw):
                msg = json.loads(raw)
                if msg["to"] == bob.public_key:
                    raise ConnectionError("boom")
                sent.append(msg["to"])

        alice.signaling_ws = FlakyWS()
        asyncio.run(alice._handle_signaling_message({
            "type": "peers",
            "peers": {bob.public_key: {}, carol.public_key: {}},
        }))
        assert sent == [carol.public_key]
        assert len(alice.db.queued_outbox(bob.public_key)) == 1
        assert len(alice.db.queued_outbox(carol.public_key)) == 0
    finally:
        asyncio.run(alice.close())
        bob.db.close()
        carol.db.close()


def test_delete_everywhere_group_fanout_is_concurrent_and_isolated(tmp_path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    carol = make_node(tmp_path, "carol")
    try:
        befriend(alice, bob)
        befriend(alice, carol)
        gid = str(uuid.uuid4())
        alice.db.create_group(gid, "Team", alice.public_key)
        alice.db.add_group_member(gid, bob.public_key)
        alice.db.add_group_member(gid, carol.public_key)
        alice.db.save_group_key(gid, 1, b"g" * 32, alice.public_key)
        msg_id = str(uuid.uuid4())
        alice.db.save_message(msg_id, alice.public_key, "secret", "out", group_id=gid)

        delivered = []

        async def stub_relay(peer_pubkey, payload, queue_on_failure=False, ephemeral=False):
            if peer_pubkey == bob.public_key:
                raise RuntimeError("bob stalled")
            delivered.append(peer_pubkey)

        alice.send_relay = stub_relay
        asyncio.run(alice.send_message_delete_everywhere(msg_id))
        assert carol.public_key in delivered
        assert bob.public_key not in delivered
        assert alice.db.get_message(msg_id)["deleted_at"] is not None
    finally:
        alice.db.close()
        bob.db.close()
        carol.db.close()


# ─── Multi-device SignalingServer metadata & status ──────────────────────────


def test_signaling_server_multi_device_meta_preserves_direct_url_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "relay.db"))
    srv = SignalingServer()
    try:
        pk = "a" * (srv.crypto.sign_public_key_bytes * 2)
        ws1 = object()
        ws2 = object()
        srv.clients[pk] = {ws1, ws2}
        srv.socket_meta[ws1] = {"relay_alias": "a" * 64, "direct_url": "ws://127.0.0.1:4100"}
        srv.socket_meta[ws2] = {"relay_alias": "a" * 64, "direct_url": None}

        # Second device without direct_url must not erase first device's direct_url.
        srv._refresh_peer_meta(pk)
        assert srv.peer_meta[pk]["direct_url"] == "ws://127.0.0.1:4100"

        # Removing device 1 should recompute peer_meta so stale direct_url vanishes.
        srv.clients[pk].discard(ws1)
        srv.socket_meta.pop(ws1, None)
        srv._refresh_peer_meta(pk)
        assert srv.peer_meta[pk]["direct_url"] is None

        # Removing last device removes peer_meta entry.
        srv.clients[pk].discard(ws2)
        srv.socket_meta.pop(ws2, None)
        srv._refresh_peer_meta(pk)
        assert pk not in srv.peer_meta
    finally:
        srv.close()


def test_state_payload_reports_signaling_connected_and_cli_version(tmp_path, capsys):
    node = make_node(tmp_path, "status")
    try:
        assert node.state_payload()["signaling_connected"] is False
        node.signaling_ws = object()
        assert node.state_payload()["signaling_connected"] is True
    finally:
        node.db.close()

    with pytest.raises(SystemExit) as exc:
        chat_module.parse_args(["--version"])
    assert exc.value.code == 0
    assert VERSION in capsys.readouterr().out


# ─── Embedded HTML / CSS / JS UX & accessibility contracts ───────────────────


def test_embedded_ui_has_in_app_dialogs_accessibility_and_responsive_fixes():
    html = chat_module.HTML

    # Native blocking browser dialogs must never be used in embedded UI JS.
    script = html.split("<script>", 1)[1]
    assert not re.search(r"\b(?:window\.)?(?:alert|confirm|prompt)\s*\(", script)

    # Custom modal dialogs & safety comparison exist.
    for modal_id in ("confirmModal", "promptModal", "safetyModal", "scrollBottomBtn", "searchAllScope"):
        assert f'id="{modal_id}"' in html

    # Accessibility improvements on previously non-button interactive controls.
    assert 'id="idCard" role="button" tabindex="0" aria-expanded="false"' in html
    assert '<button type="button" class="reply-quote"' in html
    assert '<button type="button" class="reaction-chip' in html

    # Multi-line newline preservation & mediaRecorder cleanup.
    assert ".msg-text" in html
    assert "white-space: pre-wrap" in html
    assert "mediaRecorder === recorder" in script

    # Mobile responsive rule no longer flips .unread-badge to block or collapses sidebar at 640px.
    mobile_section = html.split("@media (max-width: 720px)", 1)[1]
    assert ".unread-badge { display: flex; }" in mobile_section
    assert ".unread-badge { display: block; }" not in html
    assert "Rekey session" in html
    assert "signaling_status" in html
