"""Feature and regression tests for the Quantum Chat v4.0.0 upgrade.

Covers the three headline features and their security posture:
- Message replies with quoted previews (1:1 and group), including hostile
  reply_to validation on the receive path
- Edit-any-of-your-own-messages over encrypted, counter-protected frames with
  monotonic edited_at (a replayed older edit can never roll a newer one back)
- Delete-for-everyone with authorship-checked signed frames and a tombstone
  that erases the plaintext body while keeping reply chains resolvable

Plus the platform work that shipped alongside: schema migration from v3.5
databases, the cached AES-GCM cipher object, the WebSocket bridge deadlock
fix, and the new UI protocol commands.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import secrets
import socket
import sqlite3
import threading
import time
import uuid

import pytest

import chat as chat_module
from chat import (
    SCHEMA_VERSION,
    Database,
    QuantumNode,
    canonical_json,
    validate_msg_id,
)

# ─── Shared helpers ──────────────────────────────────────────────────────────


def make_node(tmp_path, name, **kwargs):
    node = QuantumNode(str(tmp_path / f"{name}.db"), "ws://127.0.0.1:65535",
                       direct_url=None, enable_direct=False, **kwargs)
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
        def send_relay(peer_pubkey, payload, queue_on_failure=False, ephemeral=False, _self=node):
            targets = [t for t in by_key.get(peer_pubkey, []) if t is not _self]

            async def deliver():
                if not targets:
                    if ephemeral or queue_on_failure:
                        return
                    raise RuntimeError("Not connected to signaling server")
                for target in targets:
                    await target.handle_relay_payload(_self.public_key, payload)

            return deliver()

        node.send_relay = send_relay


@pytest.fixture()
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


@pytest.fixture()
def trio(tmp_path):
    alice = make_node(tmp_path, "alice")
    bob = make_node(tmp_path, "bob")
    carol = make_node(tmp_path, "carol")
    for a, b in ((alice, bob), (alice, carol), (bob, carol)):
        befriend(a, b)
    link(alice, bob, carol)
    try:
        yield alice, bob, carol
    finally:
        for n in (alice, bob, carol):
            n.db.close()


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, payload):
        self.sent.append(json.loads(payload))


def add_ui(node):
    ws = FakeWS()
    node.ui_clients.add(ws)
    return ws


def establish(alice, bob):
    asyncio.run(alice.connect_peer(bob.public_key))
    assert bob.public_key in alice.sessions
    assert alice.public_key in bob.sessions


def last_message(node):
    msgs = node.db.recent_messages()
    assert msgs, "expected at least one message"
    return msgs[-1]


def find_body(node, fragment):
    return next(m for m in node.db.recent_messages() if fragment in m["body"])


# ─── Reply references ────────────────────────────────────────────────────────


def test_reply_roundtrip_1_to_1(pair):
    alice, bob = pair
    establish(alice, bob)

    asyncio.run(alice.send_chat(bob.public_key, "root message"))
    root = find_body(bob, "root message")

    asyncio.run(bob.send_chat(alice.public_key, "a quoted reply", reply_to=root["msg_id"]))
    reply_on_alice = find_body(alice, "a quoted reply")
    assert reply_on_alice["reply_to"] == root["msg_id"]
    assert reply_on_alice["direction"] == "in"

    # The sender's own copy carries the reference too.
    reply_on_bob = find_body(bob, "a quoted reply")
    assert reply_on_bob["reply_to"] == root["msg_id"]
    assert reply_on_bob["direction"] == "out"


def test_reply_reference_survives_reload(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "to be quoted"))
    root = find_body(bob, "to be quoted")
    asyncio.run(bob.send_chat(alice.public_key, "quoting you", reply_to=root["msg_id"]))

    # Re-open the database file with the same master key and confirm the
    # reference persisted.
    db_path = bob.db.conn.execute("PRAGMA database_list").fetchall()[0][2]
    master_key = bob.local_master_key
    bob.db.close()
    db = Database(db_path, master_key=master_key)
    msgs = [m for m in db.recent_messages() if m["body"] == "quoting you"]
    assert msgs and msgs[0]["reply_to"] == root["msg_id"]
    db.close()


def test_send_reply_validates_target_exists(pair):
    alice, bob = pair
    establish(alice, bob)
    with pytest.raises(ValueError, match="not in local history"):
        asyncio.run(alice.send_chat(bob.public_key, "reply to nothing",
                                    reply_to=str(uuid.uuid4())))


def test_send_reply_validates_same_conversation(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    asyncio.run(alice.send_chat(bob.public_key, "private with bob"))
    root = find_body(alice, "private with bob")
    # Quoting a Bob message inside a chat with Carol must be refused.
    with pytest.raises(ValueError, match="different conversation"):
        asyncio.run(alice.send_chat(carol.public_key, "sneaky cross-quote",
                                    reply_to=root["msg_id"]))


def test_hostile_reply_reference_is_shape_checked(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "hello"))

    # Rebuild a chat frame carrying a malformed reply_to (not a UUID) —
    # the receiver must reject the whole frame rather than persist it.
    session_key = bob.sessions[alice.public_key]
    counter = alice.db.next_send_counter(bob.public_key)
    payload = {
        "msg_id": str(uuid.uuid4()), "from": alice.public_key,
        "to": bob.public_key, "group_id": None,
        "reply_to": "not-a-uuid-at-all", "counter": counter,
        "sent_at": chat_module.utc_ts(),
    }
    msg_key = alice.crypto.derive_message_key(
        session_key, alice.public_key, bob.public_key, counter, "chat"
    )
    packet = alice.crypto.encrypt(msg_key, chat_module.pad_plaintext(b"evil"), canonical_json(payload))
    with pytest.raises(ValueError):
        asyncio.run(bob.handle_relay_payload(alice.public_key,
                                             {"kind": "chat", "payload": payload, "packet": packet}))
    assert not any("evil" == m["body"] for m in bob.db.recent_messages())


def test_group_reply_roundtrip(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    establish(bob, carol)

    group_id = str(uuid.uuid4())
    for n in (alice, bob, carol):
        n.db.create_group(group_id, "v4 group", alice.public_key)
        n.db.add_group_member(group_id, n.public_key)
        for other in (alice, bob, carol):
            if other.public_key != n.public_key:
                n.db.add_group_member(group_id, other.public_key)
    key = b"g" * 32
    for n in (alice, bob, carol):
        n.db.save_group_key(group_id, 1, key, alice.public_key)

    asyncio.run(alice.send_group_chat(group_id, "group root"))
    root = find_body(bob, "group root")
    asyncio.run(bob.send_group_chat(group_id, "group reply", reply_to=root["msg_id"]))

    got = find_body(carol, "group reply")
    assert got["reply_to"] == root["msg_id"]
    assert got["group_id"] == group_id


def test_group_reply_target_must_be_in_same_group(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    group_id = str(uuid.uuid4())
    for n in (alice, bob, carol):
        n.db.create_group(group_id, "g", alice.public_key)
        n.db.add_group_member(group_id, n.public_key)
        for other in (alice, bob, carol):
            if other.public_key != n.public_key:
                n.db.add_group_member(group_id, other.public_key)
    key = b"g" * 32
    for n in (alice, bob, carol):
        n.db.save_group_key(group_id, 1, key, alice.public_key)
    asyncio.run(alice.send_group_chat(group_id, "group root"))

    # A 1:1 message cannot be quoted inside the group.
    asyncio.run(alice.send_chat(bob.public_key, "private note"))
    private = find_body(alice, "private note")
    with pytest.raises(ValueError):
        asyncio.run(alice.send_group_chat(group_id, "cross quote", reply_to=private["msg_id"]))


# ─── Message editing ─────────────────────────────────────────────────────────


def test_edit_roundtrip_1_to_1(pair):
    alice, bob = pair
    establish(alice, bob)
    ui_bob = add_ui(bob)
    asyncio.run(alice.send_chat(bob.public_key, "typo tomoorrow"))
    target = find_body(alice, "typo tomoorrow")

    asyncio.run(alice.send_message_edit(target["msg_id"], "typo tomorrow, fixed"))

    fixed_on_bob = find_body(bob, "typo tomorrow, fixed")
    assert fixed_on_bob["msg_id"] == target["msg_id"]
    assert fixed_on_bob["edited_at"] is not None
    fixed_on_alice = alice.db.get_message(target["msg_id"])
    assert fixed_on_alice["body"] == "typo tomorrow, fixed"
    assert any(f.get("type") == "message_edited" and f["msg_id"] == target["msg_id"]
               for f in ui_bob.sent)


def test_edit_is_owner_only(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "alice's words"))
    target = find_body(bob, "alice's words")
    with pytest.raises(ValueError, match="Only your own"):
        asyncio.run(bob.send_message_edit(target["msg_id"], "rewritten by bob"))


def test_edit_rejects_missing_and_empty(pair):
    alice, bob = pair
    establish(alice, bob)
    with pytest.raises(ValueError):
        asyncio.run(alice.send_message_edit(str(uuid.uuid4()), "ghost edit"))
    asyncio.run(alice.send_chat(bob.public_key, "editable"))
    target = find_body(alice, "editable")
    with pytest.raises(ValueError):
        asyncio.run(alice.send_message_edit(target["msg_id"], "   "))


def test_replayed_older_edit_cannot_roll_back_newer(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "v1"))
    target = find_body(alice, "v1")

    # Capture the first edit frame, apply it, then replay it after a newer
    # edit — the monotonic edited_at guard must keep the newest body.
    captured = {}
    original_send = alice.send_relay

    async def capture(peer, payload, queue_on_failure=False, ephemeral=False):
        if payload.get("kind") == "message_edit":
            captured["frame"] = payload
        return await original_send(peer, payload, queue_on_failure=queue_on_failure,
                                   ephemeral=ephemeral)

    alice.send_relay = capture
    asyncio.run(alice.send_message_edit(target["msg_id"], "v2"))
    old_frame = captured["frame"]
    assert find_body(bob, "v2")

    # Newer edit with a strictly later timestamp.
    time.sleep(0.01)
    asyncio.run(alice.send_message_edit(target["msg_id"], "v3"))
    assert find_body(bob, "v3")

    # Replay the older "v2" frame directly at Bob. The consumed counter must
    # reject it outright (duplicate detection); even a counter-bypassing
    # replay would still be refused by the monotonic edited_at guard.
    with pytest.raises(ValueError):
        asyncio.run(bob.handle_relay_payload(alice.public_key, old_frame))
    assert find_body(bob, "v3")
    assert not any(m["body"] == "v2" for m in bob.db.recent_messages())


def test_hostile_edit_for_foreign_message_is_rejected(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(bob.send_chat(alice.public_key, "bob's message"))
    target = find_body(alice, "bob's message")

    # Alice builds a well-formed edit frame but for a message Bob authored.
    session_key = alice.sessions[bob.public_key]
    counter = alice.db.next_send_counter(bob.public_key)
    payload = {
        "msg_id": target["msg_id"], "from": alice.public_key, "to": bob.public_key,
        "counter": counter, "edited_at": chat_module.utc_ts(),
    }
    msg_key = alice.crypto.derive_message_key(
        session_key, alice.public_key, bob.public_key, counter, "edit"
    )
    packet = alice.crypto.encrypt(msg_key, chat_module.pad_plaintext(b"hijacked"), canonical_json(payload))
    with pytest.raises(ValueError, match="not authored by the sender"):
        asyncio.run(bob.handle_relay_payload(alice.public_key,
                                             {"kind": "message_edit", "payload": payload, "packet": packet}))
    assert find_body(alice, "bob's message")["body"] == "bob's message"


def test_group_edit_roundtrip(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    establish(bob, carol)
    group_id = str(uuid.uuid4())
    for n in (alice, bob, carol):
        n.db.create_group(group_id, "g", alice.public_key)
        n.db.add_group_member(group_id, n.public_key)
        for other in (alice, bob, carol):
            if other.public_key != n.public_key:
                n.db.add_group_member(group_id, other.public_key)
    key = b"g" * 32
    for n in (alice, bob, carol):
        n.db.save_group_key(group_id, 1, key, alice.public_key)

    asyncio.run(alice.send_group_chat(group_id, "group typo"))
    target = find_body(carol, "group typo")
    asyncio.run(alice.send_message_edit(target["msg_id"], "group typo fixed"))

    assert find_body(bob, "group typo fixed")["edited_at"] is not None
    assert find_body(carol, "group typo fixed")["edited_at"] is not None


def test_group_edit_from_non_author_is_rejected(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    group_id = str(uuid.uuid4())
    for n in (alice, bob, carol):
        n.db.create_group(group_id, "g", alice.public_key)
        n.db.add_group_member(group_id, n.public_key)
        for other in (alice, bob, carol):
            if other.public_key != n.public_key:
                n.db.add_group_member(group_id, other.public_key)
    key = b"g" * 32
    for n in (alice, bob, carol):
        n.db.save_group_key(group_id, 1, key, alice.public_key)

    asyncio.run(alice.send_group_chat(group_id, "alice said this"))
    target = find_body(carol, "alice said this")

    # Bob signs an edit frame for Alice's message; Carol must reject it
    # because the stored author is Alice, not Bob.
    meta = {"msg_id": target["msg_id"], "from": bob.public_key, "group_id": group_id,
            "epoch": 1, "edited_at": chat_module.utc_ts()}
    packet = bob.crypto.encrypt(key, chat_module.pad_plaintext(b"bob rewrite"), canonical_json(meta))
    frame = bob.signed_payload("group_message_edit", {"meta": meta, "packet": packet})
    with pytest.raises(ValueError, match="not authored by the sender"):
        asyncio.run(carol.handle_relay_payload(bob.public_key, frame))
    assert find_body(carol, "alice said this")["body"] == "alice said this"


# ─── Delete-for-everyone ─────────────────────────────────────────────────────


def test_delete_for_everywhere_roundtrip(pair):
    alice, bob = pair
    establish(alice, bob)
    ui_bob = add_ui(bob)
    asyncio.run(alice.send_chat(bob.public_key, "regrettable message"))
    target = find_body(bob, "regrettable message")
    # A reaction riding on the message must disappear with the tombstone.
    asyncio.run(bob.send_reaction(alice.public_key, target["msg_id"], "🔥", "add"))
    assert bob.db.get_reactions([target["msg_id"]])[target["msg_id"]]

    asyncio.run(alice.send_message_delete_everywhere(target["msg_id"]))

    tomb_on_bob = bob.db.get_message(target["msg_id"])
    assert tomb_on_bob["deleted_at"] is not None
    assert tomb_on_bob["body"] == ""          # plaintext truly erased
    assert not bob.db.get_reactions([target["msg_id"]]).get(target["msg_id"])
    tomb_on_alice = alice.db.get_message(target["msg_id"])
    assert tomb_on_alice["deleted_at"] is not None
    assert any(f.get("type") == "message_tombstoned" and f["msg_id"] == target["msg_id"]
               for f in ui_bob.sent)


def test_tombstone_hydrates_cleanly_after_reload(pair):
    """The regression: a stale body_nonce over an erased body used to make
    every later hydration of the row raise InvalidTag, taking the whole
    state payload (and thus the UI) down with it."""
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "doomed"))
    target = find_body(bob, "doomed")
    asyncio.run(alice.send_message_delete_everywhere(target["msg_id"]))

    # Full hydration must not raise, and must report the tombstone fields.
    msgs = bob.db.recent_messages()
    tomb = next(m for m in msgs if m["msg_id"] == target["msg_id"])
    assert tomb["deleted_at"] is not None
    assert tomb["body"] == ""
    state = bob.state_payload()   # must not raise
    assert any(m["msg_id"] == target["msg_id"] and m.get("deleted_at")
               for m in state["messages"])


def test_delete_for_everywhere_is_owner_only(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "alice's to delete"))
    target = find_body(bob, "alice's to delete")
    with pytest.raises(ValueError, match="Only your own"):
        asyncio.run(bob.send_message_delete_everywhere(target["msg_id"]))


def test_hostile_delete_for_foreign_message_is_rejected(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(bob.send_chat(alice.public_key, "bob's permanent record"))
    target = find_body(alice, "bob's permanent record")

    # Alice signs a delete notice for a message Bob authored.
    frame = alice.signed_payload("message_delete", {
        "from": alice.public_key, "to": bob.public_key,
        "msg_id": target["msg_id"], "deleted_at": chat_module.utc_ts(),
    })
    with pytest.raises(ValueError, match="Only the message author"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, frame))
    assert find_body(bob, "bob's permanent record")["body"] == "bob's permanent record"


def test_unsigned_delete_notice_is_rejected(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "signed only"))
    target = find_body(bob, "signed only")
    with pytest.raises(ValueError, match="signature"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, {
            "kind": "message_delete",
            "payload": {"from": alice.public_key, "to": bob.public_key,
                        "msg_id": target["msg_id"], "deleted_at": chat_module.utc_ts()},
        }))


def test_delete_notice_for_unknown_message_is_accepted_as_noop(pair):
    alice, bob = pair
    establish(alice, bob)
    frame = alice.signed_payload("message_delete", {
        "from": alice.public_key, "to": bob.public_key,
        "msg_id": str(uuid.uuid4()), "deleted_at": chat_module.utc_ts(),
    })
    # Duplicate or out-of-window deliveries must not raise (they would force
    # pointless retries); there is simply nothing to tombstone.
    asyncio.run(bob.handle_relay_payload(alice.public_key, frame))


def test_tombstone_keeps_reply_chain_resolvable(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "will be deleted"))
    root = find_body(bob, "will be deleted")
    asyncio.run(bob.send_chat(alice.public_key, "quoting the doomed", reply_to=root["msg_id"]))
    asyncio.run(alice.send_message_delete_everywhere(root["msg_id"]))

    # The reply's reference still resolves to a row (rendered as a
    # placeholder by the UI) instead of dangling.
    reply = find_body(alice, "quoting the doomed")
    assert reply["reply_to"] == root["msg_id"]
    quoted = alice.db.get_message(root["msg_id"])
    assert quoted is not None and quoted["deleted_at"] is not None


# ─── Multi-device sync of the new events ─────────────────────────────────────


def test_device_sync_applies_edit_and_tombstone(tmp_path):
    alice = make_node(tmp_path, "alice")
    key = alice.crypto.derive_device_sync_key(alice.secret_key)
    alice.db.save_message("m1", alice.public_key, "original", "out",
                          recipient=alice.public_key, delivered=True, status="delivered")
    alice.db.save_message("m2", alice.public_key, "will vanish", "out",
                          recipient=alice.public_key, delivered=True, status="delivered")

    def sync_envelope(event, data):
        body = canonical_json({"event": event, "data": data})
        packet = alice.crypto.encrypt(key, body)
        return alice.signed_payload("device_sync", {"packet": packet})

    asyncio.run(alice._handle_device_sync(alice.public_key,
                 sync_envelope("message_edited", {"msg_id": "m1", "body": "corrected",
                                                  "edited_at": chat_module.utc_ts()})))
    assert alice.db.get_message("m1")["body"] == "corrected"

    asyncio.run(alice._handle_device_sync(alice.public_key,
                 sync_envelope("message_tombstoned", {"msg_id": "m2"})))
    gone = alice.db.get_message("m2")
    assert gone["deleted_at"] is not None and gone["body"] == ""


# ─── UI protocol commands ────────────────────────────────────────────────────


def test_ui_commands_edit_and_delete_everywhere(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "editable via ui"))
    target = find_body(alice, "editable via ui")

    asyncio.run(alice._dispatch_ui(FakeWS(), {
        "type": "edit_message", "msg_id": target["msg_id"], "text": "edited via ui",
    }))
    assert find_body(bob, "edited via ui")

    asyncio.run(alice._dispatch_ui(FakeWS(), {
        "type": "delete_message_everywhere", "msg_id": target["msg_id"],
    }))
    assert bob.db.get_message(target["msg_id"])["deleted_at"] is not None


def test_ui_send_message_carries_reply_to(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "ui reply root"))
    root = find_body(alice, "ui reply root")
    asyncio.run(alice._dispatch_ui(FakeWS(), {
        "type": "send_message", "pubkey": bob.public_key,
        "text": "the reply itself", "reply_to": root["msg_id"],
    }))
    got = find_body(bob, "the reply itself")
    assert got["reply_to"] == root["msg_id"]


# ─── Schema migration from v3.5 ──────────────────────────────────────────────


def test_schema_version_bumped():
    assert SCHEMA_VERSION == 6


def test_v35_database_migrates_additively(tmp_path):
    """A database written by v3.5 (no reply_to/edited_at/deleted_at columns)
    must open cleanly under v4, gain the new columns, and keep its rows."""
    db_path = str(tmp_path / "legacy.db")
    legacy = sqlite3.connect(db_path)
    legacy.executescript("""
        CREATE TABLE identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_key TEXT NOT NULL, secret_key BLOB NOT NULL,
            created_at INTEGER NOT NULL, secret_nonce BLOB,
            key_version INTEGER NOT NULL DEFAULT 0);
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            msg_id TEXT UNIQUE NOT NULL, sender_pubkey TEXT NOT NULL,
            recipient_pubkey TEXT, group_id TEXT, body TEXT NOT NULL,
            direction TEXT NOT NULL, timestamp INTEGER NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'sent', body_nonce BLOB,
            key_version INTEGER NOT NULL DEFAULT 0, read_at INTEGER);
    """)
    legacy.execute(
        "INSERT INTO messages (msg_id, sender_pubkey, body, direction, timestamp) "
        "VALUES ('legacy-1', 'aa', 'old plaintext', 'in', 12345)")
    legacy.commit()
    legacy.close()

    db = Database(db_path, master_key=None)
    cols = db._columns("messages")
    assert {"reply_to", "edited_at", "deleted_at"} <= cols
    msgs = db.recent_messages()
    assert msgs and msgs[0]["body"] == "old plaintext"
    assert msgs[0].get("reply_to") is None
    db.close()


# ─── validate_msg_id ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad", ["", "   ", "not-a-uuid", "x" * 200, "GGGGGGGG-1111-1111-1111-111111111111", None])
def test_validate_msg_id_rejects_garbage(bad):
    with pytest.raises(ValueError):
        validate_msg_id(bad)


def test_validate_msg_id_normalizes_hex_case():
    # Canonical ids are lowercase UUIDs; validate_msg_id is strict-shape.
    value = str(uuid.uuid4())
    assert validate_msg_id(value) == value
    with pytest.raises(ValueError):
        validate_msg_id(value.upper())


# ─── Cached AES-GCM cipher ───────────────────────────────────────────────────


def test_aead_object_is_cached_and_correct(tmp_path):
    master = secrets.token_bytes(32)
    db = Database(str(tmp_path / "cache.db"), master_key=master)
    first = db._aead()
    second = db._aead()
    assert first is second, "AESGCM construction should be cached per Database"
    for i in range(200):
        db.save_message(f"m{i}", "ab" * 32, f"body {i}", "in", recipient="cd" * 32)
    msgs = db.recent_messages(limit=500)
    assert len(msgs) == 200
    assert msgs[0]["body"] == "body 0"
    db.close()

    # A second Database over the same file (fresh cache) still decrypts.
    db2 = Database(str(tmp_path / "cache.db"), master_key=master)
    assert db2.recent_messages(limit=500)[0]["body"] == "body 0"
    db2.close()


def test_hydration_batch_is_fast(tmp_path):
    """Functional smoke for the cached-cipher fast path: a history an order
    of magnitude larger than a UI page hydrates without issue."""
    master = secrets.token_bytes(32)
    db = Database(str(tmp_path / "big.db"), master_key=master)
    for i in range(2000):
        db.save_message(f"m{i}", "ab" * 32, f"message number {i}", "in", recipient="cd" * 32)
    msgs = db.recent_messages(limit=2000)
    assert len(msgs) == 2000
    db.close()


# ─── WebSocket bridge deadlock regression ────────────────────────────────────


def test_http_to_ui_ws_bridge_completes_handshake(tmp_path):
    """The bridge used to deadlock on its rfile.peek(): peek issues a raw
    read when the buffer is empty, and a WebSocket client sends nothing
    until it sees the 101, so the opening handshake never completed and the
    browser only survived by failing over to the direct UI port."""
    import websockets

    node = QuantumNode(str(tmp_path / "bridge.db"), "ws://127.0.0.1:65535",
                       direct_url=None, enable_direct=False)
    node.allow_remote_ui = False
    httpd = chat_module.start_http(node, "127.0.0.1", 0, 0, require_http_auth=False)
    http_port = httpd.server_address[1]
    ui_port = http_port + 1
    httpd.ui_ws_port = ui_port

    # Stand up a minimal WS backend that just holds connections open.
    async def backend():
        async def hold(ws):
            try:
                await ws.recv()
            except Exception:
                pass
        async with websockets.serve(hold, "127.0.0.1", ui_port):
            await asyncio.Future()

    threading.Thread(target=lambda: asyncio.run(backend()), daemon=True).start()
    time.sleep(0.4)

    async def probe():
        # The opening handshake must complete promptly; the old deadlock
        # hung here until the client's own timeout gave up.
        async with websockets.connect(
                f"ws://127.0.0.1:{http_port}/?token={node.ui_token}",
                open_timeout=3) as ws:
            await ws.send(json.dumps({"type": "refresh"}))
            return True

    try:
        loop = asyncio.new_event_loop()
        try:
            assert loop.run_until_complete(asyncio.wait_for(probe(), timeout=6))
        finally:
            loop.close()
    finally:
        httpd.shutdown()
        httpd.server_close()
        node.db.close()


# ─── UI HTML sanity for the v4 features ──────────────────────────────────────


def test_ui_html_contains_v4_affordances():
    html = chat_module.HTML
    assert "composerContext" in html, "reply/edit context bar must exist"
    assert "startReply" in html and "startEdit" in html
    assert "cancelComposerContext" in html
    assert "deleteMessageEverywhereUi" in html
    assert "appendMessageLive" in html, "incremental render fast path must exist"
    assert "message_edited" in html and "message_tombstoned" in html
    assert "reply-quote" in html, "quoted preview styling must exist"
    assert "tombstone" in html
    assert "edited-label" in html


def test_ui_state_messages_expose_new_fields(pair):
    alice, bob = pair
    establish(alice, bob)
    asyncio.run(alice.send_chat(bob.public_key, "field probe"))
    state = bob.state_payload()
    msg = next(m for m in state["messages"] if m["body"] == "field probe")
    assert "reply_to" in msg and "edited_at" in msg and "deleted_at" in msg


# ─── Audit & hardening regressions ───────────────────────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_http_to_ui_ws_bridge_transfers_large_frames(tmp_path):
    """Bridged WebSockets run on non-blocking sockets and must handle partial
    writes (BlockingIOError) cleanly for large payloads >256 KB."""
    websockets = chat_module.require_websockets()
    http_port = _free_port()
    ui_port = _free_port()
    node = chat_module.QuantumNode(
        str(tmp_path / "large_bridge.db"), "ws://127.0.0.1:1", enable_direct=False
    )
    httpd = chat_module.start_http(
        node, "127.0.0.1", http_port, ui_ws_port=ui_port, require_http_auth=False
    )

    async def backend():
        async def echo(ws):
            try:
                async for msg in ws:
                    await ws.send(msg)
            except Exception:
                pass
        async with websockets.serve(echo, "127.0.0.1", ui_port, max_size=2 * 1024 * 1024):
            await asyncio.Future()

    threading.Thread(target=lambda: asyncio.run(backend()), daemon=True).start()
    time.sleep(0.4)

    big_payload = "Q" * (600 * 1024)

    async def probe():
        async with websockets.connect(
            f"ws://127.0.0.1:{http_port}/?token={node.ui_token}",
            open_timeout=5, max_size=2 * 1024 * 1024,
        ) as ws:
            await ws.send(big_payload)
            got = await asyncio.wait_for(ws.recv(), timeout=5)
            return got == big_payload

    try:
        loop = asyncio.new_event_loop()
        try:
            assert loop.run_until_complete(probe()) is True
        finally:
            loop.close()
    finally:
        node._shutting_down = True
        httpd.shutdown()
        httpd.server_close()
        node.db.close()


def test_cross_context_edits_are_rejected(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)

    group_a = str(uuid.uuid4())
    group_b = str(uuid.uuid4())
    key_a = b"a" * 32
    key_b = b"b" * 32
    for gid, k in ((group_a, key_a), (group_b, key_b)):
        for n in (alice, bob, carol):
            n.db.create_group(gid, f"grp-{gid[:4]}", alice.public_key)
            n.db.add_group_member(gid, alice.public_key)
            n.db.add_group_member(gid, bob.public_key)
            n.db.add_group_member(gid, carol.public_key)
            n.db.save_group_key(gid, 1, k, alice.public_key)

    asyncio.run(alice.send_group_chat(group_a, "in group a"))
    grp_msg = find_body(bob, "in group a")

    # 1. Trying to edit a group message over a 1:1 session must be rejected.
    session_key = alice.sessions[bob.public_key]
    counter = alice.db.next_send_counter(bob.public_key)
    payload = {
        "msg_id": grp_msg["msg_id"], "from": alice.public_key, "to": bob.public_key,
        "counter": counter, "edited_at": chat_module.utc_ts_ms(),
    }
    msg_key = alice.crypto.derive_message_key(
        session_key, alice.public_key, bob.public_key, counter, "edit"
    )
    packet = alice.crypto.encrypt(msg_key, chat_module.pad_plaintext(b"dm hijack"), canonical_json(payload))
    with pytest.raises(ValueError, match="group message"):
        asyncio.run(bob.handle_relay_payload(
            alice.public_key, {"kind": "message_edit", "payload": payload, "packet": packet}
        ))

    # 2. Trying to edit a Group A message using a Group B envelope must be rejected.
    meta_b = {
        "msg_id": grp_msg["msg_id"], "from": alice.public_key, "group_id": group_b,
        "epoch": 1, "edited_at": chat_module.utc_ts_ms(),
    }
    packet_b = alice.crypto.encrypt(key_b, chat_module.pad_plaintext(b"cross group"), canonical_json(meta_b))
    frame_b = alice.signed_payload("group_message_edit", {"meta": meta_b, "packet": packet_b})
    with pytest.raises(ValueError, match="does not belong to this group"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, frame_b))

    assert find_body(bob, "in group a")["body"] == "in group a"


def test_edit_message_atomic_against_tombstone_and_stale_timestamp(tmp_path):
    db = chat_module.Database(str(tmp_path / "atomic_edit.db"), master_key=b"m" * 32)
    try:
        mid = str(uuid.uuid4())
        pk = "ab" * 32
        db.save_message(mid, pk, "initial", "out", recipient="cd" * 32)
        assert db.edit_message(mid, "newer", 2000) is True
        assert db.edit_message(mid, "stale", 1500) is False
        assert db.get_message(mid)["body"] == "newer"
        assert db.tombstone_message(mid, deleted_at=3000) is True
        assert db.edit_message(mid, "resurrect", 4000) is False
        row = db.get_message(mid)
        assert row["deleted_at"] == 3000
        assert row["body"] == ""
    finally:
        db.close()


def test_reserve_send_counters_requires_active_session(tmp_path):
    db = chat_module.Database(str(tmp_path / "no_sess.db"), master_key=b"n" * 32)
    try:
        with pytest.raises(ValueError, match="No active session"):
            db.reserve_send_counters("ef" * 32, 1)
    finally:
        db.close()


def test_group_edit_fanout_isolates_failing_recipient_and_group_delivered_flag(trio):
    alice, bob, carol = trio
    establish(alice, bob)
    establish(alice, carol)
    group_id = str(uuid.uuid4())
    for n in (alice, bob, carol):
        n.db.create_group(group_id, "resilient", alice.public_key)
        n.db.add_group_member(group_id, alice.public_key)
        n.db.add_group_member(group_id, bob.public_key)
        n.db.add_group_member(group_id, carol.public_key)
        n.db.save_group_key(group_id, 1, b"k" * 32, alice.public_key)

    asyncio.run(alice.send_group_chat(group_id, "original"))
    target = find_body(carol, "original")

    orig_send_relay = alice.send_relay

    async def flaky_send_relay(peer, payload, **kwargs):
        if peer == bob.public_key:
            raise RuntimeError("bob relay broken")
        return await orig_send_relay(peer, payload, **kwargs)

    alice.send_relay = flaky_send_relay
    try:
        asyncio.run(alice.send_message_edit(target["msg_id"], "fixed"))
    finally:
        alice.send_relay = orig_send_relay

    assert find_body(carol, "fixed") is not None
    assert alice.db.get_message(target["msg_id"])["body"] == "fixed"

    # When all sends fail in send_group_chat, DB delivered must be 0.
    async def all_fail(peer, payload, **kwargs):
        raise RuntimeError("network down")

    alice.send_relay = all_fail
    try:
        asyncio.run(alice.send_group_chat(group_id, "offline group msg"))
    finally:
        alice.send_relay = orig_send_relay
    failed_msg = alice.db.search_messages("offline group msg")[0]
    assert failed_msg["delivered"] == 0


def test_handle_chat_rejects_unknown_group_id(pair):
    alice, bob = pair
    establish(alice, bob)
    session_key = alice.sessions[bob.public_key]
    counter = alice.db.next_send_counter(bob.public_key)
    payload = {
        "msg_id": str(uuid.uuid4()), "from": alice.public_key,
        "to": bob.public_key, "group_id": str(uuid.uuid4()),
        "reply_to": None, "counter": counter, "sent_at": chat_module.utc_ts(),
    }
    msg_key = alice.crypto.derive_message_key(
        session_key, alice.public_key, bob.public_key, counter, "chat"
    )
    packet = alice.crypto.encrypt(msg_key, chat_module.pad_plaintext(b"injected"), canonical_json(payload))
    with pytest.raises(ValueError, match="unknown group"):
        asyncio.run(bob.handle_relay_payload(
            alice.public_key, {"kind": "chat", "payload": payload, "packet": packet}
        ))


def test_file_chunk_rejects_late_chunks_mismatches_and_cleans_corrupt_shards(pair):
    alice, bob = pair
    establish(alice, bob)

    # Normal 2-chunk transfer succeeds and stores complete file
    raw = b"A" * (chat_module.MAX_CHUNK_BYTES + 128)
    fid = str(uuid.uuid4())
    sha = hashlib.sha256(raw).hexdigest()
    total_chunks = 2

    def build_chunk(idx, chunk_bytes, file_id=fid, tot=total_chunks, size=len(raw), file_sha=sha, gid=None):
        counter = alice.db.next_send_counter(bob.public_key)
        meta = {
            "file_id": file_id, "filename": "f.bin", "size": size, "sha256": file_sha,
            "from": alice.public_key, "to": bob.public_key, "group_id": gid,
            "mime_type": "application/octet-stream",
            "total_chunks": tot, "chunk_size": chat_module.MAX_CHUNK_BYTES,
            "sent_at": chat_module.utc_ts(), "chunk_index": idx,
            "counter": counter, "chunk_sha256": hashlib.sha256(chunk_bytes).hexdigest(),
        }
        mk = alice.crypto.derive_message_key(
            alice.sessions[bob.public_key], alice.public_key, bob.public_key, counter, "file-chunk"
        )
        pkt = alice.crypto.encrypt(mk, chunk_bytes, canonical_json(meta))
        return {"kind": "file_chunk", "payload": meta, "packet": pkt}

    c0 = build_chunk(0, raw[:chat_module.MAX_CHUNK_BYTES])
    c1 = build_chunk(1, raw[chat_module.MAX_CHUNK_BYTES:])
    asyncio.run(bob.handle_relay_payload(alice.public_key, c0))
    asyncio.run(bob.handle_relay_payload(alice.public_key, c1))
    assert bob.db.get_file(fid) is not None

    # Late chunk for already-completed file must be rejected without leaving shard dir
    c_late = build_chunk(0, raw[:chat_module.MAX_CHUNK_BYTES])
    with pytest.raises(ValueError, match="already completed"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, c_late))
    assert not (bob.files_dir / f"{fid}.chunks").exists()

    # Corrupted shard on disk during final reassembly must clean up shards
    fid2 = str(uuid.uuid4())
    sha2 = hashlib.sha256(raw).hexdigest()
    d0 = build_chunk(0, raw[:chat_module.MAX_CHUNK_BYTES], file_id=fid2, file_sha=sha2)
    d1 = build_chunk(1, raw[chat_module.MAX_CHUNK_BYTES:], file_id=fid2, file_sha=sha2)
    asyncio.run(bob.handle_relay_payload(alice.public_key, d0))
    # Mismatched total_chunks for fid2 must be rejected
    bad_tot = build_chunk(0, b"xyz", file_id=fid2, tot=1, size=3, file_sha=hashlib.sha256(b"xyz").hexdigest())
    with pytest.raises(ValueError, match="Conflicting"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, bad_tot))
    # Corrupt shard 0 ciphertext on disk before chunk 1 arrives
    shard0 = bob.files_dir / f"{fid2}.chunks" / "0"
    shard0.write_bytes(b"corrupted-ciphertext")
    with pytest.raises(Exception):
        asyncio.run(bob.handle_relay_payload(alice.public_key, d1))
    assert bob.db.file_chunks(fid2) == []
    assert not (bob.files_dir / f"{fid2}.chunks").exists()

    # Unknown group_id in file chunk must be rejected
    bad_grp = build_chunk(0, b"hi", file_id=str(uuid.uuid4()), tot=1, size=2,
                          file_sha=hashlib.sha256(b"hi").hexdigest(), gid=str(uuid.uuid4()))
    with pytest.raises(ValueError, match="unknown group"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, bad_grp))


def test_signaling_server_purges_expired_queue_and_caps_rate_buckets(tmp_path, monkeypatch):
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "relay_cap.db"))
    srv = chat_module.SignalingServer()
    try:
        target = "cd" * 1312
        old_ts = chat_module.utc_ts() - chat_module.OFFLINE_QUEUE_TTL - 10
        for _ in range(chat_module.MAX_OFFLINE_QUEUE_PER_TARGET):
            srv.relay_db.execute(
                "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
                (target, "{}", old_ts),
            )
        srv.relay_db.commit()
        assert srv._offline_queue_full(target) is False
        assert srv._offline_queue_count(target) == 0

        ws = object()
        for _ in range(10):
            srv._rate_ok(ws, limit=3)
        assert len(srv.rate[ws]) == 3

        for _ in range(10):
            srv._pubkey_rate_ok(target, limit=4)
        assert len(srv.pubkey_rate[target]) == 4
    finally:
        srv.relay_db.close()


def test_direct_pool_eviction_and_closed_socket_reacquire(tmp_path):
    node = chat_module.QuantumNode(
        str(tmp_path / "pool.db"), "ws://127.0.0.1:1", enable_direct=True
    )
    try:
        closed_calls = []

        class FakeWS:
            def __init__(self, is_open=True):
                self.close_code = None if is_open else 1000

            async def close(self):
                closed_calls.append(True)
                self.close_code = 1000

        async def run():
            old_ws = FakeWS(is_open=True)
            node.peer_direct["peer1"] = "ws://127.0.0.1:9001"
            node._direct_pool["ws://127.0.0.1:9001"] = old_ws
            # Evicting an unused URL closes its pooled WebSocket.
            await node._handle_signaling_message({
                "type": "peers",
                "peers": {"peer1": {"relay_alias": None, "direct_url": "ws://127.0.0.1:9002"}},
            })
            await asyncio.sleep(0.05)
            assert closed_calls == [True]
            assert "ws://127.0.0.1:9001" not in node._direct_pool

            # _acquire_direct_conn drops closed pooled sockets instead of reusing them.
            dead_ws = FakeWS(is_open=False)
            node._direct_pool["ws://127.0.0.1:9002"] = dead_ws
            assert node._is_ws_open(dead_ws) is False

        asyncio.run(run())
    finally:
        node.db.close()


def test_ui_group_read_receipt_keeps_dm_unread_and_device_sync_validates(pair):
    alice, bob = pair
    establish(alice, bob)
    bob.db.increment_unread(alice.public_key)
    group_id = str(uuid.uuid4())
    bob.db.create_group(group_id, "Team", alice.public_key)
    bob.db.add_group_member(group_id, bob.public_key)
    gid_msg = str(uuid.uuid4())
    bob.db.save_message(gid_msg, alice.public_key, "in group", "in", group_id=group_id)

    ui_ws = add_ui(bob)
    asyncio.run(bob._dispatch_ui(ui_ws, {
        "type": "read_receipt", "pubkey": alice.public_key, "msg_id": gid_msg, "group_id": group_id,
    }))
    friend = next(f for f in bob.db.get_friends() if f["pubkey"] == alice.public_key)
    assert friend["unread"] == 1

    # Invalid synced message with empty body must be rejected
    key = bob.crypto.derive_device_sync_key(bob.secret_key)
    bad_body = canonical_json({
        "event": "chat_in",
        "data": {"msg_id": "x", "sender_pubkey": alice.public_key, "body": ""},
    })
    env = bob.signed_payload("device_sync", {"packet": bob.crypto.encrypt(key, bad_body)})
    with pytest.raises(ValueError, match="Invalid synced chat message"):
        asyncio.run(bob._handle_device_sync(bob.public_key, env))


def test_ui_html_v401_hardening_checks():
    html = chat_module.HTML
    assert "location.protocol === 'https:' ? '443' : '80'" in html
    assert "selectedTarget.type === 'friend' ? selectedTarget.id : m.sender_pubkey" in html
    assert "function copyTextToClipboard(" in html
    assert "((a.id ?? 1e15) - (b.id ?? 1e15))" in html
    assert "displayName(m.sender_pubkey)" in html
    assert "0 / 65,536" in html
    assert ".msg-actions { display: none; }" in html
    assert "ws://[::1]:*" not in html

    handler = object.__new__(chat_module.ChatHTTPHandler)
    handler.require_http_auth = False
    sent = []
    handler.send_header = lambda k, v: sent.append((k, v))
    handler.headers = {"Host": "127.0.0.1:8000"}
    chat_module.ChatHTTPHandler._security_headers(handler)
    csp = next(v for k, v in sent if k == "Content-Security-Policy")
    assert "[::1]" not in csp
    assert "ws://127.0.0.1:*" in csp


def test_signaling_purge_empty_commits_transaction(tmp_path, monkeypatch):
    relay_db = tmp_path / "relay_purge.db"
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(relay_db))
    srv = chat_module.SignalingServer()
    try:
        srv._purge_expired_offline_queue()
        assert srv.relay_db.in_transaction is False
    finally:
        srv.relay_db.close()



