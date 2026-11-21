"""Regression tests for the v3.5.0 enhancement and hardening pass.

Every test pins one specific fix from the audit: database lock discipline,
search scoping, read-receipt timestamps, replay-window poisoning, handshake
glare, group-invite ownership and epoch monotonicity, abandoned chunk
transfers, outbox queueing on mid-send failures, UI socket leaks, non-ASCII
token handling, RFC-compliant Range handling, and relay offline-queue bounds.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace
from urllib.parse import urlparse

import pytest

import chat as chat_module
from chat import (
    MAX_CHUNK_BYTES,
    MAX_TEXT_BYTES,
    REPLAY_WINDOW,
    ChatHTTPHandler,
    Database,
    LocalKeyStore,
    QuantumNode,
    b64e,
    canonical_json,
    pad_plaintext,
    parse_http_range,
)

# ─── Helpers ──────────────────────────────────────────────────────────────────


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


class FakeWS:
    def __init__(self):
        self.sent = []

    async def send(self, payload):
        self.sent.append(json.loads(payload))


def add_ui(node):
    ws = FakeWS()
    node.ui_clients.add(ws)
    return ws


def capture_sends(node, outbox):
    """Replace node.send_relay with a recorder so tests control delivery order."""
    async def fake_send(peer_pubkey, payload, queue_on_failure=False, ephemeral=False):
        outbox.append((node, peer_pubkey, payload))

    node.send_relay = fake_send


def make_file_handler(tmp_path, plaintext=b"attachment-bytes", mime="application/pdf",
                      filename="doc.pdf", extra_path="", headers=None):
    file_id = str(uuid.uuid4())
    path = tmp_path / file_id
    path.write_bytes(plaintext)
    meta = {"file_id": file_id, "filename": filename, "mime_type": mime,
            "size": len(plaintext), "storage_path": str(path), "file_nonce": None,
            "group_id": None}
    handler = object.__new__(ChatHTTPHandler)
    handler.path = f"/files/{file_id}{extra_path}"
    handler.require_http_auth = False
    handler.node = SimpleNamespace(
        ui_token="t",
        db=SimpleNamespace(get_file=lambda requested: meta if requested == file_id else None),
        decrypt_from_disk=lambda raw, fid, nonce: plaintext,
    )
    handler.headers = headers or {}
    captured = {"headers": [], "body": b""}
    handler.send_response = lambda code, _msg=None: captured.update(status=code)
    handler.send_header = lambda k, v: captured["headers"].append((k, v))
    handler.end_headers = lambda: None
    handler.send_error = lambda code, msg="": captured.update(status=code, error=msg)
    handler.wfile = SimpleNamespace(write=lambda data: captured.update(body=captured["body"] + bytes(data)))
    return handler, captured, meta


# ─── Database layer ───────────────────────────────────────────────────────────


def test_recv_counter_rejects_implausible_forward_jumps(tmp_path):
    """One authenticated frame with counter=2**60 used to poison the replay
    window so every later legitimate message was rejected until a rekey."""
    pytest.importorskip("cryptography")
    db = Database(str(tmp_path / "t.db"), master_key=b"k" * 32)
    try:
        peer = "ab" * 32
        db.save_session(peer, str(uuid.uuid4()), b"s" * 32, initiator=False)
        db.mark_recv_counter(peer, 5)
        # Normal forward progress is fine.
        db.mark_recv_counter(peer, 10)
        # A leap beyond the window must be refused, not adopted.
        with pytest.raises(ValueError, match="implausibly far ahead"):
            db.mark_recv_counter(peer, 10 + REPLAY_WINDOW + 1)
        # The window was not moved by the rejected frame.
        with pytest.raises(ValueError, match="outside the replay window"):
            db.mark_recv_counter(peer, 10 - REPLAY_WINDOW - 1)
        assert db.get_session(peer)["recv_counter"] == 10
    finally:
        db.close()


def test_search_in_1v1_scope_excludes_the_peer_group_messages(tmp_path):
    pytest.importorskip("cryptography")
    db = Database(str(tmp_path / "t.db"), master_key=b"k" * 32)
    try:
        peer = "ab" * 32
        gid = str(uuid.uuid4())
        db.save_message("m1", peer, "secret plans alpha", "in", recipient="cd" * 32)
        db.save_message("m2", peer, "secret plans beta", "in", group_id=gid)
        hits = db.search_messages("secret plans", target=peer)
        # Searching inside the 1:1 conversation must not surface the peer's
        # messages from shared groups.
        assert [m["msg_id"] for m in hits] == ["m1"]
        group_hits = db.search_messages("secret plans", target=gid)
        assert [m["msg_id"] for m in group_hits] == ["m2"]
    finally:
        db.close()


def test_save_read_receipt_persists_the_reader_timestamp(tmp_path):
    pytest.importorskip("cryptography")
    db = Database(str(tmp_path / "t.db"), master_key=b"k" * 32)
    try:
        db.save_message("m1", "ab" * 32, "hello", "out", recipient="cd" * 32)
        reader_ts = chat_module.utc_ts() - 500
        assert db.save_read_receipt("m1", "cd" * 32, read_at=reader_ts) is True
        receipts = db.get_read_receipts(["m1"])
        # The stored receipt carries the READER's timestamp, not our
        # processing time — this is what keeps read_at accurate after a reload.
        assert receipts["m1"] == reader_ts
    finally:
        db.close()


def test_message_metadata_prefers_the_stamped_read_at(tmp_path):
    pytest.importorskip("cryptography")
    node = make_node(tmp_path, "meta")
    try:
        node.db.save_message("m1", node.public_key, "outgoing", "out", recipient="ab" * 32)
        stamped = chat_module.utc_ts() - 900
        node.db.mark_remote_read("m1", stamped)
        # A receipts-table row with a *later* local processing time must not
        # overwrite the accurate stamped value.
        node.db.save_read_receipt("m1", "ab" * 32, read_at=chat_module.utc_ts())
        msgs = node._with_message_metadata(node.db.recent_messages())
        assert msgs[0]["read_at"] == stamped
    finally:
        node.db.close()


def test_wrong_passphrase_error_names_the_passphrase(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    monkeypatch.setenv("QUANTUM_CHAT_PASSPHRASE", "correct horse")
    db_path = str(tmp_path / "wrapped.db")
    store = LocalKeyStore(db_path)
    key = store.load_or_create()
    assert store.path.exists()
    monkeypatch.setenv("QUANTUM_CHAT_PASSPHRASE", "wrong battery")
    store2 = LocalKeyStore(db_path)
    with pytest.raises(RuntimeError, match="Wrong QUANTUM_CHAT_PASSPHRASE"):
        store2.load_or_create()
    assert key


# ─── Session handshake ────────────────────────────────────────────────────────


def test_handshake_glare_converges_on_one_session_key(pair):
    """Both peers initiating at once used to leave each side holding a
    different session key — every message failed AEAD and nothing healed."""
    alice, bob = pair
    alice_out, bob_out = [], []
    capture_sends(alice, alice_out)
    capture_sends(bob, bob_out)

    asyncio.run(alice.connect_peer(bob.public_key))
    asyncio.run(bob.connect_peer(alice.public_key))

    offers = [(n, p) for n, _, p in alice_out + bob_out if p.get("kind") == "session_offer"]
    accepts: list[tuple[object, dict]] = []

    # Crossing delivery: each offer reaches the peer BEFORE any accept does.
    for node, payload in offers:
        peer = bob if node is alice else alice
        sender = alice if node is alice else bob
        try:
            asyncio.run(peer.handle_relay_payload(sender.public_key, payload))
        except ValueError as exc:
            # The tie-break loser's offer is ignored by design.
            assert "glare" not in str(exc).lower()
        # Collect whatever accept the responder just produced.
        outbox = alice_out if peer is alice else bob_out
        for _, _, frame in outbox:
            if frame.get("kind") == "session_accept":
                accepts.append((peer, frame))
        outbox.clear()

    # Deliver the accepts; the one addressed to a dropped pending offer is
    # allowed to fail — the surviving handshake must still converge.
    for responder, frame in accepts:
        dest = alice if responder is bob else bob
        sender = bob if responder is bob else alice
        try:
            asyncio.run(dest.handle_relay_payload(sender.public_key, frame))
        except ValueError as exc:
            assert "does not match an active offer" in str(exc)

    assert alice.sessions[bob.public_key] == bob.sessions[alice.public_key]
    alice_sid = alice.db.get_session(bob.public_key)["session_id"]
    bob_sid = bob.db.get_session(alice.public_key)["session_id"]
    assert alice_sid == bob_sid


def test_session_offer_with_a_future_timestamp_expires(pair):
    alice, bob = pair
    kem_pk, _ = alice.crypto.new_kem_keypair()
    offer = alice.signed_payload("session_offer", {
        "protocol": "quantum-chat-v4", "from": alice.public_key, "to": bob.public_key,
        "session_id": str(uuid.uuid4()), "kem_pk": b64e(kem_pk),
        "created_at": chat_module.utc_ts() + chat_module.PENDING_OFFER_TTL + 60,
    })
    with pytest.raises(ValueError, match="expired"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, offer))


# ─── Groups ───────────────────────────────────────────────────────────────────


def test_inbound_group_invite_records_the_inviter_as_owner(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    gid = str(uuid.uuid4())
    invite = {"group_id": gid, "name": "Team",
              "members": [alice.public_key, bob.public_key],
              "from": alice.public_key, "to": bob.public_key, "epoch": 1}
    asyncio.run(alice.send_group_invite(bob.public_key, invite, b"\x01" * 32))
    # The INVITER owns the group in the recipient's database; the recipient
    # is a plain member. The old behavior let any invite recipient rotate
    # the key and split the group's key state.
    assert bob.db.group_role(gid, alice.public_key) == "owner"
    assert bob.db.group_role(gid, bob.public_key) == "member"
    with pytest.raises(ValueError, match="owner"):
        asyncio.run(bob.rotate_group_key(gid))


def test_group_invite_rejects_epoch_downgrade_but_keeps_redelivery(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    gid = str(uuid.uuid4())
    members = [alice.public_key, bob.public_key]
    alice.db.create_group(gid, "Team", alice.public_key)
    alice.db.add_group_member(gid, alice.public_key, role="owner")
    alice.db.add_group_member(gid, bob.public_key)

    frames: list[tuple[object, object, dict]] = []
    capture_sends(alice, frames)

    async def deliver_to_bob():
        pending = [f for _, _, f in frames if f.get("kind") == "group_invite"]
        frames.clear()
        for frame in pending:
            await bob.handle_relay_payload(alice.public_key, frame)
        return pending

    k1 = b"\x01" * 32
    invite1 = {"group_id": gid, "name": "Team", "members": members,
               "from": alice.public_key, "to": bob.public_key, "epoch": 1}
    asyncio.run(alice.send_group_invite(bob.public_key, invite1, k1))
    delivered_epoch1 = asyncio.run(deliver_to_bob())
    assert bob.db.get_group_key(gid)["epoch"] == 1
    assert bob.db.get_group_key(gid)["key"] == k1

    # Rotate to epoch 2 and deliver it.
    k2 = b"\x02" * 32
    alice.db.save_group_key(gid, 2, k2, alice.public_key)
    invite2 = {**invite1, "epoch": 2}
    asyncio.run(alice.send_group_invite(bob.public_key, invite2, k2))
    asyncio.run(deliver_to_bob())
    assert bob.db.get_group_key(gid)["epoch"] == 2
    assert bob.db.get_group_key(gid)["key"] == k2

    # NOW a hostile relay replays the still-validly-signed epoch-1 invite:
    # without the monotonicity check this rolled the local epoch backwards,
    # letting removed members read new traffic again from their old key.
    # (The epoch check runs before counter consumption, so the replay is
    # caught even though this exact frame was seen before.)
    with pytest.raises(ValueError, match="older than or conflicts"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, delivered_epoch1[0]))
    assert bob.db.get_group_key(gid)["epoch"] == 2
    assert bob.db.get_group_key(gid)["key"] == k2

    # Same-epoch redelivery with matching key material (the documented
    # idempotent _deliver_group_keys_to path) is accepted silently.
    asyncio.run(alice.send_group_invite(bob.public_key, invite2, k2))
    asyncio.run(deliver_to_bob())
    assert bob.db.get_group_key(gid)["epoch"] == 2
    assert bob.db.get_group_key(gid)["key"] == k2


# ─── Transport ────────────────────────────────────────────────────────────────


def test_send_relay_queues_when_the_socket_dies_mid_send(tmp_path):
    node = make_node(tmp_path, "sender")
    try:
        class MidSendDeath:
            async def send(self, payload):
                raise RuntimeError("ConnectionClosed: 1000")

        node.signaling_ws = MidSendDeath()
        peer = "ab" * 32
        envelope = {"type": "relay", "to": peer, "payload": {"kind": "chat"}}
        asyncio.run(node.send_relay(peer, {"kind": "chat"}, queue_on_failure=True))
        # queue_on_failure must hold even when the failure happens during the
        # send, not just when the socket was already gone at entry.
        assert node.db.outbox_depth() == 1
        queued = node.db.queued_outbox(peer)
        assert json.loads(queued[0]["payload"]) == envelope
        assert node.db.metrics().get("relay_sent", 0) == 0
    finally:
        node.db.close()


def test_failed_initial_ui_push_discards_the_client(tmp_path):
    node = make_node(tmp_path, "ui")
    try:
        class VanishedClient:
            def __init__(self, token):
                self.request = SimpleNamespace(path=f"/?token={token}", headers={})

            async def send(self, payload):
                raise RuntimeError("client vanished before the state push")

        ws = VanishedClient(node.ui_token)
        asyncio.run(node.handle_ui(ws))
        assert ws not in node.ui_clients
    finally:
        node.db.close()


def test_ui_ws_token_comparison_survives_non_ascii(tmp_path):
    node = make_node(tmp_path, "ui")
    try:
        class Probe:
            def __init__(self, path):
                self.request = SimpleNamespace(path=path, headers={})

            async def send(self, payload):
                raise AssertionError("should not be reached")

        # compare_digest used to raise TypeError on non-ASCII str operands,
        # escaping as an unhandled exception instead of a clean 1008 close.
        bad = Probe("/?token=%C3%BCber")  # percent-decodes to non-ASCII
        assert node._ui_authenticated(bad) is False
        good = Probe(f"/?token={node.ui_token}")
        assert node._ui_authenticated(good) is True
    finally:
        node.db.close()


def test_http_token_comparison_survives_non_ascii(tmp_path):
    handler = object.__new__(ChatHTTPHandler)
    handler.node = SimpleNamespace(ui_token="secret-token")
    handler.headers = {}
    # A percent-decoded non-ASCII query token used to crash the handler
    # thread with a TypeError instead of answering 401.
    parsed = urlparse("/?token=%C3%BCber")
    assert handler._http_authenticated(parsed) is False
    parsed = urlparse("/?token=secret-token")
    assert handler._http_authenticated(parsed) is True
    handler.headers = {"Authorization": "Bearer ünïcødé"}
    parsed = urlparse("/?token=wrong-token")
    # Neither the (non-ASCII) bearer nor the wrong query token matches.
    assert handler._http_authenticated(parsed) is False


def test_direct_authenticated_connections_get_the_generous_rate_limit(tmp_path):
    node = make_node(tmp_path, "direct")
    try:
        # Unauthenticated frames stay on the tight bucket…
        for _ in range(chat_module.DIRECT_RATE_LIMIT):
            assert node._direct_rate_ok("203.0.113.7") is True
        assert node._direct_rate_ok("203.0.113.7") is False
        # …while an authenticated bulk transfer fits the generous one.
        node._direct_rate.clear()
        for _ in range(chat_module.DIRECT_AUTHED_RATE_LIMIT):
            assert node._direct_rate_ok("203.0.113.8", limit=chat_module.DIRECT_AUTHED_RATE_LIMIT) is True
        assert node._direct_rate_ok("203.0.113.8", limit=chat_module.DIRECT_AUTHED_RATE_LIMIT) is False
        assert chat_module.DIRECT_AUTHED_RATE_LIMIT * MAX_CHUNK_BYTES > 15 * 1024 * 1024
    finally:
        node.db.close()


# ─── Chat intake validation ───────────────────────────────────────────────────


def test_oversized_inbound_chat_is_rejected_without_burning_the_counter(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    counter = alice.db.next_send_counter(bob.public_key)
    session_key = alice.sessions[bob.public_key]
    big_text = "x" * (MAX_TEXT_BYTES + 1)

    def craft(text, cnt):
        payload = {"msg_id": str(uuid.uuid4()), "from": alice.public_key,
                   "to": bob.public_key, "counter": cnt}
        msg_key = alice.crypto.derive_message_key(
            session_key, alice.public_key, bob.public_key, cnt, "chat")
        packet = alice.crypto.encrypt(msg_key, pad_plaintext(text.encode()), canonical_json(payload))
        return {"kind": "chat", "payload": payload, "packet": packet}

    with pytest.raises(ValueError, match="too large"):
        asyncio.run(bob.handle_chat(alice.public_key, craft(big_text, counter)))
    # The rejected frame must not consume its counter: the sender's
    # retransmission (or a corrected message reusing the counter) is
    # processed instead of tripping duplicate detection forever.
    asyncio.run(bob.handle_chat(alice.public_key, craft("fine", counter)))
    bodies = [m["body"] for m in bob.db.recent_messages()]
    assert "fine" in bodies and not any(b.startswith("x" * 100) for b in bodies)


# ─── Chunk transfer hygiene ───────────────────────────────────────────────────


def test_stale_chunk_transfers_are_reaped_and_fresh_ones_kept(tmp_path):
    node = make_node(tmp_path, "chunks")
    try:
        stale_id = str(uuid.uuid4())
        stale_dir = node.files_dir / f"{stale_id}.chunks"
        stale_dir.mkdir(parents=True)
        stored, nonce = node.encrypt_chunk_for_disk(b"stale-chunk", stale_id, 0)
        stale_path = stale_dir / "0"
        stale_path.write_bytes(stored)
        node.db.save_file_chunk(stale_id, 0, 2, str(stale_path), nonce)
        node.db.conn.execute("UPDATE file_chunks SET received_at=? WHERE file_id=?",
                             (chat_module.utc_ts() - 10_000, stale_id))
        node.db.conn.commit()

        fresh_id = str(uuid.uuid4())
        fresh_dir = node.files_dir / f"{fresh_id}.chunks"
        fresh_dir.mkdir(parents=True)
        stored, nonce = node.encrypt_chunk_for_disk(b"fresh-chunk", fresh_id, 0)
        fresh_path = fresh_dir / "0"
        fresh_path.write_bytes(stored)
        node.db.save_file_chunk(fresh_id, 0, 2, str(fresh_path), nonce)

        reclaimed = node.cleanup_stale_chunk_transfers(max_age=3600)
        assert reclaimed > 0
        # The abandoned transfer's shards and rows are gone…
        assert not stale_dir.exists()
        assert node.db.file_chunks(stale_id) == []
        # …while the in-flight transfer is untouched.
        assert fresh_dir.exists()
        assert len(node.db.file_chunks(fresh_id)) == 1
    finally:
        node.db.close()


# ─── Typing timers ────────────────────────────────────────────────────────────


def test_typing_timer_handle_is_reaped_after_firing(pair, monkeypatch):
    alice, bob = pair
    ui = add_ui(bob)
    monkeypatch.setattr(chat_module, "TYPING_INACTIVITY_TTL", 0.05)
    signed = alice.signed_payload("typing", {
        "from": alice.public_key, "to": bob.public_key, "active": True})

    async def run():
        await bob.handle_relay_payload(alice.public_key, signed)
        assert alice.public_key in bob._typing_timers
        await asyncio.sleep(0.3)
        # The fired handle used to stay in the dict forever (a bounded
        # per-peer leak); clear_typing must pop it.
        assert alice.public_key not in bob._typing_timers

    asyncio.run(run())
    assert any(f.get("type") == "typing" and f.get("active") is False for f in ui.sent)


# ─── HTTP Range / HEAD semantics ──────────────────────────────────────────────


def test_malformed_range_header_is_ignored_and_served_in_full(tmp_path):
    handler, captured, meta = make_file_handler(tmp_path, extra_path="", headers={"Range": "bytes=abc"})
    handler.path = f"/files/{meta['file_id']}?token=t"
    ChatHTTPHandler.do_GET(handler)
    # RFC 9110 §14.2: an invalid Range header MUST be ignored → 200 + body.
    assert captured["status"] == 200
    assert captured["body"] == b"attachment-bytes"


def test_unsatisfiable_range_still_answers_416(tmp_path):
    handler, captured, meta = make_file_handler(tmp_path, headers={"Range": "bytes=999999-"})
    handler.path = f"/files/{meta['file_id']}?token=t"
    ChatHTTPHandler.do_GET(handler)
    assert captured["status"] == 416
    assert any(k == "Content-Range" and v == f"bytes */{len(b'attachment-bytes')}"
               for k, v in captured["headers"])


def test_valid_range_still_answers_206(tmp_path):
    handler, captured, meta = make_file_handler(tmp_path, headers={"Range": "bytes=0-3"})
    handler.path = f"/files/{meta['file_id']}?token=t"
    ChatHTTPHandler.do_GET(handler)
    assert captured["status"] == 206
    assert captured["body"] == b"atta"
    assert any(k == "Content-Range" and v.startswith("bytes 0-3/") for k, v in captured["headers"])


def test_head_files_advertises_the_get_length(tmp_path):
    plaintext = b"attachment-bytes"
    handler, captured, meta = make_file_handler(tmp_path, plaintext=plaintext)
    handler.path = f"/files/{meta['file_id']}?token=t"
    ChatHTTPHandler.do_HEAD(handler)
    assert captured["status"] == 200
    length = next(v for k, v in captured["headers"] if k == "Content-Length")
    # HEAD used to advertise Content-Length: 0 regardless of the real size.
    assert int(length) == len(plaintext)
    assert captured["body"] == b""


def test_parse_http_range_rfc_contract():
    # Syntax errors are ignorable (None); only unsatisfiable ranges raise.
    assert parse_http_range("", 10) is None
    assert parse_http_range("units=0-5", 10) is None
    assert parse_http_range("bytes=abc", 10) is None
    assert parse_http_range("bytes=0-1,4-5", 10) is None  # multi-range unsupported → ignore
    assert parse_http_range("bytes=2-5", 10) == (2, 5)
    assert parse_http_range("bytes=7-", 10) == (7, 9)
    assert parse_http_range("bytes=-3", 10) == (7, 9)
    with pytest.raises(chat_module.UnsatisfiableRange):
        parse_http_range("bytes=20-30", 10)
    with pytest.raises(chat_module.UnsatisfiableRange):
        parse_http_range("bytes=-3", 0)
    # UnsatisfiableRange is a ValueError subclass for backward compatibility.
    assert issubclass(chat_module.UnsatisfiableRange, ValueError)


# ─── Relay offline queue bounds ───────────────────────────────────────────────


def _run_relay_socket(relay_server, frames):
    """Feed frames into one relay connection (challenge-signed registration).

    Returns a stand-in socket exposing frames()/frames_of_type() like the
    FakeSocket used by the other test modules."""

    class SocketAdapter:
        def __init__(self):
            self.sent = []
            self.remote_address = ("203.0.113.51", 1234)
            self._incoming = []

        async def send(self, data):
            frame = json.loads(data)
            self.sent.append(data)
            if frame.get("type") == "register_challenge":
                self._incoming.extend(frames(frame["nonce"]))

        def __aiter__(self):
            return self

        async def __anext__(self):
            if not self._incoming:
                raise StopAsyncIteration
            return self._incoming.pop(0)

    sock = SocketAdapter()
    asyncio.run(relay_server.handle(sock))

    def frames_decoded():
        return [json.loads(raw) for raw in sock.sent]

    sock.frames = frames_decoded
    sock.frames_of_type = lambda kind: [f for f in frames_decoded() if f.get("type") == kind]
    return sock


def _register_frame(node, nonce):
    challenge = {"type": "register_challenge", "nonce": nonce, "pubkey": node.public_key}
    sig = b64e(node.crypto.sign(node.secret_key, canonical_json(challenge)))
    return json.dumps({
        "type": "register", "pubkey": node.public_key,
        "signature": sig, "challenge": nonce,
        "relay_alias": node.relay_alias, "direct_url": node.direct_url,
    })


def test_offline_queue_cap_counts_persisted_rows(tmp_path, monkeypatch):
    """The 500-envelope cap used to read a process-local dict, so every relay
    restart granted another 500 rows for a target that never connects. The
    cap now counts the DATABASE, which survives restarts."""
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "relay.db"))
    from chat import MAX_OFFLINE_QUEUE_PER_TARGET, SignalingServer

    relay = SignalingServer()
    target = QuantumNode(str(tmp_path / "target.db"), "ws://127.0.0.1:65535",
                         direct_url=None, enable_direct=False)
    sender = QuantumNode(str(tmp_path / "sender.db"), "ws://127.0.0.1:65535",
                         direct_url=None, enable_direct=False)
    try:
        now = chat_module.utc_ts()
        with relay.relay_db:
            relay.relay_db.executemany(
                "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
                [(target.public_key,
                  json.dumps({"type": "relay", "payload": {"kind": "chat", "i": i}}), now)
                 for i in range(MAX_OFFLINE_QUEUE_PER_TARGET)])

        def frames(nonce):
            return [
                _register_frame(sender, nonce),
                json.dumps({"type": "relay", "to": target.public_key,
                            "payload": {"kind": "chat", "over-cap": True}}),
            ]

        socket = _run_relay_socket(relay, frames)
        errors = socket.frames_of_type("error")
        assert any("queue is full" in e.get("text", "") for e in errors)
        assert relay.relay_db.execute(
            "SELECT COUNT(*) FROM offline_queue WHERE target=?", (target.public_key,)
        ).fetchone()[0] == MAX_OFFLINE_QUEUE_PER_TARGET
    finally:
        target.db.close()
        sender.db.close()
        relay.relay_db.close()


def test_relay_internal_errors_do_not_leak_exception_details(tmp_path, monkeypatch):
    """Non-validation exceptions used to echo str(exc) to any client."""
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "relay.db"))
    from chat import SignalingServer

    relay = SignalingServer()
    node = QuantumNode(str(tmp_path / "leak.db"), "ws://127.0.0.1:65535",
                       direct_url=None, enable_direct=False)
    try:
        # A frame that parses as JSON but is not an object makes the dispatch
        # itself fail with AttributeError — an internal inconsistency, not
        # validated bad input, and it used to echo str(exc) verbatim.
        def frames(nonce):
            return [
                _register_frame(node, nonce),
                json.dumps(["not", "an", "object"]),
            ]

        socket = _run_relay_socket(relay, frames)
        errors = socket.frames_of_type("error")
        assert any(e.get("text") == "Invalid frame" for e in errors)
        assert not any("'list' object" in e.get("text", "") for e in errors)
    finally:
        node.db.close()
        relay.relay_db.close()
