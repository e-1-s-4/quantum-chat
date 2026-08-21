"""Regression tests for the v3.4.0 hardening and enhancement pass.

Each test pins a specific fix: inline-attachment XSS, call/typing frame
authentication, group-key delivery to sessionless members, outbox staleness
after a rekey, direct-frame freshness, per-server HTTP state, and several
smaller correctness fixes.
"""

from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace

import pytest

import chat as chat_module
from chat import (
    INLINE_CONTENT_TYPES,
    MAX_GROUP_MEMBERS,
    ChatHTTPHandler,
    Database,
    LocalKeyStore,
    QuantumNode,
    b64d,
    b64e,
    canonical_json,
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
    """Minimal UI WebSocket stand-in."""

    def __init__(self):
        self.sent = []

    async def send(self, payload):
        self.sent.append(json.loads(payload))


def add_ui(node):
    ws = FakeWS()
    node.ui_clients.add(ws)
    return ws


async def establish_session(alice, bob):
    """Run a full PQ handshake between two linked nodes."""
    await alice.connect_peer(bob.public_key)


# ─── Inline attachment XSS (critical) ─────────────────────────────────────────


def _file_handler(tmp_path, mime_type, filename="evil.html", view=True):
    file_id = str(uuid.uuid4())
    path = tmp_path / file_id
    path.write_bytes(b"<script>alert(1)</script>")
    meta = {
        "file_id": file_id, "filename": filename, "mime_type": mime_type,
        "size": path.stat().st_size, "storage_path": str(path), "file_nonce": None,
        "group_id": None,
    }
    handler = object.__new__(ChatHTTPHandler)
    handler.path = f"/files/{file_id}" + ("?view=1&token=t" if view else "?token=t")
    handler.require_http_auth = False
    handler.node = SimpleNamespace(
        ui_token="t",
        db=SimpleNamespace(get_file=lambda requested: meta if requested == file_id else None),
        decrypt_from_disk=lambda raw, fid, nonce: b"<script>alert(1)</script>",
    )
    handler.headers = {}
    captured = {"headers": []}
    handler.send_response = lambda code, _msg=None: captured.update(status=code)
    handler.send_header = lambda key, value: captured["headers"].append((key, value))
    handler.end_headers = lambda: None
    handler.send_error = lambda code, msg="": captured.update(status=code, error=msg)
    handler.wfile = SimpleNamespace(write=lambda data: len(data))
    return handler, captured


@pytest.mark.parametrize("ctype", ["text/html", "image/svg+xml", "application/xhtml+xml", "text/xml"])
def test_dangerous_mime_types_are_never_served_inline(tmp_path, ctype):
    """A sender-controlled text/html (or SVG/XML) attachment must download
    instead of rendering on the app's own origin, where attacker script could
    read the UI token and drive the local WebSocket API."""
    handler, captured = _file_handler(tmp_path, ctype)
    ChatHTTPHandler.do_GET(handler)
    disposition = next(v for k, v in captured["headers"] if k == "Content-Disposition")
    assert disposition.startswith("attachment"), ctype


@pytest.mark.parametrize("ctype", ["image/png", "audio/webm", "video/mp4", "text/plain"])
def test_safe_mime_types_still_render_inline_with_a_sandbox(tmp_path, ctype):
    handler, captured = _file_handler(tmp_path, ctype, filename="clip.bin")
    ChatHTTPHandler.do_GET(handler)
    assert captured["status"] == 200
    disposition = next(v for k, v in captured["headers"] if k == "Content-Disposition")
    assert disposition.startswith("inline")
    csps = [v for k, v in captured["headers"] if k == "Content-Security-Policy"]
    assert any("sandbox" in c for c in csps)


def test_inline_allowlist_excludes_scriptable_types():
    dangerous = {"text/html", "image/svg+xml", "application/xhtml+xml",
                 "text/xml", "application/xml", "application/javascript"}
    assert not dangerous & INLINE_CONTENT_TYPES


def test_head_request_does_not_decrypt_the_file(tmp_path):
    """HEAD used to decrypt the whole attachment just to throw the body away;
    it must serve metadata only."""
    calls = []
    file_id = str(uuid.uuid4())
    path = tmp_path / file_id
    path.write_bytes(b"ciphertext")

    def fake_decrypt(raw, fid, nonce):
        calls.append(fid)
        return b"plaintext"

    meta = {"file_id": file_id, "filename": "a.png", "mime_type": "image/png",
            "size": 9, "storage_path": str(path), "file_nonce": None, "group_id": None}
    handler = object.__new__(ChatHTTPHandler)
    handler.path = f"/files/{file_id}?token=t"
    handler.require_http_auth = False
    handler.node = SimpleNamespace(
        ui_token="t",
        db=SimpleNamespace(get_file=lambda requested: meta if requested == file_id else None),
        decrypt_from_disk=fake_decrypt,
    )
    handler.headers = {}
    captured = {"headers": []}
    handler.send_response = lambda code, _msg=None: captured.update(status=code)
    handler.send_header = lambda k, v: captured["headers"].append((k, v))
    handler.end_headers = lambda: None
    handler.send_error = lambda code, msg="": captured.update(status=code, error=msg)
    handler.wfile = SimpleNamespace(write=lambda data: len(data))
    ChatHTTPHandler.do_HEAD(handler)
    assert captured["status"] == 200
    assert calls == []


def test_host_header_cannot_inject_csp_directives():
    """A Host header containing ';' used to terminate connect-src early so an
    injected directive could override the real policy (first occurrence wins)."""
    handler = object.__new__(ChatHTTPHandler)
    handler.require_http_auth = True
    sent = []
    handler.send_header = lambda k, v: sent.append((k, v))
    handler.headers = {"Host": "127.0.0.1:8000; script-src 'unsafe-eval'"}
    ChatHTTPHandler._security_headers(handler)
    csp = next(v for k, v in sent if k == "Content-Security-Policy")
    assert "script-src 'unsafe-eval'" not in csp
    # The rejected host falls back to the loopback-only policy.
    assert "ws://127.0.0.1:8000" not in csp
    assert "ws://127.0.0.1:*" in csp

    sent.clear()
    handler.headers = {"Host": "localhost:8765"}
    ChatHTTPHandler._security_headers(handler)
    csp = next(v for k, v in sent if k == "Content-Security-Policy")
    assert "ws://localhost:8765" in csp


# ─── call_end / typing authentication ─────────────────────────────────────────


def test_call_end_requires_a_valid_signature(pair):
    alice, bob = pair
    bob.active_calls[alice.public_key] = {"call_id": "c1", "role": "callee", "media": "audio", "state": "active"}
    forged = {"kind": "call_end", "payload": {
        "from": alice.public_key, "to": bob.public_key, "call_id": "c1", "reason": "hangup"}}
    with pytest.raises(ValueError, match="Invalid call end signature"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, forged))
    # The forged end must not tear down the call.
    assert alice.public_key in bob.active_calls

    signed = alice.signed_payload("call_end", forged["payload"])
    asyncio.run(bob.handle_relay_payload(alice.public_key, signed))
    assert alice.public_key not in bob.active_calls


def test_call_end_ignores_a_stale_call_id(pair):
    alice, bob = pair
    bob.active_calls[alice.public_key] = {"call_id": "current", "role": "callee", "media": "audio", "state": "active"}
    stale = alice.signed_payload("call_end", {
        "from": alice.public_key, "to": bob.public_key, "call_id": "old", "reason": "hangup"})
    asyncio.run(bob.handle_relay_payload(alice.public_key, stale))
    assert alice.public_key in bob.active_calls


def test_typing_indicators_are_signed(pair):
    alice, bob = pair
    ui = add_ui(bob)

    unsigned = {"kind": "typing", "from": alice.public_key, "to": bob.public_key, "active": True}
    asyncio.run(bob.handle_relay_payload(alice.public_key, unsigned))
    assert not any(f.get("type") == "typing" for f in ui.sent)

    signed = alice.signed_payload("typing", {
        "from": alice.public_key, "to": bob.public_key, "active": True})
    asyncio.run(bob.handle_relay_payload(alice.public_key, signed))
    assert any(f.get("type") == "typing" and f.get("active") for f in ui.sent)


def test_blocked_peer_typing_and_call_frames_are_dropped(pair):
    alice, bob = pair
    bob.db.block_friend(alice.public_key, True)
    ui = add_ui(bob)
    signed = alice.signed_payload("typing", {
        "from": alice.public_key, "to": bob.public_key, "active": True})
    asyncio.run(bob.handle_relay_payload(alice.public_key, signed))
    assert not any(f.get("type") == "typing" for f in ui.sent)


# ─── Group keys reach members without live sessions ───────────────────────────


def test_group_invite_enforces_the_member_cap(pair):
    alice, bob = pair
    invite = alice.signed_payload("group_invite", {
        "group_id": str(uuid.uuid4()), "name": "Team",
        "members": [bob.public_key] + [alice.public_key] * MAX_GROUP_MEMBERS,
        "from": alice.public_key, "to": bob.public_key, "epoch": 1})
    with pytest.raises(ValueError, match="too many members"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, invite))


def test_session_accept_that_fails_validation_keeps_the_pending_offer(pair):
    alice, bob = pair
    asyncio.run(establish_session(alice, bob))
    # Simulate a fresh handshake offer from alice that is still pending.
    kem_pk, kem_sk = alice.crypto.new_kem_keypair()
    session_id = str(uuid.uuid4())
    offer_payload = {
        "protocol": "quantum-chat-v4", "from": alice.public_key, "to": bob.public_key,
        "session_id": session_id, "kem_pk": b64e(kem_pk), "created_at": chat_module.utc_ts(),
    }
    from chat import PendingOffer
    bob.pending_offers[alice.public_key] = PendingOffer(
        peer_pubkey=alice.public_key, session_id=session_id,
        kem_secret_key=kem_sk, created_at=chat_module.utc_ts(),
        offer_payload=offer_payload)

    bad_protocol = alice.signed_payload("session_accept", {
        "protocol": "quantum-chat-v3", "from": alice.public_key, "to": bob.public_key,
        "session_id": session_id, "ciphertext": b64e(b"x" * 32), "accepted_at": chat_module.utc_ts(),
    })
    with pytest.raises(ValueError, match="Unsupported session protocol"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, bad_protocol))
    # The offer survived, so a corrected accept can complete without a new
    # handshake round trip.
    assert alice.public_key in bob.pending_offers


def test_owner_redelivers_group_keys_when_a_session_establishes(pair):
    alice, bob = pair
    gid = str(uuid.uuid4())
    alice.db.create_group(gid, "Team", alice.public_key)
    alice.db.add_group_member(gid, alice.public_key, role="owner")
    alice.db.add_group_member(gid, bob.public_key)
    key = b"\x01" * 32
    alice.db.save_group_key(gid, 1, key, alice.public_key)

    delivered = []
    original = alice.send_group_invite

    async def capture(peer, invite, group_key):
        delivered.append((peer, invite["epoch"]))
        await original(peer, invite, group_key)

    alice.send_group_invite = capture
    asyncio.run(establish_session(alice, bob))

    assert (bob.public_key, 1) in delivered
    stored = bob.db.get_group_key(gid)
    assert stored and stored["key"] == key


def test_rotate_group_key_distributes_a_new_epoch_and_bumps_the_epoch(pair):
    alice, bob = pair
    gid = str(uuid.uuid4())
    alice.db.create_group(gid, "Team", alice.public_key)
    alice.db.add_group_member(gid, alice.public_key, role="owner")
    alice.db.add_group_member(gid, bob.public_key)
    old_key = b"\x0b" * 32
    alice.db.save_group_key(gid, 1, old_key, alice.public_key)
    asyncio.run(establish_session(alice, bob))
    bob_received = []
    original_bob_handle = bob.handle_relay_payload

    async def spy(peer, payload):
        if payload.get("kind") == "group_invite":
            bob_received.append(payload["payload"]["epoch"])
        await original_bob_handle(peer, payload)

    bob.handle_relay_payload = spy
    asyncio.run(alice.rotate_group_key(gid))

    assert bob_received == [2]
    new = alice.db.get_group_key(gid)
    assert new["epoch"] == 2 and new["key"] != old_key
    # Bob can decrypt with the rotated epoch key.
    stored = bob.db.get_group_key(gid)
    assert stored["epoch"] == 2


def test_rotate_group_key_requires_the_owner(pair):
    alice, bob = pair
    gid = str(uuid.uuid4())
    alice.db.create_group(gid, "Team", alice.public_key)
    alice.db.add_group_member(gid, alice.public_key, role="owner")
    with pytest.raises(ValueError, match="Only the group owner"):
        asyncio.run(bob.rotate_group_key(gid))


# ─── Outbox staleness after a rekey ───────────────────────────────────────────


def test_outbox_records_the_sealing_session_for_session_bound_kinds(tmp_path):
    db = Database(str(tmp_path / "outbox.db"), master_key=b"k" * 32)
    try:
        peer = "ab" * 32
        db.save_session(peer, "sid-1", b"\x02" * 32, initiator=True)
        db.queue_outbox(peer, {"type": "relay", "to": peer, "payload": {"kind": "chat"}})
        db.queue_outbox(peer, {"type": "relay", "to": peer, "payload": {"kind": "read_receipt"}})
        queued = db.queued_outbox(peer)
        by_kind = {json.loads(q["payload"])["payload"]["kind"]: q for q in queued}
        assert by_kind["chat"]["session_id"] == "sid-1"
        # Receipts are signed but not session-encrypted: they survive rekeys.
        assert by_kind["read_receipt"]["session_id"] is None
    finally:
        db.close()


def test_flush_retires_items_whose_session_rekeyed(pair, caplog):
    alice, bob = pair
    alice.signaling_ws = FakeWS()
    alice.db.save_session(bob.public_key, "old-session", b"\x03" * 32, initiator=True)
    alice.db.queue_outbox(bob.public_key, {"kind": "chat", "payload": {"stale": True}})
    alice.db.save_session(bob.public_key, "new-session", b"\x04" * 32, initiator=True)

    asyncio.run(alice.flush_outbox(bob.public_key))

    rows = alice.db.conn.execute("SELECT status FROM outbox").fetchall()
    assert [r["status"] for r in rows] == ["expired"]
    assert any("rekeyed" in r.getMessage() for r in caplog.records)


def test_flush_sends_items_whose_session_is_current(pair):
    alice, bob = pair
    alice.signaling_ws = FakeWS()
    alice.db.save_session(bob.public_key, "current", b"\x05" * 32, initiator=True)
    envelope = {"type": "relay", "to": bob.public_key,
                "payload": {"kind": "chat", "payload": {"fresh": True}}}
    alice.db.queue_outbox(bob.public_key, envelope)

    asyncio.run(alice.flush_outbox(bob.public_key))

    assert alice.signaling_ws.sent == [envelope]
    rows = alice.db.conn.execute("SELECT status FROM outbox").fetchall()
    assert [r["status"] for r in rows] == ["sent"]


# ─── Direct transport hardening ───────────────────────────────────────────────


def test_direct_rate_limit_does_not_grow_buckets_once_exhausted():
    node = object.__new__(QuantumNode)
    node._direct_rate = {}
    for _ in range(30):
        assert node._direct_rate_ok("203.0.113.5") is True
    for _ in range(50):
        assert node._direct_rate_ok("203.0.113.5") is False
    # Rejected attempts are not recorded, so the bucket stays at the limit.
    assert len(node._direct_rate["203.0.113.5"]) == 30


def test_direct_frame_freshness_bound(pair):
    alice, bob = pair
    old_hello = {"from": alice.public_key, "to": bob.public_key,
                 "sent_at": chat_module.utc_ts() - 3600, "payload": {"kind": "typing"}}
    sig = b64e(alice.crypto.sign(alice.secret_key, canonical_json(old_hello)))
    socket = FakeSocket([json.dumps({"type": "direct", **old_hello, "signature": sig})])
    socket.remote_address = ("203.0.113.10", 1234)
    asyncio.run(bob.handle_direct_peer(socket))
    assert any("too old" in f.get("text", "") for f in socket.frames())


class FakeSocket:
    def __init__(self, incoming=None):
        self.sent = []
        self.closed = None
        self._incoming = list(incoming or [])

    async def send(self, data):
        self.sent.append(json.loads(data))

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    def __aiter__(self):
        async def gen():
            while self._incoming:
                yield self._incoming.pop(0)
        return gen()

    def frames(self):
        return self.sent


# ─── Key store / backup error contracts ───────────────────────────────────────


def test_wrapped_key_without_passphrase_reports_the_missing_env_var(tmp_path):
    store = LocalKeyStore(str(tmp_path / "wrapped.db"))
    store.path.write_text("QCWRAP2:" + b64e(b"\x01" * 16) + ":" + b64e(b"\x02" * 40), encoding="ascii")
    with pytest.raises(RuntimeError, match="QUANTUM_CHAT_PASSPHRASE is required"):
        store.load_or_create()


def test_legacy_qcwrap1_key_reports_the_migration_recipe(tmp_path):
    store = LocalKeyStore(str(tmp_path / "legacy.db"))
    store.path.write_text("QCWRAP1:salt:blob", encoding="ascii")
    with pytest.raises(RuntimeError, match="v2.0"):
        store.load_or_create()


def test_corrupted_identity_backup_raises_valueerror_not_jsondecodeerror():
    from chat import IDENTITY_BACKUP_AAD, pack_identity_backup, require_cryptography, scrypt_derive
    blob = pack_identity_backup("ab" * 32, b"\x06" * 32, "correct horse")
    parts = blob.split(":")
    salt, nonce = b64d(parts[1]), b64d(parts[2])
    AESGCM, _, _ = require_cryptography()
    key = scrypt_derive("correct horse", salt)
    # Re-encrypt a decryptable-but-corrupt plaintext under the same key/AAD.
    tampered = AESGCM(key).encrypt(nonce, b"not-json{", IDENTITY_BACKUP_AAD)
    broken = f"{parts[0]}:{parts[1]}:{parts[2]}:{b64e(tampered)}"
    with pytest.raises(ValueError, match="Corrupted identity backup"):
        chat_module.unpack_identity_backup(broken, "correct horse")


# ─── Database helpers ─────────────────────────────────────────────────────────


def test_reserve_send_counters_returns_an_ordered_range(tmp_path):
    db = Database(str(tmp_path / "counters.db"), master_key=b"k" * 32)
    try:
        peer = "cd" * 32
        db.save_session(peer, "s", b"\x07" * 32, initiator=True)
        first = db.reserve_send_counters(peer, 3)
        second = db.reserve_send_counters(peer, 2)
        assert first == [1, 2, 3]
        assert second == [4, 5]
        assert db.reserve_send_counters(peer, 0) == []
    finally:
        db.close()


def test_session_freshness_does_not_need_to_decrypt_the_key(tmp_path):
    db = Database(str(tmp_path / "fresh.db"), master_key=b"k" * 32)
    try:
        peer = "ef" * 32
        db.save_session(peer, "s", b"\x08" * 32, initiator=True)
        # Corrupt the encrypted key blob: freshness must still read fine.
        with db.lock:
            db.conn.execute("UPDATE sessions SET key=? WHERE peer_pubkey=?", (b"\x00" * 48, peer))
            db.conn.commit()
        established = db.session_established_at(peer)
        assert established is not None
        assert chat_module.utc_ts() - established < chat_module.SESSION_TTL
    finally:
        db.close()


def test_stale_recv_counters_from_old_sessions_are_pruned(tmp_path):
    db = Database(str(tmp_path / "replay.db"), master_key=b"k" * 32)
    try:
        peer = "12" * 32
        db.save_session(peer, "old-session", b"\x09" * 32, initiator=True)
        with db.lock:
            db.conn.execute(
                "INSERT INTO recv_counters (peer_pubkey, session_id, counter, seen_at) VALUES (?, ?, ?, ?)",
                (peer, "old-session", 5, chat_module.utc_ts() - chat_module.SESSION_TTL - 10),
            )
            db.conn.commit()
        db.save_session(peer, "new-session", b"\x0a" * 32, initiator=True)
        db.mark_recv_counter(peer, 1)
        with db.lock:
            remaining = db.conn.execute(
                "SELECT session_id FROM recv_counters WHERE peer_pubkey=?", (peer,)
            ).fetchall()
        assert {r["session_id"] for r in remaining} == {"new-session"}
    finally:
        db.close()


# ─── Node state hygiene ───────────────────────────────────────────────────────


def test_remove_friend_purges_in_memory_state(pair):
    alice, bob = pair
    asyncio.run(establish_session(alice, bob))
    alice.peer_direct[bob.public_key] = "ws://127.0.0.1:9999"
    alice.active_calls[bob.public_key] = {"call_id": "c", "role": "caller"}

    asyncio.run(alice._dispatch_ui(FakeWS(), {"type": "remove_friend", "pubkey": bob.public_key}))

    assert bob.public_key not in alice.sessions
    assert bob.public_key not in alice.peer_direct
    assert bob.public_key not in alice.active_calls
    assert bob.public_key not in alice.pending_offers


def test_block_friend_drops_live_calls_and_direct_hint(pair):
    alice, bob = pair
    asyncio.run(establish_session(alice, bob))
    alice.peer_direct[bob.public_key] = "ws://127.0.0.1:9999"
    alice.active_calls[bob.public_key] = {"call_id": "c", "role": "caller"}

    asyncio.run(alice._dispatch_ui(FakeWS(), {
        "type": "block_friend", "pubkey": bob.public_key, "blocked": True}))

    assert bob.public_key not in alice.sessions
    assert bob.public_key not in alice.peer_direct
    assert bob.public_key not in alice.active_calls


def test_broadcast_ui_survives_a_client_that_mutates_the_set_during_send():
    class SlowClient:
        def __init__(self, clients):
            self.clients = clients

        async def send(self, payload):
            # Simulate a tab closing while the broadcast is suspended.
            self.clients.clear()

    node = object.__new__(QuantumNode)
    node.ui_clients = set()
    slow = SlowClient(node.ui_clients)
    node.ui_clients.add(slow)
    node.ui_clients.add(FakeWS())
    asyncio.run(node.broadcast_ui({"type": "state"}))


# ─── HTTP server isolation ────────────────────────────────────────────────────


def test_start_http_binds_state_per_server_instance(tmp_path, monkeypatch):
    """Two nodes in one process must not share (and overwrite) HTTP state."""
    from chat import start_http
    sockets = []

    class FakeServer:
        def __init__(self, addr, handler):
            self.addr = addr
            self.handler = handler
            sockets.append(self)

        def serve_forever(self):
            pass

        def shutdown(self):
            pass

        def server_close(self):
            pass

    monkeypatch.setattr(chat_module, "ThreadedHTTPServer", FakeServer)
    monkeypatch.setattr(chat_module.threading, "Thread", lambda **kw: SimpleNamespace(start=lambda: None))

    node_a = make_node(tmp_path, "http_a")
    node_b = make_node(tmp_path, "http_b")
    try:
        server_a = start_http(node_a, "127.0.0.1", 0, ui_ws_port=1111)
        server_b = start_http(node_b, "127.0.0.1", 0, ui_ws_port=2222, require_http_auth=True)
        assert server_a.node is node_a and server_b.node is node_b
        assert server_a.ui_ws_port == 1111 and server_b.ui_ws_port == 2222
        assert server_a.require_http_auth is False and server_b.require_http_auth is True
    finally:
        node_a.db.close()
        node_b.db.close()


# ─── Signaling loop resilience ────────────────────────────────────────────────


def test_signaling_loop_nulls_socket_after_a_clean_server_close(tmp_path, monkeypatch):
    import websockets

    node = make_node(tmp_path, "sigloop")

    class FakeConn:
        def __init__(self):
            self.sent = []

        async def send(self, data):
            self.sent.append(data)

        def __aiter__(self):
            async def gen():
                yield json.dumps({"type": "peers", "peers": []})
            return gen()

        async def __aenter__(self):
            return self

        async def __aexit__(self, *exc):
            return False

    class FakeConnect:
        def __init__(self, url, max_size=None):
            self.conn = FakeConn()

        async def __aenter__(self):
            return self.conn

        async def __aexit__(self, *exc):
            return False

    monkeypatch.setattr(websockets, "connect", FakeConnect)
    node._shutting_down = True  # run exactly one iteration

    async def noop_broadcast(_event):
        pass

    monkeypatch.setattr(type(node), "broadcast_ui", noop_broadcast)
    asyncio.run(node.connect_signaling_loop())
    assert node.signaling_ws is None
    node.db.close()
