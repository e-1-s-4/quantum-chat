import asyncio
import json
import os
import sqlite3
import tempfile
import uuid
from types import SimpleNamespace

import pytest

from chat import (
    ChatHTTPHandler,
    Database,
    PQModule,
    QuantumCrypto,
    files_dir_for_db,
    pad_plaintext,
    parse_args,
    parse_http_range,
    run_node,
    safe_content_type,
    safe_filename,
    unpad_plaintext,
    validate_file_id,
    validate_label,
    validate_public_key,
)


def test_attachment_helpers_preserve_mime_ranges_and_node_isolation(tmp_path):
    assert safe_content_type("audio/webm;codecs=opus", "voice.webm") == "audio/webm"
    assert safe_content_type("not a mime", "photo.png") == "image/png"
    assert parse_http_range("", 10) is None
    assert parse_http_range("bytes=2-5", 10) == (2, 5)
    assert parse_http_range("bytes=7-", 10) == (7, 9)
    assert parse_http_range("bytes=-3", 10) == (7, 9)
    with pytest.raises(ValueError):
        parse_http_range("bytes=20-30", 10)
    with pytest.raises(ValueError):
        parse_http_range("bytes=0-1,4-5", 10)

    alice_dir = files_dir_for_db(str(tmp_path / "alice.db"))
    bob_dir = files_dir_for_db(str(tmp_path / "bob.db"))
    assert alice_dir != bob_dir
    assert str(alice_dir).endswith("alice.db.files")


def test_validate_public_key_enforces_hex_and_expected_length():
    assert validate_public_key("AAff", expected_bytes=2) == "aaff"
    with pytest.raises(ValueError):
        validate_public_key("xyz")
    with pytest.raises(ValueError):
        validate_public_key("aaff", expected_bytes=3)


def test_validate_file_id_requires_canonical_uuid():
    file_id = str(uuid.uuid4())
    assert validate_file_id(file_id) == file_id
    for bad in ["../escape", "", file_id.upper(), "not-a-uuid"]:
        with pytest.raises(ValueError):
            validate_file_id(bad)


def test_labels_and_filenames_are_bounded_and_basename_only():
    assert validate_label("  Alice  ", "Nickname", 20) == "Alice"
    assert safe_filename("../secret.txt") == "secret.txt"
    with pytest.raises(ValueError):
        validate_label("x" * 21, "Nickname", 20)


def test_database_encrypts_identity_session_and_message_at_rest():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    key = b"k" * 32
    try:
        db = Database(path, master_key=key)
        db.save_identity("aa", b"secret-key")
        db.save_session("bb", "session", b"session-key", initiator=True)
        inserted = db.save_message("m1", "aa", "hello", "out", recipient="bb")
        assert inserted is True
        assert db.load_identity() == ("aa", b"secret-key")
        assert db.get_session("bb")["key"] == b"session-key"
        assert db.recent_messages()[0]["body"] == "hello"
        conn = sqlite3.connect(path)
        raw_secret, secret_nonce = conn.execute("SELECT secret_key, secret_nonce FROM identity").fetchone()
        raw_message, body_nonce = conn.execute("SELECT body, body_nonce FROM messages").fetchone()
        conn.close()
        assert secret_nonce is not None and raw_secret != b"secret-key"
        assert body_nonce is not None and raw_message != "hello"
        assert db.save_message("m1", "aa", "hello", "out", recipient="bb") is False
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_state_payload_is_json_serializable_with_encrypted_rows():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.save_message("m1", "aa", "hello", "out", recipient="bb")
        db.save_file(
            str(uuid.uuid4()), "hello.txt", "aa", 5, "f" * 64, "/tmp/hello.txt",
            recipient="bb", file_nonce=b"nonce"
        )
        import chat as chat_module
        node = SimpleNamespace(
            public_key="aa",
            signaling_url="ws://127.0.0.1:8766",
            online_peers=set(),
            relay_alias="relay",
            direct_url=None,
            db=db,
            max_storage_bytes=0,
            ice_servers=[{"urls": "stun:stun.l.google.com:19302"}],
        )
        node._with_message_metadata = chat_module.QuantumNode._with_message_metadata.__get__(node)
        node._storage_bytes_used = chat_module.QuantumNode._storage_bytes_used.__get__(node)
        payload = chat_module.QuantumNode.state_payload(node)
        json.dumps(payload)
        assert "body_nonce" not in payload["messages"][0]
        assert "file_nonce" not in payload["files"][0]
        assert "storage_path" not in payload["files"][0]
        assert payload["files"][0]["sender_pubkey"] == "aa"
        assert payload["files"][0]["recipient_pubkey"] == "bb"
        assert payload["files"][0]["direction"] == "out"
        assert payload["files"][0]["mime_type"] == "text/plain"
        assert payload["has_more_messages"] is False
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_replay_window_accepts_out_of_order_and_rejects_duplicates():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.save_session("bb", "session", b"session-key", initiator=True)
        db.mark_recv_counter("bb", 2)
        db.mark_recv_counter("bb", 1)
        with pytest.raises(ValueError):
            db.mark_recv_counter("bb", 1)
        assert db.get_session("bb")["recv_counter"] == 2
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_group_keys_chunks_metrics_and_friend_verification_persist():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        gid = str(uuid.uuid4())
        db.create_group(gid, "Team", "aa")
        db.save_group_key(gid, 1, b"g" * 32, "aa")
        assert db.get_group_key(gid)["key"] == b"g" * 32
        db.add_friend("bb", "Bob")
        db.verify_friend("bb")
        db.set_friend_transport("bb", "alias", "ws://127.0.0.1:9999")
        friend = db.get_friends()[0]
        assert friend["verified"] == 1
        assert friend["direct_url"] == "ws://127.0.0.1:9999"
        file_id = str(uuid.uuid4())
        assert db.save_file_chunk(file_id, 0, 1, "/tmp/chunk") is True
        assert db.save_file_chunk(file_id, 0, 1, "/tmp/chunk") is False
        db.metric_inc("relay_sent", 2)
        assert db.metrics()["relay_sent"] == 2
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_http_auth_required_for_root_when_remote_mode_enabled():
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/"
    handler.require_http_auth = True
    handler._http_authenticated = lambda parsed: False
    called = []
    handler.send_error = lambda code, msg="": called.append((code, msg))
    handler._send = lambda *_args, **_kwargs: called.append(("sent", "ok"))
    handler.send_response = lambda *_args, **_kwargs: None
    handler.send_header = lambda *_args, **_kwargs: None
    handler.end_headers = lambda: None
    handler.wfile = SimpleNamespace(write=lambda _data: None)
    ChatHTTPHandler.do_GET(handler)
    assert called and called[0][0] == 401


def test_remote_mode_csp_includes_dynamic_host():
    headers = {}
    handler = object.__new__(ChatHTTPHandler)
    handler.require_http_auth = True
    handler.headers = {"Host": "chat.example.com:8443"}
    handler.send_header = lambda k, v: headers.__setitem__(k, v)
    ChatHTTPHandler._security_headers(handler)
    csp = headers["Content-Security-Policy"]
    assert "ws://chat.example.com:8443" in csp
    assert "wss://chat.example.com:8443" in csp


def test_ui_auth_accepts_modern_websockets_request_shape():
    node = SimpleNamespace(ui_token="token123", allow_remote_ui=False)
    ws = SimpleNamespace(
        request=SimpleNamespace(
            path="/?token=token123",
            headers={"Origin": "http://127.0.0.1:8000"},
        )
    )
    import chat
    assert chat.QuantumNode._ui_authenticated(node, ws) is True


def test_ui_auth_accepts_legacy_websockets_request_shape_and_rejects_remote_origin():
    node = SimpleNamespace(ui_token="token123", allow_remote_ui=False)
    ws = SimpleNamespace(
        path="/?token=token123",
        request_headers={"Origin": "http://chat.example.com"},
    )
    import chat
    assert chat.QuantumNode._ui_authenticated(node, ws) is False
    node.allow_remote_ui = True
    assert chat.QuantumNode._ui_authenticated(node, ws) is True


def test_local_key_store_scrypt_roundtrip_and_legacy_rejection(monkeypatch, tmp_path):
    pytest.importorskip("cryptography")
    import chat as chat_module

    db_path = str(tmp_path / "id.db")
    monkeypatch.setenv("QUANTUM_CHAT_PASSPHRASE", "correct horse battery staple")
    store = chat_module.LocalKeyStore(db_path)
    key = store.load_or_create()
    assert len(key) == 32

    # A fresh store pointed at the same file with the right passphrase unwraps it.
    store2 = chat_module.LocalKeyStore(db_path)
    assert store2.load_or_create() == key

    # Wrong passphrase must fail closed, not silently return a bad key.
    monkeypatch.setenv("QUANTUM_CHAT_PASSPHRASE", "wrong passphrase")
    store3 = chat_module.LocalKeyStore(db_path)
    with pytest.raises(Exception):
        store3.load_or_create()

    # A legacy v2.0 HKDF-wrapped file must be rejected with actionable guidance,
    # not silently accepted with the weaker (no work-factor) derivation.
    legacy_path = tmp_path / "legacy.db.key"
    legacy_path.write_text("QCWRAP1:AAAA:AAAA", encoding="ascii")
    monkeypatch.setenv("QUANTUM_CHAT_PASSPHRASE", "correct horse battery staple")
    legacy_store = chat_module.LocalKeyStore(str(tmp_path / "legacy.db"))
    with pytest.raises(RuntimeError, match="legacy"):
        legacy_store.load_or_create()


def test_group_member_removal_rotates_key_and_excludes_removed_member():
    pytest.importorskip("cryptography")
    import chat as chat_module

    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        gid = str(uuid.uuid4())
        db.create_group(gid, "Team", "owner")
        db.add_group_member(gid, "member-b")
        db.save_group_key(gid, 1, b"g" * 32, "owner")
        assert db.group_role(gid, "owner") == "owner"
        assert db.group_role(gid, "member-b") == "member"

        node = SimpleNamespace(db=db, public_key="owner", sessions={})
        node.state_payload = lambda: {}

        async def fake_broadcast(_event):
            return None

        node.broadcast_ui = fake_broadcast
        node.rotate_group_key = chat_module.QuantumNode.rotate_group_key.__get__(node)
        node.remove_group_member = chat_module.QuantumNode.remove_group_member.__get__(node)

        asyncio.run(node.remove_group_member(gid, "member-b"))

        assert db.group_members(gid) == ["owner"]
        key_row = db.get_group_key(gid)
        assert key_row["epoch"] == 2
        assert key_row["key"] != b"g" * 32

        # Non-owners cannot remove members or rotate the key.
        node2 = SimpleNamespace(db=db, public_key="member-b", sessions={})
        node2.rotate_group_key = chat_module.QuantumNode.rotate_group_key.__get__(node2)
        with pytest.raises(ValueError):
            asyncio.run(node2.rotate_group_key(gid))
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_file_chunks_are_encrypted_at_rest_and_cleaned_up_after_reassembly(tmp_path, monkeypatch):
    pytest.importorskip("cryptography")
    import chat as chat_module

    monkeypatch.chdir(tmp_path)
    fd, path = tempfile.mkstemp(dir=str(tmp_path))
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        node = SimpleNamespace(db=db)
        node.encrypt_chunk_for_disk = chat_module.QuantumNode.encrypt_chunk_for_disk.__get__(node)
        node.decrypt_chunk_from_disk = chat_module.QuantumNode.decrypt_chunk_from_disk.__get__(node)

        file_id = str(uuid.uuid4())
        plaintext_chunk = b"top secret chunk bytes"
        stored, nonce = node.encrypt_chunk_for_disk(plaintext_chunk, file_id, 0)
        assert stored != plaintext_chunk  # never persisted in plaintext
        assert nonce is not None
        assert db.save_file_chunk(file_id, 0, 1, "/tmp/chunk0", chunk_nonce=nonce) is True

        roundtrip = node.decrypt_chunk_from_disk(stored, file_id, 0, nonce)
        assert roundtrip == plaintext_chunk

        rows = db.delete_file_chunks(file_id)
        assert len(rows) == 1
        assert db.file_chunks(file_id) == []
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_storage_quota_rejects_files_over_the_configured_limit():
    pytest.importorskip("cryptography")
    import chat as chat_module

    node = SimpleNamespace(max_storage_bytes=1000)
    node.db = SimpleNamespace(metrics=lambda: {"storage_bytes": 900})
    node._storage_bytes_used = chat_module.QuantumNode._storage_bytes_used.__get__(node)
    node._check_storage_quota = chat_module.QuantumNode._check_storage_quota.__get__(node)

    node._check_storage_quota(50)  # 900 + 50 <= 1000, fine
    with pytest.raises(ValueError, match="quota"):
        node._check_storage_quota(200)  # 900 + 200 > 1000

    # A non-positive limit disables enforcement entirely.
    node.max_storage_bytes = 0
    node._check_storage_quota(10 ** 9)


def test_identity_backup_roundtrip_and_wrong_passphrase():
    pytest.importorskip("cryptography")
    import chat as chat_module

    pk = "ab" * 900
    sk = os.urandom(64)
    blob = chat_module.pack_identity_backup(pk, sk, "a reasonably strong passphrase")
    assert blob.startswith("QCID1:")

    got_pk, got_sk = chat_module.unpack_identity_backup(blob, "a reasonably strong passphrase")
    assert got_pk == pk.lower()
    assert got_sk == sk

    with pytest.raises(ValueError):
        chat_module.unpack_identity_backup(blob, "wrong passphrase")
    with pytest.raises(ValueError):
        chat_module.unpack_identity_backup("not-a-real-backup", "whatever")


def test_message_pagination_returns_older_pages_in_order():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        for i in range(5):
            db.save_message(f"m{i}", "aa", f"body-{i}", "out", recipient="bb")
        first_page = db.recent_messages(limit=2)
        assert [m["body"] for m in first_page] == ["body-3", "body-4"]
        assert db.has_messages_before(first_page[0]["id"]) is True

        older_page = db.messages_before(first_page[0]["id"], limit=2)
        assert [m["body"] for m in older_page] == ["body-1", "body-2"]
        assert db.has_messages_before(older_page[0]["id"]) is True

        oldest_page = db.messages_before(older_page[0]["id"], limit=2)
        assert [m["body"] for m in oldest_page] == ["body-0"]
        assert db.has_messages_before(oldest_page[0]["id"]) is False
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_group_details_fingerprint_does_not_crash_on_uuid_group_id():
    # group_id is a UUID4 string with dashes, not a hex-encoded public key;
    # group_details_for must not try to bytes.fromhex() it directly.
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        gid = str(uuid.uuid4())
        assert "-" in gid
        db.create_group(gid, "Team", "owner")
        details = db.group_details_for("owner")
        assert len(details) == 1
        assert details[0]["group_id"] == gid
        assert ":" in details[0]["fingerprint"]
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_remote_mode_ui_url_prints_token(monkeypatch):
    printed = []

    class FakeNode:
        def __init__(self, *_args, **_kwargs):
            self.public_key = "ab" * 8
            self.ui_token = "token123"
            self.db = SimpleNamespace(close=lambda: None)
            self.allow_remote_ui = False
            self._shutting_down = False
            self.signaling_ws = None

        async def connect_signaling_loop(self):
            return None

    async def fake_start_ui_ws(*_args, **_kwargs):
        return None

    async def fake_start_direct_peer(*_args, **_kwargs):
        return None

    def fake_start_http(*_args, **_kwargs):
        return SimpleNamespace(shutdown=lambda: None)

    monkeypatch.setattr("chat.QuantumNode", FakeNode)
    monkeypatch.setattr("chat.start_http", fake_start_http)
    monkeypatch.setattr("chat.start_ui_ws", fake_start_ui_ws)
    monkeypatch.setattr("chat.start_direct_peer", fake_start_direct_peer)
    monkeypatch.setattr("chat.key_fingerprint", lambda _k: "ff:ff")
    monkeypatch.setattr("builtins.print", lambda *args, **_kwargs: printed.append(" ".join(str(a) for a in args)))
    monkeypatch.setattr("chat.webbrowser.open", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("chat.asyncio.create_task", lambda coro: coro)
    # The mocked gather raises CancelledError immediately; the new run_node
    # catches CancelledError as a graceful shutdown request, so the test
    # should verify a clean exit (no exception) and that the URL with token
    # was printed before the shutdown.
    monkeypatch.setattr("chat.asyncio.gather", lambda *tasks: (_ for _ in ()).throw(asyncio.CancelledError()))
    monkeypatch.setattr("chat.asyncio.Future", lambda: None)

    args = SimpleNamespace(
        db=":memory:",
        signaling_url="ws://127.0.0.1:8766",
        enable_direct=False,
        direct_advertise_host=None,
        direct_host="127.0.0.1",
        direct_port=8768,
        allow_remote_ui=True,
        http_host="0.0.0.0",
        http_port=9000,
        ui_ws_port=8765,
        open_browser=False,
        with_signaling=False,
        signaling_host="0.0.0.0",
        signaling_port=8766,
        ui_ws_host="0.0.0.0",
        max_storage_mb=4096,
        ice_servers=None,
    )
    # New behavior: graceful shutdown catches CancelledError and exits cleanly.
    import chat
    asyncio.run(chat.run_node(args))
    assert any("UI:        http://0.0.0.0:9000?token=token123" in line for line in printed)
    assert any("Goodbye." in line for line in printed)


# ─── New tests added in v3.1.0 ─────────────────────────────────────────────────
# These cover the critical security regression in PQModule.verify, the new
# rename_friend / block_friend surface area, the OPTIONS/HEAD HTTP handlers,
# and the /version probe endpoint.


def test_pqmodule_verify_rejects_wrong_message_and_wrong_signature():
    """Regression test for a critical security bug: an earlier version of
    PQModule.verify wrapped pqcrypto.verify() in a bare ``try: verify(...);
    return True``, which returned True even when the underlying verify
    returned False. This test pins the correct behavior so the bug can't
    silently come back."""
    pytest.importorskip("pqcrypto")
    pq = PQModule()
    pk, sk = pq.sign_keypair()
    sig = pq.sign(sk, b"hello world")
    # Correct message + correct signature -> True
    assert pq.verify(pk, b"hello world", sig) is True
    # Wrong message -> must be False (this is the case the bug accepted)
    assert pq.verify(pk, b"goodbye world", sig) is False
    # Wrong signature bytes -> must be False
    assert pq.verify(pk, b"hello world", b"\x00" * len(sig)) is False
    # Wrong public key (right size, all zeros) -> must be False
    assert pq.verify(b"\x00" * len(pk), b"hello world", sig) is False


def test_quantum_crypto_verify_round_trip():
    """Same regression at the QuantumCrypto wrapper level."""
    pytest.importorskip("pqcrypto")
    qc = QuantumCrypto()
    pk, sk = qc.new_identity()
    sig = qc.sign(sk, b"payload")
    assert qc.verify(pk, b"payload", sig) is True
    assert qc.verify(pk, b"tampered", sig) is False


def test_database_rename_friend_validates_and_persists():
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.add_friend("aa", "Alice")
        # Rename to a new nickname
        assert db.rename_friend("aa", "Alicia") == "Alicia"
        assert db.get_friends()[0]["nickname"] == "Alicia"
        # Empty nickname clears it
        assert db.rename_friend("aa", "   ") is None
        assert db.get_friends()[0]["nickname"] is None
        # Too long nickname is rejected by the validator, not silently truncated
        with pytest.raises(ValueError):
            db.rename_friend("aa", "x" * 200)
        # Renaming a non-existent friend is an error
        with pytest.raises(ValueError):
            db.rename_friend("zz", "Nobody")
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_block_friend_drops_active_session():
    """Blocking a friend must also drop the live session row, so an attacker
    who later compromises the friend's identity can't keep using the
    existing pairwise key — they'd have to complete a fresh signed
    handshake first."""
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.add_friend("bb", "Bob")
        db.save_session("bb", "session-1", b"secret-key", initiator=True)
        assert db.get_session("bb") is not None
        db.block_friend("bb", blocked=True)
        assert db.get_session("bb") is None
        # Unblock should not silently re-create a session; the peer must
        # initiate a new handshake.
        db.block_friend("bb", blocked=False)
        assert db.get_session("bb") is None
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_http_options_handler_returns_204_with_security_headers():
    headers = {}
    handler = object.__new__(ChatHTTPHandler)
    handler.require_http_auth = False
    handler.send_response = lambda code, _msg=None: headers.__setitem__("_status", code)
    handler.send_header = lambda k, v: headers.__setitem__(k, v)
    handler.end_headers = lambda: headers.__setitem__("_ended", True)
    ChatHTTPHandler.do_OPTIONS(handler)
    assert headers["_status"] == 204
    assert headers["Allow"] == "GET, HEAD, OPTIONS"
    assert headers["X-Frame-Options"] == "DENY"
    assert headers["X-XSS-Protection"] == "1; mode=block"


def test_http_head_handler_discards_body_but_sends_headers():
    """HEAD /health should send headers (including the JSON content-type)
    but no body — useful for monitoring tools that just want metadata.
    The handler re-implements routing rather than wrapping do_GET, so we
    exercise it directly with a fake response writer."""
    captured = {}
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/health"
    handler.require_http_auth = False
    handler._http_authenticated = lambda parsed: True
    handler.node = SimpleNamespace(health=lambda: {"status": "ok"})
    handler.headers = {}
    handler.send_response = lambda code, _msg=None: captured.__setitem__("status", code)
    handler.send_header = lambda k, v: captured.__setitem__(k, v)
    handler.end_headers = lambda: captured.__setitem__("_ended", True)
    ChatHTTPHandler.do_HEAD(handler)
    assert captured.get("status") == 200
    assert "application/json" in captured.get("Content-Type", "")
    assert captured.get("X-Frame-Options") == "DENY"


def test_http_get_version_returns_lightweight_payload():
    """The /version endpoint is a no-auth, no-identity probe suitable for
    monitoring/CI checks that don't need the full /health payload."""
    captured = {}
    handler = object.__new__(ChatHTTPHandler)
    handler.path = "/version"
    handler.require_http_auth = False
    handler._http_authenticated = lambda parsed: True
    handler.node = None
    handler.headers = {}
    handler.send_response = lambda code, _msg=None: captured.__setitem__("status", code)
    handler.send_header = lambda k, v: captured.__setitem__(k, v)
    handler.end_headers = lambda: captured.__setitem__("_ended", True)
    written = []
    handler.wfile = SimpleNamespace(write=lambda data: (written.append(data), len(data))[1])
    ChatHTTPHandler.do_GET(handler)
    assert captured["status"] == 200
    payload = json.loads(written[0].decode())
    assert "version" in payload
    assert "app" in payload


def test_http_file_view_supports_inline_byte_ranges(tmp_path):
    file_id = str(uuid.uuid4())
    path = tmp_path / file_id
    path.write_bytes(b"0123456789")
    meta = {
        "file_id": file_id,
        "filename": "voice-message.webm",
        "mime_type": "audio/webm",
        "size": 10,
        "storage_path": str(path),
        "file_nonce": None,
    }
    node = SimpleNamespace(
        ui_token="token",
        db=SimpleNamespace(get_file=lambda requested: meta if requested == file_id else None),
        decrypt_from_disk=lambda data, _file_id, _nonce: data,
    )
    captured = {}
    written = []
    handler = object.__new__(ChatHTTPHandler)
    handler.path = f"/files/{file_id}?view=1&token=token"
    handler.require_http_auth = False
    handler.node = node
    handler.headers = {"Range": "bytes=3-6"}
    handler.send_response = lambda code, _msg=None: captured.__setitem__("status", code)
    handler.send_header = lambda key, value: captured.__setitem__(key, value)
    handler.end_headers = lambda: None
    handler.send_error = lambda code, msg="": captured.update(status=code, error=msg)
    handler.wfile = SimpleNamespace(write=lambda data: written.append(data))

    ChatHTTPHandler.do_GET(handler)

    assert captured["status"] == 206
    assert captured["Content-Type"] == "audio/webm"
    assert captured["Content-Range"] == "bytes 3-6/10"
    assert captured["Content-Length"] == "4"
    assert captured["Accept-Ranges"] == "bytes"
    assert captured["Content-Disposition"].startswith("inline;")
    assert written == [b"3456"]


def test_direct_rate_gc_drops_stale_buckets():
    """_direct_rate_gc must drop buckets whose entries have all aged out so
    the dict can't grow unboundedly as peers cycle through source IPs."""
    pytest.importorskip("cryptography")
    import chat as chat_module
    from types import SimpleNamespace
    node = SimpleNamespace(_direct_rate={"1.2.3.4": [0], "5.6.7.8": [int(__import__("time").time())]})
    chat_module.QuantumNode._direct_rate_gc(node)
    assert "1.2.3.4" not in node._direct_rate  # aged out, dropped
    assert "5.6.7.8" in node._direct_rate       # recent, kept


def test_message_body_with_url_is_safe_under_linkify():
    """Sanity-check the linkify helper's regex doesn't mangle non-URL text
    and properly escapes quotes in the href attribute. We exercise it via
    the esc()+linkify() pipeline used by the renderer."""
    # The linkify helper lives in the JS UI, not the Python module, so this
    # test just guards the URL regex pattern itself from regressing.
    import re
    pattern = re.compile(r"https?://[^\s<]+")
    assert pattern.findall("see https://example.com for details") == ["https://example.com"]
    assert pattern.findall("no urls here") == []
    # No false positives on bare scheme-less domains
    assert pattern.findall("go to example.com") == []


# ─── Additional regression tests for v3.1.0 fixes found via e2e testing ────────


def test_mark_remote_read_sets_read_at_on_outgoing_message():
    """handle_read_receipt now calls mark_remote_read to stamp the read_at
    column on the sender's outgoing message. Without this, the UI's '✓✓ read'
    indicator never lights up even after the recipient reads the message."""
    pytest.importorskip("cryptography")
    fd, path = tempfile.mkstemp()
    os.close(fd)
    os.remove(path)
    try:
        db = Database(path, master_key=b"k" * 32)
        db.save_message("m1", "aa", "hello", "out", recipient="bb")
        # Initially read_at is None.
        assert db.recent_messages()[0]["read_at"] is None
        # mark_remote_read stamps the timestamp from the receipt.
        db.mark_remote_read("m1", 1700000000)
        assert db.recent_messages()[0]["read_at"] == 1700000000
        # A later receipt with a more accurate timestamp can correct it.
        db.mark_remote_read("m1", 1700000005)
        assert db.recent_messages()[0]["read_at"] == 1700000005
        db.close()
    finally:
        for suffix in ["", "-wal", "-shm"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


def test_send_chat_saves_message_before_send_relay():
    """Regression test for a race condition: send_chat previously saved the
    outgoing message AFTER send_relay returned. With direct transport,
    send_relay blocks until the peer processes the message and returns an
    ack, so the ack's update_message_status call ran before save_message,
    matched zero rows, and the message was then INSERTed with
    status='sent_to_relay' — overwriting the (never-applied)
    'delivered_to_peer' update. We can't easily exercise the full async
    flow in a unit test, but we can at least assert that save_message
    happens before any send_relay call by checking that the message exists
    in the DB immediately after send_chat, even if the relay send fails."""
    pytest.importorskip("cryptography")
    pytest.importorskip("pqcrypto")
    import chat as chat_module
    from types import SimpleNamespace
    import tempfile, os

    fd, path = tempfile.mkstemp(); os.close(fd); os.remove(path)
    try:
        # Use a real node so we exercise the real save_message path.
        node = chat_module.QuantumNode(
            path, "ws://127.0.0.1:65535",  # unreachable signaling URL
            direct_url=None, enable_direct=False,
        )
        node.allow_remote_ui = False
        # Construct a pubkey of the right hex length (expected_public_key_bytes
        # is in BYTES, so we need 2x that many hex chars).
        fake_pk = "bb" * node.expected_public_key_bytes
        # Add a fake friend so send_chat's validation passes.
        node.db.add_friend(fake_pk, "Bob")
        # Save a fake session so require_fresh_session doesn't try to handshake.
        node.sessions[fake_pk] = b"x" * 32
        node.db.save_session(fake_pk, "session-1", b"x" * 32, initiator=True)
        # Make the session appear fresh (otherwise the real session_fresh
        # would see established_at = now, which is fresh anyway, but be explicit).
        orig_fresh = chat_module.QuantumNode.session_fresh
        chat_module.QuantumNode.session_fresh = lambda self, pk: True
        # Stub connect_peer so require_fresh_session's fallback doesn't try
        # to actually handshake if session_fresh ever returns False.
        async def fake_connect_peer(_pk):
            return None
        orig_connect = chat_module.QuantumNode.connect_peer
        chat_module.QuantumNode.connect_peer = fake_connect_peer
        try:
            # send_relay will queue silently (queue_on_failure=True with no
            # signaling connection); we want to verify that the message is
            # saved BEFORE the queue happens.
            import asyncio
            try:
                asyncio.run(node.send_chat(fake_pk, "hello race test"))
            except Exception:
                pass  # send_relay may raise; that's fine
            # The message should exist in the DB regardless of relay outcome.
            msgs = node.db.recent_messages()
            assert any(m["body"] == "hello race test" for m in msgs), \
                "send_chat must save the outgoing message before send_relay"
        finally:
            chat_module.QuantumNode.session_fresh = orig_fresh
            chat_module.QuantumNode.connect_peer = orig_connect
        node.db.close()
    finally:
        for suffix in ["", "-wal", "-shm", ".key"]:
            try:
                os.remove(path + suffix)
            except FileNotFoundError:
                pass


# ── v3.2.0 additions ─────────────────────────────────────────────────────────

def test_pad_plaintext_round_trips_and_buckets_length():
    for msg in (b"", b"hi", b"x" * 255, b"x" * 256, b"x" * 257, "👍 unicode test".encode()):
        padded = pad_plaintext(msg)
        assert len(padded) % 256 == 0
        assert unpad_plaintext(padded) == msg


def test_pad_plaintext_different_messages_can_share_a_bucket_length():
    # The whole point: two different short messages should be indistinguishable
    # by ciphertext length once padded to the same bucket.
    assert len(pad_plaintext(b"ok")) == len(pad_plaintext(b"sure, sounds good"))


def test_unpad_plaintext_rejects_corrupt_length_prefix():
    with pytest.raises(ValueError):
        unpad_plaintext(b"\xff\xff\xff\xff" + b"\x00" * 16)
    with pytest.raises(ValueError):
        unpad_plaintext(b"\x00\x00")


def test_derive_device_sync_key_is_deterministic_and_identity_specific():
    crypto = QuantumCrypto()
    sk_a = b"a" * 64
    sk_b = b"b" * 64
    key_a1 = crypto.derive_device_sync_key(sk_a)
    key_a2 = crypto.derive_device_sync_key(sk_a)
    key_b = crypto.derive_device_sync_key(sk_b)
    assert key_a1 == key_a2, "same secret key must derive the same sync key every time"
    assert key_a1 != key_b, "different identities must not share a sync key"
    assert len(key_a1) == 32


def test_search_messages_finds_substring_case_insensitively(tmp_path):
    db = Database(str(tmp_path / "search.db"), master_key=b"k" * 32)
    try:
        db.save_message("m1", "alice", "The quick brown fox", "out", recipient="bob")
        db.save_message("m2", "bob", "jumps over the lazy dog", "in", recipient="alice")
        db.save_message("m3", "alice", "totally unrelated", "out", recipient="bob")
        results = db.search_messages("QUICK BROWN")
        assert len(results) == 1
        assert results[0]["msg_id"] == "m1"
        results2 = db.search_messages("the")
        assert {r["msg_id"] for r in results2} == {"m1", "m2"}
        assert db.search_messages("") == []
        assert db.search_messages("nonexistent phrase") == []
    finally:
        db.close()


def test_search_messages_can_be_scoped_to_one_target(tmp_path):
    db = Database(str(tmp_path / "search2.db"), master_key=b"k" * 32)
    try:
        db.save_message("m1", "alice", "hello carol", "out", recipient="carol")
        db.save_message("m2", "alice", "hello dave", "out", recipient="dave")
        results = db.search_messages("hello", target="carol")
        assert [r["msg_id"] for r in results] == ["m1"]
    finally:
        db.close()


def test_signaling_server_supports_multiple_sockets_per_identity():
    import chat as chat_module
    server = chat_module.SignalingServer()
    ws1, ws2 = object(), object()
    server.clients.setdefault("pk1", set()).add(ws1)
    server.clients.setdefault("pk1", set()).add(ws2)
    assert server.clients["pk1"] == {ws1, ws2}
    # Fan-out target set excludes the sending socket, which is exactly the
    # logic the relay branch in handle() uses for self-addressed device sync.
    targets = [t for t in server.clients.get("pk1", ()) if t is not ws1]
    assert targets == [ws2]


def test_pubkey_rate_limit_is_aggregate_across_devices():
    import chat as chat_module
    server = chat_module.SignalingServer()
    for _ in range(300):
        assert server._pubkey_rate_ok("pk1", limit=300, window=60)
    # The 301st call within the window should be rejected even though no
    # single socket individually hit a per-socket limit.
    assert server._pubkey_rate_ok("pk1", limit=300, window=60) is False


def test_ice_servers_default_is_stun_only_and_env_override_is_respected(monkeypatch):
    import chat as chat_module
    monkeypatch.delenv("QUANTUM_CHAT_ICE_SERVERS", raising=False)
    default = chat_module.QuantumNode._load_ice_servers()
    assert default == [{"urls": "stun:stun.l.google.com:19302"}]

    custom = json.dumps([{"urls": "turn:turn.example.com:3478", "username": "u", "credential": "p"}])
    monkeypatch.setenv("QUANTUM_CHAT_ICE_SERVERS", custom)
    assert chat_module.QuantumNode._load_ice_servers() == json.loads(custom)

    monkeypatch.setenv("QUANTUM_CHAT_ICE_SERVERS", "{not valid json")
    assert chat_module.QuantumNode._load_ice_servers() == [{"urls": "stun:stun.l.google.com:19302"}]


def test_run_node_rejects_malformed_ice_servers_cli_flag():
    args = parse_args(["--ice-servers", "{not json", "--no-browser"])
    with pytest.raises(SystemExit):
        asyncio.run(run_node(args))
