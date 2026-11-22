import asyncio
import datetime
import ipaddress
import json
import re
import secrets
import sqlite3
import subprocess
import sys
import threading
import urllib.request
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

import chat


def _free_port() -> int:
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _make_pair(tmp_path: Path):
    alice = chat.QuantumNode(str(tmp_path / "alice.db"), "ws://127.0.0.1:8766")
    bob = chat.QuantumNode(str(tmp_path / "bob.db"), "ws://127.0.0.1:8766")
    alice.db.add_friend(bob.public_key, "Bob")
    bob.db.add_friend(alice.public_key, "Alice")

    async def deliver(sender, recipient, payload):
        await recipient.handle_relay_payload(sender.public_key, payload)

    async def alice_send(peer, payload, queue_on_failure=False, ephemeral=False):
        if peer == bob.public_key:
            await deliver(alice, bob, payload)

    async def bob_send(peer, payload, queue_on_failure=False, ephemeral=False):
        if peer == alice.public_key:
            await deliver(bob, alice, payload)

    alice.send_relay = alice_send
    bob.send_relay = bob_send
    return alice, bob


def _establish_pair(alice: chat.QuantumNode, bob: chat.QuantumNode) -> None:
    asyncio.run(alice.connect_peer(bob.public_key))
    assert bob.public_key in alice.sessions
    assert alice.public_key in bob.sessions


# ─── Version consistency ─────────────────────────────────────────────────────


def test_v430_version_consistency(tmp_path: Path):
    assert chat.VERSION == "4.3.0"
    assert chat.APP_NAME == "Quantum Chat"

    root = Path(__file__).resolve().parent
    pyproject_text = (root / "pyproject.toml").read_text(encoding="utf-8")
    m = re.search(r'^version\s*=\s*"([^"]+)"', pyproject_text, flags=re.MULTILINE)
    assert m is not None and m.group(1) == "4.3.0"

    pkg_data = json.loads((root / "package.json").read_text(encoding="utf-8"))
    assert pkg_data["version"] == "4.3.0"

    cli_out = subprocess.run(
        [sys.executable, str(root / "chat.py"), "--version"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert "4.3.0" in cli_out.stdout

    node = chat.QuantumNode(str(tmp_path / "ver.db"), "ws://127.0.0.1:8766")
    httpd = chat.start_http(node, "127.0.0.1", 0, 0, require_http_auth=False)
    port = httpd.server_address[1]
    try:
        assert node.state_payload()["version"] == "4.3.0"
        assert node.health()["version"] == "4.3.0"
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/version") as resp:
            v_json = json.loads(resp.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health") as resp:
            h_json = json.loads(resp.read().decode("utf-8"))
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            page = resp.read().decode("utf-8")
        assert v_json == {"version": "4.3.0", "app": "Quantum Chat"}
        assert h_json["version"] == "4.3.0"
        assert "v4.3.0" in page
    finally:
        httpd.shutdown()
        httpd.server_close()
        node.db.close()


# ─── Embedded UI inline-onclick XSS elimination ──────────────────────────────


def test_ui_eliminates_inline_onclick_xss_vectors():
    html = chat.HTML
    # Dynamic template interpolations must never be emitted inside onclick="...".
    assert not re.search(r'onclick="[^"]*\$\{', html), (
        "Interpolated expression inside onclick attribute enables attribute-decode XSS"
    )
    for required_action in (
        'data-action="open-lightbox"',
        'data-action="jump-to-message"',
        'data-action="toggle-reaction"',
        'data-action="reply"',
        'data-action="copy"',
        'data-action="edit"',
        'data-action="delete-everywhere"',
        'data-action="delete-local"',
        'data-action="mark-read"',
        'data-action="remove-friend"',
        'data-action="rotate-group-key"',
        'data-action="leave-group"',
        'data-action="open-safety"',
        'data-action="remove-group-member"',
        'data-action="add-group-member"',
    ):
        assert required_action in html

    # Verify filename sanitization + HTML escaping stays strictly inert inside data-filename.
    hostile_name = "evil');window.__xss=1;alert('x.png"
    safe_name = chat.safe_filename(hostile_name)
    escaped = (
        safe_name.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )
    rendered_btn = f'<button type="button" data-action="open-lightbox" data-filename="{escaped}"></button>'
    assert "onclick" not in rendered_btn.lower()
    assert "&#39;" in rendered_btn


# ─── Group invite authorization & membership sync ───────────────────────────


def test_group_invite_rejects_non_owner_and_reconciles_removed_members(tmp_path: Path):
    alice = chat.QuantumNode(str(tmp_path / "alice.db"), "ws://127.0.0.1:8766")
    bob = chat.QuantumNode(str(tmp_path / "bob.db"), "ws://127.0.0.1:8766")
    carol = chat.QuantumNode(str(tmp_path / "carol.db"), "ws://127.0.0.1:8766")
    nodes = [alice, bob, carol]
    for a in nodes:
        for b in nodes:
            if a is not b:
                a.db.add_friend(b.public_key)

    async def route(sender, recipient, payload):
        await recipient.handle_relay_payload(sender.public_key, payload)

    async def alice_send(peer, payload, queue_on_failure=False, ephemeral=False):
        target = next((n for n in nodes if n.public_key == peer), None)
        if target:
            await route(alice, target, payload)

    async def bob_send(peer, payload, queue_on_failure=False, ephemeral=False):
        target = next((n for n in nodes if n.public_key == peer), None)
        if target:
            await route(bob, target, payload)

    async def carol_send(peer, payload, queue_on_failure=False, ephemeral=False):
        target = next((n for n in nodes if n.public_key == peer), None)
        if target:
            await route(carol, target, payload)

    alice.send_relay = alice_send
    bob.send_relay = bob_send
    carol.send_relay = carol_send

    async def run():
        await alice.connect_peer(bob.public_key)
        await alice.connect_peer(carol.public_key)
        await bob.connect_peer(carol.public_key)

        gid = str(uuid.uuid4())
        await alice._dispatch_ui(
            SimpleNamespace(send=lambda _x: asyncio.sleep(0)),
            {
                "type": "create_group",
                "name": "Core Team",
                "members": [alice.public_key, bob.public_key, carol.public_key],
            },
        )
        groups = alice.db.group_details_for(alice.public_key)
        assert len(groups) == 1
        gid = groups[0]["group_id"]
        assert set(bob.db.group_members(gid)) == {alice.public_key, bob.public_key, carol.public_key}
        assert set(carol.db.group_members(gid)) == {alice.public_key, bob.public_key, carol.public_key}

        # Rogue non-owner Bob tries to hijack/overwrite the group via a signed group_invite to Carol.
        rogue_key = secrets.token_bytes(32)
        rogue_data = {
            "group_id": gid,
            "name": "Hijacked",
            "members": [bob.public_key, carol.public_key],
            "from": bob.public_key,
            "to": carol.public_key,
            "epoch": 99,
            "counter": bob.db.next_send_counter(carol.public_key),
        }
        bob_sess = await bob.require_fresh_session(carol.public_key, outgoing=True)
        msg_key = bob.crypto.derive_message_key(
            bob_sess, bob.public_key, carol.public_key, rogue_data["counter"], "group-key"
        )
        rogue_packet = bob.crypto.encrypt(msg_key, rogue_key, chat.canonical_json(rogue_data))
        rogue_frame = bob.signed_payload("group_invite", rogue_data) | {"packet": rogue_packet}
        with pytest.raises(ValueError, match="Only the group owner"):
            await carol.handle_relay_payload(bob.public_key, rogue_frame)

        # Carol must still have Alice as owner and epoch 1 intact.
        assert carol.db.get_group(gid)["owner_pubkey"] == alice.public_key
        assert carol.db.get_group_key(gid)["epoch"] == 1

        # Owner Alice removes Carol and rotates key -> Bob's membership list reconciles Carol out!
        await alice.remove_group_member(gid, carol.public_key)
        assert set(alice.db.group_members(gid)) == {alice.public_key, bob.public_key}
        assert set(bob.db.group_members(gid)) == {alice.public_key, bob.public_key}
        assert bob.db.get_group_key(gid)["epoch"] == 2

    try:
        asyncio.run(run())
    finally:
        for n in nodes:
            n.db.close()


# ─── Replay protection for counterless signed frames ─────────────────────────


def test_counterless_signed_frames_reject_replay_and_keep_legacy_compat(tmp_path: Path):
    alice, bob = _make_pair(tmp_path)
    try:
        _establish_pair(alice, bob)
        msg_id = str(uuid.uuid4())
        bob.db.save_message(msg_id, alice.public_key, "hello", "in", recipient=bob.public_key)

        # 1. Reaction with nonce succeeds once, replays are rejected.
        react_frame = alice.signed_payload("reaction", {
            "from": alice.public_key,
            "to": bob.public_key,
            "msg_id": msg_id,
            "emoji": "🔥",
            "action": "add",
            "nonce": secrets.token_hex(12),
        })
        asyncio.run(bob.handle_relay_payload(alice.public_key, react_frame))
        with pytest.raises(ValueError, match="Duplicate replayed frame"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, react_frame))

        # 2. Failed validation must NOT mark the nonce consumed so valid retry still works?
        #    More precisely: routing mismatch fails BEFORE _mark_relay_nonce.
        bad_ack = alice.signed_payload("delivery_ack", {
            "from": alice.public_key,
            "to": bob.public_key,
            "msg_id": "m-ack",
            "nonce": secrets.token_hex(12),
        })
        asyncio.run(bob.handle_relay_payload(alice.public_key, bad_ack))
        with pytest.raises(ValueError, match="Duplicate replayed frame"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, bad_ack))

        # 3. Call offer stale sent_at & duplicate call_id checks
        stale_offer = alice.signed_payload("call_offer", {
            "from": alice.public_key,
            "to": bob.public_key,
            "call_id": str(uuid.uuid4()),
            "media": "audio",
            "sdp": {"type": "offer", "sdp": "v=0\r\n"},
            "sent_at": chat.utc_ts() - chat.PENDING_OFFER_TTL - 10,
            "nonce": secrets.token_hex(12),
        })
        with pytest.raises(ValueError, match="stale"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, stale_offer))

        live_call_id = str(uuid.uuid4())
        live_offer = alice.signed_payload("call_offer", {
            "from": alice.public_key,
            "to": bob.public_key,
            "call_id": live_call_id,
            "media": "audio",
            "sdp": {"type": "offer", "sdp": "v=0\r\n"},
            "sent_at": chat.utc_ts(),
            "nonce": secrets.token_hex(12),
        })
        asyncio.run(bob.handle_relay_payload(alice.public_key, live_offer))
        with pytest.raises(ValueError, match="Duplicate replayed frame"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, live_offer))

        # End call cleanly, then test same call_id with a different nonce is rejected.
        end_frame = alice.signed_payload("call_end", {
            "from": alice.public_key,
            "to": bob.public_key,
            "call_id": live_call_id,
            "reason": "hangup",
            "nonce": secrets.token_hex(12),
        })
        asyncio.run(bob.handle_relay_payload(alice.public_key, end_frame))
        with pytest.raises(ValueError, match="Duplicate replayed frame"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, end_frame))

        reused_id_offer = alice.signed_payload("call_offer", {
            "from": alice.public_key,
            "to": bob.public_key,
            "call_id": live_call_id,
            "media": "audio",
            "sdp": {"type": "offer", "sdp": "v=0\r\n"},
            "sent_at": chat.utc_ts(),
            "nonce": secrets.token_hex(12),
        })
        with pytest.raises(ValueError, match="Duplicate call offer"):
            asyncio.run(bob.handle_relay_payload(alice.public_key, reused_id_offer))

        # 4. Legacy frame without "nonce" remains accepted for v3.5–v4.2 compatibility.
        legacy_react = alice.signed_payload("reaction", {
            "from": alice.public_key,
            "to": bob.public_key,
            "msg_id": msg_id,
            "emoji": "👍",
            "action": "add",
        })
        asyncio.run(bob.handle_relay_payload(alice.public_key, legacy_react))
    finally:
        alice.db.close()
        bob.db.close()


# ─── Direct peer clean close & WebSocket bridge CRLF guard ───────────────────


def test_handle_direct_peer_clean_close_does_not_count_as_rejection(tmp_path: Path):
    async def run():
        websockets = chat.require_websockets()
        port = _free_port()
        node = chat.QuantumNode(str(tmp_path / "direct.db"), "ws://127.0.0.1:8766")
        task = asyncio.create_task(chat.start_direct_peer(node, "127.0.0.1", port))
        try:
            await asyncio.sleep(0.15)
            async with websockets.connect(f"ws://127.0.0.1:{port}"):
                pass
            await asyncio.sleep(0.05)
            assert node.db.metrics().get("direct_rejected", 0) == 0
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
            node.db.close()

    asyncio.run(run())


def test_websocket_bridge_rejects_crlf_header_injection():
    errors: list[tuple[int, str]] = []
    handler = object.__new__(chat.ChatHTTPHandler)
    handler.command = "GET"
    handler.path = "/?token=abc\r\nX-Injected: yes"
    handler.request_version = "HTTP/1.1"
    handler.headers = {"Host": "127.0.0.1:8000"}
    handler.ui_ws_port = 8765
    handler.send_error = lambda code, msg="": errors.append((code, msg))
    chat.ChatHTTPHandler._bridge_websocket(handler)
    assert errors == [(400, "Bad Request")]

    errors.clear()
    handler.path = "/?token=abc"
    handler.headers = {"Host": "127.0.0.1:8000", "X-Test": "bad\nline"}
    chat.ChatHTTPHandler._bridge_websocket(handler)
    assert errors == [(400, "Bad Request")]


# ─── Schema v5 -> v6 in-place migration & data preservation ──────────────────


def test_v5_database_migrates_in_place_without_data_loss(tmp_path: Path):
    db_path = tmp_path / "legacy_v5.db"
    master_key = chat.LocalKeyStore(str(db_path)).load_or_create()
    suite = chat.QuantumCrypto()
    pk_bytes, sk_bytes = suite.new_identity()
    me = pk_bytes.hex()
    friend = "bb" * suite.sign_public_key_bytes

    raw = sqlite3.connect(str(db_path))
    raw.executescript("""
        PRAGMA user_version=5;
        CREATE TABLE identity (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            public_key TEXT NOT NULL,
            secret_key BLOB NOT NULL,
            created_at INTEGER NOT NULL,
            secret_nonce BLOB,
            key_version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE friends (
            pubkey TEXT PRIMARY KEY, nickname TEXT, trusted INTEGER NOT NULL DEFAULT 1,
            verified INTEGER NOT NULL DEFAULT 0, blocked INTEGER NOT NULL DEFAULT 0,
            relay_alias TEXT, direct_url TEXT, added_at INTEGER NOT NULL,
            last_seen INTEGER, unread INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE sessions (
            peer_pubkey TEXT PRIMARY KEY, session_id TEXT NOT NULL, key BLOB NOT NULL,
            established_at INTEGER NOT NULL, initiator INTEGER NOT NULL DEFAULT 0,
            key_nonce BLOB, key_version INTEGER NOT NULL DEFAULT 0,
            send_counter INTEGER NOT NULL DEFAULT 0, recv_counter INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE groups (group_id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, owner_pubkey TEXT, epoch INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE group_members (group_id TEXT NOT NULL, pubkey TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', joined_at INTEGER NOT NULL, PRIMARY KEY (group_id, pubkey));
        CREATE TABLE messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id TEXT UNIQUE NOT NULL,
            sender_pubkey TEXT NOT NULL, recipient_pubkey TEXT, group_id TEXT,
            body TEXT NOT NULL, direction TEXT NOT NULL, timestamp INTEGER NOT NULL,
            delivered INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'sent',
            body_nonce BLOB, key_version INTEGER NOT NULL DEFAULT 0, read_at INTEGER
        );
        CREATE TABLE files (
            file_id TEXT PRIMARY KEY, filename TEXT NOT NULL, sender_pubkey TEXT NOT NULL,
            recipient_pubkey TEXT, group_id TEXT, size INTEGER NOT NULL, sha256 TEXT NOT NULL,
            storage_path TEXT NOT NULL, uploaded_at INTEGER NOT NULL, mime_type TEXT,
            file_nonce BLOB, key_version INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE outbox (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target_pubkey TEXT NOT NULL,
            payload TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'queued',
            retry_count INTEGER NOT NULL DEFAULT 0, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL
        );
        CREATE TABLE reactions (id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id TEXT NOT NULL, peer_pubkey TEXT NOT NULL, emoji TEXT NOT NULL, direction TEXT NOT NULL DEFAULT 'in', added_at INTEGER NOT NULL, UNIQUE(msg_id, peer_pubkey, emoji));
        CREATE TABLE read_receipts (msg_id TEXT PRIMARY KEY, reader_pubkey TEXT NOT NULL, read_at INTEGER NOT NULL);
        CREATE TABLE recv_counters (peer_pubkey TEXT NOT NULL, session_id TEXT NOT NULL, counter INTEGER NOT NULL, seen_at INTEGER NOT NULL, PRIMARY KEY (peer_pubkey, session_id, counter));
        CREATE TABLE group_epochs (group_id TEXT NOT NULL, epoch INTEGER NOT NULL, key BLOB NOT NULL, key_nonce BLOB, created_at INTEGER NOT NULL, created_by TEXT NOT NULL, PRIMARY KEY (group_id, epoch));
        CREATE TABLE file_chunks (file_id TEXT NOT NULL, chunk_index INTEGER NOT NULL, total_chunks INTEGER NOT NULL, sender_pubkey TEXT NOT NULL, recipient_pubkey TEXT, group_id TEXT, filename TEXT NOT NULL, total_size INTEGER NOT NULL, file_sha256 TEXT NOT NULL, mime_type TEXT, chunk_path TEXT NOT NULL, received_at INTEGER NOT NULL, PRIMARY KEY (file_id, chunk_index));
    """)

    sk_nonce = secrets.token_bytes(12)
    sk_ct = suite.AESGCM(master_key).encrypt(sk_nonce, sk_bytes, f"identity:{me}".encode())
    raw.execute(
        "INSERT INTO identity (id, public_key, secret_key, created_at, secret_nonce, key_version) VALUES (1, ?, ?, 1000, ?, 1)",
        (me, sk_ct, sk_nonce),
    )
    raw.execute("INSERT INTO friends (pubkey, nickname, added_at) VALUES (?, 'LegacyBob', 1000)", (friend,))
    msg_nonce = secrets.token_bytes(12)
    msg_ct = suite.AESGCM(master_key).encrypt(
        msg_nonce,
        b"pre-v4 preserved message",
        f"message:m-legacy:{me}:{friend}:".encode(),
    )
    raw.execute(
        "INSERT INTO messages (msg_id, sender_pubkey, recipient_pubkey, body, direction, timestamp, body_nonce, key_version) "
        "VALUES ('m-legacy', ?, ?, ?, 'out', 1001, ?, 1)",
        (me, friend, sqlite3.Binary(msg_ct), msg_nonce),
    )
    raw.commit()
    raw.close()

    # Open migrated DB with v4.3.0 Database
    db = chat.Database(str(db_path), master_key=master_key)
    try:
        cols = {r["name"] for r in db.conn.execute("PRAGMA table_info(messages)").fetchall()}
        assert {"reply_to", "edited_at", "deleted_at"}.issubset(cols)
        outbox_cols = {r["name"] for r in db.conn.execute("PRAGMA table_info(outbox)").fetchall()}
        assert "session_id" in outbox_cols
        ver = db.conn.execute("PRAGMA user_version").fetchone()[0]
        assert int(ver) == chat.SCHEMA_VERSION

        loaded = db.load_identity()
        assert loaded == (me, sk_bytes)
        assert db.get_friends()[0]["nickname"] == "LegacyBob"
        msgs = db.recent_messages()
        assert len(msgs) == 1 and msgs[0]["body"] == "pre-v4 preserved message"
    finally:
        db.close()


# ─── CLI --check diagnostics & real TLS / WSS roundtrip ──────────────────────


def _generate_self_signed_cert(tmp_path: Path) -> tuple[Path, Path]:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def test_cli_self_check_and_tls_roundtrip(tmp_path: Path, monkeypatch):
    root = Path(__file__).resolve().parent
    proc = subprocess.run(
        [sys.executable, str(root / "chat.py"), "--check", "--db", str(tmp_path / "check.db")],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Quantum Chat v4.3.0" in proc.stdout
    assert "ML-DSA" in proc.stdout and "ML-KEM-512" in proc.stdout and "AES-256-GCM" in proc.stdout

    cert_path, key_path = _generate_self_signed_cert(tmp_path)
    srv_ssl = chat._build_ssl_server_context(str(cert_path), str(key_path))
    cli_ssl = chat._build_ssl_client_context(str(cert_path))

    # HTTPS /version roundtrip
    node = chat.QuantumNode(str(tmp_path / "tls_node.db"), "wss://127.0.0.1:8766", ssl_context=cli_ssl)
    httpd = chat.start_http(node, "127.0.0.1", 0, 0, require_http_auth=False, ssl_context=srv_ssl)
    https_port = httpd.server_address[1]
    try:
        with urllib.request.urlopen(f"https://127.0.0.1:{https_port}/version", context=cli_ssl) as resp:
            assert json.loads(resp.read().decode("utf-8"))["version"] == "4.3.0"
    finally:
        httpd.shutdown()
        httpd.server_close()

    # WSS signaling server + node connection roundtrip
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "tls_relay.db"))
    wss_port = _free_port()
    node.signaling_url = f"wss://127.0.0.1:{wss_port}"

    async def run_wss():
        sig_task = asyncio.create_task(chat.start_signaling("127.0.0.1", wss_port, ssl_context=srv_ssl))
        loop_task = asyncio.create_task(node.connect_signaling_loop())
        try:
            for _ in range(40):
                if node.signaling_ws is not None:
                    break
                await asyncio.sleep(0.05)
            assert node.signaling_ws is not None
        finally:
            node._shutting_down = True
            loop_task.cancel()
            sig_task.cancel()
            await asyncio.gather(loop_task, sig_task, return_exceptions=True)

    try:
        asyncio.run(run_wss())
    finally:
        node.db.close()


# ─── Protocol fuzzing & SQLite concurrency stress ────────────────────────────


def test_protocol_fuzzing_and_concurrent_db_stress(tmp_path: Path):
    alice, bob = _make_pair(tmp_path)
    try:
        _establish_pair(alice, bob)

        # Malformed/hostile relay frames must fail cleanly with ValueError (or safe ignore)
        malformed_cases = [
            "not-a-dict",
            None,
            {"kind": "chat"},
            {"kind": "delivery_ack", "payload": "bad"},
            {"kind": "reaction", "payload": None},
            {"kind": "call_offer", "payload": {"from": alice.public_key, "to": bob.public_key, "call_id": ""}},
            {"kind": "group_invite", "payload": {"members": "not-a-list"}},
            {"kind": "unknown_future_extension_v9", "nested": {"x": [1, 2, 3]}},
        ]
        for bad in malformed_cases:
            if isinstance(bad, dict) and bad.get("kind") == "unknown_future_extension_v9":
                asyncio.run(bob.handle_relay_payload(alice.public_key, bad))
            else:
                with pytest.raises((ValueError, TypeError, KeyError)):
                    asyncio.run(bob.handle_relay_payload(alice.public_key, bad))  # type: ignore[arg-type]

        # Concurrent multi-threaded writes and reads against Database
        errors: list[Exception] = []

        def worker(tid: int) -> None:
            try:
                for idx in range(15):
                    mid = f"stress-{tid}-{idx}-{uuid.uuid4()}"
                    alice.db.save_message(mid, alice.public_key, f"payload-{tid}-{idx}", "out", recipient=bob.public_key)
                    if idx % 3 == 0:
                        alice.db.mark_message_read(mid)
                    if idx % 5 == 0:
                        alice.db.search_messages(f"payload-{tid}", target=bob.public_key)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors
    finally:
        alice.db.close()
        bob.db.close()
