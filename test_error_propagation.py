"""Tests for error surfacing: failures that used to be swallowed silently
must now either propagate to the caller or leave a log record behind."""

from __future__ import annotations

import asyncio
import logging
import uuid
from pathlib import Path
from types import SimpleNamespace

import pytest

from chat import ChatHTTPHandler, Database, LocalKeyStore


def test_unknown_relay_payload_kind_is_logged_and_ignored(caplog):
    """An unrecognized payload kind used to fall off the end of the dispatch
    chain without a trace. Raising on it would tear down the whole signaling
    connection whenever a newer peer sends an extension frame, so unknown
    kinds are now ignored for forward compatibility — but visibly: a warning
    reaches the log instead of the frame vanishing silently."""
    pytest.importorskip("cryptography")
    pytest.importorskip("pqcrypto")
    import chat as chat_module

    node = chat_module.QuantumNode(":memory:", "ws://127.0.0.1:65535", direct_url=None, enable_direct=False)
    try:
        peer, _ = node.crypto.new_identity()
        with caplog.at_level(logging.WARNING, logger="quantum_chat"):
            asyncio.run(node.handle_relay_payload(peer.hex(), {"kind": "not_a_real_kind"}))
        assert any("not_a_real_kind" in r.getMessage() and "unsupported relay payload kind" in r.getMessage().lower()
                   for r in caplog.records)
    finally:
        node.db.close()


def test_search_reports_rows_it_could_not_decrypt(tmp_path, caplog):
    """search_messages skips undecryptable rows so one bad row can't hide the
    rest of the history, but the skip has to be visible: those rows are
    silently absent from every search result otherwise."""
    pytest.importorskip("cryptography")
    db_path = str(tmp_path / "search.db")
    db = Database(db_path, master_key=b"k" * 32)
    try:
        db.save_message(str(uuid.uuid4()), "aa", "findable needle", "in", recipient="bb")
        corrupt_id = str(uuid.uuid4())
        db.save_message(corrupt_id, "aa", "also a needle", "in", recipient="bb")
        with db.lock:
            db.conn.execute("UPDATE messages SET body=? WHERE msg_id=?", (b"\x00" * 32, corrupt_id))
            db.conn.commit()

        with caplog.at_level(logging.WARNING, logger="quantum_chat"):
            results = db.search_messages("needle")

        assert [r["body"] for r in results] == ["findable needle"]
        assert any("could not be decrypted" in r.getMessage() for r in caplog.records)
    finally:
        db.close()


def test_key_file_warns_when_permissions_cannot_be_restricted(tmp_path, monkeypatch, caplog):
    """chmod is a no-op on some filesystems so it can't be fatal, but a
    failure means the local encryption key may be world-readable."""
    pytest.importorskip("cryptography")

    def refuse_chmod(*_args, **_kwargs):
        raise OSError("chmod unsupported")

    monkeypatch.setattr("chat.os.chmod", refuse_chmod)
    store = LocalKeyStore(str(tmp_path / "perm.db"))
    with caplog.at_level(logging.WARNING, logger="quantum_chat"):
        key = store.load_or_create()

    assert len(key) == 32
    assert store.path.exists()
    assert any("Could not restrict permissions" in r.getMessage() for r in caplog.records)


def test_chunk_cleanup_only_credits_bytes_it_actually_freed(tmp_path, monkeypatch, caplog):
    """A shard that can't be unlinked must not be counted as reclaimed, or the
    storage-quota counter drifts below real disk usage on every failure."""
    pytest.importorskip("cryptography")
    pytest.importorskip("pqcrypto")
    import chat as chat_module

    db_path = str(tmp_path / "chunks.db")
    node = chat_module.QuantumNode(db_path, "ws://127.0.0.1:65535", direct_url=None, enable_direct=False)
    try:
        file_id = str(uuid.uuid4())
        chunk_dir = node.files_dir / f"{file_id}.chunks"
        chunk_dir.mkdir(parents=True, exist_ok=True)
        shard = chunk_dir / "0"
        shard.write_bytes(b"x" * 100)
        node.db.save_file_chunk(file_id, 0, 1, str(shard), None)
        node._track_storage(100)
        before = node._storage_bytes_used()

        real_unlink = Path.unlink

        def refuse_unlink(self, *args, **kwargs):
            if self == shard:
                raise OSError("device busy")
            return real_unlink(self, *args, **kwargs)

        monkeypatch.setattr(Path, "unlink", refuse_unlink)
        with caplog.at_level(logging.WARNING, logger="quantum_chat"):
            node._cleanup_file_chunks(file_id, node.db.file_chunks(file_id))

        assert node._storage_bytes_used() == before
        assert any("Could not delete chunk shard" in r.getMessage() for r in caplog.records)
    finally:
        node.db.close()


def test_http_file_serving_reports_decrypt_failure_as_500(tmp_path):
    """A decrypt failure escaped into BaseHTTPRequestHandler, which closes the
    connection without a status line; the browser then blames the network."""
    file_id = str(uuid.uuid4())
    path = tmp_path / file_id
    path.write_bytes(b"ciphertext")
    meta = {
        "file_id": file_id,
        "filename": "secret.bin",
        "mime_type": "application/octet-stream",
        "size": 10,
        "storage_path": str(path),
        "file_nonce": None,
    }

    def boom(*_args, **_kwargs):
        raise ValueError("bad tag")

    handler = object.__new__(ChatHTTPHandler)
    handler.path = f"/files/{file_id}?token=token"
    handler.require_http_auth = False
    handler.node = SimpleNamespace(
        ui_token="token",
        db=SimpleNamespace(get_file=lambda requested: meta if requested == file_id else None),
        decrypt_from_disk=boom,
    )
    handler.headers = {}
    captured = {}
    handler.send_response = lambda code, _msg=None: captured.__setitem__("status", code)
    handler.send_header = lambda key, value: captured.__setitem__(key, value)
    handler.end_headers = lambda: None
    handler.send_error = lambda code, msg="": captured.update(status=code, error=msg)
    handler.wfile = SimpleNamespace(write=lambda data: len(data))

    ChatHTTPHandler.do_GET(handler)

    assert captured["status"] == 500
    assert "decrypted" in captured["error"]


def test_ui_command_bug_is_logged_with_traceback(caplog):
    """Unexpected exceptions from a UI command are bugs, not bad input: the UI
    still gets a notice, but the traceback has to reach the log."""

    class FakeWS:
        def __init__(self, frames):
            self._frames = frames
            self.sent = []

        def __aiter__(self):
            async def gen():
                for frame in self._frames:
                    yield frame
            return gen()

        async def send(self, payload):
            self.sent.append(payload)

    import chat as chat_module

    node = object.__new__(chat_module.QuantumNode)
    node.ui_clients = set()
    node._ui_authenticated = lambda _ws: True
    node.state_payload = lambda: {"type": "state"}

    async def explode(_ws, _msg):
        raise ZeroDivisionError("bug in a handler")

    node._dispatch_ui = explode
    ws = FakeWS(['{"type": "refresh"}'])

    with caplog.at_level(logging.ERROR, logger="quantum_chat"):
        asyncio.run(chat_module.QuantumNode.handle_ui(node, ws))

    assert any("Internal error: ZeroDivisionError" in frame for frame in ws.sent)
    assert any(r.exc_info for r in caplog.records)
