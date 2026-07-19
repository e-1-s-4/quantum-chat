#!/usr/bin/env python3
"""
Quantum Chat v3.2.0 — production-oriented post-quantum end-to-end encrypted P2P chat.

New in v3.2.0:
- Multi-device sync: message history and read state sync between devices
  that share one identity, over a relay that now supports multiple live
  connections per identity
- Voice/video calls: WebRTC signaling (offer/answer/ICE) carried over the
  same PQ-authenticated relay/direct channel as everything else
- Full-text message search across 1:1 and group history
- Chat message padding to reduce ciphertext-length metadata leakage to the
  relay/network observers
- Per-identity relay rate limiting; ephemeral (non-persisted) relay envelopes
  for typing/ICE/device-sync traffic
- Parallelized group message fan-out and file-chunk transfer

New in v3.1.0:
- Critical signature verification fix
- Delivery-ack ordering and read-receipt timestamp fixes

New in v2.0:
- Typing indicators (ephemeral relay)
- Read receipts (signed, persisted)
- Emoji reactions (signed, persisted)
- Per-friend unread message counts
- Session TTL tracking and expiry warnings
- Exponential backoff reconnection
- /health HTTP endpoint
- Configurable log level (--log-level)
- Completely redesigned dark UI with image previews, drag-drop, notifications
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import hashlib
import inspect
import json
import logging
import mimetypes
import os
import re
import secrets
import sqlite3
import threading
import time
import uuid
import webbrowser
from dataclasses import dataclass
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import quote, urlparse, parse_qs
from typing import Any, Dict, List, Optional, Set, Tuple

APP_NAME = "Quantum Chat"
VERSION = "3.2.0"
DB_FILE = "quantum_chat.db"
FILES_DIR = "files"
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8000
UI_WS_HOST = "127.0.0.1"
UI_WS_PORT = 8765
SIGNALING_HOST = "0.0.0.0"
SIGNALING_PORT = 8766
DEFAULT_SIGNALING_URL = "ws://127.0.0.1:8766"
MAX_TEXT_BYTES = 64 * 1024
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_CHUNK_BYTES = 512 * 1024
DIRECT_PEER_HOST = "127.0.0.1"
DIRECT_PEER_PORT = 8768
PENDING_OFFER_TTL = 5 * 60
SESSION_TTL = 24 * 3600           # 24-hour session key lifetime
SESSION_WARN_SECS = 3600          # warn when < 1 hour left
TYPING_INACTIVITY_TTL = 6         # clear typing indicator after N seconds silence
MAX_RECONNECT_DELAY = 60          # cap exponential backoff
HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
MAX_NICKNAME_CHARS = 80
MAX_GROUP_NAME_CHARS = 120
MAX_FILENAME_CHARS = 180
MAX_GROUP_MEMBERS = 128
MAX_REACTION_EMOJI_BYTES = 8
ALLOWED_REACTIONS = {"👍", "❤️", "😂", "😮", "😢", "🔥"}
SCHEMA_VERSION = 5
REPLAY_WINDOW = 2048              # accepted out-of-order span for message counters
FILE_CHUNK_CONCURRENCY = 8        # chunks sent in flight at once per file transfer;
                                   # well under REPLAY_WINDOW so out-of-order arrival is safe
DEFAULT_MAX_STORAGE_MB = 4096      # default disk quota for received/sent file bytes
MESSAGE_PAGE_SIZE = 200            # messages sent on initial state sync / per page
SCRYPT_N, SCRYPT_R, SCRYPT_P = 2 ** 15, 8, 1    # passphrase KDF work factor
LOG = logging.getLogger("quantum_chat")


# ─── Utilities ────────────────────────────────────────────────────────────────

def validate_public_key(pubkey: str, expected_bytes: Optional[int] = None) -> str:
    value = (pubkey or "").strip().lower()
    if not value or len(value) % 2 or not HEX_RE.fullmatch(value):
        raise ValueError("Public key must be a non-empty hexadecimal string")
    if expected_bytes is not None and len(value) != expected_bytes * 2:
        raise ValueError(f"Public key must be {expected_bytes} bytes ({expected_bytes * 2} hex chars)")
    return value


def validate_file_id(file_id: str) -> str:
    value = (file_id or "").strip()
    if not UUID_RE.fullmatch(value):
        raise ValueError("File id must be a canonical UUID")
    return str(uuid.UUID(value))


def validate_label(value: Any, field: str, max_chars: int, required: bool = False) -> str:
    text = str(value or "").strip()
    if required and not text:
        raise ValueError(f"{field} is required")
    if len(text) > max_chars:
        raise ValueError(f"{field} is too long; maximum is {max_chars} characters")
    return text


def validate_emoji(emoji: str) -> str:
    emoji = (emoji or "").strip()
    if emoji not in ALLOWED_REACTIONS:
        raise ValueError(f"Reaction must be one of: {', '.join(sorted(ALLOWED_REACTIONS))}")
    return emoji


def safe_filename(filename: Any) -> str:
    name = os.path.basename(str(filename or "").replace("\\", "/")).strip() or "download.bin"
    name = name[:MAX_FILENAME_CHARS]
    return name or "download.bin"


def safe_content_type(value: Any, filename: str = "") -> str:
    content_type = str(value or "").split(";", 1)[0].strip().lower()
    if (not content_type or len(content_type) > 100
            or not re.fullmatch(r"[a-z0-9][a-z0-9.+-]*/[a-z0-9][a-z0-9.+-]*", content_type)):
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    return content_type


def files_dir_for_db(db_path: str) -> Path:
    """Return a node-local attachment root while preserving the legacy default."""
    return Path(FILES_DIR) if db_path == DB_FILE else Path(f"{Path(db_path)}.files")


def parse_http_range(value: str, size: int) -> Optional[Tuple[int, int]]:
    """Parse one RFC 7233 byte range and return inclusive offsets.

    Multiple ranges are intentionally unsupported because media elements only
    need a single range and multipart responses would add substantial surface
    area to the local file server.
    """
    value = (value or "").strip()
    if not value:
        return None
    if size < 0 or not value.startswith("bytes=") or "," in value:
        raise ValueError("Invalid byte range")
    spec = value[6:].strip()
    if "-" not in spec:
        raise ValueError("Invalid byte range")
    start_text, end_text = spec.split("-", 1)
    try:
        if not start_text:
            suffix = int(end_text)
            if suffix <= 0 or size == 0:
                raise ValueError("Unsatisfiable byte range")
            start = max(0, size - suffix)
            end = size - 1
        else:
            start = int(start_text)
            end = int(end_text) if end_text else size - 1
            if start < 0 or start >= size or end < start:
                raise ValueError("Unsatisfiable byte range")
            end = min(end, size - 1)
    except (TypeError, ValueError) as exc:
        raise ValueError("Invalid byte range") from exc
    return start, end


def utc_ts() -> int:
    return int(time.time())


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


PAD_BUCKET_BYTES = 256


def pad_plaintext(data: bytes, bucket: int = PAD_BUCKET_BYTES) -> bytes:
    """Right-pad plaintext with zero bytes up to the next multiple of
    `bucket`, prefixed with a 4-byte big-endian original length. Chat
    ciphertext length is visible to the relay and any passive network
    observer even though the content is not; without padding, that length
    leaks a strong signal about message content (e.g. "ok" vs a paragraph).
    Padding to fixed-size buckets reduces that leak to "which size bucket",
    at the cost of a few bytes of overhead per message."""
    prefix = len(data).to_bytes(4, "big")
    body = prefix + data
    pad_len = (-len(body)) % bucket
    return body + b"\x00" * pad_len


def unpad_plaintext(data: bytes) -> bytes:
    if len(data) < 4:
        raise ValueError("Padded plaintext too short")
    n = int.from_bytes(data[:4], "big")
    if n < 0 or n > len(data) - 4:
        raise ValueError("Invalid padding length")
    return data[4:4 + n]


def canonical_json(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def short_key(pubkey: str) -> str:
    return f"{pubkey[:12]}…{pubkey[-8:]}" if len(pubkey) > 24 else pubkey


def key_fingerprint(pubkey: str) -> str:
    """Return a colon-separated SHA-256 fingerprint (first 8 bytes) of the key."""
    digest = hashlib.sha256(bytes.fromhex(pubkey)).hexdigest()[:16]
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2))


def require_websockets():
    try:
        import websockets  # type: ignore
        return websockets
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: websockets. Run `pip install -r requirements.txt`.") from exc


def require_cryptography():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # type: ignore
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # type: ignore
        from cryptography.hazmat.primitives import hashes  # type: ignore
        return AESGCM, HKDF, hashes
    except ModuleNotFoundError as exc:
        raise SystemExit("Missing dependency: cryptography. Run `pip install -r requirements.txt`.") from exc


# ─── Post-Quantum Crypto ──────────────────────────────────────────────────────

class PQModule:
    """Compatibility wrapper for pqcrypto import/API variance."""

    def __init__(self) -> None:
        try:
            from pqcrypto.sign import ml_dsa_65 as sign_mod  # type: ignore
        except ImportError:
            try:
                from pqcrypto.sign import dilithium3 as sign_mod  # type: ignore
            except ModuleNotFoundError:
                try:
                    from pqcrypto.dilithium import Dilithium3 as sign_mod  # type: ignore
                except ModuleNotFoundError as exc:
                    raise SystemExit("Missing dependency: pqcrypto. Run `pip install -r requirements.txt`.") from exc
        try:
            from pqcrypto.kem import ml_kem_512 as kem_mod  # type: ignore
        except ImportError:
            try:
                from pqcrypto.kem import kyber512 as kem_mod  # type: ignore
            except ModuleNotFoundError:
                try:
                    from pqcrypto.kyber import Kyber512 as kem_mod  # type: ignore
                except ModuleNotFoundError as exc:
                    raise SystemExit("Missing dependency: pqcrypto. Run `pip install -r requirements.txt`.") from exc
        self.sign_mod = sign_mod
        self.kem_mod = kem_mod
        pk, _ = self.sign_keypair()
        self.sign_public_key_bytes = len(pk)

    def sign_keypair(self) -> Tuple[bytes, bytes]:
        return self.sign_mod.generate_keypair() if hasattr(self.sign_mod, "generate_keypair") else self.sign_mod.keypair()

    def kem_keypair(self) -> Tuple[bytes, bytes]:
        return self.kem_mod.generate_keypair() if hasattr(self.kem_mod, "generate_keypair") else self.kem_mod.keypair()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        try:
            return self.sign_mod.sign(secret_key, message)
        except TypeError:
            return self.sign_mod.sign(message, secret_key)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify a signature. pqcrypto 0.4+ returns True/False from verify()
        rather than raising, so we must inspect the return value — wrapping the
        call in a bare ``try: verify(...); return True`` was a critical bug
        that accepted every signature, valid or not."""
        # Preferred modern pqcrypto API: (public_key, message, signature) -> bool
        try:
            result = self.sign_mod.verify(public_key, message, signature)
            return bool(result)
        except TypeError:
            # Older API variants swapped argument order or raised on mismatch.
            try:
                result = self.sign_mod.verify(message, signature, public_key)
                return bool(result)
            except Exception:
                return False
        except Exception:
            # verify() raises (or the lib raises) when bytes are malformed,
            # the public key is wrong-sized, or the signature is invalid.
            return False

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return self.kem_mod.encrypt(public_key) if hasattr(self.kem_mod, "encrypt") else self.kem_mod.encapsulate(public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        try:
            return self.kem_mod.decrypt(secret_key, ciphertext)
        except TypeError:
            return self.kem_mod.decapsulate(secret_key, ciphertext)


class QuantumCrypto:
    def __init__(self) -> None:
        self.pq = PQModule()
        self.AESGCM, self.HKDF, self.hashes = require_cryptography()
        self.sign_public_key_bytes = self.pq.sign_public_key_bytes

    def new_identity(self) -> Tuple[bytes, bytes]:
        return self.pq.sign_keypair()

    def new_kem_keypair(self) -> Tuple[bytes, bytes]:
        return self.pq.kem_keypair()

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        return self.pq.sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        return self.pq.verify(public_key, message, signature)

    def kem_encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        return self.pq.encapsulate(public_key)

    def kem_decapsulate(self, secret_key: bytes, ciphertext: bytes) -> bytes:
        return self.pq.decapsulate(secret_key, ciphertext)

    def derive_session_key(self, shared_secret: bytes, a_pub: str, b_pub: str,
                           session_id: str, transcript: Optional[Dict[str, Any]] = None) -> bytes:
        transcript_hash = hashlib.sha256(canonical_json(transcript or {})).hexdigest()
        salt = hashlib.sha256("|".join(sorted([a_pub, b_pub]) + [session_id, transcript_hash]).encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt,
                         info=b"quantum-chat-v4-session-transcript")
        return hkdf.derive(shared_secret)

    def derive_message_key(self, session_key: bytes, from_pub: str, to_pub: str, counter: int, purpose: str) -> bytes:
        """Derive a per-message key bound to sender, recipient, counter, and
        purpose. Both sides of a session must compute an identical salt here:
        using an ambiguous single 'peer' pubkey (resolving to the recipient
        on the sender's side but the sender on the receiver's side) would
        make the two ends derive different keys and fail every message.
        Keeping both from_pub and to_pub (rather than dropping peer binding
        entirely) also keeps the two directions of a session on distinct
        keys, so a ciphertext sent in one direction can't be replayed as if
        it came from the other."""
        salt = hashlib.sha256(f"{from_pub}:{to_pub}:{counter}:{purpose}".encode()).digest()
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32, salt=salt,
                         info=b"quantum-chat-v1-message-key")
        return hkdf.derive(session_key)

    def derive_device_sync_key(self, secret_key: bytes) -> bytes:
        """Derive a symmetric key for syncing local state (sent/received
        messages, read status) between devices that share this identity's
        secret key — see 'Multi-device support'. Deterministic from the
        secret key alone so any device holding the same identity backup can
        compute it independently, with no extra handshake. The relay only
        ever sees the resulting ciphertext, never this key or the plaintext."""
        hkdf = self.HKDF(algorithm=self.hashes.SHA256(), length=32,
                         salt=b"quantum-chat-device-sync-v1", info=b"device-sync")
        return hkdf.derive(secret_key)

    def encrypt(self, key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
        nonce = secrets.token_bytes(12)
        ciphertext = self.AESGCM(key).encrypt(nonce, plaintext, aad)
        return {"nonce": b64e(nonce), "ciphertext": b64e(ciphertext)}

    def decrypt(self, key: bytes, packet: Dict[str, str], aad: bytes = b"") -> bytes:
        return self.AESGCM(key).decrypt(b64d(packet["nonce"]), b64d(packet["ciphertext"]), aad)


def scrypt_derive(passphrase: str, salt: bytes, length: int = 32) -> bytes:
    """Derive a symmetric key from a low-entropy passphrase using Scrypt.

    Shared by local-key-file wrapping and identity backup/export so both
    features get the same memory-hard, tunable work factor rather than a
    bare KDF that assumes high-entropy input.
    """
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # type: ignore
    kdf = Scrypt(salt=salt, length=length, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


IDENTITY_BACKUP_TAG = "QCID1"
IDENTITY_BACKUP_AAD = b"quantum-chat-identity-backup-v1"


def pack_identity_backup(public_key: str, secret_key: bytes, passphrase: str) -> str:
    """Serialize an identity keypair into a portable, passphrase-protected
    string so a person can carry their identity (and therefore their public
    key / fingerprint) to a second device. This intentionally does not carry
    friends, sessions, or message history — see README for why full
    multi-device sync is a materially larger undertaking."""
    if not passphrase:
        raise ValueError("A passphrase is required to protect an identity backup")
    AESGCM, _, _ = require_cryptography()
    salt = secrets.token_bytes(16)
    key = scrypt_derive(passphrase, salt)
    nonce = secrets.token_bytes(12)
    payload = json.dumps({"pk": public_key, "sk": b64e(secret_key)}).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, payload, IDENTITY_BACKUP_AAD)
    return f"{IDENTITY_BACKUP_TAG}:{b64e(salt)}:{b64e(nonce)}:{b64e(ciphertext)}"


def unpack_identity_backup(blob: str, passphrase: str) -> Tuple[str, bytes]:
    parts = (blob or "").strip().split(":")
    if len(parts) != 4 or parts[0] != IDENTITY_BACKUP_TAG:
        raise ValueError("Unrecognized identity backup format")
    _, salt_b64, nonce_b64, ct_b64 = parts
    AESGCM, _, _ = require_cryptography()
    key = scrypt_derive(passphrase, b64d(salt_b64))
    try:
        payload = AESGCM(key).decrypt(b64d(nonce_b64), b64d(ct_b64), IDENTITY_BACKUP_AAD)
    except Exception as exc:
        raise ValueError("Wrong passphrase or corrupted identity backup") from exc
    data = json.loads(payload.decode("utf-8"))
    return validate_public_key(data["pk"]), b64d(data["sk"])


# ─── Local Key Store ──────────────────────────────────────────────────────────

class LocalKeyStore:
    """Load or create the local database encryption key.

    By default the app remains backward compatible with the existing raw
    ``*.db.key`` file.  Operators can set QUANTUM_CHAT_PASSPHRASE to store a
    wrapped key instead; the passphrase never becomes the data-encryption key
    and the file beside the database is not directly usable without it.
    """

    def __init__(self, db_path: str) -> None:
        self.path = Path(f"{db_path}.key")
        self.mode = os.environ.get("QUANTUM_CHAT_KEY_MODE", "passphrase" if os.environ.get("QUANTUM_CHAT_PASSPHRASE") else "file")
        self.passphrase = os.environ.get("QUANTUM_CHAT_PASSPHRASE")

    def _wrap_key(self, key: bytes, salt: bytes) -> bytes:
        AESGCM, _, _ = require_cryptography()
        wrapping = scrypt_derive(self.passphrase, salt)
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(wrapping).encrypt(nonce, key, b"quantum-chat-local-key")

    def _unwrap_key(self, blob: bytes, salt: bytes) -> bytes:
        AESGCM, _, _ = require_cryptography()
        wrapping = scrypt_derive(self.passphrase, salt)
        return AESGCM(wrapping).decrypt(blob[:12], blob[12:], b"quantum-chat-local-key")

    def load_or_create(self) -> bytes:
        if self.path.exists():
            raw = self.path.read_bytes().strip()
            try:
                text = raw.decode("ascii")
                if text.startswith("QCWRAP1:"):
                    raise RuntimeError(
                        "This key file uses the legacy v2.0 HKDF-wrapped format, which used no "
                        "brute-force work factor for passphrase-derived keys. Set "
                        "QUANTUM_CHAT_PASSPHRASE and re-run the v2.0 release once to unwrap it, "
                        "then delete the .key file and start this version fresh so it can be "
                        "re-wrapped with the stronger Scrypt-based format (QCWRAP2)."
                    )
                if text.startswith("QCWRAP2:"):
                    if not self.passphrase:
                        raise RuntimeError("QUANTUM_CHAT_PASSPHRASE is required for this wrapped key file")
                    _, salt_b64, blob_b64 = text.split(":", 2)
                    key = self._unwrap_key(b64d(blob_b64), b64d(salt_b64))
                else:
                    key = b64d(text)
                    if self.mode == "passphrase" and self.passphrase:
                        # One-way compatibility migration: protect the raw key file
                        # without rewriting any existing database ciphertext.
                        self._write_wrapped(key)
            except Exception as exc:
                raise RuntimeError(f"Invalid local key file: {self.path}") from exc
            if len(key) != 32:
                raise RuntimeError(f"Invalid local key length in {self.path}")
            return key
        key = secrets.token_bytes(32)
        if self.mode == "passphrase":
            if not self.passphrase:
                raise RuntimeError("QUANTUM_CHAT_PASSPHRASE must be set when QUANTUM_CHAT_KEY_MODE=passphrase")
            self._write_wrapped(key)
        else:
            self._write_raw(key)
        return key

    def _write_raw(self, key: bytes) -> None:
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(b64e(key), encoding="ascii")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)

    def _write_wrapped(self, key: bytes) -> None:
        salt = secrets.token_bytes(16)
        blob = self._wrap_key(key, salt)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(f"QCWRAP2:{b64e(salt)}:{b64e(blob)}", encoding="ascii")
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
        tmp.replace(self.path)


# ─── Database ─────────────────────────────────────────────────────────────────

class Database:
    def __init__(self, db_path: str = DB_FILE, master_key: Optional[bytes] = None) -> None:
        self.path = db_path
        self.master_key = master_key
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute("PRAGMA journal_mode=WAL")
            self.conn.execute("PRAGMA synchronous=NORMAL")  # safe with WAL, notably faster fsync behavior
            self.conn.execute("PRAGMA foreign_keys=ON")
            self.conn.execute("PRAGMA busy_timeout=5000")
            self._init_tables()

    def _init_tables(self) -> None:
        with self.lock:
            self.conn.executescript("""
                CREATE TABLE IF NOT EXISTS identity (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    public_key TEXT NOT NULL,
                    secret_key BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    secret_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS friends (
                    pubkey TEXT PRIMARY KEY,
                    nickname TEXT,
                    trusted INTEGER NOT NULL DEFAULT 1,
                    verified INTEGER NOT NULL DEFAULT 0,
                    blocked INTEGER NOT NULL DEFAULT 0,
                    relay_alias TEXT,
                    direct_url TEXT,
                    added_at INTEGER NOT NULL,
                    last_seen INTEGER,
                    unread INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    peer_pubkey TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    key BLOB NOT NULL,
                    established_at INTEGER NOT NULL,
                    initiator INTEGER NOT NULL DEFAULT 0,
                    key_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0,
                    send_counter INTEGER NOT NULL DEFAULT 0,
                    recv_counter INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    owner_pubkey TEXT,
                    epoch INTEGER NOT NULL DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    pubkey TEXT NOT NULL,
                    role TEXT NOT NULL DEFAULT 'member',
                    joined_at INTEGER NOT NULL,
                    PRIMARY KEY (group_id, pubkey),
                    FOREIGN KEY (group_id) REFERENCES groups(group_id) ON DELETE CASCADE
                );
                CREATE TABLE IF NOT EXISTS messages (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT UNIQUE NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    recipient_pubkey TEXT,
                    group_id TEXT,
                    body TEXT NOT NULL,
                    direction TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    delivered INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL DEFAULT 'sent',
                    body_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0,
                    read_at INTEGER
                );
                CREATE TABLE IF NOT EXISTS files (
                    file_id TEXT PRIMARY KEY,
                    filename TEXT NOT NULL,
                    sender_pubkey TEXT NOT NULL,
                    recipient_pubkey TEXT,
                    group_id TEXT,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    storage_path TEXT NOT NULL,
                    uploaded_at INTEGER NOT NULL,
                    mime_type TEXT,
                    file_nonce BLOB,
                    key_version INTEGER NOT NULL DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS outbox (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_pubkey TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'queued',
                    retry_count INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    msg_id TEXT NOT NULL,
                    peer_pubkey TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    direction TEXT NOT NULL DEFAULT 'in',
                    added_at INTEGER NOT NULL,
                    UNIQUE(msg_id, peer_pubkey, emoji)
                );
                CREATE TABLE IF NOT EXISTS read_receipts (
                    msg_id TEXT PRIMARY KEY,
                    reader_pubkey TEXT NOT NULL,
                    read_at INTEGER NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recv_counters (
                    peer_pubkey TEXT NOT NULL,
                    session_id TEXT NOT NULL,
                    counter INTEGER NOT NULL,
                    seen_at INTEGER NOT NULL,
                    PRIMARY KEY (peer_pubkey, session_id, counter)
                );
                CREATE TABLE IF NOT EXISTS group_epochs (
                    group_id TEXT NOT NULL,
                    epoch INTEGER NOT NULL,
                    key BLOB NOT NULL,
                    key_nonce BLOB,
                    created_at INTEGER NOT NULL,
                    created_by TEXT NOT NULL,
                    PRIMARY KEY (group_id, epoch)
                );
                CREATE TABLE IF NOT EXISTS file_chunks (
                    file_id TEXT NOT NULL,
                    chunk_index INTEGER NOT NULL,
                    total_chunks INTEGER NOT NULL,
                    storage_path TEXT NOT NULL,
                    chunk_nonce BLOB,
                    received_at INTEGER NOT NULL,
                    PRIMARY KEY (file_id, chunk_index)
                );
                CREATE TABLE IF NOT EXISTS metrics (
                    name TEXT PRIMARY KEY,
                    value INTEGER NOT NULL DEFAULT 0
                );
                CREATE INDEX IF NOT EXISTS idx_messages_target
                    ON messages(sender_pubkey, recipient_pubkey, group_id, timestamp);
                CREATE INDEX IF NOT EXISTS idx_outbox_target_status
                    ON outbox(target_pubkey, status);
                CREATE INDEX IF NOT EXISTS idx_reactions_msg
                    ON reactions(msg_id);
                CREATE INDEX IF NOT EXISTS idx_recv_counters_peer
                    ON recv_counters(peer_pubkey, session_id, counter);
                CREATE INDEX IF NOT EXISTS idx_file_chunks_file
                    ON file_chunks(file_id, chunk_index);
            """)
            self._ensure_columns()
            self.conn.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            self.conn.commit()

    def _columns(self, table: str) -> Set[str]:
        return {row[1] for row in self.conn.execute(f"PRAGMA table_info({table})")}

    def _ensure_columns(self) -> None:
        additions: Dict[str, List[Tuple[str, str]]] = {
            "identity": [("secret_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0")],
            "sessions": [("key_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0"),
                         ("send_counter", "INTEGER NOT NULL DEFAULT 0"),
                         ("recv_counter", "INTEGER NOT NULL DEFAULT 0")],
            "groups": [("owner_pubkey", "TEXT"), ("epoch", "INTEGER NOT NULL DEFAULT 1")],
            "group_members": [("role", "TEXT NOT NULL DEFAULT 'member'")],
            "messages": [("status", "TEXT NOT NULL DEFAULT 'sent'"), ("body_nonce", "BLOB"),
                         ("key_version", "INTEGER NOT NULL DEFAULT 0"), ("read_at", "INTEGER")],
            "files": [("file_nonce", "BLOB"), ("key_version", "INTEGER NOT NULL DEFAULT 0"),
                      ("mime_type", "TEXT")],
            "file_chunks": [("chunk_nonce", "BLOB")],
            "friends": [("unread", "INTEGER NOT NULL DEFAULT 0"),
                        ("verified", "INTEGER NOT NULL DEFAULT 0"),
                        ("blocked", "INTEGER NOT NULL DEFAULT 0"),
                        ("relay_alias", "TEXT"), ("direct_url", "TEXT")],
        }
        for table, cols in additions.items():
            existing = self._columns(table)
            for name, ddl in cols:
                if name not in existing:
                    self.conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")

    # ── AEAD helpers ──────────────────────────────────────────────────────────

    def _aead(self):
        if not self.master_key:
            return None
        AESGCM, _, _ = require_cryptography()
        return AESGCM(self.master_key)

    def encrypt_blob(self, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, Optional[bytes], int]:
        aead = self._aead()
        if not aead:
            return plaintext, None, 0
        nonce = secrets.token_bytes(12)
        return aead.encrypt(nonce, plaintext, aad), nonce, 1

    def decrypt_blob(self, ciphertext: bytes, nonce: Optional[bytes], aad: bytes = b"") -> bytes:
        if not nonce:
            return ciphertext
        aead = self._aead()
        if not aead:
            raise RuntimeError("Encrypted database value cannot be decrypted without master key")
        return aead.decrypt(nonce, ciphertext, aad)

    # ── Identity ──────────────────────────────────────────────────────────────

    def load_identity(self) -> Optional[Tuple[str, bytes]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT public_key, secret_key, secret_nonce FROM identity WHERE id=1"
            ).fetchone()
            if not row:
                return None
            secret = self.decrypt_blob(row["secret_key"], row["secret_nonce"],
                                       f"identity:{row['public_key']}".encode())
            return (row["public_key"], secret)

    def save_identity(self, public_key: str, secret_key: bytes) -> None:
        blob, nonce, version = self.encrypt_blob(secret_key, f"identity:{public_key}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO identity "
                "(id, public_key, secret_key, created_at, secret_nonce, key_version) "
                "VALUES (1, ?, ?, ?, ?, ?)",
                (public_key, blob, utc_ts(), nonce, version),
            )
            self.conn.commit()

    # ── Friends ───────────────────────────────────────────────────────────────

    def add_friend(self, pubkey: str, nickname: Optional[str] = None) -> None:
        nickname = validate_label(nickname, "Nickname", MAX_NICKNAME_CHARS) or None
        with self.lock:
            self.conn.execute(
                "INSERT INTO friends (pubkey, nickname, added_at, unread, verified, blocked) VALUES (?, ?, ?, 0, 0, 0) "
                "ON CONFLICT(pubkey) DO UPDATE SET "
                "nickname=COALESCE(excluded.nickname, friends.nickname), trusted=1, blocked=0",
                (pubkey, nickname, utc_ts()),
            )
            self.conn.commit()

    def remove_friend(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute("DELETE FROM friends WHERE pubkey=?", (pubkey,))
            self.conn.execute("DELETE FROM sessions WHERE peer_pubkey=?", (pubkey,))
            self.conn.commit()

    def get_friends(self) -> List[Dict[str, Any]]:
        with self.lock:
            friends = []
            for r in self.conn.execute(
                "SELECT pubkey, nickname, last_seen, unread, verified, blocked, relay_alias, direct_url FROM friends ORDER BY added_at DESC"
            ):
                d = dict(r)
                d["fingerprint"] = key_fingerprint(d["pubkey"])
                friends.append(d)
            return friends

    def is_friend(self, pubkey: str) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM friends WHERE pubkey=? AND blocked=0", (pubkey,)
            ).fetchone() is not None

    def touch_friend(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET last_seen=? WHERE pubkey=?", (utc_ts(), pubkey)
            )
            self.conn.commit()

    def set_friend_transport(self, pubkey: str, relay_alias: Optional[str] = None,
                             direct_url: Optional[str] = None) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET relay_alias=COALESCE(?, relay_alias), direct_url=COALESCE(?, direct_url) WHERE pubkey=?",
                (relay_alias, direct_url, pubkey)
            )
            self.conn.commit()

    def verify_friend(self, pubkey: str, verified: bool = True) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET verified=? WHERE pubkey=?", (int(verified), pubkey))
            self.conn.commit()

    def rename_friend(self, pubkey: str, nickname: Optional[str]) -> str:
        """Update the nickname of an existing friend. Returns the stored
        nickname (None if cleared). Validates the label so a too-long or
        illegal nickname never reaches the DB."""
        nickname = validate_label(nickname, "Nickname", MAX_NICKNAME_CHARS) or None
        with self.lock:
            row = self.conn.execute("SELECT 1 FROM friends WHERE pubkey=?", (pubkey,)).fetchone()
            if not row:
                raise ValueError("No such friend to rename")
            self.conn.execute(
                "UPDATE friends SET nickname=? WHERE pubkey=?", (nickname, pubkey)
            )
            self.conn.commit()
        return nickname

    def block_friend(self, pubkey: str, blocked: bool = True) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET blocked=? WHERE pubkey=?", (int(blocked), pubkey))
            self.conn.commit()
            # Dropping the live session on block means an attacker who later
            # steals the friend's identity can't keep using an existing key;
            # they'd have to complete a fresh signed handshake first.
            if blocked:
                self.conn.execute("DELETE FROM sessions WHERE peer_pubkey=?", (pubkey,))
                self.conn.commit()

    def increment_unread(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE friends SET unread=unread+1 WHERE pubkey=?", (pubkey,)
            )
            self.conn.commit()

    def clear_unread(self, pubkey: str) -> None:
        with self.lock:
            self.conn.execute("UPDATE friends SET unread=0 WHERE pubkey=?", (pubkey,))
            self.conn.commit()

    # ── Sessions ──────────────────────────────────────────────────────────────

    def session_summary(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT peer_pubkey, session_id, established_at, initiator, "
                "send_counter, recv_counter FROM sessions"
            )
            return {
                r["peer_pubkey"]: {
                    "session_id": r["session_id"],
                    "established_at": r["established_at"],
                    "initiator": bool(r["initiator"]),
                    "send_counter": r["send_counter"],
                    "recv_counter": r["recv_counter"],
                    "age_secs": utc_ts() - r["established_at"],
                    "expires_in": max(0, SESSION_TTL - (utc_ts() - r["established_at"])),
                }
                for r in rows
            }

    def save_session(self, peer_pubkey: str, session_id: str, key: bytes, initiator: bool) -> None:
        blob, nonce, version = self.encrypt_blob(key, f"session:{peer_pubkey}:{session_id}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO sessions "
                "(peer_pubkey, session_id, key, established_at, initiator, key_nonce, key_version, "
                "send_counter, recv_counter) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, "
                "COALESCE((SELECT send_counter FROM sessions WHERE peer_pubkey=?),0), "
                "COALESCE((SELECT recv_counter FROM sessions WHERE peer_pubkey=?),0))",
                (peer_pubkey, session_id, blob, utc_ts(), int(initiator), nonce, version,
                 peer_pubkey, peer_pubkey),
            )
            self.conn.commit()

    def get_session(self, peer_pubkey: str) -> Optional[Dict[str, Any]]:
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            if not row:
                return None
            data = dict(row)
            data["key"] = self.decrypt_blob(
                data["key"], data.get("key_nonce"),
                f"session:{peer_pubkey}:{data['session_id']}".encode()
            )
            return data

    def next_send_counter(self, peer_pubkey: str) -> int:
        with self.lock:
            row = self.conn.execute(
                "SELECT send_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            counter = int(row["send_counter"] if row else 0) + 1
            self.conn.execute(
                "UPDATE sessions SET send_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey)
            )
            self.conn.commit()
            return counter

    def mark_recv_counter(self, peer_pubkey: str, counter: int) -> None:
        """Record a received counter with a replay window.

        Older out-of-order messages are accepted if they have not been seen and
        are within REPLAY_WINDOW of the highest observed counter.
        """
        with self.lock:
            row = self.conn.execute(
                "SELECT session_id, recv_counter FROM sessions WHERE peer_pubkey=?", (peer_pubkey,)
            ).fetchone()
            if not row:
                raise ValueError("No session for replay validation")
            highest = int(row["recv_counter"])
            if counter <= max(0, highest - REPLAY_WINDOW):
                raise ValueError("Message counter is outside the replay window")
            try:
                self.conn.execute(
                    "INSERT INTO recv_counters (peer_pubkey, session_id, counter, seen_at) VALUES (?, ?, ?, ?)",
                    (peer_pubkey, row["session_id"], counter, utc_ts())
                )
            except sqlite3.IntegrityError as exc:
                raise ValueError("Replay duplicate message detected") from exc
            if counter > highest:
                self.conn.execute(
                    "UPDATE sessions SET recv_counter=? WHERE peer_pubkey=?", (counter, peer_pubkey)
                )
            self.conn.execute(
                "DELETE FROM recv_counters WHERE peer_pubkey=? AND session_id=? AND counter<=?",
                (peer_pubkey, row["session_id"], max(0, max(highest, counter) - REPLAY_WINDOW))
            )
            self.conn.commit()

    # ── Groups ────────────────────────────────────────────────────────────────

    def create_group(self, group_id: str, name: str, owner_pubkey: str) -> None:
        name = validate_label(name, "Group name", MAX_GROUP_NAME_CHARS, required=True)
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO groups (group_id, name, created_at, owner_pubkey, epoch) "
                "VALUES (?, ?, ?, ?, 1)",
                (group_id, name, utc_ts(), owner_pubkey)
            )
            self.conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) "
                "VALUES (?, ?, ?, ?)",
                (group_id, owner_pubkey, "owner", utc_ts())
            )
            self.conn.commit()

    def add_group_member(self, group_id: str, pubkey: str, role: str = "member") -> None:
        with self.lock:
            self.conn.execute(
                "INSERT OR IGNORE INTO group_members (group_id, pubkey, role, joined_at) "
                "VALUES (?, ?, ?, ?)",
                (group_id, pubkey, role, utc_ts())
            )
            self.conn.commit()

    def remove_group_member(self, group_id: str, pubkey: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM group_members WHERE group_id=? AND pubkey=?", (group_id, pubkey)
            )
            self.conn.commit()
            return cur.rowcount > 0

    def group_role(self, group_id: str, pubkey: str) -> Optional[str]:
        with self.lock:
            row = self.conn.execute(
                "SELECT role FROM group_members WHERE group_id=? AND pubkey=?", (group_id, pubkey)
            ).fetchone()
            return row["role"] if row else None

    def groups_for(self, pubkey: str) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT g.group_id, g.name, g.created_at, g.owner_pubkey, g.epoch "
                "FROM groups g JOIN group_members gm ON g.group_id=gm.group_id "
                "WHERE gm.pubkey=? ORDER BY g.created_at DESC",
                (pubkey,),
            )
            return [dict(r) for r in rows]

    def group_members(self, group_id: str) -> List[str]:
        with self.lock:
            return [r["pubkey"] for r in self.conn.execute(
                "SELECT pubkey FROM group_members WHERE group_id=?", (group_id,)
            )]

    def group_details_for(self, pubkey: str) -> List[Dict[str, Any]]:
        groups = self.groups_for(pubkey)
        for group in groups:
            group["members"] = self.group_members(group["group_id"])
            # group_id is a UUID4 string (with dashes), not a hex-encoded
            # public key — strip the dashes to get the 32 hex chars
            # key_fingerprint expects, rather than hex-decoding the UUID as-is.
            group["fingerprint"] = key_fingerprint(group["group_id"].replace("-", ""))
        return groups

    def save_group_key(self, group_id: str, epoch: int, key: bytes, created_by: str) -> None:
        blob, nonce, _ = self.encrypt_blob(key, f"group:{group_id}:{epoch}".encode())
        with self.lock:
            self.conn.execute(
                "INSERT OR REPLACE INTO group_epochs (group_id, epoch, key, key_nonce, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?)",
                (group_id, epoch, blob, nonce, utc_ts(), created_by)
            )
            self.conn.execute("UPDATE groups SET epoch=? WHERE group_id=?", (epoch, group_id))
            self.conn.commit()

    def get_group_key(self, group_id: str, epoch: Optional[int] = None) -> Optional[Dict[str, Any]]:
        with self.lock:
            if epoch is None:
                row = self.conn.execute(
                    "SELECT ge.* FROM group_epochs ge JOIN groups g ON ge.group_id=g.group_id AND ge.epoch=g.epoch WHERE ge.group_id=?",
                    (group_id,)
                ).fetchone()
            else:
                row = self.conn.execute(
                    "SELECT * FROM group_epochs WHERE group_id=? AND epoch=?", (group_id, epoch)
                ).fetchone()
            if not row:
                return None
            d = dict(row)
            d["key"] = self.decrypt_blob(d["key"], d.get("key_nonce"), f"group:{group_id}:{d['epoch']}".encode())
            return d

    # ── Messages ──────────────────────────────────────────────────────────────

    def save_message(self, msg_id: str, sender: str, body: str, direction: str,
                     recipient: Optional[str] = None, group_id: Optional[str] = None,
                     delivered: bool = False, status: str = "sent") -> bool:
        plaintext = body.encode("utf-8")
        aad = f"message:{msg_id}:{sender}:{recipient or ''}:{group_id or ''}".encode()
        blob, nonce, version = self.encrypt_blob(plaintext, aad)
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO messages "
                "(msg_id, sender_pubkey, recipient_pubkey, group_id, body, direction, "
                "timestamp, delivered, status, body_nonce, key_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (msg_id, sender, recipient, group_id,
                 blob.decode("utf-8", "surrogateescape") if not nonce else sqlite3.Binary(blob),
                 direction, utc_ts(), int(delivered), status, nonce, version),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def update_message_status(self, msg_id: str, status: str, delivered: bool = False) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE messages SET status=?, delivered=? WHERE msg_id=?",
                (status, int(delivered), msg_id)
            )
            self.conn.commit()

    def mark_message_read(self, msg_id: str) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE messages SET read_at=? WHERE msg_id=? AND read_at IS NULL",
                (utc_ts(), msg_id)
            )
            self.conn.commit()

    def mark_remote_read(self, msg_id: str, read_at: int) -> None:
        """Stamp an outgoing message's read_at column when the remote peer
        sends us a read receipt. Distinct from mark_message_read (which is
        for incoming messages the local user has marked as read) because
        we want to honor the receipt's timestamp rather than overwriting
        with our own clock, and we update unconditionally (not just when
        read_at IS NULL) so a late-arriving receipt with a more accurate
        timestamp can correct an earlier estimate."""
        with self.lock:
            self.conn.execute(
                "UPDATE messages SET read_at=? WHERE msg_id=?",
                (int(read_at), msg_id)
            )
            self.conn.commit()

    def _hydrate_message_row(self, r: sqlite3.Row) -> Dict[str, Any]:
        d = dict(r)
        raw = d["body"]
        raw_b = raw.encode("utf-8", "surrogateescape") if isinstance(raw, str) else raw
        aad = (f"message:{d['msg_id']}:{d['sender_pubkey']}:"
               f"{d.get('recipient_pubkey') or ''}:{d.get('group_id') or ''}").encode()
        d["body"] = self.decrypt_blob(raw_b, d.get("body_nonce"), aad).decode("utf-8")
        d.pop("body_nonce", None)
        return d

    def recent_messages(self, limit: int = MESSAGE_PAGE_SIZE) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM messages ORDER BY timestamp DESC, id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._hydrate_message_row(r) for r in reversed(rows)]

    def messages_before(self, before_id: int, limit: int = MESSAGE_PAGE_SIZE) -> List[Dict[str, Any]]:
        """Fetch an older page of messages for 'load more history' in the UI."""
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM messages WHERE id < ? ORDER BY timestamp DESC, id DESC LIMIT ?",
                (before_id, limit)
            ).fetchall()
        return [self._hydrate_message_row(r) for r in reversed(rows)]

    def has_messages_before(self, before_id: int) -> bool:
        with self.lock:
            return self.conn.execute(
                "SELECT 1 FROM messages WHERE id < ? LIMIT 1", (before_id,)
            ).fetchone() is not None

    def search_messages(self, query: str, target: Optional[str] = None,
                        limit: int = 100, scan_limit: int = 20000) -> List[Dict[str, Any]]:
        """Case-insensitive substring search across message history.

        Message bodies are encrypted at rest (see encrypt_blob), so this
        can't be pushed into SQL as a LIKE/FTS query without either storing
        a plaintext search index (defeating the point of at-rest encryption)
        or a deterministic-but-leaky token index — neither is worth it for a
        local single-user database. Instead this decrypts rows newest-first
        up to `scan_limit` and filters in Python, stopping early once
        `limit` matches are found. `target` optionally restricts the scan to
        one friend pubkey or one group_id, which keeps most real searches
        fast since they're scoped to an open conversation."""
        query = (query or "").strip().lower()
        if not query:
            return []
        with self.lock:
            if target and UUID_RE.match(target):
                rows = self.conn.execute(
                    "SELECT * FROM messages WHERE group_id=? ORDER BY timestamp DESC, id DESC LIMIT ?",
                    (target, scan_limit)
                ).fetchall()
            elif target:
                rows = self.conn.execute(
                    "SELECT * FROM messages WHERE sender_pubkey=? OR recipient_pubkey=? "
                    "ORDER BY timestamp DESC, id DESC LIMIT ?",
                    (target, target, scan_limit)
                ).fetchall()
            else:
                rows = self.conn.execute(
                    "SELECT * FROM messages ORDER BY timestamp DESC, id DESC LIMIT ?", (scan_limit,)
                ).fetchall()
        results = []
        for r in rows:
            try:
                d = self._hydrate_message_row(r)
            except Exception:
                continue  # skip rows that fail to decrypt rather than aborting the whole search
            if query in d["body"].lower():
                results.append(d)
                if len(results) >= limit:
                    break
        return results

    # ── Reactions ─────────────────────────────────────────────────────────────

    def add_reaction(self, msg_id: str, peer_pubkey: str, emoji: str,
                     direction: str = "in") -> bool:
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO reactions (msg_id, peer_pubkey, emoji, direction, added_at) "
                "VALUES (?, ?, ?, ?, ?)",
                (msg_id, peer_pubkey, emoji, direction, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def remove_reaction(self, msg_id: str, peer_pubkey: str, emoji: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "DELETE FROM reactions WHERE msg_id=? AND peer_pubkey=? AND emoji=?",
                (msg_id, peer_pubkey, emoji)
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_reactions(self, msg_ids: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        if not msg_ids:
            return {}
        with self.lock:
            placeholders = ",".join("?" * len(msg_ids))
            rows = self.conn.execute(
                f"SELECT msg_id, peer_pubkey, emoji, direction, added_at "
                f"FROM reactions WHERE msg_id IN ({placeholders})",
                msg_ids
            ).fetchall()
        result: Dict[str, List[Dict[str, Any]]] = {}
        for r in rows:
            result.setdefault(r["msg_id"], []).append(dict(r))
        return result

    # ── Read Receipts ─────────────────────────────────────────────────────────

    def save_read_receipt(self, msg_id: str, reader_pubkey: str) -> bool:
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO read_receipts (msg_id, reader_pubkey, read_at) "
                "VALUES (?, ?, ?)",
                (msg_id, reader_pubkey, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_read_receipts(self, msg_ids: List[str]) -> Dict[str, int]:
        if not msg_ids:
            return {}
        with self.lock:
            placeholders = ",".join("?" * len(msg_ids))
            rows = self.conn.execute(
                f"SELECT msg_id, read_at FROM read_receipts WHERE msg_id IN ({placeholders})",
                msg_ids
            ).fetchall()
        return {r["msg_id"]: r["read_at"] for r in rows}

    # ── Files ─────────────────────────────────────────────────────────────────

    def recent_files(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM files ORDER BY uploaded_at DESC LIMIT ?", (limit,)
            )
            files = []
            for r in rows:
                d = dict(r)
                d.pop("file_nonce", None)
                files.append(d)
            return files

    def save_file(self, file_id: str, filename: str, sender: str, size: int, sha256: str,
                  path: str, recipient: Optional[str] = None, group_id: Optional[str] = None,
                  file_nonce: Optional[bytes] = None, replace: bool = False,
                  mime_type: Optional[str] = None) -> bool:
        file_id = validate_file_id(file_id)
        filename = safe_filename(filename)
        sql = "INSERT OR REPLACE" if replace else "INSERT OR IGNORE"
        with self.lock:
            cur = self.conn.execute(
                f"{sql} INTO files "
                "(file_id, filename, sender_pubkey, recipient_pubkey, group_id, "
                "size, sha256, storage_path, uploaded_at, file_nonce, key_version, mime_type) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (file_id, filename, sender, recipient, group_id, size, sha256, path,
                 utc_ts(), file_nonce, 1 if file_nonce else 0,
                 safe_content_type(mime_type, filename)),
            )
            self.conn.commit()
            return cur.rowcount > 0

    def get_file(self, file_id: str) -> Optional[Dict[str, Any]]:
        file_id = validate_file_id(file_id)
        with self.lock:
            row = self.conn.execute(
                "SELECT * FROM files WHERE file_id=?", (file_id,)
            ).fetchone()
            return dict(row) if row else None

    # ── Outbox ────────────────────────────────────────────────────────────────

    def queue_outbox(self, target_pubkey: str, payload: Dict[str, Any]) -> None:
        now = utc_ts()
        with self.lock:
            self.conn.execute(
                "INSERT INTO outbox (target_pubkey, payload, status, retry_count, created_at, updated_at) "
                "VALUES (?, ?, 'queued', 0, ?, ?)",
                (target_pubkey, json.dumps(payload), now, now)
            )
            self.conn.commit()

    def queued_outbox(self, target_pubkey: str, limit: int = 50) -> List[Dict[str, Any]]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT * FROM outbox WHERE target_pubkey=? AND status='queued' "
                "ORDER BY created_at ASC LIMIT ?",
                (target_pubkey, limit)
            ).fetchall()
            return [dict(r) for r in rows]

    def mark_outbox_sent(self, outbox_id: int) -> None:
        with self.lock:
            self.conn.execute(
                "UPDATE outbox SET status='sent', updated_at=? WHERE id=?", (utc_ts(), outbox_id)
            )
            self.conn.commit()

    def save_file_chunk(self, file_id: str, chunk_index: int, total_chunks: int, path: str,
                       chunk_nonce: Optional[bytes] = None) -> bool:
        file_id = validate_file_id(file_id)
        with self.lock:
            cur = self.conn.execute(
                "INSERT OR IGNORE INTO file_chunks (file_id, chunk_index, total_chunks, storage_path, chunk_nonce, received_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (file_id, chunk_index, total_chunks, path, chunk_nonce, utc_ts())
            )
            self.conn.commit()
            return cur.rowcount > 0

    def file_chunks(self, file_id: str) -> List[Dict[str, Any]]:
        file_id = validate_file_id(file_id)
        with self.lock:
            return [dict(r) for r in self.conn.execute(
                "SELECT * FROM file_chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)
            )]

    def delete_file_chunks(self, file_id: str) -> List[Dict[str, Any]]:
        """Remove and return chunk rows for a file, e.g. once reassembly is done."""
        file_id = validate_file_id(file_id)
        with self.lock:
            rows = [dict(r) for r in self.conn.execute(
                "SELECT * FROM file_chunks WHERE file_id=? ORDER BY chunk_index", (file_id,)
            )]
            self.conn.execute("DELETE FROM file_chunks WHERE file_id=?", (file_id,))
            self.conn.commit()
            return rows

    def metric_inc(self, name: str, amount: int = 1) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO metrics (name, value) VALUES (?, ?) ON CONFLICT(name) DO UPDATE SET value=value+excluded.value",
                (name, amount)
            )
            self.conn.commit()

    def metrics(self) -> Dict[str, int]:
        with self.lock:
            return {r["name"]: int(r["value"]) for r in self.conn.execute("SELECT name, value FROM metrics")}

    def outbox_depth(self) -> int:
        with self.lock:
            return int(self.conn.execute("SELECT COUNT(*) FROM outbox WHERE status='queued'").fetchone()[0])

    def close(self) -> None:
        with self.lock:
            self.conn.close()


# ─── Node ─────────────────────────────────────────────────────────────────────

@dataclass
class PendingOffer:
    peer_pubkey: str
    session_id: str
    kem_secret_key: bytes
    created_at: int
    offer_payload: Dict[str, Any]


class QuantumNode:
    def __init__(self, db_path: str = DB_FILE, signaling_url: str = DEFAULT_SIGNALING_URL,
                 direct_url: Optional[str] = None, enable_direct: bool = True,
                 max_storage_bytes: int = DEFAULT_MAX_STORAGE_MB * 1024 * 1024) -> None:
        self.crypto = QuantumCrypto()
        # Separate nodes commonly run from one checkout during local testing.
        # Giving every custom database its own file root prevents one node from
        # overwriting another node's encrypted copy of the same transfer.
        self.files_dir = files_dir_for_db(db_path)
        self.local_master_key = LocalKeyStore(db_path).load_or_create()
        self.db = Database(db_path, master_key=self.local_master_key)
        identity = self.db.load_identity()
        if identity:
            self.public_key, self.secret_key = identity
        else:
            import_blob = os.environ.get("QUANTUM_CHAT_IMPORT_IDENTITY")
            import_pass = os.environ.get("QUANTUM_CHAT_IMPORT_PASSPHRASE")
            if import_blob and import_pass:
                self.public_key, self.secret_key = unpack_identity_backup(import_blob, import_pass)
                LOG.info("Seeded identity %s from QUANTUM_CHAT_IMPORT_IDENTITY", key_fingerprint(self.public_key))
            else:
                pk, sk = self.crypto.new_identity()
                self.public_key, self.secret_key = pk.hex(), sk
            self.db.save_identity(self.public_key, self.secret_key)
        self.signaling_url = signaling_url
        self.signaling_ws: Any = None
        self.ui_clients: Set[Any] = set()
        self.online_peers: Set[str] = set()
        self.pending_offers: Dict[str, PendingOffer] = {}
        self.sessions: Dict[str, bytes] = {}
        self.group_members: Dict[str, Set[str]] = {}
        self.ui_token = secrets.token_urlsafe(32)
        self.expected_public_key_bytes = self.crypto.sign_public_key_bytes
        self.relay_alias = hashlib.sha256((self.public_key + ":relay-alias").encode()).hexdigest()
        self.direct_url = direct_url
        self.enable_direct = enable_direct
        self.peer_direct: Dict[str, str] = {}
        self._typing_timers: Dict[str, asyncio.TimerHandle] = {}
        self.max_storage_bytes = max_storage_bytes
        self._direct_rate: Dict[str, List[int]] = {}
        # peer_pubkey -> {"call_id", "role" ("caller"/"callee"), "media"
        # ("audio"/"video"), "state" ("ringing"/"active")}. Call *signaling*
        # (offer/answer/ICE candidates) rides the same PQ-authenticated
        # relay/direct channel as everything else in this file. The actual
        # audio/video media stream itself is standard WebRTC (DTLS-SRTP),
        # negotiated directly browser-to-browser after signaling completes —
        # that leg is not post-quantum, since no mainstream browser offers a
        # PQ WebRTC media path yet. See README for the full caveat.
        self.active_calls: Dict[str, Dict[str, Any]] = {}
        self.ice_servers = self._load_ice_servers()
        self._load_state()

    @staticmethod
    def _load_ice_servers() -> List[Dict[str, Any]]:
        raw = os.environ.get("QUANTUM_CHAT_ICE_SERVERS")
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, list):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                LOG.warning("Ignoring malformed QUANTUM_CHAT_ICE_SERVERS")
        # A public STUN-only default is enough for NAT traversal between two
        # peers that aren't both behind symmetric NATs. Production
        # deployments that need to guarantee connectivity should set
        # QUANTUM_CHAT_ICE_SERVERS to a JSON list including a TURN server
        # with credentials, e.g.:
        #   [{"urls":"stun:stun.l.google.com:19302"},
        #    {"urls":"turn:turn.example.com:3478","username":"u","credential":"p"}]
        return [{"urls": "stun:stun.l.google.com:19302"}]

    def _load_state(self) -> None:
        for friend in self.db.get_friends():
            if friend.get("direct_url"):
                self.peer_direct[friend["pubkey"]] = friend["direct_url"]
            session = self.db.get_session(friend["pubkey"])
            if session:
                self.sessions[friend["pubkey"]] = session["key"]
        for group in self.db.groups_for(self.public_key):
            self.group_members[group["group_id"]] = set(
                self.db.group_members(group["group_id"])
            )

    async def broadcast_ui(self, event: Dict[str, Any]) -> None:
        payload = json.dumps(event)
        dead = []
        for ws in self.ui_clients:
            try:
                await ws.send(payload)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.ui_clients.discard(ws)

    def _with_message_metadata(self, msgs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        msg_ids = [m["msg_id"] for m in msgs]
        reactions = self.db.get_reactions(msg_ids)
        read_receipts = self.db.get_read_receipts(msg_ids)
        for m in msgs:
            m["reactions"] = reactions.get(m["msg_id"], [])
            m["read_at"] = read_receipts.get(m["msg_id"])
        return msgs

    def _public_file(self, row: Dict[str, Any]) -> Dict[str, Any]:
        """Return the stable, non-sensitive file shape consumed by the UI."""
        return {
            "file_id": row["file_id"],
            "filename": row["filename"],
            "sender_pubkey": row["sender_pubkey"],
            "recipient_pubkey": row.get("recipient_pubkey"),
            "group_id": row.get("group_id"),
            "size": int(row["size"]),
            "sha256": row["sha256"],
            "mime_type": safe_content_type(row.get("mime_type"), row["filename"]),
            "uploaded_at": int(row["uploaded_at"]),
            "direction": "out" if row["sender_pubkey"] == self.public_key else "in",
            "url": f"/files/{row['file_id']}",
        }

    def state_payload(self) -> Dict[str, Any]:
        msgs = self._with_message_metadata(self.db.recent_messages())
        has_more = bool(msgs) and self.db.has_messages_before(msgs[0]["id"])
        return {
            "type": "state",
            "public_key": self.public_key,
            "fingerprint": key_fingerprint(self.public_key),
            "signaling_url": self.signaling_url,
            "online": sorted(self.online_peers),
            "relay_alias": self.relay_alias,
            "direct_url": self.direct_url,
            "friends": self.db.get_friends(),
            "groups": self.db.group_details_for(self.public_key),
            "messages": msgs,
            "has_more_messages": has_more,
            "files": [QuantumNode._public_file(self, f) for f in self.db.recent_files()],
            "sessions": self.db.session_summary(),
            "storage_bytes": self._storage_bytes_used(),
            "max_storage_bytes": self.max_storage_bytes,
            "version": VERSION,
            "ice_servers": self.ice_servers,
        }

    async def send_relay(self, peer_pubkey: str, payload: Dict[str, Any],
                         queue_on_failure: bool = False, ephemeral: bool = False) -> None:
        envelope: Dict[str, Any] = {"type": "relay", "to": peer_pubkey, "payload": payload}
        if ephemeral:
            # Tell the relay this is best-effort, ephemeral traffic (typing
            # indicators, ICE candidates, device-sync pings) that should be
            # dropped rather than persisted to its offline queue if the
            # target isn't currently connected — see SignalingServer.handle.
            envelope["ephemeral"] = True
        if self.enable_direct and peer_pubkey in self.peer_direct:
            try:
                await self.send_direct(peer_pubkey, payload)
                self.db.metric_inc("direct_sent")
                return
            except Exception as exc:
                LOG.debug("Direct delivery to %s failed, falling back to relay: %s", short_key(peer_pubkey), exc)
                self.db.metric_inc("direct_fallback")
        if not self.signaling_ws:
            if queue_on_failure:
                self.db.queue_outbox(peer_pubkey, envelope)
                return
            raise RuntimeError("Not connected to signaling server")
        await self.signaling_ws.send(json.dumps(envelope))
        self.db.metric_inc("relay_sent")

    async def send_direct(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        websockets = require_websockets()
        direct_url = self.peer_direct[peer_pubkey]
        hello = {"from": self.public_key, "to": peer_pubkey, "sent_at": utc_ts(), "payload": payload}
        sig = b64e(self.crypto.sign(self.secret_key, canonical_json(hello)))
        async with websockets.connect(direct_url, max_size=MAX_FILE_BYTES * 2) as ws:
            await ws.send(json.dumps({"type": "direct", **hello, "signature": sig}))
            ack = json.loads(await asyncio.wait_for(ws.recv(), timeout=5))
            if ack.get("type") != "direct_ack":
                raise RuntimeError("Direct peer did not acknowledge payload")

    def _direct_rate_ok(self, remote: str, limit: int = 30, window: int = 60) -> bool:
        now = utc_ts()
        events = [t for t in self._direct_rate.get(remote, []) if now - t < window]
        events.append(now)
        self._direct_rate[remote] = events
        return len(events) <= limit

    def _direct_rate_gc(self, window: int = 60) -> None:
        """Drop rate-limit buckets whose entries have all aged out so the
        _direct_rate dict can't grow unboundedly as peers (and attackers)
        cycle through source IPs. Cheap to call once per inbound connection."""
        now = utc_ts()
        stale_hosts = [host for host, events in self._direct_rate.items()
                       if not any(now - t < window for t in events)]
        for host in stale_hosts:
            self._direct_rate.pop(host, None)

    async def handle_direct_peer(self, ws: Any) -> None:
        self._direct_rate_gc()
        remote = getattr(ws, "remote_address", None)
        remote_host = str(remote[0]) if remote else "unknown"
        if not self._direct_rate_ok(remote_host):
            await ws.close(code=1008, reason="Rate limit exceeded")
            return
        try:
            raw = await asyncio.wait_for(ws.recv(), timeout=5)
            msg = json.loads(raw)
            if msg.get("type") != "direct" or msg.get("to") != self.public_key:
                raise ValueError("Invalid direct peer frame")
            peer = self.validate_peer_key(msg.get("from", ""))
            sig = b64d(msg.get("signature", ""))
            hello = {"from": peer, "to": self.public_key, "sent_at": msg.get("sent_at"), "payload": msg.get("payload")}
            if not self.crypto.verify(bytes.fromhex(peer), canonical_json(hello), sig):
                raise ValueError("Invalid direct peer signature")
            if not self.db.is_friend(peer):
                raise ValueError("Direct peer is not a trusted friend")
            await self.handle_relay_payload(peer, msg.get("payload"))
            await ws.send(json.dumps({"type": "direct_ack"}))
            self.db.metric_inc("direct_received")
        except Exception as exc:
            self.db.metric_inc("direct_rejected")
            try:
                await ws.send(json.dumps({"type": "error", "text": str(exc)}))
            except Exception:
                pass  # peer may already be gone

    async def flush_outbox(self, peer_pubkey: str) -> None:
        if not self.signaling_ws:
            return
        for item in self.db.queued_outbox(peer_pubkey):
            await self.signaling_ws.send(item["payload"])
            self.db.mark_outbox_sent(item["id"])

    def validate_peer_key(self, pubkey: str) -> str:
        return validate_public_key(pubkey, self.expected_public_key_bytes)

    def encrypt_for_disk(self, raw: bytes, file_id: str) -> Tuple[bytes, Optional[bytes]]:
        encrypted, nonce, _ = self.db.encrypt_blob(raw, f"file:{file_id}".encode())
        return encrypted, nonce

    def decrypt_from_disk(self, raw: bytes, file_id: str, nonce: Optional[bytes]) -> bytes:
        return self.db.decrypt_blob(raw, nonce, f"file:{file_id}".encode())

    def encrypt_chunk_for_disk(self, raw: bytes, file_id: str, chunk_index: int) -> Tuple[bytes, Optional[bytes]]:
        return self.db.encrypt_blob(raw, f"file-chunk:{file_id}:{chunk_index}".encode())[:2]

    def decrypt_chunk_from_disk(self, raw: bytes, file_id: str, chunk_index: int, nonce: Optional[bytes]) -> bytes:
        return self.db.decrypt_blob(raw, nonce, f"file-chunk:{file_id}:{chunk_index}".encode())

    # ── Storage accounting / quota ────────────────────────────────────────────

    def _storage_bytes_used(self) -> int:
        """Bytes currently on disk for files + in-flight chunks, backed by an
        incrementally maintained counter so /health does not need to walk the
        filesystem on every call. Backfills once from disk if the counter has
        never been initialized (e.g. upgrading from an older database)."""
        metrics = self.db.metrics()
        if "storage_bytes" not in metrics:
            files_dir = getattr(self, "files_dir", Path(FILES_DIR))
            total = (sum(p.stat().st_size for p in files_dir.glob("**/*") if p.is_file())
                     if files_dir.exists() else 0)
            self.db.metric_inc("storage_bytes", total)
            return total
        return metrics["storage_bytes"]

    def _check_storage_quota(self, incoming_bytes: int) -> None:
        if self.max_storage_bytes <= 0:
            return  # 0 or negative disables quota enforcement
        used = self._storage_bytes_used()
        if used + incoming_bytes > self.max_storage_bytes:
            raise ValueError(
                f"Storage quota exceeded: {used / (1024*1024):.1f} MB used, "
                f"{self.max_storage_bytes / (1024*1024):.1f} MB limit"
            )

    def _track_storage(self, delta_bytes: int) -> None:
        self.db.metric_inc("storage_bytes", delta_bytes)

    def signed_payload(self, kind: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        envelope = {"kind": kind, "payload": payload}
        sig = self.crypto.sign(self.secret_key, canonical_json(envelope))
        return {"kind": kind, "payload": payload, "signature": b64e(sig)}

    def verify_signed(self, peer_pubkey: str, data: Dict[str, Any]) -> bool:
        sig = b64d(data.get("signature", ""))
        envelope = {"kind": data.get("kind"), "payload": data.get("payload")}
        return self.crypto.verify(bytes.fromhex(peer_pubkey), canonical_json(envelope), sig)

    def cleanup_pending_offers(self) -> None:
        now = utc_ts()
        expired = [
            peer for peer, offer in self.pending_offers.items()
            if now - offer.created_at > PENDING_OFFER_TTL
        ]
        for peer in expired:
            self.pending_offers.pop(peer, None)

    def health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": VERSION,
            "public_key": self.public_key,
            "fingerprint": key_fingerprint(self.public_key),
            "signaling_connected": self.signaling_ws is not None,
            "online_peers": len(self.online_peers),
            "active_sessions": len(self.sessions),
            "friends": len(self.db.get_friends()),
            "ui_clients": len(self.ui_clients),
            "direct_enabled": self.enable_direct,
            "direct_url": self.direct_url,
            "outbox_depth": self.db.outbox_depth(),
            "metrics": self.db.metrics(),
            "file_storage_bytes": self._storage_bytes_used(),
            "max_storage_bytes": self.max_storage_bytes,
            "timestamp": utc_ts(),
        }

    # ── Session management ────────────────────────────────────────────────────

    def session_fresh(self, peer_pubkey: str) -> bool:
        session = self.db.get_session(peer_pubkey)
        return bool(session and utc_ts() - int(session["established_at"]) < SESSION_TTL)

    async def require_fresh_session(self, peer_pubkey: str, outgoing: bool = True) -> bytes:
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            self.sessions.pop(peer_pubkey, None)
            if outgoing:
                await self.connect_peer(peer_pubkey)
                raise ValueError("Secure session expired or missing; rekeying started, retry after handshake completes")
            raise ValueError("Encrypted payload received for an expired or missing session")
        return self.sessions[peer_pubkey]

    async def connect_peer(self, peer_pubkey: str) -> None:
        self.cleanup_pending_offers()
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey == self.public_key:
            raise ValueError("You cannot connect to your own public key")
        if not self.db.is_friend(peer_pubkey):
            raise ValueError("Add this public key as a friend before connecting")
        kem_pk, kem_sk = self.crypto.new_kem_keypair()
        session_id = str(uuid.uuid4())
        payload = {
            "protocol": "quantum-chat-v4",
            "from": self.public_key,
            "to": peer_pubkey,
            "session_id": session_id,
            "kem_pk": b64e(kem_pk),
            "created_at": utc_ts(),
        }
        self.pending_offers[peer_pubkey] = PendingOffer(
            peer_pubkey, session_id, kem_sk, utc_ts(), payload
        )
        await self.send_relay(peer_pubkey, self.signed_payload("session_offer", payload))
        await self.broadcast_ui({
            "type": "notice", "level": "info",
            "text": f"Session offer sent to {short_key(peer_pubkey)}"
        })

    async def handle_session_offer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.db.is_friend(peer_pubkey):
            await self.broadcast_ui({
                "type": "notice", "level": "warning",
                "text": f"Rejected untrusted session offer from {short_key(peer_pubkey)}"
            })
            return
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session offer signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Session offer routing metadata mismatch")
        if utc_ts() - int(payload.get("created_at", 0)) > PENDING_OFFER_TTL:
            raise ValueError("Session offer expired")
        if payload.get("protocol") != "quantum-chat-v4":
            raise ValueError("Unsupported session protocol")
        ciphertext, secret = self.crypto.kem_encapsulate(b64d(payload["kem_pk"]))
        transcript = {
            "offer": payload,
            "ciphertext": b64e(ciphertext),
            "roles": {"initiator": peer_pubkey, "responder": self.public_key},
        }
        key = self.crypto.derive_session_key(
            secret, self.public_key, peer_pubkey, payload["session_id"], transcript
        )
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=False)
        self.db.touch_friend(peer_pubkey)
        accept = {
            "protocol": "quantum-chat-v4",
            "from": self.public_key,
            "to": peer_pubkey,
            "session_id": payload["session_id"],
            "ciphertext": b64e(ciphertext),
            "accepted_at": utc_ts(),
        }
        await self.send_relay(peer_pubkey, self.signed_payload("session_accept", accept))
        await self.broadcast_ui({
            "type": "notice", "level": "success",
            "text": f"Secure session established with {short_key(peer_pubkey)}"
        })
        await self.broadcast_ui(self.state_payload())

    async def handle_session_accept(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid session accept signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Session accept routing metadata mismatch")
        pending = self.pending_offers.pop(peer_pubkey, None)
        if not pending or pending.session_id != payload["session_id"]:
            raise ValueError("Session accept does not match an active offer")
        if payload.get("protocol") != "quantum-chat-v4":
            raise ValueError("Unsupported session protocol")
        secret = self.crypto.kem_decapsulate(pending.kem_secret_key, b64d(payload["ciphertext"]))
        transcript = {
            "offer": pending.offer_payload,
            "ciphertext": payload["ciphertext"],
            "roles": {"initiator": self.public_key, "responder": peer_pubkey},
        }
        key = self.crypto.derive_session_key(
            secret, self.public_key, peer_pubkey, payload["session_id"], transcript
        )
        self.sessions[peer_pubkey] = key
        self.db.save_session(peer_pubkey, payload["session_id"], key, initiator=True)
        self.db.touch_friend(peer_pubkey)
        await self.broadcast_ui({
            "type": "notice", "level": "success",
            "text": f"Secure session established with {short_key(peer_pubkey)}"
        })
        await self.broadcast_ui(self.state_payload())

    # ── Chat ──────────────────────────────────────────────────────────────────

    async def send_chat(self, peer_pubkey: str, text: str,
                        group_id: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        text = (text or "").strip()
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        msg_id = str(uuid.uuid4())
        counter = self.db.next_send_counter(peer_pubkey)
        payload = {
            "msg_id": msg_id,
            "from": self.public_key,
            "to": peer_pubkey,
            "group_id": group_id,
            "counter": counter,
            "sent_at": utc_ts(),
        }
        msg_key = self.crypto.derive_message_key(
            session_key, self.public_key, peer_pubkey, counter, "chat"
        )
        packet = self.crypto.encrypt(msg_key, pad_plaintext(text.encode()), canonical_json(payload))
        # Save the outgoing message BEFORE send_relay so the row exists by
        # the time a synchronous delivery_ack comes back over the direct
        # transport. With direct delivery, send_relay blocks until the peer
        # processes the message and returns an ack; if the ack's
        # update_message_status call runs before save_message, the UPDATE
        # matches zero rows and the message is then INSERTed with
        # status='sent_to_relay', overwriting the (never-applied)
        # 'delivered_to_peer' update.
        self.db.save_message(
            msg_id, self.public_key, text, "out",
            recipient=peer_pubkey, group_id=group_id,
            delivered=False, status="sent_to_relay"
        )
        try:
            await self.send_relay(
                peer_pubkey,
                {"kind": "chat", "payload": payload, "packet": packet},
                queue_on_failure=True
            )
        except Exception:
            # If send_relay fails outright (not just queues), mark the
            # message as still pending so the UI shows it as 'sent_to_relay'
            # and the user knows to retry. The save_message above already
            # committed with that status, so we just log here.
            LOG.warning("send_relay failed for chat message %s", msg_id)
            raise
        await self.broadcast_ui({
            "type": "message",
            "message": {
                "msg_id": msg_id, "sender_pubkey": self.public_key,
                "recipient_pubkey": peer_pubkey, "group_id": group_id,
                "body": text, "direction": "out",
                "timestamp": utc_ts(), "delivered": 0,
                "status": "sent_to_relay", "reactions": [], "read_at": None,
            }
        })
        await self.sync_to_devices("chat_out", {
            "msg_id": msg_id, "sender_pubkey": self.public_key,
            "recipient_pubkey": peer_pubkey, "group_id": group_id,
            "body": text, "delivered": False, "status": "sent_to_relay",
        })

    async def handle_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Chat routing metadata mismatch")
        counter = int(payload.get("counter", 0))
        msg_key = self.crypto.derive_message_key(
            session_key, peer_pubkey, self.public_key, counter, "chat"
        )
        text = unpad_plaintext(self.crypto.decrypt(
            msg_key, data["packet"], canonical_json(payload)
        )).decode("utf-8")
        self.db.mark_recv_counter(peer_pubkey, counter)
        inserted = self.db.save_message(
            payload["msg_id"], peer_pubkey, text, "in",
            recipient=self.public_key, group_id=payload.get("group_id"),
            delivered=True, status="delivered"
        )
        if inserted:
            self.db.increment_unread(peer_pubkey)
            ack = self.signed_payload("delivery_ack", {
                "from": self.public_key, "to": peer_pubkey,
                "msg_id": payload["msg_id"], "delivered_at": utc_ts(),
            })
            await self.send_relay(peer_pubkey, ack, queue_on_failure=True)
            await self.broadcast_ui({
                "type": "message",
                "message": {
                    "msg_id": payload["msg_id"], "sender_pubkey": peer_pubkey,
                    "recipient_pubkey": self.public_key,
                    "group_id": payload.get("group_id"),
                    "body": text, "direction": "in",
                    "timestamp": utc_ts(), "delivered": 1,
                    "status": "delivered", "reactions": [], "read_at": None,
                }
            })
            await self.sync_to_devices("chat_in", {
                "msg_id": payload["msg_id"], "sender_pubkey": peer_pubkey,
                "recipient_pubkey": self.public_key, "group_id": payload.get("group_id"),
                "body": text, "delivered": True, "status": "delivered",
            })

    # ── Typing Indicators ─────────────────────────────────────────────────────

    async def send_typing(self, peer_pubkey: str, active: bool) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            return  # silently skip, session may not exist yet
        try:
            await self.send_relay(peer_pubkey, {
                "kind": "typing",
                "from": self.public_key,
                "to": peer_pubkey,
                "active": active,
            }, ephemeral=True)
        except Exception:
            pass  # typing indicators are ephemeral — failures are acceptable

    async def handle_typing(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if data.get("from") != peer_pubkey or data.get("to") != self.public_key:
            return
        active = bool(data.get("active"))
        # Cancel any pending clear timer
        if peer_pubkey in self._typing_timers:
            self._typing_timers[peer_pubkey].cancel()
            del self._typing_timers[peer_pubkey]
        await self.broadcast_ui({"type": "typing", "peer": peer_pubkey, "active": active})
        if active:
            # get_event_loop() is deprecated in 3.12+ when no loop is running;
            # we're inside an async coroutine so the running loop is the right one.
            loop = asyncio.get_running_loop()
            handle = loop.call_later(
                TYPING_INACTIVITY_TTL,
                lambda: asyncio.ensure_future(
                    self.broadcast_ui({"type": "typing", "peer": peer_pubkey, "active": False})
                )
            )
            self._typing_timers[peer_pubkey] = handle

    # ── Read Receipts ─────────────────────────────────────────────────────────

    async def send_read_receipt(self, peer_pubkey: str, msg_id: str) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if peer_pubkey not in self.sessions or not self.session_fresh(peer_pubkey):
            return
        try:
            await self.send_relay(peer_pubkey, self.signed_payload("read_receipt", {
                "from": self.public_key, "to": peer_pubkey,
                "msg_id": msg_id, "read_at": utc_ts(),
            }), queue_on_failure=True)
        except Exception as exc:
            LOG.debug("Failed to send read receipt: %s", exc)

    async def handle_read_receipt(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid read receipt signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Read receipt routing mismatch")
        msg_id = str(payload.get("msg_id", ""))
        # Use the receipt's own timestamp so the read_at column reflects
        # when the *reader* actually read it, not when we happened to
        # process the receipt (which can lag by seconds under load or
        # when the receipt was queued offline).
        read_at = int(payload.get("read_at") or utc_ts())
        if self.db.save_read_receipt(msg_id, peer_pubkey):
            # update_message_status sets status+delivered but not read_at,
            # so we also need mark_remote_read to stamp the outgoing
            # message's read_at column — without this, the UI's "✓✓ read"
            # indicator never lights up for the sender even after the
            # recipient has actually read the message.
            self.db.update_message_status(msg_id, "read", delivered=True)
            self.db.mark_remote_read(msg_id, read_at)
            await self.broadcast_ui({
                "type": "read_receipt",
                "msg_id": msg_id,
                "peer": peer_pubkey,
                "read_at": read_at,
            })

    # ── Reactions ─────────────────────────────────────────────────────────────

    async def send_reaction(self, peer_pubkey: str, msg_id: str,
                            emoji: str, action: str = "add") -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        emoji = validate_emoji(emoji)
        if action not in ("add", "remove"):
            raise ValueError("Reaction action must be 'add' or 'remove'")
        await self.require_fresh_session(peer_pubkey, outgoing=True)
        await self.send_relay(peer_pubkey, self.signed_payload("reaction", {
            "from": self.public_key, "to": peer_pubkey,
            "msg_id": msg_id, "emoji": emoji, "action": action,
        }), queue_on_failure=True)
        if action == "add":
            self.db.add_reaction(msg_id, self.public_key, emoji, direction="out")
        else:
            self.db.remove_reaction(msg_id, self.public_key, emoji)
        await self.broadcast_ui({
            "type": "reaction",
            "msg_id": msg_id, "peer": self.public_key,
            "emoji": emoji, "action": action,
        })

    async def handle_reaction(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid reaction signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Reaction routing mismatch")
        emoji = validate_emoji(payload.get("emoji", ""))
        action = payload.get("action", "add")
        if action not in ("add", "remove"):
            raise ValueError("Invalid reaction action")
        msg_id = str(payload.get("msg_id", ""))
        if action == "add":
            self.db.add_reaction(msg_id, peer_pubkey, emoji, direction="in")
        else:
            self.db.remove_reaction(msg_id, peer_pubkey, emoji)
        await self.broadcast_ui({
            "type": "reaction",
            "msg_id": msg_id, "peer": peer_pubkey,
            "emoji": emoji, "action": action,
        })

    # ── Multi-device sync ────────────────────────────────────────────────────

    async def sync_to_devices(self, event: str, data: Dict[str, Any]) -> None:
        """Best-effort fan-out of a local event (a message we just sent or
        received, or a read/unread change) to any other device that shares
        this identity's secret key. Addressed to our own public key so the
        relay's per-identity socket fan-out (see SignalingServer.handle)
        delivers it to every *other* device currently online under this
        identity, and encrypted with a key derived from the secret key
        itself so the relay never sees plaintext. This is a convenience
        sync, not a source of truth — each device's own local database
        remains authoritative for its own state — so failures are swallowed
        rather than raised."""
        try:
            key = self.crypto.derive_device_sync_key(self.secret_key)
            body = canonical_json({"event": event, "data": data})
            packet = self.crypto.encrypt(key, body)
            envelope = self.signed_payload("device_sync", {"packet": packet})
            await self.send_relay(self.public_key, envelope, ephemeral=True)
        except Exception as exc:
            LOG.debug("Device sync fan-out skipped: %s", exc)

    async def _handle_device_sync(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        if peer_pubkey != self.public_key or not self.verify_signed(self.public_key, payload):
            raise ValueError("Invalid device sync frame")
        key = self.crypto.derive_device_sync_key(self.secret_key)
        inner = payload.get("payload", {})
        body = json.loads(self.crypto.decrypt(key, inner["packet"]))
        event = body.get("event")
        data = body.get("data", {}) or {}
        if event in ("chat_out", "chat_in"):
            direction = "out" if event == "chat_out" else "in"
            inserted = self.db.save_message(
                str(data.get("msg_id", "")), str(data.get("sender_pubkey", "")),
                str(data.get("body", "")), direction,
                recipient=data.get("recipient_pubkey"), group_id=data.get("group_id"),
                delivered=bool(data.get("delivered", True)), status=str(data.get("status", "delivered")),
            )
            if inserted:
                if direction == "in":
                    self.db.increment_unread(str(data.get("sender_pubkey", "")))
                await self.broadcast_ui({"type": "message", "message": {
                    "msg_id": data.get("msg_id"), "sender_pubkey": data.get("sender_pubkey"),
                    "recipient_pubkey": data.get("recipient_pubkey"), "group_id": data.get("group_id"),
                    "body": data.get("body"), "direction": direction, "timestamp": utc_ts(),
                    "delivered": int(bool(data.get("delivered", True))),
                    "status": data.get("status", "delivered"), "reactions": [], "read_at": None,
                }})
        elif event == "read_local":
            peer = str(data.get("peer_pubkey", ""))
            if peer:
                self.db.clear_unread(peer)
                await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})

    # ── Voice/video calls (WebRTC signaling over the authenticated relay) ───

    async def send_call_offer(self, peer_pubkey: str, sdp: Dict[str, Any], media: str = "video") -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if not self.db.is_friend(peer_pubkey):
            raise ValueError("Add this public key as a friend before calling")
        if media not in ("audio", "video"):
            raise ValueError("Call media must be 'audio' or 'video'")
        if peer_pubkey in self.active_calls:
            raise ValueError("A call with this friend is already in progress")
        await self.require_fresh_session(peer_pubkey, outgoing=True)
        call_id = str(uuid.uuid4())
        self.active_calls[peer_pubkey] = {"call_id": call_id, "role": "caller", "media": media, "state": "ringing"}
        await self.send_relay(peer_pubkey, self.signed_payload("call_offer", {
            "from": self.public_key, "to": peer_pubkey, "call_id": call_id,
            "media": media, "sdp": sdp, "sent_at": utc_ts(),
        }))
        await self.broadcast_ui({
            "type": "call_state", "peer": peer_pubkey, "call_id": call_id,
            "state": "ringing", "role": "caller", "media": media,
        })

    async def handle_call_offer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.db.is_friend(peer_pubkey):
            return  # silently ignore call attempts from non-friends
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid call offer signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Call offer routing mismatch")
        media = payload.get("media") if payload.get("media") in ("audio", "video") else "video"
        if peer_pubkey in self.active_calls:
            # Already ringing/active with this peer (or with someone else,
            # scoped per-peer here) — tell the caller we're busy instead of
            # silently dropping their offer.
            try:
                await self.send_relay(peer_pubkey, self.signed_payload("call_end", {
                    "from": self.public_key, "to": peer_pubkey,
                    "call_id": payload.get("call_id"), "reason": "busy",
                }))
            except Exception:
                pass
            return
        self.active_calls[peer_pubkey] = {
            "call_id": payload.get("call_id"), "role": "callee", "media": media, "state": "ringing",
        }
        await self.broadcast_ui({
            "type": "call_incoming", "peer": peer_pubkey, "call_id": payload.get("call_id"),
            "media": media, "sdp": payload.get("sdp"),
        })

    async def send_call_answer(self, peer_pubkey: str, sdp: Dict[str, Any]) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        call = self.active_calls.get(peer_pubkey)
        if not call or call["role"] != "callee":
            raise ValueError("No incoming call from this friend to answer")
        await self.send_relay(peer_pubkey, self.signed_payload("call_answer", {
            "from": self.public_key, "to": peer_pubkey, "call_id": call["call_id"],
            "sdp": sdp, "sent_at": utc_ts(),
        }))
        call["state"] = "active"
        await self.broadcast_ui({
            "type": "call_state", "peer": peer_pubkey, "call_id": call["call_id"],
            "state": "active", "role": "callee", "media": call["media"],
        })

    async def handle_call_answer(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid call answer signature")
        payload = data["payload"]
        if payload.get("from") != peer_pubkey or payload.get("to") != self.public_key:
            raise ValueError("Call answer routing mismatch")
        call = self.active_calls.get(peer_pubkey)
        if not call or call["call_id"] != payload.get("call_id") or call["role"] != "caller":
            raise ValueError("Call answer does not match an active outgoing call")
        call["state"] = "active"
        await self.broadcast_ui({
            "type": "call_answered", "peer": peer_pubkey,
            "call_id": call["call_id"], "sdp": payload.get("sdp"),
        })

    async def send_call_ice(self, peer_pubkey: str, candidate: Dict[str, Any]) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        call = self.active_calls.get(peer_pubkey)
        if not call:
            return  # call already ended locally; drop stray trickle-ICE candidates
        await self.send_relay(peer_pubkey, self.signed_payload("call_ice", {
            "from": self.public_key, "to": peer_pubkey,
            "call_id": call["call_id"], "candidate": candidate,
        }), ephemeral=True)

    async def handle_call_ice(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            return
        payload = data["payload"]
        call = self.active_calls.get(peer_pubkey)
        if not call or call["call_id"] != payload.get("call_id"):
            return
        await self.broadcast_ui({
            "type": "call_ice", "peer": peer_pubkey, "candidate": payload.get("candidate"),
        })

    async def send_call_end(self, peer_pubkey: str, reason: str = "hangup") -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        call = self.active_calls.pop(peer_pubkey, None)
        if not call:
            return
        try:
            await self.send_relay(peer_pubkey, self.signed_payload("call_end", {
                "from": self.public_key, "to": peer_pubkey,
                "call_id": call["call_id"], "reason": reason,
            }))
        except Exception:
            pass  # best-effort — the local call state is already cleared either way
        await self.broadcast_ui({
            "type": "call_state", "peer": peer_pubkey,
            "call_id": call["call_id"], "state": "ended", "reason": reason,
        })

    async def handle_call_end(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        payload = data.get("payload", {}) if isinstance(data, dict) else {}
        call = self.active_calls.pop(peer_pubkey, None)
        await self.broadcast_ui({
            "type": "call_state", "peer": peer_pubkey,
            "call_id": (call or {}).get("call_id") or payload.get("call_id"),
            "state": "ended", "reason": payload.get("reason", "hangup"),
        })

    async def send_group_invite(self, peer_pubkey: str, invite: Dict[str, Any], group_key: bytes) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        counter = self.db.next_send_counter(peer_pubkey)
        invite = {**invite, "counter": counter}
        key_packet = self.crypto.encrypt(
            self.crypto.derive_message_key(session_key, self.public_key, peer_pubkey, counter, "group-key"),
            group_key, canonical_json(invite)
        )
        await self.send_relay(peer_pubkey, self.signed_payload("group_invite", invite) | {"packet": key_packet}, queue_on_failure=True)

    async def rotate_group_key(self, group_id: str) -> None:
        """Generate a fresh group epoch key and distribute it to current
        members over their authenticated pairwise sessions. Members who are
        no longer in group_members (e.g. just removed) are not sent the new
        key and lose the ability to read anything encrypted after this point,
        even though they may still hold prior epoch keys for old history."""
        if self.db.group_role(group_id, self.public_key) != "owner":
            raise ValueError("Only the group owner can rotate the group key")
        groups = {g["group_id"]: g for g in self.db.groups_for(self.public_key)}
        group = groups.get(group_id)
        if not group:
            raise ValueError("Unknown group")
        members = self.db.group_members(group_id)
        new_epoch = int(group["epoch"]) + 1
        new_key = secrets.token_bytes(32)
        self.db.save_group_key(group_id, new_epoch, new_key, self.public_key)

        async def deliver_key(member: str) -> None:
            if member in self.sessions and self.session_fresh(member):
                invite = {
                    "group_id": group_id, "name": group["name"], "members": members,
                    "from": self.public_key, "to": member, "epoch": new_epoch,
                }
                try:
                    await self.send_group_invite(member, invite, new_key)
                except Exception as exc:
                    LOG.warning("Failed to deliver rotated group key to %s: %s", short_key(member), exc)

        await asyncio.gather(*(deliver_key(m) for m in members if m != self.public_key))
        await self.broadcast_ui({
            "type": "notice", "level": "success",
            "text": f"Group key rotated (epoch {new_epoch})"
        })
        await self.broadcast_ui(self.state_payload())

    async def remove_group_member(self, group_id: str, pubkey: str) -> None:
        if self.db.group_role(group_id, self.public_key) != "owner":
            raise ValueError("Only the group owner can remove members")
        if pubkey == self.public_key:
            raise ValueError("The owner cannot remove themselves from the group")
        if not self.db.remove_group_member(group_id, pubkey):
            raise ValueError("That public key is not a member of this group")
        await self.rotate_group_key(group_id)

    # ── Group messaging ───────────────────────────────────────────────────────

    async def send_group_chat(self, group_id: str, text: str) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        text = (text or "").strip()
        if not text or len(text.encode()) > MAX_TEXT_BYTES:
            raise ValueError("Message is empty or too large")
        group_key = self.db.get_group_key(group_id)
        if not group_key:
            key = secrets.token_bytes(32)
            self.db.save_group_key(group_id, 1, key, self.public_key)
            group_key = self.db.get_group_key(group_id)
        epoch = int(group_key["epoch"])
        msg_id = str(uuid.uuid4())
        meta = {"msg_id": msg_id, "from": self.public_key, "group_id": group_id,
                "epoch": epoch, "sent_at": utc_ts()}
        packet = self.crypto.encrypt(group_key["key"], pad_plaintext(text.encode()), canonical_json(meta))
        envelope = self.signed_payload("group_chat", {"meta": meta, "packet": packet})
        # Save the outgoing group message BEFORE fan-out so the row exists by
        # the time any synchronous ack/reaction comes back over the direct
        # transport — same rationale as send_chat's save-before-send order.
        delivered = 0
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                delivered += 1  # optimistically count intended recipients
        self.db.save_message(msg_id, self.public_key, text, "out", group_id=group_id,
                             delivered=delivered > 0, status="sent_to_group")

        async def deliver(peer: str) -> bool:
            try:
                await self.send_relay(peer, envelope, queue_on_failure=True)
                return True
            except Exception as exc:
                LOG.warning("Group fan-out to %s failed: %s", short_key(peer), exc)
                return False

        # Fan out to all recipients concurrently instead of one at a time —
        # in a large group, sequential awaits mean the Nth member waits on
        # N-1 round trips to the relay before their copy even goes out.
        recipients = [peer for peer in members - {self.public_key} if self.db.is_friend(peer)]
        results = await asyncio.gather(*(deliver(peer) for peer in recipients)) if recipients else []
        actually_sent = sum(1 for ok in results if ok)
        await self.broadcast_ui({"type": "message", "message": {
            "msg_id": msg_id, "sender_pubkey": self.public_key, "recipient_pubkey": None,
            "group_id": group_id, "body": text, "direction": "out", "timestamp": utc_ts(),
            "delivered": int(actually_sent > 0), "status": "sent_to_group", "reactions": [], "read_at": None,
        }})

    async def send_group_file(self, group_id: str, filename: str, encoded: str,
                              content_type: Optional[str] = None) -> None:
        members = set(self.db.group_members(group_id))
        if self.public_key not in members:
            raise ValueError("You are not a member of this group")
        sent = 0
        for peer in members - {self.public_key}:
            if self.db.is_friend(peer):
                await self.send_file(peer, filename, encoded, group_id=group_id,
                                     content_type=content_type)
                sent += 1
        if not sent:
            raise ValueError("No group members with active friend records available")

    # ── File transfer ─────────────────────────────────────────────────────────

    async def send_file(self, peer_pubkey: str, filename: str, encoded: str,
                        group_id: Optional[str] = None,
                        content_type: Optional[str] = None) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        raw = b64d(encoded)
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError(f"File exceeds {MAX_FILE_BYTES // (1024*1024)} MB limit")
        self._check_storage_quota(len(raw))
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=True)
        file_id = str(uuid.uuid4())
        safe_name = safe_filename(filename)
        mime_type = safe_content_type(content_type, safe_name)
        sha = hashlib.sha256(raw).hexdigest()
        self.files_dir.mkdir(parents=True, exist_ok=True)
        storage = str(self.files_dir / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        Path(storage).write_bytes(stored)
        self.db.save_file(file_id, safe_name, self.public_key, len(raw), sha, storage,
                          recipient=peer_pubkey, group_id=group_id,
                          file_nonce=file_nonce, replace=False, mime_type=mime_type)
        self._track_storage(len(stored))
        total_chunks = max(1, (len(raw) + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES)
        manifest = {"file_id": file_id, "filename": safe_name, "size": len(raw), "sha256": sha,
                    "from": self.public_key, "to": peer_pubkey, "group_id": group_id,
                    "mime_type": mime_type,
                    "total_chunks": total_chunks, "chunk_size": MAX_CHUNK_BYTES, "sent_at": utc_ts()}
        await self.send_relay(peer_pubkey, self.signed_payload("file_manifest", manifest), queue_on_failure=True)
        # Chunk counters must be allocated in strict order up front (the
        # underlying counter is a simple per-peer increment), but the
        # encrypt+send work for each chunk is independent, so it's safe and
        # meaningfully faster — especially over a non-local relay — to fan
        # those out with bounded concurrency rather than one at a time. The
        # receive-side replay window (REPLAY_WINDOW) comfortably tolerates
        # the resulting out-of-order arrival.
        counters = [self.db.next_send_counter(peer_pubkey) for _ in range(total_chunks)]
        chunk_semaphore = asyncio.Semaphore(FILE_CHUNK_CONCURRENCY)

        async def send_chunk(idx: int, counter: int) -> None:
            async with chunk_semaphore:
                chunk = raw[idx * MAX_CHUNK_BYTES:(idx + 1) * MAX_CHUNK_BYTES]
                meta = {**manifest, "chunk_index": idx, "counter": counter,
                        "chunk_sha256": hashlib.sha256(chunk).hexdigest()}
                msg_key = self.crypto.derive_message_key(session_key, self.public_key, peer_pubkey, counter, "file-chunk")
                packet = self.crypto.encrypt(msg_key, chunk, canonical_json(meta))
                await self.send_relay(peer_pubkey, {"kind": "file_chunk", "payload": meta, "packet": packet}, queue_on_failure=True)

        results = await asyncio.gather(
            *(send_chunk(idx, counters[idx]) for idx in range(total_chunks)),
            return_exceptions=True,
        )
        for r in results:
            if isinstance(r, Exception):
                raise r
        saved_file = self.db.get_file(file_id)
        await self.broadcast_ui({
            "type": "file",
            "file": self._public_file(saved_file) if saved_file else {},
            "storage_bytes": self._storage_bytes_used(),
        })

    async def handle_file(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        # Backward-compatible single-packet file receiver.
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        meta = data["payload"]
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File routing metadata mismatch")
        file_id = validate_file_id(meta.get("file_id", ""))
        counter = int(meta.get("counter", 0))
        msg_key = self.crypto.derive_message_key(session_key, peer_pubkey, self.public_key, counter, "file")
        raw = self.crypto.decrypt(msg_key, data["packet"], canonical_json(meta))
        self.db.mark_recv_counter(peer_pubkey, counter)
        await self._store_complete_file(peer_pubkey, meta, raw, file_id)

    async def handle_file_manifest(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid file manifest signature")
        meta = data.get("payload", {})
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File manifest routing mismatch")
        validate_file_id(meta.get("file_id", ""))
        size = int(meta.get("size", -1))
        total_chunks = int(meta.get("total_chunks", 0))
        expected_chunks = max(1, (size + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES) if size >= 0 else 0
        if size < 0 or size > MAX_FILE_BYTES:
            raise ValueError("File exceeds configured limit")
        if total_chunks != expected_chunks or int(meta.get("chunk_size", 0)) != MAX_CHUNK_BYTES:
            raise ValueError("Invalid file manifest chunk layout")
        safe_filename(meta.get("filename"))
        safe_content_type(meta.get("mime_type"), str(meta.get("filename") or ""))
        self._check_storage_quota(size)
        self.db.metric_inc("file_manifests_received")

    async def handle_file_chunk(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
        meta = data["payload"]
        if meta.get("from") != peer_pubkey or meta.get("to") != self.public_key:
            raise ValueError("File chunk routing metadata mismatch")
        file_id = validate_file_id(meta.get("file_id", ""))
        counter = int(meta.get("counter", 0))
        msg_key = self.crypto.derive_message_key(session_key, peer_pubkey, self.public_key, counter, "file-chunk")
        chunk = self.crypto.decrypt(msg_key, data["packet"], canonical_json(meta))
        self.db.mark_recv_counter(peer_pubkey, counter)
        if hashlib.sha256(chunk).hexdigest() != meta.get("chunk_sha256"):
            raise ValueError("File chunk checksum mismatch")
        total_chunks = int(meta.get("total_chunks", 1))
        chunk_index = int(meta.get("chunk_index", 0))
        declared_size = int(meta.get("size", -1))
        expected_chunks = max(1, (declared_size + MAX_CHUNK_BYTES - 1) // MAX_CHUNK_BYTES) if declared_size >= 0 else 0
        if (declared_size < 0 or declared_size > MAX_FILE_BYTES
                or total_chunks != expected_chunks
                or int(meta.get("chunk_size", 0)) != MAX_CHUNK_BYTES
                or chunk_index < 0 or chunk_index >= total_chunks):
            raise ValueError("Invalid file chunk index")
        expected_size = (0 if declared_size == 0 else
                         min(MAX_CHUNK_BYTES, declared_size - chunk_index * MAX_CHUNK_BYTES))
        if len(chunk) != expected_size:
            raise ValueError("File chunk size mismatch")
        self._check_storage_quota(len(chunk))
        self.files_dir.mkdir(parents=True, exist_ok=True)
        chunk_dir = self.files_dir / f"{file_id}.chunks"
        chunk_dir.mkdir(parents=True, exist_ok=True)
        chunk_path = chunk_dir / str(chunk_index)
        # Chunks are encrypted at rest immediately, the same as a finished
        # file — they sit on disk mid-transfer and must not be recoverable
        # in plaintext from a stolen disk image while assembly is pending.
        stored_chunk, chunk_nonce = self.encrypt_chunk_for_disk(chunk, file_id, chunk_index)
        if self.db.save_file_chunk(file_id, chunk_index, total_chunks, str(chunk_path), chunk_nonce):
            # Only the first accepted delivery writes the path. A duplicate
            # chunk must not replace ciphertext while the DB still holds the
            # original nonce, which would make final reassembly undecryptable.
            chunk_path.write_bytes(stored_chunk)
            self._track_storage(len(stored_chunk))
        chunks = self.db.file_chunks(file_id)
        if len(chunks) == total_chunks:
            raw = b"".join(
                self.decrypt_chunk_from_disk(Path(c["storage_path"]).read_bytes(), file_id, c["chunk_index"], c.get("chunk_nonce"))
                for c in chunks
            )
            # Chunk shards are only scratch space for reassembly; clean them
            # up as soon as we have the full plaintext in memory, before
            # storing the final file or telling any UI client about it, so
            # no observer can ever see the chunk debris post-completion.
            self._cleanup_file_chunks(file_id, chunks)
            await self._store_complete_file(peer_pubkey, meta, raw, file_id)

    def _cleanup_file_chunks(self, file_id: str, chunks: List[Dict[str, Any]]) -> None:
        """Delete on-disk chunk shards and their DB rows once a transfer is
        reassembled (or has failed), so no encrypted-at-rest debris or stale
        rows linger, and the storage quota accounting stays accurate."""
        freed = 0
        for c in chunks:
            path = Path(c["storage_path"])
            try:
                freed += path.stat().st_size
                path.unlink()
            except OSError:
                pass
        chunk_dir = self.files_dir / f"{file_id}.chunks"
        try:
            chunk_dir.rmdir()
        except OSError:
            pass
        self.db.delete_file_chunks(file_id)
        if freed:
            self._track_storage(-freed)

    async def _store_complete_file(self, peer_pubkey: str, meta: Dict[str, Any], raw: bytes, file_id: str) -> None:
        if len(raw) > MAX_FILE_BYTES:
            raise ValueError("File exceeds configured limit")
        if hashlib.sha256(raw).hexdigest() != meta["sha256"]:
            raise ValueError("File checksum mismatch")
        self.files_dir.mkdir(parents=True, exist_ok=True)
        storage = str(self.files_dir / file_id)
        stored, file_nonce = self.encrypt_for_disk(raw, file_id)
        inserted = self.db.save_file(
            file_id, safe_filename(meta.get("filename") or "download.bin"),
            peer_pubkey, len(raw), meta["sha256"], storage,
            recipient=self.public_key, group_id=meta.get("group_id"),
            file_nonce=file_nonce, replace=False,
            mime_type=safe_content_type(meta.get("mime_type"), str(meta.get("filename") or ""))
        )
        if inserted:
            Path(storage).write_bytes(stored)
            self._track_storage(len(stored))
            saved_file = self.db.get_file(file_id)
            await self.broadcast_ui({
                "type": "file", "file": self._public_file(saved_file) if saved_file else {},
                "storage_bytes": self._storage_bytes_used(),
            })

    async def handle_group_chat(self, peer_pubkey: str, data: Dict[str, Any]) -> None:
        if not self.verify_signed(peer_pubkey, data):
            raise ValueError("Invalid group message signature")
        payload = data.get("payload", {})
        meta = payload.get("meta", {})
        if meta.get("from") != peer_pubkey:
            raise ValueError("Group message sender mismatch")
        group_id = str(meta.get("group_id", ""))
        if self.public_key not in self.db.group_members(group_id):
            raise ValueError("Group message for unknown group")
        group_key = self.db.get_group_key(group_id, int(meta.get("epoch", 0)))
        if not group_key:
            raise ValueError("Missing group epoch key")
        text = unpad_plaintext(self.crypto.decrypt(group_key["key"], payload["packet"], canonical_json(meta))).decode("utf-8")
        inserted = self.db.save_message(meta["msg_id"], peer_pubkey, text, "in", group_id=group_id,
                                        delivered=True, status="delivered")
        if inserted:
            self.db.increment_unread(peer_pubkey)
            await self.broadcast_ui({"type": "message", "message": {
                "msg_id": meta["msg_id"], "sender_pubkey": peer_pubkey,
                "recipient_pubkey": None, "group_id": group_id, "body": text,
                "direction": "in", "timestamp": utc_ts(), "delivered": 1,
                "status": "delivered", "reactions": [], "read_at": None,
            }})

    # ── Relay dispatch ────────────────────────────────────────────────────────

    async def handle_relay_payload(self, peer_pubkey: str, payload: Dict[str, Any]) -> None:
        peer_pubkey = self.validate_peer_key(peer_pubkey)
        if not isinstance(payload, dict):
            raise ValueError("Relay payload must be an object")
        kind = payload.get("kind")
        if kind == "session_offer":
            await self.handle_session_offer(peer_pubkey, payload)
        elif kind == "session_accept":
            await self.handle_session_accept(peer_pubkey, payload)
        elif kind == "chat":
            await self.handle_chat(peer_pubkey, payload)
        elif kind == "file":
            await self.handle_file(peer_pubkey, payload)
        elif kind == "file_manifest":
            await self.handle_file_manifest(peer_pubkey, payload)
        elif kind == "file_chunk":
            await self.handle_file_chunk(peer_pubkey, payload)
        elif kind == "group_chat":
            await self.handle_group_chat(peer_pubkey, payload)
        elif kind == "typing":
            await self.handle_typing(peer_pubkey, payload)
        elif kind == "read_receipt":
            await self.handle_read_receipt(peer_pubkey, payload)
        elif kind == "reaction":
            await self.handle_reaction(peer_pubkey, payload)
        elif kind == "device_sync":
            await self._handle_device_sync(peer_pubkey, payload)
        elif kind == "call_offer":
            await self.handle_call_offer(peer_pubkey, payload)
        elif kind == "call_answer":
            await self.handle_call_answer(peer_pubkey, payload)
        elif kind == "call_ice":
            await self.handle_call_ice(peer_pubkey, payload)
        elif kind == "call_end":
            await self.handle_call_end(peer_pubkey, payload)
        elif kind == "delivery_ack":
            if not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid delivery acknowledgement")
            data = payload.get("payload", {})
            if data.get("from") != peer_pubkey or data.get("to") != self.public_key:
                raise ValueError("Delivery ack routing mismatch")
            self.db.update_message_status(str(data.get("msg_id", "")),
                                          "delivered_to_peer", delivered=True)
            await self.broadcast_ui({
                "type": "status_update",
                "msg_id": str(data.get("msg_id", "")),
                "status": "delivered_to_peer",
            })
        elif kind == "group_invite":
            if not self.db.is_friend(peer_pubkey) or not self.verify_signed(peer_pubkey, payload):
                raise ValueError("Invalid group invite")
            data = payload.get("payload", {})
            if (data.get("from") != peer_pubkey or data.get("to") != self.public_key
                    or self.public_key not in data.get("members", [])):
                raise ValueError("Group invite metadata mismatch")
            group_id = validate_file_id(data["group_id"])
            self.db.create_group(group_id, data.get("name") or f"Group {group_id[:8]}", self.public_key)
            for member in data.get("members", []):
                self.db.add_group_member(group_id, self.validate_peer_key(member))
            if payload.get("packet"):
                session_key = await self.require_fresh_session(peer_pubkey, outgoing=False)
                group_key = self.crypto.decrypt(
                    self.crypto.derive_message_key(session_key, peer_pubkey, self.public_key, int(data.get("counter", 0)), "group-key"),
                    payload["packet"], canonical_json(data)
                )
                self.db.mark_recv_counter(peer_pubkey, int(data.get("counter", 0)))
                self.db.save_group_key(group_id, int(data.get("epoch", 1)), group_key, peer_pubkey)
            await self.broadcast_ui(self.state_payload())

    # ── UI WebSocket ──────────────────────────────────────────────────────────

    def _ui_authenticated(self, ws: Any) -> bool:
        request = getattr(ws, "request", None)
        path = getattr(request, "path", None) or getattr(ws, "path", "/") or "/"
        token = parse_qs(urlparse(path).query).get("token", [""])[0]
        if not secrets.compare_digest(token, self.ui_token):
            return False
        origin = None
        headers = getattr(request, "headers", None) or getattr(ws, "request_headers", None)
        if headers:
            origin = headers.get("Origin")
        if origin:
            host = (urlparse(origin).hostname or "").lower()
            if not host:
                return False
            if host not in {"127.0.0.1", "localhost", "::1"} and not getattr(self, "allow_remote_ui", False):
                return False
        return True

    async def handle_ui(self, ws: Any) -> None:
        if not self._ui_authenticated(ws):
            await ws.close(code=1008, reason="Unauthorized UI socket")
            return
        self.ui_clients.add(ws)
        await ws.send(json.dumps(self.state_payload()))
        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                    await self._dispatch_ui(ws, msg)
                except Exception as exc:
                    LOG.warning("UI command rejected: %s", exc)
                    await ws.send(json.dumps({
                        "type": "notice", "level": "error", "text": str(exc)
                    }))
        finally:
            self.ui_clients.discard(ws)

    async def _dispatch_ui(self, ws: Any, msg: Dict[str, Any]) -> None:
        typ = msg.get("type")
        if typ == "add_friend":
            pubkey = self.validate_peer_key(msg["pubkey"])
            if pubkey == self.public_key:
                raise ValueError("You cannot add your own public key as a friend")
            self.db.add_friend(pubkey, msg.get("nickname"))
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
        elif typ == "remove_friend":
            self.db.remove_friend(self.validate_peer_key(msg["pubkey"]))
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
        elif typ == "verify_friend":
            self.db.verify_friend(self.validate_peer_key(msg["pubkey"]), bool(msg.get("verified", True)))
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
        elif typ == "block_friend":
            pubkey = self.validate_peer_key(msg["pubkey"])
            blocked = bool(msg.get("blocked", True))
            self.db.block_friend(pubkey, blocked)
            if blocked:
                # Drop in-memory session state too — a blocked peer must not
                # be able to keep sending on the existing session key.
                self.sessions.pop(pubkey, None)
                self.pending_offers.pop(pubkey, None)
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
            await self.broadcast_ui(self.state_payload())
        elif typ == "rename_friend":
            pubkey = self.validate_peer_key(msg["pubkey"])
            self.db.rename_friend(pubkey, str(msg.get("nickname") or ""))
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
        elif typ == "connect":
            await self.connect_peer(msg["pubkey"])
        elif typ == "send_message":
            if msg.get("group_id"):
                await self.send_group_chat(str(msg["group_id"]), str(msg.get("text", "")))
            else:
                await self.send_chat(msg["pubkey"], str(msg.get("text", "")))
        elif typ == "send_file":
            filename = safe_filename(msg.get("filename"))
            data = str(msg.get("data", ""))
            content_type = safe_content_type(msg.get("content_type"), filename)
            if msg.get("group_id"):
                await self.send_group_file(str(msg["group_id"]), filename, data, content_type)
            else:
                await self.send_file(msg["pubkey"], filename, data, msg.get("group_id"), content_type)
        elif typ == "create_group":
            group_id = str(uuid.uuid4())
            name = (validate_label(msg.get("name"), "Group name", MAX_GROUP_NAME_CHARS)
                    or f"Group {group_id[:8]}")
            members_raw = msg.get("members", [])
            if not isinstance(members_raw, list) or len(members_raw) > MAX_GROUP_MEMBERS:
                raise ValueError(f"Group members must be a list of at most {MAX_GROUP_MEMBERS}")
            self.db.create_group(group_id, name, self.public_key)
            group_key = secrets.token_bytes(32)
            self.db.save_group_key(group_id, 1, group_key, self.public_key)
            for member in members_raw:
                member = self.validate_peer_key(member)
                if self.db.is_friend(member):
                    self.db.add_group_member(group_id, member)
                    if member in self.sessions:
                        invite = {
                            "group_id": group_id, "name": name,
                            "members": self.db.group_members(group_id),
                            "from": self.public_key, "to": member, "epoch": 1,
                        }
                        await self.send_group_invite(member, invite, group_key)
            await self.broadcast_ui(self.state_payload())
        elif typ == "remove_group_member":
            await self.remove_group_member(str(msg["group_id"]), self.validate_peer_key(msg["pubkey"]))
        elif typ == "rotate_group_key":
            await self.rotate_group_key(str(msg["group_id"]))
        elif typ == "export_backup":
            passphrase = str(msg.get("passphrase") or "")
            if len(passphrase) < 8:
                raise ValueError("Choose a backup passphrase of at least 8 characters")
            blob = pack_identity_backup(self.public_key, self.secret_key, passphrase)
            # Sent directly to the requesting client only — never broadcast,
            # since this blob (with the passphrase) reconstructs the identity.
            await ws.send(json.dumps({"type": "identity_backup", "backup": blob}))
        elif typ == "import_backup":
            if self.db.get_friends() or self.db.recent_messages(limit=1):
                raise ValueError(
                    "Refusing to import over an identity that already has friends or "
                    "message history. Import backups only into a brand-new install."
                )
            new_pk, new_sk = unpack_identity_backup(str(msg.get("backup") or ""), str(msg.get("passphrase") or ""))
            self.public_key, self.secret_key = new_pk, new_sk
            self.db.save_identity(self.public_key, self.secret_key)
            self.relay_alias = hashlib.sha256((self.public_key + ":relay-alias").encode()).hexdigest()
            self.sessions.clear()
            self.pending_offers.clear()
            await self.broadcast_ui({
                "type": "notice", "level": "success",
                "text": f"Identity imported: {key_fingerprint(self.public_key)}. Restart to reconnect to signaling with the new identity."
            })
            await self.broadcast_ui(self.state_payload())
        elif typ == "typing":
            await self.send_typing(msg["pubkey"], bool(msg.get("active", True)))
        elif typ == "read_receipt":
            await self.send_read_receipt(msg["pubkey"], str(msg["msg_id"]))
            self.db.clear_unread(msg["pubkey"])
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
            await self.sync_to_devices("read_local", {"peer_pubkey": msg["pubkey"]})
        elif typ == "reaction":
            await self.send_reaction(
                msg["pubkey"], str(msg["msg_id"]),
                str(msg["emoji"]), str(msg.get("action", "add"))
            )
        elif typ == "clear_unread":
            pubkey = self.validate_peer_key(msg["pubkey"])
            self.db.clear_unread(pubkey)
            await self.broadcast_ui({"type": "friends", "friends": self.db.get_friends()})
            await self.sync_to_devices("read_local", {"peer_pubkey": pubkey})
        elif typ == "refresh":
            await self.broadcast_ui(self.state_payload())
        elif typ == "load_more_messages":
            before_id = int(msg.get("before_id", 0))
            older = self._with_message_metadata(self.db.messages_before(before_id, MESSAGE_PAGE_SIZE))
            has_more = bool(older) and self.db.has_messages_before(older[0]["id"])
            await ws.send(json.dumps({
                "type": "history", "messages": older, "has_more_messages": has_more
            }))
        elif typ == "search_messages":
            query = str(msg.get("query") or "")
            target = msg.get("pubkey") or msg.get("group_id")
            results = self._with_message_metadata(
                self.db.search_messages(query, target=str(target) if target else None)
            )
            await ws.send(json.dumps({
                "type": "search_results", "query": query, "results": results
            }))
        elif typ == "call_offer":
            await self.send_call_offer(msg["pubkey"], msg["sdp"], str(msg.get("media", "video")))
        elif typ == "call_answer":
            await self.send_call_answer(msg["pubkey"], msg["sdp"])
        elif typ == "call_ice":
            await self.send_call_ice(msg["pubkey"], msg["candidate"])
        elif typ == "call_end":
            await self.send_call_end(msg["pubkey"], str(msg.get("reason", "hangup")))
        else:
            raise ValueError(f"Unknown command: {typ}")

    # ── Signaling loop ────────────────────────────────────────────────────────

    async def connect_signaling_loop(self) -> None:
        websockets = require_websockets()
        delay = 1.0
        # The signaling loop runs until the node is asked to shut down. A
        # stop event lets run_node's finally block cancel us cleanly instead
        # of leaving the reconnect loop running after the UI WS task is gone.
        while not getattr(self, "_shutting_down", False):
            try:
                async with websockets.connect(
                    self.signaling_url, max_size=MAX_FILE_BYTES * 2
                ) as ws:
                    self.signaling_ws = ws
                    delay = 1.0  # reset backoff on success
                    try:
                        first_raw = await asyncio.wait_for(ws.recv(), timeout=2)
                        first = json.loads(first_raw)
                        if first.get("type") == "register_challenge":
                            challenge = {
                                "type": "register_challenge",
                                "nonce": first["nonce"],
                                "pubkey": self.public_key,
                            }
                            sig = b64e(self.crypto.sign(self.secret_key, canonical_json(challenge)))
                            await ws.send(json.dumps({
                                "type": "register", "pubkey": self.public_key,
                                "signature": sig, "challenge": first["nonce"],
                                "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                            }))
                        else:
                            await ws.send(json.dumps({
                                "type": "register", "pubkey": self.public_key,
                                "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                            }))
                            await self._handle_signaling_message(first)
                    except asyncio.TimeoutError:
                        await ws.send(json.dumps({
                            "type": "register", "pubkey": self.public_key,
                            "relay_alias": self.relay_alias, "direct_url": self.direct_url,
                        }))
                    await self.broadcast_ui({
                        "type": "notice", "level": "success",
                        "text": "Connected to signaling server"
                    })
                    async for raw in ws:
                        try:
                            await self._handle_signaling_message(json.loads(raw))
                        except Exception as exc:
                            LOG.warning("Ignored malformed signaling message: %s", exc)
            except asyncio.CancelledError:
                # Cooperative cancellation during shutdown — don't reconnect.
                self.signaling_ws = None
                raise
            except Exception as exc:
                self.signaling_ws = None
                if getattr(self, "_shutting_down", False):
                    return
                LOG.warning("Signaling disconnected: %s", exc)
                # Add up to 30% jitter so a transient relay outage doesn't
                # cause every client to reconnect in lockstep and hammer the
                # server at exactly the same instant. random is fine here —
                # jitter is not security-sensitive.
                import random as _random
                jitter = _random.uniform(0, 0.3 * delay)
                wait = delay + jitter
                await self.broadcast_ui({
                    "type": "notice", "level": "warning",
                    "text": f"Disconnected from relay — reconnecting in {wait:.1f}s…"
                })
                await asyncio.sleep(wait)
                delay = min(delay * 2, MAX_RECONNECT_DELAY)

    async def _handle_signaling_message(self, msg: Dict[str, Any]) -> None:
        if msg.get("type") == "peers":
            raw_peers = msg.get("peers", [])
            if isinstance(raw_peers, dict):
                self.online_peers = set(raw_peers) - {self.public_key}
                for peer, meta in raw_peers.items():
                    if peer != self.public_key and isinstance(meta, dict):
                        if meta.get("direct_url"):
                            self.peer_direct[peer] = meta["direct_url"]
                        self.db.set_friend_transport(peer, meta.get("relay_alias"), meta.get("direct_url"))
            else:
                self.online_peers = set(raw_peers) - {self.public_key}
            await self.broadcast_ui(self.state_payload())
            for peer in list(self.online_peers):
                await self.flush_outbox(peer)
        elif msg.get("type") == "relay":
            await self.handle_relay_payload(msg["from"], msg["payload"])
        elif msg.get("type") == "error":
            await self.broadcast_ui({
                "type": "notice", "level": "error",
                "text": msg.get("text", "signaling error")
            })


# ─── Signaling Server ─────────────────────────────────────────────────────────

class SignalingServer:
    def __init__(self) -> None:
        # Dict[pubkey] -> set of live sockets. A set (not a single socket)
        # is what makes multi-device support possible: two devices holding
        # the same identity can both stay registered and connected at once,
        # and relay/self-sync traffic fans out to every socket in the set.
        self.clients: Dict[str, Set[Any]] = {}
        self.aliases: Dict[str, str] = {}
        self.peer_meta: Dict[str, Dict[str, Any]] = {}
        self.offline: Dict[str, List[Dict[str, Any]]] = {}
        self.relay_db = sqlite3.connect(os.environ.get("QUANTUM_CHAT_RELAY_DB", "quantum_chat_relay.db"), check_same_thread=False)
        self.relay_db.execute("CREATE TABLE IF NOT EXISTS offline_queue (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, envelope TEXT NOT NULL, created_at INTEGER NOT NULL)")
        self.relay_db.commit()
        self.crypto = QuantumCrypto()
        self.rate: Dict[Any, List[int]] = {}
        # Per-socket rate limiting (self.rate) is no longer sufficient on its
        # own once one identity can hold several simultaneous connections —
        # an attacker who registers many device sockets under one signed
        # identity could otherwise multiply their effective send rate. This
        # tracks an aggregate ceiling per pubkey across all of its sockets.
        self.pubkey_rate: Dict[str, List[int]] = {}

    def _rate_ok(self, ws: Any, limit: int = 120, window: int = 60) -> bool:
        now = utc_ts()
        events = [t for t in self.rate.get(ws, []) if now - t < window]
        events.append(now)
        self.rate[ws] = events
        return len(events) <= limit

    def _pubkey_rate_ok(self, pubkey: str, limit: int = 300, window: int = 60) -> bool:
        now = utc_ts()
        events = [t for t in self.pubkey_rate.get(pubkey, []) if now - t < window]
        events.append(now)
        self.pubkey_rate[pubkey] = events
        return len(events) <= limit

    async def broadcast_peers(self) -> None:
        payload = json.dumps({"type": "peers", "peers": self.peer_meta})
        for sockets in list(self.clients.values()):
            for ws in list(sockets):
                try:
                    await ws.send(payload)
                except Exception:
                    pass

    async def handle(self, ws: Any) -> None:
        pubkey = None
        nonce = secrets.token_urlsafe(32)
        await ws.send(json.dumps({"type": "register_challenge", "nonce": nonce}))
        try:
            async for raw in ws:
                if not self._rate_ok(ws):
                    await ws.send(json.dumps({"type": "error", "text": "Rate limit exceeded"}))
                    continue
                try:
                    msg = json.loads(raw)
                    if msg.get("type") == "register":
                        candidate = validate_public_key(
                            msg["pubkey"], self.crypto.sign_public_key_bytes
                        )
                        sig = msg.get("signature")
                        if sig:
                            challenge = {
                                "type": "register_challenge",
                                "nonce": msg.get("challenge"),
                                "pubkey": candidate,
                            }
                            if (msg.get("challenge") != nonce
                                    or not self.crypto.verify(
                                        bytes.fromhex(candidate),
                                        canonical_json(challenge), b64d(sig)
                                    )):
                                await ws.send(json.dumps({
                                    "type": "error", "text": "Invalid registration signature"
                                }))
                                continue
                        elif self.clients.get(candidate):
                            await ws.send(json.dumps({
                                "type": "error",
                                "text": "Duplicate unsigned registration rejected"
                            }))
                            continue
                        pubkey = candidate
                        relay_alias = str(msg.get("relay_alias") or hashlib.sha256(candidate.encode()).hexdigest())
                        if not HEX_RE.match(relay_alias) or len(relay_alias) > 128:
                            raise ValueError("Invalid relay alias")
                        direct_url = msg.get("direct_url") if isinstance(msg.get("direct_url"), str) else None
                        # Signed registrations are added alongside any existing
                        # connection for this identity rather than replacing it,
                        # so a second device holding the same identity backup
                        # can stay online at the same time as the first (see
                        # 'Multi-device support'). Unsigned registrations can't
                        # prove they hold the identity, so those are still
                        # rejected outright when the identity is already live.
                        self.clients.setdefault(pubkey, set()).add(ws)
                        self.aliases[relay_alias] = pubkey
                        self.peer_meta[pubkey] = {"relay_alias": relay_alias, "direct_url": direct_url}
                        for queued in self.offline.pop(pubkey, []):
                            await ws.send(json.dumps(queued))
                        rows = self.relay_db.execute("SELECT id, envelope FROM offline_queue WHERE target=? ORDER BY id LIMIT 500", (pubkey,)).fetchall()
                        for qid, envelope in rows:
                            await ws.send(envelope)
                            self.relay_db.execute("DELETE FROM offline_queue WHERE id=?", (qid,))
                        self.relay_db.commit()
                        await self.broadcast_peers()
                    elif msg.get("type") == "relay":
                        if not pubkey:
                            await ws.send(json.dumps({
                                "type": "error", "text": "Register before relaying"
                            }))
                            continue
                        if not self._pubkey_rate_ok(pubkey):
                            await ws.send(json.dumps({"type": "error", "text": "Rate limit exceeded"}))
                            continue
                        raw_target = str(msg.get("to", ""))
                        try:
                            target = validate_public_key(raw_target, self.crypto.sign_public_key_bytes)
                        except ValueError:
                            target = self.aliases.get(raw_target, "")
                            if not target:
                                raise
                        payload = msg.get("payload")
                        if (not isinstance(payload, dict)
                                or len(json.dumps(payload)) > MAX_FILE_BYTES * 2):
                            await ws.send(json.dumps({
                                "type": "error", "text": "Invalid relay payload"
                            }))
                            continue
                        # Fan out to every device socket registered for the
                        # target identity, excluding the sender's own socket
                        # (relevant for self-addressed device-sync traffic,
                        # where "target" is the sender's own identity and we
                        # only want *other* devices to receive it).
                        target_sockets = [t for t in self.clients.get(target, ()) if t is not ws]
                        ephemeral = bool(msg.get("ephemeral"))
                        if target_sockets:
                            envelope = json.dumps({"type": "relay", "from": pubkey, "payload": payload})
                            for target_ws in target_sockets:
                                try:
                                    await target_ws.send(envelope)
                                except Exception:
                                    LOG.debug("Dropped relay fan-out to a stale device socket for %s", short_key(target))
                        elif ephemeral:
                            # Ephemeral traffic (typing indicators, ICE
                            # candidates, device-sync pings) is a best-effort
                            # convenience signal, not durable state — persisting
                            # it to the offline queue would let it pile up
                            # forever for identities that never bring a second
                            # device online, or spam a relay/direct message the
                            # instant a peer reconnects long after it's stale.
                            await ws.send(json.dumps({"type": "queued", "to": target, "ephemeral": True}))
                        else:
                            queue = self.offline.setdefault(target, [])
                            if len(queue) >= 500:
                                await ws.send(json.dumps({"type": "error", "text": "Peer offline queue is full"}))
                            else:
                                queued = {"type": "relay", "from": pubkey, "payload": payload, "offline": True}
                                queue.append(queued)
                                self.relay_db.execute(
                                    "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
                                    (target, json.dumps(queued), utc_ts())
                                )
                                self.relay_db.commit()
                                await ws.send(json.dumps({"type": "queued", "to": target}))
                except Exception as exc:
                    LOG.warning("Rejected signaling frame: %s", exc)
                    await ws.send(json.dumps({"type": "error", "text": str(exc)}))
        finally:
            self.rate.pop(ws, None)
            if pubkey and pubkey in self.clients:
                sockets = self.clients[pubkey]
                sockets.discard(ws)
                if not sockets:
                    del self.clients[pubkey]
                    self.pubkey_rate.pop(pubkey, None)
                    self.peer_meta.pop(pubkey, None)
                    for alias, owner in list(self.aliases.items()):
                        if owner == pubkey:
                            self.aliases.pop(alias, None)
                    await self.broadcast_peers()
                # If other device sockets are still registered for this
                # identity, leave peer_meta/aliases/online-peers state alone
                # — the identity as a whole is still online.


# ─── HTTP Server ──────────────────────────────────────────────────────────────

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class ChatHTTPHandler(BaseHTTPRequestHandler):
    node: QuantumNode = None  # type: ignore
    ui_ws_port: int = UI_WS_PORT
    require_http_auth: bool = False

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if self.require_http_auth and not self._http_authenticated(parsed):
            self.send_error(401, "Unauthorized")
            return

        if path == "/":
            body = (
                HTML
                .replace("__UI_WS_PORT__", str(self.ui_ws_port))
                .replace("__UI_TOKEN__", self.node.ui_token if self.node else "")
                .replace("__VERSION__", VERSION)
            ).encode("utf-8")
            self._send(200, body, "text/html; charset=utf-8")
            return

        if path == "/health":
            body = json.dumps(self.node.health() if self.node else {"status": "no node"}).encode()
            self._send(200, body, "application/json")
            return

        if path == "/version":
            # Lightweight version probe — useful for monitoring/CI without
            # pulling the full /health payload (which includes identity).
            body = json.dumps({"version": VERSION, "app": APP_NAME}).encode()
            self._send(200, body, "application/json")
            return

        if path.startswith("/files/"):
            self._serve_file(parsed, head_only=False)
            return

        self.send_error(404)

    def _http_authenticated(self, parsed: Any) -> bool:
        token = parse_qs(parsed.query).get("token", [""])[0]
        auth = self.headers.get("Authorization", "")
        expected = self.node.ui_token if self.node else ""
        bearer = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer ") else ""
        return bool(expected and (secrets.compare_digest(token, expected) or secrets.compare_digest(bearer, expected)))

    def do_OPTIONS(self) -> None:
        """Respond to CORS preflight requests with the security headers we
        always send. We don't add an Access-Control-Allow-Origin header — the
        UI is same-origin only — but we acknowledge OPTIONS so a misconfigured
        browser doesn't show a noisy error in the console."""
        self.send_response(204)
        self._security_headers()
        self.send_header("Allow", "GET, HEAD, OPTIONS")
        self.end_headers()

    def do_HEAD(self) -> None:
        """HEAD requests return the same Content-Type and security headers as
        GET but no body — useful for monitoring tools that just want /health
        metadata. We deliberately re-implement routing rather than wrapping
        do_GET, because BaseHTTPRequestHandler.send_response/send_header all
        write through ``self.wfile`` — replacing wfile with a null sink would
        discard the status line and headers too, not just the body."""
        parsed = urlparse(self.path)
        path = parsed.path
        if self.require_http_auth and not self._http_authenticated(parsed):
            self.send_error(401, "Unauthorized")
            return
        if path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self._security_headers()
            self.end_headers()
        elif path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._security_headers()
            self.end_headers()
        elif path == "/version":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self._security_headers()
            self.end_headers()
        elif path.startswith("/files/"):
            self._serve_file(parsed, head_only=True)
        else:
            self.send_error(404)

    def _serve_file(self, parsed: Any, head_only: bool = False) -> None:
        """Serve a decrypted local attachment with media-friendly ranges."""
        try:
            file_id = validate_file_id(parsed.path.rsplit("/", 1)[-1])
        except ValueError:
            self.send_error(404, "File not found")
            return
        meta = self.node.db.get_file(file_id) if self.node else None
        if not meta or not Path(meta["storage_path"]).exists():
            self.send_error(404, "File not found")
            return

        stored = Path(meta["storage_path"]).read_bytes()
        data = (self.node.decrypt_from_disk(stored, file_id, meta.get("file_nonce"))
                if self.node else stored)
        try:
            byte_range = parse_http_range(self.headers.get("Range", ""), len(data))
        except ValueError:
            self.send_response(416)
            self.send_header("Content-Range", f"bytes */{len(data)}")
            self.send_header("Accept-Ranges", "bytes")
            self._security_headers(download=True)
            self.end_headers()
            return

        start, end = byte_range if byte_range else (0, max(0, len(data) - 1))
        body = data[start:end + 1] if data else b""
        inline = parse_qs(parsed.query).get("view", [""])[0] == "1"
        ctype = safe_content_type(meta.get("mime_type"), meta["filename"])
        self.send_response(206 if byte_range else 200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Accept-Ranges", "bytes")
        if byte_range:
            self.send_header("Content-Range", f"bytes {start}-{end}/{len(data)}")
        disposition = "inline" if inline else "attachment"
        self.send_header(
            "Content-Disposition",
            f"{disposition}; filename*=UTF-8''{quote(meta['filename'])}"
        )
        self._security_headers(download=not inline)
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _security_headers(self, download: bool = False) -> None:
        # stun:/turn: schemes are added so the browser's RTCPeerConnection can
        # reach ICE servers for voice/video calls — CSP3-compliant browsers
        # apply connect-src to WebRTC connections, not just fetch/WebSocket.
        connect_src = ("connect-src 'self' stun: turn: stuns: turns: "
                       "ws://127.0.0.1:* ws://localhost:* ws://[::1]:* "
                       "wss://127.0.0.1:* wss://localhost:* wss://[::1]:*;")
        if self.require_http_auth:
            host = (self.headers.get("Host", "") or "").strip()
            if host:
                host = host.split("/", 1)[0]
                connect_src = (
                    f"connect-src 'self' stun: turn: stuns: turns: ws://{host} wss://{host} "
                    "ws://127.0.0.1:* ws://localhost:* ws://[::1]:* "
                    "wss://127.0.0.1:* wss://localhost:* wss://[::1]:*;"
                )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        # X-Frame-Options + frame-ancestors 'none' make clickjacking on the
        # local UI harder; modern browsers honor CSP frame-ancestors, but
        # X-Frame-Options is still a useful belt-and-braces for older ones.
        self.send_header("X-Frame-Options", "DENY")
        # X-XSS-Protection is largely deprecated in modern browsers but still
        # a useful defense-in-depth header for the legacy XSS filter in older
        # Safari/Chrome; setting it to 1; mode=block stops a detected XSS
        # from rendering at all rather than sanitizing in-place.
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("X-Permitted-Cross-Domain-Policies", "none")
        # Calls need getUserMedia, which browsers gate behind Permissions-Policy
        # in addition to the user's own camera/mic prompt. frame-ancestors
        # 'none' above means this page is never embedded, so explicitly
        # allowing 'self' here only ever affects this same-origin UI itself.
        self.send_header("Permissions-Policy", "camera=(self), microphone=(self), display-capture=()")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; "
            f"{connect_src} "
            "style-src 'unsafe-inline' 'self'; "
            "script-src 'unsafe-inline' 'self'; "
            "img-src 'self' data: blob:; "
            "media-src 'self' blob: data:; "
            "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
        )

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        LOG.debug("[http] " + fmt, *args)


# ─── Embedded UI ──────────────────────────────────────────────────────────────

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>⚛ Quantum Chat</title>
<style>
:root {
  --bg: #030508;
  --glass-bg: rgba(12, 18, 30, 0.65);
  --glass-border: rgba(255, 255, 255, 0.07);
  --glass-border-hover: rgba(255, 255, 255, 0.15);
  --glass-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.37);
  
  --s1: var(--glass-bg);
  --s2: rgba(18, 25, 40, 0.5);
  --s3: rgba(25, 35, 55, 0.6);
  --s4: rgba(35, 50, 75, 0.7);
  --border: var(--glass-border);
  --border2: var(--glass-border-hover);
  
  --accent: #00d2ff;
  --accent-glow: rgba(0, 210, 255, 0.4);
  --accent2: #3a86ff;
  --accent2-glow: rgba(58, 134, 255, 0.4);
  --danger: #ff3366;
  --warn: #ffcc00;
  
  --text1: #f8f9fa;
  --text2: #adb5bd;
  --text3: #6c757d;
  
  --out-bg: linear-gradient(135deg, var(--accent2), var(--accent));
  --out-border: transparent;
  --in-bg: var(--s3);
  
  --rad: 16px;
  --font: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  --mono: "SFMono-Regular", Consolas, "Liberation Mono", ui-monospace, monospace;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  font-family: var(--font);
  background-color: var(--bg);
  background-image: 
    radial-gradient(circle at 15% 50%, rgba(58, 134, 255, 0.15), transparent 40%),
    radial-gradient(circle at 85% 30%, rgba(0, 210, 255, 0.15), transparent 40%),
    radial-gradient(circle at 50% 100%, rgba(255, 51, 102, 0.05), transparent 40%);
  background-attachment: fixed;
  color: var(--text1);
  height: 100vh;
  overflow: hidden;
  font-size: 15px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
}

/* ── Layout ── */
#app { display: flex; height: 100vh; }

#sidebar {
  width: 320px;
  min-width: 320px;
  display: flex;
  flex-direction: column;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-right: 1px solid var(--border);
  box-shadow: var(--glass-shadow);
  z-index: 10;
}

#main {
  flex: 1;
  display: flex;
  flex-direction: column;
  min-width: 0;
  background: transparent;
}

#panel {
  width: 290px;
  min-width: 290px;
  background: var(--glass-bg);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  border-left: 1px solid var(--border);
  box-shadow: var(--glass-shadow);
  display: flex;
  flex-direction: column;
  overflow-y: auto;
  z-index: 10;
}

/* ── Sidebar ── */
.sidebar-head {
  padding: 20px;
  border-bottom: 1px solid var(--border);
  background: rgba(0,0,0,0.1);
}

.app-logo {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 14px;
}

.app-logo .icon {
  font-size: 26px;
  line-height: 1;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 8px var(--accent-glow));
}

.app-logo h1 {
  font-size: 18px;
  font-weight: 700;
  letter-spacing: -0.02em;
  color: var(--text1);
}

.app-logo .ver {
  font-size: 11px;
  color: var(--text3);
  font-family: var(--mono);
  margin-top: 2px;
}

.conn-badge {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  font-size: 13px;
  font-weight: 500;
  padding: 6px 12px;
  border-radius: 999px;
  background: var(--s3);
  border: 1px solid var(--border);
  color: var(--text2);
  transition: all 0.3s ease;
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

.conn-badge.connected { 
  border-color: rgba(58, 134, 255, 0.4); 
  color: #fff;
  background: rgba(58, 134, 255, 0.1);
}
.conn-badge.connected .dot { background: var(--accent); box-shadow: 0 0 10px var(--accent); }
.conn-badge .dot {
  width: 8px; height: 8px;
  border-radius: 50%;
  background: var(--text3);
  transition: all 0.3s;
}
.conn-badge.connected .dot { animation: pulse 2s infinite; }
@keyframes pulse {
  0%,100% { opacity: 1; transform: scale(1); box-shadow: 0 0 10px var(--accent); }
  50% { opacity: 0.5; transform: scale(0.8); box-shadow: 0 0 2px var(--accent); }
}

/* Identity card */
.id-card {
  margin: 16px;
  padding: 16px;
  background: rgba(255, 255, 255, 0.03);
  border: 1px solid var(--border);
  border-radius: var(--rad);
  cursor: pointer;
  transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1);
  position: relative;
  overflow: hidden;
}
.id-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0; height: 2px;
  background: linear-gradient(90deg, var(--accent2), var(--accent));
  opacity: 0;
  transition: opacity 0.3s;
}
.id-card:hover {
  transform: translateY(-2px);
  background: rgba(255, 255, 255, 0.05);
  box-shadow: 0 8px 24px rgba(0,0,0,0.3);
  border-color: var(--border2);
}
.id-card:hover::before { opacity: 1; }

.id-card-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.id-avatar {
  width: 42px; height: 42px;
  border-radius: 50%;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  box-shadow: 0 4px 12px var(--accent-glow);
  display: flex; align-items: center; justify-content: center;
  font-size: 20px;
  flex-shrink: 0;
  color: white;
}
.id-name { font-weight: 600; font-size: 15px; }
.id-fp {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text3);
  letter-spacing: 0.05em;
}
.id-key {
  font-family: var(--mono);
  font-size: 11px;
  color: var(--text2);
  word-break: break-all;
  padding: 10px;
  background: rgba(0,0,0,0.3);
  border-radius: 10px;
  border: 1px solid var(--border);
  display: none;
  margin-top: 12px;
  line-height: 1.6;
}
.id-key.visible { 
  display: block; 
  max-height: 120px; 
  overflow-y: auto; 
  animation: fadeIn 0.3s; 
}
.id-actions { display: flex; gap: 8px; margin-top: 12px; }

/* Search */
.search-wrap {
  padding: 12px 16px;
  border-bottom: 1px solid var(--border);
}
.search-input {
  width: 100%;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 10px 14px 10px 36px;
  color: var(--text1);
  font-size: 14px;
  font-family: var(--font);
  outline: none;
  transition: all 0.2s;
  background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='%236c757d' stroke-width='2'%3E%3Ccircle cx='11' cy='11' r='8'/%3E%3Cpath d='m21 21-4.35-4.35'/%3E%3C/svg%3E");
  background-repeat: no-repeat;
  background-position: 12px center;
}
.search-input:focus { 
  border-color: var(--accent); 
  background: rgba(0,0,0,0.4);
  box-shadow: 0 0 0 2px rgba(0, 210, 255, 0.1);
}
.search-input::placeholder { color: var(--text3); }

/* Friend / group lists */
.list-section { flex: 1; overflow-y: auto; padding: 12px 0; }
.section-label {
  padding: 8px 20px 6px;
  font-size: 11px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text3);
  display: flex;
  align-items: center;
  justify-content: space-between;
}
.section-label button {
  font-size: 20px;
  color: var(--text3);
  background: none;
  border: none;
  cursor: pointer;
  padding: 0 4px;
  line-height: 1;
  transition: all 0.2s;
}
.section-label button:hover { 
  color: var(--accent); 
  transform: scale(1.1);
  filter: drop-shadow(0 0 4px var(--accent-glow));
}

.friend-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 20px;
  cursor: pointer;
  transition: all 0.2s cubic-bezier(0.25, 0.8, 0.25, 1);
  position: relative;
  margin: 2px 8px;
  border-radius: 12px;
}
.friend-item:hover { background: rgba(255, 255, 255, 0.03); }
.friend-item.active { 
  background: rgba(255, 255, 255, 0.06); 
  box-shadow: 0 4px 12px rgba(0,0,0,0.1);
}
.friend-item.active::before {
  content: '';
  position: absolute;
  left: 0; top: 12px; bottom: 12px;
  width: 4px;
  background: linear-gradient(180deg, var(--accent2), var(--accent));
  border-radius: 0 4px 4px 0;
  box-shadow: 2px 0 8px var(--accent-glow);
}

.friend-avatar {
  position: relative;
  flex-shrink: 0;
}
.avatar-circle {
  width: 42px; height: 42px;
  border-radius: 50%;
  background: linear-gradient(135deg, #1e293b, #334155);
  display: flex; align-items: center; justify-content: center;
  font-size: 16px;
  font-weight: 600;
  color: #fff;
  border: 1px solid var(--border);
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}
.online-dot {
  position: absolute;
  bottom: 0px; right: -2px;
  width: 14px; height: 14px;
  border-radius: 50%;
  background: var(--bg);
  display: flex; align-items: center; justify-content: center;
}
.online-dot::after {
  content: '';
  width: 10px; height: 10px;
  border-radius: 50%;
  background: var(--text3);
  transition: all 0.3s;
}
.online-dot.online::after { 
  background: #34d39a; 
  box-shadow: 0 0 8px #34d39a;
}

.friend-info { flex: 1; min-width: 0; }
.friend-name {
  font-size: 15px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 2px;
}
.friend-preview {
  font-size: 13px;
  color: var(--text2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.friend-meta {
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  gap: 6px;
  flex-shrink: 0;
}
.unread-badge {
  background: linear-gradient(135deg, var(--danger), #ff5e62);
  color: #fff;
  font-size: 11px;
  font-weight: 700;
  padding: 3px 8px;
  border-radius: 999px;
  min-width: 22px;
  text-align: center;
  box-shadow: 0 2px 8px rgba(255, 51, 102, 0.4);
  animation: popIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
}
@keyframes popIn {
  0% { transform: scale(0.5); opacity: 0; }
  100% { transform: scale(1); opacity: 1; }
}

.secure-tag {
  font-size: 11px;
  color: var(--accent);
  font-family: var(--mono);
  display: flex;
  align-items: center;
  gap: 4px;
}
.time-tag {
  font-size: 11px;
  color: var(--text3);
}

/* ── Main chat area ── */
.chat-header {
  display: flex;
  align-items: center;
  gap: 16px;
  padding: 16px 24px;
  border-bottom: 1px solid var(--border);
  background: rgba(10, 15, 25, 0.6);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  min-height: 72px;
  z-index: 5;
}
.chat-header-avatar {
  width: 44px; height: 44px;
  border-radius: 50%;
  background: linear-gradient(135deg, #1e293b, #334155);
  display: flex; align-items: center; justify-content: center;
  font-size: 18px;
  font-weight: 600;
  flex-shrink: 0;
  border: 1px solid var(--border);
  box-shadow: 0 4px 12px rgba(0,0,0,0.2);
}
.chat-header-info { flex: 1; min-width: 0; }
.chat-header-name { font-size: 17px; font-weight: 700; margin-bottom: 2px; }
.chat-header-sub {
  font-size: 13px;
  color: var(--text2);
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.chat-header-actions { display: flex; gap: 10px; }

.messages-wrap {
  flex: 1;
  overflow-y: auto;
  padding: 24px;
  display: flex;
  flex-direction: column;
  gap: 8px;
  scroll-behavior: smooth;
}

/* Drop overlay */
.drop-overlay {
  display: none;
  position: absolute;
  inset: 0;
  background: rgba(3, 5, 8, 0.85);
  backdrop-filter: blur(10px);
  border: 2px dashed var(--accent);
  border-radius: var(--rad);
  z-index: 20;
  align-items: center;
  justify-content: center;
  flex-direction: column;
  gap: 12px;
  font-size: 20px;
  font-weight: 600;
  color: var(--accent);
  pointer-events: none;
  animation: fadeIn 0.2s;
}
.drop-overlay.active { display: flex; }
#main { position: relative; }

/* Date divider */
.date-divider {
  display: flex;
  align-items: center;
  gap: 16px;
  margin: 16px 0;
  color: var(--text3);
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.date-divider::before, .date-divider::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, transparent, var(--border), transparent);
}

/* Messages */
.msg-group { display: flex; flex-direction: column; margin: 4px 0; }
.msg-group.flash .msg-bubble { animation: msg-flash 1.6s ease-out; }
@keyframes msg-flash {
  0% { box-shadow: 0 0 0 3px var(--accent2); }
  100% { box-shadow: none; }
}
.msg-group.out { align-items: flex-end; }
.msg-group.in { align-items: flex-start; }

.msg-bubble {
  max-width: 70%;
  padding: 12px 16px;
  border-radius: 20px;
  position: relative;
  word-break: break-word;
  line-height: 1.6;
  font-size: 15px;
  box-shadow: 0 4px 16px rgba(0,0,0,0.15);
  animation: slideUp 0.3s cubic-bezier(0.2, 0.8, 0.2, 1);
}
@keyframes slideUp {
  from { opacity: 0; transform: translateY(12px) scale(0.98); }
  to { opacity: 1; transform: translateY(0) scale(1); }
}

.msg-group.out .msg-bubble {
  background: var(--out-bg);
  border: none;
  border-bottom-right-radius: 6px;
  color: #fff;
  box-shadow: 0 4px 16px rgba(0, 210, 255, 0.2);
}
.msg-group.in .msg-bubble {
  background: var(--s3);
  backdrop-filter: blur(10px);
  -webkit-backdrop-filter: blur(10px);
  border: 1px solid var(--border);
  border-bottom-left-radius: 6px;
}

.msg-meta {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-top: 6px;
  font-size: 11px;
  color: var(--text3);
  padding: 0 6px;
}
.msg-group.out .msg-meta { flex-direction: row-reverse; }

.msg-status { display: flex; align-items: center; }
.check { color: var(--text3); font-size: 14px; }
.check.delivered { color: var(--text2); }
.check.read { color: var(--accent); filter: drop-shadow(0 0 2px var(--accent-glow)); }

.msg-image {
  max-width: 320px;
  max-height: 240px;
  border-radius: 12px;
  display: block;
  cursor: pointer;
  object-fit: cover;
  border: 1px solid rgba(255,255,255,0.1);
  transition: transform 0.2s;
}
.msg-image:hover {
  transform: scale(1.02);
}

.attachment-card {
  width: min(340px, 68vw);
  color: var(--text1);
}
.attachment-preview-link { display: block; color: inherit; text-decoration: none; }
.attachment-preview-link .msg-image { width: 100%; max-width: none; }
.attachment-head {
  display: flex; align-items: center; gap: 10px; min-width: 0;
  padding-top: 10px;
}
.attachment-head:first-child { padding-top: 0; }
.attachment-name {
  flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis;
  white-space: nowrap; font-size: 13px; font-weight: 650;
}
.attachment-meta { color: var(--text3); font-size: 11px; font-family: var(--mono); }
.attachment-download {
  display: inline-flex; align-items: center; justify-content: center;
  width: 32px; height: 32px; border: 1px solid rgba(255,255,255,.14);
  border-radius: 8px; color: inherit; text-decoration: none; flex: 0 0 auto;
}
.attachment-download:hover { background: rgba(255,255,255,.1); }
.attachment-audio { width: 100%; height: 38px; margin-top: 10px; display: block; }
.attachment-video { width: 100%; max-height: 260px; display: block; border-radius: 8px; background: #000; }
.msg-group.out .attachment-meta { color: rgba(255,255,255,.72); }

/* Inline file-message chip (non-image files shown in the chat timeline) */
.file-msg-chip {
  display: flex;
  align-items: center;
  gap: 12px;
  min-width: 220px;
  max-width: 280px;
  padding: 10px 14px;
  border-radius: 12px;
  background: rgba(0,0,0,0.25);
  border: 1px solid rgba(255,255,255,0.1);
  color: var(--text1);
  text-decoration: none;
  transition: all 0.2s;
}
.file-msg-chip:hover {
  background: rgba(0,0,0,0.4);
  border-color: var(--border2);
  transform: translateY(-1px);
}
.msg-group.out .file-msg-chip { background: rgba(0,0,0,0.25); color: #fff; }
.file-msg-icon { font-size: 22px; flex-shrink: 0; }
.file-msg-text { flex: 1; min-width: 0; display: flex; flex-direction: column; gap: 2px; }
.file-msg-name {
  font-size: 13px; font-weight: 600;
  white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.file-msg-size { font-size: 11px; color: var(--text3); font-family: var(--mono); }
.file-msg-dl { font-size: 18px; color: var(--accent); flex-shrink: 0; }

/* Inline link inside a message bubble */
.inline-link {
  color: var(--accent);
  text-decoration: none;
  border-bottom: 1px solid rgba(0, 210, 255, 0.4);
  word-break: break-all;
  transition: all 0.15s;
}
.inline-link:hover { border-bottom-color: var(--accent); text-shadow: 0 0 6px var(--accent-glow); }
.msg-group.out .inline-link { color: #fff; border-bottom-color: rgba(255,255,255,0.5); }
.msg-group.out .inline-link:hover { border-bottom-color: #fff; }

/* Chat message hover actions (copy, delete) */
.msg-actions {
  display: flex;
  gap: 4px;
  opacity: 0;
  transition: opacity 0.2s;
  margin-left: 6px;
}
.msg-group.in .msg-actions { margin-left: 0; margin-right: 6px; }
.msg-bubble:hover ~ .msg-meta .msg-actions,
.msg-meta:hover .msg-actions,
.msg-meta:focus-within .msg-actions { opacity: 1; }
/* Touch devices have no hover state at all, so hover-gated actions would
   otherwise be permanently invisible and unreachable there — always show
   them below the ~tablet breakpoint and on any device that reports no
   hover capability. */
@media (hover: none), (max-width: 768px) {
  .msg-actions { opacity: 1; }
}
.msg-action-btn {
  background: none; border: none; cursor: pointer;
  color: var(--text3); font-size: 11px; padding: 2px 6px;
  border-radius: 4px; transition: all 0.15s;
}
.msg-action-btn:hover, .msg-action-btn:focus-visible { background: rgba(255,255,255,0.08); color: var(--text1); }

/* Reactions */
.reactions {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: -6px;
  margin-bottom: 4px;
  z-index: 2;
  position: relative;
}
.reaction-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 3px 8px;
  border-radius: 999px;
  background: var(--s2);
  backdrop-filter: blur(8px);
  border: 1px solid var(--border);
  font-size: 13px;
  cursor: pointer;
  transition: all 0.2s;
  box-shadow: 0 2px 8px rgba(0,0,0,0.15);
}
.reaction-chip:hover { 
  border-color: var(--accent); 
  transform: translateY(-2px);
  box-shadow: 0 4px 12px rgba(0,0,0,0.25);
}
.reaction-chip.mine { 
  border-color: var(--accent); 
  background: rgba(0, 210, 255, 0.1); 
}

.reaction-bar {
  display: flex;
  opacity: 0;
  visibility: hidden;
  transform: translateY(10px) scale(0.95);
  position: absolute;
  bottom: calc(100% + 8px);
  background: var(--s2);
  backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  border-radius: 14px;
  padding: 6px;
  gap: 4px;
  z-index: 10;
  box-shadow: 0 8px 32px rgba(0,0,0,0.4);
  transition: opacity 0.2s cubic-bezier(0.2, 0.8, 0.2, 1),
              transform 0.2s cubic-bezier(0.2, 0.8, 0.2, 1),
              visibility 0.2s;
  transition-delay: 1.5s;
}
.msg-group.out .reaction-bar { right: 0; }
.msg-group.in .reaction-bar { left: 0; }
.msg-bubble:hover .reaction-bar {
  opacity: 1;
  visibility: visible;
  transform: translateY(0) scale(1);
  transition-delay: 0s;
}
.reaction-bar:hover,
.reaction-bar:focus-within {
  opacity: 1;
  visibility: visible;
  transform: translateY(0) scale(1);
  transition-delay: 0s;
}
/* Same touch-accessibility rationale as .msg-actions above: without a real
   hover state, this bar would never appear on a touchscreen. It's shown
   inline instead of as a hover flyout below the tablet breakpoint. */
@media (hover: none), (max-width: 768px) {
  .reaction-bar {
    opacity: 1; visibility: visible; transform: none;
    position: static; margin-top: 6px; box-shadow: none;
  }
}
.reaction-btn {
  width: 36px; height: 36px;
  border-radius: 10px;
  background: none;
  border: none;
  cursor: pointer;
  font-size: 18px;
  display: flex; align-items: center; justify-content: center;
  transition: all 0.2s;
}
.reaction-btn:hover, .reaction-btn:focus-visible { background: rgba(255,255,255,0.1); transform: scale(1.1); }

/* Typing indicator */
#typing-indicator {
  padding: 0 24px 12px;
  min-height: 32px;
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
  color: var(--text2);
}
.typing-dots {
  display: flex;
  gap: 4px;
  align-items: center;
  background: var(--s3);
  padding: 8px 12px;
  border-radius: 16px;
  border: 1px solid var(--border);
}
.typing-dot {
  width: 6px; height: 6px;
  border-radius: 50%;
  background: var(--accent);
  animation: bounce 1.4s infinite ease-in-out;
  box-shadow: 0 0 4px var(--accent-glow);
}
.typing-dot:nth-child(2) { animation-delay: 0.2s; }
.typing-dot:nth-child(3) { animation-delay: 0.4s; }
@keyframes bounce {
  0%,80%,100% { transform: translateY(0); opacity: 0.4; }
  40% { transform: translateY(-4px); opacity: 1; }
}

/* Composer */
.composer {
  padding: 16px 24px 20px;
  border-top: 1px solid var(--border);
  background: rgba(10, 15, 25, 0.6);
  backdrop-filter: blur(20px);
  -webkit-backdrop-filter: blur(20px);
  z-index: 5;
}
.composer-inner {
  display: flex;
  gap: 12px;
  align-items: flex-end;
  background: rgba(0,0,0,0.3);
  border: 1px solid var(--border);
  border-radius: 20px;
  padding: 10px 14px;
  transition: all 0.3s;
  box-shadow: inset 0 2px 8px rgba(0,0,0,0.2);
}
.composer-inner:focus-within { 
  border-color: var(--accent); 
  box-shadow: 0 0 0 3px rgba(0, 210, 255, 0.15), inset 0 2px 8px rgba(0,0,0,0.2);
}
#text {
  flex: 1;
  background: none;
  border: none;
  outline: none;
  color: var(--text1);
  font-family: var(--font);
  font-size: 15px;
  resize: none;
  max-height: 140px;
  min-height: 24px;
  line-height: 1.5;
  padding-bottom: 4px;
}
#text::placeholder { color: var(--text3); }
.composer-actions { display: flex; align-items: center; gap: 6px; }
.icon-btn {
  width: 38px; height: 38px;
  display: flex; align-items: center; justify-content: center;
  background: none; border: none; cursor: pointer;
  color: var(--text2);
  border-radius: 10px;
  font-size: 20px;
  transition: all 0.2s;
}
.icon-btn:hover { 
  background: rgba(255,255,255,0.05); 
  color: var(--accent); 
  transform: translateY(-1px);
}
.send-btn {
  width: 40px; height: 40px;
  display: flex; align-items: center; justify-content: center;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  border: none; cursor: pointer;
  color: #fff;
  border-radius: 12px;
  font-size: 18px;
  transition: all 0.2s;
  flex-shrink: 0;
  box-shadow: 0 4px 12px var(--accent-glow);
}
.send-btn:hover { 
  transform: translateY(-2px);
  box-shadow: 0 6px 16px var(--accent-glow);
}
.send-btn:active { transform: scale(0.95); }
.send-btn:disabled { 
  opacity: 0.4; 
  cursor: not-allowed; 
  background: var(--s4); 
  box-shadow: none;
  transform: none;
}

.char-hint {
  font-size: 11px;
  color: var(--text3);
  text-align: right;
  margin-top: 6px;
  font-family: var(--mono);
}
.transfer-status {
  min-height: 20px; margin-top: 7px; display: flex; align-items: center; gap: 8px;
  color: var(--text2); font-size: 11px;
}
.transfer-status:empty { min-height: 0; margin-top: 0; }
.transfer-status .progress-track {
  width: 96px; height: 4px; overflow: hidden; background: rgba(255,255,255,.1); border-radius: 2px;
}
.transfer-status .progress-fill { height: 100%; background: var(--accent); transition: width .15s linear; }
.icon-btn.busy { opacity: .45; pointer-events: none; }

/* ── Right panel ── */
.panel-section {
  padding: 18px 20px;
  border-bottom: 1px solid var(--border);
}
.panel-title {
  font-size: 12px;
  font-weight: 700;
  text-transform: uppercase;
  letter-spacing: 0.15em;
  color: var(--text3);
  margin-bottom: 14px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.panel-title::after {
  content: '';
  flex: 1;
  height: 1px;
  background: linear-gradient(90deg, var(--border), transparent);
}

.stat-row {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 12px;
}
.stat-box {
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 14px;
  text-align: center;
  transition: all 0.2s;
}
.stat-box:hover {
  background: rgba(255,255,255,0.03);
  border-color: var(--border2);
  transform: translateY(-2px);
}
.stat-box b { 
  display: block; 
  font-size: 24px; 
  font-weight: 700; 
  margin-bottom: 4px;
  background: linear-gradient(135deg, var(--accent2), var(--accent));
  -webkit-background-clip: text;
  -webkit-text-fill-color: transparent;
}
.stat-box span { font-size: 11px; color: var(--text2); text-transform: uppercase; font-weight: 600; letter-spacing: 0.05em; }

.session-item {
  padding: 12px;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 8px;
  font-size: 13px;
  transition: all 0.2s;
}
.session-item:hover {
  border-color: var(--border2);
  background: rgba(255,255,255,0.02);
}
.session-item-name { font-weight: 600; margin-bottom: 4px; font-size: 14px; }
.session-item-meta { color: var(--text2); font-family: var(--mono); font-size: 11px; }
.session-age {
  font-size: 11px;
  margin-top: 8px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.session-age .bar {
  flex: 1;
  height: 4px;
  background: rgba(255,255,255,0.1);
  border-radius: 2px;
  overflow: hidden;
}
.session-age .fill {
  height: 100%;
  background: linear-gradient(90deg, #34d39a, #10b981);
  border-radius: 2px;
  transition: width 0.3s;
  box-shadow: 0 0 6px rgba(16, 185, 129, 0.4);
}
.session-age .fill.warn { background: linear-gradient(90deg, #fbbf24, #f59e0b); box-shadow: 0 0 6px rgba(245, 158, 11, 0.4); }
.session-age .fill.danger { background: linear-gradient(90deg, #fb7185, #e11d48); box-shadow: 0 0 6px rgba(225, 29, 72, 0.4); }

.file-item {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 10px 14px;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  margin-bottom: 8px;
  transition: all 0.2s;
}
.file-item:hover {
  transform: translateY(-2px);
  border-color: var(--border2);
  box-shadow: 0 4px 12px rgba(0,0,0,0.15);
}
.file-icon { 
  font-size: 24px; 
  flex-shrink: 0; 
  background: rgba(255,255,255,0.05);
  width: 40px; height: 40px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 10px;
}
.file-info { flex: 1; min-width: 0; }
.file-name {
  font-size: 13px;
  font-weight: 600;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
  margin-bottom: 2px;
}
.file-meta { font-size: 11px; color: var(--text2); }
.file-dl {
  font-size: 20px;
  color: var(--text3);
  text-decoration: none;
  transition: all 0.2s;
  flex-shrink: 0;
  width: 32px; height: 32px;
  display: flex; align-items: center; justify-content: center;
  border-radius: 8px;
}
.file-dl:hover { 
  color: var(--accent); 
  background: rgba(0, 210, 255, 0.1);
}
.file-audio { width: 100%; height: 32px; margin-top: 6px; }
.file-audio::-webkit-media-controls-panel { background: var(--s3); }

/* ── Storage quota ── */
.quota-row { font-size: 11px; margin-top: 8px; }
.quota-row .bar {
  height: 4px; background: rgba(255,255,255,0.1); border-radius: 2px; overflow: hidden; margin-top: 6px;
}
.quota-row .fill {
  height: 100%; border-radius: 2px; transition: width 0.3s;
  background: linear-gradient(90deg, var(--accent2), var(--accent));
  box-shadow: 0 0 6px var(--accent-glow);
}
.quota-row .fill.warn { background: linear-gradient(90deg, #fbbf24, #f59e0b); box-shadow: 0 0 6px rgba(245, 158, 11, 0.4); }
.quota-row .fill.danger { background: linear-gradient(90deg, #fb7185, #e11d48); box-shadow: 0 0 6px rgba(225, 29, 72, 0.4); }
.quota-label { display: flex; justify-content: space-between; color: var(--text2); }

/* ── Group member management ── */
.member-row {
  display: flex; align-items: center; gap: 8px;
  padding: 8px 10px; border-radius: 10px;
  background: rgba(0,0,0,0.2); border: 1px solid var(--border);
  margin-bottom: 6px; font-size: 12px;
}
.member-row .mono { flex: 1; min-width: 0; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: var(--text2); }
.member-row .role-tag {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.05em;
  color: var(--text3); background: rgba(255,255,255,0.05); padding: 2px 6px; border-radius: 999px;
}
.member-row .rm-btn {
  background: none; border: none; color: var(--text3); cursor: pointer; font-size: 14px;
  width: 22px; height: 22px; border-radius: 6px; flex-shrink: 0;
}
.member-row .rm-btn:hover { color: var(--danger); background: rgba(255, 51, 102, 0.1); }

/* ── Load more history ── */
.load-more-row { display: flex; justify-content: center; padding: 4px 0 14px; }
.load-more-btn {
  font-size: 12px; color: var(--text2); background: var(--s3);
  border: 1px solid var(--border); border-radius: 999px; padding: 6px 16px; cursor: pointer;
  transition: all 0.2s;
}
.load-more-btn:hover { border-color: var(--border2); color: var(--text1); }

/* ── Recording mic button ── */
.icon-btn.recording {
  color: var(--danger);
  animation: recPulse 1.2s infinite;
}
@keyframes recPulse {
  0%,100% { opacity: 1; } 50% { opacity: 0.45; }
}
.rec-indicator {
  display: flex; align-items: center; gap: 6px;
  font-size: 12px; color: var(--danger); font-family: var(--mono);
  padding: 0 24px 8px;
}
.rec-indicator .dot {
  width: 8px; height: 8px; border-radius: 50%; background: var(--danger);
  box-shadow: 0 0 6px var(--danger); animation: pulse 1s infinite;
}
.rec-cancel {
  margin-left: 8px; padding: 3px 8px; border: 1px solid rgba(255,51,102,.45);
  border-radius: 6px; background: transparent; color: var(--danger); cursor: pointer;
}

/* ── Modal (identity backup / restore) ── */
.modal-overlay {
  display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.6);
  backdrop-filter: blur(4px); z-index: 100;
  align-items: center; justify-content: center;
}
.modal-overlay.open { display: flex; }
.modal {
  width: 420px; max-width: 92vw; max-height: 84vh; overflow-y: auto;
  background: var(--s2); border: 1px solid var(--border2); border-radius: var(--rad);
  box-shadow: var(--glass-shadow); padding: 22px;
}
.modal h2 { font-size: 16px; margin-bottom: 6px; }
.modal p.hint { font-size: 12px; color: var(--text2); margin-bottom: 14px; line-height: 1.5; }
.modal .field { margin-bottom: 10px; }
.modal textarea.field { min-height: 90px; font-family: var(--mono); font-size: 11px; resize: vertical; }
.modal-tabs { display: flex; gap: 6px; margin-bottom: 16px; }
.modal-tabs button {
  flex: 1; padding: 8px; font-size: 12px; border-radius: 8px; border: 1px solid var(--border);
  background: var(--s3); color: var(--text2); cursor: pointer;
}
.modal-tabs button.active { color: #fff; border-color: var(--accent2); background: rgba(58,134,255,0.15); }
.modal-actions { display: flex; gap: 8px; margin-top: 14px; }

/* ── Message search ── */
.search-results { max-height: 320px; overflow-y: auto; display: flex; flex-direction: column; gap: 6px; margin-top: 4px; }
.search-result-item {
  text-align: left; width: 100%; padding: 10px 12px; border-radius: 10px;
  border: 1px solid var(--border); background: var(--s3); color: var(--text);
  cursor: pointer; font-size: 13px; line-height: 1.4;
}
.search-result-item:hover, .search-result-item:focus-visible { border-color: var(--accent2); background: rgba(58,134,255,0.1); }
.search-result-meta { font-size: 11px; color: var(--text3); margin-bottom: 4px; }
.search-empty { font-size: 12px; color: var(--text3); text-align: center; padding: 18px 0; }

/* ── Calls ── */
.call-modal { text-align: center; }
.call-modal-avatar {
  width: 72px; height: 72px; border-radius: 50%; margin: 0 auto 14px;
  display: flex; align-items: center; justify-content: center;
  font-size: 30px; background: linear-gradient(135deg, var(--accent2), var(--accent));
  animation: call-pulse 1.4s ease-in-out infinite;
}
@keyframes call-pulse {
  0%, 100% { box-shadow: 0 0 0 0 var(--accent-glow); }
  50% { box-shadow: 0 0 0 14px rgba(58,134,255,0); }
}
.call-overlay {
  position: fixed; inset: 0; z-index: 200; background: #050608;
  display: flex; align-items: center; justify-content: center;
}
.call-overlay[hidden] { display: none; }
.call-overlay-inner { position: relative; width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; }
#remoteVideo {
  position: absolute; inset: 0; width: 100%; height: 100%; object-fit: cover; background: #0a0b0d;
}
#localVideo {
  position: absolute; bottom: 96px; right: 20px; width: 140px; height: 100px;
  object-fit: cover; border-radius: 12px; border: 2px solid var(--border2);
  box-shadow: var(--glass-shadow); background: #111; z-index: 2;
}
.call-overlay-info {
  position: relative; z-index: 1; display: flex; flex-direction: column; align-items: center;
  gap: 8px; color: #fff; text-shadow: 0 2px 8px rgba(0,0,0,0.6);
}
.call-overlay-avatar {
  width: 88px; height: 88px; border-radius: 50%; display: flex; align-items: center;
  justify-content: center; font-size: 34px; background: linear-gradient(135deg, var(--accent2), var(--accent));
}
.call-overlay-name { font-size: 20px; font-weight: 700; }
.call-overlay-status { font-size: 13px; opacity: 0.85; }
.call-overlay-controls {
  position: absolute; bottom: 28px; left: 50%; transform: translateX(-50%);
  display: flex; gap: 16px; z-index: 3;
}
.call-btn {
  width: 56px; height: 56px; border-radius: 50%; border: none; cursor: pointer;
  background: rgba(255,255,255,0.14); color: #fff; font-size: 22px;
  display: flex; align-items: center; justify-content: center; transition: all 0.15s;
}
.call-btn:hover { background: rgba(255,255,255,0.24); }
.call-btn:active { transform: scale(0.94); }
.call-btn.call-btn-muted { background: rgba(255,255,255,0.35); }
.call-btn-end { background: var(--danger, #e5484d); }
.call-btn-end:hover { filter: brightness(1.1); }

/* ── Add friend / group panels ── */
.slide-panel {
  background: rgba(0,0,0,0.15);
  border-bottom: 1px solid var(--border);
  overflow: hidden;
  max-height: 0;
  transition: max-height 0.4s cubic-bezier(0.25, 0.8, 0.25, 1);
}
.slide-panel.open { max-height: 400px; }
.slide-panel-inner { padding: 16px 20px; display: flex; flex-direction: column; gap: 12px; }

/* ── Buttons ── */
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  padding: 10px 18px;
  border-radius: 12px;
  font-family: var(--font);
  font-size: 14px;
  font-weight: 600;
  border: none;
  cursor: pointer;
  transition: all 0.2s;
}
.btn:active { transform: scale(0.96); }
.btn-primary { 
  background: linear-gradient(135deg, var(--accent2), var(--accent)); 
  color: #fff; 
  box-shadow: 0 4px 12px var(--accent-glow);
}
.btn-primary:hover { 
  box-shadow: 0 6px 16px var(--accent-glow); 
  filter: brightness(1.1);
}
.btn-secondary { 
  background: rgba(255,255,255,0.05); 
  color: var(--text1); 
  border: 1px solid var(--border); 
}
.btn-secondary:hover { 
  border-color: var(--border2); 
  background: rgba(255,255,255,0.08);
}
.btn-danger { 
  background: rgba(255, 51, 102, 0.1); 
  color: var(--danger); 
  border: 1px solid rgba(255, 51, 102, 0.2); 
}
.btn-danger:hover { 
  background: rgba(255, 51, 102, 0.2); 
  box-shadow: 0 4px 12px rgba(255, 51, 102, 0.2);
}
.btn-sm { padding: 6px 12px; font-size: 13px; border-radius: 8px; }

/* ── Inputs ── */
.field {
  width: 100%;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 12px 16px;
  color: var(--text1);
  font-family: var(--font);
  font-size: 14px;
  outline: none;
  transition: all 0.2s;
}
.field:focus { 
  border-color: var(--accent); 
  background: rgba(0,0,0,0.4);
  box-shadow: 0 0 0 3px rgba(0, 210, 255, 0.1);
}
.field::placeholder { color: var(--text3); }

/* ── Toast ── */
#toasts {
  position: fixed;
  bottom: 24px;
  right: 24px;
  display: flex;
  flex-direction: column-reverse;
  gap: 12px;
  z-index: 100;
  max-width: 380px;
}
.toast {
  padding: 16px 20px;
  border-radius: 16px;
  background: rgba(18, 25, 40, 0.85);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border);
  font-size: 14px;
  animation: slideIn 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275);
  box-shadow: 0 12px 32px rgba(0,0,0,0.5);
  display: flex;
  align-items: flex-start;
  gap: 12px;
}
.toast.info { border-left: 4px solid var(--accent); }
.toast.success { border-left: 4px solid #34d39a; }
.toast.error { border-left: 4px solid var(--danger); }
.toast.warning { border-left: 4px solid var(--warn); }
.toast-icon { flex-shrink: 0; font-size: 18px; margin-top: 2px; }
@keyframes slideIn {
  from { transform: translateX(120%); opacity: 0; }
  to { transform: translateX(0); opacity: 1; }
}
@keyframes fadeOut {
  from { opacity: 1; transform: scale(1); }
  to { opacity: 0; transform: scale(0.9); }
}

/* ── Empty states ── */
.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  flex: 1;
  gap: 16px;
  color: var(--text3);
  text-align: center;
  padding: 40px;
}
.empty-state .emo { 
  font-size: 48px; 
  margin-bottom: 8px;
  filter: drop-shadow(0 8px 16px rgba(0,0,0,0.2));
}
.empty-state h3 { font-size: 18px; color: var(--text1); font-weight: 600; }
.empty-state p { font-size: 14px; max-width: 280px; line-height: 1.6; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 6px; height: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { 
  background: rgba(255,255,255,0.1); 
  border-radius: 6px; 
}
::-webkit-scrollbar-thumb:hover { background: rgba(255,255,255,0.2); }

/* ── Mode selector ── */
.mode-tabs {
  display: flex;
  gap: 4px;
  margin: 12px 16px;
  border-radius: 12px;
  overflow: hidden;
  background: rgba(0,0,0,0.2);
  border: 1px solid var(--border);
  padding: 4px;
}
.mode-tab {
  flex: 1;
  padding: 8px;
  text-align: center;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  background: transparent;
  color: var(--text2);
  border: none;
  border-radius: 8px;
  transition: all 0.2s;
}
.mode-tab:hover { color: var(--text1); background: rgba(255,255,255,0.05); }
.mode-tab.active { 
  background: rgba(255,255,255,0.1); 
  color: #fff; 
  box-shadow: 0 2px 8px rgba(0,0,0,0.2);
}

/* ── Misc ── */
.muted { color: var(--text2); }
.mono { font-family: var(--mono); }

@media (max-width: 960px) {
  #panel { display: none; }
}
@media (max-width: 768px) {
  #sidebar { width: 280px; min-width: 280px; }
}
@media (max-width: 640px) {
  #sidebar { width: 72px; min-width: 72px; }
  .friend-info, .id-key, .search-wrap, .mode-tabs,
  .section-label span, .friend-name, .unread-badge { display: none; }
  .friend-avatar { margin: 0 auto; }
  .sidebar-head .conn-badge span { display: none; }
  .app-logo h1, .app-logo .ver { display: none; }
  .app-logo { justify-content: center; }
  .section-label { justify-content: center; padding: 12px 0; }
  .id-card { padding: 12px; }
  .id-card-head { justify-content: center; }
  .id-card-head > div:last-child { display: none; }
  .composer { padding: 12px; }
  .messages-wrap { padding-left: 12px; padding-right: 12px; }
  .msg-bubble { max-width: 88%; }
  .attachment-card { width: min(310px, 76vw); }
}
</style>
</head>
<body>
<div id="app">
  <!-- ── Sidebar ─────────────────────────── -->
  <aside id="sidebar">
    <div class="sidebar-head">
      <div class="app-logo">
        <span class="icon">⚛</span>
        <div>
          <h1>Quantum Chat</h1>
          <div class="ver">v__VERSION__</div>
        </div>
      </div>
      <div class="conn-badge" id="connBadge">
        <span class="dot"></span>
        <span id="connText">connecting…</span>
      </div>
    </div>

    <!-- Identity card -->
    <div class="id-card" onclick="toggleId()">
      <div class="id-card-head">
        <div class="id-avatar">⚛</div>
        <div>
          <div class="id-name">Your Identity</div>
          <div class="id-fp mono" id="myFp">loading…</div>
        </div>
      </div>
      <div class="id-key" id="myKey" onclick="event.stopPropagation()">loading…</div>
      <div class="id-actions" id="idActions" style="display:none">
        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();copyKey()">Copy key</button>
        <button class="btn btn-secondary btn-sm" onclick="event.stopPropagation();openBackupModal()">Backup / restore</button>
      </div>
    </div>

    <!-- Mode tabs -->
    <div class="mode-tabs">
      <button class="mode-tab active" id="tabFriends" onclick="setMode('friends')">Friends</button>
      <button class="mode-tab" id="tabGroups" onclick="setMode('groups')">Groups</button>
    </div>

    <!-- Search -->
    <div class="search-wrap">
      <input class="search-input" id="sideSearch" placeholder="Search…" oninput="renderSidebar()">
    </div>

    <!-- Add Friend panel -->
    <div class="slide-panel" id="addPanel">
      <div class="slide-panel-inner">
        <input class="field" id="friendKey" placeholder="Friend public key">
        <input class="field" id="friendName" placeholder="Nickname (optional)">
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" style="flex:1" onclick="addFriend()">Add friend</button>
          <button class="btn btn-secondary" onclick="toggleAdd()">Cancel</button>
        </div>
      </div>
    </div>

    <!-- Add Group panel -->
    <div class="slide-panel" id="groupPanel">
      <div class="slide-panel-inner">
        <input class="field" id="groupName" placeholder="Group name">
        <input class="field" id="groupMembers" placeholder="Member keys, comma-separated (or leave empty)">
        <div style="display:flex;gap:8px">
          <button class="btn btn-primary" style="flex:1" onclick="createGroup()">Create</button>
          <button class="btn btn-secondary" onclick="toggleGroup()">Cancel</button>
        </div>
      </div>
    </div>

    <div class="list-section" id="listSection"></div>
  </aside>

  <!-- ── Main chat ───────────────────────── -->
  <main id="main">
    <!-- Chat header -->
    <div class="chat-header" id="chatHeader">
      <div class="empty-state" style="flex-direction:row;padding:0;flex:1">
        <span style="color:var(--text3);font-size:13px">← Select a friend or group to start chatting</span>
      </div>
    </div>

    <!-- Group member management -->
    <div class="slide-panel" id="groupManagePanel">
      <div class="slide-panel-inner" id="groupManageBody"></div>
    </div>

    <!-- Messages -->
    <div class="messages-wrap" id="messages">
      <div class="empty-state">
        <div class="emo">🔐</div>
        <h3>Post-quantum encrypted</h3>
        <p>All messages are encrypted with Kyber-512 + AES-256-GCM. Select a contact to start.</p>
      </div>
    </div>

    <!-- Typing indicator -->
    <div id="typing-indicator"></div>
    <div id="recIndicator"></div>

    <!-- Drop overlay -->
    <div class="drop-overlay" id="dropOverlay">
      <div style="font-size:36px">📎</div>
      <div>Drop file to send encrypted</div>
    </div>

    <!-- Composer -->
    <div class="composer">
      <div class="composer-inner">
        <textarea id="text" rows="1" placeholder="Type an encrypted message…"
          aria-label="Message text" oninput="onTextInput()" onkeydown="onTextKey(event)"></textarea>
        <div class="composer-actions">
          <label class="icon-btn" id="attachBtn" title="Attach file" aria-label="Attach file" role="button" tabindex="0">
            📎
            <input id="fileInput" type="file" hidden onchange="sendFile()" aria-label="Choose a file to send">
          </label>
          <button class="icon-btn" id="micBtn" title="Record voice message" aria-label="Record voice message" onclick="toggleVoiceRecording()">🎙️</button>
          <button class="send-btn" id="sendBtn" onclick="sendMessage()" disabled title="Send" aria-label="Send message">➤</button>
        </div>
      </div>
      <div class="transfer-status" id="transferStatus"></div>
      <div class="char-hint" id="charHint">0 / 65536</div>
    </div>
  </main>

  <!-- ── Right panel ─────────────────────── -->
  <aside id="panel">
    <div class="panel-section">
      <div class="panel-title">Overview</div>
      <div class="stat-row">
        <div class="stat-box"><b id="statFriends">0</b><span>friends</span></div>
        <div class="stat-box"><b id="statOnline">0</b><span>online</span></div>
        <div class="stat-box"><b id="statSessions">0</b><span>sessions</span></div>
        <div class="stat-box"><b id="statFiles">0</b><span>files</span></div>
      </div>
    </div>
    <div class="panel-section" id="panelSessions">
      <div class="panel-title">Secure sessions</div>
      <div id="sessionList"><span class="muted" style="font-size:12px">No sessions yet</span></div>
    </div>
    <div class="panel-section" id="panelFiles">
      <div class="panel-title">Recent files</div>
      <div id="fileList"><span class="muted" style="font-size:12px">No files yet</span></div>
    </div>
    <div class="panel-section" id="panelStorage">
      <div class="panel-title">Storage</div>
      <div id="storageQuota"></div>
    </div>
  </aside>
</div>

<!-- Backup / restore identity modal -->
<div class="modal-overlay" id="backupModal" role="dialog" aria-modal="true" aria-labelledby="backupModalTitle">
  <div class="modal">
    <h2 id="backupModalTitle">Identity backup &amp; restore</h2>
    <p class="hint">
      Carry your identity (public key / fingerprint) to a second device. This does
      <b>not</b> copy friends, sessions, or message history — only your signing keypair,
      protected by the passphrase you choose. Import only into a brand-new install.
    </p>
    <div class="modal-tabs">
      <button id="backupTabExport" class="active" onclick="setBackupTab('export')">Export</button>
      <button id="backupTabImport" onclick="setBackupTab('import')">Import</button>
    </div>
    <div id="backupExportPane">
      <input class="field" id="backupExportPass" type="password" placeholder="Choose a backup passphrase (min 8 chars)">
      <button class="btn btn-primary" style="width:100%" onclick="exportBackup()">Generate backup</button>
      <textarea class="field" id="backupExportResult" readonly placeholder="Your encrypted backup will appear here…"></textarea>
      <button class="btn btn-secondary btn-sm" onclick="copyBackupResult()">Copy to clipboard</button>
    </div>
    <div id="backupImportPane" style="display:none">
      <textarea class="field" id="backupImportBlob" placeholder="Paste an identity backup string (starts with QCID1:)"></textarea>
      <input class="field" id="backupImportPass" type="password" placeholder="Backup passphrase">
      <button class="btn btn-primary" style="width:100%" onclick="importBackup()">Import identity</button>
    </div>
    <div class="modal-actions">
      <button class="btn btn-secondary" style="flex:1" onclick="closeBackupModal()">Close</button>
    </div>
  </div>
</div>

<!-- Message search -->
<div class="modal-overlay" id="searchModal" role="dialog" aria-modal="true" aria-labelledby="searchModalTitle">
  <div class="modal">
    <h2 id="searchModalTitle">Search messages</h2>
    <p class="hint" id="searchScopeHint">Searching this conversation.</p>
    <input class="field" id="searchInput" type="text" placeholder="Search…"
           aria-label="Search message text" oninput="debounceSearch()"
           onkeydown="if(event.key==='Enter') runSearch()">
    <div id="searchResults" class="search-results" aria-live="polite"></div>
    <div class="modal-actions">
      <button class="btn btn-secondary" style="flex:1" onclick="closeSearchModal()">Close</button>
    </div>
  </div>
</div>

<!-- Incoming call -->
<div class="modal-overlay" id="incomingCallModal" role="dialog" aria-modal="true" aria-labelledby="incomingCallTitle">
  <div class="modal call-modal">
    <div class="call-modal-avatar" id="incomingCallAvatar">📞</div>
    <h2 id="incomingCallTitle">Incoming call</h2>
    <p class="hint" id="incomingCallSub">someone is calling…</p>
    <div class="modal-actions">
      <button class="btn btn-danger" style="flex:1" onclick="declineCall()" aria-label="Decline call">Decline</button>
      <button class="btn btn-primary" style="flex:1" onclick="acceptCall()" aria-label="Accept call">Accept</button>
    </div>
  </div>
</div>

<!-- Active/outgoing call overlay -->
<div class="call-overlay" id="callOverlay" hidden role="dialog" aria-modal="true" aria-labelledby="callOverlayName">
  <div class="call-overlay-inner">
    <video id="remoteVideo" autoplay playsinline></video>
    <video id="localVideo" autoplay playsinline muted></video>
    <div class="call-overlay-info">
      <div class="call-overlay-avatar" id="callOverlayAvatar">📞</div>
      <div class="call-overlay-name" id="callOverlayName">—</div>
      <div class="call-overlay-status" id="callOverlayStatus" aria-live="polite">Calling…</div>
    </div>
    <div class="call-overlay-controls">
      <button class="call-btn" id="callMuteBtn" onclick="toggleCallMute()" aria-label="Mute microphone" title="Mute microphone">🎙️</button>
      <button class="call-btn" id="callCameraBtn" onclick="toggleCallCamera()" aria-label="Turn camera off" title="Turn camera off">🎥</button>
      <button class="call-btn call-btn-end" onclick="hangupCall()" aria-label="End call" title="End call">📵</button>
    </div>
  </div>
</div>

<!-- Toasts -->
<div id="toasts"></div>

<script>
// ─── State ──────────────────────────────────────────────────────────────────
const UI_WS_PORT = __UI_WS_PORT__;
const UI_TOKEN = "__UI_TOKEN__";
const MAX_FILE_BYTES_UI = 512*1024*1024;

let state = {
  public_key: '', fingerprint: '', signaling_url: '',
  online: [], friends: [], groups: [], messages: [],
  files: [], sessions: {}, has_more_messages: false,
  storage_bytes: 0, max_storage_bytes: 0,
};
let ws = null;
let mode = 'friends';          // 'friends' | 'groups'
let selectedTarget = null;     // {type:'friend'|'group', id:string}
let typing = {};               // peer_pubkey -> timestamp
let typingTimer = null;
let myTypingActive = false;
let myTypingTimeout = null;
let notificationsGranted = false;
let unreadTitle = 0;
let titleTimer = null;
let mediaRecorder = null;
let recordedChunks = [];
let recordStart = 0;
let recordTimer = null;
let recordingTarget = null;
let discardRecording = false;
let uploadInProgress = false;
let pendingUploadName = '';
let loadingMore = false;
let searchDebounceTimer = null;
// Call state: at most one call in flight at a time in this UI.
let pc = null;                 // RTCPeerConnection
let localStream = null;
let currentCall = null;        // {peer, call_id, role, media, state}
let pendingIceQueue = [];      // candidates that arrived before setRemoteDescription

// ─── Utils ──────────────────────────────────────────────────────────────────
const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const short = k => k ? k.slice(0,10)+'…'+k.slice(-6) : '';
// Auto-link bare URLs in already-escaped text. Returns HTML. We deliberately
// only match http(s):// to avoid mangling code samples or local paths, and we
// add target=_blank + rel="noopener" so the new tab can't reach back into the app.
const linkify = escapedHtml => {
  return escapedHtml.replace(/(https?:\/\/[^\s<]+)/g, url => {
    const safe = url.replace(/"/g,'&quot;');
    return `<a href="${safe}" target="_blank" rel="noopener noreferrer" class="inline-link">${url}</a>`;
  });
};
const fmt = n => {
  if(!Number.isFinite(+n)) return '0 B';
  let u=['B','KB','MB','GB'],i=0; n=+n;
  while(n>=1024&&i<u.length-1){n/=1024;i++}
  return `${n.toFixed(i?1:0)} ${u[i]}`;
};
const relTime = ts => {
  if(!ts) return '';
  const d = Date.now()/1000 - ts, m = Math.floor(d/60), h = Math.floor(d/3600), day = Math.floor(d/86400);
  if(d < 60) return 'just now';
  if(m < 60) return `${m}m ago`;
  if(h < 24) return `${h}h ago`;
  if(day < 7) return `${day}d ago`;
  return new Date(ts*1000).toLocaleDateString();
};
const fullTime = ts => ts ? new Date(ts*1000).toLocaleString() : '';
const dateLabel = ts => {
  if(!ts) return '';
  const d = new Date(ts*1000), today = new Date();
  if(d.toDateString() === today.toDateString()) return 'Today';
  const yesterday = new Date(today); yesterday.setDate(today.getDate()-1);
  if(d.toDateString() === yesterday.toDateString()) return 'Yesterday';
  return d.toLocaleDateString(undefined, {weekday:'long',month:'short',day:'numeric'});
};
const fileIcon = name => {
  const ext = (name||'').split('.').pop().toLowerCase();
  const map = {png:'🖼️',jpg:'🖼️',jpeg:'🖼️',gif:'🖼️',webp:'🖼️',svg:'🖼️',
               mp4:'🎬',mov:'🎬',avi:'🎬',webm:'🎬',mkv:'🎬',
               mp3:'🎵',wav:'🎵',ogg:'🎵',flac:'🎵',aac:'🎵',
               pdf:'📄',doc:'📄',docx:'📄',txt:'📄',md:'📄',
               zip:'📦',tar:'📦',gz:'📦',rar:'📦',
               py:'💻',js:'💻',ts:'💻',html:'💻',css:'💻',sh:'💻',
  };
  return map[ext] || '📎';
};
const isImage = name => /\.(png|jpg|jpeg|gif|webp|svg)$/i.test(name||'');
const isAudio = (name, type='') => String(type).startsWith('audio/') ||
  /\.(mp3|wav|ogg|oga|flac|aac|m4a|opus)$/i.test(name||'') ||
  (/^voice-message-/i.test(name||'') && /\.webm$/i.test(name||''));
const isVideo = (name, type='') => String(type).startsWith('video/') ||
  /\.(mp4|mov|m4v|avi|mkv|webm)$/i.test(name||'');
const snapshotTarget = () => selectedTarget ? {...selectedTarget} : null;
const fileViewUrl = fileId => `/files/${encodeURIComponent(fileId)}?view=1&token=${encodeURIComponent(UI_TOKEN)}`;
const fileDownloadUrl = fileId => `/files/${encodeURIComponent(fileId)}?token=${encodeURIComponent(UI_TOKEN)}`;
const normalizeFile = f => ({
  ...f,
  sender_pubkey: f.sender_pubkey || f.from || '',
  recipient_pubkey: f.recipient_pubkey || f.to || null,
  direction: f.direction || ((f.sender_pubkey || f.from) === state.public_key ? 'out' : 'in'),
  uploaded_at: f.uploaded_at || f.sent_at || (Date.now()/1000|0),
  mime_type: f.mime_type || '',
});
const fileMessage = raw => {
  const f = normalizeFile(raw);
  return {
    msg_id: `file-${f.file_id}`,
    sender_pubkey: f.sender_pubkey,
    recipient_pubkey: f.recipient_pubkey,
    group_id: f.group_id || null,
    body: f.filename,
    direction: f.direction,
    timestamp: f.uploaded_at,
    delivered: 1,
    status: 'delivered',
    reactions: [], read_at: 1,
    _isFile: true, _file: f,
  };
};
const avatarLetter = name => (name||'?').trim()[0].toUpperCase();
const avatarColor = key => {
  let h = 0;
  for(let c of (key||'')) h = ((h<<5)-h) + c.charCodeAt(0);
  const colors = ['#1a3a8f','#2a1a8f','#1a6a5f','#5a1a6f','#8f3a1a','#1a5a8f'];
  return colors[Math.abs(h) % colors.length];
};

// ─── WebSocket ───────────────────────────────────────────────────────────────
function wsConnect() {
  const scheme = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${scheme}://${location.hostname}:${UI_WS_PORT}/?token=${encodeURIComponent(UI_TOKEN)}`);
  ws.onopen = () => setConn(true);
  ws.onclose = () => { setConn(false); setTimeout(wsConnect, 1500); };
  ws.onerror = () => {};
  ws.onmessage = e => handle(JSON.parse(e.data));
}

function setConn(connected) {
  const b = $('connBadge'), t = $('connText');
  b.className = 'conn-badge' + (connected ? ' connected' : '');
  t.textContent = connected ? 'connected' : 'disconnected';
}

function send(obj) {
  if(ws && ws.readyState === 1) {
    try { ws.send(JSON.stringify(obj)); return true; }
    catch(_) { toast('Could not send to the local node', 'error'); return false; }
  }
  toast('UI socket not connected', 'warning');
  return false;
}

// ─── Message handler ─────────────────────────────────────────────────────────
function handle(d) {
  if(d.type === 'state') {
    state = d;
    state.files = (state.files||[]).map(normalizeFile);
    render();
  } else if(d.type === 'friends') {
    state.friends = d.friends;
    renderSidebar();
    renderChatHeader();
  } else if(d.type === 'history') {
    const el = $('messages');
    const prevHeight = el.scrollHeight, prevTop = el.scrollTop;
    state.messages = [...d.messages, ...state.messages];
    state.has_more_messages = d.has_more_messages;
    loadingMore = false;
    renderMessages();
    el.scrollTop = prevTop + (el.scrollHeight - prevHeight);
  } else if(d.type === 'identity_backup') {
    $('backupExportResult').value = d.backup;
    toast('Backup generated — copy it somewhere safe', 'success');
  } else if(d.type === 'notice') {
    if(d.level === 'error' && loadingMore) { loadingMore = false; renderMessages(); }
    if(d.level === 'error' && uploadInProgress) finishUpload();
    toast(d.text, d.level || 'info');
  } else if(d.type === 'message') {
    state.messages.push(d.message);
    const isSelected = selectedTarget &&
      (selectedTarget.type === 'friend'
        ? !d.message.group_id && (d.message.sender_pubkey === selectedTarget.id || d.message.recipient_pubkey === selectedTarget.id)
        : d.message.group_id === selectedTarget.id);
    if(!isSelected && d.message.direction === 'in') {
      const friend = state.friends.find(f => f.pubkey === d.message.sender_pubkey);
      const name = friend?.nickname || short(d.message.sender_pubkey);
      notify(name, d.message.body);
      bumpUnread(d.message.sender_pubkey);
    }
    renderMessages();
    renderSidebar();
    scrollBottom(false);
    if(isSelected && d.message.direction === 'in') {
      send({type:'clear_unread', pubkey: d.message.sender_pubkey});
    }
  } else if(d.type === 'file') {
    const file = normalizeFile(d.file);
    state.files = [file, ...state.files.filter(f => f.file_id !== file.file_id)];
    if(d.storage_bytes !== undefined) state.storage_bytes = d.storage_bytes;
    $('statFiles').textContent = state.files.length;
    renderFiles();
    renderStorageQuota();
    if(file.direction === 'out' && (!pendingUploadName || pendingUploadName === file.filename)) finishUpload();
    renderMessages();
    if(selectedTarget) scrollBottom(false);
    const isSelected = selectedTarget && matchTarget(fileMessage(file));
    if(isSelected && file.direction === 'in') send({type:'clear_unread', pubkey:file.sender_pubkey});
    if(!isSelected && file.direction === 'in') {
      const friend = state.friends.find(f => f.pubkey === file.sender_pubkey);
      notify(friend?.nickname || short(file.sender_pubkey), `Sent ${file.filename}`);
      bumpUnread(file.sender_pubkey);
    }
    toast(`${file.direction === 'in' ? '📥 Received' : '📤 Sent'} ${file.filename}`, 'success');
  } else if(d.type === 'typing') {
    if(d.active) {
      typing[d.peer] = Date.now();
      setTimeout(() => {
        delete typing[d.peer];
        renderTyping();
      }, 6000);
    } else {
      delete typing[d.peer];
    }
    renderTyping();
  } else if(d.type === 'status_update') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) { m.status = d.status; renderMessages(); }
  } else if(d.type === 'read_receipt') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) { m.status = 'read'; m.read_at = d.read_at; renderMessages(); }
  } else if(d.type === 'reaction') {
    const m = state.messages.find(x => x.msg_id === d.msg_id);
    if(m) {
      if(!m.reactions) m.reactions = [];
      if(d.action === 'add') {
        if(!m.reactions.find(r => r.peer_pubkey === d.peer && r.emoji === d.emoji))
          m.reactions.push({peer_pubkey: d.peer, emoji: d.emoji});
      } else {
        m.reactions = m.reactions.filter(r => !(r.peer_pubkey === d.peer && r.emoji === d.emoji));
      }
      renderMessages();
    }
  } else if(d.type === 'search_results') {
    renderSearchResults(d.query, d.results || []);
  } else if(d.type === 'call_incoming') {
    handleCallIncoming(d);
  } else if(d.type === 'call_answered') {
    handleCallAnswered(d);
  } else if(d.type === 'call_ice') {
    handleCallIceCandidate(d);
  } else if(d.type === 'call_state') {
    handleCallStateEvent(d);
  }
}

// ─── Render ──────────────────────────────────────────────────────────────────
function render() {
  $('myKey').textContent = state.public_key || '';
  $('myFp').textContent = state.fingerprint || '';
  $('statFriends').textContent = state.friends.length;
  $('statOnline').textContent = state.online.length;
  $('statSessions').textContent = Object.keys(state.sessions||{}).length;
  $('statFiles').textContent = (state.files||[]).length;
  renderSidebar();
  renderMessages();
  renderSessions();
  renderFiles();
  renderStorageQuota();
  updateSendBtn();
}

function renderSidebar() {
  const q = ($('sideSearch').value||'').toLowerCase();
  const el = $('listSection');
  el.innerHTML = '';

  if(mode === 'friends') {
    const friends = state.friends.filter(f =>
      !q || (f.nickname||'').toLowerCase().includes(q) || f.pubkey.toLowerCase().includes(q)
    );
    const addBtn = `<button onclick="toggleAdd()" title="Add friend" aria-label="Add friend">＋</button>`;
    const label = document.createElement('div');
    label.className = 'section-label';
    label.innerHTML = `<span>Friends (${friends.length})</span>${addBtn}`;
    el.appendChild(label);
    if(!friends.length) {
      el.innerHTML += '<div style="padding:16px;color:var(--text3);font-size:12px;text-align:center">No friends yet — add one above</div>';
      return;
    }
    friends.forEach(f => {
      const online = state.online.includes(f.pubkey);
      const secure = !!(state.sessions&&state.sessions[f.pubkey]);
      const isSelected = selectedTarget?.type === 'friend' && selectedTarget?.id === f.pubkey;
      const lastMsg = [...state.messages].reverse().find(m =>
        !m.group_id && (m.sender_pubkey === f.pubkey || m.recipient_pubkey === f.pubkey)
      );
      const unread = f.unread || 0;
      const div = document.createElement('div');
      div.className = 'friend-item' + (isSelected ? ' active' : '');
      div.onclick = () => selectFriend(f.pubkey);
      const bgColor = avatarColor(f.pubkey);
      div.innerHTML = `
        <div class="friend-avatar">
          <div class="avatar-circle" style="background:${bgColor}">${esc(avatarLetter(f.nickname||f.pubkey))}</div>
          <div class="online-dot ${online?'online':''}"></div>
        </div>
        <div class="friend-info">
          <div class="friend-name">${esc(f.nickname||short(f.pubkey))}</div>
          <div class="friend-preview">${lastMsg ? esc(lastMsg.body.slice(0,40)) : secure?'🔒 secure session':(f.verified?'✅ verified':'⚠️ unverified')}</div>
        </div>
        <div class="friend-meta">
          ${unread ? `<div class="unread-badge">${unread}</div>` : ''}
          ${f.verified ? '<div class="secure-tag">✅</div>' : '<div class="secure-tag">⚠️</div>'} ${secure ? '<div class="secure-tag">🔒</div>' : ''}
          ${lastMsg ? `<div class="time-tag">${relTime(lastMsg.timestamp)}</div>` : ''}
        </div>
      `;
      el.appendChild(div);
    });
  } else {
    const groups = state.groups.filter(g =>
      !q || (g.name||'').toLowerCase().includes(q)
    );
    const addBtn = `<button onclick="toggleGroup()" title="Create group" aria-label="Create group">＋</button>`;
    const label = document.createElement('div');
    label.className = 'section-label';
    label.innerHTML = `<span>Groups (${groups.length})</span>${addBtn}`;
    el.appendChild(label);
    if(!groups.length) {
      el.innerHTML += '<div style="padding:16px;color:var(--text3);font-size:12px;text-align:center">No groups yet</div>';
      return;
    }
    groups.forEach(g => {
      const isSelected = selectedTarget?.type === 'group' && selectedTarget?.id === g.group_id;
      const div = document.createElement('div');
      div.className = 'friend-item' + (isSelected ? ' active' : '');
      div.onclick = () => selectGroup(g.group_id);
      div.innerHTML = `
        <div class="friend-avatar">
          <div class="avatar-circle" style="background:#1a3a8f">👥</div>
        </div>
        <div class="friend-info">
          <div class="friend-name">${esc(g.name)}</div>
          <div class="friend-preview">${(g.members||[]).length} members</div>
        </div>
      `;
      el.appendChild(div);
    });
  }
}

function renderAttachment(m) {
  const f = m._file;
  const viewUrl = fileViewUrl(f.file_id);
  const downloadUrl = fileDownloadUrl(f.file_id);
  const head = `<div class="attachment-head">
    <span class="file-msg-icon">${fileIcon(f.filename)}</span>
    <span style="min-width:0;flex:1">
      <span class="attachment-name" title="${esc(f.filename)}">${esc(f.filename)}</span>
      <span class="attachment-meta">${fmt(f.size)}</span>
    </span>
    <a class="attachment-download" href="${downloadUrl}" download title="Download ${esc(f.filename)}" onclick="event.stopPropagation()">↓</a>
  </div>`;
  if(isImage(f.filename)) {
    return `<div class="attachment-card">
      <a class="attachment-preview-link" href="${viewUrl}" target="_blank" rel="noopener noreferrer">
        <img class="msg-image" src="${viewUrl}" alt="${esc(f.filename)}" loading="lazy">
      </a>${head}</div>`;
  }
  if(isAudio(f.filename, f.mime_type)) {
    return `<div class="attachment-card">${head}
      <audio class="attachment-audio" controls preload="metadata" src="${viewUrl}">Audio playback is not supported.</audio>
    </div>`;
  }
  if(isVideo(f.filename, f.mime_type)) {
    return `<div class="attachment-card">
      <video class="attachment-video" controls preload="metadata" src="${viewUrl}"></video>${head}
    </div>`;
  }
  return `<a class="file-msg-chip" href="${downloadUrl}" download title="Download ${esc(f.filename)}">
    <span class="file-msg-icon">${fileIcon(f.filename)}</span>
    <span class="file-msg-text">
      <span class="file-msg-name">${esc(f.filename)}</span>
      <span class="file-msg-size">${fmt(f.size)} · encrypted attachment</span>
    </span>
    <span class="file-msg-dl">↓</span>
  </a>`;
}

function renderMessages() {
  const el = $('messages');
  if(!selectedTarget) return;

  const msgs = [
    ...(state.messages||[]),
    ...(state.files||[]).map(fileMessage),
  ].filter(m => matchTarget(m)).sort((a,b) => (a.timestamp-b.timestamp) || String(a.msg_id).localeCompare(String(b.msg_id)));
  const loadMoreHtml = state.has_more_messages
    ? `<div class="load-more-row"><button class="load-more-btn" onclick="loadMore()" ${loadingMore?'disabled':''}>${loadingMore?'Loading…':'Load older messages'}</button></div>`
    : '';
  if(!msgs.length) {
    el.innerHTML = loadMoreHtml + '<div class="empty-state"><div class="emo">🔒</div><h3>No messages yet</h3><p>Send the first encrypted message!</p></div>';
    return;
  }

  let html = loadMoreHtml;
  let lastDate = '';
  let lastSender = '';

  msgs.forEach((m, idx) => {
    const thisDate = dateLabel(m.timestamp);
    if(thisDate !== lastDate) {
      html += `<div class="date-divider">${thisDate}</div>`;
      lastDate = thisDate;
      lastSender = '';
    }

    const isOut = m.direction === 'out';
    const sameGroup = m.sender_pubkey === lastSender && idx > 0;
    lastSender = m.sender_pubkey;

    const statusIcon = isOut ? msgStatus(m) : '';

    // Reactions HTML
    const reactMap = {};
    (m.reactions||[]).forEach(r => {
      if(!reactMap[r.emoji]) reactMap[r.emoji] = {count:0, mine:false};
      reactMap[r.emoji].count++;
      if(r.peer_pubkey === state.public_key) reactMap[r.emoji].mine = true;
    });
    const reactHtml = Object.entries(reactMap).map(([emoji, info]) =>
      `<span class="reaction-chip ${info.mine?'mine':''}" onclick="toggleReaction('${esc(m.msg_id)}','${esc(m.recipient_pubkey||m.sender_pubkey)}','${emoji}')">${emoji} ${info.count}</span>`
    ).join('');

    const bodyHtml = m._isFile ? renderAttachment(m) : `<span>${linkify(esc(m.body))}</span>`;

    // Reaction bar
    const reactionBar = m._isFile ? '' : `<div class="reaction-bar">
      ${['👍','❤️','😂','😮','😢','🔥'].map(e=>`<button class="reaction-btn" onclick="event.stopPropagation();toggleReaction('${esc(m.msg_id)}','${esc(isOut?m.recipient_pubkey:m.sender_pubkey)}','${e}')">${e}</button>`).join('')}
    </div>`;

    html += `
      <div class="msg-group ${isOut?'out':'in'}" data-msg-id="${esc(m.msg_id)}">
        <div class="msg-bubble" style="${sameGroup?'margin-top:1px':''}">
          ${reactionBar}
          ${bodyHtml}
        </div>
        ${reactHtml ? `<div class="reactions" style="padding:0 4px">${reactHtml}</div>` : ''}
        <div class="msg-meta">
          <span title="${fullTime(m.timestamp)}">${relTime(m.timestamp)}</span>
          ${statusIcon}
          ${!isOut && !m.read_at ? `<button style="background:none;border:none;color:var(--text3);cursor:pointer;font-size:10px;padding:0" onclick="markRead('${esc(m.msg_id)}','${esc(m.sender_pubkey)}')">mark read</button>` : ''}
          ${m._isFile ? '' : `<div class="msg-actions">
            <button class="msg-action-btn" title="Copy message text" onclick="copyMessage('${esc(m.msg_id)}')">⧉ Copy</button>
            <button class="msg-action-btn" title="Delete locally" onclick="deleteMessageLocally('${esc(m.msg_id)}')">🗑 Delete</button>
          </div>`}
        </div>
      </div>
    `;
  });

  el.innerHTML = html;
}

function msgStatus(m) {
  const s = m.status || '';
  if(s === 'read') return `<span class="check read" title="Read">✓✓</span>`;
  if(s === 'delivered_to_peer' || s === 'delivered') return `<span class="check delivered" title="Delivered">✓✓</span>`;
  if(s === 'sent_to_relay') return `<span class="check" title="Sent">✓</span>`;
  return `<span style="font-size:10px;color:var(--text3)" title="Sending">🕐</span>`;
}

function renderTyping() {
  const el = $('typing-indicator');
  const target = selectedTarget;
  if(!target || target.type !== 'friend') { el.innerHTML = ''; return; }
  if(typing[target.id]) {
    const f = state.friends.find(x=>x.pubkey===target.id);
    const name = f?.nickname || short(target.id);
    el.innerHTML = `<span style="color:var(--text2);font-size:12px">${esc(name)} is typing</span><div class="typing-dots"><div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div></div>`;
  } else {
    el.innerHTML = '';
  }
}

function renderSessions() {
  const el = $('sessionList');
  const entries = Object.entries(state.sessions||{});
  if(!entries.length) {
    el.innerHTML = '<span class="muted" style="font-size:12px">No sessions yet</span>';
    return;
  }
  const SESSION_TTL = 86400;
  el.innerHTML = entries.map(([peer, s]) => {
    const f = state.friends.find(x=>x.pubkey===peer);
    const name = f?.nickname || short(peer);
    const pct = Math.min(100, Math.round((s.expires_in/SESSION_TTL)*100));
    const cls = pct > 50 ? '' : pct > 20 ? 'warn' : 'danger';
    const expiresLabel = s.expires_in > 3600
      ? `${Math.floor(s.expires_in/3600)}h remaining`
      : s.expires_in > 60
      ? `${Math.floor(s.expires_in/60)}m remaining`
      : `Expired`;
    return `<div class="session-item">
      <div class="session-item-name">${esc(name)}</div>
      <div class="session-item-meta">${short(peer)}</div>
      <div class="session-age">
        <span style="font-size:10px;color:var(--text3)">${expiresLabel}</span>
        <div class="bar"><div class="fill ${cls}" style="width:${pct}%"></div></div>
      </div>
    </div>`;
  }).join('');
}

function renderFiles() {
  const el = $('fileList');
  if(!state.files.length) {
    el.innerHTML = '<span class="muted" style="font-size:12px">No files yet</span>';
    return;
  }
  el.innerHTML = state.files.slice(0,10).map(f => {
    const viewUrl = fileViewUrl(f.file_id);
    const downloadUrl = fileDownloadUrl(f.file_id);
    const direction = f.direction === 'out' ? 'Sent' : 'Received';
    return `
    <div class="file-item" style="flex-direction:column;align-items:stretch">
      <div style="display:flex;align-items:center;gap:12px">
        <div class="file-icon">${fileIcon(f.filename)}</div>
        <div class="file-info">
          <div class="file-name" title="${esc(f.filename)}">${esc(f.filename)}</div>
          <div class="file-meta">${direction} · ${fmt(f.size)} · ${relTime(f.uploaded_at)}</div>
        </div>
        <a class="file-dl" href="${downloadUrl}" download title="Download">↓</a>
      </div>
      ${isAudio(f.filename, f.mime_type) ? `<audio class="file-audio" controls preload="metadata" src="${viewUrl}"></audio>` : ''}
    </div>
  `;
  }).join('');
}

function renderStorageQuota() {
  const el = $('storageQuota');
  const used = state.storage_bytes || 0;
  const max = state.max_storage_bytes || 0;
  if(!max) {
    el.innerHTML = `<div class="quota-label"><span>${fmt(used)} used</span><span>no limit</span></div>`;
    return;
  }
  const pct = Math.min(100, Math.round((used/max)*100));
  const cls = pct < 70 ? '' : pct < 90 ? 'warn' : 'danger';
  el.innerHTML = `
    <div class="quota-row">
      <div class="quota-label"><span>${fmt(used)} used</span><span>${fmt(max)} limit</span></div>
      <div class="bar"><div class="fill ${cls}" style="width:${pct}%"></div></div>
    </div>`;
}

function renderChatHeader() {
  const el = $('chatHeader');
  if(!selectedTarget) {
    el.innerHTML = '<div style="flex:1;display:flex;align-items:center;justify-content:center;color:var(--text3);font-size:13px">← Select a friend or group to start chatting</div>';
    return;
  }
  if(selectedTarget.type === 'friend') {
    const f = state.friends.find(x=>x.pubkey===selectedTarget.id);
    const name = f?.nickname || short(selectedTarget.id);
    const online = state.online.includes(selectedTarget.id);
    const secure = !!(state.sessions&&state.sessions[selectedTarget.id]);
    const bgColor = avatarColor(selectedTarget.id);
    el.innerHTML = `
      <div class="chat-header-avatar" style="background:${bgColor}">${esc(avatarLetter(f?.nickname||selectedTarget.id))}</div>
      <div class="chat-header-info">
        <div class="chat-header-name">${esc(name)}</div>
        <div class="chat-header-sub">
          ${online?'🟢 Online':'⚫ Offline'} · ${secure?'🔒 Secure session':'🔓 No session'} · ${f?.verified?'✅ Verified':'⚠️ Unverified'} · ${f?.direct_url?'🌐 Direct-capable':'relay'}
          ${f?.fingerprint?` · Safety ${esc(f.fingerprint)}`:''}${f?.last_seen?` · Last seen ${relTime(f.last_seen)}`:''}
        </div>
      </div>
      <div class="chat-header-actions">
        ${!secure?`<button class="btn btn-primary btn-sm" onclick="connectPeer()">Connect</button>`:''}
        <button class="btn btn-secondary btn-sm" onclick="openSearchModal()" title="Search this conversation" aria-label="Search this conversation">🔍</button>
        ${secure?`<button class="btn btn-secondary btn-sm" onclick="startCall('audio')" title="Voice call" aria-label="Start voice call">📞</button>
        <button class="btn btn-secondary btn-sm" onclick="startCall('video')" title="Video call" aria-label="Start video call">🎥</button>`:''}
        <button class="btn btn-secondary btn-sm" onclick="renameFriend()" title="Edit nickname">✎ Rename</button>
        ${f?.verified?`<button class="btn btn-secondary btn-sm" onclick="verifyFriend(false)">Unverify</button>`:`<button class="btn btn-primary btn-sm" onclick="verifyFriend(true)">Verify safety</button>`}
        ${f?.blocked
          ? `<button class="btn btn-primary btn-sm" onclick="blockFriend(false)">Unblock</button>`
          : `<button class="btn btn-danger btn-sm" onclick="blockFriend(true)" title="Block this friend and drop the active session">Block</button>`}
        <button class="btn btn-secondary btn-sm" onclick="removeFriend('${esc(selectedTarget.id)}')">Remove</button>
      </div>
    `;
  } else {
    const g = state.groups.find(x=>x.group_id===selectedTarget.id);
    const name = g?.name || 'Group';
    const isOwner = g && g.owner_pubkey === state.public_key;
    el.innerHTML = `
      <div class="chat-header-avatar">👥</div>
      <div class="chat-header-info">
        <div class="chat-header-name">${esc(name)}</div>
        <div class="chat-header-sub">${(g?.members||[]).length} members · epoch ${g?.epoch??0} · ${esc(g?.fingerprint||'')}</div>
      </div>
      <div class="chat-header-actions">
        <button class="btn btn-secondary btn-sm" onclick="openSearchModal()" title="Search this conversation" aria-label="Search this conversation">🔍</button>
        ${isOwner ? `<button class="btn btn-secondary btn-sm" onclick="toggleGroupManage()">Manage members</button>
        <button class="btn btn-secondary btn-sm" onclick="rotateGroupKey('${esc(g.group_id)}')" title="Generate a fresh group key and redistribute it to current members">Rotate key</button>` : ''}
      </div>
    `;
    if($('groupManagePanel').classList.contains('open')) renderGroupManage();
  }
}

function toggleGroupManage() {
  $('groupManagePanel').classList.toggle('open');
  if($('groupManagePanel').classList.contains('open')) renderGroupManage();
}

function renderGroupManage() {
  const g = state.groups.find(x=>x.group_id===selectedTarget?.id);
  const el = $('groupManageBody');
  if(!g) { el.innerHTML = ''; return; }
  const isOwner = g.owner_pubkey === state.public_key;
  el.innerHTML = (g.members||[]).map(pubkey => {
    const f = state.friends.find(x=>x.pubkey===pubkey);
    const label = pubkey === state.public_key ? 'You' : (f?.nickname || short(pubkey));
    const role = pubkey === g.owner_pubkey ? 'owner' : 'member';
    const canRemove = isOwner && pubkey !== g.owner_pubkey;
    return `<div class="member-row">
      <span class="role-tag">${role}</span>
      <span class="mono" title="${esc(pubkey)}">${esc(label)}</span>
      ${canRemove ? `<button class="rm-btn" title="Remove from group" aria-label="Remove ${esc(label)} from group" onclick="removeGroupMember('${esc(g.group_id)}','${esc(pubkey)}')">✕</button>` : ''}
    </div>`;
  }).join('') || '<span class="muted" style="font-size:12px">No members</span>';
}

function removeGroupMember(group_id, pubkey) {
  if(!confirm('Remove this member and rotate the group key? They will lose access to future messages.')) return;
  send({type:'remove_group_member', group_id, pubkey});
}

function rotateGroupKey(group_id) {
  if(!confirm('Generate a new group key and redistribute it to current members?')) return;
  send({type:'rotate_group_key', group_id});
}

// ─── Selection ────────────────────────────────────────────────────────────────
function selectFriend(pubkey) {
  selectedTarget = {type:'friend', id:pubkey};
  delete typing[pubkey];
  renderTyping();
  renderSidebar();
  renderChatHeader();
  renderMessages();
  scrollBottom(true);
  send({type:'clear_unread', pubkey});
  updateSendBtn();
  // Request browser notification permission lazily
  if(Notification.permission === 'default') Notification.requestPermission();
}

function selectGroup(group_id) {
  selectedTarget = {type:'group', id:group_id};
  renderSidebar();
  renderChatHeader();
  renderMessages();
  scrollBottom(true);
  updateSendBtn();
}

function matchTarget(m) {
  if(!selectedTarget) return false;
  if(selectedTarget.type === 'group') return m.group_id === selectedTarget.id;
  return !m.group_id && (m.sender_pubkey === selectedTarget.id || m.recipient_pubkey === selectedTarget.id);
}

// ─── Mode ─────────────────────────────────────────────────────────────────────
function setMode(m) {
  mode = m;
  $('tabFriends').className = 'mode-tab' + (m==='friends'?' active':'');
  $('tabGroups').className  = 'mode-tab' + (m==='groups' ?' active':'');
  selectedTarget = null;
  renderSidebar();
  renderChatHeader();
  renderMessages();
  updateSendBtn();
}

// ─── Actions ──────────────────────────────────────────────────────────────────
function toggleId() {
  const k = $('myKey'), a = $('idActions');
  const show = !k.classList.contains('visible');
  k.classList.toggle('visible', show);
  a.style.display = show ? 'flex' : 'none';
}

function copyKey() {
  navigator.clipboard.writeText(state.public_key||'').then(()=>toast('Public key copied','success'));
}

function toggleAdd() {
  const p = $('addPanel');
  p.classList.toggle('open');
  if(p.classList.contains('open')) $('friendKey').focus();
}

function toggleGroup() {
  const p = $('groupPanel');
  p.classList.toggle('open');
  if(p.classList.contains('open')) $('groupName').focus();
}

function addFriend() {
  const pk = $('friendKey').value.trim(), nick = $('friendName').value.trim();
  if(!pk) return;
  send({type:'add_friend', pubkey:pk, nickname:nick||undefined});
  $('friendKey').value=''; $('friendName').value='';
  $('addPanel').classList.remove('open');
  setMode('friends');
}

function removeFriend(pubkey) {
  if(!confirm('Remove this friend and their local session?')) return;
  send({type:'remove_friend', pubkey});
  selectedTarget = null;
  renderChatHeader();
  renderMessages();
}

function connectPeer() {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  send({type:'connect', pubkey: selectedTarget.id});
}

function verifyFriend(verified) {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  const f = state.friends.find(x=>x.pubkey===selectedTarget.id);
  if(verified && !confirm(`Verify this safety fingerprint?

${f?.fingerprint||selectedTarget.id}`)) return;
  send({type:'verify_friend', pubkey:selectedTarget.id, verified});
}

function renameFriend() {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  const f = state.friends.find(x=>x.pubkey===selectedTarget.id);
  const current = f?.nickname || '';
  // prompt() is intentionally simple — it lets the user clear the nickname
  // (Cancel keeps the existing one, OK with empty input clears it).
  const newName = prompt('Nickname for this friend (leave blank to clear):', current);
  if(newName === null) return;
  send({type:'rename_friend', pubkey:selectedTarget.id, nickname:newName.trim()});
}

function blockFriend(blocked) {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  const verb = blocked ? 'block' : 'unblock';
  if(blocked && !confirm(`Block this friend? Their active session will be dropped and they won't be able to send you further messages until you unblock them.`)) return;
  if(!blocked && !confirm(`Unblock this friend? They will be able to initiate a new session handshake.`)) return;
  send({type:'block_friend', pubkey:selectedTarget.id, blocked});
}

function copyMessage(msgId) {
  const m = state.messages.find(x => x.msg_id === msgId);
  if(!m || !m.body) return;
  // Use the Clipboard API with a textarea fallback for older browsers.
  if(navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(m.body).then(() => toast('Message copied', 'success'));
  } else {
    const ta = document.createElement('textarea');
    ta.value = m.body; document.body.appendChild(ta); ta.select();
    try { document.execCommand('copy'); toast('Message copied', 'success'); }
    catch(_) { toast('Copy failed', 'error'); }
    document.body.removeChild(ta);
  }
}

function deleteMessageLocally(msgId) {
  if(!confirm('Delete this message locally? This only removes it from your view — the sender and any other devices still have it.')) return;
  state.messages = state.messages.filter(m => m.msg_id !== msgId);
  renderMessages();
  toast('Message removed from this device', 'info');
}

// ─── Message search ───────────────────────────────────────────────────────────
function openSearchModal() {
  if(!selectedTarget) { toast('Select a friend or group first', 'warning'); return; }
  const label = selectedTarget.type === 'friend'
    ? (state.friends.find(f=>f.pubkey===selectedTarget.id)?.nickname || short(selectedTarget.id))
    : (state.groups.find(g=>g.group_id===selectedTarget.id)?.name || 'this group');
  $('searchScopeHint').textContent = `Searching your conversation with ${label}.`;
  $('searchResults').innerHTML = '';
  $('searchInput').value = '';
  $('searchModal').classList.add('open');
  setTimeout(() => $('searchInput').focus(), 50);
}
function closeSearchModal() {
  $('searchModal').classList.remove('open');
}
function debounceSearch() {
  clearTimeout(searchDebounceTimer);
  searchDebounceTimer = setTimeout(runSearch, 300);
}
function runSearch() {
  const query = $('searchInput').value.trim();
  if(!query || !selectedTarget) { $('searchResults').innerHTML = ''; return; }
  const payload = {type:'search_messages', query};
  if(selectedTarget.type === 'group') payload.group_id = selectedTarget.id;
  else payload.pubkey = selectedTarget.id;
  send(payload);
}
function renderSearchResults(query, results) {
  const el = $('searchResults');
  if(!results.length) {
    el.innerHTML = `<div class="search-empty">No messages match "${esc(query)}"</div>`;
    return;
  }
  el.innerHTML = results.map(m => {
    const snippet = m.body.length > 160 ? m.body.slice(0, 160) + '…' : m.body;
    const who = m.direction === 'out' ? 'You' : short(m.sender_pubkey);
    return `<button class="search-result-item" onclick="jumpToMessage('${esc(m.msg_id)}')">
      <div class="search-result-meta">${esc(who)} · ${relTime(m.timestamp)}</div>
      ${esc(snippet)}
    </button>`;
  }).join('');
}
function jumpToMessage(msgId) {
  closeSearchModal();
  const node = document.querySelector(`[data-msg-id="${CSS.escape(msgId)}"]`);
  if(!node) {
    toast("That message isn't loaded yet — try 'Load older messages' first", 'info');
    return;
  }
  node.scrollIntoView({behavior:'smooth', block:'center'});
  node.classList.add('flash');
  setTimeout(() => node.classList.remove('flash'), 1600);
}

// ─── Voice/video calls ─────────────────────────────────────────────────────────
// Call *signaling* (offer/answer/ICE) is relayed over the same PQ-authenticated
// channel as everything else in this app. The media stream itself is standard
// WebRTC (DTLS-SRTP), negotiated directly browser-to-browser — that leg is not
// post-quantum, since no mainstream browser offers one yet.
function friendName(pubkey) {
  return state.friends.find(f=>f.pubkey===pubkey)?.nickname || short(pubkey);
}

async function startCall(media) {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  if(currentCall) { toast('Already in a call', 'warning'); return; }
  if(!navigator.mediaDevices?.getUserMedia || !window.RTCPeerConnection) {
    toast('Calls are not supported in this browser', 'error');
    return;
  }
  const peer = selectedTarget.id;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video: media==='video'});
  } catch(err) {
    toast(`Couldn't access ${media==='video'?'camera/microphone':'microphone'}: ${err.message}`, 'error');
    return;
  }
  currentCall = {peer, call_id:null, role:'caller', media, state:'ringing'};
  setupPeerConnection(peer, media);
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
  try {
    const offer = await pc.createOffer();
    await pc.setLocalDescription(offer);
    send({type:'call_offer', pubkey: peer, sdp: pc.localDescription, media});
    showCallOverlay(peer, media, 'Calling…');
  } catch(err) {
    toast(`Couldn't start the call: ${err.message}`, 'error');
    cleanupCall();
  }
}

function setupPeerConnection(peer, media) {
  pc = new RTCPeerConnection({iceServers: state.ice_servers || [{urls:'stun:stun.l.google.com:19302'}]});
  pc.onicecandidate = e => {
    if(e.candidate && currentCall) send({type:'call_ice', pubkey: peer, candidate: e.candidate.toJSON()});
  };
  pc.ontrack = e => {
    const remote = $('remoteVideo');
    if(remote.srcObject !== e.streams[0]) remote.srcObject = e.streams[0];
  };
  pc.onconnectionstatechange = () => {
    if(pc && (pc.connectionState === 'failed' || pc.connectionState === 'disconnected')) {
      toast('Call connection lost', 'warning');
    }
  };
  $('localVideo').srcObject = localStream;
  $('localVideo').style.display = media === 'video' ? '' : 'none';
  $('remoteVideo').style.display = media === 'video' ? '' : 'none';
}

function showCallOverlay(peer, media, status) {
  $('callOverlayName').textContent = friendName(peer);
  $('callOverlayStatus').textContent = status;
  $('callOverlayAvatar').textContent = media === 'video' ? '🎥' : '📞';
  $('callOverlay').hidden = false;
  $('callMuteBtn').classList.remove('call-btn-muted');
  $('callCameraBtn').textContent = '🎥';
}

function handleCallIncoming(d) {
  if(currentCall) {
    // Already busy — mirror the server-side busy handling for defense in depth.
    send({type:'call_end', pubkey: d.peer, reason:'busy'});
    return;
  }
  currentCall = {peer:d.peer, call_id:d.call_id, role:'callee', media:d.media, state:'ringing', offerSdp:d.sdp};
  $('incomingCallAvatar').textContent = d.media === 'video' ? '🎥' : '📞';
  $('incomingCallSub').textContent = `${friendName(d.peer)} is ${d.media === 'video' ? 'video ' : ''}calling…`;
  $('incomingCallModal').classList.add('open');
  playRingtone();
}

async function acceptCall() {
  $('incomingCallModal').classList.remove('open');
  if(!currentCall || currentCall.role !== 'callee') return;
  if(!navigator.mediaDevices?.getUserMedia || !window.RTCPeerConnection) {
    toast('Calls are not supported in this browser', 'error');
    send({type:'call_end', pubkey: currentCall.peer, reason:'no-media'});
    currentCall = null;
    return;
  }
  const {peer, media, offerSdp} = currentCall;
  try {
    localStream = await navigator.mediaDevices.getUserMedia({audio:true, video: media==='video'});
  } catch(err) {
    toast(`Couldn't access ${media==='video'?'camera/microphone':'microphone'}: ${err.message}`, 'error');
    send({type:'call_end', pubkey: peer, reason:'no-media'});
    currentCall = null;
    return;
  }
  setupPeerConnection(peer, media);
  localStream.getTracks().forEach(t => pc.addTrack(t, localStream));
  try {
    await pc.setRemoteDescription(offerSdp);
    await flushIceQueue();
    const answer = await pc.createAnswer();
    await pc.setLocalDescription(answer);
    send({type:'call_answer', pubkey: peer, sdp: pc.localDescription});
    currentCall.state = 'active';
    showCallOverlay(peer, media, 'Connected');
  } catch(err) {
    toast(`Couldn't answer the call: ${err.message}`, 'error');
    cleanupCall();
  }
}

function declineCall() {
  $('incomingCallModal').classList.remove('open');
  if(currentCall) send({type:'call_end', pubkey: currentCall.peer, reason:'declined'});
  currentCall = null;
}

async function handleCallAnswered(d) {
  if(!currentCall || currentCall.peer !== d.peer || !pc) return;
  try {
    await pc.setRemoteDescription(d.sdp);
    await flushIceQueue();
    currentCall.state = 'active';
    $('callOverlayStatus').textContent = 'Connected';
  } catch(err) {
    toast(`Call setup failed: ${err.message}`, 'error');
    cleanupCall();
  }
}

async function handleCallIceCandidate(d) {
  if(!currentCall || currentCall.peer !== d.peer || !d.candidate) return;
  if(pc && pc.remoteDescription) {
    try { await pc.addIceCandidate(d.candidate); } catch(_) {}
  } else {
    pendingIceQueue.push(d.candidate);
  }
}

async function flushIceQueue() {
  while(pendingIceQueue.length && pc) {
    const c = pendingIceQueue.shift();
    try { await pc.addIceCandidate(c); } catch(_) {}
  }
}

function handleCallStateEvent(d) {
  if(!currentCall || currentCall.peer !== d.peer) return;
  if(d.state === 'ringing' && currentCall.role === 'caller') {
    $('callOverlayStatus').textContent = 'Ringing…';
  } else if(d.state === 'active') {
    currentCall.state = 'active';
    $('callOverlayStatus').textContent = 'Connected';
  } else if(d.state === 'ended') {
    const reasonText = {busy:'They were on another call', declined:'Call declined', hangup:'Call ended', 'no-media':'They could not join'}[d.reason] || 'Call ended';
    toast(reasonText, 'info');
    cleanupCall();
  }
}

function hangupCall() {
  if(currentCall) send({type:'call_end', pubkey: currentCall.peer, reason:'hangup'});
  cleanupCall();
}

function cleanupCall() {
  if(pc) { try { pc.close(); } catch(_) {} pc = null; }
  if(localStream) { localStream.getTracks().forEach(t => t.stop()); localStream = null; }
  currentCall = null;
  pendingIceQueue = [];
  $('callOverlay').hidden = true;
  $('incomingCallModal').classList.remove('open');
  const rv = $('remoteVideo'), lv = $('localVideo');
  if(rv) rv.srcObject = null;
  if(lv) lv.srcObject = null;
  stopRingtone();
}

function toggleCallMute() {
  if(!localStream) return;
  const track = localStream.getAudioTracks()[0];
  if(!track) return;
  track.enabled = !track.enabled;
  $('callMuteBtn').classList.toggle('call-btn-muted', !track.enabled);
  $('callMuteBtn').setAttribute('aria-label', track.enabled ? 'Mute microphone' : 'Unmute microphone');
}

function toggleCallCamera() {
  if(!localStream) return;
  const track = localStream.getVideoTracks()[0];
  if(!track) return;
  track.enabled = !track.enabled;
  $('callCameraBtn').classList.toggle('call-btn-muted', !track.enabled);
  $('callCameraBtn').textContent = track.enabled ? '🎥' : '🚫';
  $('callCameraBtn').setAttribute('aria-label', track.enabled ? 'Turn camera off' : 'Turn camera on');
}

let ringtoneOsc = null;
function playRingtone() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const osc = ctx.createOscillator();
    const gain = ctx.createGain();
    osc.frequency.value = 440;
    gain.gain.value = 0.05;
    osc.connect(gain).connect(ctx.destination);
    osc.start();
    ringtoneOsc = {ctx, osc};
    setTimeout(stopRingtone, 20000);  // stop on its own if never answered/declined
  } catch(_) {}
}
function stopRingtone() {
  if(ringtoneOsc) { try { ringtoneOsc.osc.stop(); ringtoneOsc.ctx.close(); } catch(_) {} ringtoneOsc = null; }
}

function sendMessage() {
  const text = $('text').value.trim();
  if(!text || !selectedTarget) return;
  if(selectedTarget.type === 'group') {
    send({type:'send_message', group_id:selectedTarget.id, text});
  } else {
    send({type:'send_message', pubkey:selectedTarget.id, text});
  }
  $('text').value = '';
  onTextInput();
  stopTyping();
}

function sendFile() {
  const f = $('fileInput').files[0];
  if(!f) return;
  sendFileBlob(f, f.name, snapshotTarget());
  $('fileInput').value = '';
}

function targetCanReceiveFiles(target) {
  if(!target) { toast('Select a friend or group first', 'warning'); return false; }
  if(target.type === 'friend' && !state.sessions?.[target.id]) {
    toast('Connect this friend securely before sending a file', 'warning');
    return false;
  }
  return true;
}

function setTransferStatus(text, percent=null) {
  $('transferStatus').innerHTML = text ? `<span>${esc(text)}</span>${percent === null ? '' :
    `<span class="progress-track"><span class="progress-fill" style="display:block;width:${Math.max(0,Math.min(100,percent))}%"></span></span>`}` : '';
}

function finishUpload() {
  uploadInProgress = false;
  pendingUploadName = '';
  $('attachBtn').classList.remove('busy');
  setTransferStatus('');
}

function sendFileBlob(blob, filename, target=snapshotTarget()) {
  if(!targetCanReceiveFiles(target)) return;
  if(uploadInProgress) { toast('Wait for the current attachment to finish', 'warning'); return; }
  if(blob.size > MAX_FILE_BYTES_UI) { toast('File exceeds 512 MB limit','error'); return; }
  const available = state.max_storage_bytes > 0 ? state.max_storage_bytes - (state.storage_bytes||0) : Infinity;
  if(blob.size > available) { toast('This file exceeds the remaining local storage quota', 'error'); return; }
  uploadInProgress = true;
  pendingUploadName = filename;
  $('attachBtn').classList.add('busy');
  setTransferStatus(`Preparing ${filename}`, 0);
  const r = new FileReader();
  r.onprogress = e => {
    if(e.lengthComputable) setTransferStatus(`Preparing ${filename}`, Math.round(e.loaded/e.total*100));
  };
  r.onerror = () => { finishUpload(); toast('Could not read that file', 'error'); };
  r.onload = () => {
    const data = r.result.split(',')[1];
    setTransferStatus(`Encrypting and sending ${filename}`);
    let sent;
    if(target.type === 'group') {
      sent = send({type:'send_file', group_id:target.id, filename, content_type:blob.type, data});
    } else {
      sent = send({type:'send_file', pubkey:target.id, filename, content_type:blob.type, data});
    }
    if(!sent) finishUpload();
  };
  r.readAsDataURL(blob);
}

// ─── Voice messages ─────────────────────────────────────────────────────────
async function toggleVoiceRecording() {
  if(mediaRecorder && mediaRecorder.state === 'recording') {
    stopVoiceRecording(false);
    return;
  }
  const target = snapshotTarget();
  if(!targetCanReceiveFiles(target)) return;
  if(uploadInProgress) { toast('Wait for the current attachment to finish', 'warning'); return; }
  if(!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
    toast('Voice recording is not supported in this browser', 'error'); return;
  }
  try {
    const stream = await navigator.mediaDevices.getUserMedia({audio: true});
    recordedChunks = [];
    recordingTarget = target;
    discardRecording = false;
    const preferred = ['audio/webm;codecs=opus', 'audio/ogg;codecs=opus', 'audio/mp4'];
    const mimeType = preferred.find(t => MediaRecorder.isTypeSupported?.(t));
    mediaRecorder = new MediaRecorder(stream, mimeType ? {mimeType} : undefined);
    mediaRecorder.ondataavailable = e => { if(e.data.size > 0) recordedChunks.push(e.data); };
    mediaRecorder.onerror = () => {
      discardRecording = true;
      stream.getTracks().forEach(t => t.stop());
      toast('Voice recording failed', 'error');
    };
    mediaRecorder.onstop = () => {
      stream.getTracks().forEach(t => t.stop());
      clearInterval(recordTimer);
      $('recIndicator').innerHTML = '';
      $('micBtn').classList.remove('recording');
      const blob = new Blob(recordedChunks, {type: mediaRecorder.mimeType || 'audio/webm'});
      const kind = mediaRecorder.mimeType || 'audio/webm';
      const ext = kind.includes('ogg') ? 'ogg' : kind.includes('mp4') ? 'm4a' : 'webm';
      if(!discardRecording && blob.size > 0) {
        sendFileBlob(blob, `voice-message-${Date.now()}.${ext}`, recordingTarget);
      } else if(!discardRecording) {
        toast('No audio was captured', 'warning');
      }
      mediaRecorder = null;
      recordingTarget = null;
    };
    mediaRecorder.start(1000);
    recordStart = Date.now();
    $('micBtn').classList.add('recording');
    recordTimer = setInterval(() => {
      const secs = Math.floor((Date.now()-recordStart)/1000);
      $('recIndicator').innerHTML = `<div class="rec-indicator"><span class="dot"></span>Recording ${String(Math.floor(secs/60)).padStart(1,'0')}:${String(secs%60).padStart(2,'0')}
        <button class="rec-cancel" onclick="stopVoiceRecording(true)">Cancel</button></div>`;
      if(secs >= 300) {
        toast('Five-minute recording limit reached', 'info');
        stopVoiceRecording(false);
      }
    }, 200);
  } catch(err) {
    toast('Microphone access denied or unavailable', 'error');
  }
}

function stopVoiceRecording(discard=false) {
  if(!mediaRecorder || mediaRecorder.state !== 'recording') return;
  discardRecording = discard;
  mediaRecorder.stop();
}

// ─── Identity backup / restore ──────────────────────────────────────────────
function openBackupModal() {
  $('backupModal').classList.add('open');
}
function closeBackupModal() {
  $('backupModal').classList.remove('open');
}
function setBackupTab(tab) {
  $('backupTabExport').classList.toggle('active', tab==='export');
  $('backupTabImport').classList.toggle('active', tab==='import');
  $('backupExportPane').style.display = tab==='export' ? '' : 'none';
  $('backupImportPane').style.display = tab==='import' ? '' : 'none';
}
function exportBackup() {
  const passphrase = $('backupExportPass').value;
  if(passphrase.length < 8) { toast('Passphrase must be at least 8 characters', 'error'); return; }
  send({type:'export_backup', passphrase});
}
function copyBackupResult() {
  const el = $('backupExportResult');
  if(!el.value) { toast('Generate a backup first', 'warning'); return; }
  el.select();
  navigator.clipboard?.writeText(el.value).then(() => toast('Backup copied to clipboard', 'success'))
    .catch(() => document.execCommand('copy'));
}
function importBackup() {
  const backup = $('backupImportBlob').value.trim();
  const passphrase = $('backupImportPass').value;
  if(!backup || !passphrase) { toast('Paste a backup and enter its passphrase', 'error'); return; }
  if(!confirm('This replaces your current identity in place. Only do this on a brand-new install with no friends or history yet. Continue?')) return;
  send({type:'import_backup', backup, passphrase});
  closeBackupModal();
}

function createGroup() {
  const name = $('groupName').value.trim();
  const raw = $('groupMembers').value.trim();
  const members = raw ? raw.split(',').map(s=>s.trim()).filter(Boolean)
    : (selectedTarget?.type==='friend' ? [selectedTarget.id] : []);
  send({type:'create_group', name, members});
  $('groupName').value=''; $('groupMembers').value='';
  $('groupPanel').classList.remove('open');
  setMode('groups');
}

function markRead(msg_id, peer_pubkey) {
  send({type:'read_receipt', pubkey:peer_pubkey, msg_id});
}

function loadMore() {
  if(loadingMore || !state.messages.length) return;
  loadingMore = true;
  renderMessages();
  send({type:'load_more_messages', before_id: state.messages[0].id});
}

function toggleReaction(msg_id, peer_pubkey, emoji) {
  if(!peer_pubkey || peer_pubkey === state.public_key) return;
  const m = state.messages.find(x=>x.msg_id===msg_id);
  if(!m) return;
  const existing = (m.reactions||[]).find(r=>r.peer_pubkey===state.public_key&&r.emoji===emoji);
  const action = existing ? 'remove' : 'add';
  send({type:'reaction', pubkey:peer_pubkey, msg_id, emoji, action});
}

// ─── Typing ───────────────────────────────────────────────────────────────────
function startTyping() {
  if(!selectedTarget || selectedTarget.type !== 'friend') return;
  if(!myTypingActive) {
    myTypingActive = true;
    send({type:'typing', pubkey:selectedTarget.id, active:true});
  }
  clearTimeout(myTypingTimeout);
  myTypingTimeout = setTimeout(stopTyping, 3000);
}

function stopTyping() {
  if(myTypingActive && selectedTarget?.type==='friend') {
    myTypingActive = false;
    send({type:'typing', pubkey:selectedTarget.id, active:false});
  }
  clearTimeout(myTypingTimeout);
}

function onTextInput() {
  const v = $('text').value;
  const bytes = new TextEncoder().encode(v).length;
  $('charHint').textContent = `${bytes.toLocaleString()} / 65,536`;
  updateSendBtn();
  autoResize($('text'));
  if(v.trim()) startTyping(); else stopTyping();
}

function onTextKey(e) {
  if(e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
}

function autoResize(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.min(ta.scrollHeight, 120) + 'px';
}

function updateSendBtn() {
  const hasText = !!$('text').value.trim();
  const hasTarget = !!selectedTarget;
  $('sendBtn').disabled = !(hasText && hasTarget);
}

// ─── Scroll ───────────────────────────────────────────────────────────────────
function scrollBottom(instant) {
  const el = $('messages');
  if(instant) el.scrollTop = el.scrollHeight;
  else setTimeout(() => el.scrollTop = el.scrollHeight, 50);
}

// ─── Unread ───────────────────────────────────────────────────────────────────
function bumpUnread(pubkey) {
  unreadTitle++;
  updateTitle();
}

function updateTitle() {
  document.title = unreadTitle > 0 ? `(${unreadTitle}) ⚛ Quantum Chat` : '⚛ Quantum Chat';
}

// ─── Notifications ────────────────────────────────────────────────────────────
function notify(title, body) {
  if(Notification.permission === 'granted') {
    try {
      new Notification(`⚛ ${title}`, {body: body.slice(0,120), icon: ''});
    } catch(_) {}
  }
}

// ─── Toast ────────────────────────────────────────────────────────────────────
function toast(text, level='info') {
  const icons = {info:'ℹ️', success:'✅', error:'❌', warning:'⚠️'};
  const div = document.createElement('div');
  div.className = `toast ${level}`;
  div.innerHTML = `<span class="toast-icon">${icons[level]||'ℹ️'}</span><span>${esc(text)}</span>`;
  $('toasts').appendChild(div);
  setTimeout(() => div.remove(), 4500);
}

// ─── Drag & Drop ─────────────────────────────────────────────────────────────
const mainEl = $('main');
mainEl.addEventListener('dragover', e => {
  e.preventDefault();
  if(selectedTarget) $('dropOverlay').classList.add('active');
});
mainEl.addEventListener('dragleave', e => {
  if(!mainEl.contains(e.relatedTarget)) $('dropOverlay').classList.remove('active');
});
mainEl.addEventListener('drop', e => {
  e.preventDefault();
  $('dropOverlay').classList.remove('active');
  const target = snapshotTarget();
  if(!target) { toast('Select a contact first', 'warning'); return; }
  const file = e.dataTransfer.files[0];
  if(!file) return;
  sendFileBlob(file, file.name, target);
});

// Focus on window return — clear title unread
window.addEventListener('focus', () => {
  unreadTitle = 0;
  updateTitle();
});

wsConnect();
</script>
</body>
</html>
"""


# ─── Entry point ──────────────────────────────────────────────────────────────

def start_http(node: QuantumNode, host: str, port: int,
               ui_ws_port: int = UI_WS_PORT, require_http_auth: bool = False) -> ThreadedHTTPServer:
    ChatHTTPHandler.node = node
    ChatHTTPHandler.ui_ws_port = ui_ws_port
    ChatHTTPHandler.require_http_auth = require_http_auth
    httpd = ThreadedHTTPServer((host, port), ChatHTTPHandler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd


async def start_ui_ws(node: QuantumNode, host: str, port: int) -> None:
    websockets = require_websockets()
    async with websockets.serve(node.handle_ui, host, port, max_size=MAX_FILE_BYTES * 2):
        await asyncio.Future()


async def start_direct_peer(node: QuantumNode, host: str, port: int) -> None:
    websockets = require_websockets()
    async with websockets.serve(node.handle_direct_peer, host, port, max_size=MAX_FILE_BYTES * 2):
        LOG.info("Direct peer listener on ws://%s:%d", host, port)
        await asyncio.Future()


async def start_signaling(host: str, port: int) -> None:
    websockets = require_websockets()
    server = SignalingServer()
    async with websockets.serve(server.handle, host, port, max_size=MAX_FILE_BYTES * 2):
        LOG.info("Signaling server listening on ws://%s:%d", host, port)
        print(f"Signaling server listening on ws://{host}:{port}")
        await asyncio.Future()


def _is_local_host(host: str) -> bool:
    return host in {"127.0.0.1", "localhost", "::1"}


async def _cleanup_runtime_tasks(tasks: List[Any]) -> None:
    pending: List[asyncio.Task[Any]] = []
    for task in tasks:
        if isinstance(task, asyncio.Task):
            if not task.done():
                task.cancel()
                pending.append(task)
        elif inspect.iscoroutine(task):
            task.close()
    if pending:
        await asyncio.wait(pending)


async def run_node(args: argparse.Namespace) -> None:
    if (not _is_local_host(args.http_host) or not _is_local_host(args.ui_ws_host)) and not args.allow_remote_ui:
        raise SystemExit("Refusing to expose the UI on a non-local interface without --allow-remote-ui")
    if args.ice_servers:
        try:
            json.loads(args.ice_servers)  # validate before handing it to the node
        except json.JSONDecodeError as exc:
            raise SystemExit(f"--ice-servers is not valid JSON: {exc}")
        os.environ["QUANTUM_CHAT_ICE_SERVERS"] = args.ice_servers
    direct_url = None
    if args.enable_direct:
        advertised_host = args.direct_advertise_host or args.direct_host
        direct_url = f"ws://{advertised_host}:{args.direct_port}"
    node = QuantumNode(args.db, args.signaling_url, direct_url=direct_url, enable_direct=args.enable_direct,
                      max_storage_bytes=args.max_storage_mb * 1024 * 1024)
    node.allow_remote_ui = args.allow_remote_ui
    ui_url = f"http://{args.http_host}:{args.http_port}"
    if args.allow_remote_ui:
        ui_url = f"{ui_url}?token={quote(node.ui_token)}"
    httpd = start_http(node, args.http_host, args.http_port, args.ui_ws_port,
                       require_http_auth=args.allow_remote_ui)
    LOG.info("%s v%s — identity: %s", APP_NAME, VERSION, node.public_key)
    print(f"{APP_NAME} v{VERSION}")
    print(f"Identity:  {node.public_key}")
    print(f"Fingerprint: {key_fingerprint(node.public_key)}")
    print(f"UI:        {ui_url}")
    print(f"Health:    http://{args.http_host}:{args.http_port}/health")
    print("Press Ctrl+C to shut down cleanly.")
    if args.open_browser:
        try:
            webbrowser.open(ui_url)
        except Exception:
            pass  # headless or no default browser — not fatal
    tasks = [
        asyncio.create_task(start_ui_ws(node, args.ui_ws_host, args.ui_ws_port)),
        asyncio.create_task(node.connect_signaling_loop()),
    ]
    if args.enable_direct:
        tasks.append(asyncio.create_task(start_direct_peer(node, args.direct_host, args.direct_port)))
    if args.with_signaling:
        tasks.append(asyncio.create_task(start_signaling(args.signaling_host, args.signaling_port)))

    # Install SIGINT/SIGTERM handlers so Ctrl+C and `kill <pid>` shut the
    # node down cleanly: set the cooperative shutdown flag, cancel the
    # long-lived tasks, and let the finally block close the DB. Without
    # this, KeyboardInterrupt prints an ugly traceback and leaves WAL
    # files in an un-checkpointed state.
    loop = asyncio.get_running_loop()
    stop_event = asyncio.Event()

    def _request_stop() -> None:
        if not stop_event.is_set():
            LOG.info("Shutdown requested — stopping tasks and closing database…")
            node._shutting_down = True
            stop_event.set()
            # Cancel any long-lived tasks so gather() unblocks promptly.
            for task in tasks:
                if isinstance(task, asyncio.Task) and not task.done():
                    task.cancel()

    for sig in ("SIGINT", "SIGTERM"):
        try:
            loop.add_signal_handler(getattr(__import__("signal"), sig), _request_stop)
        except (NotImplementedError, RuntimeError):
            # add_signal_handler isn't available on Windows or when not in
            # the main thread; fall back to KeyboardInterrupt on Ctrl+C.
            pass

    try:
        # Race the long-lived task gather against the stop event so a
        # signal can interrupt the otherwise-blocking gather. Using gather
        # alone would let a single Ctrl+C turn into a noisy traceback.
        gather_task = asyncio.ensure_future(asyncio.gather(*tasks))
        stop_task = asyncio.ensure_future(stop_event.wait())
        done, pending = await asyncio.wait({gather_task, stop_task},
                                           return_when=asyncio.FIRST_COMPLETED)
        # If gather completed (e.g. one task errored), surface its exception.
        for d in done:
            if d is gather_task and not d.cancelled():
                exc = d.exception()
                if exc:
                    raise exc
    except (KeyboardInterrupt, asyncio.CancelledError):
        _request_stop()
    finally:
        # Cancel the stop helper if it's still pending (signal didn't fire).
        if 'stop_task' in locals() and not stop_task.done():
            stop_task.cancel()
        await _cleanup_runtime_tasks(tasks)
        try:
            httpd.shutdown()
        except Exception:
            pass
        try:
            node.db.close()
        except Exception:
            pass
        # Also close the signaling server's relay DB if we started one.
        try:
            relay_db = getattr(getattr(node, "signaling_ws", None), "relay_db", None)
            if relay_db:
                relay_db.close()
        except Exception:
            pass
        print("Goodbye.")


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=f"Quantum Chat v{VERSION} — post-quantum P2P encrypted chat"
    )
    sub = parser.add_subparsers(dest="command")
    signal_cmd = sub.add_parser("signal", help="run only the signaling/relay server")
    signal_cmd.add_argument("--host", default=SIGNALING_HOST)
    signal_cmd.add_argument("--port", type=int, default=SIGNALING_PORT)

    parser.add_argument("--db", default=DB_FILE)
    parser.add_argument("--signaling-url", default=DEFAULT_SIGNALING_URL)
    parser.add_argument("--with-signaling", action="store_true",
                        help="also start a local signaling server")
    parser.add_argument("--signaling-host", default=SIGNALING_HOST)
    parser.add_argument("--signaling-port", type=int, default=SIGNALING_PORT)
    parser.add_argument("--http-host", default=HTTP_HOST)
    parser.add_argument("--http-port", type=int, default=HTTP_PORT)
    parser.add_argument("--ui-ws-host", default=UI_WS_HOST)
    parser.add_argument("--ui-ws-port", type=int, default=UI_WS_PORT)
    parser.add_argument("--allow-remote-ui", action="store_true",
                        help="allow binding HTTP/UI WebSocket to non-local interfaces and require token auth for non-root HTTP routes")
    parser.add_argument("--enable-direct", action="store_true", default=True,
                        help="enable direct peer WebSocket listener and direct delivery fallback")
    parser.add_argument("--no-direct", dest="enable_direct", action="store_false")
    parser.add_argument("--direct-host", default=DIRECT_PEER_HOST)
    parser.add_argument("--direct-port", type=int, default=DIRECT_PEER_PORT)
    parser.add_argument("--direct-advertise-host", default=None,
                        help="host/IP peers should use to reach this node's direct listener")
    parser.add_argument("--no-browser", dest="open_browser", action="store_false")
    parser.add_argument(
        "--max-storage-mb", type=int, default=DEFAULT_MAX_STORAGE_MB,
        help=f"disk quota in MB for received/sent file bytes, 0 disables enforcement (default: {DEFAULT_MAX_STORAGE_MB})"
    )
    parser.add_argument(
        "--ice-servers", default=None,
        help="JSON list of WebRTC ICE servers for voice/video calls, e.g. "
             '\'[{"urls":"stun:stun.l.google.com:19302"},'
             '{"urls":"turn:turn.example.com:3478","username":"u","credential":"p"}]\'. '
             "Defaults to a public STUN-only server, or $QUANTUM_CHAT_ICE_SERVERS if set. "
             "STUN alone won't traverse every NAT; add a TURN server for reliable connectivity."
    )
    parser.add_argument(
        "--log-level",
        default="WARNING",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="logging verbosity (default: WARNING)"
    )
    parser.set_defaults(open_browser=True)
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> None:
    args = parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level, logging.WARNING),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
    if args.command == "signal":
        asyncio.run(start_signaling(args.host, args.port))
    else:
        asyncio.run(run_node(args))


if __name__ == "__main__":
    main()
