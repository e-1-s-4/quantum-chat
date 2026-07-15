# Quantum Chat

**v3.1.0** — a single-file, browser-based, post-quantum end-to-end encrypted peer-to-peer chat application.

Quantum Chat ships a local dark-mode web UI, a local UI WebSocket API, an optional WebSocket signaling/relay server, SQLite persistence, encrypted file transfer, friend management, small group fan-out, typing indicators, read receipts, emoji reactions, unread counts, voice messages, identity backup/restore, a configurable storage quota, and JSON health/version endpoints — all in one Python file.

> **Security note:** this project uses post-quantum primitives through `pqcrypto`, but it has **not** been independently audited. Treat it as hardened experimental application code, not a certified secure messenger. Remote production deployments still need an external security review, TLS termination, operational monitoring, and a clear key-backup plan.

---

## Table of contents

- [What's new in v3.1.0](#whats-new-in-v310)
- [Features](#features)
- [Requirements](#requirements)
- [Quick start on one machine](#quick-start-on-one-machine)
- [Multi-machine setup](#multi-machine-setup)
- [Browser UI](#browser-ui)
- [HTTP endpoints](#http-endpoints)
- [How it works](#how-it-works)
- [Persistence and at-rest encryption](#persistence-and-at-rest-encryption)
- [Passphrase KDF migration](#passphrase-kdf-migration)
- [Multi-device support](#multi-device-support)
- [Command reference](#command-reference)
- [Environment variables](#environment-variables)
- [Project structure](#project-structure)
- [Threat model and current limits](#threat-model-and-current-limits)
- [Testing](#testing)
- [Packaging and development](#packaging-and-development)
- [Historical changelog](#historical-changelog)
- [License](#license)

---

## What's new in v3.1.0

v3.1.0 is a security and correctness release. It fixes three bugs found through end-to-end testing, adds several missing UI features, hardens the HTTP surface, and introduces graceful shutdown. The full test suite grew from 19 unit tests to **30 unit tests + 13 live HTTP smoke tests + 15 end-to-end protocol tests**, all passing.

### Critical fixes

If you're upgrading from v3.0.0, these affect core security and correctness:

- **Fixed: signature verification silently accepted every signature.** `pqcrypto` 0.4+ returns `True`/`False` from `verify()` rather than raising on mismatch, but the `PQModule.verify` wrapper unconditionally returned `True` after the call. This meant **every signed payload** — session offers, accepts, group invites, read receipts, reactions, file manifests, delivery acks, direct-peer hellos — was treated as valid regardless of whether the signature actually matched. The wrapper now inspects the return value and properly returns `False` on mismatch. A regression test (`test_pqmodule_verify_rejects_wrong_message_and_wrong_signature`) pins this behavior going forward.
- **Fixed: delivery acknowledgements never updated the sender's message status.** `send_chat` saved the outgoing message *after* `send_relay` returned, but with direct transport `send_relay` blocks until the peer processes the message and returns a `delivery_ack`. The ack's `update_message_status` call therefore ran before the message existed in the DB, matched zero rows, and the subsequent `INSERT` with `status='sent_to_relay'` overwrote the (never-applied) `delivered_to_peer` update. The save now happens *before* `send_relay`. The same pattern was fixed in `send_group_chat`. A regression test (`test_send_chat_saves_message_before_send_relay`) pins the order.
- **Fixed: read receipts never stamped the sender's `read_at` column.** `handle_read_receipt` called `update_message_status(msg_id, "read")` but that only updates `status` and `delivered` — not `read_at`. The UI's "✓✓ read" indicator therefore never lit up for the sender, even after the recipient had actually read the message. A new `mark_remote_read` DB method stamps `read_at` using the receipt's own timestamp (so the column reflects when the *reader* read it, not when we happened to process the receipt). A regression test (`test_mark_remote_read_sets_read_at_on_outgoing_message`) pins the behavior.
- **Fixed: broken inline image previews.** The UI rendered `<img src="${m._imgSrc}">` for image messages but `_imgSrc` was never populated anywhere, so images never appeared inline. File transfers now also push a synthetic message into the chat timeline with the file URL set, so images preview inline and non-image files render as a clickable download chip.
- **Fixed: deprecated `asyncio.get_event_loop()`** in the typing-indicator clear timer. Replaced with `asyncio.get_running_loop()` so the timer still works on Python 3.12+ where `get_event_loop()` is deprecated inside a running loop.

### New features

- **Friend nickname editing:** a ✎ Rename button in the chat header lets you change (or clear) a friend's nickname at any time. The new `rename_friend` DB method validates the label and rejects too-long or missing-friend renames.
- **Block / unblock UI:** the chat header now exposes Block / Unblock buttons. Blocking a friend also drops their live pairwise session, so an attacker who later compromises the friend's identity can't keep using the existing session key — they'd have to complete a fresh signed handshake after you unblock them.
- **Copy message to clipboard:** every message has a hover ⧉ Copy button that copies the message body to the clipboard (with a `document.execCommand('copy')` fallback for older browsers).
- **Delete message locally:** every message has a hover 🗑 Delete button that removes it from *your* view only — the sender and any other devices still have it. Useful for tidying without affecting the protocol.
- **URL auto-linking:** bare `http(s)://` URLs in chat messages are auto-linked with `target="_blank" rel="noopener noreferrer"`, so links open in a new tab without leaking `window.opener` back into the app. Code samples and local paths are deliberately not touched.
- **`/version` endpoint:** a lightweight, identity-free JSON probe suitable for monitoring/CI checks that don't need the full `/health` payload.
- **HTTP `OPTIONS` handler:** responds to CORS preflight requests with `204 No Content` plus the standard security headers, so misconfigured browsers don't show noisy console errors.
- **HTTP `HEAD` handler:** `HEAD /health`, `HEAD /version`, and `HEAD /files/<id>` return the same headers as `GET` without a body, useful for monitoring tools.
- **Inline file chips in chat:** non-image file transfers now render in the chat timeline as a clickable chip with icon, filename, size, and a download link — not just in the side panel.

### Hardening

- **Graceful shutdown:** `Ctrl+C` and `SIGTERM` now trigger an orderly shutdown — long-lived tasks are cancelled, the HTTP server is shut down, the SQLite DB and any relay DB are closed, and `Goodbye.` is printed. No more ugly tracebacks or un-checkpointed WAL files.
- **Reconnection jitter:** the signaling reconnect backoff now adds up to 30% random jitter so a transient relay outage doesn't cause every client to reconnect in lockstep and hammer the server at the exact same instant.
- **Direct-peer rate-limit GC:** stale rate-limit buckets for IPs that haven't connected recently are now garbage-collected on each new connection, so the `_direct_rate` dict can't grow unboundedly as peers (and attackers) cycle through source IPs.
- **Stronger HTTP security headers:** added `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `X-Permitted-Cross-Domain-Policies: none` alongside the existing CSP, `X-Content-Type-Options`, `Referrer-Policy`, and `Cache-Control`. Added `media-src 'self' blob: data:` to the CSP so the inline audio player for voice messages renders correctly.

### Testing

- Unit tests grew from 19 → 30 cases, covering the verify regression, nickname rename, block-drops-session, OPTIONS/HEAD handlers, the `/version` probe, direct-rate GC, the save-before-send order, and the new `mark_remote_read` method.
- A new live HTTP smoke test (`scripts/smoke_test.py`) starts a fresh node, hits `/health`, `/version`, `/`, `/files/<bad-id>`, `HEAD /health`, and `OPTIONS /`, then shuts the node down with `SIGTERM` to verify the graceful-shutdown path. 13 checks, all passing.
- A new end-to-end test (`scripts/e2e_test.py`) starts a real signaling server + two real nodes, establishes a Kyber session, exchanges an encrypted chat, verifies delivery acks, read receipts, and reactions all propagate, and exercises nickname rename + block/unblock. 15 checks, all passing.

---

## Features

**Identity & friends**
- Persistent ML-DSA/Dilithium identity keypair, created once and stored in SQLite.
- Add peers by public key with an optional nickname; see online/session status, unread counts, verification state, and last-message previews at a glance.
- Rename, block, unblock, verify, and remove friends from the chat header.
- Safety-number/fingerprint verification state for trusted friends.

**Post-quantum crypto**
- Peers authenticate handshakes with **ML-DSA/Dilithium** signatures and establish shared secrets with **Kyber-512** (ML-KEM-512).
- Pairwise sessions track a 24-hour lifetime; the UI warns when session keys are close to expiry.
- Every chat message and file payload is encrypted with **AES-256-GCM** using HKDF-derived per-message keys, bound to sender, recipient, counter, and purpose. Binding both sender and recipient (rather than a single ambiguous "peer" value) keeps the two directions of a session on distinct keys.
- Replay hardening: inbound chat/file payloads include counters, a replay window accepts valid out-of-order delivery, and duplicate counters/IDs are rejected.

**Networking**
- Direct peer WebSocket transport with relay fallback: nodes advertise an optional direct listener and try direct encrypted delivery before falling back to the signaling relay.
- Exponential backoff with up to 30% jitter when reconnecting to the relay.
- Outbox queues eligible outbound payloads locally when offline; the relay persists offline envelopes in a small SQLite queue.
- Per-socket rate limiting on both the relay and the direct peer listener; stale rate-limit buckets are GC'd on each new connection.

**Messaging**
- 1:1 and group chat, with target-scoped message history, quick text filter, and a "Load older messages" pager.
- Typing indicators (ephemeral relay messages), delivery/read status ticks, a manual **mark read** action, and hover emoji reaction controls.
- Per-friend unread counts persist in SQLite and clear when a conversation is read. Browser notifications and title unread-count updates fire when messages arrive while the page is unfocused.
- Copy-message-to-clipboard and delete-message-locally hover actions on every message.
- URL auto-linking with `rel="noopener noreferrer"`.

**Files**
- Encrypted chunked file transfer with a signed manifest, SHA-256 checksum verification, and AES-256-GCM at rest (in flight and once complete).
- Inline image previews in the chat timeline; non-image files render as a clickable download chip.
- Voice messages: record a short voice note in the browser (🎙️ button) and send it through the existing encrypted file pipeline; audio files render with an inline player.
- Drag-and-drop upload support.
- Configurable storage quota (`--max-storage-mb`) caps total on-disk file bytes; oversized incoming or outgoing files are rejected up front. Usage is tracked incrementally and shown as a bar in the UI.

**Groups**
- Create groups from selected friends or comma-separated public keys; group file fan-out.
- Per-group epoch keys; membership keys are distributed over authenticated pairwise sessions.
- Group owners can remove members and manually rotate the group key — a fresh epoch key is generated and redistributed only to remaining members, so a removed member cannot read anything encrypted afterward.

**Persistence & local security**
- SQLite-backed: identity, friends, sessions, groups, messages, files, outbox, reactions, read receipts, and session health metadata all persist across restarts.
- Encrypted at rest: secret keys, session keys, message bodies, file bytes, and in-flight file chunks are all AES-256-GCM encrypted with a per-database local master key file.
- Passphrase-wrapped key files via `QUANTUM_CHAT_PASSPHRASE` use **Scrypt** (memory-hard, tunable work factor) as of v3.0.
- WAL mode with `PRAGMA synchronous=NORMAL` for better write throughput; schema versioning, busy timeout, indexes, and serialized database access.

**HTTP & UI security**
- Browser UI WebSocket requires a random startup token and rejects non-local origins; remote UI binds require `--allow-remote-ui`.
- HTTP security headers on every response: `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, `X-Permitted-Cross-Domain-Policies: none`.
- Non-root HTTP routes require the startup token when `--allow-remote-ui` is set.

**Health & observability**
- `/health` exposes node status, queue depth, storage usage, metrics, and identity as JSON.
- `/version` is a lightweight, identity-free JSON probe for monitoring/CI.
- `HEAD` and `OPTIONS` handlers on all routes.
- `--log-level` controls runtime logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).

**One-file app:** all Python, HTTP serving, WebSocket handling, and the browser UI live in `chat.py`.

---

## Requirements

- Python 3.10+ (tested on 3.12)
- Packages listed in `requirements.txt`:
  - `cryptography>=42.0.0`
  - `websockets>=12.0`
  - `pqcrypto>=0.3.0`

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

---

## Quick start on one machine

Start a local node and a local signaling server together:

```bash
python chat.py --with-signaling
```

Open the UI at:

```text
http://127.0.0.1:8000
```

The process also prints the node identity, public-key fingerprint, UI URL, and health URL. Health status is available at:

```text
http://127.0.0.1:8000/health
```

Press `Ctrl+C` to shut down cleanly — the node cancels its tasks, closes the DB, and prints `Goodbye.`

To run a second local node for testing, use different ports and a different database:

```bash
python chat.py --db peer2.db --http-port 8001 --ui-ws-port 8767 --direct-port 8769 --signaling-url ws://127.0.0.1:8766 --no-browser
```

Then open `http://127.0.0.1:8001` manually.

---

## Multi-machine setup

Run the signaling server on a reachable host:

```bash
python chat.py signal --host 0.0.0.0 --port 8766
```

Run each peer and point it at that signaling server. For direct LAN delivery, advertise a host/IP other peers can reach:

```bash
python chat.py --signaling-url ws://SIGNALING_HOST_OR_IP:8766 --direct-advertise-host THIS_NODE_IP
```

Each peer then:

1. Copies their public key or fingerprint from **Your identity**.
2. Shares it with the other peer through a trusted out-of-band channel.
3. Adds the other peer in **Friends**.
4. Clicks **Connect** to complete the Kyber session handshake.
5. Sends messages, reacts, marks messages read, or transfers files after the secure session notice appears and the friend shows a secure session badge.

---

## Browser UI

The local browser interface includes:

- A redesigned dark three-column layout with responsive mobile behavior.
- A dashboard for friend, online peer, secure session, and file counts.
- Friend cards with online badges, secure-session badges, unread counters, and last-message previews.
- Target-scoped message history with a quick text filter and a "Load older messages" control.
- Typing indicators, delivery/read status ticks, a manual **mark read** action, and hover emoji reaction controls.
- **Hover ⧉ Copy** and **🗑 Delete** actions on every message.
- **✎ Rename**, **Block / Unblock**, **Verify safety**, and **Remove** buttons in the chat header.
- Browser notifications and title unread-count updates when messages arrive while the page is unfocused.
- A session health panel that shows established pairwise sessions and remaining key lifetime.
- A recent encrypted files panel with local download links, image-friendly browser previews, inline audio playback for voice messages, and drag-and-drop upload support.
- **Inline image previews and file chips** in the chat timeline itself.
- A storage-quota bar showing bytes used against the configured limit.
- Group creation from either the selected friend or comma-separated public keys, plus group file fan-out; group owners get a member-management panel to remove members and a manual key-rotation control.
- An identity backup/restore modal for moving your identity to a second device.

---

## HTTP endpoints

| Method & path | Auth | Description |
| --- | --- | --- |
| `GET /` | token if `--allow-remote-ui` | The browser UI HTML. |
| `GET /health` | token if `--allow-remote-ui` | Node status, queue depth, storage usage, metrics, and identity as JSON. |
| `GET /version` | none | Lightweight `{"version": "...", "app": "..."}` JSON probe. Suitable for monitoring/CI without exposing identity. |
| `GET /files/<uuid>` | token if `--allow-remote-ui` | Download an encrypted-at-rest file (decrypted on the fly). |
| `HEAD /` `HEAD /health` `HEAD /version` `HEAD /files/<uuid>` | token if `--allow-remote-ui` | Same headers as `GET`, no body. |
| `OPTIONS /` | none | `204 No Content` with security headers and `Allow: GET, HEAD, OPTIONS`. |

All responses include `Content-Security-Policy`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block`, and `X-Permitted-Cross-Domain-Policies: none`.

---

## How it works

### Cryptographic flow

1. A peer creates a persistent ML-DSA/Dilithium identity keypair.
2. When connecting to a friend, the initiator creates an ephemeral Kyber keypair and sends a signed `session_offer` through the signaling server.
3. The responder verifies the signature, encapsulates a shared secret to the initiator's Kyber public key, stores an HKDF-derived AES-256-GCM key, and returns a signed `session_accept`.
4. The initiator verifies the acceptance signature, decapsulates the Kyber ciphertext, derives the same AES-256-GCM key, and stores the session.
5. Session keys are derived with transcript binding and are tracked with a 24-hour lifetime.
6. Chat/file payloads use HKDF-derived per-message keys — bound to the session key, sender, recipient, a monotonic counter, and a purpose tag — plus AES-256-GCM authenticated associated data for routing metadata. Binding both sender and recipient (rather than a single ambiguous "peer" value) keeps the two directions of a session on distinct keys.
7. Delivery acknowledgements, read receipts, reactions, and group invites are signed with the sender's persistent identity key. (v3.1.0 fixed a critical bug where `PQModule.verify` accepted every signature — see [What's new](#whats-new-in-v310).)
8. Group messages are encrypted with a per-group epoch key. Removing a member or manually rotating the key generates a new epoch key and redistributes it only to remaining members over their authenticated pairwise sessions, so a removed member cannot decrypt anything sent after that point.

### Networking model

Quantum Chat uses a WebSocket signaling/relay server to discover online peers, exchange direct-transport metadata, and route encrypted envelopes when direct delivery is unavailable. Nodes with reachable direct listeners advertise a direct WebSocket URL and attempt direct friend-to-friend delivery before falling back to the relay. The relay can see enough routing metadata for discovery and fallback delivery, but not decrypted message text or file contents.

The relay issues a signed-registration challenge for clients that support it, validates public-key sizes, records short-lived relay aliases and optional direct URLs, performs basic payload-shape checks, persists bounded offline queues in SQLite, and applies per-socket rate limiting. Nodes reconnect with exponential backoff plus jitter after relay failures.

This model works reliably on LANs and across NAT when peers can reach either each other or the signaling server. Direct delivery is opportunistic and relay fallback remains available for peers behind restrictive NAT or firewalls.

---

## Persistence and at-rest encryption

The default SQLite database is `quantum_chat.db`. File metadata is saved in SQLite and encrypted file bytes are saved in the `files/` directory. In-flight file chunks are also encrypted at rest as soon as they're received, and are deleted as soon as a transfer is reassembled — nothing sits on disk in plaintext at any point, even mid-transfer.

A local master key file named like `<database>.key` is created beside the database and protects local secret material, message bodies, session keys, and stored file bytes. For stronger local protection, set `QUANTUM_CHAT_PASSPHRASE` before startup; the app will wrap the local key file with a Scrypt-derived wrapping key. Back up both the database and its key material if you need to preserve a node identity and local history.

Total on-disk file storage (finished files plus any in-flight chunks) is capped by `--max-storage-mb` (default 4096 MB; set to `0` to disable enforcement). Usage is tracked incrementally rather than by walking the filesystem, and is shown as a bar in the browser UI.

---

## Passphrase KDF migration

v3.0 wraps the local key file's passphrase-derived wrapping key with Scrypt instead of HKDF, since HKDF has no brute-force work factor and is a poor fit for user-chosen passphrases. If you have an existing `QUANTUM_CHAT_PASSPHRASE`-protected `.key` file from v2.0, this version will refuse to open it and print migration instructions: run the v2.0 release once with the passphrase set to unwrap it, delete the `.key` file, then start this version so it re-wraps the (unwrapped) local key with the stronger format.

---

## Multi-device support

Quantum Chat's identity, friends, sessions, and history all live in one local SQLite database, so there's no built-in protocol for keeping multiple devices in sync — that's a substantially larger undertaking (similar in spirit to how other E2E messengers implement multi-device support) than this project takes on.

What v3.0 adds is a practical way to *carry your identity* to a second device: from the identity card, choose **Backup / restore** to export your signing keypair as a passphrase-protected string. Importing it on a brand-new install lets that install operate as you (same public key and fingerprint). This does **not** copy your friends list, sessions, or message history — those stay local to each device — and the UI refuses to import over an identity that already has friends or history, to avoid silently orphaning local state. Treat the exported string like a password: anyone with it and the passphrase can act as your identity.

For scripted setups, a brand-new (never-started) database can also be seeded directly at startup by setting `QUANTUM_CHAT_IMPORT_IDENTITY` (the backup string) and `QUANTUM_CHAT_IMPORT_PASSPHRASE` before the first run.

---

## Command reference

Run the node UI:

```bash
python chat.py [options]
```

Useful node options:

| Option | Default | Description |
| --- | --- | --- |
| `--db` | `quantum_chat.db` | SQLite database path. A sibling `*.key` file stores the local at-rest encryption key. |
| `--signaling-url` | `ws://127.0.0.1:8766` | Signaling/relay server URL. |
| `--with-signaling` | disabled | Also start a signaling server in the same process. |
| `--signaling-host` | `0.0.0.0` | Host for the bundled signaling server when `--with-signaling` is used. |
| `--signaling-port` | `8766` | Port for the bundled signaling server when `--with-signaling` is used. |
| `--http-host` | `127.0.0.1` | Host for the browser UI. |
| `--http-port` | `8000` | Port for the browser UI and HTTP API. |
| `--ui-ws-host` | `127.0.0.1` | Host for the local UI WebSocket. |
| `--ui-ws-port` | `8765` | Port for the local UI WebSocket. |
| `--no-browser` | disabled | Do not open a browser automatically. |
| `--allow-remote-ui` | disabled | Allow non-local HTTP/UI WebSocket binds; non-root HTTP routes require the startup token. |
| `--enable-direct` / `--no-direct` | enabled | Enable or disable the direct peer WebSocket transport. |
| `--direct-host` | `127.0.0.1` | Host/interface for the direct peer listener. |
| `--direct-port` | `8768` | Port for the direct peer listener. |
| `--direct-advertise-host` | direct host | Host/IP advertised to friends for direct delivery. |
| `--max-storage-mb` | `4096` | Disk quota in MB for received/sent file bytes. `0` disables enforcement. |
| `--log-level` | `WARNING` | Logging verbosity: `DEBUG`, `INFO`, `WARNING`, or `ERROR`. |

Run only the signaling server:

```bash
python chat.py signal --host 0.0.0.0 --port 8766
```

---

## Environment variables

| Variable | Purpose |
| --- | --- |
| `QUANTUM_CHAT_PASSPHRASE` | If set, the local master key file is wrapped with a Scrypt-derived key. Required for opening an existing wrapped `.key` file. |
| `QUANTUM_CHAT_KEY_MODE` | `file` (default) or `passphrase`. Forces the key-file mode regardless of whether `QUANTUM_CHAT_PASSPHRASE` is set. |
| `QUANTUM_CHAT_IMPORT_IDENTITY` | A `QCID1:...` backup string to seed a brand-new database with on first run. |
| `QUANTUM_CHAT_IMPORT_PASSPHRASE` | The passphrase for `QUANTUM_CHAT_IMPORT_IDENTITY`. |
| `QUANTUM_CHAT_RELAY_DB` | Path for the relay's offline-queue SQLite DB (default: `quantum_chat_relay.db`). |

---

## Project structure

```text
chat.py                                # Application, crypto, DB, WebSocket relay/client, HTTP UI
requirements.txt                       # Runtime dependencies
pyproject.toml                         # Package metadata and console entry point
README.md                              # This document
LICENSE                                # MIT
test_validation_and_database.py        # Unit tests (30 cases)
scripts/smoke_test.py                  # Live HTTP smoke test (13 checks)
scripts/e2e_test.py                    # End-to-end protocol test (15 checks)
quantum_chat.db                        # Created at runtime
quantum_chat.db.key                    # Created at runtime; local at-rest encryption key
files/                                 # Created at runtime for encrypted transferred files
```

---

## Threat model and current limits

Quantum Chat aims to protect message and file contents from the signaling relay and passive network observers. It assumes users verify friend public keys or fingerprints through a trusted out-of-band channel and that invited group members are trusted to receive group content.

Important remaining limits:

- Direct peer WebSocket delivery is attempted when peers advertise reachable direct listeners; the relay remains the fallback for NAT or firewall-restricted peers.
- Relay-visible metadata is reduced through short-lived aliases and opaque encrypted payloads where possible, but a relay still sees connection timing and enough routing metadata to deliver envelopes.
- Group messages use stored group epoch keys and signed key distribution; this is stronger than per-message pairwise encryption, though it is not a certified MLS implementation.
- Delivery acknowledgements, read receipts, reactions, typing indicators, local retries, and relay-persistent offline queues improve UX. There is no multi-device message/history sync — see [Multi-device support](#multi-device-support).
- File transfer uses encrypted chunks and a signed manifest, encrypted at rest for the duration of the transfer; browsers may still impose practical upload memory limits.
- Local at-rest encryption can use raw key-file compatibility or passphrase-wrapped key files via `QUANTUM_CHAT_PASSPHRASE` (Scrypt-derived as of v3.0). Protect and back up the active key material.
- Remote UI exposure is blocked unless `--allow-remote-ui` is provided; production deployments should still put the UI behind TLS and additional access controls.
- The app is not externally audited and should be reviewed before high-risk deployments.

---

## Testing

### Unit tests

```bash
pytest test_validation_and_database.py
```

30 cases covering: public-key/file-id/label validation, at-rest encryption of identity/session/message/file rows, replay-window behavior, group keys/chunks/metrics, HTTP auth and CSP, UI WebSocket auth (modern + legacy shapes), Scrypt key-file wrapping and legacy rejection, group member removal + key rotation, file-chunk encryption at rest + cleanup, storage quota, identity backup round-trip, message pagination, group fingerprint on UUIDs, the v3.1.0 verify regression, nickname rename, block-drops-session, OPTIONS/HEAD handlers, the `/version` probe, direct-rate GC, the save-before-send order, and `mark_remote_read`.

### Live HTTP smoke test

```bash
python scripts/smoke_test.py
```

Starts a fresh node on private ports, hits `/health`, `/version`, `/`, `/files/<bad-id>`, `HEAD /health`, and `OPTIONS /`, verifies all security headers, then sends `SIGTERM` to verify the graceful-shutdown path. 13 checks.

### End-to-end protocol test

```bash
python scripts/e2e_test.py
```

Starts a real signaling server + two real nodes (Alice and Bob), establishes a Kyber session, exchanges an encrypted chat, verifies delivery acks, read receipts, and reactions all propagate end-to-end, and exercises nickname rename + block/unblock. 15 checks. This is the test that caught all three v3.1.0 critical bugs.

### Manual database exercise

Exercise the database layer without network services:

```bash
python - <<'PY'
from chat import Database, LocalKeyStore
import tempfile, os, uuid
fd, path = tempfile.mkstemp(); os.close(fd); os.remove(path)
key_path = path + '.key'
db = Database(path, master_key=LocalKeyStore(path).load_or_create())
me, friend = 'aa' * 974, 'bb' * 974           # stand-ins for real hex-encoded ML-DSA public keys
gid, file_id = str(uuid.uuid4()), str(uuid.uuid4())
db.save_identity(me, b'secret')
db.add_friend(friend, 'Alice')
db.create_group(gid, 'Group', me)
db.add_group_member(gid, friend)
db.save_message('m1', me, 'hello', 'out', recipient=friend, delivered=True)
db.save_file(file_id, 'note.txt', me, 5, '2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824', path, recipient=friend)
print(db.load_identity()[0][:8], db.get_friends()[0]['nickname'], db.group_details_for(me)[0]['name'], db.recent_messages()[0]['body'], db.recent_files()[0]['filename'])
db.close(); os.remove(path); os.remove(key_path)
PY
```

---

## Packaging and development

Install as an editable package with development tools:

```bash
python -m pip install -e .[dev]
```

Run the console entry point:

```bash
quantum-chat --with-signaling
```

Compile the app:

```bash
python -m py_compile chat.py
```

---

## Historical changelog

### v3.0.0

**Critical fixes:**

- Fixed: 1:1 chat and file messages could fail to decrypt. The per-message key derivation used a peer identifier that resolved differently on the sending and receiving side of a session, so the two ends could derive different keys. All message/file/group-key encryption call sites now derive keys from an explicit, symmetric `(from, to)` pair instead.
- Fixed: creating or listing any group crashed. Group IDs (UUIDs, which contain dashes) were being hex-decoded as if they were public keys when computing a display fingerprint. Groups now fingerprint correctly.
- Fixed: file chunks were written to disk in plaintext while a transfer was in progress, and were never cleaned up after reassembly. Chunks are now encrypted at rest immediately (same as a finished file) and are deleted as soon as reassembly completes.
- Hardened: passphrase-based local key wrapping (`QUANTUM_CHAT_PASSPHRASE`) now uses Scrypt instead of HKDF.

**New features:** group member removal and key rotation, identity backup & restore, storage quota, voice messages, message pagination, lighter UI updates.

### v2.0

- Strict algorithm-sized public-key validation for friends, relay registration, and relay targets.
- Signed signaling registration challenges to reduce public-key hijacking on the relay.
- Basic relay rate limiting and payload shape checks.
- UI WebSocket bearer token and local-origin checks.
- HTTP security headers for the app shell, `/health`, and downloads.
- SQLite schema versioning, busy timeout, indexes, WAL mode, and serialized database access.
- Encrypted-at-rest identity keys, session keys, message bodies, and downloaded/sent file bytes.
- Replay protections using message/file counters plus insert-only duplicate handling.
- Signed delivery acknowledgements, read receipts, emoji reactions, and group invites.
- Persistent unread counts, enforced session TTL rekeying, direct-delivery metrics, offline relay queueing, and an expanded JSON health endpoint.
- Safety-number/fingerprint verification state for trusted friends.

---

## License

MIT License. See [LICENSE](LICENSE).
