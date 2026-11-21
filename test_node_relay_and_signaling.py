"""Unit tests for the least-covered parts of chat.py.

Baseline coverage measured with ``pytest --cov=chat`` on the pre-existing
suite left three areas almost untested: ``QuantumNode``'s relay/UI dispatch
and message handlers (~23% of statements covered), ``SignalingServer.handle``
(~17%), and the ``PQModule`` pqcrypto compatibility shim (~34%). The live
scripts under scripts/ exercise some of that code, but only through real
sockets and real subprocesses, so a regression there fails slowly and far
from its cause.

The tests here drive the same code paths in-process: node-to-node traffic is
delivered by replacing ``send_relay`` with a direct call into the peer node's
``handle_relay_payload``, and the relay/UI/direct-peer sockets are replaced by
small fakes. No network, no subprocesses.
"""

import asyncio
import hashlib
import json
import uuid
from pathlib import Path

import pytest

import chat as chat_module
from chat import (
    MAX_CHUNK_BYTES,
    PQModule,
    QuantumNode,
    SignalingServer,
    b64e,
    canonical_json,
)

# ─── Fakes ────────────────────────────────────────────────────────────────────


class FakeSocket:
    """Minimal stand-in for a websockets connection.

    Supports the three shapes chat.py uses: ``send``, ``close``, async
    iteration over inbound frames, and ``recv``.
    """

    def __init__(self, incoming=None):
        self.sent = []
        self.closed = None
        self._incoming = list(incoming or [])

    async def send(self, data):
        self.sent.append(data)

    async def close(self, code=1000, reason=""):
        self.closed = (code, reason)

    async def recv(self):
        if not self._incoming:
            raise RuntimeError("no more frames")
        return self._incoming.pop(0)

    def __aiter__(self):
        async def gen():
            while self._incoming:
                yield self._incoming.pop(0)

        return gen()

    def frames(self):
        return [json.loads(raw) for raw in self.sent]

    def frames_of_type(self, kind):
        return [f for f in self.frames() if f.get("type") == kind]


def make_node(tmp_path, name, **kwargs):
    node = QuantumNode(str(tmp_path / f"{name}.db"), "ws://127.0.0.1:65535",
                       direct_url=None, enable_direct=False, **kwargs)
    node.allow_remote_ui = False
    node.ui = FakeSocket()
    node.ui_clients.add(node.ui)
    return node


def link(*nodes):
    """Deliver each node's relay traffic straight into its peers' handlers.

    Mirrors what SignalingServer does for a connected peer, including the
    fan-out to *other* devices sharing one identity that multi-device sync
    relies on, without needing a relay process or sockets.
    """
    by_key = {}
    for node in nodes:
        by_key.setdefault(node.public_key, []).append(node)
        node.delivery_errors = []

    for node in nodes:
        def send_relay(peer_pubkey, payload, queue_on_failure=False, ephemeral=False, _self=node):
            targets = [t for t in by_key.get(peer_pubkey, []) if t is not _self]

            async def deliver():
                if not targets:
                    if ephemeral:
                        return
                    if queue_on_failure:
                        _self.db.queue_outbox(peer_pubkey, payload)
                        return
                    raise RuntimeError("Not connected to signaling server")
                for target in targets:
                    try:
                        await target.handle_relay_payload(_self.public_key, payload)
                    except Exception as exc:  # noqa: BLE001
                        # Each recipient runs in its own process in reality, so
                        # one recipient rejecting a frame is logged there and
                        # never surfaces to the sender (see
                        # connect_signaling_loop's per-frame try/except).
                        target.delivery_errors.append(exc)

            return deliver()

        node.send_relay = send_relay


def befriend(a, b):
    a.db.add_friend(b.public_key, "peer")
    b.db.add_friend(a.public_key, "peer")


# ─── PQModule compatibility shim ──────────────────────────────────────────────
#
# PQModule exists purely to paper over pqcrypto's API variance across
# versions (generate_keypair/keygen/keypair, encaps/encrypt/encapsulate,
# positional argument order). Only the branch matching the installed
# pqcrypto build ever ran under the old suite, so a typo in any other branch
# would only surface on a user's machine with a different pqcrypto version.


def _shim(sign_mod=None, kem_mod=None):
    shim = object.__new__(PQModule)
    shim.sign_mod = sign_mod
    shim.kem_mod = kem_mod
    return shim


def test_pqmodule_keypair_shim_supports_every_pqcrypto_spelling():
    class GenerateKeypair:
        @staticmethod
        def generate_keypair():
            return b"pk-generate", b"sk-generate"

    class Keygen:
        @staticmethod
        def keygen():
            return b"pk-keygen", b"sk-keygen"

    class Keypair:
        @staticmethod
        def keypair():
            return b"pk-keypair", b"sk-keypair"

    for mod, expected in [(GenerateKeypair, b"pk-generate"), (Keygen, b"pk-keygen"), (Keypair, b"pk-keypair")]:
        assert _shim(sign_mod=mod).sign_keypair()[0] == expected
        assert _shim(kem_mod=mod).kem_keypair()[0] == expected


def test_pqmodule_sign_falls_back_to_legacy_argument_order():
    class LegacyOrder:
        """pqcrypto builds that take (message, secret_key)."""

        @staticmethod
        def sign(message, secret_key):
            if message == b"secret":  # called with the modern order
                raise TypeError("wrong argument order")
            return b"signed:" + message

    assert _shim(sign_mod=LegacyOrder).sign(b"secret", b"body") == b"signed:body"


def test_pqmodule_verify_handles_legacy_order_and_never_raises():
    class LegacyVerify:
        @staticmethod
        def verify(*args):
            if len(args) != 3:
                raise TypeError("bad arity")
            first, second, third = args
            if first == b"pk":  # modern (public_key, message, signature)
                raise TypeError("unsupported signature")
            return first == b"message" and second == b"sig" and third == b"pk"

    shim = _shim(sign_mod=LegacyVerify)
    assert shim.verify(b"pk", b"message", b"sig") is True
    assert shim.verify(b"pk", b"other", b"sig") is False

    class ExplodingVerify:
        @staticmethod
        def verify(_public_key, _message, _signature):
            raise ValueError("signature mismatch")

    # A raising verify must be reported as "not verified", never propagated
    # as an exception and never treated as success.
    assert _shim(sign_mod=ExplodingVerify).verify(b"pk", b"message", b"sig") is False

    class DoubleFailure:
        @staticmethod
        def verify(*_args):
            raise TypeError("no supported call shape")

    assert _shim(sign_mod=DoubleFailure).verify(b"pk", b"message", b"sig") is False


def test_pqmodule_kem_shim_supports_every_encapsulation_spelling():
    class Encaps:
        @staticmethod
        def encaps(public_key):
            return b"ct-encaps", public_key

        @staticmethod
        def decaps(secret_key, ciphertext):
            return b"ss:" + secret_key + ciphertext

    class Encrypt:
        @staticmethod
        def encrypt(public_key):
            return b"ct-encrypt", public_key

        @staticmethod
        def decrypt(ciphertext, secret_key):
            if ciphertext == b"sk":  # modern (secret_key, ciphertext)
                raise TypeError("wrong argument order")
            return b"ss:" + secret_key + ciphertext

    class Encapsulate:
        @staticmethod
        def encapsulate(public_key):
            return b"ct-encapsulate", public_key

        @staticmethod
        def decapsulate(secret_key, ciphertext):
            return b"ss:" + secret_key + ciphertext

    assert _shim(kem_mod=Encaps).encapsulate(b"pk")[0] == b"ct-encaps"
    assert _shim(kem_mod=Encrypt).encapsulate(b"pk")[0] == b"ct-encrypt"
    assert _shim(kem_mod=Encapsulate).encapsulate(b"pk")[0] == b"ct-encapsulate"

    assert _shim(kem_mod=Encaps).decapsulate(b"sk", b"ct") == b"ss:skct"
    assert _shim(kem_mod=Encrypt).decapsulate(b"sk", b"ct") == b"ss:skct"
    assert _shim(kem_mod=Encapsulate).decapsulate(b"sk", b"ct") == b"ss:skct"


# ─── SignalingServer.handle ───────────────────────────────────────────────────


@pytest.fixture()
def relay(tmp_path, monkeypatch):
    monkeypatch.setenv("QUANTUM_CHAT_RELAY_DB", str(tmp_path / "relay.db"))
    return SignalingServer()


def register_frame(node, nonce):
    challenge = {"type": "register_challenge", "nonce": nonce, "pubkey": node.public_key}
    sig = b64e(node.crypto.sign(node.secret_key, canonical_json(challenge)))
    return json.dumps({
        "type": "register", "pubkey": node.public_key,
        "signature": sig, "challenge": nonce,
        "relay_alias": node.relay_alias, "direct_url": node.direct_url,
    })


def run_relay_socket(relay_server, frames):
    """Run one relay connection, feeding it frames after the challenge.

    ``frames`` is a callable receiving the challenge nonce so tests can sign
    a registration against it.
    """
    socket = FakeSocket()

    async def drive():
        nonce_holder = {}
        original_send = socket.send

        async def capture(data):
            await original_send(data)
            frame = json.loads(data)
            if frame.get("type") == "register_challenge":
                nonce_holder["nonce"] = frame["nonce"]
                socket._incoming.extend(frames(frame["nonce"]))

        socket.send = capture
        await relay_server.handle(socket)
        return nonce_holder.get("nonce")

    asyncio.run(drive())
    return socket


def test_relay_registration_requires_a_valid_challenge_signature(relay, tmp_path):
    node = make_node(tmp_path, "signer")
    try:
        socket = run_relay_socket(relay, lambda nonce: [
            json.dumps({
                "type": "register", "pubkey": node.public_key,
                "signature": b64e(b"\x00" * 64), "challenge": nonce,
            }),
        ])
        errors = socket.frames_of_type("error")
        assert errors and errors[0]["text"] == "Invalid registration signature"
        assert relay.clients == {}
    finally:
        node.db.close()


def test_relay_registration_publishes_alias_and_peer_metadata(relay, tmp_path):
    node = make_node(tmp_path, "registrant")
    try:
        socket = run_relay_socket(relay, lambda nonce: [register_frame(node, nonce)])
        peers = socket.frames_of_type("peers")
        assert peers, "a successful registration must broadcast the peer list"
        assert peers[-1]["peers"][node.public_key]["relay_alias"] == node.relay_alias
        # The connection closed at the end of handle(), so its bookkeeping
        # must be fully torn down rather than leaking a stale entry.
        assert relay.clients == {}
        assert relay.aliases == {}
        assert relay.peer_meta == {}
    finally:
        node.db.close()


def test_relay_rejects_a_stale_challenge_and_any_unsigned_registration(relay, tmp_path):
    node = make_node(tmp_path, "stale")
    try:
        socket = run_relay_socket(relay, lambda nonce: [
            register_frame(node, "not-the-issued-nonce"),
        ])
        assert any(f.get("text") == "Invalid registration signature" for f in socket.frames())

        # Registration is always challenge-signed: an unsigned register cannot
        # prove it holds the identity's secret key, so it is rejected even when
        # the identity has no live socket — accepting it would let anyone claim
        # an offline identity, occupy its routing entry, and drain its queued
        # envelopes. (Multi-device support is served by *signed* registrations
        # fanning out to a set of sockets, not by unsigned fallbacks.)
        relay.clients.pop(node.public_key, None)
        socket = run_relay_socket(relay, lambda nonce: [
            json.dumps({"type": "register", "pubkey": node.public_key}),
        ])
        assert any(f.get("text") == "Invalid registration signature"
                   for f in socket.frames())
        assert not any(f.get("type") == "registered" for f in socket.frames())
    finally:
        node.db.close()


def test_relay_requires_registration_before_relaying(relay, tmp_path):
    node = make_node(tmp_path, "unregistered")
    try:
        socket = run_relay_socket(relay, lambda nonce: [
            json.dumps({"type": "relay", "to": node.public_key, "payload": {"kind": "chat"}}),
        ])
        assert any(f.get("text") == "Register before relaying" for f in socket.frames())
    finally:
        node.db.close()


def test_relay_rejects_non_object_and_oversized_payloads(relay, tmp_path):
    node = make_node(tmp_path, "payloads")
    try:
        socket = run_relay_socket(relay, lambda nonce: [
            register_frame(node, nonce),
            json.dumps({"type": "relay", "to": node.public_key, "payload": "not-an-object"}),
        ])
        assert any(f.get("text") == "Invalid relay payload" for f in socket.frames())
    finally:
        node.db.close()


def test_relay_queues_durable_traffic_but_drops_ephemeral_traffic(relay, tmp_path):
    sender = make_node(tmp_path, "sender")
    target = make_node(tmp_path, "target")
    try:
        socket = run_relay_socket(relay, lambda nonce: [
            register_frame(sender, nonce),
            json.dumps({"type": "relay", "to": target.public_key, "payload": {"kind": "chat"}}),
            json.dumps({"type": "relay", "to": target.public_key,
                        "payload": {"kind": "typing"}, "ephemeral": True}),
        ])
        queued = socket.frames_of_type("queued")
        assert len(queued) == 2
        assert queued[0].get("ephemeral") is None
        assert queued[1]["ephemeral"] is True
        # Only the durable envelope is persisted for later delivery.
        rows = relay.relay_db.execute(
            "SELECT envelope FROM offline_queue WHERE target=?", (target.public_key,)
        ).fetchall()
        assert len(rows) == 1
        assert json.loads(rows[0][0])["payload"] == {"kind": "chat"}
    finally:
        sender.db.close()
        target.db.close()


def test_relay_drains_the_offline_queue_on_registration(relay, tmp_path):
    node = make_node(tmp_path, "returning")
    try:
        envelope = json.dumps({"type": "relay", "from": "peer", "payload": {"kind": "chat"}, "offline": True})
        relay.relay_db.execute(
            "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
            (node.public_key, envelope, chat_module.utc_ts()),
        )
        relay.relay_db.commit()
        socket = run_relay_socket(relay, lambda nonce: [register_frame(node, nonce)])
        assert any(f.get("type") == "relay" and f.get("offline") for f in socket.frames())
        assert relay.relay_db.execute(
            "SELECT COUNT(*) FROM offline_queue WHERE target=?", (node.public_key,)
        ).fetchone()[0] == 0
    finally:
        node.db.close()


def test_relay_purges_expired_offline_queue_rows_on_registration(relay, tmp_path):
    node = make_node(tmp_path, "expired-queue")
    try:
        envelope = json.dumps({"type": "relay", "from": "peer", "payload": {"kind": "chat"}, "offline": True})
        relay.relay_db.execute(
            "INSERT INTO offline_queue (target, envelope, created_at) VALUES (?, ?, ?)",
            (node.public_key, envelope, chat_module.utc_ts() - chat_module.OFFLINE_QUEUE_TTL - 10),
        )
        relay.relay_db.commit()
        socket = run_relay_socket(relay, lambda nonce: [register_frame(node, nonce)])
        # An envelope older than the TTL is purged, not delivered: replaying
        # week-old chat into a freshly connecting client helps nobody.
        assert not any(f.get("type") == "relay" and f.get("offline") for f in socket.frames())
        assert relay.relay_db.execute(
            "SELECT COUNT(*) FROM offline_queue WHERE target=?", (node.public_key,)
        ).fetchone()[0] == 0
    finally:
        node.db.close()


def test_relay_rejects_re_registration_on_the_same_socket(relay, tmp_path):
    node = make_node(tmp_path, "re-registrant")
    other = make_node(tmp_path, "other-identity")
    try:
        def frames(nonce):
            return [
                register_frame(node, nonce),
                register_frame(node, nonce),  # duplicate, same identity
                register_frame(other, nonce),  # hostile: different identity
            ]
        socket = run_relay_socket(relay, frames)
        errors = socket.frames_of_type("error")
        assert any("Already registered" in e.get("text", "") for e in errors)
        assert any("another identity" in e.get("text", "") for e in errors)
        # The peers broadcast (emitted by the *successful* first registration)
        # must never advertise the second identity: a leaked re-registration
        # would have added it as a phantom online peer.
        peers_frames = socket.frames_of_type("peers")
        assert peers_frames, "expected a peers broadcast after registration"
        assert other.public_key not in peers_frames[-1]["peers"]
        assert node.public_key in peers_frames[-1]["peers"]
    finally:
        node.db.close()
        other.db.close()


def test_relay_resolves_targets_by_alias_and_fans_out_to_other_devices(relay, tmp_path):
    sender = make_node(tmp_path, "alias-sender")
    device_a, device_b = FakeSocket(), FakeSocket()
    try:
        target_pubkey = "cc" * sender.expected_public_key_bytes
        relay.clients[target_pubkey] = {device_a, device_b}
        relay.aliases["deadbeef"] = target_pubkey
        run_relay_socket(relay, lambda nonce: [
            register_frame(sender, nonce),
            json.dumps({"type": "relay", "to": "deadbeef", "payload": {"kind": "chat"}}),
        ])
        for device in (device_a, device_b):
            relayed = device.frames_of_type("relay")
            assert len(relayed) == 1
            assert relayed[0]["from"] == sender.public_key
    finally:
        sender.db.close()


def test_relay_per_socket_rate_limit_rejects_a_flood(relay, tmp_path):
    node = make_node(tmp_path, "flood")
    try:
        frames = [register_frame(node, "unused")] * 0
        socket = run_relay_socket(relay, lambda nonce: [
            json.dumps({"type": "ping"}) for _ in range(125)
        ] + frames)
        errors = [f for f in socket.frames() if f.get("text") == "Rate limit exceeded"]
        assert errors, "the 121st frame on one socket must be rate limited"
    finally:
        node.db.close()


def test_relay_keeps_identity_online_while_another_device_socket_remains(relay, tmp_path):
    node = make_node(tmp_path, "multidevice")
    other_device = FakeSocket()
    try:
        run_relay_socket(relay, lambda nonce: [register_frame(node, nonce)])
        assert relay.clients == {}

        # With a second device socket registered, disconnecting one socket must
        # leave the identity registered and its alias/metadata intact.
        relay.clients.setdefault(node.public_key, set()).add(other_device)
        run_relay_socket(relay, lambda nonce: [register_frame(node, nonce)])
        assert relay.clients[node.public_key] == {other_device}
        assert node.relay_alias in relay.aliases
        assert node.public_key in relay.peer_meta
    finally:
        node.db.close()


# ─── QuantumNode: session handshake and chat ──────────────────────────────────


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


def test_handshake_establishes_a_matching_session_key_on_both_sides(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    assert alice.sessions[bob.public_key] == bob.sessions[alice.public_key]
    assert alice.db.get_session(bob.public_key)["initiator"] == 1
    assert bob.db.get_session(alice.public_key)["initiator"] == 0
    assert alice.pending_offers == {}


def test_connect_peer_rejects_self_and_unknown_keys(pair):
    alice, _bob = pair
    with pytest.raises(ValueError, match="your own public key"):
        asyncio.run(alice.connect_peer(alice.public_key))
    stranger = "ab" * alice.expected_public_key_bytes
    with pytest.raises(ValueError, match="friend"):
        asyncio.run(alice.connect_peer(stranger))


def test_session_offer_from_a_non_friend_is_dropped_with_a_notice(pair, tmp_path):
    alice, bob = pair
    stranger = make_node(tmp_path, "stranger")
    link(alice, bob, stranger)
    try:
        # The stranger knows Alice, but Alice has never added the stranger.
        stranger.db.add_friend(alice.public_key, "target")
        asyncio.run(stranger.connect_peer(alice.public_key))
        assert alice.public_key not in stranger.sessions
        notices = [f for f in alice.ui.frames_of_type("notice") if "untrusted" in f["text"]]
        assert notices, "an offer from a non-friend must be refused, not answered"
    finally:
        stranger.db.close()


def test_session_offer_with_a_forged_signature_is_rejected(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    forged = {"kind": "session_offer", "payload": {"from": alice.public_key, "to": bob.public_key},
              "signature": b64e(b"\x00" * 64)}
    with pytest.raises(ValueError, match="signature"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, forged))


def test_session_accept_must_match_a_pending_offer(pair):
    alice, bob = pair
    accept = alice.signed_payload("session_accept", {
        "protocol": "quantum-chat-v4", "from": alice.public_key, "to": bob.public_key,
        "session_id": str(uuid.uuid4()), "ciphertext": b64e(b"x"),
    })
    with pytest.raises(ValueError, match="active offer"):
        asyncio.run(bob.handle_session_accept(alice.public_key, accept))


def test_chat_round_trip_delivers_plaintext_and_acknowledges_delivery(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    asyncio.run(alice.send_chat(bob.public_key, "hello bob"))

    assert bob.delivery_errors == [] and alice.delivery_errors == []
    received = bob.db.recent_messages()
    assert [m["body"] for m in received] == ["hello bob"]
    assert received[0]["direction"] == "in"
    assert bob.db.get_friends()[0]["unread"] == 1
    # Bob's delivery ack rides back through the same link and updates Alice's
    # copy of the message.
    assert alice.db.recent_messages()[0]["status"] == "delivered_to_peer"
    assert any(f["type"] == "status_update" for f in alice.ui.frames())


def test_chat_rejects_routing_mismatch_and_replayed_counters(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))

    captured = []
    original = bob.handle_relay_payload

    async def capture(peer, payload):
        captured.append(payload)
        await original(peer, payload)

    bob.handle_relay_payload = capture
    asyncio.run(alice.send_chat(bob.public_key, "recorded"))
    chat_payload = next(p for p in captured if p.get("kind") == "chat")

    # Replaying the exact frame must be refused by the counter window.
    with pytest.raises(ValueError):
        asyncio.run(original(alice.public_key, chat_payload))

    tampered = {**chat_payload, "payload": {**chat_payload["payload"], "to": "somebody-else"}}
    with pytest.raises(ValueError, match="routing metadata"):
        asyncio.run(original(alice.public_key, tampered))


def test_send_chat_validates_text_and_requires_a_fresh_session(pair):
    alice, bob = pair
    with pytest.raises(ValueError, match="empty or too large"):
        asyncio.run(alice.send_chat(bob.public_key, "   "))
    with pytest.raises(ValueError, match="empty or too large"):
        asyncio.run(alice.send_chat(bob.public_key, "x" * (chat_module.MAX_TEXT_BYTES + 1)))
    # No session yet: send_chat starts a rekey and asks the caller to retry
    # rather than sending anything unencrypted.
    with pytest.raises(ValueError, match="rekeying"):
        asyncio.run(alice.send_chat(bob.public_key, "no session yet"))


def test_chat_for_an_expired_session_is_refused_without_rekeying(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    payload = {"kind": "chat", "payload": {"from": alice.public_key, "to": bob.public_key,
                                           "counter": 1, "msg_id": str(uuid.uuid4())},
               "packet": {"nonce": b64e(b"n" * 12), "ciphertext": b64e(b"c")}}
    bob.sessions.pop(alice.public_key)
    with pytest.raises(ValueError, match="expired or missing session"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, payload))


# ─── QuantumNode: typing, receipts, reactions ────────────────────────────────


def test_typing_indicator_is_broadcast_and_auto_cleared(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))

    async def scenario():
        await alice.send_typing(bob.public_key, True)
        await alice.send_typing(bob.public_key, False)

    asyncio.run(scenario())
    typing = bob.ui.frames_of_type("typing")
    assert [f["active"] for f in typing] == [True, False]
    assert [f["peer"] for f in typing] == [alice.public_key, alice.public_key]
    # The inactivity timer for the active frame is cancelled by the following
    # inactive frame, so no timer is left behind.
    assert bob._typing_timers == {}


def test_typing_frames_with_mismatched_routing_are_ignored(pair):
    alice, bob = pair
    asyncio.run(bob.handle_typing(alice.public_key, {
        "kind": "typing", "from": alice.public_key, "to": "someone-else", "active": True,
    }))
    assert bob.ui.frames_of_type("typing") == []


def test_typing_without_a_session_is_skipped_silently(pair):
    alice, bob = pair
    asyncio.run(alice.send_typing(bob.public_key, True))
    assert bob.ui.frames_of_type("typing") == []


def test_read_receipt_marks_the_sender_copy_read_with_the_reader_timestamp(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    asyncio.run(alice.send_chat(bob.public_key, "read me"))
    msg_id = bob.db.recent_messages()[0]["msg_id"]

    asyncio.run(bob.send_read_receipt(alice.public_key, msg_id))
    sender_copy = alice.db.recent_messages()[0]
    assert sender_copy["status"] == "read"
    assert sender_copy["read_at"] is not None
    assert any(f["type"] == "read_receipt" for f in alice.ui.frames())


def test_read_receipt_with_a_forged_signature_is_rejected(pair):
    alice, bob = pair
    forged = {"kind": "read_receipt",
              "payload": {"from": bob.public_key, "to": alice.public_key, "msg_id": "m1"},
              "signature": b64e(b"\x00" * 64)}
    with pytest.raises(ValueError, match="signature"):
        asyncio.run(alice.handle_relay_payload(bob.public_key, forged))


def test_reactions_round_trip_and_reject_unlisted_emoji(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    asyncio.run(alice.send_chat(bob.public_key, "react to me"))
    msg_id = bob.db.recent_messages()[0]["msg_id"]

    asyncio.run(bob.send_reaction(alice.public_key, msg_id, "👍"))
    assert [r["emoji"] for r in alice.db.get_reactions([msg_id])[msg_id]] == ["👍"]

    asyncio.run(bob.send_reaction(alice.public_key, msg_id, "👍", action="remove"))
    assert alice.db.get_reactions([msg_id]).get(msg_id, []) == []

    with pytest.raises(ValueError):
        asyncio.run(bob.send_reaction(alice.public_key, msg_id, "🚀"))
    with pytest.raises(ValueError, match="add"):
        asyncio.run(bob.send_reaction(alice.public_key, msg_id, "👍", action="shrug"))


def test_incoming_reaction_validates_action_and_routing(pair):
    alice, bob = pair
    bad_action = bob.signed_payload("reaction", {
        "from": bob.public_key, "to": alice.public_key,
        "msg_id": "m1", "emoji": "👍", "action": "sideways",
    })
    with pytest.raises(ValueError, match="reaction action"):
        asyncio.run(alice.handle_reaction(bob.public_key, bad_action))

    misrouted = bob.signed_payload("reaction", {
        "from": bob.public_key, "to": "elsewhere", "msg_id": "m1", "emoji": "👍", "action": "add",
    })
    with pytest.raises(ValueError, match="routing"):
        asyncio.run(alice.handle_reaction(bob.public_key, misrouted))


# ─── QuantumNode: multi-device sync ──────────────────────────────────────────


@pytest.fixture()
def two_devices(tmp_path):
    """Two nodes sharing one identity, plus a peer, all linked in-process."""
    device_one = make_node(tmp_path, "device1")
    device_two = make_node(tmp_path, "device2")
    # Device two adopts device one's identity, exactly as importing an
    # identity backup would.
    device_two.public_key, device_two.secret_key = device_one.public_key, device_one.secret_key
    device_two.db.save_identity(device_two.public_key, device_two.secret_key)
    peer = make_node(tmp_path, "peer")
    for device in (device_one, device_two):
        befriend(device, peer)
    link(device_one, device_two, peer)
    try:
        yield device_one, device_two, peer
    finally:
        for node in (device_one, device_two, peer):
            node.db.close()


def test_sent_and_received_messages_sync_to_the_other_device(two_devices):
    device_one, device_two, peer = two_devices
    asyncio.run(device_one.connect_peer(peer.public_key))
    asyncio.run(device_one.send_chat(peer.public_key, "from device one"))

    # Device two also receives the peer's session_accept (the relay fans out
    # to every socket of the identity) and rejects it, since only the device
    # that made the offer holds the matching pending offer.
    assert [str(e) for e in device_two.delivery_errors] == [
        "Session accept does not match an active offer"]
    synced = [m["body"] for m in device_two.db.recent_messages()]
    assert synced == ["from device one"]
    assert device_two.db.recent_messages()[0]["direction"] == "out"

    asyncio.run(peer.send_chat(device_one.public_key, "reply to device one"))
    bodies = {m["body"]: m["direction"] for m in device_two.db.recent_messages()}
    # Device two never held a session with the peer, yet still sees the reply.
    assert bodies["reply to device one"] == "in"
    assert peer.public_key not in device_two.sessions


def test_clearing_unread_on_one_device_clears_it_on_the_other(two_devices):
    device_one, device_two, peer = two_devices
    asyncio.run(peer.connect_peer(device_one.public_key))
    asyncio.run(peer.send_chat(device_one.public_key, "unread message"))
    assert device_two.db.get_friends()[0]["unread"] == 1

    asyncio.run(device_one._dispatch_ui(device_one.ui, {
        "type": "clear_unread", "pubkey": peer.public_key,
    }))
    assert device_two.db.get_friends()[0]["unread"] == 0


def test_device_sync_from_another_identity_is_rejected(two_devices):
    _device_one, device_two, peer = two_devices
    frame = peer.signed_payload("device_sync", {"packet": {"nonce": b64e(b"n" * 12),
                                                          "ciphertext": b64e(b"c")}})
    with pytest.raises(ValueError, match="device sync"):
        asyncio.run(device_two.handle_relay_payload(peer.public_key, frame))


# ─── QuantumNode: calls ───────────────────────────────────────────────────────


def test_call_offer_answer_ice_and_hangup_flow(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))

    asyncio.run(alice.send_call_offer(bob.public_key, {"type": "offer", "sdp": "x"}, "audio"))
    incoming = bob.ui.frames_of_type("call_incoming")
    assert incoming and incoming[0]["media"] == "audio"
    call_id = incoming[0]["call_id"]

    asyncio.run(bob.send_call_answer(alice.public_key, {"type": "answer", "sdp": "y"}))
    assert alice.active_calls[bob.public_key]["state"] == "active"
    assert alice.ui.frames_of_type("call_answered")[0]["call_id"] == call_id

    asyncio.run(alice.send_call_ice(bob.public_key, {"candidate": "candidate:1"}))
    assert bob.ui.frames_of_type("call_ice")[0]["candidate"] == {"candidate": "candidate:1"}

    asyncio.run(bob.send_call_end(alice.public_key, "hangup"))
    assert bob.active_calls == {}
    assert alice.active_calls == {}
    assert alice.ui.frames_of_type("call_state")[-1]["state"] == "ended"


def test_second_offer_to_a_busy_peer_is_answered_with_busy(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    asyncio.run(alice.send_call_offer(bob.public_key, {"type": "offer"}))
    bob_call_id = bob.active_calls[alice.public_key]["call_id"]

    # Alice's node forgets the call (e.g. reload) and offers again; Bob is
    # still ringing, so he must reply busy instead of double-ringing.
    alice.active_calls.clear()
    asyncio.run(alice.send_call_offer(bob.public_key, {"type": "offer"}))
    busy = [f for f in alice.ui.frames_of_type("call_state") if f["state"] == "ended"]
    assert [f["reason"] for f in busy] == ["busy"]
    # Bob's busy reply lands while Alice is still inside send_call_offer, so it
    # clears the call she had just registered.
    assert alice.active_calls == {}
    assert bob.active_calls[alice.public_key]["call_id"] == bob_call_id
    assert len(bob.ui.frames_of_type("call_incoming")) == 1


def test_call_offer_requires_a_friend_and_valid_media(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    with pytest.raises(ValueError, match="media"):
        asyncio.run(alice.send_call_offer(bob.public_key, {}, "hologram"))
    stranger = "ab" * alice.expected_public_key_bytes
    with pytest.raises(ValueError, match="friend"):
        asyncio.run(alice.send_call_offer(stranger, {}))


def test_call_answer_without_an_incoming_call_is_refused(pair):
    alice, bob = pair
    with pytest.raises(ValueError, match="No incoming call"):
        asyncio.run(bob.send_call_answer(alice.public_key, {}))


def test_call_offers_from_non_friends_are_ignored(pair, tmp_path):
    alice, bob = pair
    alice.db.remove_friend(bob.public_key)
    offer = bob.signed_payload("call_offer", {
        "from": bob.public_key, "to": alice.public_key, "call_id": str(uuid.uuid4()),
        "media": "video", "sdp": {},
    })
    asyncio.run(alice.handle_call_offer(bob.public_key, offer))
    assert alice.active_calls == {}
    assert alice.ui.frames_of_type("call_incoming") == []


# ─── QuantumNode: files ───────────────────────────────────────────────────────


def test_chunked_file_transfer_reassembles_and_cleans_up_shards(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    payload = bytes(range(256)) * 6000  # ~1.5 MB: several chunks
    asyncio.run(alice.send_file(bob.public_key, "report.bin", b64e(payload)))

    listed = bob.db.recent_files()
    assert len(listed) == 1
    # recent_files() deliberately withholds the nonce; the full row carries it.
    assert "file_nonce" not in listed[0]
    file_id = listed[0]["file_id"]
    record = bob.db.get_file(file_id)
    stored = bob.decrypt_from_disk(
        Path(record["storage_path"]).read_bytes(), file_id, record["file_nonce"],
    )
    assert stored == payload
    assert bob.db.file_chunks(file_id) == []
    assert not (bob.files_dir / f"{file_id}.chunks").exists()
    assert bob.db.metrics()["file_manifests_received"] == 1
    assert bob.ui.frames_of_type("file")


def test_file_manifest_rejects_an_inconsistent_chunk_layout(pair):
    alice, bob = pair
    base = {"file_id": str(uuid.uuid4()), "filename": "x.bin", "from": alice.public_key,
            "to": bob.public_key, "size": 10, "sha256": "0" * 64,
            "total_chunks": 1, "chunk_size": MAX_CHUNK_BYTES}

    async def run(overrides, match):
        payload = alice.signed_payload("file_manifest", {**base, **overrides})
        with pytest.raises(ValueError, match=match):
            await bob.handle_file_manifest(alice.public_key, payload)

    asyncio.run(run({"size": -1}, "configured limit"))
    asyncio.run(run({"total_chunks": 5}, "chunk layout"))
    asyncio.run(run({"chunk_size": 1}, "chunk layout"))
    asyncio.run(run({"to": "elsewhere"}, "routing"))


def test_file_chunk_rejects_checksum_and_size_mismatches(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))

    def chunk_payload(chunk, **meta_overrides):
        counter = alice.db.next_send_counter(bob.public_key)
        meta = {"file_id": str(uuid.uuid4()), "filename": "x.bin", "from": alice.public_key,
                "to": bob.public_key, "size": len(chunk), "sha256": "0" * 64,
                "total_chunks": 1, "chunk_size": MAX_CHUNK_BYTES, "chunk_index": 0,
                "counter": counter,
                "chunk_sha256": hashlib.sha256(chunk).hexdigest()}
        meta.update(meta_overrides)
        msg_key = alice.crypto.derive_message_key(
            alice.sessions[bob.public_key], alice.public_key, bob.public_key, counter, "file-chunk")
        packet = alice.crypto.encrypt(msg_key, chunk, canonical_json(meta))
        return {"kind": "file_chunk", "payload": meta, "packet": packet}

    with pytest.raises(ValueError, match="checksum"):
        asyncio.run(bob.handle_file_chunk(alice.public_key, chunk_payload(b"abc", chunk_sha256="0" * 64)))
    with pytest.raises(ValueError, match="chunk index"):
        asyncio.run(bob.handle_file_chunk(alice.public_key, chunk_payload(b"abc", chunk_index=7)))
    with pytest.raises(ValueError, match="size mismatch"):
        asyncio.run(bob.handle_file_chunk(alice.public_key, chunk_payload(b"abc", size=99)))


def test_send_file_enforces_the_storage_quota(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    alice.max_storage_bytes = 16
    with pytest.raises(ValueError, match="quota"):
        asyncio.run(alice.send_file(bob.public_key, "big.bin", b64e(b"x" * 64)))
    assert alice.db.recent_files() == []


# ─── QuantumNode: groups ──────────────────────────────────────────────────────


def test_group_chat_fans_out_to_members_and_decrypts_with_the_epoch_key(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    group_id = str(uuid.uuid4())
    asyncio.run(alice._dispatch_ui(alice.ui, {
        "type": "create_group", "name": "Team", "members": [bob.public_key],
    }))
    group_id = alice.db.group_details_for(alice.public_key)[0]["group_id"]
    assert bob.db.group_members(group_id) == sorted(bob.db.group_members(group_id))
    assert alice.public_key in bob.db.group_members(group_id)

    asyncio.run(alice.send_group_chat(group_id, "hello team"))
    assert [m["body"] for m in bob.db.recent_messages() if m["group_id"] == group_id] == ["hello team"]


def test_group_chat_requires_membership_and_a_known_epoch_key(pair):
    alice, bob = pair
    group_id = str(uuid.uuid4())
    with pytest.raises(ValueError, match="not a member"):
        asyncio.run(alice.send_group_chat(group_id, "hello"))

    alice.db.create_group(group_id, "Solo", alice.public_key)
    meta = {"msg_id": str(uuid.uuid4()), "from": bob.public_key, "group_id": group_id,
            "epoch": 9, "sent_at": 0}
    frame = bob.signed_payload("group_chat", {"meta": meta, "packet": {
        "nonce": b64e(b"n" * 12), "ciphertext": b64e(b"c")}})
    bob.db.create_group(group_id, "Solo", bob.public_key)
    with pytest.raises(ValueError, match="epoch key"):
        asyncio.run(bob.handle_group_chat(bob.public_key, frame))


# ─── QuantumNode: UI dispatch ────────────────────────────────────────────────


def dispatch(node, msg):
    asyncio.run(node._dispatch_ui(node.ui, msg))


def test_friend_commands_validate_and_broadcast(pair):
    alice, bob = pair
    alice.db.remove_friend(bob.public_key)

    dispatch(alice, {"type": "add_friend", "pubkey": bob.public_key, "nickname": "Bob"})
    assert alice.db.get_friends()[0]["nickname"] == "Bob"

    dispatch(alice, {"type": "rename_friend", "pubkey": bob.public_key, "nickname": "Bobby"})
    assert alice.db.get_friends()[0]["nickname"] == "Bobby"

    dispatch(alice, {"type": "verify_friend", "pubkey": bob.public_key})
    assert alice.db.get_friends()[0]["verified"] == 1

    dispatch(alice, {"type": "remove_friend", "pubkey": bob.public_key})
    assert alice.db.get_friends() == []

    with pytest.raises(ValueError, match="your own public key"):
        dispatch(alice, {"type": "add_friend", "pubkey": alice.public_key})


def test_block_friend_command_drops_session_and_pending_offer(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))
    alice.pending_offers[bob.public_key] = chat_module.PendingOffer(
        bob.public_key, "sid", b"sk", 0, {})

    dispatch(alice, {"type": "block_friend", "pubkey": bob.public_key})
    assert bob.public_key not in alice.sessions
    assert bob.public_key not in alice.pending_offers
    assert alice.db.get_friends()[0]["blocked"] == 1


def test_unknown_ui_command_is_rejected(pair):
    alice, _bob = pair
    with pytest.raises(ValueError, match="Unknown command"):
        dispatch(alice, {"type": "self_destruct"})


def test_delete_message_command_is_idempotent_and_notifies_clients(pair):
    alice, _bob = pair
    alice.db.save_message("m1", alice.public_key, "bye", "out", recipient=alice.public_key)
    dispatch(alice, {"type": "delete_message", "msg_id": "m1"})
    assert alice.db.recent_messages() == []
    assert alice.ui.frames_of_type("message_deleted")[0]["msg_id"] == "m1"
    with pytest.raises(ValueError, match="no longer available"):
        dispatch(alice, {"type": "delete_message", "msg_id": "m1"})


def test_load_more_messages_and_search_reply_only_to_the_requesting_socket(pair):
    alice, _bob = pair
    for i in range(4):
        alice.db.save_message(f"m{i}", alice.public_key, f"body-{i}", "out",
                              recipient=alice.public_key)
    newest_id = alice.db.recent_messages()[-1]["id"]

    dispatch(alice, {"type": "load_more_messages", "before_id": newest_id})
    history = alice.ui.frames_of_type("history")
    assert [m["body"] for m in history[0]["messages"]] == ["body-0", "body-1", "body-2"]

    dispatch(alice, {"type": "search_messages", "query": "body-2"})
    results = alice.ui.frames_of_type("search_results")
    assert [m["body"] for m in results[0]["results"]] == ["body-2"]


def test_export_backup_requires_a_passphrase_and_is_sent_privately(pair):
    alice, _bob = pair
    with pytest.raises(ValueError, match="at least 8"):
        dispatch(alice, {"type": "export_backup", "passphrase": "short"})

    other_client = FakeSocket()
    alice.ui_clients.add(other_client)
    dispatch(alice, {"type": "export_backup", "passphrase": "a good passphrase"})
    backups = alice.ui.frames_of_type("identity_backup")
    assert backups and backups[0]["backup"].startswith("QCID1:")
    assert other_client.frames() == [], "the backup blob must never be broadcast"

    restored_pk, restored_sk = chat_module.unpack_identity_backup(
        backups[0]["backup"], "a good passphrase")
    assert (restored_pk, restored_sk) == (alice.public_key, alice.secret_key)


def test_import_backup_refuses_to_overwrite_an_active_identity(pair, tmp_path):
    alice, bob = pair
    blob = chat_module.pack_identity_backup(bob.public_key, bob.secret_key, "passphrase!")
    with pytest.raises(ValueError, match="brand-new install"):
        dispatch(alice, {"type": "import_backup", "backup": blob, "passphrase": "passphrase!"})

    fresh = make_node(tmp_path, "fresh")
    try:
        asyncio.run(fresh._dispatch_ui(fresh.ui, {
            "type": "import_backup", "backup": blob, "passphrase": "passphrase!",
        }))
        assert fresh.public_key == bob.public_key
        assert fresh.db.load_identity()[0] == bob.public_key
        assert fresh.sessions == {}
    finally:
        fresh.db.close()


def test_add_group_member_command_requires_ownership_and_friendship(pair):
    alice, bob = pair
    group_id = str(uuid.uuid4())
    bob.db.create_group(group_id, "Bob's group", bob.public_key)
    with pytest.raises(ValueError, match="owner"):
        dispatch(alice, {"type": "add_group_member", "group_id": group_id,
                         "pubkey": bob.public_key})

    alice.db.create_group(group_id, "Alice's group", alice.public_key)
    stranger = "ab" * alice.expected_public_key_bytes
    with pytest.raises(ValueError, match="friend"):
        dispatch(alice, {"type": "add_group_member", "group_id": group_id, "pubkey": stranger})


def test_refresh_command_broadcasts_the_full_state(pair):
    alice, _bob = pair
    dispatch(alice, {"type": "refresh"})
    state = alice.ui.frames_of_type("state")[-1]
    assert state["public_key"] == alice.public_key
    assert state["version"] == chat_module.VERSION


# ─── QuantumNode: UI socket lifecycle and direct transport ───────────────────


def test_handle_ui_rejects_an_unauthenticated_socket(pair):
    alice, _bob = pair
    socket = FakeSocket()
    socket.path = "/?token=wrong"
    socket.request_headers = {}
    asyncio.run(alice.handle_ui(socket))
    assert socket.closed == (1008, "Unauthorized UI socket")
    assert socket not in alice.ui_clients


def test_handle_ui_replies_with_an_error_notice_for_a_bad_command(pair):
    alice, _bob = pair
    socket = FakeSocket([json.dumps({"type": "nonsense"}), "{not json"])
    socket.path = f"/?token={alice.ui_token}"
    socket.request_headers = {}
    asyncio.run(alice.handle_ui(socket))
    notices = socket.frames_of_type("notice")
    assert len(notices) == 2
    assert all(n["level"] == "error" for n in notices)
    # The socket is registered while it is live and dropped afterwards.
    assert socket not in alice.ui_clients
    assert socket.frames_of_type("state")


def test_direct_peer_frame_is_verified_before_it_is_dispatched(pair):
    alice, bob = pair
    asyncio.run(alice.connect_peer(bob.public_key))

    captured = {}

    async def capture(peer, payload):
        captured["peer"] = peer
        captured["payload"] = payload

    bob.handle_relay_payload = capture
    hello = {"from": alice.public_key, "to": bob.public_key, "sent_at": chat_module.utc_ts(),
             "payload": {"kind": "typing"}}
    sig = b64e(alice.crypto.sign(alice.secret_key, canonical_json(hello)))
    socket = FakeSocket([json.dumps({"type": "direct", **hello, "signature": sig})])
    asyncio.run(bob.handle_direct_peer(socket))
    assert socket.frames_of_type("direct_ack")
    assert captured["peer"] == alice.public_key
    assert bob.db.metrics()["direct_received"] == 1


def test_direct_peer_rejects_a_forged_signature_and_a_rate_flood(pair):
    alice, bob = pair
    hello = {"from": alice.public_key, "to": bob.public_key, "sent_at": chat_module.utc_ts(),
             "payload": {"kind": "typing"}}
    socket = FakeSocket([json.dumps({"type": "direct", **hello, "signature": b64e(b"\x00" * 64)})])
    socket.remote_address = ("203.0.113.9", 1234)
    asyncio.run(bob.handle_direct_peer(socket))
    # Rejections answer with a generic error frame so an unauthenticated
    # prober cannot distinguish "bad signature" from "not a friend".
    assert any(f.get("type") == "error" and f.get("text") == "Frame rejected"
               for f in socket.frames())
    assert bob.db.metrics()["direct_rejected"] == 1

    # Rate limiting is enforced per *frame* now that direct connections are
    # long-lived and carry many frames, so a flooded keep-alive connection is
    # closed as soon as any frame exceeds the bucket.
    flood = FakeSocket([
        json.dumps({"type": "direct", **hello, "signature": b64e(b"\x00" * 64)})
        for _ in range(3)
    ])
    flood.remote_address = ("203.0.113.9", 1234)
    bob._direct_rate["203.0.113.9"] = [chat_module.utc_ts()] * 40
    asyncio.run(bob.handle_direct_peer(flood))
    assert flood.closed == (1008, "Rate limit exceeded")


# ─── QuantumNode: signaling client ───────────────────────────────────────────


def test_peer_list_updates_transports_and_flushes_the_outbox(pair):
    alice, bob = pair
    envelope = {"type": "relay", "to": bob.public_key, "payload": {"kind": "typing"}}
    alice.db.queue_outbox(bob.public_key, envelope)
    alice.signaling_ws = FakeSocket()

    asyncio.run(alice._handle_signaling_message({"type": "peers", "peers": {
        bob.public_key: {"relay_alias": bob.relay_alias, "direct_url": "ws://127.0.0.1:9999"},
        alice.public_key: {"relay_alias": alice.relay_alias, "direct_url": None},
    }}))

    assert alice.online_peers == {bob.public_key}
    assert alice.peer_direct[bob.public_key] == "ws://127.0.0.1:9999"
    assert alice.db.get_friends()[0]["direct_url"] == "ws://127.0.0.1:9999"
    assert alice.signaling_ws.frames() == [envelope]
    assert alice.db.queued_outbox(bob.public_key) == []


def test_signaling_errors_surface_as_ui_notices_and_lists_are_accepted(pair):
    alice, bob = pair
    asyncio.run(alice._handle_signaling_message({"type": "peers", "peers": [bob.public_key,
                                                                           alice.public_key]}))
    assert alice.online_peers == {bob.public_key}

    asyncio.run(alice._handle_signaling_message({"type": "error", "text": "Rate limit exceeded"}))
    notice = alice.ui.frames_of_type("notice")[-1]
    assert notice["level"] == "error"
    assert notice["text"] == "Rate limit exceeded"


def test_relay_payload_must_be_an_object_with_a_known_kind(pair):
    alice, bob = pair
    with pytest.raises(ValueError, match="must be an object"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, ["not", "an", "object"]))
    # An unknown kind is ignored rather than raising, so a newer peer's
    # extension frames don't tear down an older node's connection.
    asyncio.run(bob.handle_relay_payload(alice.public_key, {"kind": "quantum_teleport"}))


def test_delivery_ack_and_group_invite_metadata_are_validated(pair):
    alice, bob = pair
    misrouted_ack = alice.signed_payload("delivery_ack", {
        "from": alice.public_key, "to": "elsewhere", "msg_id": "m1"})
    with pytest.raises(ValueError, match="routing mismatch"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, misrouted_ack))

    invite = alice.signed_payload("group_invite", {
        "group_id": str(uuid.uuid4()), "name": "Team", "members": [alice.public_key],
        "from": alice.public_key, "to": bob.public_key, "epoch": 1})
    with pytest.raises(ValueError, match="metadata mismatch"):
        asyncio.run(bob.handle_relay_payload(alice.public_key, invite))
