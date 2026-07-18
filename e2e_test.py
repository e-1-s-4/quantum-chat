#!/usr/bin/env python3
"""End-to-end test: start two nodes that share a signaling server, add each
other as friends, establish a session, and exchange an encrypted chat message.

This exercises the real pqcrypto + Kyber + Dilithium + AES-GCM crypto path
end to end, including the critical verify() fix from v3.1.0."""

from __future__ import annotations
import asyncio
import json
import os
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
WORKDIR = ROOT / "scripts" / "e2e-run"
WORKDIR.mkdir(parents=True, exist_ok=True)

# Use private ports.
PORTS = {
    "signaling": 28000,
    "alice_http": 28001, "alice_ui": 28002, "alice_direct": 28003,
    "bob_http":   28011, "bob_ui":   28012, "bob_direct":   28013,
}

sys.path.insert(0, str(ROOT))
import chat
import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')


async def run_node(db_path: str, http_port: int, ui_port: int, direct_port: int,
                   signaling_port: int) -> chat.QuantumNode:
    """Construct a QuantumNode and start its background tasks (UI WS, direct
    peer listener, signaling client). The caller is responsible for shutting
    the node down."""
    direct_url = f"ws://127.0.0.1:{direct_port}"
    node = chat.QuantumNode(
        db_path, f"ws://127.0.0.1:{signaling_port}",
        direct_url=direct_url, enable_direct=True,
        max_storage_bytes=1024 * 1024 * 1024,
    )
    node.allow_remote_ui = False
    # Start the HTTP server (synchronous, in a thread).
    chat.start_http(node, "127.0.0.1", http_port, ui_port, require_http_auth=False)
    # Start the UI WS, direct peer, and signaling client tasks.
    asyncio.create_task(chat.start_ui_ws(node, "127.0.0.1", ui_port))
    asyncio.create_task(chat.start_direct_peer(node, "127.0.0.1", direct_port))
    asyncio.create_task(node.connect_signaling_loop())
    return node


async def wait_for_signaling(node: chat.QuantumNode, timeout: float = 10.0) -> bool:
    """Wait until the node has connected to the signaling server."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if node.signaling_ws is not None:
            return True
        await asyncio.sleep(0.1)
    return False


async def wait_for_peer_online(node: chat.QuantumNode, peer_pubkey: str,
                                timeout: float = 10.0) -> bool:
    """Wait until the node sees the given peer as online."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer_pubkey in node.online_peers:
            return True
        await asyncio.sleep(0.1)
    return False


async def wait_for_session(node: chat.QuantumNode, peer_pubkey: str,
                            timeout: float = 10.0) -> bool:
    """Wait until a pairwise session with peer_pubkey is established."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if peer_pubkey in node.sessions:
            return True
        await asyncio.sleep(0.1)
    return False


async def main():
    print("=== Quantum Chat v3.1.0 end-to-end test ===")
    # Clear any old DBs.
    for f in WORKDIR.glob("*"):
        if f.is_file():
            f.unlink()

    # Start the signaling server in-process.
    print("Starting signaling server on port", PORTS["signaling"])
    signaling_task = asyncio.create_task(
        chat.start_signaling("127.0.0.1", PORTS["signaling"])
    )
    await asyncio.sleep(0.5)

    # Start Alice and Bob.
    print("Starting Alice (http:", PORTS["alice_http"], ")")
    alice = await run_node(
        str(WORKDIR / "alice.db"), PORTS["alice_http"], PORTS["alice_ui"],
        PORTS["alice_direct"], PORTS["signaling"],
    )
    print(f"  Alice pubkey: {alice.public_key[:32]}…")
    print("Starting Bob (http:", PORTS["bob_http"], ")")
    bob = await run_node(
        str(WORKDIR / "bob.db"), PORTS["bob_http"], PORTS["bob_ui"],
        PORTS["bob_direct"], PORTS["signaling"],
    )
    print(f"  Bob pubkey:   {bob.public_key[:32]}…")

    failures = []
    def check(name, ok, detail=""):
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f": {detail}" if detail else ""))
        if not ok:
            failures.append(name)

    # Wait for both to connect to signaling.
    a_ok = await wait_for_signaling(alice)
    b_ok = await wait_for_signaling(bob)
    check("alice-connects-to-signaling", a_ok)
    check("bob-connects-to-signaling", b_ok)

    # Each adds the other as a friend.
    alice.db.add_friend(bob.public_key, "Bob")
    bob.db.add_friend(alice.public_key, "Alice")
    check("alice-adds-bob-as-friend", alice.db.is_friend(bob.public_key))
    check("bob-adds-alice-as-friend", bob.db.is_friend(alice.public_key))

    # Wait for both to see each other as online (via the relay's peer list).
    await asyncio.sleep(1.0)
    a_sees_b = await wait_for_peer_online(alice, bob.public_key, timeout=5)
    b_sees_a = await wait_for_peer_online(bob, alice.public_key, timeout=5)
    check("alice-sees-bob-online", a_sees_b)
    check("bob-sees-alice-online", b_sees_a)

    # Alice initiates a session handshake.
    await alice.connect_peer(bob.public_key)
    session_ok = await wait_for_session(alice, bob.public_key, timeout=5)
    check("alice-establishes-session-with-bob", session_ok)
    # Bob should also have the session.
    bob_session_ok = await wait_for_session(bob, alice.public_key, timeout=3)
    check("bob-establishes-session-with-alice", bob_session_ok)

    if not (session_ok and bob_session_ok):
        print("FATAL: no session, can't send chat. Aborting.")
        failures.append("session-establishment")
    else:
        # Alice sends Bob a message.
        test_msg = f"Hello Bob, this is a v3.1.0 end-to-end test message at {time.time()}"
        await alice.send_chat(bob.public_key, test_msg)
        # Wait for Bob to receive it.
        received = None
        deadline = time.time() + 5
        while time.time() < deadline:
            msgs = bob.db.recent_messages()
            for m in msgs:
                if m["sender_pubkey"] == alice.public_key and m["direction"] == "in":
                    received = m
                    break
            if received:
                break
            await asyncio.sleep(0.1)
        check("bob-receives-encrypted-message-from-alice",
              received is not None and received["body"] == test_msg,
              f"received={received['body'][:50] if received else None}…")

        # Bob sends a reply.
        reply = "Hi Alice! Message received loud and clear."
        await bob.send_chat(alice.public_key, reply)
        received_reply = None
        deadline = time.time() + 5
        while time.time() < deadline:
            for m in alice.db.recent_messages():
                if m["sender_pubkey"] == bob.public_key and m["direction"] == "in":
                    received_reply = m
                    break
            if received_reply:
                break
            await asyncio.sleep(0.1)
        check("alice-receives-encrypted-reply-from-bob",
              received_reply is not None and received_reply["body"] == reply,
              f"received={received_reply['body'][:50] if received_reply else None}…")

        # Verify delivery ack was processed (Alice's message should now be marked delivered_to_peer).
        await asyncio.sleep(0.5)
        alice_msgs = alice.db.recent_messages()
        acked = any(m["body"] == test_msg and m["status"] in ("delivered_to_peer", "delivered")
                    for m in alice_msgs)
        check("alice-receives-delivery-ack-from-bob", acked)

        # Test the verify() fix in a real flow: send a read receipt, which
        # is signed and verified on the receiving end.
        bob_msg_id = next((m["msg_id"] for m in alice.db.recent_messages()
                           if m["sender_pubkey"] == bob.public_key), None)
        if bob_msg_id:
            await alice.send_read_receipt(bob.public_key, bob_msg_id)
            await asyncio.sleep(0.5)
            bob_msg = next((m for m in bob.db.recent_messages()
                            if m["msg_id"] == bob_msg_id), None)
            check("bob-receives-signed-read-receipt",
                  bob_msg is not None and bob_msg["status"] == "read"
                  and bob_msg["read_at"] is not None)
        else:
            check("bob-receives-signed-read-receipt", False, "no msg to mark read")

        # Test reactions (signed payload, exercises verify path).
        if received:
            await bob.send_reaction(alice.public_key, received["msg_id"], "👍", "add")
            await asyncio.sleep(0.5)
            reactions = alice.db.get_reactions([received["msg_id"]])
            check("alice-receives-signed-reaction",
                  bool(reactions.get(received["msg_id"])),
                  f"reactions={reactions}")

    # Test nickname renaming (DB-level).
    alice.db.rename_friend(bob.public_key, "Bobby")
    friends = alice.db.get_friends()
    renamed = next((f for f in friends if f["pubkey"] == bob.public_key), None)
    check("alice-can-rename-bob", renamed and renamed["nickname"] == "Bobby")

    # Test block/unblock drops session.
    alice.db.block_friend(bob.public_key, blocked=True)
    blocked_session_dropped = alice.db.get_session(bob.public_key) is None
    alice.db.block_friend(bob.public_key, blocked=False)
    check("blocking-bob-drops-alice-session-row", blocked_session_dropped)

    # Clean shutdown.
    print("Shutting down…")
    alice._shutting_down = True
    bob._shutting_down = True
    signaling_task.cancel()
    try:
        await asyncio.sleep(0.5)
    except Exception:
        pass
    alice.db.close()
    bob.db.close()

    passed = sum(1 for n in failures if n not in failures)  # silly
    total = len(failures) + (15 - len(failures))  # we ran ~15 checks
    print(f"\n=== E2E summary: {15 - len(failures)}/15 passed, {len(failures)} failed ===")
    if failures:
        print("Failed checks:")
        for n in failures:
            print(f"  - {n}")
    return 0 if not failures else 1


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
