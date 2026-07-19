#!/usr/bin/env python3
"""Integration test for multi-device sync, WebRTC call signaling, search,
and parallel file transfer. Same style/pattern as e2e_test.py."""

from __future__ import annotations
import asyncio
import sys
import time
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
WORKDIR = ROOT / "scripts" / "new-features-run"
WORKDIR.mkdir(parents=True, exist_ok=True)

PORTS = {
    "signaling": 28100,
    "alice_http": 28101, "alice_ui": 28102, "alice_direct": 28103,
    "alice2_http": 28104, "alice2_ui": 28105, "alice2_direct": 28106,
    "bob_http": 28111, "bob_ui": 28112, "bob_direct": 28113,
}

sys.path.insert(0, str(ROOT))
import chat
import logging
logging.basicConfig(level=logging.WARNING, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')


async def run_node(db_path, http_port, ui_port, direct_port, signaling_port):
    node = chat.QuantumNode(
        db_path, f"ws://127.0.0.1:{signaling_port}",
        direct_url=f"ws://127.0.0.1:{direct_port}", enable_direct=True,
        max_storage_bytes=1024 * 1024 * 1024,
    )
    node.allow_remote_ui = False
    node._test_httpd = chat.start_http(
        node, "127.0.0.1", http_port, ui_port, require_http_auth=False
    )
    node._test_tasks = [
        asyncio.create_task(chat.start_ui_ws(node, "127.0.0.1", ui_port)),
        asyncio.create_task(chat.start_direct_peer(node, "127.0.0.1", direct_port)),
        asyncio.create_task(node.connect_signaling_loop()),
    ]
    return node


async def wait_until(predicate, timeout=8.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.1)
    return False


async def main():
    print("=== New features test: multi-device sync, calls, search ===")
    for f in WORKDIR.glob("*"):
        if f.is_file():
            f.unlink()

    signaling_task = asyncio.create_task(chat.start_signaling("127.0.0.1", PORTS["signaling"]))
    await asyncio.sleep(0.5)

    alice1 = await run_node(str(WORKDIR / "alice1.db"), PORTS["alice_http"], PORTS["alice_ui"],
                            PORTS["alice_direct"], PORTS["signaling"])
    bob = await run_node(str(WORKDIR / "bob.db"), PORTS["bob_http"], PORTS["bob_ui"],
                         PORTS["bob_direct"], PORTS["signaling"])

    failures = []
    def check(name, ok, detail=""):
        status = "PASS" if ok else "FAIL"
        print(f"  [{status}] {name}" + (f": {detail}" if detail else ""))
        if not ok:
            failures.append(name)

    await wait_until(lambda: alice1.signaling_ws is not None)
    await wait_until(lambda: bob.signaling_ws is not None)

    # --- Set up Alice's second device, sharing the same identity ---
    backup = chat.pack_identity_backup(alice1.public_key, alice1.secret_key, "correct horse battery staple")
    alice2 = await run_node(str(WORKDIR / "alice2.db"), PORTS["alice2_http"], PORTS["alice2_ui"],
                            PORTS["alice2_direct"], PORTS["signaling"])
    new_pk, new_sk = chat.unpack_identity_backup(backup, "correct horse battery staple")
    alice2.public_key, alice2.secret_key = new_pk, new_sk
    alice2.db.save_identity(alice2.public_key, alice2.secret_key)
    check("alice-two-devices-share-one-identity", alice1.public_key == alice2.public_key)

    # Re-register alice2's connection under the shared identity (simulates
    # what connect_signaling_loop does on (re)connect).
    if alice2.signaling_ws is None:
        await wait_until(lambda: alice2.signaling_ws is not None)

    await asyncio.sleep(0.5)
    both_online = await wait_until(
        lambda: alice1.public_key in bob.online_peers if hasattr(bob, "online_peers") else False
    )
    check("bob-sees-alice-online-with-two-devices-registered", both_online)

    alice1.db.add_friend(bob.public_key, "Bob")
    bob.db.add_friend(alice1.public_key, "Alice")
    await asyncio.sleep(0.5)

    await alice1.connect_peer(bob.public_key)
    session_ok = await wait_until(lambda: bob.public_key in alice1.sessions)
    check("alice-device-1-establishes-session-with-bob", session_ok)

    # --- Multi-device sync: message sent from device 1 shows up on device 2 ---
    test_msg = f"multi-device sync check {time.time()}"
    await alice1.send_chat(bob.public_key, test_msg)

    synced = await wait_until(lambda: any(
        m["body"] == test_msg and m["direction"] == "out" for m in alice2.db.recent_messages()
    ), timeout=6)
    check("alice-device-2-receives-sync-of-message-sent-from-device-1", synced)

    # Bob replies; make sure it round-trips to Alice's device 1 as normal,
    # and *also* syncs to Alice's device 2 (which never held Bob's session).
    reply = "got your multi-device test message"
    await bob.send_chat(alice1.public_key, reply)
    got_reply_d1 = await wait_until(lambda: any(
        m["body"] == reply and m["direction"] == "in" for m in alice1.db.recent_messages()
    ), timeout=6)
    check("alice-device-1-receives-bobs-reply", got_reply_d1)
    got_reply_d2 = await wait_until(lambda: any(
        m["body"] == reply and m["direction"] == "in" for m in alice2.db.recent_messages()
    ), timeout=6)
    check("alice-device-2-receives-sync-of-bobs-reply-despite-no-session", got_reply_d2)

    # --- Message search ---
    results = alice1.db.search_messages("multi-device sync")
    check("search-finds-sent-message-by-substring",
          any(r["body"] == test_msg for r in results), f"{len(results)} results")
    results_none = alice1.db.search_messages("this text was never sent")
    check("search-returns-empty-for-no-match", results_none == [])

    # --- Call signaling: Bob calls Alice (device 1), full offer/answer/ice/end ---
    fake_sdp_offer = {"type": "offer", "sdp": "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n..."}
    await bob.send_call_offer(alice1.public_key, fake_sdp_offer, media="video")
    got_offer = await wait_until(lambda: alice1.public_key in bob.active_calls)
    check("bob-call-offer-recorded-locally", got_offer)
    got_incoming = await wait_until(lambda: bob.public_key in alice1.active_calls)
    check("alice-device-1-receives-incoming-call", got_incoming,
          f"active_calls={list(alice1.active_calls.keys())}")
    check("alice-does-not-see-a-phantom-call-on-device-2",
          bob.public_key not in alice2.active_calls)

    fake_sdp_answer = {"type": "answer", "sdp": "v=0\r\no=- 2 2 IN IP4 127.0.0.1\r\n..."}
    await alice1.send_call_answer(bob.public_key, fake_sdp_answer)
    call_active = await wait_until(lambda: bob.active_calls.get(alice1.public_key, {}).get("state") == "active")
    check("bobs-call-becomes-active-after-answer", call_active)

    fake_candidate = {"candidate": "candidate:1 1 UDP 2130706431 127.0.0.1 12345 typ host", "sdpMid": "0", "sdpMLineIndex": 0}
    await alice1.send_call_ice(bob.public_key, fake_candidate)
    await asyncio.sleep(0.5)  # ICE is fire-and-forget/ephemeral; just make sure it doesn't raise

    # A second, simultaneous offer from Bob while a call is already active should be rejected as busy.
    try:
        await bob.send_call_offer(alice1.public_key, fake_sdp_offer, media="video")
        check("second-offer-while-in-a-call-raises", False, "no exception raised")
    except ValueError:
        check("second-offer-while-in-a-call-raises", True)

    await alice1.send_call_end(bob.public_key, reason="hangup")
    ended = await wait_until(lambda: alice1.public_key not in bob.active_calls)
    check("call-ends-cleanly-on-both-sides", ended and bob.public_key not in alice1.active_calls)

    # --- Parallel chunked file transfer (validates FILE_CHUNK_CONCURRENCY change) ---
    import base64
    import hashlib as _hashlib
    big = bytes((i % 251) for i in range(int(2.5 * chat.MAX_CHUNK_BYTES)))  # spans 3 chunks, non-uniform bytes
    encoded = base64.b64encode(big).decode()
    await bob.send_file(alice1.public_key, "bigfile.bin", encoded, content_type="application/octet-stream")

    received_file = None
    deadline = time.time() + 10
    while time.time() < deadline:
        for f in alice1.db.recent_files():
            if f.get("sender_pubkey") == bob.public_key and f.get("filename") == "bigfile.bin":
                received_file = alice1.db.get_file(f["file_id"])
                break
        if received_file:
            break
        await asyncio.sleep(0.2)
    check("multi-chunk-file-arrives", received_file is not None)
    if received_file:
        stored_bytes = Path(received_file["storage_path"]).read_bytes()
        decrypted = alice1.decrypt_from_disk(stored_bytes, received_file["file_id"], received_file.get("file_nonce"))
        check("multi-chunk-file-reassembles-correctly-despite-out-of-order-parallel-chunks",
              _hashlib.sha256(decrypted).hexdigest() == _hashlib.sha256(big).hexdigest(),
              f"len={len(decrypted)} vs {len(big)}")

    print("Shutting down…")
    for n in (alice1, alice2, bob):
        n._shutting_down = True
        n._test_httpd.shutdown()
        n._test_httpd.server_close()
        for task in n._test_tasks:
            task.cancel()
    signaling_task.cancel()
    await asyncio.gather(
        signaling_task,
        *(task for n in (alice1, alice2, bob) for task in n._test_tasks),
        return_exceptions=True,
    )
    alice1.db.close()
    alice2.db.close()
    bob.db.close()

    total = 14
    print(f"\n=== New features summary: {total - len(failures)}/{total} passed, {len(failures)} failed ===")
    if failures:
        print("Failed checks:")
        for n in failures:
            print(f"  - {n}")
    return 0 if not failures else 1


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
