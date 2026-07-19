#!/usr/bin/env python3
"""Live smoke test for Quantum Chat v3.1.0.

Starts a fresh node on a private DB + ports, hits /health, /version,
/, and an invalid /files/<bad-id>, then shuts it down with SIGTERM to
verify the graceful-shutdown path. Prints a summary at the end."""

from __future__ import annotations
import os
import signal
import subprocess
import sys
import time
import urllib.request
import urllib.error
import json
from pathlib import Path

ROOT = Path(__file__).parent.resolve()
WORKDIR = ROOT / "scripts" / "smoke-run"
WORKDIR.mkdir(parents=True, exist_ok=True)

# Use private ports so we don't clash with anything else.
HTTP_PORT = 18080
UI_WS_PORT = 18765
SIGNALING_PORT = 18766
DIRECT_PORT = 18768

if __name__ == "__main__":
    env = dict(os.environ)
    env["QUANTUM_CHAT_KEY_MODE"] = "file"  # skip passphrase wrapping for the smoke test

    cmd = [
        sys.executable, "chat.py",
        "--db", str(WORKDIR / "smoke.db"),
        "--http-port", str(HTTP_PORT),
        "--ui-ws-port", str(UI_WS_PORT),
        "--signaling-port", str(SIGNALING_PORT),
        "--signaling-url", f"ws://127.0.0.1:{SIGNALING_PORT}",
        "--direct-port", str(DIRECT_PORT),
        "--no-browser",
        "--with-signaling",
        "--log-level", "INFO",
    ]
    print(f"Starting: {' '.join(cmd)}")
    proc = subprocess.Popen(
        cmd, cwd=str(ROOT), env=env,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )

    results = []
    def check(name, ok, detail=""):
        results.append((name, ok, detail))
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f": {detail}" if detail else ""))

    try:
        # Wait for the server to come up.
        base = f"http://127.0.0.1:{HTTP_PORT}"
        deadline = time.time() + 15
        ready = False
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(f"{base}/version", timeout=1) as r:
                    if r.status == 200:
                        ready = True
                        break
            except Exception:
                time.sleep(0.2)
        check("server-starts-and-serves-/version", ready)
        if not ready:
            # Print whatever the server logged to stderr/stdout for debugging.
            try:
                out, _ = proc.communicate(timeout=2)
                print("--- server output ---")
                print(out[-3000:])
            except Exception:
                pass
            sys.exit(1)

        # /version
        try:
            with urllib.request.urlopen(f"{base}/version") as r:
                data = json.loads(r.read().decode())
            check("version-payload-has-version-and-app",
                  data.get("version") == "3.2.0" and data.get("app") == "Quantum Chat",
                  str(data))
        except Exception as e:
            check("version-payload-has-version-and-app", False, str(e))

        # /health
        try:
            with urllib.request.urlopen(f"{base}/health") as r:
                data = json.loads(r.read().decode())
            check("health-returns-ok-status",
                  data.get("status") == "ok" and "fingerprint" in data and "metrics" in data,
                  f"status={data.get('status')}")
            check("health-reports-zero-friends-on-fresh-db",
                  data.get("friends") == 0 and data.get("active_sessions") == 0,
                  f"friends={data.get('friends')} sessions={data.get('active_sessions')}")
        except Exception as e:
            check("health-returns-ok-status", False, str(e))

        # / (UI HTML)
        try:
            req = urllib.request.Request(f"{base}/")
            with urllib.request.urlopen(req) as r:
                body = r.read().decode("utf-8")
                ct = r.headers.get("Content-Type", "")
            check("root-serves-html-with-token",
                  "text/html" in ct and "__UI_TOKEN__" not in body and "Quantum Chat" in body,
                  f"content-type={ct}")
            # Check security headers
            xf = r.headers.get("X-Frame-Options", "")
            xs = r.headers.get("X-XSS-Protection", "")
            csp = r.headers.get("Content-Security-Policy", "")
            check("root-has-X-Frame-Options-DENY", xf == "DENY", xf)
            check("root-has-X-XSS-Protection-block", xs == "1; mode=block", xs)
            check("root-has-CSP-with-frame-ancestors-none",
                  "frame-ancestors 'none'" in csp, csp[:80])
            check("root-has-media-src-for-voice-messages",
                  "media-src" in csp, csp[:80])
        except Exception as e:
            check("root-serves-html-with-token", False, str(e))

        # /files/<bad-id> -> 404
        try:
            urllib.request.urlopen(f"{base}/files/not-a-uuid")
            check("files-bad-id-returns-404", False, "no error raised")
        except urllib.error.HTTPError as e:
            check("files-bad-id-returns-404", e.code == 404, f"code={e.code}")
        except Exception as e:
            check("files-bad-id-returns-404", False, str(e))

        # HEAD /health
        try:
            req = urllib.request.Request(f"{base}/health", method="HEAD")
            with urllib.request.urlopen(req) as r:
                check("head-health-returns-200-no-body",
                      r.status == 200 and r.read() == b"",
                      f"status={r.status}")
        except Exception as e:
            check("head-health-returns-200-no-body", False, str(e))

        # OPTIONS /  (CORS preflight)
        try:
            req = urllib.request.Request(f"{base}/", method="OPTIONS")
            with urllib.request.urlopen(req) as r:
                check("options-returns-204",
                      r.status == 204 and r.headers.get("Allow") == "GET, HEAD, OPTIONS",
                      f"status={r.status} allow={r.headers.get('Allow')}")
        except Exception as e:
            check("options-returns-204", False, str(e))

        # Trigger graceful shutdown via SIGTERM.
        print(f"Sending SIGTERM to pid {proc.pid}…")
        proc.send_signal(signal.SIGTERM)
        try:
            rc = proc.wait(timeout=8)
            check("graceful-shutdown-returns-clean-exit", rc == 0, f"rc={rc}")
        except subprocess.TimeoutExpired:
            proc.kill()
            check("graceful-shutdown-returns-clean-exit", False, "timed out, had to kill")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()

    # Print summary.
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    print(f"\n=== Smoke summary: {passed} passed, {failed} failed ===")
    sys.exit(0 if failed == 0 else 1)
