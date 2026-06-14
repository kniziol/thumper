#!/usr/bin/env python3
"""Standalone receiver for the Thumper generic webhook plugin.

Verifies the replay-resistant timestamped signature (see plugins/alert/webhook),
rejects stale or forged requests, and pretty-prints each event. Stdlib only - no
dependency on the thumper package - so it can be dropped onto any box.

Usage:
    python tools/webhook_test_server.py --port 9000 --secret s3cr3t
    python tools/webhook_test_server.py          # no secret: accept unsigned
"""
import argparse
import hashlib
import hmac
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

MAX_AGE = 300  # seconds backward: how long a signed payload stays acceptable
MAX_SKEW = 60  # seconds forward: clock-drift slack only (see verify_timestamped)


def check_signature(secret, *, ts, body, signature, now):
    """Return (ok: bool, reason: str). With no secret, accept anything.

    Asymmetric window, mirroring services.signing.verify_timestamped: a generous
    backward tolerance for slow delivery, a tight forward cap so a future-dated
    timestamp can't stretch its own replay window."""
    if not secret:
        return True, "ok"
    if ts is None or signature is None:
        return False, "missing signature headers"
    if ts > now + MAX_SKEW:
        return False, f"future timestamp ({ts - now}s ahead)"
    if now - ts > MAX_AGE:
        return False, f"stale timestamp ({now - ts}s old)"
    expected = "sha256=" + hmac.new(secret.encode(), f"{ts}.".encode() + body,
                                    hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        return False, "bad signature"
    return True, "ok"


def _make_handler(secret):
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("content-length", 0))
            body = self.rfile.read(length)
            ts_raw = self.headers.get("X-Thumper-Timestamp")
            ts = int(ts_raw) if ts_raw and ts_raw.isdigit() else None
            sig = self.headers.get("X-Thumper-Signature")

            ok, reason = check_signature(secret, ts=ts, body=body, signature=sig,
                                         now=int(time.time()))
            if not ok:
                print(f"[REJECT] {reason}")
                self.send_response(401)
                self.end_headers()
                return

            try:
                event = json.loads(body)
            except json.JSONDecodeError:
                event = {"_raw": body.decode("utf-8", "replace")}
            print(f"[ok]  sig {reason}  tripwire={event.get('tripwire_name')!r}")
            print(f"      process={event.get('process')!r} path={event.get('accessed_path')!r}")
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"received"}')

        def log_message(self, *args):  # silence default per-request logging
            pass

    return Handler


def main():
    ap = argparse.ArgumentParser(description="Thumper webhook test receiver")
    ap.add_argument("--port", type=int, default=9000)
    ap.add_argument("--secret", default=None, help="HMAC signing secret (omit to accept unsigned)")
    args = ap.parse_args()

    # Line-buffer stdout so each request prints live even when piped/redirected
    # (block buffering would otherwise swallow output until exit - useless for a
    # receiver whose whole job is to show what it got).
    sys.stdout.reconfigure(line_buffering=True)

    server = HTTPServer(("0.0.0.0", args.port), _make_handler(args.secret))
    mode = "verifying signatures" if args.secret else "accepting unsigned"
    print(f"listening on :{args.port} ({mode})")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
