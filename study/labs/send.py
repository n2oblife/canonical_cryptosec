#!/usr/bin/env python3
"""Minimal lab client for crypto_server.

Usage:
  study/labs/send.py FILE [--uds PATH | --tcp HOST:PORT] [--timeout SECONDS] [--sign KEY]

  FILE        payload to send. With --sign, FILE is a raw script that gets signed first.
  --sign KEY  sign FILE with this private key (same format as scripts/sign_script.sh).

Unlike tests/helpers.py, errors and timeouts are reported loudly, not swallowed.
"""
import argparse
import base64
import socket
import subprocess
import sys
import time


def sign(key: str, script: bytes) -> bytes:
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key],
        input=script, capture_output=True, check=True,
    ).stdout
    return b"# SIG: " + base64.b64encode(sig) + b"\n" + script


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--uds", default="/tmp/sec_server.sock")
    ap.add_argument("--tcp")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--sign", metavar="KEY")
    args = ap.parse_args()

    with open(args.file, "rb") as f:
        data = f.read()
    if args.sign:
        data = sign(args.sign, data)

    if args.tcp:
        host, port = args.tcp.rsplit(":", 1)
        sock = socket.create_connection((host, int(port)), timeout=args.timeout)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(args.timeout)
        sock.connect(args.uds)

    start = time.monotonic()
    try:
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)  # half-close: "end of request"
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            sys.stdout.write(chunk.decode(errors="replace"))
            sys.stdout.flush()
    except socket.timeout:
        print(f"\n[lab] TIMEOUT after {args.timeout}s (server never closed the connection)")
        return 124
    except OSError as e:
        print(f"\n[lab] socket error: {e!r}")
        return 1
    finally:
        sock.close()
    print(f"[lab] done in {time.monotonic() - start:.2f}s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
