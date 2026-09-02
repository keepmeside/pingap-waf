#!/usr/bin/env python3
"""Echo upstream for Phase 02 Spike E.

Reports the request body byte count it actually read, plus a SHA-256 of those
bytes. The point of the spike is that this number comes from the far side of the
proxy: a body the proxy destroyed shows up here as 0, no matter what the proxy
logged on its own side.

Handles the "Content-Length promised N, got fewer" case explicitly rather than
blocking forever, because that is precisely the failure mode under test.
"""

import hashlib
import json
import socket
import sys
import threading

READ_TIMEOUT_S = 3.0


def read_until_headers(conn):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return buf, b""
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    return head, rest


def content_length(head):
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.strip().lower() == b"content-length":
            try:
                return int(value.strip())
            except ValueError:
                return 0
    return 0


def handle(conn):
    conn.settimeout(READ_TIMEOUT_S)
    try:
        head, body = read_until_headers(conn)
        if not head:
            return
        promised = content_length(head)
        truncated = False
        # Read exactly what Content-Length promised, but give up on timeout so a
        # destroyed body surfaces as a short read instead of a hang.
        while len(body) < promised:
            try:
                chunk = conn.recv(min(65536, promised - len(body)))
            except socket.timeout:
                truncated = True
                break
            if not chunk:
                truncated = True
                break
            body += chunk

        result = {
            "content_length_header": promised,
            "body_bytes_received": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "truncated": truncated,
        }
        payload = json.dumps(result).encode()
        conn.sendall(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: application/json\r\n"
            b"Content-Length: " + str(len(payload)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + payload
        )
        print(json.dumps(result), flush=True)
    except Exception as exc:  # noqa: BLE001 - spike diagnostics only
        print(f"[echo] error: {exc}", file=sys.stderr, flush=True)
    finally:
        conn.close()


def main():
    port = int(sys.argv[1])
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(16)
    print(f"[echo] listening on 127.0.0.1:{port}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
