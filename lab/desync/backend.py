#!/usr/bin/env python3
"""TE-priority backend for the real-desync lab.

Frames request bodies by **Transfer-Encoding: chunked** when present (ignoring
Content-Length), otherwise by Content-Length. Connections are keep-alive, and —
crucially — any bytes left in the receive buffer after a framed request remain
as the *prefix of the next request* on the same connection. That carry-over is
the actual desync mechanism: when the CL-framing frontend forwards more bytes
than this backend consumes for a request, the surplus poisons the next request.
"""

from __future__ import annotations

import os
import socket
import threading

HOST = os.environ.get("BIND_HOST", "0.0.0.0")
PORT = int(os.environ.get("BIND_PORT", "8000"))
# Framing policy: "te" honours Transfer-Encoding over Content-Length (disagrees
# with the CL-first frontend -> desync = the vulnerable config). "cl" frames by
# the first Content-Length and ignores TE (agrees with the frontend -> patched).
FRAMING = os.environ.get("FRAMING", "te").lower()


def recv_until(sock: socket.socket, buf: bytes, delim: bytes):
    """Return (chunk_up_to_and_including_delim, remaining_buf) or (None, buf)."""
    while delim not in buf:
        data = sock.recv(4096)
        if not data:
            return None, buf
        buf += data
    idx = buf.index(delim) + len(delim)
    return buf[:idx], buf[idx:]


def parse_headers(head: bytes):
    lines = head.split(b"\r\n")
    request_line = lines[0]
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    return request_line, headers


def first_content_length(head: bytes) -> int | None:
    """First Content-Length value (matches the frontend's duplicate handling)."""
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return None
    return None


def read_chunked_body(sock: socket.socket, buf: bytes):
    """Consume a chunked body up to the terminating zero-size chunk.

    Returns (ok, remaining_buf). `ok` is False if the peer closed before the
    body completed (the backend then just hangs/closes — exactly what a real
    desynced backend does while waiting for the rest of a truncated chunk)."""
    while True:
        line, buf = recv_until(sock, buf, b"\r\n")
        if line is None:
            return False, buf
        size_token = line.strip().split(b";")[0]
        try:
            size = int(size_token, 16)
        except ValueError:
            return False, buf
        if size == 0:
            # Trailing CRLF that closes the chunked body (ignore trailers).
            line, buf = recv_until(sock, buf, b"\r\n")
            return (line is not None), buf
        while len(buf) < size + 2:
            data = sock.recv(4096)
            if not data:
                return False, buf
            buf += data
        buf = buf[size + 2 :]


def read_cl_body(sock: socket.socket, buf: bytes, n: int):
    while len(buf) < n:
        data = sock.recv(4096)
        if not data:
            break
        buf += data
    return buf[n:]


def respond(sock: socket.socket, body_text: str) -> None:
    body = body_text.encode("latin1", "replace")
    head = (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Length: %d\r\n"
        b"Server: lab-backend\r\n"
        b"Connection: keep-alive\r\n\r\n" % len(body)
    )
    sock.sendall(head + body)


def handle(sock: socket.socket) -> None:
    buf = b""
    try:
        while True:
            head, buf = recv_until(sock, buf, b"\r\n\r\n")
            if head is None:
                break
            request_line, headers = parse_headers(head)
            te = headers.get(b"transfer-encoding", b"").lower()
            if FRAMING == "te" and b"chunked" in te:
                ok, buf = read_chunked_body(sock, buf)
                if not ok:
                    break  # truncated chunk: backend gives up (connection dies)
            else:
                # CL framing (always, in "cl" mode; or no chunked TE in "te" mode).
                # Use the first Content-Length so a patched ("cl") backend frames
                # identically to the CL-first frontend and nothing desyncs.
                n = first_content_length(head) or 0
                buf = read_cl_body(sock, buf, n)
            # The response body echoes the request line the backend actually
            # parsed. A poisoned (smuggled-prefixed) request therefore yields a
            # visibly different body/route than the client intended.
            route = request_line.decode("latin1", "replace")
            respond(sock, f"BACKEND served: [{route}]")
            # Any leftover bytes in `buf` are the prefix of the next request.
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            sock.close()
        except OSError:
            pass


def main() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, PORT))
    srv.listen(64)
    policy = "TE-priority (vulnerable)" if FRAMING == "te" else "CL-first (patched)"
    print(f"[backend:{FRAMING}] {policy} backend listening on {HOST}:{PORT}", flush=True)
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
