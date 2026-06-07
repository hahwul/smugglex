#!/usr/bin/env python3
"""CL-framing frontend proxy for the real-desync lab.

Frames client request bodies strictly by **Content-Length** — it never looks at
Transfer-Encoding, and on duplicate Content-Length it uses the *first* value —
and forwards each request verbatim over a single shared, persistent connection
to the backend. Because that backend connection is reused across every client
request, any bytes the backend leaves unconsumed (the surplus this CL frontend
forwarded past what a TE backend stopped at) become the prefix of the next
request on the connection — a genuine, socket-level desync.

Whether that surplus actually appears depends on the backend's framing:
  * TE-honouring backend (``FRAMING=te``)  -> frontend/backend disagree -> desync.
  * CL-first backend     (``FRAMING=cl``)  -> they agree            -> patched.

Like a real reverse proxy it bounds its waits: ``CLIENT_BODY_TIMEOUT`` (a client
that declares more body than it sends gets a fast 400 instead of stalling the
proxy) and ``UPSTREAM_TIMEOUT`` (a backend hung on a truncated chunk yields a
504 — the timing/status signature scanners key on)."""

from __future__ import annotations

import os
import socket
import threading

LISTEN_HOST = os.environ.get("BIND_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("BIND_PORT", "8080"))
BACKEND_HOST = os.environ.get("BACKEND_HOST", "127.0.0.1")
BACKEND_PORT = int(os.environ.get("BACKEND_PORT", "8000"))
UPSTREAM_TIMEOUT = float(os.environ.get("UPSTREAM_TIMEOUT", "6"))
CLIENT_BODY_TIMEOUT = float(os.environ.get("CLIENT_BODY_TIMEOUT", "0.7"))

_lock = threading.Lock()
_backend: socket.socket | None = None
_backend_buf = b""

_BAD_REQUEST = (
    b"HTTP/1.1 400 Bad Request\r\nContent-Length: 11\r\n"
    b"Connection: keep-alive\r\n\r\nbad request"
)
_GATEWAY_TIMEOUT = (
    b"HTTP/1.1 504 Gateway Timeout\r\nContent-Length: 15\r\n"
    b"Connection: keep-alive\r\n\r\nupstream timeout"
)


def _connect_backend() -> None:
    global _backend, _backend_buf
    _backend = socket.create_connection((BACKEND_HOST, BACKEND_PORT))
    _backend.settimeout(UPSTREAM_TIMEOUT)
    _backend_buf = b""


def _close_backend() -> None:
    global _backend
    if _backend is not None:
        try:
            _backend.close()
        except OSError:
            pass
    _backend = None


def _backend_recv_until(delim: bytes):
    global _backend_buf
    while delim not in _backend_buf:
        data = _backend.recv(4096)
        if not data:
            return None
        _backend_buf += data
    idx = _backend_buf.index(delim) + len(delim)
    out, _backend_buf = _backend_buf[:idx], _backend_buf[idx:]
    return out


def _first_content_length(head: bytes) -> int:
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            try:
                return int(line.split(b":", 1)[1].strip())
            except ValueError:
                return 0
    return 0


def _read_one_backend_response():
    global _backend_buf
    head = _backend_recv_until(b"\r\n\r\n")
    if head is None:
        return None
    n = _first_content_length(head)
    while len(_backend_buf) < n:
        data = _backend.recv(4096)
        if not data:
            break
        _backend_buf += data
    body, _backend_buf = _backend_buf[:n], _backend_buf[n:]
    return head + body


def forward(raw_request: bytes) -> bytes:
    """Forward one client request over the shared backend connection."""
    global _backend
    with _lock:
        for attempt in range(2):
            try:
                if _backend is None:
                    _connect_backend()
                _backend.sendall(raw_request)
                resp = _read_one_backend_response()
                if resp is None:
                    raise ConnectionError("backend closed")
                return resp
            except (TimeoutError, socket.timeout):
                _close_backend()  # backend hung on an incomplete body
                return _GATEWAY_TIMEOUT
            except (ConnectionError, OSError):
                _close_backend()
                if attempt == 1:
                    return _GATEWAY_TIMEOUT
    return _GATEWAY_TIMEOUT


def _recv_until(sock: socket.socket, buf: bytes, delim: bytes):
    while delim not in buf:
        data = sock.recv(4096)
        if not data:
            return None, buf
        buf += data
    idx = buf.index(delim) + len(delim)
    return buf[:idx], buf[idx:]


def handle_client(sock: socket.socket) -> None:
    sock.settimeout(CLIENT_BODY_TIMEOUT)
    buf = b""
    try:
        while True:
            try:
                head, buf = _recv_until(sock, buf, b"\r\n\r\n")
            except (TimeoutError, socket.timeout):
                break  # idle keep-alive — let the connection lapse
            if head is None:
                break

            n = _first_content_length(head)  # strict CL framing, ignore TE
            try:
                while len(buf) < n:
                    data = sock.recv(4096)
                    if not data:
                        raise ConnectionError("client closed mid-body")
                    buf += data
            except (TimeoutError, socket.timeout):
                # Client declared more body than it sent — fail fast rather than
                # stalling the proxy on a partial body.
                sock.sendall(_BAD_REQUEST)
                break
            body, buf = buf[:n], buf[n:]
            sock.sendall(forward(head + body))
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
    srv.bind((LISTEN_HOST, LISTEN_PORT))
    srv.listen(64)
    print(
        f"[frontend] CL-first proxy on {LISTEN_HOST}:{LISTEN_PORT} -> "
        f"backend {BACKEND_HOST}:{BACKEND_PORT} "
        f"(client-body timeout {CLIENT_BODY_TIMEOUT}s, upstream timeout {UPSTREAM_TIMEOUT}s)",
        flush=True,
    )
    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle_client, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
