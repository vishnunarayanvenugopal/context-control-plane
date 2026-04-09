from __future__ import annotations

import select
import socket
import socketserver
import threading
import urllib.parse
from dataclasses import dataclass, field


def _normalize_destination(host: str, port: int) -> str:
    return f"{host.strip().lower()}:{int(port)}"


def _matches_allowlist(destination: str, allowlist: tuple[str, ...]) -> bool:
    host, _sep, port = destination.partition(":")
    for candidate in allowlist:
        allowed_host, _sep, allowed_port = str(candidate).strip().lower().partition(":")
        if not allowed_host:
            continue
        if allowed_port and allowed_port != "*" and port and allowed_port != port:
            continue
        if host == allowed_host or host.endswith(f".{allowed_host}"):
            return True
    return False


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, server_address: tuple[str, int], allowlist: tuple[str, ...]):
        self.allowlist = allowlist
        self._lock = threading.Lock()
        self.requested_destinations: list[str] = []
        self.blocked_destinations: list[str] = []
        super().__init__(server_address, _ProxyHandler)

    def record_destination(self, destination: str, *, allowed: bool) -> None:
        with self._lock:
            if destination not in self.requested_destinations:
                self.requested_destinations.append(destination)
            if not allowed and destination not in self.blocked_destinations:
                self.blocked_destinations.append(destination)


class _ProxyHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        request_line = self.rfile.readline(65536).decode("latin-1").strip()
        if not request_line:
            return
        parts = request_line.split()
        if len(parts) != 3:
            self._send_error(400, "Bad Request")
            return
        method, target, version = parts
        if method.upper() == "CONNECT":
            self._handle_connect(target, version)
            return
        self._handle_http(method, target, version)

    def _handle_connect(self, target: str, version: str) -> None:
        host, port = _parse_authority(target, default_port=443)
        destination = _normalize_destination(host, port)
        allowed = _matches_allowlist(destination, self.server.allowlist)
        self.server.record_destination(destination, allowed=allowed)
        if not allowed:
            self._send_error(403, "Forbidden")
            return
        try:
            upstream = socket.create_connection((host, port), timeout=2.0)
        except OSError:
            self._send_error(502, "Bad Gateway")
            return
        self.wfile.write(f"{version} 200 Connection Established\r\n\r\n".encode("latin-1"))
        self.wfile.flush()
        _relay_bidirectional(self.connection, upstream)

    def _handle_http(self, method: str, target: str, version: str) -> None:
        headers = _read_headers(self.rfile)
        host = ""
        port = 80
        path = target
        if "://" in target:
            parsed = urllib.parse.urlsplit(target)
            host = parsed.hostname or ""
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
        else:
            host_header = headers.get("host", "")
            host, port = _parse_authority(host_header, default_port=80)
        destination = _normalize_destination(host, port)
        allowed = _matches_allowlist(destination, self.server.allowlist)
        self.server.record_destination(destination, allowed=allowed)
        if not allowed:
            self._send_error(403, "Forbidden")
            return

        body = b""
        content_length = int(headers.get("content-length", "0") or 0)
        if content_length > 0:
            body = self.rfile.read(content_length)
        try:
            upstream = socket.create_connection((host, port), timeout=2.0)
        except OSError:
            self._send_error(502, "Bad Gateway")
            return
        request_headers = [
            f"{method} {path or '/'} {version}",
            *[
                f"{key}: {value}"
                for key, value in headers.items()
                if key.lower() not in {"proxy-connection", "connection"}
            ],
            "",
            "",
        ]
        upstream.sendall("\r\n".join(request_headers).encode("latin-1") + body)
        _relay_one_way(upstream, self.connection)

    def _send_error(self, code: int, message: str) -> None:
        body = f"{message}\n".encode("utf-8")
        response = (
            f"HTTP/1.1 {code} {message}\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1")
        self.wfile.write(response + body)
        self.wfile.flush()


def _parse_authority(value: str, *, default_port: int) -> tuple[str, int]:
    text = str(value or "").strip()
    if ":" not in text:
        return text, default_port
    host, port_text = text.rsplit(":", 1)
    if port_text.isdigit():
        return host, int(port_text)
    return text, default_port


def _read_headers(stream) -> dict[str, str]:
    headers: dict[str, str] = {}
    while True:
        line = stream.readline(65536).decode("latin-1")
        if line in {"\r\n", "\n", ""}:
            break
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers


def _relay_one_way(source: socket.socket, target: socket.socket) -> None:
    with source, target:
        while True:
            data = source.recv(65536)
            if not data:
                break
            target.sendall(data)


def _relay_bidirectional(left: socket.socket, right: socket.socket) -> None:
    with left, right:
        sockets = [left, right]
        while sockets:
            ready, _, _ = select.select(sockets, [], [], 2.0)
            if not ready:
                break
            for sock in ready:
                data = sock.recv(65536)
                if not data:
                    if sock in sockets:
                        sockets.remove(sock)
                    continue
                peer = right if sock is left else left
                peer.sendall(data)


@dataclass
class McpAllowlistProxy:
    allowlist: tuple[str, ...]
    host: str = "127.0.0.1"
    port: int = 0
    _server: _ProxyServer | None = field(default=None, init=False, repr=False)
    _thread: threading.Thread | None = field(default=None, init=False, repr=False)

    @property
    def proxy_url(self) -> str:
        return f"http://localhost:{self.port}"

    def start(self) -> "McpAllowlistProxy":
        server = _ProxyServer((self.host, self.port), self.allowlist)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self._server = server
        self._thread = thread
        self.port = server.server_address[1]
        return self

    def snapshot(self) -> dict[str, object]:
        if self._server is None:
            return {"requestedDestinations": [], "blockedDestinations": []}
        return {
            "requestedDestinations": list(self._server.requested_destinations),
            "blockedDestinations": list(self._server.blocked_destinations),
        }

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
        if self._thread is not None:
            self._thread.join(timeout=1.0)
        self._server = None
        self._thread = None
