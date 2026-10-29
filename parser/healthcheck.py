#!/usr/bin/env python3
"""Проверка живости серверов: tcp (быстро) и deep (через xray/sing-box)."""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
from typing import Any

from link_parser import Server

DEFAULT_TEST_HOST = "cp.cloudflare.com"
DEFAULT_TEST_PATH = "/generate_204"


def tcp_check(host: str, port: int, timeout: float = 6.0) -> tuple[bool, int | None]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, int((time.monotonic() - started) * 1000)
    except OSError:
        return False, None


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed")
        buf += chunk
    return buf


def _socks5_http_get(socks_port: int, host: str, path: str, timeout: float) -> bool:
    target = host.encode("idna")
    with socket.create_connection(("127.0.0.1", socks_port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(b"\x05\x01\x00")
        if _recv_exact(sock, 2) != b"\x05\x00":
            return False
        sock.sendall(b"\x05\x01\x00\x03" + bytes([len(target)]) + target
                     + (80).to_bytes(2, "big"))
        head = _recv_exact(sock, 4)
        if head[0] != 5 or head[1] != 0:
            return False
        atyp = head[3]
        if atyp == 1:
            _recv_exact(sock, 6)
        elif atyp == 3:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 4:
            _recv_exact(sock, 18)
        else:
            return False
        sock.sendall((f"GET {path} HTTP/1.1\r\nHost: {host}\r\n"
                      "User-Agent: vpn-subnet-parser/1.0\r\n"
                      "Connection: close\r\n\r\n").encode())
        try:
            data = sock.recv(128)
        except socket.timeout:
            return False
        return data.startswith(b"HTTP/") and b" 204" in data.split(b"\r\n", 1)[0]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _tls_block(srv: Server) -> dict[str, Any]:
    p = srv.params
    block: dict[str, Any] = {
        "serverName": p.get("sni") or p.get("host") or srv.host,
        "fingerprint": p.get("fp") or "chrome",
    }
    if p.get("alpn"):
        block["alpn"] = [a for a in p["alpn"].split(",") if a]
    if str(p.get("allowInsecure", "")).lower() in ("1", "true"):
        block["allowInsecure"] = True
    return block


def to_xray_outbound(srv: Server) -> dict[str, Any]:
    p = srv.params
    network = p.get("type", "tcp")
    security = p.get("security", "none")
    stream: dict[str, Any] = {
        "network": "raw" if network == "tcp" else network,
        "security": security,
    }
    if security == "tls":
        stream["tlsSettings"] = _tls_block(srv)
    elif security == "reality":
        stream["realitySettings"] = {
            **_tls_block(srv),
            "publicKey": p.get("pbk", ""),
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", "/"),
        }
    if network == "ws":
        ws: dict[str, Any] = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        stream["wsSettings"] = ws
    elif network == "grpc":
        stream["grpcSettings"] = {"serviceName": p.get("serviceName", "")}
    elif network in ("http", "h2"):
        stream["httpSettings"] = {
            "path": p.get("path") or "/",
            "host": [p["host"]] if p.get("host") else [],
        }
    if srv.protocol == "vless":
        user: dict[str, Any] = {"id": srv.identity, "encryption": "none"}
        if p.get("flow"):
            user["flow"] = p["flow"]
        return {
            "protocol": "vless",
            "settings": {"vnext": [{"address": srv.host, "port": srv.port,
                                    "users": [user]}]},
            "streamSettings": stream,
        }
    return {
        "protocol": "trojan",
        "settings": {"servers": [{"address": srv.host, "port": srv.port,
                                  "password": srv.identity}]},
        "streamSettings": stream,
    }


def to_singbox_outbound(srv: Server) -> dict[str, Any]:
    p = srv.params
    out: dict[str, Any] = {
        "type": "hysteria2", "server": srv.host, "server_port": srv.port,
        "password": srv.identity,
        "tls": {"enabled": True, "server_name": p.get("sni") or srv.host,
                "insecure": str(p.get("allowInsecure", "")).lower() in ("1", "true")},
    }
    if p.get("obfs") == "salamander":
        out["obfs"] = {"type": "salamander", "password": p.get("obfs-password", "")}
    return out


def _wait_port(port: int, deadline: float) -> bool:
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return True
        except OSError:
            time.sleep(0.1)
    return False


def deep_check(srv: Server, *, xray_bin: str = "xray",
               singbox_bin: str = "sing-box", timeout: float = 20.0,
               test_host: str = DEFAULT_TEST_HOST,
               test_path: str = DEFAULT_TEST_PATH) -> tuple[bool | None, int | None, str]:
    use_singbox = srv.protocol == "hysteria2"
    binary = singbox_bin if use_singbox else xray_bin
    if not shutil.which(binary):
        return None, None, f"binary_not_found:{binary}"
    port = _free_port()
    if use_singbox:
        config = {
            "log": {"level": "warn"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [to_singbox_outbound(srv)],
        }
    else:
        config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{"type": "socks", "listen": "127.0.0.1", "port": port,
                          "settings": {"udp": False}}],
            "outbounds": [to_xray_outbound(srv)],
        }
    tmp = tempfile.NamedTemporaryFile("w", suffix=".json", delete=False, encoding="utf-8")
    proc: subprocess.Popen | None = None
    try:
        json.dump(config, tmp)
        tmp.close()
        proc = subprocess.Popen([binary, "run", "-c", tmp.name],
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                start_new_session=True)
        if not _wait_port(port, time.monotonic() + min(timeout, 10.0)):
            return False, None, "client_did_not_start"
        started = time.monotonic()
        ok = _socks5_http_get(port, test_host, test_path, timeout)
        elapsed = int((time.monotonic() - started) * 1000)
        return (True, elapsed, "ok") if ok else (False, None, "probe_failed")
    except (OSError, ValueError) as exc:
        return None, None, f"error:{type(exc).__name__}"
    finally:
        if proc and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
        try:
            os.unlink(tmp.name)
        except OSError:
            pass


def check(srv: Server, mode: str = "tcp", **kwargs: Any) -> tuple[bool | None, int | None, str]:
    if mode == "deep":
        return deep_check(srv, **kwargs)
    if srv.protocol == "hysteria2":
        return None, None, "udp_protocol_tcp_check_not_applicable"
    ok, latency = tcp_check(srv.host, srv.port, timeout=kwargs.get("timeout", 6.0))
    return ok, latency, "ok" if ok else "tcp_refused"
