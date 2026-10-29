#!/usr/bin/env python3
"""Парсер VLESS / Trojan / Hysteria2."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Iterable

SUPPORTED = ("vless", "trojan", "hysteria2")
_LINK_RE = re.compile(r"^(vless|trojan|hysteria2|hy2)://", re.IGNORECASE)
_ANY_LINK_RE = re.compile(r"(?:vless|trojan|hysteria2|hy2)://\S+", re.IGNORECASE)


def _pad_b64(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    return s + "=" * (-len(s) % 4)


def try_b64decode(s: str) -> str | None:
    s = "".join(s.split())
    if len(s) < 8:
        return None
    try:
        raw = base64.b64decode(_pad_b64(s), validate=False)
    except (binascii.Error, ValueError):
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text or not any(ch.isprintable() for ch in text):
        return None
    return text


@dataclass
class Server:
    protocol: str
    host: str
    port: int
    identity: str
    name: str = ""
    params: dict[str, str] = field(default_factory=dict)
    source: str = ""

    @property
    def key(self) -> str:
        p = self.params
        return "|".join([
            self.protocol, self.host.lower().strip("."), str(self.port),
            self.identity, p.get("type", "tcp"), p.get("security", "none"),
            p.get("sni", ""), p.get("path", ""), p.get("host", ""),
            p.get("serviceName", ""),
        ])

    @property
    def id(self) -> str:
        return hashlib.sha256(self.key.encode("utf-8")).hexdigest()[:16]

    @property
    def display_name(self) -> str:
        return self.name or f"{self.protocol}-{self.host}:{self.port}"

    def link(self) -> str:
        p = {k: v for k, v in self.params.items() if v not in (None, "")}
        p.pop("name", None)
        query = urllib.parse.urlencode(p, quote_via=urllib.parse.quote, safe="")
        frag = urllib.parse.quote(self.display_name, safe="")
        auth = urllib.parse.quote(self.identity, safe="")
        base = (f"{self.protocol}://{auth}@{self.host}:{self.port}"
                if auth else f"{self.protocol}://{self.host}:{self.port}")
        return f"{base}?{query}#{frag}" if query else f"{base}#{frag}"

    def to_dict(self, **extra: Any) -> dict:
        data = {
            "id": self.id, "protocol": self.protocol, "name": self.display_name,
            "host": self.host, "port": self.port, "link": self.link(),
            "params": dict(self.params), "source": self.source,
        }
        data.update(extra)
        return data


def parse_link(raw: str, source: str = "") -> Server | None:
    raw = (raw or "").strip()
    if not raw or not _LINK_RE.match(raw):
        return None
    try:
        u = urllib.parse.urlsplit(raw)
        host, port = u.hostname, u.port
    except ValueError:
        return None
    if not host:
        return None
    scheme = u.scheme.lower()
    proto = "hysteria2" if scheme == "hy2" else scheme
    if proto not in SUPPORTED:
        return None
    identity = urllib.parse.unquote(u.username or "")
    if u.password:
        identity = f"{identity}:{urllib.parse.unquote(u.password)}"
    if proto in ("vless", "trojan") and not identity:
        return None
    params = dict(urllib.parse.parse_qsl(u.query, keep_blank_values=True))
    params.pop("name", None)
    params.setdefault("security", "none")
    params.setdefault("type", "tcp")
    return Server(proto, host, int(port or 443), identity,
                  urllib.parse.unquote(u.fragment or "").strip(), params, source)


def _stream_params(ss: dict) -> dict[str, str]:
    params: dict[str, str] = {}
    net = ss.get("network", "tcp") or "tcp"
    sec = ss.get("security", "none") or "none"
    params["type"] = "h2" if net == "http" else ("tcp" if net == "raw" else net)
    params["security"] = sec
    tls = ss.get("realitySettings") if sec == "reality" else ss.get("tlsSettings")
    tls = tls if isinstance(tls, dict) else {}
    for src, dst in (("serverName", "sni"), ("fingerprint", "fp"),
                     ("publicKey", "pbk"), ("shortId", "sid"), ("spiderX", "spx")):
        if tls.get(src):
            params[dst] = str(tls[src])
    if tls.get("allowInsecure"):
        params["allowInsecure"] = "1"
    if isinstance(tls.get("alpn"), list) and tls["alpn"]:
        params["alpn"] = ",".join(str(a) for a in tls["alpn"])
    if net == "ws":
        ws = ss.get("wsSettings") or {}
        params["path"] = str(ws.get("path") or "/")
        hh = (ws.get("headers") or {}).get("Host")
        if hh:
            params["host"] = str(hh)
    elif net == "grpc":
        params["serviceName"] = str((ss.get("grpcSettings") or {}).get("serviceName") or "")
    elif net in ("http", "h2"):
        h2 = ss.get("httpSettings") or {}
        params["path"] = str(h2.get("path") or "/")
        hosts = h2.get("host") or []
        if isinstance(hosts, list) and hosts:
            params["host"] = str(hosts[0])
    return params


def _xray_outbound(o: dict, proto: str, source: str) -> Server | None:
    settings = o.get("settings") or {}
    params = _stream_params(o.get("streamSettings") or {})
    name = str(o.get("tag") or "")
    if proto == "vless":
        vnext = (settings.get("vnext") or [{}])[0] or {}
        user = (vnext.get("users") or [{}])[0] or {}
        host, port = vnext.get("address"), vnext.get("port")
        identity = str(user.get("id") or "")
        if user.get("flow"):
            params["flow"] = str(user["flow"])
        if not host or not identity:
            return None
        return Server("vless", str(host), int(port or 443), identity, name, params, source)
    if proto == "trojan":
        srv = (settings.get("servers") or [{}])[0] or {}
        host, port = srv.get("address"), srv.get("port")
        identity = str(srv.get("password") or "")
        if not host or not identity:
            return None
        return Server("trojan", str(host), int(port or 443), identity, name, params, source)
    return None


def _singbox_outbound(o: dict, proto: str, source: str) -> Server | None:
    host = o.get("server")
    if not host:
        return None
    params: dict[str, str] = {}
    tls = o.get("tls") or {}
    if tls.get("enabled"):
        params["security"] = "reality" if tls.get("reality") else "tls"
        if tls.get("server_name"):
            params["sni"] = str(tls["server_name"])
        if tls.get("insecure"):
            params["allowInsecure"] = "1"
        if isinstance(tls.get("alpn"), list) and tls["alpn"]:
            params["alpn"] = ",".join(str(a) for a in tls["alpn"])
        reality = tls.get("reality") or {}
        if reality.get("public_key"):
            params["pbk"] = str(reality["public_key"])
        if reality.get("short_id"):
            params["sid"] = str(reality["short_id"])
    else:
        params["security"] = "none"
    transport = o.get("transport") or {}
    ttype = str(transport.get("type") or "tcp")
    params["type"] = {"http": "h2"}.get(ttype, ttype)
    if ttype in ("ws", "http", "httpupgrade"):
        params["path"] = str(transport.get("path") or "/")
        h = (transport.get("headers") or {}).get("Host")
        if isinstance(h, list):
            h = h[0] if h else None
        if h:
            params["host"] = str(h)
    elif ttype == "grpc":
        params["serviceName"] = str(transport.get("service_name") or "")
    if proto == "hysteria2":
        identity = str(o.get("password") or "")
        obfs = o.get("obfs") or {}
        if obfs.get("type") == "salamander":
            params["obfs"] = "salamander"
            if obfs.get("password"):
                params["obfs-password"] = str(obfs["password"])
    else:
        identity = str(o.get("uuid") or o.get("password") or "")
    if not identity:
        return None
    return Server(proto, str(host), int(o.get("server_port") or 443),
                  identity, str(o.get("tag") or ""), params, source)


def parse_outbound(obj: dict, source: str = "") -> Server | None:
    if not isinstance(obj, dict):
        return None
    proto = str(obj.get("protocol") or obj.get("type") or "").lower()
    if proto not in SUPPORTED:
        return None
    if "settings" in obj or "streamSettings" in obj:
        return _xray_outbound(obj, proto, source)
    return _singbox_outbound(obj, proto, source)


def parse_json_doc(doc: Any, source: str = "") -> list[Server]:
    items: list[Any] = []
    if isinstance(doc, list):
        items = doc
    elif isinstance(doc, dict):
        if isinstance(doc.get("outbounds"), list):
            items = doc["outbounds"]
        elif isinstance(doc.get("servers"), list):
            items = doc["servers"]
        elif "protocol" in doc or "type" in doc:
            items = [doc]
    out: list[Server] = []
    for item in items:
        srv = parse_outbound(item, source) if isinstance(item, dict) else None
        if srv:
            out.append(srv)
    return out


def parse_text(text: str, source: str = "") -> list[Server]:
    if not text:
        return []
    body = text.strip()
    if "://" not in body:
        decoded = try_b64decode(body)
        if decoded and "://" in decoded:
            body = decoded
    out: list[Server] = []
    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("//"):
            continue
        match = _ANY_LINK_RE.search(line)
        if not match:
            continue
        srv = parse_link(match.group(0), source)
        if srv:
            out.append(srv)
    return out


def parse_file(path: str) -> list[Server]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        raw = fh.read()
    source = os.path.basename(path)
    if path.lower().endswith(".json"):
        try:
            return parse_json_doc(json.loads(raw), source)
        except json.JSONDecodeError:
            return []
    return parse_text(raw, source)


def parse_dir(path: str) -> list[Server]:
    collected: list[Server] = []
    if not os.path.isdir(path):
        return collected
    for name in sorted(os.listdir(path)):
        full = os.path.join(path, name)
        if not os.path.isfile(full):
            continue
        if not name.lower().endswith((".txt", ".json", ".sub", ".conf")):
            continue
        try:
            collected.extend(parse_file(full))
        except OSError:
            continue
    return dedupe(collected)


def dedupe(servers: Iterable[Server]) -> list[Server]:
    seen: dict[str, Server] = {}
    for srv in servers:
        seen.setdefault(srv.id, srv)
    return list(seen.values())
