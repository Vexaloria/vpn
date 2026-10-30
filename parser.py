#!/usr/bin/env python3
"""
sub-parser — самодостаточный скрипт: bootstrap → fetch → parse → dedupe → test → geo → rename.

Первый запуск (локально или в Actions):
    python parser.py            # сам поставит pip-зависимости, скачает нужные ядра, гоняет пайплайн

Команды:
    python parser.py            # полный прогон
    python parser.py cores      # скачать оба ядра принудительно
    python parser.py check      # только диагностика окружения
"""
from __future__ import annotations

import subprocess
import sys


# ─────────────────────── bootstrap (до остальных импортов) ───────────────────────
def _bootstrap() -> None:
    """Поставить requests и PyYAML, если их нет. Вызывается до их импорта."""
    required = {"requests": "requests", "yaml": "PyYAML"}
    missing = []
    for mod, pkg in required.items():
        try:
            __import__(mod)
        except ImportError:
            missing.append(pkg)
    if not missing:
        return
    print(f"[bootstrap] missing python deps: {missing}")
    cmds = [
        [sys.executable, "-m", "pip", "install", "--quiet", "--disable-pip-version-check", *missing],
        [sys.executable, "-m", "pip", "install", "--quiet", "--user", *missing],
        [sys.executable, "-m", "pip", "install", "--quiet", "--break-system-packages", *missing],
    ]
    for cmd in cmds:
        try:
            subprocess.check_call(cmd)
            print(f"[bootstrap] installed: {missing}")
            return
        except subprocess.CalledProcessError:
            continue
    raise SystemExit(
        f"[bootstrap] не смог поставить {missing}. "
        f"Поставь вручную: pip install {' '.join(missing)}"
    )


_bootstrap()


# ─────────────────────── импорты ───────────────────────
import base64
import hashlib
import io
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import tarfile
import time
import uuid
import zipfile
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

import requests
import urllib3
import yaml

urllib3.disable_warnings()

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
OUT_DIR = ROOT / "output"
TMP_DIR = ROOT / "tmp"
CORES_DIR = ROOT / "cores"

SCHEMES = ("vmess://", "vless://", "trojan://", "ss://",
           "hysteria2://", "hy2://", "tuic://")
XRAY_PROTOS = {"vless", "vmess", "trojan", "ss"}
SINGBOX_PROTOS = {"hysteria2", "tuic"}


# ─────────────────────── utils ───────────────────────
def ensure_dirs() -> None:
    for d in (DATA_DIR, OUT_DIR, TMP_DIR, CORES_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_config() -> dict:
    p = ROOT / "config.yaml"
    if not p.exists():
        print(f"[config] {p} не найден — дефолты")
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def read_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def write_json(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


def write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def sha1(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8", "ignore")).hexdigest()


def slug(s: str, maxlen: int = 40) -> str:
    s = s.strip()
    m = re.match(r"^[a-zA-Z]+://([^/:?#]+)", s)
    host = m.group(1) if m else s
    host = re.sub(r"[^a-zA-Z0-9._-]+", "-", host).strip("-")[:maxlen]
    return f"{host}-{sha1(s)[:6]}"


def flag(cc: str) -> str:
    if not cc or len(cc) != 2 or not cc.isalpha():
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in cc.upper())


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def stable_hwid() -> str:
    p = DATA_DIR / "device.json"
    data = read_json(p, {})
    if not data.get("hwid"):
        data["hwid"] = uuid.uuid4().hex.upper()
        write_json(p, data)
    return data["hwid"]


def b64decode_loose(s: str) -> bytes | None:
    s = s.strip().replace("\n", "").replace("\r", "").replace(" ", "")
    if not s:
        return None
    s = s.replace("-", "+").replace("_", "/")
    pad = (-len(s)) % 4
    try:
        return base64.b64decode(s + "=" * pad, validate=False)
    except Exception:
        return None


def printable_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    good = sum(1 for c in b if 32 <= c < 127 or c in (9, 10, 13))
    return good / len(b)


# ─────────────────────── fetch ───────────────────────
def build_headers(cfg: dict) -> dict:
    f = cfg.get("fetch", {}) or {}
    headers = {"User-Agent": f.get("user_agent", "Happ/2.6.2")}
    for k, v in (f.get("headers") or {}).items():
        if v == "auto":
            v = stable_hwid()
        headers[k] = str(v)
    return headers


def fetch_subscription(url: str, cfg: dict) -> str | None:
    f = cfg.get("fetch", {}) or {}
    timeout = int(f.get("timeout", 25))
    retries = int(f.get("retries", 2))
    headers = build_headers(cfg)
    if (f.get("send_headers_to") or "all") == "none":
        headers = {"User-Agent": f.get("user_agent", "Happ/2.6.2")}
    last = None
    for _ in range(retries + 1):
        try:
            r = requests.get(url, headers=headers, timeout=timeout, verify=True)
            if r.status_code == 200 and r.text.strip():
                return r.text
            last = f"HTTP {r.status_code}"
        except requests.exceptions.SSLError as e:
            last = f"SSL: {e}"
            try:
                r = requests.get(url, headers=headers, timeout=timeout, verify=False)
                if r.status_code == 200 and r.text.strip():
                    return r.text
                last = f"HTTP {r.status_code} (no-verify)"
            except Exception as e2:
                last = str(e2)
        except Exception as e:
            last = str(e)
    print(f"[fetch] FAIL {url} -> {last}")
    return None


def _is_b64_payload(s: str) -> bool:
    if len(s) < 32:
        return False
    return re.fullmatch(r"[A-Za-z0-9+/=\s_\-]+", s) is not None


def _outbound_dict_to_uri(d: dict) -> str | None:
    proto = (d.get("protocol") or "").lower()
    if proto not in ("vmess", "vless", "trojan", "shadowsocks"):
        return None
    try:
        ss = d.get("streamSettings") or {}
        net = ss.get("network", "tcp")
        sec = ss.get("security", "none")
        common = [f"type={net}", f"security={sec}"]
        if sec == "tls":
            tls = ss.get("tlsSettings") or {}
            if tls.get("serverName"):
                common.append("sni=" + tls["serverName"])
            if tls.get("fingerprint"):
                common.append("fp=" + tls["fingerprint"])
        if sec == "reality":
            rs = ss.get("realitySettings") or {}
            for k, q in (("serverName", "sni"), ("fingerprint", "fp"),
                         ("publicKey", "pbk"), ("shortId", "sid")):
                if rs.get(k):
                    common.append(f"{q}={rs[k]}")
        if net == "ws":
            ws = ss.get("wsSettings") or {}
            if ws.get("path"):
                common.append("path=" + ws["path"])
            h = (ws.get("headers") or {}).get("Host")
            if h:
                common.append("host=" + h)
        if net == "grpc":
            gs = ss.get("grpcSettings") or {}
            if gs.get("serviceName"):
                common.append("serviceName=" + gs["serviceName"])

        q = "&".join(common)
        tag = d.get("tag") or ""

        if proto in ("vmess", "vless"):
            vnext = (d.get("settings") or {}).get("vnext") or []
            if not vnext:
                return None
            v = vnext[0]
            user = (v.get("users") or [{}])[0]
            host, port, uid = v.get("address"), v.get("port"), user.get("id")
            if not (host and port and uid):
                return None
            if proto == "vless":
                if user.get("flow"):
                    q += "&flow=" + user["flow"]
                return f"vless://{uid}@{host}:{port}?{q}#{tag}"
            return (f"vmess://{uid}@{host}:{port}?{q}"
                    f"&aid={user.get('alterId', 0)}&scy={user.get('security', 'auto')}#{tag}")

        if proto == "trojan":
            servers = (d.get("settings") or {}).get("servers") or []
            if not servers:
                return None
            s = servers[0]
            return f"trojan://{s.get('password')}@{s.get('address')}:{s.get('port')}?{q}#{tag}"

        if proto == "shadowsocks":
            servers = (d.get("settings") or {}).get("servers") or []
            if not servers:
                return None
            s = servers[0]
            userinfo = base64.b64encode(
                f"{s.get('method')}:{s.get('password')}".encode()
            ).decode().rstrip("=")
            return f"ss://{userinfo}@{s.get('address')}:{s.get('port')}#{tag}"
    except Exception:
        return None
    return None


def _extract_json(obj, depth: int) -> list[str]:
    out: list[str] = []
    if depth > 6:
        return out
    if isinstance(obj, str):
        s = obj.strip()
        if s.startswith(SCHEMES):
            out.append(s)
        elif _is_b64_payload(s):
            dec = b64decode_loose(s)
            if dec and printable_ratio(dec) > 0.9:
                out.extend(decode_payload(dec.decode("utf-8", "ignore"), depth + 1))
        return out
    if isinstance(obj, list):
        for item in obj:
            out.extend(_extract_json(item, depth + 1))
        return out
    if isinstance(obj, dict):
        uri = _outbound_dict_to_uri(obj)
        if uri:
            out.append(uri)
            return out
        for v in obj.values():
            out.extend(_extract_json(v, depth + 1))
    return out


def decode_payload(text: str, depth: int = 0) -> list[str]:
    out: list[str] = []
    if not text or depth > 4:
        return out
    s = text.strip()
    if not s:
        return out
    if s[0] in "[{":
        try:
            out.extend(_extract_json(json.loads(s), depth))
            if out:
                return out
        except Exception:
            pass
    if _is_b64_payload(s) and "\n" not in s.strip():
        dec = b64decode_loose(s)
        if dec and printable_ratio(dec) > 0.85:
            inner = decode_payload(dec.decode("utf-8", "ignore"), depth + 1)
            if inner:
                return inner
    for line in s.splitlines():
        line = line.strip().strip('",')
        if not line:
            continue
        if line.startswith(SCHEMES):
            out.append(line)
        elif _is_b64_payload(line):
            dec = b64decode_loose(line)
            if dec and printable_ratio(dec) > 0.85:
                out.extend(decode_payload(dec.decode("utf-8", "ignore"), depth + 1))
    return out


# ─────────────────────── parse ───────────────────────
def _q(uri: str) -> dict:
    q = parse_qs(urlsplit(uri).query, keep_blank_values=True)
    return {k: v[0] for k, v in q.items()}


def _parse_vmess(uri: str) -> dict | None:
    body = uri[len("vmess://"):]
    dec = b64decode_loose(body)
    if not dec:
        return None
    try:
        d = json.loads(dec.decode("utf-8", "ignore"))
    except Exception:
        return None
    host = str(d.get("add") or "").strip()
    try:
        port = int(d.get("port") or 0)
    except Exception:
        return None
    if not host or not port:
        return None
    return {
        "proto": "vmess", "host": host, "port": port,
        "id": str(d.get("id") or ""), "name": str(d.get("ps") or ""), "raw": uri,
        "params": {
            "net": str(d.get("net") or "tcp"), "type": str(d.get("type") or "none"),
            "host": str(d.get("host") or ""), "path": str(d.get("path") or ""),
            "tls": str(d.get("tls") or ""), "sni": str(d.get("sni") or ""),
            "alpn": str(d.get("alpn") or ""), "scy": str(d.get("scy") or "auto"),
            "aid": str(d.get("aid") or 0),
        },
    }


def _parse_vless(uri: str) -> dict | None:
    u = urlsplit(uri)
    if not u.hostname:
        return None
    return {"proto": "vless", "host": u.hostname, "port": u.port or 443,
            "id": unquote(u.username or ""), "name": unquote(u.fragment or ""),
            "raw": uri, "params": _q(uri)}


def _parse_trojan(uri: str) -> dict | None:
    u = urlsplit(uri)
    if not u.hostname:
        return None
    return {"proto": "trojan", "host": u.hostname, "port": u.port or 443,
            "id": unquote(u.username or ""), "name": unquote(u.fragment or ""),
            "raw": uri, "params": _q(uri)}


def _parse_ss(uri: str) -> dict | None:
    body = uri[len("ss://"):]
    name = ""
    if "#" in body:
        body, name = body.split("#", 1)
        name = unquote(name)
    if "?" in body:
        body, query = body.split("?", 1)
        if "plugin=" in query:
            return None
    if "@" not in body:
        dec = b64decode_loose(body)
        if not dec:
            return None
        body = dec.decode("utf-8", "ignore")
    userinfo, _, hostport = body.rpartition("@")
    dec = b64decode_loose(userinfo)
    creds = dec.decode("utf-8", "ignore") if dec else unquote(userinfo)
    if ":" not in creds or ":" not in hostport:
        return None
    method, password = creds.split(":", 1)
    host, _, port = hostport.rpartition(":")
    try:
        port_i = int(port)
    except Exception:
        return None
    if not host or not method:
        return None
    return {"proto": "ss", "host": host, "port": port_i, "id": password,
            "name": name, "raw": uri, "params": {"method": method}}


def _parse_hy2(uri: str) -> dict | None:
    fixed = uri.replace("hy2://", "hysteria2://", 1)
    u = urlsplit(fixed)
    if not u.hostname:
        return None
    return {"proto": "hysteria2", "host": u.hostname, "port": u.port or 443,
            "id": unquote(u.username or ""), "name": unquote(u.fragment or ""),
            "raw": uri, "params": _q(fixed)}


def _parse_tuic(uri: str) -> dict | None:
    u = urlsplit(uri)
    if not u.hostname:
        return None
    return {"proto": "tuic", "host": u.hostname, "port": u.port or 443,
            "id": unquote(u.username or ""), "password": unquote(u.password or ""),
            "name": unquote(u.fragment or ""), "raw": uri, "params": _q(uri)}


def parse_uri(uri: str) -> dict | None:
    uri = uri.strip()
    try:
        if uri.startswith("vmess://"): return _parse_vmess(uri)
        if uri.startswith("vless://"): return _parse_vless(uri)
        if uri.startswith("trojan://"): return _parse_trojan(uri)
        if uri.startswith("ss://"): return _parse_ss(uri)
        if uri.startswith(("hysteria2://", "hy2://")): return _parse_hy2(uri)
        if uri.startswith("tuic://"): return _parse_tuic(uri)
    except Exception:
        return None
    return None


def _norm(v: str) -> str:
    return (v or "").strip().lower().rstrip("/")


def config_hash(c: dict) -> str:
    p = c["params"]
    host = _norm(c["host"])
    if c["proto"] == "vless":
        parts = [host, c["port"], c["id"].lower(),
                 _norm(p.get("type", "tcp")), _norm(p.get("security", "none")),
                 _norm(p.get("sni") or p.get("peer", "")),
                 _norm(p.get("alpn", "")), _norm(p.get("path", "")),
                 _norm(p.get("host", "")), _norm(p.get("serviceName", "")),
                 p.get("pbk", ""), p.get("sid", ""), p.get("flow", ""),
                 _norm(p.get("headerType", ""))]
    elif c["proto"] == "vmess":
        parts = [host, c["port"], c["id"].lower(), p.get("aid", "0"),
                 _norm(p.get("scy", "auto")), _norm(p.get("net", "tcp")),
                 _norm(p.get("type", "none")), _norm(p.get("host", "")),
                 _norm(p.get("path", "")), _norm(p.get("tls", "")),
                 _norm(p.get("sni", "")), _norm(p.get("alpn", ""))]
    elif c["proto"] == "trojan":
        parts = [host, c["port"], c["id"],
                 _norm(p.get("sni", "")), _norm(p.get("type", "tcp")),
                 _norm(p.get("path", "")), _norm(p.get("host", "")),
                 _norm(p.get("alpn", ""))]
    elif c["proto"] == "ss":
        parts = [host, c["port"], _norm(p.get("method", "")), c["id"]]
    elif c["proto"] == "hysteria2":
        parts = [host, c["port"], c["id"], _norm(p.get("sni", "")),
                 _norm(p.get("obfs", "")), p.get("obfs-password", "")]
    elif c["proto"] == "tuic":
        parts = [host, c["port"], c["id"], c["password"],
                 _norm(p.get("sni", "")), _norm(p.get("alpn", "")),
                 _norm(p.get("congestion_control", ""))]
    else:
        parts = [c["proto"], host, c["port"]]
    return sha1("|".join(str(x) for x in parts))


def parse_many(uris: list[str]) -> tuple[list[dict], int]:
    parsed, failed = [], 0
    for u in uris:
        c = parse_uri(u)
        if c:
            parsed.append(c)
        else:
            failed += 1
    return parsed, failed


# ─────────────────────── geo ───────────────────────
class Geo:
    CACHE_FILE = DATA_DIR / "geo_cache.json"

    def __init__(self, cfg: dict):
        self.cache_days = int((cfg.get("geo") or {}).get("cache_days", 30))
        self.cache: dict[str, dict] = read_json(self.CACHE_FILE, {})
        self._ip: dict[str, str | None] = {}
        self._dirty = False

    def resolve(self, host: str) -> str | None:
        if host in self._ip:
            return self._ip[host]
        ip: str | None = None
        try:
            socket.inet_aton(host)
            ip = host
        except OSError:
            try:
                ip = socket.gethostbyname(host)
            except Exception:
                ip = self._doh(host)
        self._ip[host] = ip
        return ip

    @staticmethod
    def _doh(host: str) -> str | None:
        try:
            r = requests.get("https://dns.google/resolve",
                             params={"name": host, "type": "A"}, timeout=8)
            for a in r.json().get("Answer", []):
                if a.get("type") == 1:
                    return a["data"]
        except Exception:
            pass
        return None

    def _cached(self, ip: str) -> dict | None:
        rec = self.cache.get(ip)
        if not rec:
            return None
        if time.time() - rec.get("ts", 0) > self.cache_days * 86400:
            return None
        return rec

    @staticmethod
    def _private(ip: str) -> bool:
        return ip.startswith(("10.", "127.", "192.168.", "172.16.", "172.17.",
                              "172.18.", "172.19.", "172.2", "172.30.", "172.31."))

    def lookup_many(self, ips: list[str]) -> None:
        need = []
        for ip in dict.fromkeys(ips):
            if not ip or self._private(ip):
                continue
            if self._cached(ip) is None:
                need.append(ip)
        for i in range(0, len(need), 100):
            chunk = need[i:i + 100]
            try:
                r = requests.post("http://ip-api.com/batch",
                                  params={"fields": "status,country,countryCode,query"},
                                  json=[{"query": ip} for ip in chunk], timeout=20)
                for item in r.json():
                    if item.get("status") == "success" and item.get("query"):
                        self.cache[item["query"]] = {
                            "country": item.get("country") or "",
                            "countryCode": item.get("countryCode") or "",
                            "ts": time.time(),
                        }
                        self._dirty = True
            except Exception as e:
                print(f"[geo] batch failed: {e}")
            if i + 100 < len(need):
                time.sleep(1.5)

    def info(self, host: str) -> dict:
        ip = self._ip.get(host) or ""
        rec = self._cached(ip) if ip else None
        return {"ip": ip,
                "country": (rec or {}).get("country") or "Unknown",
                "country_code": (rec or {}).get("countryCode") or ""}

    def save(self) -> None:
        if self._dirty:
            write_json(self.CACHE_FILE, self.cache)
            self._dirty = False


# ─────────────────────── cores (авто-скачивание) ───────────────────────
UA_GH = {"User-Agent": "sub-parser/1.0"}
XRAY_REPO = "XTLS/Xray-core"
SINGBOX_REPO = "SagerNet/sing-box"
XRAY_ASSET_RE = re.compile(r"^Xray-linux-64\.zip$")
SINGBOX_ASSET_RE = re.compile(r"^sing-box-.*-linux-amd64\.tar\.gz$")


def _latest_asset(repo: str, pattern: re.Pattern) -> str | None:
    try:
        r = requests.get(f"https://api.github.com/repos/{repo}/releases/latest",
                         headers=UA_GH, timeout=30)
        r.raise_for_status()
        for a in r.json().get("assets", []):
            if pattern.match(a.get("name", "")):
                return a.get("browser_download_url")
    except Exception as e:
        print(f"[cores] {repo}: API failed: {e}")
    return None


def _chmod_exec(path: Path) -> None:
    path.chmod(path.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)


def ensure_xray() -> Path | None:
    out = CORES_DIR / "xray"
    if out.exists():
        return out
    url = _latest_asset(XRAY_REPO, XRAY_ASSET_RE)
    if not url:
        return None
    print("[cores] downloading xray...")
    try:
        r = requests.get(url, headers=UA_GH, timeout=120)
        r.raise_for_status()
    except Exception as e:
        print(f"[cores] xray download: {e}")
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(r.content)) as z:
            member = next((n for n in z.namelist() if n == "xray"), None)
            if not member:
                return None
            out.write_bytes(z.read(member))
        _chmod_exec(out)
        print(f"[cores] xray -> {out}")
        return out
    except Exception as e:
        print(f"[cores] xray extract: {e}")
        return None


def ensure_singbox() -> Path | None:
    out = CORES_DIR / "sing-box"
    if out.exists():
        return out
    url = _latest_asset(SINGBOX_REPO, SINGBOX_ASSET_RE)
    if not url:
        return None
    print("[cores] downloading sing-box...")
    try:
        r = requests.get(url, headers=UA_GH, timeout=120)
        r.raise_for_status()
    except Exception as e:
        print(f"[cores] sing-box download: {e}")
        return None
    try:
        with tarfile.open(fileobj=io.BytesIO(r.content), mode="r:gz") as t:
            member = next((m for m in t.getmembers()
                           if m.name.endswith("/sing-box") and m.isfile()), None)
            if not member:
                return None
            f = t.extractfile(member)
            if not f:
                return None
            out.write_bytes(f.read())
        _chmod_exec(out)
        print(f"[cores] sing-box -> {out}")
        return out
    except Exception as e:
        print(f"[cores] sing-box extract: {e}")
        return None


def ensure_curl() -> bool:
    if shutil.which("curl"):
        return True
    print("[cores] WARNING: curl не найден. Проверка конфигов работать не будет.")
    return False


def ensure_cores(needed_protos: set[str] | None = None) -> tuple[Path | None, Path | None]:
    """Скачать только нужные ядра. None = скачать оба."""
    need_xray = needed_protos is None or bool(needed_protos & XRAY_PROTOS)
    need_sb = needed_protos is None or bool(needed_protos & SINGBOX_PROTOS)
    xray = ensure_xray() if need_xray else None
    sb = ensure_singbox() if need_sb else None
    ensure_curl()
    return xray, sb


# ─────────────────────── tester ───────────────────────
def _net_and_sec(c: dict) -> tuple[str, str]:
    p = c["params"]
    net = (p.get("type") or p.get("net") or "tcp").lower()
    if net in ("http", "h2"): net = "http"
    sec = (p.get("security") or "").lower()
    if not sec and (p.get("tls") or "").lower() == "tls":
        sec = "tls"
    if sec not in ("tls", "reality"): sec = "none"
    return net, sec


def _stream(c: dict) -> dict | None:
    p = c["params"]
    net, sec = _net_and_sec(c)
    sni = p.get("sni") or p.get("peer") or p.get("host") or c["host"]
    st: dict = {"network": net}
    if net == "ws":
        ws = {"path": p.get("path") or "/"}
        if p.get("host"):
            ws["headers"] = {"Host": p["host"]}
        st["wsSettings"] = ws
    elif net == "grpc":
        st["grpcSettings"] = {"serviceName": p.get("serviceName") or p.get("path") or ""}
    elif net == "http":
        hs = {"path": p.get("path") or "/"}
        if p.get("host"):
            hs["host"] = [p["host"]]
        st["httpSettings"] = hs
    elif net == "quic":
        return None
    elif net not in ("tcp", "raw"):
        return None
    if sec == "tls":
        tls = {"serverName": sni, "allowInsecure": True}
        if p.get("alpn"):
            tls["alpn"] = [a for a in p["alpn"].split(",") if a]
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        st["security"] = "tls"
        st["tlsSettings"] = tls
    elif sec == "reality":
        st["security"] = "reality"
        st["realitySettings"] = {
            "serverName": sni, "fingerprint": p.get("fp") or "chrome",
            "publicKey": p.get("pbk") or "", "shortId": p.get("sid") or "",
            "spiderX": "",
        }
    else:
        st["security"] = "none"
    return st


def build_xray(c: dict, port: int) -> dict | None:
    st = _stream(c)
    if st is None:
        return None
    p = c["params"]
    proto = c["proto"]
    if proto in ("vless", "vmess"):
        if proto == "vless":
            user = {"id": c["id"], "encryption": "none"}
            if p.get("flow"):
                user["flow"] = p["flow"]
        else:
            try:
                aid = int(p.get("aid") or 0)
            except Exception:
                aid = 0
            user = {"id": c["id"], "alterId": aid, "security": p.get("scy") or "auto"}
        ob = {"protocol": proto, "tag": "proxy",
              "settings": {"vnext": [{"address": c["host"], "port": c["port"], "users": [user]}]},
              "streamSettings": st}
    elif proto == "trojan":
        ob = {"protocol": "trojan", "tag": "proxy",
              "settings": {"servers": [{"address": c["host"], "port": c["port"],
                                        "password": c["id"]}]},
              "streamSettings": st}
    elif proto == "ss":
        ob = {"protocol": "shadowsocks", "tag": "proxy",
              "settings": {"servers": [{"address": c["host"], "port": c["port"],
                                        "method": p.get("method"), "password": c["id"]}]},
              "streamSettings": {"network": "tcp"}}
    else:
        return None
    return {"log": {"loglevel": "none"},
            "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "socks",
                          "settings": {"auth": "noauth", "udp": False}}],
            "outbounds": [ob]}


def build_singbox(c: dict, port: int) -> dict | None:
    p = c["params"]
    tls = {"enabled": True,
           "server_name": p.get("sni") or p.get("peer") or c["host"],
           "insecure": True}
    if p.get("alpn"):
        tls["alpn"] = [a for a in p["alpn"].split(",") if a]
    if c["proto"] == "hysteria2":
        ob = {"type": "hysteria2", "tag": "proxy", "server": c["host"],
              "server_port": c["port"], "password": c["id"], "tls": tls}
        if p.get("obfs"):
            ob["obfs"] = {"type": p["obfs"], "password": p.get("obfs-password") or ""}
    elif c["proto"] == "tuic":
        ob = {"type": "tuic", "tag": "proxy", "server": c["host"],
              "server_port": c["port"], "uuid": c["id"],
              "password": c.get("password") or "", "tls": tls,
              "congestion_control": p.get("congestion_control") or "bbr"}
    else:
        return None
    return {"log": {"level": "error"},
            "inbounds": [{"type": "socks", "tag": "in",
                          "listen": "127.0.0.1", "listen_port": port}],
            "outbounds": [ob, {"type": "direct", "tag": "direct"}],
            "route": {"final": "proxy"}}


def _wait_port(port: int, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.3):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def _curl(port: int, url: str, timeout: int) -> tuple[bool, float | None]:
    cmd = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code} %{time_total}",
           "--socks5-hostname", f"127.0.0.1:{port}",
           "--max-time", str(timeout), url]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
    except Exception:
        return False, None
    if r.returncode != 0:
        return False, None
    parts = (r.stdout or "").strip().split()
    if len(parts) != 2:
        return False, None
    code, t = parts
    if code in ("200", "204"):
        try:
            return True, float(t)
        except ValueError:
            return False, None
    return False, None


class Tester:
    def __init__(self, cfg: dict):
        t = cfg.get("test") or {}
        self.enabled = bool(t.get("enabled", True))
        self.concurrency = int(t.get("concurrency", 24))
        self.timeout = int(t.get("timeout", 8))
        self.check_url = t.get("check_url") or "http://cp.cloudflare.com/generate_204"
        self.retries = int(t.get("retry_failed", 1))
        self.xray = CORES_DIR / "xray"
        self.singbox = CORES_DIR / "sing-box"

    def _exe_for(self, proto: str) -> Path | None:
        if proto in XRAY_PROTOS: return self.xray
        if proto in SINGBOX_PROTOS: return self.singbox
        return None

    def test_one(self, c: dict) -> dict:
        if not self.enabled:
            return {"ok": False, "ping": None, "status": "disabled"}
        exe = self._exe_for(c["proto"])
        if exe is None:
            return {"ok": False, "ping": None, "status": "unsupported"}
        if not exe.exists():
            return {"ok": False, "ping": None, "status": "no-core"}
        port = free_port()
        cfgobj = build_xray(c, port) if c["proto"] in XRAY_PROTOS else build_singbox(c, port)
        if cfgobj is None:
            return {"ok": False, "ping": None, "status": "unsupported"}
        path = TMP_DIR / f"cfg_{sha1(c['raw'])[:16]}_{port}.json"
        write_json(path, cfgobj)
        proc = None
        try:
            proc = subprocess.Popen([str(exe), "run", "-c", str(path)],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                    start_new_session=True)
            if not _wait_port(port, 5):
                return {"ok": False, "ping": None, "status": "no-listener"}
            for _ in range(self.retries + 1):
                ok, t = _curl(port, self.check_url, self.timeout)
                if ok:
                    return {"ok": True, "ping": max(1, int(t * 1000)), "status": "ok"}
            return {"ok": False, "ping": None, "status": "dead"}
        finally:
            if proc and proc.poll() is None:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except Exception:
                    proc.kill()
                try:
                    proc.wait(timeout=3)
                except Exception:
                    pass
            try:
                path.unlink()
            except OSError:
                pass

    def test_many(self, items: list[tuple[str, dict]]) -> dict[str, dict]:
        results: dict[str, dict] = {}
        total = len(items)
        if total == 0:
            return results
        done = 0
        with ThreadPoolExecutor(max_workers=max(1, self.concurrency)) as ex:
            futs = {ex.submit(self.test_one, c): h for h, c in items}
            for f in as_completed(futs):
                h = futs[f]
                try:
                    results[h] = f.result()
                except Exception as e:
                    results[h] = {"ok": False, "ping": None,
                                  "status": f"error:{type(e).__name__}"}
                done += 1
                if done % 50 == 0 or done == total:
                    okn = sum(1 for r in results.values() if r["ok"])
                    print(f"[test] {done}/{total} checked, {okn} ok")
        return results


# ─────────────────────── store ───────────────────────
def load_state() -> dict:
    st = read_json(DATA_DIR / "state.json", None)
    if not isinstance(st, dict) or "configs" not in st:
        st = {"version": 1, "configs": {}}
    return st


def save_state(st: dict) -> None:
    write_json(DATA_DIR / "state.json", st)


def update_state(st: dict, c: dict, h: str, res: dict,
                 geo_info: dict | None, sources, cfg: dict) -> dict:
    now = int(time.time())
    rec = st["configs"].get(h)
    if rec is None:
        rec = {"proto": c["proto"], "host": c["host"], "port": c["port"],
               "raw": c["raw"], "name_original": c["name"],
               "first_seen": now, "last_seen": now, "last_ok": 0,
               "ok_count": 0, "fail_count": 0, "fail_streak": 0,
               "ping": None, "country": "", "country_code": "", "ip": "",
               "sources": []}
        st["configs"][h] = rec
    rec["last_seen"] = now
    rec["raw"] = c["raw"]
    for s in sources or []:
        if s not in rec["sources"]:
            rec["sources"].append(s)
    if geo_info:
        rec["ip"] = geo_info.get("ip") or rec["ip"]
        rec["country"] = geo_info.get("country") or rec["country"]
        rec["country_code"] = geo_info.get("country_code") or rec["country_code"]
    status = (res or {}).get("status")
    if res and res.get("ok"):
        rec["ok_count"] += 1
        rec["fail_streak"] = 0
        rec["last_ok"] = now
        p = res.get("ping") or 0
        old = rec.get("ping")
        rec["ping"] = p if not old else int(0.6 * old + 0.4 * p)
    elif status in ("dead", "no-listener"):
        rec["fail_count"] += 1
        rec["fail_streak"] += 1
    return rec


def prune_state(st: dict, cfg: dict) -> int:
    d = int((cfg.get("storage") or {}).get("drop_after_fail_streak", 3))
    lim = int((cfg.get("storage") or {}).get("max_entries", 5000))
    drop = [h for h, r in st["configs"].items() if r["fail_streak"] >= d]
    for h in drop:
        del st["configs"][h]
    if len(st["configs"]) > lim:
        ordered = sorted(st["configs"].items(),
                         key=lambda kv: (kv[1].get("last_ok") or 0,
                                         kv[1].get("last_seen") or 0))
        for h, _ in ordered[: len(st["configs"]) - lim]:
            del st["configs"][h]
    return len(drop)


# ─────────────────────── naming ───────────────────────
def _pad_b64(s: str) -> str:
    s = s.replace("-", "+").replace("_", "/")
    return s + "=" * ((-len(s)) % 4)


def with_name(c: dict, name: str) -> str:
    raw = c["raw"]
    if raw.startswith("vmess://"):
        try:
            dec = base64.b64decode(_pad_b64(raw[len("vmess://"):]))
            d = json.loads(dec.decode("utf-8", "ignore"))
            d["ps"] = name
            enc = base64.b64encode(
                json.dumps(d, ensure_ascii=False).encode()
            ).decode().rstrip("=")
            return "vmess://" + enc
        except Exception:
            return raw
    base = raw.split("#", 1)[0]
    return base + "#" + quote(name, safe="")


# ─────────────────────── main ───────────────────────
def read_sources() -> list[str]:
    p = ROOT / "sources.txt"
    if not p.exists():
        print(f"[main] {p} не найден")
        return []
    out = []
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def cmd_run() -> int:
    ensure_dirs()
    cfg = load_config()
    urls = read_sources()
    if not urls:
        print("[main] нет ссылок в sources.txt — нечего делать")
        return 1

    state = load_state()
    parsed_by_source: OrderedDict[str, list[str]] = OrderedDict()
    configs: dict[str, dict] = {}
    src_of: dict[str, set[str]] = {}
    st_stats = {"sources": 0, "uris": 0, "parsed": 0, "parse_failed": 0, "unique": 0}

    for url in urls:
        text = fetch_subscription(url, cfg)
        if not text:
            continue
        st_stats["sources"] += 1
        uris = decode_payload(text)
        st_stats["uris"] += len(uris)
        parsed, failed = parse_many(uris)
        st_stats["parsed"] += len(parsed)
        st_stats["parse_failed"] += failed
        s = slug(url)
        lst = parsed_by_source.setdefault(s, [])
        for c in parsed:
            h = config_hash(c)
            if h not in configs:
                configs[h] = c
            src_of.setdefault(h, set()).add(s)
            if h not in lst:
                lst.append(h)
        print(f"[main] {s}: uris={len(uris)} parsed={len(parsed)} failed={failed}")

    st_stats["unique"] = len(configs)
    print(f"[main] unique configs: {len(configs)}")
    if not configs:
        print("[main] нечего проверять")
        return 0

    maxc = int((cfg.get("test") or {}).get("max_configs", 1500))
    if len(configs) > maxc:
        items = list(configs.items())
        items.sort(key=lambda kv: (0 if state["configs"].get(kv[0], {}).get("last_ok") else 1,
                                   kv[1]["host"]))
        keep = {h for h, _ in items[:maxc]}
        for h in list(configs):
            if h not in keep:
                del configs[h]
        for s in parsed_by_source:
            parsed_by_source[s] = [h for h in parsed_by_source[s] if h in keep]
        print(f"[main] capped to {len(configs)} (max={maxc})")

    # ── авто-скачивание только нужных ядер
    needed = {c["proto"] for c in configs.values()}
    print(f"[main] protocols in pool: {sorted(needed)}")
    ensure_cores(needed)

    tester = Tester(cfg)
    results = tester.test_many(list(configs.items()))

    geo = Geo(cfg)
    for c in configs.values():
        geo.resolve(c["host"])
    geo.lookup_many(list(geo._ip.values()))
    geo.save()

    for h, c in configs.items():
        res = results.get(h, {"ok": False, "ping": None, "status": "skipped"})
        update_state(state, c, h, res, geo.info(c["host"]),
                     src_of.get(h, set()), cfg)
    dropped = prune_state(state, cfg)
    save_state(state)
    if dropped:
        print(f"[main] pruned {dropped} dead config(s)")

    ncfg = cfg.get("naming") or {}
    template = ncfg.get("template", "{flag} {country} {index} | @VEXALORIAVPN")
    sort_by = ncfg.get("sort_by", "ping")
    include_untested = bool((cfg.get("test") or {}).get("include_untested", True))

    def ping_key(h: str):
        r = results.get(h) or {}
        return r.get("ping") or 10 ** 9

    def rec_of(h: str) -> dict:
        return state["configs"].get(h, {})

    def make_name(h: str, index: int) -> str:
        rec = rec_of(h)
        return template.format(
            flag=flag(rec.get("country_code") or ""),
            country=rec.get("country") or "Unknown",
            index=index,
        )

    working = [h for h in configs if (results.get(h) or {}).get("ok")]
    working.sort(key=ping_key)
    all_lines = [with_name(configs[h], make_name(h, i))
                 for i, h in enumerate(working, 1)]
    all_text = "\n".join(all_lines) + ("\n" if all_lines else "")
    write_text(OUT_DIR / "all.txt", all_text)
    write_text(OUT_DIR / "all_base64.txt",
               base64.b64encode(all_text.encode()).decode("ascii"))

    (OUT_DIR / "by_source").mkdir(parents=True, exist_ok=True)
    stats_rows = []
    for s, hashes in parsed_by_source.items():
        hs = []
        for h in hashes:
            r = results.get(h) or {}
            if r.get("ok"):
                hs.append(h)
            elif include_untested and r.get("status") in (
                    "untested", "unsupported", "no-core", "disabled", "skipped"):
                hs.append(h)
        if sort_by == "ping":
            hs.sort(key=ping_key)
        lines = []
        for i, h in enumerate(hs, 1):
            c = configs[h]
            lines.append(with_name(c, make_name(h, i)))
            rec = rec_of(h)
            total = (rec.get("ok_count") or 0) + (rec.get("fail_count") or 0)
            stats_rows.append({
                "source": s, "name": make_name(h, i),
                "proto": c["proto"], "host": c["host"], "port": c["port"],
                "ping": (results.get(h) or {}).get("ping"),
                "status": (results.get(h) or {}).get("status"),
                "country": rec.get("country") or "",
                "country_code": rec.get("country_code") or "",
                "uptime": round((rec.get("ok_count") or 0) / total, 3) if total else None,
            })
        write_text(OUT_DIR / "by_source" / f"{s}.txt",
                   "\n".join(lines) + ("\n" if lines else ""))
        print(f"[main] by_source/{s}.txt: {len(lines)} config(s)")

    write_json(OUT_DIR / "stats.json", {
        "generated_at": int(time.time()),
        "summary": {
            "sources": st_stats["sources"], "uris": st_stats["uris"],
            "parsed": st_stats["parsed"], "parse_failed": st_stats["parse_failed"],
            "unique": st_stats["unique"], "tested": len(results),
            "working": len(working),
        },
        "configs": stats_rows,
    })
    print(f"[main] done: unique={st_stats['unique']} tested={len(results)} "
          f"working={len(working)} out={OUT_DIR}")
    return 0


def cmd_check() -> int:
    ensure_dirs()
    ok = True
    print("[check] python deps: OK")  # прошли через _bootstrap() при импорте
    if shutil.which("curl"):
        print("[check] curl: OK")
    else:
        print("[check] curl: MISSING")
        ok = False
    x, s = ensure_cores(None)
    print(f"[check] xray: {'OK' if x else 'MISSING'}")
    print(f"[check] sing-box: {'OK' if s else 'MISSING'}")
    urls = read_sources()
    print(f"[check] sources.txt: {len(urls)} url(s)" if urls else "[check] sources.txt: пусто")
    print(f"[check] config.yaml: {'OK' if load_config() else 'defaults'}")
    return 0 if ok else 1


def main() -> int:
    cmd = sys.argv[1] if len(sys.argv) > 1 else "run"
    if cmd == "cores":
        ensure_dirs()
        ensure_cores(None)
        return 0
    if cmd == "check":
        return cmd_check()
    if cmd == "run":
        return cmd_run()
    print(f"unknown command: {cmd}. Use: run | cores | check")
    return 2


if __name__ == "__main__":
    sys.exit(main())
