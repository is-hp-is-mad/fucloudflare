"""Cross-platform offline simulators, protocol clients, and 3-node cluster harness.

Zero external network dependencies and zero dependency on playwright/aioquic/cbor2/fido2.
Works identically on Windows Python 3.11+ and Linux/WSL Python 3.10+.
"""
from __future__ import annotations

import base64
import ctypes
import datetime
import hashlib
import hmac
import http.client
import http.server
import json
import os
import secrets
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import urllib.parse
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.x509.oid import NameOID

try:
    import httpx  # type: ignore
except ImportError:
    httpx = None

try:
    import h2  # type: ignore
    import h2.config  # type: ignore
    import h2.connection  # type: ignore
    import h2.events  # type: ignore
except ImportError:
    h2 = None


class ContractConfig:
    """Centralized M1-M4 CLI flags and HTTP API endpoints per PROJECT.md Interface Contracts."""

    # CLI flags
    ROLE_FLAG = "--role"
    PEERS_FLAG = "--peers"
    PROXY_LISTEN_FLAG = "--proxy-listen"
    PROXY_TLS_LISTEN_FLAG = "--proxy-tls-listen"
    PANEL_HOST_FLAG = "--panel-host"
    ACME_DIR_FLAG = "--acme-directory"
    H3_FRONT_FLAG = "--h3-front-listen"
    EXPORT_DOMAINS_FLAG = "--export-domains"
    NODE_NAME_FLAG = "--node-name"

    # Roles
    ROLE_PEER = "peer"
    ROLE_ACCELERATE = "accelerate"

    # Hostnames
    PANEL_HOST = "dashboard.fucloudflare.com"
    AUTH_HOST = "auth.fucloudflare.com"

    # Sync & Control Plane API paths (under /client/v4 unless noted)
    SYNC_PATH = "/replication/sync"
    KV_NAMESPACES_PATH = "/kv/namespaces"
    D1_DATABASES_PATH = "/d1/database"
    WORKER_SCRIPTS_PATH = "/workers/scripts"
    WORKER_CRON_TRIGGER_PATH = "/workers/scripts/{name}/scheduled"
    PASSKEY_REGISTER_PATH = "/account/passkeys"
    PROXY_RULES_PATH = "/proxy/rules"
    OAUTH_CLIENTS_PATH = "/oauth/clients"
    PANEL_OAUTH_LOGIN_PATH = "/auth/oauth/login"
    PANEL_OAUTH_CALLBACK_PATH = "/auth/oauth/callback"

    # Default local CA discard address
    ACME_DISCARD = "http://127.0.0.1:9/directory"


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def free_port(dual_udp: bool = False) -> int:
    """Allocate an ephemeral port on 127.0.0.1 (optionally verifying UDP is free too)."""
    for _ in range(50):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        if not dual_udp:
            return port
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            u.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            u.close()
    raise RuntimeError("unable to allocate free port")


def wait_for(what: str, probe: Callable[[], Any], timeout: float = 15.0, interval: float = 0.2) -> Any:
    deadline = time.time() + timeout
    last_err = None
    while time.time() < deadline:
        try:
            got = probe()
            if got:
                return got
        except Exception as exc:  # noqa: BLE001
            last_err = exc
        time.sleep(interval)
    detail = f" ({last_err})" if last_err else ""
    raise AssertionError(f"timed out waiting for: {what}{detail}")


def rss_bytes(pid: int) -> int:
    """Return resident set size in bytes for `pid` on Windows or Linux."""
    if os.name == "nt":
        class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
            _fields_ = [
                ("cb", ctypes.c_ulong),
                ("PageFaultCount", ctypes.c_ulong),
                ("PeakWorkingSetSize", ctypes.c_size_t),
                ("WorkingSetSize", ctypes.c_size_t),
                ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPagedPoolUsage", ctypes.c_size_t),
                ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                ("PagefileUsage", ctypes.c_size_t),
                ("PeakPagefileUsage", ctypes.c_size_t),
            ]

        PROCESS_QUERY_INFORMATION = 0x0400
        PROCESS_VM_READ = 0x0010
        k32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
        if not h:
            raise OSError(f"OpenProcess failed for pid={pid}")
        try:
            pmc = PROCESS_MEMORY_COUNTERS()
            pmc.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if not psapi.GetProcessMemoryInfo(h, ctypes.byref(pmc), pmc.cb):
                raise OSError(f"GetProcessMemoryInfo failed for pid={pid}")
            return int(pmc.WorkingSetSize)
        finally:
            k32.CloseHandle(h)
    with open(f"/proc/{pid}/statm", "r", encoding="utf-8") as f:
        parts = f.read().split()
    pages = int(parts[1])
    return pages * os.sysconf("SC_PAGE_SIZE")


# ---------------------------------------------------------------------------
# Pure-Python CBOR Encoder + WebAuthn Simulator
# ---------------------------------------------------------------------------


def _cbor_head(major: int, n: int) -> bytes:
    mt = major << 5
    if n < 24:
        return bytes([mt | n])
    if n < 0x100:
        return bytes([mt | 24, n])
    if n < 0x10000:
        return bytes([mt | 25]) + struct.pack(">H", n)
    if n < 0x100000000:
        return bytes([mt | 26]) + struct.pack(">I", n)
    return bytes([mt | 27]) + struct.pack(">Q", n)


def cbor_encode(obj: Any) -> bytes:
    """Minimal RFC 8949 CBOR encoder supporting int, bytes, str, list, dict, bool, None."""
    if obj is None:
        return b"\xf6"
    if isinstance(obj, bool):
        return b"\xf5" if obj else b"\xf4"
    if isinstance(obj, int):
        if obj >= 0:
            return _cbor_head(0, obj)
        return _cbor_head(1, -1 - obj)
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
        return _cbor_head(2, len(raw)) + raw
    if isinstance(obj, str):
        raw = obj.encode("utf-8")
        return _cbor_head(3, len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return _cbor_head(4, len(obj)) + b"".join(cbor_encode(x) for x in obj)
    if isinstance(obj, dict):
        items = [(cbor_encode(k), cbor_encode(v)) for k, v in obj.items()]
        items.sort(key=lambda kv: (len(kv[0]), kv[0]))
        return _cbor_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise TypeError(f"unsupported CBOR type: {type(obj)!r}")


class WebAuthnSimulator:
    """Pure-Python + cryptography software FIDO2 / WebAuthn authenticator."""

    def __init__(self, alg: int = -7, cred_id: bytes | None = None):
        if alg not in (-7, -8, -257):
            raise ValueError(f"unsupported COSE alg: {alg}")
        self.alg = alg
        self.raw_cred_id = cred_id or os.urandom(16)
        self.id = b64u_encode(self.raw_cred_id)
        self.sign_count = 0

        if alg == -7:
            self.private_key = ec.generate_private_key(ec.SECP256R1())
        elif alg == -8:
            self.private_key = ed25519.Ed25519PrivateKey.generate()
        else:
            self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

        self.spki_der = self.private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.public_key = b64u_encode(self.spki_der)

    def _cose_public_key(self) -> dict[int, Any]:
        pub = self.private_key.public_key()
        if self.alg == -7:
            nums = pub.public_numbers()  # type: ignore[union-attr]
            return {
                1: 2,  # EC2
                3: -7,  # ES256
                -1: 1,  # P-256
                -2: nums.x.to_bytes(32, "big"),
                -3: nums.y.to_bytes(32, "big"),
            }
        if self.alg == -8:
            raw = pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return {1: 1, 3: -8, -1: 6, -2: raw}  # OKP / Ed25519
        nums = pub.public_numbers()  # type: ignore[union-attr]
        n_bytes = nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big")
        e_bytes = nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")
        return {1: 3, 3: -257, -1: n_bytes, -2: e_bytes}

    def register(
        self,
        challenge: str,
        origin: str,
        flags: int = 0x45,  # UP | UV | AT
        name: str = "sim-key",
        rp_id_override: str | None = None,
        cross_origin: bool = False,
        alg_override: int | None = None,
    ) -> dict[str, Any]:
        rp_id = rp_id_override or (urllib.parse.urlparse(origin).hostname or "localhost")
        client_data = json.dumps(
            {
                "type": "webauthn.create",
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": cross_origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        self.sign_count += 1
        auth_data = hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + struct.pack(">I", self.sign_count)
        if flags & 0x40:
            aaguid = b"\x00" * 16
            cose = cbor_encode(self._cose_public_key())
            auth_data += aaguid + struct.pack(">H", len(self.raw_cred_id)) + self.raw_cred_id + cose

        att_obj = cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth_data})
        cd_b64 = b64u_encode(client_data)
        ad_b64 = b64u_encode(auth_data)
        return {
            # Fields expected by src/auth.rs
            "id": self.id,
            "public_key": self.public_key,
            "alg": self.alg if alg_override is None else alg_override,
            "client_data": cd_b64,
            "authenticator_data": ad_b64,
            "name": name,
            # Standard WebAuthn Level 2 shape for auth.fucloudflare.com Worker
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": cd_b64,
                "attestationObject": b64u_encode(att_obj),
                "authenticatorData": ad_b64,
                "publicKey": self.public_key,
                "publicKeyAlgorithm": self.alg if alg_override is None else alg_override,
            },
        }

    def _sign(self, payload: bytes) -> bytes:
        if self.alg == -7:
            return self.private_key.sign(payload, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
        if self.alg == -8:
            return self.private_key.sign(payload)  # type: ignore[union-attr]
        return self.private_key.sign(payload, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]

    def assert_login(
        self,
        challenge: str,
        origin: str,
        flags: int = 0x05,  # UP | UV
        rp_id_override: str | None = None,
        count_override: int | None = None,
        cross_origin: bool = False,
        tamper_sig: bool = False,
        tamper_auth_data: bool = False,
    ) -> dict[str, Any]:
        rp_id = rp_id_override or (urllib.parse.urlparse(origin).hostname or "localhost")
        client_data = json.dumps(
            {
                "type": "webauthn.get",
                "challenge": challenge,
                "origin": origin,
                "crossOrigin": cross_origin,
            },
            separators=(",", ":"),
        ).encode("utf-8")

        cnt = count_override if count_override is not None else (self.sign_count + 1)
        self.sign_count = cnt
        auth_data = bytearray(
            hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags]) + struct.pack(">I", cnt)
        )
        signed = bytes(auth_data) + hashlib.sha256(client_data).digest()
        sig = bytearray(self._sign(signed))
        if tamper_sig and sig:
            sig[-1] ^= 0xFF
        if tamper_auth_data:
            auth_data[0] ^= 0xFF

        cd_b64 = b64u_encode(client_data)
        ad_b64 = b64u_encode(bytes(auth_data))
        sig_b64 = b64u_encode(bytes(sig))
        return {
            # Fields expected by src/auth.rs
            "id": self.id,
            "client_data": cd_b64,
            "authenticator_data": ad_b64,
            "signature": sig_b64,
            # Standard WebAuthn Level 2 shape for auth.fucloudflare.com Worker
            "rawId": self.id,
            "type": "public-key",
            "response": {
                "clientDataJSON": cd_b64,
                "authenticatorData": ad_b64,
                "signature": sig_b64,
                "userHandle": None,
            },
        }

    @staticmethod
    def verify_assertion(spki_der: bytes, alg: int, auth_data: bytes, client_data: bytes, signature: bytes) -> bool:
        pub = serialization.load_der_public_key(spki_der)
        signed = auth_data + hashlib.sha256(client_data).digest()
        try:
            if alg == -7:
                pub.verify(signature, signed, ec.ECDSA(hashes.SHA256()))  # type: ignore[union-attr]
            elif alg == -8:
                pub.verify(signature, signed)  # type: ignore[union-attr]
            elif alg == -257:
                pub.verify(signature, signed, padding.PKCS1v15(), hashes.SHA256())  # type: ignore[union-attr]
            else:
                return False
            return True
        except Exception:  # noqa: BLE001
            return False


# ---------------------------------------------------------------------------
# Local Mock Linux.do Connect & Custom OAuth2 Server
# ---------------------------------------------------------------------------


class MockOAuthServer:
    """Offline mock OAuth2 / Linux.do Connect provider on 127.0.0.1:0."""

    def __init__(self, client_id: str = "fucf-linuxdo-client", client_secret: str = "fucf-linuxdo-secret"):
        self.client_id = client_id
        self.client_secret = client_secret
        self.persona = "normal"  # normal | no_email | silenced | inactive | deny
        self.user_id = 4242
        self.username = "linuxdo_tester"
        self.name = "LinuxDo Tester"
        self.email = "linuxdo_tester@example.test"
        self._lock = threading.Lock()
        self._codes: dict[str, dict[str, Any]] = {}
        self._tokens: dict[str, dict[str, Any]] = {}
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port = 0
        self.requests_seen: list[tuple[str, str]] = []

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "MockOAuthServer":
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):  # noqa: ANN002
                pass

            def _send_json(self, code: int, obj: Any) -> None:
                raw = json.dumps(obj).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                parent.requests_seen.append(("GET", parsed.path))
                if parsed.path in ("/oauth2/authorize", "/authorize"):
                    qs = urllib.parse.parse_qs(parsed.query)
                    cid = (qs.get("client_id") or [""])[0]
                    redir = (qs.get("redirect_uri") or [""])[0]
                    state = (qs.get("state") or [""])[0]
                    rtype = (qs.get("response_type") or [""])[0]
                    if cid != parent.client_id or not redir or rtype != "code":
                        self._send_json(400, {"error": "invalid_request"})
                        return
                    sep = "&" if "?" in redir else "?"
                    if parent.persona == "deny":
                        loc = f"{redir}{sep}error=access_denied&state={urllib.parse.quote(state)}"
                        self.send_response(302)
                        self.send_header("Location", loc)
                        self.end_headers()
                        return
                    code = "ld_code_" + secrets.token_urlsafe(16)
                    with parent._lock:
                        parent._codes[code] = {
                            "client_id": cid,
                            "redirect_uri": redir,
                            "persona": parent.persona,
                            "used": False,
                        }
                    loc = f"{redir}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                    self.send_response(302)
                    self.send_header("Location", loc)
                    self.end_headers()
                    return

                if parsed.path in ("/api/user", "/oauth2/userinfo", "/userinfo"):
                    auth = self.headers.get("Authorization", "")
                    if not auth.startswith("Bearer "):
                        self._send_json(401, {"error": "unauthorized"})
                        return
                    tok = auth[7:].strip()
                    with parent._lock:
                        info = parent._tokens.get(tok)
                    if not info:
                        self._send_json(401, {"error": "invalid_token"})
                        return
                    p = info["persona"]
                    payload: dict[str, Any] = {
                        "id": parent.user_id,
                        "sub": f"linuxdo:{parent.user_id}",
                        "username": parent.username,
                        "preferred_username": parent.username,
                        "name": parent.name,
                        "trust_level": 2,
                        "active": p != "inactive",
                        "silenced": p == "silenced",
                        "avatar_template": "/avatar/{size}.png",
                    }
                    if p != "no_email":
                        payload["email"] = parent.email
                    self._send_json(200, payload)
                    return

                self._send_json(404, {"error": "not_found"})

            def do_POST(self) -> None:
                parsed = urllib.parse.urlparse(self.path)
                parent.requests_seen.append(("POST", parsed.path))
                if parsed.path not in ("/oauth2/token", "/token"):
                    self._send_json(404, {"error": "not_found"})
                    return
                n = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(n).decode("utf-8", "replace")
                form = urllib.parse.parse_qs(raw)
                cid = (form.get("client_id") or [""])[0]
                csec = (form.get("client_secret") or [""])[0]
                auth = self.headers.get("Authorization", "")
                if auth.startswith("Basic "):
                    try:
                        decoded = base64.b64decode(auth[6:].strip()).decode("utf-8")
                        cid, csec = decoded.split(":", 1)
                    except Exception:  # noqa: BLE001
                        self._send_json(401, {"error": "invalid_client"})
                        return
                if cid != parent.client_id or csec != parent.client_secret:
                    self._send_json(401, {"error": "invalid_client"})
                    return
                grant_type = (form.get("grant_type") or [""])[0]
                if grant_type != "authorization_code":
                    self._send_json(400, {"error": "unsupported_grant_type"})
                    return
                code = (form.get("code") or [""])[0]
                redir = (form.get("redirect_uri") or [""])[0]
                with parent._lock:
                    entry = parent._codes.get(code)
                    if not entry or entry["used"] or entry["client_id"] != cid or entry["redirect_uri"] != redir:
                        self._send_json(400, {"error": "invalid_grant"})
                        return
                    entry["used"] = True
                    access_token = "ld_tok_" + secrets.token_urlsafe(24)
                    parent._tokens[access_token] = {"persona": entry["persona"]}
                self._send_json(
                    200,
                    {
                        "access_token": access_token,
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "scope": "user",
                    },
                )

        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None


# ---------------------------------------------------------------------------
# Local Test Origins: HTTP/HTTPS, h2c, WebSocket (RFC 6455), and SSE
# ---------------------------------------------------------------------------


def _generate_self_signed_pem(cn: str = "origin.local") -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(cn), x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


class TestOriginServer:
    """Configurable local HTTP/1.1 (or TLS) origin for edge, proxy, and streaming checks."""

    def __init__(self, tag: str = "origin1", use_tls: bool = False):
        self.tag = tag
        self.use_tls = use_tls
        self.hits = 0
        self.requests: list[dict[str, Any]] = []
        self._server: http.server.ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self._cert_dir: str | None = None
        self.port = 0

    @property
    def url(self) -> str:
        scheme = "https" if self.use_tls else "http"
        return f"{scheme}://127.0.0.1:{self.port}"

    def start(self) -> "TestOriginServer":
        parent = self

        class Handler(http.server.BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *args):  # noqa: ANN002
                pass

            def _handle(self, method: str) -> None:
                parent.hits += 1
                te = (self.headers.get("Transfer-Encoding") or "").lower()
                body = b""
                if "chunked" in te:
                    chunks = []
                    while True:
                        line = self.rfile.readline()
                        if not line:
                            break
                        sz = int(line.strip().split(b";", 1)[0], 16)
                        if sz == 0:
                            while self.rfile.readline() not in (b"\r\n", b"\n", b""):
                                pass
                            break
                        chunks.append(self.rfile.read(sz))
                        self.rfile.read(2)
                    body = b"".join(chunks)
                else:
                    clen = int(self.headers.get("Content-Length", "0") or "0")
                    if clen > 0:
                        body = self.rfile.read(clen)

                parsed = urllib.parse.urlparse(self.path)
                qs = urllib.parse.parse_qs(parsed.query)
                hdrs = {k.lower(): v for k, v in self.headers.items()}
                parent.requests.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": hdrs,
                        "body_len": len(body),
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                    }
                )

                if parsed.path == "/slow":
                    ms = int((qs.get("ms") or ["200"])[0])
                    time.sleep(ms / 1000.0)

                if parsed.path == "/large":
                    mb = float((qs.get("mb") or ["1"])[0])
                    total = int(mb * 1024 * 1024)
                    block = (b"0123456789abcdef" * 4096)  # 64 KiB
                    h = hashlib.sha256()
                    rem = total
                    while rem > 0:
                        take = min(rem, len(block))
                        h.update(block[:take])
                        rem -= take
                    digest = h.hexdigest()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/octet-stream")
                    self.send_header("Content-Length", str(total))
                    self.send_header("X-Stream-SHA256", digest)
                    self.send_header("X-Origin-Tag", parent.tag)
                    self.end_headers()
                    rem = total
                    while rem > 0:
                        take = min(rem, len(block))
                        self.wfile.write(block[:take])
                        rem -= take
                    self.wfile.flush()
                    return

                if parsed.path.startswith("/status/"):
                    code = int(parsed.path.rsplit("/", 1)[-1])
                    payload = json.dumps({"tag": parent.tag, "status": code}).encode("utf-8")
                    self.send_response(code)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                    return

                payload = json.dumps(
                    {
                        "tag": parent.tag,
                        "method": method,
                        "path": self.path,
                        "host": self.headers.get("Host"),
                        "headers": hdrs,
                        "body_len": len(body),
                        "body_sha256": hashlib.sha256(body).hexdigest(),
                        "remote": self.client_address[0],
                    }
                ).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Server", f"test-origin/{parent.tag}")
                self.send_header("Alt-Svc", 'h3=":443"')
                self.send_header("X-Origin-Tag", parent.tag)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self) -> None:
                self._handle("GET")

            def do_POST(self) -> None:
                self._handle("POST")

            def do_PUT(self) -> None:
                self._handle("PUT")

            def do_DELETE(self) -> None:
                self._handle("DELETE")

        class _ReuseHTTPServer(http.server.ThreadingHTTPServer):
            allow_reuse_address = True

        self._server = _ReuseHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._server.server_address[1]
        if self.use_tls:
            self._cert_dir = tempfile.mkdtemp(prefix="fucf-test-origin-")
            cert_pem, key_pem = _generate_self_signed_pem()
            cert_p = os.path.join(self._cert_dir, "cert.pem")
            key_p = os.path.join(self._cert_dir, "key.pem")
            with open(cert_p, "wb") as f:
                f.write(cert_pem)
            with open(key_p, "wb") as f:
                f.write(key_pem)
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(cert_p, key_p)
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._cert_dir:
            shutil.rmtree(self._cert_dir, ignore_errors=True)
            self._cert_dir = None


class H2OriginServer:
    """Cleartext HTTP/2 (h2c) origin server using `h2` when available, with stdlib h2c fallback."""

    def __init__(self, tag: str = "h2c-origin"):
        self.tag = tag
        self.hits = 0
        self.requests: list[dict[str, Any]] = []
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False
        self.port = 0

    @property
    def url(self) -> str:
        return f"h2c://127.0.0.1:{self.port}"

    def start(self) -> "H2OriginServer":
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop and self._sock:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket) -> None:
        if h2 is not None:
            self._handle_with_h2(conn)
        else:
            self._handle_stdlib_h2c(conn)

    def _handle_with_h2(self, conn: socket.socket) -> None:
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        h2conn = h2.connection.H2Connection(config=cfg)
        h2conn.initiate_connection()
        streams: dict[int, dict[str, Any]] = {}
        try:
            conn.sendall(h2conn.data_to_send())
            conn.settimeout(5.0)
            while not self._stop:
                data = conn.recv(65535)
                if not data:
                    break
                events = h2conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        hdrs = {k.lower(): v for k, v in ev.headers}
                        streams[ev.stream_id] = {"headers": hdrs, "body": bytearray()}
                    elif isinstance(ev, h2.events.DataReceived):
                        if ev.stream_id in streams:
                            streams[ev.stream_id]["body"].extend(ev.data)
                        h2conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                    elif isinstance(ev, h2.events.StreamEnded):
                        st = streams.pop(ev.stream_id, {"headers": {}, "body": b""})
                        self.hits += 1
                        hdrs = st["headers"]
                        self.requests.append({"headers": hdrs, "body_len": len(st["body"])})
                        payload = json.dumps(
                            {
                                "tag": self.tag,
                                "proto": "h2c",
                                "path": hdrs.get(":path", "/"),
                                "method": hdrs.get(":method", "GET"),
                                "authority": hdrs.get(":authority", hdrs.get("host", "")),
                                "headers": hdrs,
                            }
                        ).encode("utf-8")
                        h2conn.send_headers(
                            ev.stream_id,
                            [
                                (":status", "200"),
                                ("content-type", "application/json"),
                                ("server", f"h2c-origin/{self.tag}"),
                                ("content-length", str(len(payload))),
                            ],
                        )
                        h2conn.send_data(ev.stream_id, payload, end_stream=True)
                out = h2conn.data_to_send()
                if out:
                    conn.sendall(out)
        except OSError:
            pass
        finally:
            conn.close()

    def _handle_stdlib_h2c(self, conn: socket.socket) -> None:
        """Minimal RFC 7540 h2c server fallback when `h2` package is absent (e.g. WSL)."""
        preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        try:
            conn.settimeout(5.0)
            buf = b""
            while len(buf) < len(preface):
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            if not buf.startswith(preface):
                return
            buf = buf[len(preface):]
            # Send empty server SETTINGS frame
            conn.sendall(b"\x00\x00\x00\x04\x00\x00\x00\x00\x00")
            while not self._stop:
                while len(buf) < 9:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                length = int.from_bytes(buf[0:3], "big")
                ftype = buf[3]
                flags = buf[4]
                sid = struct.unpack(">I", buf[5:9])[0] & 0x7FFFFFFF
                while len(buf) < 9 + length:
                    chunk = conn.recv(4096)
                    if not chunk:
                        return
                    buf += chunk
                payload_in = buf[9:9 + length]
                buf = buf[9 + length:]
                if ftype == 4 and not (flags & 0x01):
                    # ACK SETTINGS
                    conn.sendall(b"\x00\x00\x00\x04\x01\x00\x00\x00\x00")
                elif ftype == 1 and (flags & 0x01):  # HEADERS + END_STREAM
                    self.hits += 1
                    self.requests.append({"headers": {}, "body_len": 0, "stream_id": sid})
                    body = json.dumps({"tag": self.tag, "proto": "h2c", "stream_id": sid}).encode("utf-8")
                    # Static HPACK: 0x88 = :status: 200
                    hdr_block = b"\x88"
                    conn.sendall(len(hdr_block).to_bytes(3, "big") + b"\x01\x04" + struct.pack(">I", sid) + hdr_block)
                    conn.sendall(len(body).to_bytes(3, "big") + b"\x00\x01" + struct.pack(">I", sid) + body)
                elif ftype == 0 and (flags & 0x01):  # DATA + END_STREAM
                    self.hits += 1
                    self.requests.append({"headers": {}, "body_len": len(payload_in), "stream_id": sid})
                    body = json.dumps({"tag": self.tag, "proto": "h2c", "stream_id": sid}).encode("utf-8")
                    hdr_block = b"\x88"
                    conn.sendall(len(hdr_block).to_bytes(3, "big") + b"\x01\x04" + struct.pack(">I", sid) + hdr_block)
                    conn.sendall(len(body).to_bytes(3, "big") + b"\x00\x01" + struct.pack(">I", sid) + body)
                elif ftype == 7:  # GOAWAY
                    return
        except OSError:
            pass
        finally:
            conn.close()

    def stop(self) -> None:
        self._stop = True
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Pure-Stdlib RFC 6455 WebSocket Server & Client
# ---------------------------------------------------------------------------

_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def _ws_read_frame(sock: socket.socket) -> tuple[int, bytes]:
    def exact(n: int) -> bytes:
        buf = bytearray()
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                raise EOFError("websocket EOF")
            buf.extend(chunk)
        return bytes(buf)

    b1, b2 = exact(2)
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack(">H", exact(2))[0]
    elif length == 127:
        length = struct.unpack(">Q", exact(8))[0]
    mask = exact(4) if masked else b""
    payload = exact(length)
    if masked:
        payload = bytes(payload[i] ^ mask[i % 4] for i in range(length))
    return opcode, payload


def _ws_write_frame(sock: socket.socket, opcode: int, data: bytes, mask_client: bool) -> None:
    hdr = bytearray([0x80 | (opcode & 0x0F)])
    n = len(data)
    mbit = 0x80 if mask_client else 0x00
    if n < 126:
        hdr.append(mbit | n)
    elif n < 65536:
        hdr.append(mbit | 126)
        hdr.extend(struct.pack(">H", n))
    else:
        hdr.append(mbit | 127)
        hdr.extend(struct.pack(">Q", n))
    if mask_client:
        mask = os.urandom(4)
        hdr.extend(mask)
        masked_data = bytes(data[i] ^ mask[i % 4] for i in range(n))
        sock.sendall(bytes(hdr) + masked_data)
    else:
        sock.sendall(bytes(hdr) + data)


class WsEchoServer:
    """Pure-stdlib RFC 6455 WebSocket echo server on 127.0.0.1:0."""

    def __init__(self, tag: str = "ws-echo"):
        self.tag = tag
        self.connections = 0
        self.active_connections = 0
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    @property
    def ws_url(self) -> str:
        return f"ws://127.0.0.1:{self.port}"

    def start(self) -> "WsEchoServer":
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop and self._sock:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        self.active_connections += 1
        try:
            conn.settimeout(10.0)
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
            head = raw.split(b"\r\n\r\n", 1)[0].decode("latin1")
            lines = head.split("\r\n")
            req_line = lines[0]
            path = req_line.split(" ")[1] if len(req_line.split(" ")) >= 2 else "/"
            hdrs = {}
            for ln in lines[1:]:
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    hdrs[k.strip().lower()] = v.strip()

            if path == "/reject-403":
                conn.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nforbidden")
                return

            key = hdrs.get("sec-websocket-key", "")
            accept = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode("ascii")).digest()).decode("ascii")
            self.connections += 1
            conn.sendall(
                (
                    "HTTP/1.1 101 Switching Protocols\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Accept: {accept}\r\n"
                    f"X-Ws-Tag: {self.tag}\r\n\r\n"
                ).encode("ascii")
            )
            while not self._stop:
                opcode, payload = _ws_read_frame(conn)
                if opcode == 0x8:  # Close
                    _ws_write_frame(conn, 0x8, b"", mask_client=False)
                    break
                if opcode == 0x9:  # Ping
                    _ws_write_frame(conn, 0xA, payload, mask_client=False)
                elif opcode in (0x1, 0x2):
                    _ws_write_frame(conn, opcode, payload, mask_client=False)
        except (OSError, EOFError):
            pass
        finally:
            self.active_connections -= 1
            conn.close()

    def stop(self) -> None:
        self._stop = True
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


def ws_connect(
    host: str,
    port: int,
    path: str = "/",
    headers: dict[str, str] | None = None,
    use_tls: bool = False,
    server_hostname: str | None = None,
    timeout: float = 10.0,
) -> tuple[socket.socket, int, dict[str, str]]:
    """Connect pure-stdlib RFC 6455 WebSocket client; returns (sock, status_code, resp_headers)."""
    raw_sock = socket.create_connection((host, port), timeout=timeout)
    sock: socket.socket = raw_sock
    if use_tls:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        sock = ctx.wrap_socket(raw_sock, server_hostname=server_hostname or (headers or {}).get("Host") or host)
    sock.settimeout(timeout)

    key = base64.b64encode(os.urandom(16)).decode("ascii")
    req_hdrs = {
        "Host": f"{host}:{port}",
        "Upgrade": "websocket",
        "Connection": "Upgrade",
        "Sec-WebSocket-Key": key,
        "Sec-WebSocket-Version": "13",
    }
    if headers:
        req_hdrs.update(headers)
    req = f"GET {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in req_hdrs.items()) + "\r\n"
    sock.sendall(req.encode("latin1"))

    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise EOFError("EOF before WebSocket handshake response")
        buf += chunk
    head = buf.split(b"\r\n\r\n", 1)[0].decode("latin1")
    lines = head.split("\r\n")
    status = int(lines[0].split(" ")[1])
    resp_hdrs: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            resp_hdrs[k.strip().lower()] = v.strip()
    return sock, status, resp_hdrs


def ws_send(sock: socket.socket, data: str | bytes, opcode: int | None = None) -> None:
    if isinstance(data, str):
        op = 0x1 if opcode is None else opcode
        payload = data.encode("utf-8")
    else:
        op = 0x2 if opcode is None else opcode
        payload = data
    _ws_write_frame(sock, op, payload, mask_client=True)


def ws_recv(sock: socket.socket, timeout: float = 10.0) -> tuple[int, bytes]:
    sock.settimeout(timeout)
    return _ws_read_frame(sock)


def ws_close(sock: socket.socket) -> None:
    try:
        _ws_write_frame(sock, 0x8, b"", mask_client=True)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# SSE / Chunked Real-Time Streaming Origin
# ---------------------------------------------------------------------------


class SseOriginServer:
    """Real-time SSE and mid-stream reset origin on 127.0.0.1:0."""

    def __init__(self, tag: str = "sse-origin"):
        self.tag = tag
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False
        self.port = 0

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> "SseOriginServer":
        self._sock = socket.create_server(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()
        return self

    def _serve(self) -> None:
        while not self._stop and self._sock:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn: socket.socket) -> None:
        try:
            conn.settimeout(5.0)
            raw = b""
            while b"\r\n\r\n" not in raw:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                raw += chunk
            first = raw.split(b"\r\n", 1)[0].decode("latin1")
            path = first.split(" ")[1] if len(first.split(" ")) >= 2 else "/sse"
            parsed = urllib.parse.urlparse(path)
            qs = urllib.parse.parse_qs(parsed.query)

            if parsed.path == "/reset-mid":
                conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"
                )
                msg = b"data: partial\n\n"
                conn.sendall(f"{len(msg):x}\r\n".encode("ascii") + msg + b"\r\n")
                time.sleep(0.05)
                # Abrupt close without terminating 0\r\n\r\n chunk
                conn.close()
                return

            count = int((qs.get("count") or ["4"])[0])
            delay_ms = int((qs.get("delay_ms") or ["250"])[0])
            conn.sendall(
                (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/event-stream\r\n"
                    "Cache-Control: no-cache\r\n"
                    "Transfer-Encoding: chunked\r\n"
                    f"X-Sse-Tag: {self.tag}\r\n\r\n"
                ).encode("ascii")
            )
            for i in range(count):
                evt = f"id: {i}\ndata: tick-{i}-{self.tag}\n\n".encode("utf-8")
                conn.sendall(f"{len(evt):x}\r\n".encode("ascii") + evt + b"\r\n")
                if i + 1 < count:
                    time.sleep(delay_ms / 1000.0)
            conn.sendall(b"0\r\n\r\n")
        except OSError:
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self) -> None:
        self._stop = True
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None


# ---------------------------------------------------------------------------
# Protocol Clients: HTTP/2 (httpx+h2 or curl --http2) & HTTP/3 (fucf h3-get)
# ---------------------------------------------------------------------------


class H2Client:
    """HTTP/2 client using httpx+h2 when available, with clean curl --http2 fallback."""

    @staticmethod
    def request(
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
        prior_knowledge: bool = False,
        timeout: float = 15.0,
    ) -> tuple[int, dict[str, str], bytes, str]:
        if httpx is not None and h2 is not None and not prior_knowledge:
            with httpx.Client(http2=True, verify=False, timeout=timeout) as client:
                r = client.request(method, url, headers=headers or {}, content=body)
                return r.status_code, {k.lower(): v for k, v in r.headers.items()}, r.content, r.http_version

        curl_bin = "curl.exe" if os.name == "nt" else "curl"
        cmd = [curl_bin, "-sS", "-k", "-i", "--max-time", str(int(timeout)), "-X", method]
        if prior_knowledge:
            cmd.append("--http2-prior-knowledge")
        else:
            cmd.append("--http2")
        for k, v in (headers or {}).items():
            cmd.extend(["-H", f"{k}: {v}"])
        if body is not None:
            cmd.extend(["--data-binary", "@-"])
        cmd.append(url)
        res = subprocess.run(cmd, input=body, capture_output=True, timeout=timeout + 5)
        if res.returncode != 0:
            raise RuntimeError(f"curl HTTP/2 failed ({res.returncode}): {res.stderr.decode('utf-8', 'replace')}")
        raw = res.stdout
        sep = b"\r\n\r\n" if b"\r\n\r\n" in raw else b"\n\n"
        head_bytes, body_bytes = raw.split(sep, 1)
        head_lines = head_bytes.decode("latin1").splitlines()
        parts = head_lines[0].split(" ", 2)
        proto = parts[0]
        status = int(parts[1])
        hdrs: dict[str, str] = {}
        for ln in head_lines[1:]:
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        return status, hdrs, body_bytes, proto


class H3Client:
    """HTTP/3 client backed by `fucf h3-get --connect 127.0.0.1:<port> --insecure`."""

    def __init__(self, fucf_bin: str):
        self.bin = fucf_bin

    def get(self, url: str, connect_port: int | None = None, timeout: float = 30.0) -> tuple[int, dict[str, str], str, str]:
        connect_arg = f"127.0.0.1:{connect_port}" if connect_port else "127.0.0.1"
        cmd = [self.bin, "h3-get", url, "--connect", connect_arg, "--insecure"]
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        out = res.stdout
        if res.returncode != 0 or not out.startswith("HTTP/3"):
            raise RuntimeError(f"h3-get failed (rc={res.returncode}): stdout={out!r} stderr={res.stderr!r}")
        lines = out.splitlines()
        first = lines[0].split()
        status = int(first[1])
        hdrs: dict[str, str] = {}
        body_start = len(lines)
        for i, ln in enumerate(lines[1:], start=1):
            if ln == "":
                body_start = i + 1
                break
            if ":" in ln:
                k, v = ln.split(":", 1)
                hdrs[k.strip().lower()] = v.strip()
        body = "\n".join(lines[body_start:])
        return status, hdrs, body, out


# ---------------------------------------------------------------------------
# 3-Node Local Cluster Harness (`peer_a`, `peer_b`, `accel_jp`)
# ---------------------------------------------------------------------------


class NodeHandle:
    def __init__(
        self,
        name: str,
        role: str,
        edge_ip: str,
        ports: dict[str, int],
        data_dir: str,
        panel_host: str | None = None,
        extra_args: list[str] | None = None,
    ):
        self.name = name
        self.role = role
        self.edge_ip = edge_ip
        self.ports = ports
        self.data_dir = data_dir
        self.panel_host = panel_host
        self.extra_args = extra_args or []
        self.proc: subprocess.Popen[bytes] | None = None
        self.log_path = os.path.join(data_dir, f"{name}.log")
        self._log_fh: Any = None


class ClusterHarness:
    """Manages a 3-node local cluster: peer_a, peer_b, and accel_jp (--role accelerate)."""

    def __init__(self, fucf_bin: str, token: str = "e2e-cluster-token", keep_logs: bool = False):
        self.bin = fucf_bin
        self.token = token
        self.keep_logs = keep_logs
        self.root_dir = tempfile.mkdtemp(prefix="fucf-cluster-")
        self.nodes: dict[str, NodeHandle] = {}
        self.h3 = H3Client(fucf_bin)
        self._failed = False

    def mark_failed(self) -> None:
        self._failed = True

    def add_node(
        self,
        name: str,
        role: str,
        edge_ip: str,
        panel_host: str | None = None,
        extra_args: list[str] | None = None,
    ) -> NodeHandle:
        data_dir = os.path.join(self.root_dir, name)
        os.makedirs(data_dir, exist_ok=True)
        ports = {
            "dns": free_port(dual_udp=True),
            "api": free_port(),
            "http": free_port(),
            "https": free_port(dual_udp=True),
            "front": free_port(),
            "proxy": free_port(),
            "proxy_tls": free_port(),
        }
        nh = NodeHandle(name, role, edge_ip, ports, data_dir, panel_host=panel_host, extra_args=extra_args)
        self.nodes[name] = nh
        return nh

    def setup_default_3node(self) -> "ClusterHarness":
        self.add_node("peer_a", ContractConfig.ROLE_PEER, "203.0.113.11", panel_host=ContractConfig.PANEL_HOST)
        self.add_node("peer_b", ContractConfig.ROLE_PEER, "203.0.113.12", panel_host=ContractConfig.PANEL_HOST)
        self.add_node("accel_jp", ContractConfig.ROLE_ACCELERATE, "203.0.113.13")
        return self

    def _peer_urls_for(self, name: str) -> list[str]:
        return [
            f"http://127.0.0.1:{nh.ports['api']}"
            for k, nh in self.nodes.items()
            if k != name and nh.role == ContractConfig.ROLE_PEER
        ]

    def start_node(self, name: str) -> None:
        nh = self.nodes[name]
        if nh.proc and nh.proc.poll() is None:
            return
        domains_file = os.path.join(nh.data_dir, "domains.lst")
        argv = [
            self.bin,
            ContractConfig.ROLE_FLAG,
            nh.role,
            ContractConfig.NODE_NAME_FLAG,
            nh.name,
            "--dns-listen",
            f"127.0.0.1:{nh.ports['dns']}",
            "--api-listen",
            f"127.0.0.1:{nh.ports['api']}",
            "--http-listen",
            f"127.0.0.1:{nh.ports['http']}",
            "--https-listen",
            f"127.0.0.1:{nh.ports['https']}",
            "--spectrum-bind",
            "127.0.0.1",
            "--data-dir",
            nh.data_dir,
            "--api-token",
            self.token,
            "--edge-ip",
            nh.edge_ip,
            ContractConfig.ACME_DIR_FLAG,
            ContractConfig.ACME_DISCARD,
            ContractConfig.H3_FRONT_FLAG,
            f"127.0.0.1:{nh.ports['front']}",
            ContractConfig.PROXY_LISTEN_FLAG,
            f"127.0.0.1:{nh.ports['proxy']}",
            ContractConfig.PROXY_TLS_LISTEN_FLAG,
            f"127.0.0.1:{nh.ports['proxy_tls']}",
            ContractConfig.EXPORT_DOMAINS_FLAG,
            domains_file,
        ]
        peers = self._peer_urls_for(name)
        if peers:
            argv.extend([ContractConfig.PEERS_FLAG, ",".join(peers)])
        if nh.panel_host:
            argv.extend([ContractConfig.PANEL_HOST_FLAG, nh.panel_host])
        argv.extend(nh.extra_args)

        nh._log_fh = open(nh.log_path, "ab")
        nh.proc = subprocess.Popen(argv, stdout=nh._log_fh, stderr=nh._log_fh)

    def wait_ready(self, name: str, timeout: float = 15.0) -> None:
        nh = self.nodes[name]

        def _probe() -> bool:
            if nh.proc and nh.proc.poll() is not None:
                raise RuntimeError(f"node {name} exited early with code {nh.proc.returncode}")
            with socket.create_connection(("127.0.0.1", nh.ports["api"]), timeout=0.5):
                return True

        wait_for(f"node {name} API ready", _probe, timeout=timeout, interval=0.1)

    def start(self) -> "ClusterHarness":
        if not self.nodes:
            self.setup_default_3node()
        for name in self.nodes:
            self.start_node(name)
        for name in self.nodes:
            self.wait_ready(name)
        return self

    def stop_node(self, name: str) -> None:
        nh = self.nodes[name]
        if nh.proc:
            if nh.proc.poll() is None:
                nh.proc.terminate() if os.name != "nt" else nh.proc.kill()
                try:
                    nh.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    nh.proc.kill()
                    nh.proc.wait()
            nh.proc = None
        if nh._log_fh:
            nh._log_fh.close()
            nh._log_fh = None

    def restart(self, name: str) -> None:
        self.stop_node(name)
        self.start_node(name)
        self.wait_ready(name)

    def api(
        self,
        node: str,
        method: str,
        path: str,
        body: Any = None,
        raw: str | bytes | None = None,
        token: str | None = None,
        headers: dict[str, str] | None = None,
        prefix: str = "/client/v4",
    ) -> tuple[int, dict[str, Any]]:
        nh = self.nodes[node]
        conn = http.client.HTTPConnection("127.0.0.1", nh.ports["api"], timeout=15)
        tok = self.token if token is None else token
        req_hdrs = {"Content-Type": "application/json"}
        if tok:
            req_hdrs["Authorization"] = f"Bearer {tok}"
        if headers:
            req_hdrs.update(headers)
        data = raw if raw is not None else (json.dumps(body) if body is not None else None)
        full_path = prefix + path if not path.startswith(prefix) and prefix else path
        conn.request(method, full_path, body=data, headers=req_hdrs)
        resp = conn.getresponse()
        raw_resp = resp.read()
        try:
            parsed = json.loads(raw_resp)
        except ValueError:
            parsed = {"raw": raw_resp.decode("utf-8", "replace")}
        return resp.status, parsed

    def edge(
        self,
        node: str,
        path: str = "/",
        host: str = "example.test",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        use_tls: bool = False,
        port_kind: str | None = None,
        follow_redirects: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        nh = self.nodes[node]
        kind = port_kind or ("https" if use_tls else "http")
        port = nh.ports[kind]
        if use_tls:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn: http.client.HTTPConnection = http.client.HTTPSConnection("127.0.0.1", port, timeout=30, context=ctx)
        else:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=30)
        req_hdrs = {"Host": host, **(headers or {})}
        conn.request(method, path, body=body, headers=req_hdrs)
        r = conn.getresponse()
        data = r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        if follow_redirects and r.status in (301, 302, 303, 307, 308) and "location" in hdrs:
            loc = urllib.parse.urlparse(hdrs["location"])
            next_host = loc.hostname or host
            next_path = loc.path + (f"?{loc.query}" if loc.query else "")
            return self.edge(node, next_path, host=next_host, use_tls=use_tls, port_kind=port_kind)
        return r.status, hdrs, data

    def proxy(
        self,
        node: str,
        path: str = "/",
        host: str = "app.local",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
        use_tls: bool = False,
    ) -> tuple[int, dict[str, str], bytes]:
        kind = "proxy_tls" if use_tls else "proxy"
        return self.edge(node, path=path, host=host, method=method, headers=headers, body=body, use_tls=use_tls, port_kind=kind)

    def front(
        self,
        node: str,
        path: str = "/",
        host: str = "example.test",
        method: str = "GET",
        headers: dict[str, str] | None = None,
        body: bytes | str | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        return self.edge(node, path=path, host=host, method=method, headers=headers, body=body, port_kind="front")

    def dns_query(self, node: str, name: str, qtype: int = 1) -> tuple[int, int, bytes]:
        """Send UDP DNS query; returns (rcode, ancount, raw_packet)."""
        nh = self.nodes[node]
        q = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
        q += b"".join(bytes([len(lbl)]) + lbl.encode("ascii") for lbl in name.strip(".").split(".") if lbl)
        q += b"\x00" + struct.pack("!HH", qtype, 1)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3.0)
        try:
            s.sendto(q, ("127.0.0.1", nh.ports["dns"]))
            resp = s.recv(4096)
        finally:
            s.close()
        flags, _, ancount = struct.unpack("!HHH", resp[2:8])
        rcode = flags & 0x0F
        return rcode, ancount, resp

    def wait_converged(self, probe: Callable[[], Any], timeout: float = 15.0) -> Any:
        return wait_for("cluster convergence", probe, timeout=timeout, interval=0.25)

    def rss_bytes(self, node: str) -> int:
        nh = self.nodes[node]
        if not nh.proc:
            raise RuntimeError(f"node {node} is not running")
        return rss_bytes(nh.proc.pid)

    def stop(self) -> None:
        for name in list(self.nodes):
            self.stop_node(name)
        if not (self.keep_logs and self._failed):
            shutil.rmtree(self.root_dir, ignore_errors=True)
        else:
            print(f"  [harness] logs kept at {self.root_dir}")
