"""Modular 4-tier opaque-box E2E test registry and execution context."""
from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from .harness import (
    ClusterHarness,
    ContractConfig,
    H2OriginServer,
    MockOAuthServer,
    SseOriginServer,
    TestOriginServer,
    WsEchoServer,
    free_port,
    wait_for,
)


@dataclass
class TestCase:
    id: str
    tier: str  # "1", "2", "3", "4"
    suite: str  # "r1", "r2", "r3", "r4", "r5"
    reqs: tuple[str, ...]
    description: str
    fn: Callable[["TestContext"], None]
    tags: tuple[str, ...] = ()

    def matches(self, tier: str = "all", suite: str = "all", flt: str | None = None) -> bool:
        if tier != "all" and self.tier != tier:
            return False
        if suite != "all":
            if self.suite != suite and suite not in self.tags:
                return False
        if flt:
            needle = flt.lower()
            hay = " ".join([self.id, self.suite, *self.reqs, *self.tags, self.description]).lower()
            if needle not in hay:
                return False
        return True


REGISTRY: list[TestCase] = []


def register_test(
    test_id: str,
    tier: str,
    suite: str,
    reqs: tuple[str, ...] | list[str],
    description: str,
    tags: tuple[str, ...] = (),
) -> Callable[[Callable[["TestContext"], None]], Callable[["TestContext"], None]]:
    def _wrap(fn: Callable[["TestContext"], None]) -> Callable[["TestContext"], None]:
        REGISTRY.append(
            TestCase(
                id=test_id,
                tier=str(tier),
                suite=suite,
                reqs=tuple(reqs),
                description=description,
                fn=fn,
                tags=tuple(tags),
            )
        )
        return fn

    return _wrap


class TestContext:
    """Shared lazy-initialized cluster, local test origins, and helper methods."""

    def __init__(self, fucf_bin: str, keep_logs: bool = False):
        self.bin = fucf_bin
        self.keep_logs = keep_logs
        self.cluster: ClusterHarness | None = None
        self.origin1: TestOriginServer | None = None
        self.origin2: TestOriginServer | None = None
        self.tls_origin: TestOriginServer | None = None
        self.h2_origin: H2OriginServer | None = None
        self.ws_origin: WsEchoServer | None = None
        self.sse_origin: SseOriginServer | None = None
        self.mock_oauth: MockOAuthServer | None = None
        self.admin_token: str | None = None
        self.admin_email = "admin@fucloudflare.test"
        self.admin_password = "AdminPass!2026_Secure"
        self._seq = 0

    def next_tag(self, prefix: str = "t") -> str:
        self._seq += 1
        return f"{prefix}{self._seq}-{secrets.token_hex(3)}"

    def ensure_origins(self) -> None:
        if self.origin1 is None:
            self.origin1 = TestOriginServer("origin1").start()
        if self.origin2 is None:
            self.origin2 = TestOriginServer("origin2").start()
        if self.tls_origin is None:
            self.tls_origin = TestOriginServer("tls-origin", use_tls=True).start()
        if self.h2_origin is None:
            self.h2_origin = H2OriginServer("h2c-origin").start()
        if self.ws_origin is None:
            self.ws_origin = WsEchoServer("ws-echo").start()
        if self.sse_origin is None:
            self.sse_origin = SseOriginServer("sse-origin").start()
        if self.mock_oauth is None:
            self.mock_oauth = MockOAuthServer().start()

    def ensure_cluster(self) -> ClusterHarness:
        self.ensure_origins()
        if self.cluster is None:
            self.cluster = ClusterHarness(self.bin, keep_logs=self.keep_logs).setup_default_3node()
            self.cluster.start()
        return self.cluster

    def ensure_panel_admin(self, node: str = "peer_a") -> str:
        c = self.ensure_cluster()
        if self.admin_token:
            st, _ = c.api(node, "GET", "/account", token=self.admin_token)
            if st == 200:
                return self.admin_token
        st, r = c.api(node, "GET", "/auth/status", token="")
        assert st == 200, f"/auth/status failed: {st} {r}"
        if not r.get("result", {}).get("initialized"):
            st2, r2 = c.api(
                node,
                "POST",
                "/auth/setup",
                body={"token": c.token, "email": self.admin_email, "password": self.admin_password},
                token="",
            )
            assert st2 == 200, f"/auth/setup failed: {st2} {r2}"
            self.admin_token = r2["result"]["token"]
        else:
            st2, r2 = c.api(
                node,
                "POST",
                "/auth/login",
                body={"email": self.admin_email, "password": self.admin_password},
                token="",
            )
            assert st2 == 200 and "token" in r2.get("result", {}), f"admin login failed: {st2} {r2}"
            self.admin_token = r2["result"]["token"]
        return self.admin_token

    def new_cluster(self) -> ClusterHarness:
        """Spawn an isolated disposable 3-node cluster for destructive/restart tests."""
        return ClusterHarness(self.bin, keep_logs=self.keep_logs).setup_default_3node().start()

    def create_zone(self, name: str, node: str = "peer_a", origin_port: int | None = None) -> dict[str, Any]:
        c = self.ensure_cluster()
        st, r = c.api(node, "POST", "/zones", {"name": name})
        assert st == 200 and r.get("success"), f"create zone {name} failed: {st} {r}"
        z = r["result"]
        zid = z["id"]
        st_rec, r_rec = c.api(
            node,
            "POST",
            f"/zones/{zid}/dns_records",
            {"type": "A", "name": "@", "content": "127.0.0.1", "proxied": True},
        )
        assert st_rec == 200, f"create A record failed: {st_rec} {r_rec}"
        if origin_port is not None:
            st_or, r_or = c.api(
                node,
                "POST",
                f"/zones/{zid}/origin_rules",
                {"expression": "", "origin_port": origin_port},
            )
            assert st_or == 200, f"create origin rule failed: {st_or} {r_or}"
        return z

    def deploy_worker(
        self,
        script_name: str,
        code: str,
        zone_id: str,
        pattern: str,
        node: str = "peer_a",
        kv_bindings: dict[str, str] | None = None,
        d1_bindings: dict[str, str] | None = None,
        crons: list[str] | None = None,
        vars_dict: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        c = self.ensure_cluster()
        st, r = c.api(node, "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/{script_name}", raw=code)
        assert st == 200 and r.get("success"), f"upload worker {script_name} failed: {st} {r}"
        settings: dict[str, Any] = {}
        if kv_bindings is not None:
            settings["kv_bindings"] = kv_bindings
        if d1_bindings is not None:
            settings["d1_bindings"] = d1_bindings
        if crons is not None:
            settings["crons"] = crons
        if vars_dict is not None:
            settings["vars"] = vars_dict
        if settings:
            st_s, r_s = c.api(node, "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/{script_name}/settings", settings)
            assert st_s == 200 and r_s.get("success"), f"worker settings failed: {st_s} {r_s}"
        st_r, r_r = c.api(
            node,
            "POST",
            f"/zones/{zone_id}/workers/routes",
            {"pattern": pattern, "script": script_name},
        )
        assert st_r == 200 and r_r.get("success"), f"worker route failed: {st_r} {r_r}"
        return r["result"]

    def create_kv(self, title: str, node: str = "peer_a") -> str:
        c = self.ensure_cluster()
        st, r = c.api(node, "POST", ContractConfig.KV_NAMESPACES_PATH, {"title": title})
        assert st == 200 and r.get("success"), f"create KV {title} failed: {st} {r}"
        return r["result"]["id"]

    def create_d1(self, name: str, node: str = "peer_a") -> str:
        c = self.ensure_cluster()
        st, r = c.api(node, "POST", ContractConfig.D1_DATABASES_PATH, {"name": name})
        assert st == 200 and r.get("success"), f"create D1 {name} failed: {st} {r}"
        return r["result"]["uuid"] if "uuid" in r["result"] else r["result"]["id"]

    def create_proxy_rule(self, rule: dict[str, Any], node: str = "peer_a") -> dict[str, Any]:
        c = self.ensure_cluster()
        st, r = c.api(node, "POST", ContractConfig.PROXY_RULES_PATH, rule)
        assert st == 200 and r.get("success"), f"create proxy rule failed: {st} {r}"
        return r["result"]

    def delete_proxy_rule(self, rule_id: str, node: str = "peer_a") -> None:
        c = self.ensure_cluster()
        c.api(node, "DELETE", f"{ContractConfig.PROXY_RULES_PATH}/{rule_id}")

    def mark_failed(self) -> None:
        if self.cluster:
            self.cluster.mark_failed()

    def close(self) -> None:
        if self.cluster:
            self.cluster.stop()
            self.cluster = None
        for srv in (
            self.origin1,
            self.origin2,
            self.tls_origin,
            self.h2_origin,
            self.ws_origin,
            self.sse_origin,
            self.mock_oauth,
        ):
            if srv:
                srv.stop()
        self.origin1 = None
        self.origin2 = None
        self.tls_origin = None
        self.h2_origin = None
        self.ws_origin = None
        self.sse_origin = None
        self.mock_oauth = None


# ---------------------------------------------------------------------------
# Headless Edge / Chrome CDP Helper for R5 UI Tests
# ---------------------------------------------------------------------------


def find_browser_executable() -> str | None:
    candidates = [
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    ]
    for p in candidates:
        if os.path.exists(p):
            return p
    for name in ("google-chrome", "chromium", "chromium-browser", "msedge"):
        found = shutil.which(name)
        if found:
            return found
    return None


class CdpSession:
    """Minimal offline CDP controller using local Edge/Chrome + websockets."""

    def __init__(self, browser_exe: str, host_rules: str = ""):
        self.browser_exe = browser_exe
        self.host_rules = host_rules
        self.user_dir = tempfile.mkdtemp(prefix="fucf-cdp-")
        self.proc: subprocess.Popen[bytes] | None = None
        self.cdp_port = 0
        self.ws_url = ""
        self._msg_id = 0

    def start(self) -> "CdpSession":
        import http.client as hc

        argv = [
            self.browser_exe,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--ignore-certificate-errors",
            "--remote-debugging-port=0",
            f"--user-data-dir={self.user_dir}",
            "--window-size=1440,900",
        ]
        if self.host_rules:
            argv.append(f"--host-resolver-rules={self.host_rules}")
        argv.append("about:blank")
        self.proc = subprocess.Popen(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        active_port_file = os.path.join(self.user_dir, "DevToolsActivePort")
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if os.path.exists(active_port_file):
                with open(active_port_file, "r", encoding="utf-8") as f:
                    lines = f.read().splitlines()
                if lines and lines[0].isdigit():
                    self.cdp_port = int(lines[0])
                    break
            time.sleep(0.1)
        assert self.cdp_port > 0, "headless browser did not expose DevToolsActivePort"

        def _get_target() -> str | None:
            conn = hc.HTTPConnection("127.0.0.1", self.cdp_port, timeout=3)
            conn.request("GET", "/json/list")
            r = conn.getresponse()
            targets = json.loads(r.read())
            for t in targets:
                if t.get("type") == "page" and t.get("webSocketDebuggerUrl"):
                    return t["webSocketDebuggerUrl"]
            return None

        self.ws_url = wait_for("CDP page target", _get_target, timeout=10.0)
        return self

    def run_script(self, url: str, js_fn: str, viewport: tuple[int, int] | None = None) -> dict[str, Any]:
        """Navigate to `url`, execute async `js_fn` returning JSON, capture console/page/5xx errors."""
        import asyncio
        import websockets  # type: ignore

        async def _go() -> dict[str, Any]:
            console_errors: list[str] = []
            exceptions: list[str] = []
            http_5xx: list[tuple[str, int]] = []
            failed_external: list[str] = []
            headers_seen: dict[str, dict[str, str]] = {}

            async with websockets.connect(self.ws_url, max_size=10 * 1024 * 1024) as ws:
                async def call(method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
                    self._msg_id += 1
                    mid = self._msg_id
                    await ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
                    while True:
                        raw = await asyncio.wait_for(ws.recv(), timeout=20.0)
                        msg = json.loads(raw)
                        if msg.get("id") == mid:
                            if "error" in msg:
                                raise RuntimeError(f"CDP {method} error: {msg['error']}")
                            return msg.get("result", {})
                        ev_m = msg.get("method")
                        ev_p = msg.get("params", {})
                        if ev_m == "Runtime.consoleAPICalled" and ev_p.get("type") == "error":
                            console_errors.append(str(ev_p.get("args", [])))
                        elif ev_m == "Runtime.exceptionThrown":
                            exceptions.append(str(ev_p.get("exceptionDetails", {})))
                        elif ev_m == "Network.responseReceived":
                            resp = ev_p.get("response", {})
                            r_url = resp.get("url", "")
                            st = int(resp.get("status", 0))
                            headers_seen[r_url] = {k.lower(): v for k, v in resp.get("headers", {}).items()}
                            if st >= 500:
                                http_5xx.append((r_url, st))
                        elif ev_m == "Network.loadingFailed":
                            failed_external.append(str(ev_p))

                await call("Page.enable")
                await call("Runtime.enable")
                await call("Network.enable")
                if viewport:
                    await call(
                        "Emulation.setDeviceMetricsOverride",
                        {"width": viewport[0], "height": viewport[1], "deviceScaleFactor": 1, "mobile": viewport[0] < 600},
                    )
                await call("Page.navigate", {"url": url})
                await asyncio.sleep(0.8)
                res = await call(
                    "Runtime.evaluate",
                    {"expression": js_fn, "awaitPromise": True, "returnByValue": True},
                )
                # Drain any queued events briefly
                try:
                    while True:
                        raw = await asyncio.wait_for(ws.recv(), timeout=0.2)
                        msg = json.loads(raw)
                        ev_m = msg.get("method")
                        ev_p = msg.get("params", {})
                        if ev_m == "Runtime.consoleAPICalled" and ev_p.get("type") == "error":
                            console_errors.append(str(ev_p.get("args", [])))
                        elif ev_m == "Runtime.exceptionThrown":
                            exceptions.append(str(ev_p.get("exceptionDetails", {})))
                except asyncio.TimeoutError:
                    pass
                return {
                    "value": res.get("result", {}).get("value"),
                    "exception": res.get("exceptionDetails"),
                    "console_errors": console_errors,
                    "exceptions": exceptions,
                    "http_5xx": http_5xx,
                    "failed_external": failed_external,
                    "headers": headers_seen,
                }

        return asyncio.run(_go())

    def stop(self) -> None:
        if self.proc:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait()
            self.proc = None
        shutil.rmtree(self.user_dir, ignore_errors=True)


def load_all_tiers() -> list[TestCase]:
    from . import tier1_features, tier2_boundaries, tier3_pairwise, tier4_scenarios  # noqa: F401

    return list(REGISTRY)


def select_tests(tier: str = "all", suite: str = "all", flt: str | None = None) -> list[TestCase]:
    all_tests = load_all_tiers()
    return [t for t in all_tests if t.matches(tier=tier, suite=suite, flt=flt)]
