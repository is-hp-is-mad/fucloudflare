#!/usr/bin/env python3
"""Offline headless browser UI verifier for fucloudflare (fucf) via Chrome DevTools Protocol.

Drives local Microsoft Edge (`msedge.exe`) or Google Chrome (`chrome.exe` / `chromium`)
using `--headless=new --remote-debugging-port=0` and CDP over `websockets` (no Playwright
and no chromedriver binary needed, working 100% offline).

CLI:
    python scripts/ui_check.py [--bin <fucf_bin>] [--browser <path>] [--panel-url <url>] [--auth-url <url>] [--out-json <path>] [--selftest]

Importable API:
    run_ui_checks(fucf_bin: str | None = None, panel_url: str | None = None, auth_url: str | None = None, api_url: str | None = None, api_token: str | None = None, browser_path: str | None = None, out_json: str | None = None) -> dict
    run_selftest() -> dict
    contrast_ratio(rgb1: tuple[int, int, int], rgb2: tuple[int, int, int]) -> float
    parse_rgb(css_color: str) -> tuple[int, int, int]
"""

from __future__ import annotations

import argparse
import asyncio
import http.client
import http.server
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import websockets


ACCOUNT_TABS = [
    "overview",
    "zones",
    "fleet",
    "steering",
    "workers",
    "proxy",
    "oauth",
    "account",
    "users",
]

ZONE_TABS = [
    "overview",
    "dns",
    "ssl",
    "security",
    "rules",
    "network",
    "caching",
    "workers",
    "email",
    "analytics",
    "manage",
]


def parse_rgb(css_color: str) -> tuple[int, int, int]:
    """Parse CSS `rgb(...)`, `rgba(...)`, `#rrggbb`, or `#rgb` into an `(r, g, b)` tuple."""
    s = (css_color or "").strip().lower()
    m = re.match(r"^rgba?\(\s*(\d+)\s*[,\s]\s*(\d+)\s*[,\s]\s*(\d+)", s)
    if m:
        return int(m.group(1)), int(m.group(2)), int(m.group(3))
    if s.startswith("#"):
        hx = s[1:]
        if len(hx) == 3:
            return tuple(int(c * 2, 16) for c in hx)  # type: ignore[return-value]
        if len(hx) >= 6:
            return int(hx[0:2], 16), int(hx[2:4], 16), int(hx[4:6], 16)
    raise ValueError(f"Unsupported CSS color string: {css_color!r}")


def _relative_luminance(rgb: tuple[int, int, int]) -> float:
    def _lin(c: int) -> float:
        s = c / 255.0
        return s / 12.92 if s <= 0.04045 else ((s + 0.055) / 1.055) ** 2.4

    r, g, b = (_lin(rgb[0]), _lin(rgb[1]), _lin(rgb[2]))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(rgb1: tuple[int, int, int], rgb2: tuple[int, int, int]) -> float:
    """Compute WCAG 2.1 contrast ratio between two `(r, g, b)` colors (range 1.0 .. 21.0)."""
    l1 = _relative_luminance(rgb1)
    l2 = _relative_luminance(rgb2)
    hi, lo = max(l1, l2), min(l1, l2)
    return (hi + 0.05) / (lo + 0.05)


def discover_browser(explicit: str | None = None) -> str:
    """Locate local Edge or Chrome/Chromium executable offline."""
    if explicit:
        if os.path.exists(explicit):
            return explicit
        found = shutil.which(explicit)
        if found:
            return found
        raise FileNotFoundError(f"Specified browser not found: {explicit}")

    candidates: list[str] = []
    if os.name == "nt":
        pf86 = os.environ.get("PROGRAMFILES(X86)", r"C:\Program Files (x86)")
        pf = os.environ.get("PROGRAMFILES", r"C:\Program Files")
        local = os.environ.get("LOCALAPPDATA", "")
        candidates.extend([
            os.path.join(pf86, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(local, "Microsoft", "Edge", "Application", "msedge.exe"),
            os.path.join(pf, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(pf86, "Google", "Chrome", "Application", "chrome.exe"),
            os.path.join(local, "Google", "Chrome", "Application", "chrome.exe"),
        ])
        for name in ("msedge", "chrome"):
            w = shutil.which(name)
            if w:
                candidates.append(w)
    else:
        for name in ("google-chrome", "chromium", "chromium-browser", "microsoft-edge"):
            w = shutil.which(name)
            if w:
                candidates.append(w)
        candidates.extend([
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/microsoft-edge",
        ])

    for path in candidates:
        if path and os.path.exists(path):
            return path
    raise FileNotFoundError("No local headless browser (msedge / chrome / chromium) found")


class CdpSession:
    """Async Chrome DevTools Protocol client over `websockets`."""

    def __init__(self, ws: Any) -> None:
        self._ws = ws
        self._next_id = 1
        self._pending: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self._recv_task: asyncio.Task[None] | None = None
        self.console_errors: list[dict[str, Any]] = []
        self.uncaught_exceptions: list[dict[str, Any]] = []
        self.http_5xx: list[dict[str, Any]] = []
        self.doc_responses: list[dict[str, Any]] = []
        self._load_event = asyncio.Event()

    async def start(self) -> None:
        self._recv_task = asyncio.create_task(self._recv_loop())
        await self.send("Runtime.enable")
        await self.send("Log.enable")
        await self.send("Page.enable")
        await self.send("Network.enable")
        await self.send("DOM.enable")
        await self.send(
            "Page.addScriptToEvaluateOnNewDocument",
            {
                "source": (
                    "window.__uiErrors = [];"
                    "window.addEventListener('error', function(e) {"
                    "  window.__uiErrors.push({type:'error', message: e.message || String(e.error || 'error'), filename: e.filename || '', lineno: e.lineno || 0});"
                    "});"
                    "window.addEventListener('unhandledrejection', function(e) {"
                    "  window.__uiErrors.push({type:'unhandledrejection', message: String(e.reason && e.reason.stack ? e.reason.stack : e.reason)});"
                    "});"
                )
            },
        )

    async def close(self) -> None:
        if self._recv_task is not None:
            self._recv_task.cancel()
            try:
                await self._recv_task
            except asyncio.CancelledError:
                pass
        await self._ws.close()

    async def _recv_loop(self) -> None:
        try:
            async for raw in self._ws:
                msg = json.loads(raw)
                if "id" in msg:
                    fut = self._pending.pop(msg["id"], None)
                    if fut is not None and not fut.done():
                        fut.set_result(msg)
                    continue
                method = msg.get("method", "")
                params = msg.get("params", {})
                if method == "Runtime.consoleAPICalled":
                    if params.get("type") == "error":
                        args = [
                            a.get("value", a.get("description", ""))
                            for a in params.get("args", [])
                        ]
                        self.console_errors.append(
                            {"source": "console.error", "args": args}
                        )
                elif method == "Runtime.exceptionThrown":
                    details = params.get("exceptionDetails", {})
                    exc = details.get("exception", {})
                    self.uncaught_exceptions.append(
                        {
                            "source": "Runtime.exceptionThrown",
                            "text": details.get("text", ""),
                            "description": exc.get("description", exc.get("value", "")),
                        }
                    )
                elif method == "Log.entryAdded":
                    entry = params.get("entry", {})
                    if entry.get("level") == "error":
                        entry_url = entry.get("url", "")
                        entry_text = entry.get("text", "")
                        # panel.html #/oauth intentionally probes /oauth/{clients,providers} and degrades gracefully on 404;
                        # browsers also auto-request /favicon.ico on auth.fucloudflare.com
                        if "404" in entry_text and (
                            entry_url.endswith("/client/v4/oauth/clients")
                            or entry_url.endswith("/client/v4/oauth/providers")
                            or entry_url.endswith("/favicon.ico")
                        ):
                            continue
                        self.console_errors.append(
                            {
                                "source": "Log.entryAdded",
                                "text": entry_text,
                                "url": entry_url,
                            }
                        )
                elif method == "Network.responseReceived":
                    resp = params.get("response", {})
                    status = int(resp.get("status", 0) or 0)
                    if status >= 500:
                        self.http_5xx.append(
                            {
                                "url": resp.get("url", ""),
                                "status": status,
                                "statusText": resp.get("statusText", ""),
                            }
                        )
                    if params.get("type") == "Document":
                        self.doc_responses.append(
                            {
                                "url": resp.get("url", ""),
                                "status": status,
                                "headers": {
                                    str(k).lower(): str(v)
                                    for k, v in (resp.get("headers") or {}).items()
                                },
                            }
                        )
                elif method == "Page.loadEventFired":
                    self._load_event.set()
        except websockets.exceptions.ConnectionClosed:
            pass

    async def send(
        self, method: str, params: dict[str, Any] | None = None, timeout: float = 15.0
    ) -> dict[str, Any]:
        req_id = self._next_id
        self._next_id += 1
        loop = asyncio.get_running_loop()
        fut: asyncio.Future[dict[str, Any]] = loop.create_future()
        self._pending[req_id] = fut
        payload = {"id": req_id, "method": method, "params": params or {}}
        await self._ws.send(json.dumps(payload))
        resp = await asyncio.wait_for(fut, timeout=timeout)
        if "error" in resp:
            raise RuntimeError(f"CDP {method} failed: {resp['error']}")
        return resp.get("result", {})

    async def eval(self, expression: str, timeout: float = 15.0) -> Any:
        res = await self.send(
            "Runtime.evaluate",
            {
                "expression": expression,
                "awaitPromise": True,
                "returnByValue": True,
            },
            timeout=timeout,
        )
        if "exceptionDetails" in res:
            details = res["exceptionDetails"]
            exc = details.get("exception", {})
            raise RuntimeError(
                f"JS eval error: {details.get('text', '')} {exc.get('description', '')}"
            )
        return res.get("result", {}).get("value")

    async def navigate(self, url: str, settle_s: float = 0.35) -> None:
        self._load_event.clear()
        await self.send("Page.navigate", {"url": url})
        try:
            await asyncio.wait_for(self._load_event.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            pass
        for _ in range(40):
            state = await self.eval("document.readyState")
            if state == "complete":
                break
            await asyncio.sleep(0.05)
        await asyncio.sleep(settle_s)

    async def reload(self, settle_s: float = 0.35) -> None:
        self._load_event.clear()
        await self.send("Page.reload", {"ignoreCache": False})
        try:
            await asyncio.wait_for(self._load_event.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            pass
        await asyncio.sleep(settle_s)

    async def set_viewport(self, width: int, height: int, mobile: bool = False) -> None:
        await self.send(
            "Emulation.setDeviceMetricsOverride",
            {
                "width": width,
                "height": height,
                "deviceScaleFactor": 1,
                "mobile": mobile,
                "screenWidth": width,
                "screenHeight": height,
            },
        )
        await asyncio.sleep(0.15)

    async def collect_errors(self) -> dict[str, list[Any]]:
        try:
            page_errs = await self.eval("window.__uiErrors || []")
        except Exception:
            page_errs = []
        return {
            "console_errors": list(self.console_errors),
            "uncaught_exceptions": list(self.uncaught_exceptions) + list(page_errs or []),
            "http_5xx": list(self.http_5xx),
        }

    async def clear_errors(self) -> None:
        self.console_errors.clear()
        self.uncaught_exceptions.clear()
        self.http_5xx.clear()
        try:
            await self.eval("window.__uiErrors = []")
        except Exception:
            pass


class HeadlessCdpBrowser:
    """Manages an offline headless Edge/Chrome process and CDP WebSocket session."""

    def __init__(self, browser_path: str | None = None, extra_host_maps: str | None = None) -> None:
        self.browser_path = discover_browser(browser_path)
        self.extra_host_maps = (
            extra_host_maps
            or "MAP dashboard.fucloudflare.com 127.0.0.1, MAP auth.fucloudflare.com 127.0.0.1"
        )
        self._profile_dir: str | None = None
        self._proc: subprocess.Popen[bytes] | None = None
        self.cdp_port: int = 0
        self.page_ws_url: str = ""

    def start(self) -> "HeadlessCdpBrowser":
        self._profile_dir = tempfile.mkdtemp(prefix="fucf-cdp-")
        cmd = [
            self.browser_path,
            "--headless=new",
            "--disable-gpu",
            "--no-first-run",
            "--no-default-browser-check",
            "--remote-debugging-port=0",
            "--ignore-certificate-errors",
            f"--user-data-dir={self._profile_dir}",
            "--window-size=1440,900",
            "--no-proxy-server",
            f"--host-resolver-rules={self.extra_host_maps}",
            "about:blank",
        ]
        if os.name != "nt" and hasattr(os, "geteuid") and os.geteuid() == 0:
            cmd.insert(-1, "--no-sandbox")

        self._proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        da_path = os.path.join(self._profile_dir, "DevToolsActivePort")
        deadline = time.monotonic() + 15.0
        while time.monotonic() < deadline:
            if os.path.exists(da_path):
                try:
                    lines = Path(da_path).read_text(encoding="utf-8").strip().splitlines()
                    if lines and lines[0].strip().isdigit():
                        self.cdp_port = int(lines[0].strip())
                        break
                except OSError:
                    pass
            time.sleep(0.05)

        if self.cdp_port <= 0:
            raise RuntimeError("Headless browser failed to publish DevToolsActivePort")

        # Wait for /json/list to expose a "page" target
        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            try:
                raw = urllib.request.urlopen(
                    f"http://127.0.0.1:{self.cdp_port}/json/list", timeout=2.0
                ).read()
                targets = json.loads(raw)
                pages = [t for t in targets if t.get("type") == "page" and t.get("webSocketDebuggerUrl")]
                if pages:
                    self.page_ws_url = pages[0]["webSocketDebuggerUrl"]
                    break
            except Exception:
                pass
            time.sleep(0.05)

        if not self.page_ws_url:
            # Create a fresh page target explicitly
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.cdp_port}/json/new?about:blank", method="PUT"
            )
            raw = urllib.request.urlopen(req, timeout=3.0).read()
            tgt = json.loads(raw)
            self.page_ws_url = tgt["webSocketDebuggerUrl"]

        return self

    def stop(self) -> None:
        if self._proc is not None:
            try:
                self._proc.kill()
                self._proc.wait(timeout=5)
            except Exception:
                pass
            self._proc = None
        if self._profile_dir is not None:
            shutil.rmtree(self._profile_dir, ignore_errors=True)
            self._profile_dir = None

    def __enter__(self) -> "HeadlessCdpBrowser":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()


# ---------------------------------------------------------------------------
# UI Inspection Helpers
# ---------------------------------------------------------------------------

async def _inspect_theme_and_contrast(session: CdpSession) -> dict[str, Any]:
    """Read computed Light/Dark root attributes, surface RGBs, and text contrast."""
    return await session.eval(
        """(() => {
          const root = document.documentElement;
          const body = document.body;
          const card = document.querySelector('[data-kumo-component="Card"], .card, [data-sidebar="sidebar"], main, form');
          const heading = document.querySelector('h1, h2, h3, [data-kumo-component="Text"], p, body');
          const bs = getComputedStyle(body);
          const cs = card ? getComputedStyle(card) : bs;
          const hs = heading ? getComputedStyle(heading) : bs;
          return {
            datasetMode: root.dataset.mode || null,
            datasetTheme: root.dataset.theme || null,
            colorScheme: getComputedStyle(root).colorScheme || "",
            bodyBg: bs.backgroundColor,
            bodyColor: bs.color,
            cardBg: cs.backgroundColor,
            cardColor: cs.color,
            textColor: hs.color,
            localStorageTheme: (() => {
              try {
                return localStorage.getItem('theme') || localStorage.getItem('fucf_theme') || localStorage.getItem('mode') || null;
              } catch { return null; }
            })()
          };
        })()"""
    )


async def _find_and_click_theme_toggle(session: CdpSession) -> bool:
    """Attempt to click the Light/Dark theme toggle button in the DOM."""
    return bool(
        await session.eval(
            """(() => {
              const selectors = [
                '[data-mode-toggle]',
                '[data-theme-toggle]',
                '[data-act="theme"]',
                '[data-testid="theme-toggle"]',
                'button[aria-label*="主题" i]',
                'button[aria-label*="theme" i]',
                'button[aria-label*="mode" i]',
                'button[aria-label*="dark" i]',
                'button[title*="主题" i]',
                'button[title*="theme" i]'
              ];
              for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) { el.click(); return true; }
              }
              const btns = Array.from(document.querySelectorAll('button, [role="button"]'));
              for (const b of btns) {
                const txt = (b.innerText || b.getAttribute('aria-label') || '').trim().toLowerCase();
                if (['dark', 'light', '深色', '浅色', '暗色', '亮色', '夜间', '日间'].some(k => txt.includes(k))) {
                  b.click();
                  return true;
                }
              }
              return false;
            })()"""
        )
    )


async def _measure_geometry(session: CdpSession) -> dict[str, Any]:
    """Measure sidebar width, topbar height, and viewport scroll dimensions."""
    return await session.eval(
        """(() => {
          const aside = document.querySelector('[data-sidebar="sidebar"], aside, .side');
          const header = document.querySelector('header, .top');
          const main = document.querySelector('main');
          const ar = aside ? aside.getBoundingClientRect() : null;
          const hr = header ? header.getBoundingClientRect() : null;
          const mr = main ? main.getBoundingClientRect() : null;
          return {
            sidebarWidth: ar ? Math.round(ar.width) : null,
            topbarHeight: hr ? Math.round(hr.height) : null,
            mainWidth: mr ? Math.round(mr.width) : null,
            scrollWidth: document.documentElement.scrollWidth,
            clientWidth: document.documentElement.clientWidth
          };
        })()"""
    )


async def _click_sidebar_collapse(session: CdpSession) -> bool:
    return bool(
        await session.eval(
            """(() => {
              const selectors = [
                '[data-sidebar="trigger"]',
                'button[aria-label*="折叠" i]',
                'button[aria-label*="收起" i]',
                'button[aria-label*="collapse" i]',
                'button[aria-label*="sidebar" i]',
                '[data-act="sidebar-toggle"]'
              ];
              for (const sel of selectors) {
                const el = document.querySelector(sel);
                if (el) { el.click(); return true; }
              }
              return false;
            })()"""
        )
    )


def _is_light_surface(rgb: tuple[int, int, int]) -> bool:
    return min(rgb) >= 235


def _is_dark_surface(rgb: tuple[int, int, int]) -> bool:
    return max(rgb) <= 35


_CHROME_UNSAFE_PORTS = {
    1, 7, 9, 11, 13, 15, 17, 19, 20, 21, 22, 23, 25, 37, 42, 43, 53, 69, 77, 79,
    87, 95, 101, 102, 103, 104, 109, 110, 111, 113, 115, 117, 119, 123, 135, 137,
    139, 143, 161, 179, 389, 427, 465, 512, 513, 514, 515, 526, 530, 531, 532,
    540, 548, 554, 556, 563, 587, 601, 636, 989, 990, 993, 995, 1719, 1720, 1723,
    2049, 3659, 4045, 5060, 5061, 6000, 6566, 6665, 6666, 6667, 6668, 6669, 6697,
    10080,
}


def _free_tcp_udp_port() -> int:
    for _ in range(64):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            p = int(s.getsockname()[1])
        if p in _CHROME_UNSAFE_PORTS:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            try:
                u.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _api_req(
    api_port: int, token: str | None, method: str, path: str, body: dict[str, Any] | bytes | str | None = None
) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", api_port, timeout=15)
    try:
        is_raw = isinstance(body, (bytes, str))
        headers = {"Content-Type": "application/javascript" if is_raw else "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        if body is None:
            payload = None
        elif isinstance(body, bytes):
            payload = body
        elif isinstance(body, str):
            payload = body.encode("utf-8")
        else:
            payload = json.dumps(body)
        conn.request(method, "/client/v4" + path, body=payload, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
        try:
            data = json.loads(raw)
        except Exception:
            data = {"raw": raw.decode("utf-8", "replace")}
        return resp.status, data
    finally:
        conn.close()


def _wait_tcp(port: int, timeout_s: float = 15.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.5):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"Timed out waiting for port 127.0.0.1:{port}")


# ---------------------------------------------------------------------------
# Full UI Verification Flow
# ---------------------------------------------------------------------------

async def _run_ui_checks_async(
    browser: HeadlessCdpBrowser,
    panel_url: str,
    auth_url: str | None,
    email: str,
    password: str,
    zone_id: str | None,
) -> dict[str, Any]:
    checks: list[dict[str, Any]] = []

    def _rec(name: str, cond: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(cond), "detail": detail})

    async with websockets.connect(browser.page_ws_url, max_size=32 * 1024 * 1024) as ws:
        session = CdpSession(ws)
        await session.start()
        try:
            await session.set_viewport(1440, 900, mobile=False)
            await session.navigate(panel_url, settle_s=0.5)

            # 1. CSP / security headers
            csp_ok = False
            xfo_ok = False
            for doc in session.doc_responses:
                hdrs = doc.get("headers", {})
                if "frame-ancestors 'none'" in hdrs.get("content-security-policy", ""):
                    csp_ok = True
                if hdrs.get("x-frame-options", "").upper() == "DENY":
                    xfo_ok = True
            _rec("panel_security_headers", csp_ok and xfo_ok, f"csp={csp_ok}, xfo={xfo_ok}")

            # 2. Authenticate via UI login form if present
            logged_in = await session.eval(
                f"""(async () => {{
                  const emailInput = document.querySelector('input[type="email"], input[name="email"], input[autocomplete="username"]');
                  const passInput = document.querySelector('input[type="password"], input[name="password"]');
                  if (emailInput && passInput) {{
                    const setVal = (el, val) => {{
                      el.value = val;
                      el.dispatchEvent(new Event('input', {{ bubbles: true }}));
                      el.dispatchEvent(new Event('change', {{ bubbles: true }}));
                    }};
                    setVal(emailInput, {json.dumps(email)});
                    setVal(passInput, {json.dumps(password)});
                    const form = emailInput.closest('form') || document.querySelector('form');
                    const btn = (form && form.querySelector('button[type="submit"], button.pri, button')) || document.querySelector('button[type="submit"]');
                    if (btn) btn.click();
                    return 'submitted';
                  }}
                  return 'already_authenticated_or_custom';
                }})()"""
            )
            if logged_in == "submitted":
                for _ in range(40):
                    has_shell = await session.eval(
                        "Boolean(document.querySelector('[data-sidebar=\"sidebar\"], aside, .side, #zsw'))"
                    )
                    if has_shell:
                        break
                    await asyncio.sleep(0.15)
            await asyncio.sleep(0.3)

            # 3. Light & Dark mode verification
            light_info = await _inspect_theme_and_contrast(session)
            try:
                l_bg = parse_rgb(light_info["bodyBg"])
                l_fg = parse_rgb(light_info["textColor"])
                l_contrast = contrast_ratio(l_fg, l_bg)
                light_ok = _is_light_surface(l_bg) and l_contrast >= 4.5
            except Exception:
                l_contrast = 0.0
                light_ok = False
            _rec(
                "panel_light_theme_wcag",
                light_ok,
                f"bg={light_info.get('bodyBg')}, fg={light_info.get('textColor')}, contrast={l_contrast:.2f}",
            )

            # Toggle to dark mode
            dark_achieved = False
            for _ in range(3):
                clicked = await _find_and_click_theme_toggle(session)
                if not clicked:
                    break
                await asyncio.sleep(0.2)
                cur = await _inspect_theme_and_contrast(session)
                if cur.get("datasetMode") == "dark" or cur.get("datasetTheme") == "dark":
                    dark_achieved = True
                    break

            dark_info = await _inspect_theme_and_contrast(session)
            try:
                d_bg = parse_rgb(dark_info["bodyBg"])
                d_fg = parse_rgb(dark_info["textColor"])
                d_contrast = contrast_ratio(d_fg, d_bg)
                dark_ok = dark_achieved and _is_dark_surface(d_bg) and d_contrast >= 4.5
            except Exception:
                d_contrast = 0.0
                dark_ok = False
            _rec(
                "panel_dark_theme_wcag",
                dark_ok,
                f"mode={dark_info.get('datasetMode') or dark_info.get('datasetTheme')}, bg={dark_info.get('bodyBg')}, contrast={d_contrast:.2f}",
            )

            # Reload persistence
            await session.reload(settle_s=0.4)
            after_reload = await _inspect_theme_and_contrast(session)
            persisted = (
                after_reload.get("datasetMode") == "dark"
                or after_reload.get("datasetTheme") == "dark"
            )
            _rec("panel_dark_theme_persistence", persisted, f"after_reload={after_reload.get('datasetMode') or after_reload.get('datasetTheme')}")

            # 4. Layout & Geometry (Desktop 1440x900 + Sidebar Collapse + Mobile 375x812)
            geom_exp = await _measure_geometry(session)
            sw_exp = geom_exp.get("sidebarWidth") or 0
            th = geom_exp.get("topbarHeight") or 0
            collapsed_ok = False
            sw_col = None
            if await _click_sidebar_collapse(session):
                await asyncio.sleep(0.35)
                geom_col = await _measure_geometry(session)
                sw_col = geom_col.get("sidebarWidth")
                collapsed_ok = sw_col is not None and 45 <= sw_col <= 75
                await _click_sidebar_collapse(session)
                await asyncio.sleep(0.3)
            _rec(
                "panel_desktop_geometry",
                (235 <= sw_exp <= 285) and (40 <= th <= 72) and collapsed_ok,
                f"sidebar={sw_exp}px->{sw_col}px, topbar={th}px",
            )

            await session.set_viewport(375, 812, mobile=True)
            mob = await _measure_geometry(session)
            _rec(
                "panel_mobile_no_overflow",
                mob["scrollWidth"] <= mob["clientWidth"],
                f"scrollWidth={mob['scrollWidth']}, clientWidth={mob['clientWidth']}",
            )
            await session.set_viewport(1440, 900, mobile=False)

            # 5. Navigate Account Tabs
            acc_visited = 0
            for tab in ACCOUNT_TABS:
                await session.eval(f"location.hash = '#/ {tab}'".replace(" ", ""))
                await asyncio.sleep(0.25)
                has_text = await session.eval("document.body.innerText.trim().length > 0")
                if has_text:
                    acc_visited += 1
            _rec("panel_account_tabs_navigation", acc_visited == len(ACCOUNT_TABS), f"visited={acc_visited}/{len(ACCOUNT_TABS)}")

            # 6. Navigate Zone Tabs
            if zone_id:
                zone_visited = 0
                for ztab in ZONE_TABS:
                    await session.eval(f"location.hash = '#/zone/{zone_id}/{ztab}'")
                    await asyncio.sleep(0.2)
                    has_text = await session.eval("document.body.innerText.trim().length > 0")
                    if has_text:
                        zone_visited += 1
                _rec("panel_zone_tabs_navigation", zone_visited == len(ZONE_TABS), f"visited={zone_visited}/{len(ZONE_TABS)}")

            # 7. Interactive Modal/Drawer check on #/zones
            await session.eval("location.hash = '#/zones'")
            await asyncio.sleep(0.3)
            modal_ok = bool(
                await session.eval(
                    """(() => {
                      const btns = Array.from(document.querySelectorAll('button'));
                      const addBtn = btns.find(b => /添加|新增|add|create|new/i.test(b.innerText || ''));
                      if (!addBtn) return false;
                      addBtn.click();
                      const dlg = document.querySelector('[role="dialog"], .drawer, .modal, [data-kumo-component="Dialog"]');
                      if (!dlg) return false;
                      const closeBtn = dlg.querySelector('[data-close], button[aria-label*="关闭" i], button[aria-label*="close" i]');
                      if (closeBtn) closeBtn.click();
                      return true;
                    })()"""
                )
            )
            _rec("panel_interactive_modal", modal_ok, f"modal_opened_and_closed={modal_ok}")

            # 8. Auth Worker UI (auth.fucloudflare.com)
            if auth_url:
                await session.navigate(auth_url, settle_s=0.4)
                auth_info = await session.eval(
                    """(() => {
                      const href = location.href || '';
                      const isErr = href.startsWith('chrome-error://');
                      const txt = document.body.innerText || '';
                      const hasInteractive = Boolean(document.querySelector('button, input, a, form'));
                      const hasAuthText = /passkey|通行密钥|linux\\.do|oauth|sign in|登录|authorize/i.test(txt);
                      const hasAuthHooks = !isErr && hasAuthText && hasInteractive;
                      return { len: txt.trim().length, hasAuthHooks, url: href, title: document.title };
                    })()"""
                )
                _rec(
                    "auth_worker_ui_render",
                    auth_info["len"] > 0 and auth_info["hasAuthHooks"],
                    str(auth_info),
                )

            # 9. Zero console / uncaught / 5xx error gate
            errs = await session.collect_errors()
            zero_errs = (
                len(errs["console_errors"]) == 0
                and len(errs["uncaught_exceptions"]) == 0
                and len(errs["http_5xx"]) == 0
            )
            _rec("zero_browser_errors", zero_errs, json.dumps(errs))

            return {
                "passed": all(c["passed"] for c in checks),
                "checks": checks,
                "errors": errs,
            }
        finally:
            await session.close()


def run_ui_checks(
    fucf_bin: str | None = None,
    panel_url: str | None = None,
    auth_url: str | None = None,
    api_url: str | None = None,
    api_token: str | None = None,
    browser_path: str | None = None,
    out_json: str | None = None,
) -> dict[str, Any]:
    """Run headless Edge/Chrome CDP UI verification against fucf panel and auth.fucloudflare.com."""
    proc: subprocess.Popen[bytes] | None = None
    data_dir: str | None = None
    email = "admin@fucloudflare.test"
    password = "TestPass123!"
    zone_id: str | None = None
    host_maps = "MAP dashboard.fucloudflare.com 127.0.0.1, MAP auth.fucloudflare.com 127.0.0.1"

    try:
        if not panel_url:
            if not fucf_bin or not os.path.exists(fucf_bin):
                raise FileNotFoundError(
                    f"Either --panel-url or a valid --bin fucf executable is required (got {fucf_bin!r})"
                )
            help_res = subprocess.run([fucf_bin, "--help"], capture_output=True, text=True, timeout=10)
            help_text = help_res.stdout + "\n" + help_res.stderr
            has_role = "--role" in help_text
            has_proxy = "--proxy-listen" in help_text

            data_dir = tempfile.mkdtemp(prefix="fucf-ui-")
            dns_port = _free_tcp_udp_port()
            api_port = _free_tcp_udp_port()
            http_port = _free_tcp_udp_port()
            https_port = _free_tcp_udp_port()
            token = api_token or "ui-check-token"

            cmd = [
                fucf_bin,
                "--dns-listen", f"127.0.0.1:{dns_port}",
                "--api-listen", f"127.0.0.1:{api_port}",
                "--http-listen", f"127.0.0.1:{http_port}",
                "--https-listen", f"127.0.0.1:{https_port}",
                "--http3-listen", "off",
                "--panel-host", "dashboard.fucloudflare.com",
                "--data-dir", data_dir,
                "--api-token", token,
                "--acme-directory", "off",
                "--edge-ip", "127.0.0.1",
            ]
            if has_role:
                cmd.extend(["--role", "peer"])
            if has_proxy:
                proxy_port = _free_tcp_udp_port()
                cmd.extend(["--proxy-listen", f"127.0.0.1:{proxy_port}"])

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _wait_tcp(api_port, timeout_s=15.0)
            _wait_tcp(https_port, timeout_s=10.0)

            # Bootstrap panel account + test zone
            _api_req(
                api_port,
                None,
                "POST",
                "/auth/setup",
                {"email": email, "password": password, "token": token},
            )
            z_st, z_res = _api_req(
                api_port, token, "POST", "/zones", {"name": "ui-test.example", "type": "full"}
            )
            if z_st in (200, 201) and z_res.get("result"):
                zone_id = z_res["result"]["id"]
                _api_req(
                    api_port,
                    token,
                    "POST",
                    f"/zones/{zone_id}/dns_records",
                    {"type": "A", "name": "www", "content": "192.0.2.10", "proxied": True},
                )
            panel_url = f"https://dashboard.fucloudflare.com:{https_port}/"
            if not auth_url:
                auth_worker_path = Path(__file__).resolve().parent.parent / "workers" / "auth" / "worker.js"
                if auth_worker_path.is_file():
                    fz_st, fz_res = _api_req(
                        api_port, token, "POST", "/zones", {"name": "fucloudflare.com", "type": "full"}
                    )
                    if fz_st in (200, 201) and fz_res.get("result"):
                        fz_id = fz_res["result"]["id"]
                        _api_req(
                            api_port,
                            token,
                            "POST",
                            f"/zones/{fz_id}/dns_records",
                            {"type": "A", "name": "auth", "content": "192.0.2.10", "proxied": True},
                        )
                        kv_st, kv_res = _api_req(
                            api_port, token, "POST", "/kv/namespaces", {"title": "auth-kv"}
                        )
                        d1_st, d1_res = _api_req(
                            api_port, token, "POST", "/d1/database", {"name": "auth-db"}
                        )
                        w_st, _ = _api_req(
                            api_port,
                            token,
                            "PUT",
                            "/workers/scripts/auth",
                            auth_worker_path.read_text(encoding="utf-8"),
                        )
                        if w_st in (200, 201):
                            kv_id = (kv_res.get("result") or {}).get("id") if kv_st in (200, 201) else None
                            d1_id = (d1_res.get("result") or {}).get("uuid") or (d1_res.get("result") or {}).get("id") if d1_st in (200, 201) else None
                            patch_body: dict[str, Any] = {
                                "vars": {"ISSUER": f"https://auth.fucloudflare.com:{https_port}"}
                            }
                            if kv_id:
                                patch_body["kv_bindings"] = {"AUTH_KV": kv_id}
                            if d1_id:
                                patch_body["d1_bindings"] = {"AUTH_DB": d1_id}
                            _api_req(api_port, token, "PATCH", "/workers/scripts/auth/settings", patch_body)
                            _api_req(
                                api_port,
                                token,
                                "POST",
                                f"/zones/{fz_id}/workers/routes",
                                {"pattern": "auth.fucloudflare.com/*", "script": "auth"},
                            )
                auth_url = f"https://auth.fucloudflare.com:{https_port}/login"
        elif api_url and api_token:
            parsed = urlparse(api_url)
            if parsed.port:
                z_st, z_res = _api_req(parsed.port, api_token, "GET", "/zones")
                if z_st == 200 and z_res.get("result"):
                    zone_id = z_res["result"][0]["id"]

        with HeadlessCdpBrowser(browser_path=browser_path, extra_host_maps=host_maps) as browser:
            result = asyncio.run(
                _run_ui_checks_async(browser, panel_url, auth_url, email, password, zone_id)
            )
            result["panel_url"] = panel_url
            result["auth_url"] = auth_url
            result["browser"] = browser.browser_path

            if out_json:
                Path(out_json).parent.mkdir(parents=True, exist_ok=True)
                Path(out_json).write_text(json.dumps(result, indent=2), encoding="utf-8")
            return result
    finally:
        if proc is not None:
            proc.kill()
            proc.wait(timeout=5)
        if data_dir is not None:
            shutil.rmtree(data_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Self-Test (verifies WCAG math + real headless Edge/Chrome CDP offline)
# ---------------------------------------------------------------------------

_SELFTEST_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Kumo UI Selftest</title>
<style>
:root {
  --cf-canvas: #fbfbfb;
  --cf-base: #ffffff;
  --cf-text: #0a0a0a;
  --cf-line: rgba(10,10,10,0.1);
  --sidebar-nav-width: 260px;
  color-scheme: light;
}
:root[data-mode="dark"] {
  --cf-canvas: #030303;
  --cf-base: #0f0f0f;
  --cf-text: #fafafa;
  --cf-line: #333333;
  color-scheme: dark;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--cf-canvas);
  color: var(--cf-text);
  font-family: system-ui, sans-serif;
}
.shell {
  display: grid;
  grid-template-columns: var(--sidebar-nav-width) 1fr;
  min-height: 100vh;
}
aside[data-sidebar="sidebar"] {
  width: var(--sidebar-nav-width);
  background: var(--cf-canvas);
  border-right: 1px solid var(--cf-line);
  padding: 12px;
}
header {
  height: 58px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0 16px;
  border-bottom: 1px solid var(--cf-line);
  background: var(--cf-canvas);
}
main { padding: 24px; max-width: 1000px; }
[data-kumo-component="Card"] {
  background: var(--cf-base);
  border: 1px solid var(--cf-line);
  border-radius: 12px;
  padding: 20px;
}
#modal-backdrop { display: none; position: fixed; inset: 0; background: rgba(0,0,0,0.4); }
#modal-backdrop.open { display: flex; align-items: center; justify-content: center; }
@media (max-width: 767px) {
  .shell { grid-template-columns: 1fr; }
  aside[data-sidebar="sidebar"] { display: none; }
}
</style>
<script>
try {
  if (localStorage.getItem("theme") === "dark") {
    document.documentElement.dataset.mode = "dark";
  }
} catch {}
</script>
</head>
<body>
<div class="shell">
  <aside data-sidebar="sidebar">
    <nav>
      <a href="#/overview">Overview</a>
      <a href="#/zones">Zones</a>
    </nav>
    <button id="sidebar-toggle" data-sidebar="trigger" type="button">Collapse</button>
  </aside>
  <div>
    <header>
      <span>fucloudflare</span>
      <button id="theme-toggle" data-mode-toggle type="button">Dark</button>
    </header>
    <main>
      <div data-kumo-component="Card">
        <h1>Account Home</h1>
        <p>Selftest Kumo surface</p>
        <button id="open-modal" type="button">Add Zone</button>
        <button id="emit-error" type="button">Trigger Error</button>
      </div>
    </main>
  </div>
</div>
<div id="modal-backdrop">
  <div role="dialog" aria-modal="true">
    <h2>New Zone</h2>
    <button id="close-modal" data-close type="button">Close</button>
  </div>
</div>
<script>
document.getElementById("theme-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const next = root.dataset.mode === "dark" ? "light" : "dark";
  if (next === "dark") root.dataset.mode = "dark";
  else delete root.dataset.mode;
  try { localStorage.setItem("theme", next); } catch {}
});
document.getElementById("sidebar-toggle").addEventListener("click", () => {
  const root = document.documentElement;
  const cur = getComputedStyle(root).getPropertyValue("--sidebar-nav-width").trim();
  root.style.setProperty("--sidebar-nav-width", cur === "57px" ? "260px" : "57px");
});
document.getElementById("open-modal").addEventListener("click", () => {
  document.getElementById("modal-backdrop").classList.add("open");
});
document.getElementById("close-modal").addEventListener("click", () => {
  document.getElementById("modal-backdrop").classList.remove("open");
});
document.getElementById("emit-error").addEventListener("click", () => {
  console.error("selftest-console-error");
  setTimeout(() => { throw new Error("selftest-uncaught-exception"); }, 0);
});
</script>
</body>
</html>
"""


class _SelftestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        body = _SELFTEST_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Frame-Options", "DENY")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; frame-ancestors 'none'",
        )
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: Any) -> None:
        pass


class _QuietHttpServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: Any, client_address: Any) -> None:
        pass


def run_selftest(browser_path: str | None = None) -> dict[str, Any]:
    """Verify WCAG contrast math and real headless browser CDP execution + error capture."""
    checks: list[dict[str, Any]] = []

    def _rec(name: str, cond: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(cond), "detail": detail})
        if not cond:
            raise AssertionError(f"ui_check selftest failed [{name}]: {detail}")

    # 1. WCAG contrast math
    bw = contrast_ratio((0, 0, 0), (255, 255, 255))
    _rec("contrast_black_white", abs(bw - 21.0) < 0.05, f"ratio={bw:.2f}")
    kumo_light = contrast_ratio(parse_rgb("#0a0a0a"), parse_rgb("#fbfbfb"))
    _rec("contrast_kumo_light", kumo_light > 18.0, f"ratio={kumo_light:.2f}")
    kumo_dark = contrast_ratio(parse_rgb("#fafafa"), parse_rgb("#030303"))
    _rec("contrast_kumo_dark", kumo_dark > 19.0, f"ratio={kumo_dark:.2f}")
    low = contrast_ratio(parse_rgb("#777777"), parse_rgb("#999999"))
    _rec("contrast_low_fails_aa", low < 4.5, f"ratio={low:.2f}")

    # 2. Local HTTP server + real Headless Edge/Chrome CDP
    srv = _QuietHttpServer(("127.0.0.1", 0), _SelftestHandler)
    port = srv.server_address[1]
    srv_thread = threading.Thread(target=srv.serve_forever, daemon=True)
    srv_thread.start()

    async def _cdp_selftest(ws_url: str) -> None:
        async with websockets.connect(ws_url, max_size=16 * 1024 * 1024) as ws:
            sess = CdpSession(ws)
            await sess.start()
            try:
                await sess.set_viewport(1440, 900, mobile=False)
                await sess.navigate(f"http://127.0.0.1:{port}/", settle_s=0.2)

                # Light surface & WCAG
                light = await _inspect_theme_and_contrast(sess)
                l_ratio = contrast_ratio(parse_rgb(light["textColor"]), parse_rgb(light["bodyBg"]))
                _rec("cdp_light_mode", parse_rgb(light["bodyBg"]) == (251, 251, 251) and l_ratio >= 4.5, str(light))

                # Toggle Dark mode
                toggled = await _find_and_click_theme_toggle(sess)
                _rec("cdp_click_theme_toggle", toggled, f"clicked={toggled}")
                dark = await _inspect_theme_and_contrast(sess)
                d_ratio = contrast_ratio(parse_rgb(dark["textColor"]), parse_rgb(dark["bodyBg"]))
                _rec(
                    "cdp_dark_mode",
                    dark["datasetMode"] == "dark" and parse_rgb(dark["bodyBg"]) == (3, 3, 3) and d_ratio >= 4.5,
                    str(dark),
                )

                # Reload persistence
                await sess.reload(settle_s=0.2)
                reloaded = await _inspect_theme_and_contrast(sess)
                _rec("cdp_reload_persistence", reloaded["datasetMode"] == "dark", str(reloaded))

                # Sidebar geometry 260px -> 57px + 58px topbar
                g1 = await _measure_geometry(sess)
                await _click_sidebar_collapse(sess)
                g2 = await _measure_geometry(sess)
                _rec(
                    "cdp_sidebar_collapse_geometry",
                    g1["sidebarWidth"] == 260 and g2["sidebarWidth"] == 57 and g1["topbarHeight"] == 58,
                    f"g1={g1}, g2={g2}",
                )

                # Mobile viewport non-overflow
                await sess.set_viewport(375, 812, mobile=True)
                gm = await _measure_geometry(sess)
                _rec("cdp_mobile_layout", gm["scrollWidth"] <= gm["clientWidth"], str(gm))
                await sess.set_viewport(1440, 900, mobile=False)

                # Modal click interaction
                await sess.eval("document.getElementById('open-modal').click()")
                dlg_open = await sess.eval("document.getElementById('modal-backdrop').classList.contains('open')")
                _rec("cdp_modal_interaction", bool(dlg_open), f"open={dlg_open}")

                # Confirm 0 errors before intentional error trigger
                clean_errs = await sess.collect_errors()
                _rec(
                    "cdp_zero_errors_on_clean_page",
                    not clean_errs["console_errors"] and not clean_errs["uncaught_exceptions"] and not clean_errs["http_5xx"],
                    str(clean_errs),
                )

                # Trigger real console.error + uncaught exception and verify CDP catches both
                await sess.clear_errors()
                await sess.eval("document.getElementById('emit-error').click()")
                await asyncio.sleep(0.2)
                caught = await sess.collect_errors()
                has_console = any("selftest-console-error" in str(x) for x in caught["console_errors"])
                has_exc = any("selftest-uncaught-exception" in str(x) for x in caught["uncaught_exceptions"])
                _rec("cdp_real_error_capture", has_console and has_exc, str(caught))
            finally:
                await sess.close()

    try:
        with HeadlessCdpBrowser(browser_path=browser_path) as browser:
            asyncio.run(_cdp_selftest(browser.page_ws_url))
            return {"passed": True, "browser": browser.browser_path, "checks": checks}
    finally:
        srv.shutdown()
        srv.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Offline headless Edge/Chrome CDP UI verifier for fucf")
    default_bin = os.path.join("target", "debug", "fucf.exe" if os.name == "nt" else "fucf")
    parser.add_argument("--bin", default=default_bin, help="Path to fucf binary (if launching local instance)")
    parser.add_argument("--browser", default=None, help="Explicit path to msedge / chrome / chromium")
    parser.add_argument("--panel-url", default=None, help="Existing panel URL to test instead of spawning fucf")
    parser.add_argument("--auth-url", default=None, help="Existing auth.fucloudflare.com URL to test")
    parser.add_argument("--out-json", default=None, help="Path to write JSON verification report")
    parser.add_argument("--selftest", action="store_true", help="Run offline WCAG + CDP browser self-test")
    args = parser.parse_args(argv)

    if args.selftest:
        try:
            res = run_selftest(browser_path=args.browser)
            for chk in res["checks"]:
                print(f"  ok   {chk['name']}")
            print(f"ui_check selftest passed ({len(res['checks'])} checks, browser={res['browser']})")
            return 0
        except Exception as exc:
            print(f"ui_check selftest FAILED: {exc}", file=sys.stderr)
            return 1

    res = run_ui_checks(
        fucf_bin=args.bin,
        panel_url=args.panel_url,
        auth_url=args.auth_url,
        browser_path=args.browser,
        out_json=args.out_json,
    )
    for chk in res["checks"]:
        mark = "ok  " if chk["passed"] else "FAIL"
        print(f"  {mark} {chk['name']}: {chk['detail']}")
    return 0 if res.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
