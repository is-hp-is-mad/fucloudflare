#!/usr/bin/env python3
"""Reproducible native reverse proxy benchmark for fucloudflare (fucf).

CLI:
    python scripts/bench_proxy.py [--bin <fucf_bin>] [--out-json <path>] [--out-md <path>] [--quick] [--selftest]

Importable API:
    run_benchmark(fucf_bin: str, out_json: str | None = None, out_md: str | None = None, quick: bool = False) -> dict
    run_selftest() -> dict
    percentile(values: list[float], p: float) -> float
    throughput_mb_s(total_bytes: int, elapsed_s: float) -> float
"""

from __future__ import annotations

import argparse
import asyncio
import ctypes
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

try:
    import httpx
except ImportError:  # pragma: no cover - optional fallback handled below
    httpx = None

try:
    import h2.config
    import h2.connection
    import h2.events
    import h2.settings
    HAS_H2 = True
except ImportError:  # pragma: no cover - graceful fallback when h2 is missing
    HAS_H2 = False


SMALL_PAYLOAD: bytes = b"fucf-bench-small-0123456789abcde" * 32  # exact 1024 bytes
assert len(SMALL_PAYLOAD) == 1024

STREAM_CHUNK: bytes = (
    b"fucf-stream-block-0123456789abcdef0123456789abcdef0123456789abcd" * 1024
)  # exact 64 KiB
assert len(STREAM_CHUNK) == 65536


def percentile(values: list[float], p: float) -> float:
    """Compute the p-th percentile (0..100) using linear interpolation."""
    if not values:
        return 0.0
    s = sorted(float(v) for v in values)
    if p <= 0.0:
        return s[0]
    if p >= 100.0:
        return s[-1]
    k = (len(s) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(s) - 1)
    if f == c:
        return s[f]
    return s[f] + (s[c] - s[f]) * (k - f)


def throughput_mb_s(total_bytes: int, elapsed_s: float) -> float:
    """Compute throughput in MiB/s (1024*1024 bytes per MiB)."""
    if total_bytes <= 0 or elapsed_s <= 0.0:
        return 0.0
    return (total_bytes / (1024.0 * 1024.0)) / elapsed_s


def deterministic_stream_sha256(total_bytes: int) -> str:
    """Compute the exact SHA-256 hex digest for `total_bytes` of STREAM_CHUNK."""
    h = hashlib.sha256()
    full, rem = divmod(total_bytes, len(STREAM_CHUNK))
    for _ in range(full):
        h.update(STREAM_CHUNK)
    if rem:
        h.update(STREAM_CHUNK[:rem])
    return h.hexdigest()


def rss_bytes(pid: int) -> int:
    """Return resident set size (RSS / WorkingSetSize) in bytes for `pid`, or 0 if unavailable."""
    if pid <= 0:
        return 0
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

        PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
        PROCESS_VM_READ = 0x0010
        kernel32 = ctypes.windll.kernel32
        psapi = ctypes.windll.psapi
        handle = kernel32.OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, False, pid
        )
        if not handle:
            return 0
        try:
            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(PROCESS_MEMORY_COUNTERS)
            if psapi.GetProcessMemoryInfo(handle, ctypes.byref(counters), counters.cb):
                return int(counters.WorkingSetSize)
            return 0
        finally:
            kernel32.CloseHandle(handle)
    else:
        statm_path = f"/proc/{pid}/statm"
        try:
            with open(statm_path, "r", encoding="utf-8") as fh:
                parts = fh.read().strip().split()
            if len(parts) >= 2:
                return int(parts[1]) * os.sysconf("SC_PAGE_SIZE")
        except OSError:
            return 0
    return 0


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _free_tcp_udp_port() -> int:
    """Allocate a port free on both TCP and UDP (needed for HTTPS + HTTP/3 QUIC)."""
    for _ in range(64):
        p = _free_tcp_port()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as u:
            try:
                u.bind(("127.0.0.1", p))
                return p
            except OSError:
                continue
    return _free_tcp_port()


class BenchOriginServer:
    """Async HTTP/1.1 keep-alive benchmark origin running on a background thread.

    Serves:
      - GET /small         -> deterministic 1024-byte payload (Cache-Control: no-store)
      - GET /stream?mb=8   -> chunked Transfer-Encoding deterministic stream
      - GET /health        -> 200 ok
    """

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: asyncio.AbstractServer | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self.requests_served = 0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "BenchOriginServer":
        self._thread = threading.Thread(target=self._run_thread, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10.0)
        if self._error is not None:
            raise RuntimeError(f"BenchOriginServer failed to start: {self._error}")
        if self.port <= 0:
            raise RuntimeError("BenchOriginServer timed out waiting to bind")
        return self

    def stop(self) -> None:
        if self._loop is not None and self._loop.is_running():
            async def _shutdown() -> None:
                if self._server is not None:
                    self._server.close()
                    await self._server.wait_closed()
                self._loop.stop()

            asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def __enter__(self) -> "BenchOriginServer":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            self._server = loop.run_until_complete(
                asyncio.start_server(self._handle_client, self.host, self._requested_port, backlog=512)
            )
            sock = self._server.sockets[0]
            self.port = int(sock.getsockname()[1])
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:
            self._error = exc
            self._ready.set()
        finally:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        try:
            while True:
                head = await reader.readuntil(b"\r\n\r\n")
                lines = head[:-4].split(b"\r\n")
                if not lines:
                    break
                req_line = lines[0].decode("latin1", errors="replace").split()
                if len(req_line) < 2:
                    break
                method, raw_target = req_line[0].upper(), req_line[1]
                version = req_line[2] if len(req_line) >= 3 else "HTTP/1.1"
                headers: dict[str, str] = {}
                for raw_h in lines[1:]:
                    if b":" in raw_h:
                        k, v = raw_h.split(b":", 1)
                        headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()

                content_length = int(headers.get("content-length", "0") or "0")
                if content_length > 0:
                    await reader.readexactly(content_length)

                conn_hdr = headers.get("connection", "").lower()
                keep_alive = (version == "HTTP/1.1" and "close" not in conn_hdr) or (
                    version == "HTTP/1.0" and "keep-alive" in conn_hdr
                )

                parsed = urlparse(raw_target)
                path = parsed.path
                self.requests_served += 1

                if method in ("GET", "HEAD") and path == "/small":
                    resp = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Length: {len(SMALL_PAYLOAD)}\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Cache-Control: no-store\r\n"
                        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n"
                    ).encode("ascii")
                    writer.write(resp)
                    if method == "GET":
                        writer.write(SMALL_PAYLOAD)
                    await writer.drain()
                elif method == "GET" and path == "/stream":
                    qs = parse_qs(parsed.query)
                    try:
                        mb = max(1, min(64, int(qs.get("mb", ["8"])[0])))
                    except ValueError:
                        mb = 8
                    total_bytes = mb * 1024 * 1024
                    resp = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Transfer-Encoding: chunked\r\n"
                        f"Content-Type: application/octet-stream\r\n"
                        f"Cache-Control: no-store\r\n"
                        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n"
                    ).encode("ascii")
                    writer.write(resp)
                    await writer.drain()

                    remaining = total_bytes
                    while remaining > 0:
                        sz = min(remaining, len(STREAM_CHUNK))
                        chunk = STREAM_CHUNK if sz == len(STREAM_CHUNK) else STREAM_CHUNK[:sz]
                        writer.write(f"{sz:x}\r\n".encode("ascii"))
                        writer.write(chunk)
                        writer.write(b"\r\n")
                        remaining -= sz
                        await writer.drain()
                    writer.write(b"0\r\n\r\n")
                    await writer.drain()
                elif path == "/health":
                    resp = (
                        f"HTTP/1.1 200 OK\r\n"
                        f"Content-Length: 2\r\n"
                        f"Cache-Control: no-store\r\n"
                        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\nok"
                    ).encode("ascii")
                    writer.write(resp)
                    await writer.drain()
                else:
                    body = b"not found"
                    resp = (
                        f"HTTP/1.1 404 Not Found\r\n"
                        f"Content-Length: {len(body)}\r\n"
                        f"Connection: {'keep-alive' if keep_alive else 'close'}\r\n\r\n"
                    ).encode("ascii") + body
                    writer.write(resp)
                    await writer.drain()

                if not keep_alive:
                    break
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError, OSError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


class H2COriginServer:
    """Async HTTP/2 cleartext (h2c prior-knowledge) origin using `h2`."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0) -> None:
        self.host = host
        self._requested_port = port
        self.port: int = 0
        self.available: bool = HAS_H2
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: asyncio.AbstractServer | None = None
        self._ready = threading.Event()
        self._error: BaseException | None = None
        self.requests_served = 0

    @property
    def base_url(self) -> str:
        return f"http://{self.host}:{self.port}"

    def start(self) -> "H2COriginServer":
        if not self.available:
            return self
        self._thread = threading.Thread(target=self._run_thread, daemon=True)
        self._thread.start()
        self._ready.wait(timeout=10.0)
        if self._error is not None:
            raise RuntimeError(f"H2COriginServer failed to start: {self._error}")
        return self

    def stop(self) -> None:
        if not self.available:
            return
        if self._loop is not None and self._loop.is_running():
            async def _shutdown() -> None:
                if self._server is not None:
                    self._server.close()
                    await self._server.wait_closed()
                self._loop.stop()

            asyncio.run_coroutine_threadsafe(_shutdown(), self._loop)
        if self._thread is not None:
            self._thread.join(timeout=5.0)

    def __enter__(self) -> "H2COriginServer":
        return self.start()

    def __exit__(self, exc_type: Any, exc: Any, tb: Any) -> None:
        self.stop()

    def _run_thread(self) -> None:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        try:
            self._server = loop.run_until_complete(
                asyncio.start_server(self._handle_client, self.host, self._requested_port, backlog=256)
            )
            self.port = int(self._server.sockets[0].getsockname()[1])
            self._ready.set()
            loop.run_forever()
        except BaseException as exc:
            self._error = exc
            self._ready.set()
        finally:
            pending = asyncio.all_tasks(loop)
            for t in pending:
                t.cancel()
            if pending:
                loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            loop.close()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        cfg = h2.config.H2Configuration(client_side=False, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        # stream_id -> remaining bytes to send for large /stream responses
        pending_streams: dict[int, int] = {}

        async def _pump_streams() -> None:
            for sid in list(pending_streams.keys()):
                rem = pending_streams[sid]
                while rem > 0:
                    win = conn.local_flow_control_window(sid)
                    if win <= 0:
                        break
                    max_frame = conn.max_outbound_frame_size
                    sz = min(rem, win, max_frame, len(STREAM_CHUNK))
                    if sz <= 0:
                        break
                    chunk = STREAM_CHUNK[:sz]
                    end_stream = (rem - sz) == 0
                    conn.send_data(sid, chunk, end_stream=end_stream)
                    rem -= sz
                    pending_streams[sid] = rem
                if pending_streams[sid] == 0:
                    del pending_streams[sid]
            out = conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()

        try:
            while True:
                data = await reader.read(65536)
                if not data:
                    break
                events = conn.receive_data(data)
                for ev in events:
                    if isinstance(ev, h2.events.RequestReceived):
                        hdrs = dict(ev.headers)
                        raw_path = hdrs.get(":path", "/")
                        parsed = urlparse(raw_path)
                        self.requests_served += 1
                        if parsed.path == "/small":
                            conn.send_headers(
                                ev.stream_id,
                                [
                                    (":status", "200"),
                                    ("content-length", str(len(SMALL_PAYLOAD))),
                                    ("content-type", "application/octet-stream"),
                                    ("cache-control", "no-store"),
                                ],
                            )
                            conn.send_data(ev.stream_id, SMALL_PAYLOAD, end_stream=True)
                        elif parsed.path == "/stream":
                            qs = parse_qs(parsed.query)
                            try:
                                mb = max(1, min(64, int(qs.get("mb", ["8"])[0])))
                            except ValueError:
                                mb = 8
                            total_bytes = mb * 1024 * 1024
                            conn.send_headers(
                                ev.stream_id,
                                [
                                    (":status", "200"),
                                    ("content-length", str(total_bytes)),
                                    ("content-type", "application/octet-stream"),
                                    ("cache-control", "no-store"),
                                ],
                            )
                            pending_streams[ev.stream_id] = total_bytes
                        elif parsed.path == "/health":
                            conn.send_headers(
                                ev.stream_id,
                                [(":status", "200"), ("content-length", "2")],
                            )
                            conn.send_data(ev.stream_id, b"ok", end_stream=True)
                        else:
                            conn.send_headers(
                                ev.stream_id,
                                [(":status", "404"), ("content-length", "9")],
                            )
                            conn.send_data(ev.stream_id, b"not found", end_stream=True)
                    elif isinstance(ev, h2.events.WindowUpdated):
                        pass
                    elif isinstance(ev, h2.events.StreamReset):
                        pending_streams.pop(ev.stream_id, None)
                    elif isinstance(ev, h2.events.ConnectionTerminated):
                        return
                await _pump_streams()
        except (ConnectionResetError, BrokenPipeError, OSError, h2.exceptions.ProtocolError):
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Async Protocol Benchmark Workers
# ---------------------------------------------------------------------------

async def _read_http1_response(
    reader: asyncio.StreamReader,
) -> tuple[int, dict[str, str], bytes]:
    """Read one HTTP/1.1 response (Content-Length or chunked)."""
    head = await reader.readuntil(b"\r\n\r\n")
    lines = head[:-4].split(b"\r\n")
    status_parts = lines[0].decode("latin1", errors="replace").split()
    status = int(status_parts[1]) if len(status_parts) >= 2 else 0
    headers: dict[str, str] = {}
    for raw_h in lines[1:]:
        if b":" in raw_h:
            k, v = raw_h.split(b":", 1)
            headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()

    if "chunked" in headers.get("transfer-encoding", "").lower():
        buf = bytearray()
        while True:
            size_line = await reader.readuntil(b"\r\n")
            sz_str = size_line[:-2].split(b";", 1)[0].strip()
            sz = int(sz_str, 16)
            if sz == 0:
                while True:
                    trailer = await reader.readuntil(b"\r\n")
                    if trailer == b"\r\n":
                        break
                break
            chunk = await reader.readexactly(sz)
            buf.extend(chunk)
            await reader.readexactly(2)  # trailing CRLF
        return status, headers, bytes(buf)

    cl = int(headers.get("content-length", "0") or "0")
    body = await reader.readexactly(cl) if cl > 0 else b""
    return status, headers, body


async def _bench_h1_keepalive(
    target_host: str,
    target_port: int,
    host_header: str,
    path: str,
    concurrency: int,
    total_requests: int,
    expected_body: bytes | None = SMALL_PAYLOAD,
) -> dict[str, Any]:
    """Run concurrent HTTP/1.1 keep-alive GET requests using raw asyncio sockets."""
    latencies_ms: list[float] = []
    errors = 0
    counter = 0
    lock = asyncio.Lock()
    req_bytes = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host_header}\r\n"
        f"Connection: keep-alive\r\n"
        f"User-Agent: fucf-bench/1.0\r\n\r\n"
    ).encode("ascii")

    async def worker() -> None:
        nonlocal counter, errors
        reader: asyncio.StreamReader | None = None
        writer: asyncio.StreamWriter | None = None
        try:
            while True:
                async with lock:
                    if counter >= total_requests:
                        break
                    counter += 1

                t0 = time.perf_counter()
                try:
                    if writer is None or writer.is_closing() or reader is None:
                        reader, writer = await asyncio.wait_for(
                            asyncio.open_connection(target_host, target_port), timeout=5.0
                        )
                    writer.write(req_bytes)
                    await writer.drain()
                    status, hdrs, body = await asyncio.wait_for(
                        _read_http1_response(reader), timeout=10.0
                    )
                    dt = (time.perf_counter() - t0) * 1000.0
                    if status != 200 or (expected_body is not None and body != expected_body):
                        errors += 1
                    else:
                        latencies_ms.append(dt)
                    if "close" in hdrs.get("connection", "").lower():
                        writer.close()
                        await writer.wait_closed()
                        reader = None
                        writer = None
                except Exception:
                    errors += 1
                    if writer is not None:
                        try:
                            writer.close()
                        except Exception:
                            pass
                    reader = None
                    writer = None
        finally:
            if writer is not None:
                try:
                    writer.close()
                    await writer.wait_closed()
                except Exception:
                    pass

    t_start = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    elapsed = max(1e-9, time.perf_counter() - t_start)

    return {
        "requests": total_requests,
        "concurrency": concurrency,
        "succeeded": len(latencies_ms),
        "errors": errors,
        "elapsed_s": round(elapsed, 4),
        "req_s": round(len(latencies_ms) / elapsed, 2),
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
    }


async def _bench_h2c_direct(
    target_host: str,
    target_port: int,
    authority: str,
    path: str,
    concurrency: int,
    total_requests: int,
    expected_body: bytes | None = SMALL_PAYLOAD,
) -> dict[str, Any]:
    """Run direct HTTP/2 cleartext (h2c) requests using `h2` over asyncio."""
    if not HAS_H2:
        return {"skipped": True, "reason": "h2 library not installed", "errors": 0}

    latencies_ms: list[float] = []
    errors = 0
    counter = 0
    lock = asyncio.Lock()

    async def worker() -> None:
        nonlocal counter, errors
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target_host, target_port), timeout=5.0
        )
        cfg = h2.config.H2Configuration(client_side=True, header_encoding="utf-8")
        conn = h2.connection.H2Connection(config=cfg)
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        try:
            while True:
                async with lock:
                    if counter >= total_requests:
                        break
                    counter += 1

                t0 = time.perf_counter()
                try:
                    sid = conn.get_next_available_stream_id()
                    conn.send_headers(
                        sid,
                        [
                            (":method", "GET"),
                            (":path", path),
                            (":scheme", "http"),
                            (":authority", authority),
                            ("user-agent", "fucf-bench/1.0"),
                        ],
                        end_stream=True,
                    )
                    writer.write(conn.data_to_send())
                    await writer.drain()

                    status = 0
                    chunks: list[bytes] = []
                    done = False
                    while not done:
                        data = await asyncio.wait_for(reader.read(65536), timeout=10.0)
                        if not data:
                            raise ConnectionError("EOF from h2c server")
                        for ev in conn.receive_data(data):
                            if isinstance(ev, h2.events.ResponseReceived):
                                hdrs = dict(ev.headers)
                                status = int(hdrs.get(":status", "0"))
                            elif isinstance(ev, h2.events.DataReceived):
                                chunks.append(ev.data)
                                conn.acknowledge_received_data(
                                    ev.flow_controlled_length, ev.stream_id
                                )
                            elif isinstance(ev, h2.events.StreamEnded):
                                done = True
                        out = conn.data_to_send()
                        if out:
                            writer.write(out)
                            await writer.drain()

                    dt = (time.perf_counter() - t0) * 1000.0
                    body = b"".join(chunks)
                    if status != 200 or (expected_body is not None and body != expected_body):
                        errors += 1
                    else:
                        latencies_ms.append(dt)
                except Exception:
                    errors += 1
                    break
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    t_start = time.perf_counter()
    await asyncio.gather(*(worker() for _ in range(concurrency)))
    elapsed = max(1e-9, time.perf_counter() - t_start)

    return {
        "protocol": "h2c",
        "requests": total_requests,
        "concurrency": concurrency,
        "succeeded": len(latencies_ms),
        "errors": errors,
        "elapsed_s": round(elapsed, 4),
        "req_s": round(len(latencies_ms) / elapsed, 2),
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
    }


async def _bench_h2_tls_proxy(
    https_port: int,
    host_header: str,
    path: str,
    concurrency: int,
    total_requests: int,
    expected_body: bytes | None = SMALL_PAYLOAD,
) -> dict[str, Any]:
    """Run HTTP/2 over TLS against fucf using httpx (or curl --http2 fallback)."""
    latencies_ms: list[float] = []
    errors = 0

    if httpx is not None and HAS_H2:
        counter = 0
        lock = asyncio.Lock()
        url = f"https://127.0.0.1:{https_port}{path}"
        limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
        async with httpx.AsyncClient(http2=True, verify=False, limits=limits, timeout=15.0) as client:
            async def worker() -> None:
                nonlocal counter, errors
                while True:
                    async with lock:
                        if counter >= total_requests:
                            break
                        counter += 1
                    t0 = time.perf_counter()
                    try:
                        resp = await client.get(url, headers={"Host": host_header})
                        dt = (time.perf_counter() - t0) * 1000.0
                        if (
                            resp.status_code != 200
                            or resp.http_version != "HTTP/2"
                            or (expected_body is not None and resp.content != expected_body)
                        ):
                            errors += 1
                        else:
                            latencies_ms.append(dt)
                    except Exception:
                        errors += 1

            t_start = time.perf_counter()
            await asyncio.gather(*(worker() for _ in range(concurrency)))
            elapsed = max(1e-9, time.perf_counter() - t_start)

        return {
            "protocol": "h2",
            "client": "httpx",
            "requests": total_requests,
            "concurrency": concurrency,
            "succeeded": len(latencies_ms),
            "errors": errors,
            "elapsed_s": round(elapsed, 4),
            "req_s": round(len(latencies_ms) / elapsed, 2),
            "p50_ms": round(percentile(latencies_ms, 50), 3),
            "p95_ms": round(percentile(latencies_ms, 95), 3),
            "p99_ms": round(percentile(latencies_ms, 99), 3),
        }

    # curl --http2 fallback (for minimal Python without httpx/h2)
    curl_bin = shutil.which("curl") or shutil.which("curl.exe")
    if not curl_bin:
        return {"skipped": True, "reason": "neither httpx+h2 nor curl available", "errors": 1}

    capped_total = min(total_requests, 64)
    capped_conc = min(concurrency, 8)
    url = f"https://127.0.0.1:{https_port}{path}"

    def _one(_: int) -> tuple[bool, float]:
        t0 = time.perf_counter()
        res = subprocess.run(
            [curl_bin, "-sS", "-k", "--http2", "-H", f"Host: {host_header}", url],
            capture_output=True,
            timeout=10,
        )
        dt = (time.perf_counter() - t0) * 1000.0
        ok = res.returncode == 0 and (expected_body is None or res.stdout == expected_body)
        return ok, dt

    t_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=capped_conc) as pool:
        for ok, dt in pool.map(_one, range(capped_total)):
            if ok:
                latencies_ms.append(dt)
            else:
                errors += 1
    elapsed = max(1e-9, time.perf_counter() - t_start)
    return {
        "protocol": "h2",
        "client": "curl",
        "requests": capped_total,
        "concurrency": capped_conc,
        "succeeded": len(latencies_ms),
        "errors": errors,
        "elapsed_s": round(elapsed, 4),
        "req_s": round(len(latencies_ms) / elapsed, 2),
        "p50_ms": round(percentile(latencies_ms, 50), 3),
        "p95_ms": round(percentile(latencies_ms, 95), 3),
        "p99_ms": round(percentile(latencies_ms, 99), 3),
    }


def _bench_h3_quic(
    fucf_bin: str,
    https_port: int,
    h3_host: str,
    seq_count: int,
    conc_workers: int,
    conc_total: int,
) -> dict[str, Any]:
    """Run HTTP/3 benchmarks using `fucf h3-get --connect 127.0.0.1:<port> --insecure`."""
    url = f"https://{h3_host}:{https_port}/small"
    connect = f"127.0.0.1:{https_port}"
    re_timing = re.compile(r"handshake\s+(\d+)\s*ms,\s*total\s+(\d+)\s*ms")

    def _run_one(_: int = 0) -> tuple[bool, float, float]:
        t0 = time.perf_counter()
        res = subprocess.run(
            [fucf_bin, "h3-get", url, "--connect", connect, "--insecure"],
            capture_output=True,
            text=True,
            timeout=20,
        )
        wall_ms = (time.perf_counter() - t0) * 1000.0
        if res.returncode != 0 or "HTTP/3.0 200" not in res.stdout:
            return False, 0.0, wall_ms
        m = re_timing.search(res.stdout)
        if m:
            return True, float(m.group(1)), float(m.group(2))
        return True, wall_ms, wall_ms

    seq_handshakes: list[float] = []
    seq_totals: list[float] = []
    seq_errors = 0
    t_seq_start = time.perf_counter()
    for i in range(seq_count):
        ok, hs, tot = _run_one(i)
        if ok:
            seq_handshakes.append(hs)
            seq_totals.append(tot)
        else:
            seq_errors += 1
    seq_elapsed = max(1e-9, time.perf_counter() - t_seq_start)

    conc_totals: list[float] = []
    conc_errors = 0
    t_conc_start = time.perf_counter()
    with ThreadPoolExecutor(max_workers=conc_workers) as pool:
        for ok, _, tot in pool.map(_run_one, range(conc_total)):
            if ok:
                conc_totals.append(tot)
            else:
                conc_errors += 1
    conc_elapsed = max(1e-9, time.perf_counter() - t_conc_start)

    all_totals = seq_totals + conc_totals
    return {
        "sequential": {
            "requests": seq_count,
            "succeeded": len(seq_totals),
            "errors": seq_errors,
            "elapsed_s": round(seq_elapsed, 4),
            "handshake_p50_ms": round(percentile(seq_handshakes, 50), 3),
            "total_p50_ms": round(percentile(seq_totals, 50), 3),
            "total_p95_ms": round(percentile(seq_totals, 95), 3),
        },
        "concurrent": {
            "concurrency": conc_workers,
            "requests": conc_total,
            "succeeded": len(conc_totals),
            "errors": conc_errors,
            "elapsed_s": round(conc_elapsed, 4),
            "total_p50_ms": round(percentile(conc_totals, 50), 3),
            "total_p95_ms": round(percentile(conc_totals, 95), 3),
        },
        "total_p50_ms": round(percentile(all_totals, 50), 3),
        "total_p95_ms": round(percentile(all_totals, 95), 3),
        "errors": seq_errors + conc_errors,
    }


async def _stream_one_http1(
    target_host: str,
    target_port: int,
    host_header: str,
    path: str,
    expected_sha256: str,
    expected_size: int,
) -> tuple[bool, float, int]:
    """Stream one HTTP/1.1 download and compute SHA-256 incrementally."""
    t0 = time.perf_counter()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(target_host, target_port), timeout=10.0
    )
    try:
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host_header}\r\n"
            f"Connection: close\r\n"
            f"User-Agent: fucf-bench/1.0\r\n\r\n"
        ).encode("ascii")
        writer.write(req)
        await writer.drain()

        head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=15.0)
        ttfb_ms = (time.perf_counter() - t0) * 1000.0
        lines = head[:-4].split(b"\r\n")
        status_parts = lines[0].decode("latin1", errors="replace").split()
        status = int(status_parts[1]) if len(status_parts) >= 2 else 0
        if status != 200:
            return False, ttfb_ms, 0

        headers: dict[str, str] = {}
        for raw_h in lines[1:]:
            if b":" in raw_h:
                k, v = raw_h.split(b":", 1)
                headers[k.decode("latin1").strip().lower()] = v.decode("latin1").strip()

        hasher = hashlib.sha256()
        received = 0
        if "chunked" in headers.get("transfer-encoding", "").lower():
            while True:
                size_line = await asyncio.wait_for(reader.readuntil(b"\r\n"), timeout=30.0)
                sz = int(size_line[:-2].split(b";", 1)[0].strip(), 16)
                if sz == 0:
                    while True:
                        trailer = await reader.readuntil(b"\r\n")
                        if trailer == b"\r\n":
                            break
                    break
                rem = sz
                while rem > 0:
                    chunk = await asyncio.wait_for(
                        reader.read(min(rem, 65536)), timeout=30.0
                    )
                    if not chunk:
                        raise ConnectionError("EOF inside chunk")
                    hasher.update(chunk)
                    received += len(chunk)
                    rem -= len(chunk)
                await reader.readexactly(2)
        else:
            cl = headers.get("content-length")
            if cl is not None:
                rem = int(cl)
                while rem > 0:
                    chunk = await asyncio.wait_for(
                        reader.read(min(rem, 65536)), timeout=30.0
                    )
                    if not chunk:
                        raise ConnectionError("EOF before Content-Length")
                    hasher.update(chunk)
                    received += len(chunk)
                    rem -= len(chunk)
            else:
                while True:
                    chunk = await asyncio.wait_for(reader.read(65536), timeout=30.0)
                    if not chunk:
                        break
                    hasher.update(chunk)
                    received += len(chunk)

        ok = received == expected_size and hasher.hexdigest() == expected_sha256
        return ok, ttfb_ms, received
    finally:
        try:
            writer.close()
            await writer.wait_closed()
        except Exception:
            pass


async def _bench_stream_high_conc(
    target_host: str,
    target_port: int,
    host_header: str,
    concurrency: int,
    mb_each: int,
    fucf_pid: int = 0,
) -> dict[str, Any]:
    """Run concurrent large chunked downloads and verify 100% SHA-256 byte integrity."""
    stream_bytes = mb_each * 1024 * 1024
    expected_sha = deterministic_stream_sha256(stream_bytes)
    path = f"/stream?mb={mb_each}"
    rss_before = rss_bytes(fucf_pid) if fucf_pid else 0

    t_start = time.perf_counter()
    tasks = [
        _stream_one_http1(target_host, target_port, host_header, path, expected_sha, stream_bytes)
        for _ in range(concurrency)
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    elapsed = max(1e-9, time.perf_counter() - t_start)

    rss_after = rss_bytes(fucf_pid) if fucf_pid else 0
    ttfb_list: list[float] = []
    total_verified = 0
    errors = 0
    for item in results:
        if isinstance(item, BaseException):
            errors += 1
        else:
            ok, ttfb_ms, nbytes = item
            if ok:
                ttfb_list.append(ttfb_ms)
                total_verified += nbytes
            else:
                errors += 1

    rss_delta_mb = (
        round((rss_after - rss_before) / (1024.0 * 1024.0), 3)
        if (rss_before > 0 and rss_after > 0)
        else 0.0
    )
    return {
        "concurrency": concurrency,
        "mb_each": mb_each,
        "expected_total_bytes": concurrency * stream_bytes,
        "bytes_verified": total_verified,
        "sha256_verified": errors == 0 and total_verified == concurrency * stream_bytes,
        "errors": errors,
        "elapsed_s": round(elapsed, 4),
        "mb_s": round(throughput_mb_s(total_verified, elapsed), 2),
        "ttfb_p95_ms": round(percentile(ttfb_list, 95), 3),
        "rss_before_mb": round(rss_before / (1024.0 * 1024.0), 2) if rss_before else 0.0,
        "rss_after_mb": round(rss_after / (1024.0 * 1024.0), 2) if rss_after else 0.0,
        "rss_delta_mb": rss_delta_mb,
    }


# ---------------------------------------------------------------------------
# fucf Control Plane Helpers & Benchmark Orchestrator
# ---------------------------------------------------------------------------

def _api_req(
    api_port: int,
    token: str,
    method: str,
    path: str,
    body: dict[str, Any] | None = None,
) -> tuple[int, dict[str, Any]]:
    conn = http.client.HTTPConnection("127.0.0.1", api_port, timeout=15)
    try:
        payload = json.dumps(body) if body is not None else None
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
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
    raise RuntimeError(f"Timed out waiting for TCP port 127.0.0.1:{port}")


def format_markdown_report(report: dict[str, Any]) -> str:
    """Render a benchmark report dictionary as Markdown."""
    w = report.get("workloads", {})
    env = report.get("environment", {})
    lines = [
        "# fucloudflare Native Reverse Proxy Benchmark Report",
        "",
        f"- **Timestamp (UTC)**: {report.get('timestamp_utc', '')}",
        f"- **Platform**: {env.get('platform', '')} (Python {env.get('python', '')})",
        f"- **Binary**: `{report.get('fucf_bin', '')}`",
        f"- **Mode**: `{'quick' if report.get('quick') else 'full'}` ({report.get('proxy_mode', 'unknown')})",
        f"- **Overall Result**: `{'PASS' if report.get('passed') else 'FAIL'}`",
        "",
        "## Throughput & Latency Summary",
        "",
        "| Workload | Target | Throughput | p50 (ms) | p95 (ms) | p99 (ms) | Errors |",
        "|---|---|---:|---:|---:|---:|---:|",
    ]

    def _add_rps_row(name: str, label: str, d: dict[str, Any]) -> None:
        if d.get("skipped"):
            lines.append(f"| {name} | {label} | skipped ({d.get('reason', '')}) | - | - | - | {d.get('errors', 0)} |")
            return
        lines.append(
            f"| {name} | {label} | {d.get('req_s', 0)} req/s | {d.get('p50_ms', 0)} | {d.get('p95_ms', 0)} | {d.get('p99_ms', 0)} | {d.get('errors', 0)} |"
        )

    h1 = w.get("h1_keepalive", {})
    if "direct" in h1:
        _add_rps_row("h1_keepalive", "Direct Origin", h1["direct"])
    if "proxy" in h1:
        _add_rps_row("h1_keepalive", "fucf Proxy", h1["proxy"])

    h2 = w.get("h2_tls", {})
    if "direct" in h2:
        _add_rps_row("h2_tls", "Direct h2c Origin", h2["direct"])
    if "proxy" in h2:
        _add_rps_row("h2_tls", "fucf HTTPS/H2 Proxy", h2["proxy"])

    h3 = w.get("h3_quic", {})
    if h3:
        lines.append(
            f"| h3_quic | fucf H3/QUIC (`h3-get`) | - | {h3.get('total_p50_ms', 0)} | {h3.get('total_p95_ms', 0)} | - | {h3.get('errors', 0)} |"
        )

    st = w.get("stream_high_conc", {})
    for target_key, label in (("direct", "Direct Origin Stream"), ("proxy", "fucf Proxy Stream")):
        sd = st.get(target_key, {})
        if sd:
            lines.append(
                f"| stream_high_conc | {label} | {sd.get('mb_s', 0)} MiB/s | - | {sd.get('ttfb_p95_ms', 0)} (TTFB) | - | {sd.get('errors', 0)} |"
            )

    lines.extend(["", "## Integrity & Resource Checks", ""])
    proxy_stream = st.get("proxy", {})
    lines.append(
        f"- **Stream SHA-256 Integrity (Direct / Proxy)**: "
        f"{st.get('direct', {}).get('sha256_verified')} / {proxy_stream.get('sha256_verified')}"
    )
    lines.append(
        f"- **fucf RSS During Streaming**: before `{proxy_stream.get('rss_before_mb', 0)} MiB`, "
        f"after `{proxy_stream.get('rss_after_mb', 0)} MiB`, delta `{proxy_stream.get('rss_delta_mb', 0)} MiB`"
    )
    for chk in report.get("checks", []):
        mark = "PASS" if chk.get("passed") else "FAIL"
        lines.append(f"- [{mark}] `{chk.get('name')}`: {chk.get('detail')}")
    lines.append("")
    return "\n".join(lines)


def run_benchmark(
    fucf_bin: str,
    out_json: str | None = None,
    out_md: str | None = None,
    quick: bool = False,
) -> dict[str, Any]:
    """Run direct vs fucf native reverse proxy benchmarks across H1, H2, H3, and high-concurrency streaming."""
    if not os.path.exists(fucf_bin):
        raise FileNotFoundError(f"fucf binary not found: {fucf_bin}")

    help_res = subprocess.run([fucf_bin, "--help"], capture_output=True, text=True, timeout=10)
    help_text = help_res.stdout + "\n" + help_res.stderr
    has_role = "--role" in help_text
    has_proxy_listen = "--proxy-listen" in help_text

    if quick:
        h1_c, h1_n = 8, 200
        h2_c, h2_n = 8, 200
        h3_seq, h3_conc_w, h3_conc_n = 5, 4, 8
        stream_c, stream_mb = 4, 2
    else:
        h1_c, h1_n = 32, 2000
        h2_c, h2_n = 32, 2000
        h3_seq, h3_conc_w, h3_conc_n = 20, 8, 16
        stream_c, stream_mb = 16, 8

    data_dir = tempfile.mkdtemp(prefix="fucf-bench-")
    proc: subprocess.Popen[bytes] | None = None
    try:
        with BenchOriginServer() as h1_origin, H2COriginServer() as h2c_origin:
            dns_port = _free_tcp_udp_port()
            api_port = _free_tcp_port()
            http_port = _free_tcp_port()
            https_port = _free_tcp_udp_port()
            proxy_port = _free_tcp_port() if has_proxy_listen else http_port
            token = "bench-token"

            cmd = [
                fucf_bin,
                "--dns-listen", f"127.0.0.1:{dns_port}",
                "--api-listen", f"127.0.0.1:{api_port}",
                "--http-listen", f"127.0.0.1:{http_port}",
                "--https-listen", f"127.0.0.1:{https_port}",
                "--http3-listen", f"127.0.0.1:{https_port}",
                "--data-dir", data_dir,
                "--api-token", token,
                "--acme-directory", "off",
                "--edge-ip", "127.0.0.1",
                "--cache-mb", "64",
            ]
            if has_role:
                cmd.extend(["--role", "peer"])
            if has_proxy_listen:
                cmd.extend(["--proxy-listen", f"127.0.0.1:{proxy_port}"])

            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            _wait_tcp(api_port, timeout_s=15.0)
            _wait_tcp(http_port, timeout_s=10.0)
            _wait_tcp(https_port, timeout_s=10.0)
            if has_proxy_listen:
                _wait_tcp(proxy_port, timeout_s=10.0)

            # Configure routing: prefer LocalProxyRule (/client/v4/proxy/rules), fallback to Zone + OriginRule
            proxy_mode = "zone_origin_rule"
            rule_status, _ = _api_req(
                api_port,
                token,
                "POST",
                "/proxy/rules",
                {
                    "name": "bench-h1",
                    "hosts": ["bench.local"],
                    "path_prefix": "/",
                    "exact_path": False,
                    "upstreams": [{"url": h1_origin.base_url, "weight": 1}],
                    "preserve_host": False,
                    "priority": 10,
                    "enabled": True,
                },
            )
            if rule_status in (200, 201):
                proxy_mode = "local_proxy_rule"
                if h2c_origin.available:
                    _api_req(
                        api_port,
                        token,
                        "POST",
                        "/proxy/rules",
                        {
                            "name": "bench-h2c",
                            "hosts": ["h2c-bench.local"],
                            "path_prefix": "/",
                            "exact_path": False,
                            "upstreams": [{"url": h2c_origin.base_url.replace("http://", "h2c://"), "weight": 1}],
                            "preserve_host": False,
                            "priority": 10,
                            "enabled": True,
                        },
                    )
            else:
                proxy_port = http_port

            # Also configure a proxied zone so HTTPS/H2/H3 work seamlessly in both modes
            z_status, z_data = _api_req(
                api_port, token, "POST", "/zones", {"name": "bench.local", "type": "full"}
            )
            if z_status in (200, 201) and z_data.get("result"):
                zid = z_data["result"]["id"]
                _api_req(
                    api_port,
                    token,
                    "POST",
                    f"/zones/{zid}/dns_records",
                    {"type": "A", "name": "@", "content": "127.0.0.1", "proxied": True},
                )
                _api_req(
                    api_port,
                    token,
                    "PATCH",
                    f"/zones/{zid}/settings/ssl",
                    {"value": "flexible"},
                )
                _api_req(
                    api_port,
                    token,
                    "PATCH",
                    f"/zones/{zid}/settings/http2",
                    {"value": True},
                )
                _api_req(
                    api_port,
                    token,
                    "PATCH",
                    f"/zones/{zid}/settings/http3",
                    {"value": True},
                )
                _api_req(
                    api_port,
                    token,
                    "POST",
                    f"/zones/{zid}/origin_rules",
                    {
                        "description": "bench origin",
                        "expression": "",
                        "origin_host": "127.0.0.1",
                        "origin_port": h1_origin.port,
                        "origin_scheme": "http",
                        "priority": 1,
                        "enabled": True,
                    },
                )
                _api_req(
                    api_port,
                    token,
                    "POST",
                    f"/zones/{zid}/cache_rules",
                    {
                        "description": "bypass cache for benchmark",
                        "expression": "",
                        "cache": False,
                        "priority": 1,
                        "enabled": True,
                    },
                )

            # Wait briefly for Snapshot rebuild
            time.sleep(0.3)

            # Warmup
            asyncio.run(_bench_h1_keepalive("127.0.0.1", proxy_port, "bench.local", "/small", 4, 16))

            # Workload 1: HTTP/1.1 Keep-Alive
            h1_direct = asyncio.run(
                _bench_h1_keepalive("127.0.0.1", h1_origin.port, "127.0.0.1", "/small", h1_c, h1_n)
            )
            h1_proxy = asyncio.run(
                _bench_h1_keepalive("127.0.0.1", proxy_port, "bench.local", "/small", h1_c, h1_n)
            )

            # Workload 2: HTTP/2
            h2_direct = asyncio.run(
                _bench_h2c_direct("127.0.0.1", h2c_origin.port, "127.0.0.1", "/small", h2_c, h2_n)
            )
            h2_proxy = asyncio.run(
                _bench_h2_tls_proxy(https_port, "bench.local", "/small", h2_c, h2_n)
            )

            # Workload 3: HTTP/3 QUIC
            h3_proxy = _bench_h3_quic(
                fucf_bin, https_port, "bench.local", h3_seq, h3_conc_w, h3_conc_n
            )

            # Workload 4: High-Concurrency Streaming
            stream_direct = asyncio.run(
                _bench_stream_high_conc("127.0.0.1", h1_origin.port, "127.0.0.1", stream_c, stream_mb, 0)
            )
            stream_proxy = asyncio.run(
                _bench_stream_high_conc("127.0.0.1", proxy_port, "bench.local", stream_c, stream_mb, proc.pid)
            )

            checks = [
                {
                    "name": "h1_keepalive_zero_errors",
                    "passed": h1_direct["errors"] == 0 and h1_proxy["errors"] == 0,
                    "detail": f"direct_err={h1_direct['errors']}, proxy_err={h1_proxy['errors']}",
                },
                {
                    "name": "h2_tls_zero_errors",
                    "passed": h2_direct.get("errors", 0) == 0 and h2_proxy.get("errors", 0) == 0,
                    "detail": f"direct_err={h2_direct.get('errors', 0)}, proxy_err={h2_proxy.get('errors', 0)}",
                },
                {
                    "name": "h3_quic_zero_errors",
                    "passed": h3_proxy["errors"] == 0,
                    "detail": f"h3_err={h3_proxy['errors']}",
                },
                {
                    "name": "stream_sha256_integrity",
                    "passed": (
                        stream_direct["errors"] == 0
                        and stream_proxy["errors"] == 0
                        and stream_direct["sha256_verified"]
                        and stream_proxy["sha256_verified"]
                    ),
                    "detail": f"proxy_bytes={stream_proxy['bytes_verified']}, mb_s={stream_proxy['mb_s']}",
                },
            ]

            report: dict[str, Any] = {
                "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "fucf_bin": os.path.abspath(fucf_bin),
                "quick": quick,
                "proxy_mode": proxy_mode,
                "environment": {
                    "platform": platform.platform(),
                    "python": platform.python_version(),
                    "has_httpx": httpx is not None,
                    "has_h2": HAS_H2,
                },
                "workloads": {
                    "h1_keepalive": {"direct": h1_direct, "proxy": h1_proxy},
                    "h2_tls": {"direct": h2_direct, "proxy": h2_proxy},
                    "h3_quic": h3_proxy,
                    "stream_high_conc": {"direct": stream_direct, "proxy": stream_proxy},
                },
                "checks": checks,
                "passed": all(c["passed"] for c in checks),
            }

            if out_json:
                Path(out_json).parent.mkdir(parents=True, exist_ok=True)
                Path(out_json).write_text(json.dumps(report, indent=2), encoding="utf-8")
            if out_md:
                Path(out_md).parent.mkdir(parents=True, exist_ok=True)
                Path(out_md).write_text(format_markdown_report(report), encoding="utf-8")

            return report
    finally:
        if proc is not None:
            proc.kill()
            proc.wait(timeout=5)
        shutil.rmtree(data_dir, ignore_errors=True)


# ---------------------------------------------------------------------------
# Self-Test (verifies math, BenchOriginServer, H2COriginServer, streaming SHA)
# ---------------------------------------------------------------------------

def run_selftest() -> dict[str, Any]:
    """Exercise percentile, throughput, BenchOriginServer, H2COriginServer, and report formatting."""
    checks: list[dict[str, Any]] = []

    def _rec(name: str, cond: bool, detail: str) -> None:
        checks.append({"name": name, "passed": bool(cond), "detail": detail})
        if not cond:
            raise AssertionError(f"selftest failed [{name}]: {detail}")

    # 1. Percentile math
    _rec("percentile_empty", percentile([], 50) == 0.0, "empty -> 0.0")
    _rec("percentile_single", percentile([42.5], 95) == 42.5, "single -> 42.5")
    vec = [10.0, 20.0, 30.0, 40.0, 50.0]
    _rec("percentile_p0", percentile(vec, 0) == 10.0, f"p0={percentile(vec, 0)}")
    _rec("percentile_p50", percentile(vec, 50) == 30.0, f"p50={percentile(vec, 50)}")
    _rec("percentile_p95", abs(percentile(vec, 95) - 48.0) < 1e-6, f"p95={percentile(vec, 95)}")
    _rec("percentile_p100", percentile(vec, 100) == 50.0, f"p100={percentile(vec, 100)}")

    # 2. Throughput math
    mb_s = throughput_mb_s(10 * 1024 * 1024, 2.0)
    _rec("throughput_mb_s", abs(mb_s - 5.0) < 1e-6, f"10 MiB / 2s = {mb_s}")
    _rec("throughput_zero", throughput_mb_s(1024, 0.0) == 0.0, "zero elapsed -> 0.0")

    # 3. Deterministic SHA-256
    sha_1m = deterministic_stream_sha256(1024 * 1024)
    _rec("deterministic_sha_len", len(sha_1m) == 64, f"len={len(sha_1m)}")

    # 4. Real BenchOriginServer H1 keep-alive + chunked stream SHA-256
    with BenchOriginServer() as origin:
        h1_res = asyncio.run(
            _bench_h1_keepalive("127.0.0.1", origin.port, "127.0.0.1", "/small", 4, 40)
        )
        _rec(
            "bench_origin_h1_keepalive",
            h1_res["errors"] == 0 and h1_res["succeeded"] == 40 and h1_res["req_s"] > 0,
            str(h1_res),
        )
        st_res = asyncio.run(
            _bench_stream_high_conc("127.0.0.1", origin.port, "127.0.0.1", 4, 1, os.getpid())
        )
        _rec(
            "bench_origin_stream_sha256",
            st_res["errors"] == 0
            and st_res["sha256_verified"]
            and st_res["bytes_verified"] == 4 * 1024 * 1024,
            str(st_res),
        )

    # 5. Real H2COriginServer (when h2 installed)
    with H2COriginServer() as h2_origin:
        if h2_origin.available:
            h2_res = asyncio.run(
                _bench_h2c_direct("127.0.0.1", h2_origin.port, "127.0.0.1", "/small", 4, 32)
            )
            _rec(
                "h2c_origin_small",
                h2_res["errors"] == 0 and h2_res["succeeded"] == 32,
                str(h2_res),
            )
        else:
            _rec("h2c_origin_graceful_skip", True, "h2 not installed; graceful skip verified")

    # 6. Markdown report formatter
    sample_report = {
        "timestamp_utc": "2026-11-27T00:00:00Z",
        "fucf_bin": "fucf",
        "quick": True,
        "proxy_mode": "local_proxy_rule",
        "environment": {"platform": "test", "python": "3.11"},
        "workloads": {
            "h1_keepalive": {"direct": {"req_s": 1000, "p50_ms": 1.0, "p95_ms": 2.0, "p99_ms": 3.0, "errors": 0},
                             "proxy": {"req_s": 900, "p50_ms": 1.1, "p95_ms": 2.2, "p99_ms": 3.5, "errors": 0}},
            "h2_tls": {"direct": {"req_s": 800, "p50_ms": 1.2, "p95_ms": 2.4, "p99_ms": 3.6, "errors": 0},
                       "proxy": {"req_s": 750, "p50_ms": 1.3, "p95_ms": 2.5, "p99_ms": 3.8, "errors": 0}},
            "h3_quic": {"total_p50_ms": 5.0, "total_p95_ms": 9.0, "errors": 0},
            "stream_high_conc": {"direct": {"mb_s": 500.0, "ttfb_p95_ms": 2.0, "sha256_verified": True, "errors": 0},
                                 "proxy": {"mb_s": 400.0, "ttfb_p95_ms": 2.5, "sha256_verified": True, "rss_before_mb": 20.0, "rss_after_mb": 24.0, "rss_delta_mb": 4.0, "errors": 0}},
        },
        "checks": [{"name": "selftest", "passed": True, "detail": "ok"}],
        "passed": True,
    }
    md = format_markdown_report(sample_report)
    _rec("markdown_report_format", "h1_keepalive" in md and "stream_high_conc" in md, "md rendered")

    return {"passed": True, "checks": checks}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Reproducible native reverse proxy benchmark for fucf")
    default_bin = os.path.join("target", "debug", "fucf.exe" if os.name == "nt" else "fucf")
    parser.add_argument("--bin", default=default_bin, help="Path to compiled fucf binary")
    parser.add_argument("--out-json", default=None, help="Path to write JSON benchmark report")
    parser.add_argument("--out-md", default=None, help="Path to write Markdown benchmark report")
    parser.add_argument("--quick", action="store_true", help="Run reduced quick benchmark counts")
    parser.add_argument("--selftest", action="store_true", help="Run offline helper & origin self-test")
    args = parser.parse_args(argv)

    if args.selftest:
        try:
            res = run_selftest()
            for chk in res["checks"]:
                print(f"  ok   {chk['name']} ({chk['detail']})")
            print(f"bench_proxy selftest passed ({len(res['checks'])} checks)")
            return 0
        except Exception as exc:
            print(f"bench_proxy selftest FAILED: {exc}", file=sys.stderr)
            return 1

    report = run_benchmark(
        fucf_bin=args.bin,
        out_json=args.out_json,
        out_md=args.out_md,
        quick=args.quick,
    )
    print(format_markdown_report(report))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
