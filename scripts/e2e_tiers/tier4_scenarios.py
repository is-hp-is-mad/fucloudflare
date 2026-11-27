"""Tier 4 — 12 Realistic End-to-End Application Scenarios (T4-001 .. T4-012)."""
from __future__ import annotations

import hashlib
import importlib
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from typing import Any

from . import TestContext, register_test
from .harness import (
    ClusterHarness,
    ContractConfig,
    H2Client,
    WebAuthnSimulator,
    b64u_encode,
    free_port,
    wait_for,
    ws_close,
    ws_connect,
    ws_recv,
    ws_send,
)
from .tier1_features import (
    _complete_oauth_pkce_flow,
    _linuxdo_oauth_login,
    _pkce_pair,
    _register_oauth_client,
    _seed_auth_session_via_oauth,
)


@register_test(
    "T4-001",
    "4",
    "r2",
    ("REQ-01", "REQ-02", "REQ-03", "REQ-04", "REQ-05", "REQ-07", "REQ-08", "REQ-10", "REQ-11", "REQ-14"),
    "Full 3-node production topology lifecycle (peer_a + peer_b + accel_jp)",
)
def t4_001(ctx: TestContext) -> None:
    ctx.ensure_origins()
    c = ctx.new_cluster()
    try:
        # 1. Initialize panel on peer_a
        st, r = c.api("peer_a", "POST", "/auth/setup", {"token": c.token, "email": "ops@fucloudflare.test", "password": "OpsPass!2026_Secure"}, token="")
        assert st == 200
        tok = r["result"]["token"]

        # 2. Configure zone + DNS + WAF + Worker (KV + D1 + Cron) + LocalProxyRule + Hy2 fallback
        z = c.api("peer_a", "POST", "/zones", {"name": "prod.test"}, token=tok)[1]["result"]
        zid = z["id"]
        c.api("peer_a", "POST", f"/zones/{zid}/dns_records", {"type": "A", "name": "@", "content": "127.0.0.1", "proxied": True}, token=tok)
        c.api("peer_a", "POST", f"/zones/{zid}/origin_rules", {"expression": "", "origin_port": ctx.origin1.port}, token=tok)
        kv_id = c.api("peer_a", "POST", ContractConfig.KV_NAMESPACES_PATH, {"title": "prod-kv"}, token=tok)[1]["result"]["id"]
        d1_res = c.api("peer_a", "POST", ContractConfig.D1_DATABASES_PATH, {"name": "prod-d1"}, token=tok)[1]["result"]
        db_id = d1_res.get("uuid") or d1_res["id"]

        worker_js = """export default {
            async scheduled(ctrl, env) {
                await env.KV.put("cron_tick", String(ctrl.scheduledTime));
            },
            async fetch(req, env) {
                const u = new URL(req.url);
                if (u.pathname === "/app/write") {
                    await env.KV.put("k", "v-prod");
                    await env.DB.exec("CREATE TABLE IF NOT EXISTS hits(id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT)");
                    await env.DB.prepare("INSERT INTO hits(path) VALUES(?)").bind(u.pathname).run();
                    return Response.json({ wrote: true });
                }
                const k = await env.KV.get("k");
                const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM hits").first("c");
                return Response.json({ k, cnt, cron: await env.KV.get("cron_tick") });
            }
        }"""
        c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/prod-app", raw=worker_js, token=tok)
        c.api("peer_a", "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/prod-app/settings", {"kv_bindings": {"KV": kv_id}, "d1_bindings": {"DB": db_id}, "crons": ["* * * * *"]}, token=tok)
        c.api("peer_a", "POST", f"/zones/{zid}/workers/routes", {"pattern": "prod.test/app/*", "script": "prod-app"}, token=tok)

        c.api("peer_b", "POST", ContractConfig.PROXY_RULES_PATH, {"name": "app-proxy", "hosts": ["svc.prod.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "enabled": True}, token=tok)
        c.api("peer_b", "POST", ContractConfig.PROXY_RULES_PATH, {"name": "hy2-fb", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "is_fallback": True, "priority": -100, "enabled": True}, token=tok)

        assert c.edge("peer_a", "/app/write", host="prod.test")[0] == 200
        assert c.edge("peer_a", "/__scheduled", host="prod.test")[0] == 200

        # 3. Verify full convergence on peer_b and read-only edge serving on accel_jp
        c.wait_converged(
            lambda: (lambda s, _, b: s == 200 and json.loads(b)["k"] == "v-prod" and json.loads(b)["cnt"] == 1)(
                *c.edge("peer_b", "/app/read", host="prod.test")
            )
        )
        c.wait_converged(lambda: c.proxy("peer_a", "/", host="svc.prod.local")[0] == 200)
        c.wait_converged(lambda: c.edge("accel_jp", "/a/style.css", host="prod.test")[0] == 200)
        c.wait_converged(lambda: c.front("accel_jp", "/masq", host="random-masq.test")[0] == 200)

        # 4. accel_jp invariants
        assert not os.path.exists(os.path.join(c.nodes["accel_jp"].data_dir, "state.json"))
        assert c.dns_query("accel_jp", "prod.test", qtype=2)[1] == 0
        assert c.rss_bytes("accel_jp") <= 200 * 1024 * 1024

        # 5. Restart peers and verify durability
        c.restart("peer_a")
        c.restart("peer_b")
        st_r, _, b_r = c.edge("peer_b", "/app/read", host="prod.test")
        assert st_r == 200 and json.loads(b_r)["k"] == "v-prod" and json.loads(b_r)["cnt"] == 1
    finally:
        c.stop()


@register_test(
    "T4-002",
    "4",
    "r4",
    ("REQ-09", "REQ-15", "REQ-16", "REQ-17", "REQ-18"),
    "Multi-node dashboard.fucloudflare.com SSO + Passkey + Linux.do end-to-end",
)
def t4_002(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")

    # 1. Linux.do login -> link Passkey -> logout -> Passkey login
    cookie = _seed_auth_session_via_oauth(ctx, node="peer_a")
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin, name="t4002-pk")))[0] == 200
    c.edge("peer_a", "/logout", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie})

    def _passkey_on_b() -> str | None:
        chal2 = json.loads(c.edge("peer_b", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
        st, hdrs, _ = c.edge("peer_b", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))
        if st == 200 and hdrs.get("set-cookie"):
            return hdrs["set-cookie"].split(";", 1)[0]
        return None

    auth_cookie_b = c.wait_converged(_passkey_on_b)

    # 2. Panel SSO across peer_a -> auth.fucloudflare.com -> peer_b callback -> /zones & /audit
    st, hdrs, _ = c.edge("peer_a", "/client/v4" + ContractConfig.PANEL_OAUTH_LOGIN_PATH, host=ContractConfig.PANEL_HOST, use_tls=True)
    assert st in (302, 303)
    panel_ck = hdrs.get("set-cookie", "").split(";", 1)[0]
    auth_u = urllib.parse.urlparse(hdrs["location"])
    st2, h2, _ = c.edge("peer_b", auth_u.path + "?" + auth_u.query, host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": auth_cookie_b})
    assert st2 in (302, 303)
    cb_u = urllib.parse.urlparse(h2["location"])
    st3, h3, _ = c.edge("peer_b", cb_u.path + "?" + cb_u.query, host=ContractConfig.PANEL_HOST, use_tls=True, headers={"Cookie": panel_ck} if panel_ck else None)
    assert st3 in (200, 302, 303) and "fucf_s_" in h3.get("set-cookie", "")
    sess = "fucf_s_" + h3["set-cookie"].split("fucf_s_", 1)[1].split(";", 1)[0]
    assert c.api("peer_a", "GET", "/zones", token=sess)[0] == 200
    assert c.api("peer_b", "GET", "/zones", token=sess)[0] == 200


@register_test(
    "T4-003",
    "4",
    "r3",
    ("REQ-11", "REQ-12", "REQ-13", "REQ-14"),
    "Caddy-free native reverse proxy multi-service stack (H1/H2/H3/WS/SSE/Hy2)",
)
def t4_003(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4003")
    c = ctx.ensure_cluster()
    rules = [
        ctx.create_proxy_rule({"name": f"h1-{tag}", "hosts": [f"web.{tag}.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}),
        ctx.create_proxy_rule({"name": f"h2-{tag}", "hosts": [f"grpc.{tag}.local"], "path_prefix": "/", "upstreams": [{"url": ctx.h2_origin.url}], "enabled": True}),
        ctx.create_proxy_rule({"name": f"ws-{tag}", "hosts": [f"ws.{tag}.local"], "path_prefix": "/", "upstreams": [{"url": ctx.ws_origin.url}], "enabled": True}),
        ctx.create_proxy_rule({"name": f"sse-{tag}", "hosts": [f"sse.{tag}.local"], "path_prefix": "/", "upstreams": [{"url": ctx.sse_origin.url}], "enabled": True}),
        ctx.create_proxy_rule({"name": f"fb-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "is_fallback": True, "priority": -100, "enabled": True}),
    ]
    errors: list[str] = []

    def _run_h1():
        try:
            assert c.proxy("peer_a", "/ok", host=f"web.{tag}.local")[0] == 200
        except Exception as e:
            errors.append(f"h1: {e}")

    def _run_h2():
        try:
            p = c.nodes["peer_a"].ports["proxy_tls"]
            st, _, _, proto = H2Client.request(f"https://127.0.0.1:{p}/", headers={"Host": f"grpc.{tag}.local"})
            assert st == 200 and "2" in proto
        except Exception as e:
            errors.append(f"h2: {e}")

    def _run_h3():
        try:
            p = c.nodes["peer_a"].ports["https"]
            st, _, _, _ = c.h3.get(f"https://web.{tag}.local:{p}/h3", connect_port=p)
            assert st == 200
        except Exception as e:
            errors.append(f"h3: {e}")

    def _run_ws():
        try:
            sock, st, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/", headers={"Host": f"ws.{tag}.local"})
            assert st == 101
            ws_send(sock, "stack-ws")
            op, data = ws_recv(sock)
            ws_close(sock)
            assert op == 1 and data == b"stack-ws"
        except Exception as e:
            errors.append(f"ws: {e}")

    def _run_sse():
        try:
            st, _, body = c.proxy("peer_a", "/sse?count=3&delay_ms=50", host=f"sse.{tag}.local")
            assert st == 200 and b"tick-2" in body
        except Exception as e:
            errors.append(f"sse: {e}")

    def _run_fb():
        try:
            st, _, body = c.front("peer_a", "/", host=f"masq-{tag}.unknown.local")
            assert st == 200 and json.loads(body)["tag"] == "origin2"
        except Exception as e:
            errors.append(f"fb: {e}")

    try:
        threads = [threading.Thread(target=fn) for fn in (_run_h1, _run_h2, _run_h3, _run_ws, _run_sse, _run_fb)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=20)
        assert not errors, f"multi-service stack errors: {errors}"
        dfile = os.path.join(c.nodes["peer_a"].data_dir, "domains.lst")
        c.wait_converged(lambda: os.path.exists(dfile) and f"web.{tag}.local" in open(dfile, encoding="utf-8").read())
    finally:
        for r in rules:
            ctx.delete_proxy_rule(r["id"])


@register_test(
    "T4-004",
    "4",
    "r1",
    ("REQ-01", "REQ-02", "REQ-03", "REQ-04", "REQ-05", "REQ-06", "REQ-08"),
    "Stateful Worker app (KV session + D1 ledger + Cron aggregator + WebCrypto HMAC)",
)
def t4_004(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4004")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test")
    kv_id = ctx.create_kv(f"appkv-{tag}")
    db_id = ctx.create_d1(f"appd1-{tag}")
    ctx.deploy_worker(
        f"app-{tag}",
        """export default {
            async scheduled(ctrl, env, ctx) {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, amt INT); CREATE TABLE IF NOT EXISTS rollup(ts INT, total INT)");
                const total = (await env.DB.prepare("SELECT COALESCE(SUM(amt), 0) AS s FROM ledger").first("s")) || 0;
                ctx.waitUntil((async () => {
                    await env.DB.prepare("INSERT INTO rollup VALUES(?, ?)").bind(ctrl.scheduledTime, total).run();
                    await env.KV.put("latest_total", String(total));
                })());
            },
            async fetch(req, env) {
                const u = new URL(req.url);
                await env.DB.exec("CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY AUTOINCREMENT, amt INT); CREATE TABLE IF NOT EXISTS rollup(ts INT, total INT)");
                const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("app-secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
                if (u.pathname === "/tx") {
                    const amt = Number(u.searchParams.get("amt") || "10");
                    await env.DB.batch([
                        env.DB.prepare("INSERT INTO ledger(amt) VALUES(?)").bind(amt),
                        env.DB.prepare("INSERT INTO ledger(amt) VALUES(?)").bind(amt)
                    ]);
                    await env.KV.put("sess:1", "active", { expirationTtl: 120 });
                    const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode("tx:" + amt));
                    return Response.json({ ok: true, sigLen: sig.byteLength });
                }
                return Response.json({
                    sess: await env.KV.get("sess:1"),
                    latest: await env.KV.get("latest_total"),
                    rollups: (await env.DB.prepare("SELECT total FROM rollup").all()).results
                });
            }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        d1_bindings={"DB": db_id},
        crons=["*/5 * * * *"],
    )
    assert c.edge("peer_a", "/tx?amt=25", host=f"{tag}.test")[0] == 200
    assert c.edge("peer_a", "/__scheduled", host=f"{tag}.test")[0] == 200
    c.wait_converged(
        lambda: (lambda s, _, b: s == 200 and json.loads(b).get("latest") == "50" and json.loads(b).get("sess") == "active")(
            *c.edge("peer_b", "/state", host=f"{tag}.test")
        )
    )


@register_test(
    "T4-005",
    "4",
    "r2",
    ("REQ-07", "REQ-08", "REQ-09"),
    "Split-brain / concurrent peer write convergence & node outage recovery",
)
def t4_005(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4005")
    c = ctx.new_cluster()
    try:
        z = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})[1]["result"]
        kv_id = c.api("peer_a", "POST", ContractConfig.KV_NAMESPACES_PATH, {"title": f"sb-{tag}"})[1]["result"]["id"]
        db_res = c.api("peer_a", "POST", ContractConfig.D1_DATABASES_PATH, {"name": f"sb-{tag}"})[1]["result"]
        db_id = db_res.get("uuid") or db_res["id"]
        code = """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname.startsWith("/kv/")) {
                const k = u.pathname.slice(4);
                await env.KV.put(k, u.searchParams.get("v") || "1");
                return new Response("ok");
            }
            if (u.pathname === "/d1") {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS sb(k TEXT PRIMARY KEY, v TEXT)");
                await env.DB.prepare("INSERT OR REPLACE INTO sb VALUES(?, ?)").bind(u.searchParams.get("k"), u.searchParams.get("v")).run();
                return new Response("ok");
            }
            return Response.json({
                ka: await env.KV.get("ka"),
                kb: await env.KV.get("kb"),
                rows: (await env.DB.prepare("SELECT k, v FROM sb ORDER BY k").all()).results
            });
        } }"""
        c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/sb-{tag}", raw=code)
        c.api("peer_a", "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/sb-{tag}/settings", {"kv_bindings": {"KV": kv_id}, "d1_bindings": {"DB": db_id}})
        c.api("peer_a", "POST", f"/zones/{z['id']}/workers/routes", {"pattern": f"{tag}.test/*", "script": f"sb-{tag}"})
        c.wait_converged(lambda: c.edge("peer_b", "/kv/init?v=0", host=f"{tag}.test")[0] == 200)

        # Outage on peer_b while peer_a mutates
        c.stop_node("peer_b")
        assert c.edge("peer_a", "/kv/ka?v=a1", host=f"{tag}.test")[0] == 200
        assert c.edge("peer_a", "/d1?k=r1&v=from-a", host=f"{tag}.test")[0] == 200
        c.api("peer_a", "POST", "/zones", {"name": f"{tag}-while-down.test"})

        # Bring peer_b back, write disjoint items to peer_b concurrently
        c.start_node("peer_b")
        c.wait_ready("peer_b")
        assert c.edge("peer_b", "/kv/kb?v=b1", host=f"{tag}.test")[0] == 200
        assert c.edge("peer_b", "/d1?k=r2&v=from-b", host=f"{tag}.test")[0] == 200

        expected_rows = [{"k": "r1", "v": "from-a"}, {"k": "r2", "v": "from-b"}]
        c.wait_converged(
            lambda: json.loads(c.edge("peer_a", "/state", host=f"{tag}.test")[2]) == {"ka": "a1", "kb": "b1", "rows": expected_rows}
            and json.loads(c.edge("peer_b", "/state", host=f"{tag}.test")[2]) == {"ka": "a1", "kb": "b1", "rows": expected_rows}
        )
        assert any(x["name"] == f"{tag}-while-down.test" for x in c.api("peer_b", "GET", "/zones")[1]["result"])
    finally:
        c.stop()


@register_test(
    "T4-006",
    "4",
    "r3",
    ("REQ-11", "REQ-12", "REQ-13"),
    "High-concurrency native proxy streaming & sustained load (bench_proxy.py)",
    tags=("bench",),
)
def t4_006(ctx: TestContext) -> None:
    bench_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "bench_proxy.py")
    assert os.path.exists(bench_path), f"missing {bench_path}"
    tmp_dir = tempfile.mkdtemp(prefix="fucf-bench-")
    out_json = os.path.join(tmp_dir, "bench.json")
    try:
        try:
            mod = importlib.import_module("bench_proxy")
        except ImportError:
            sys.path.insert(0, os.path.dirname(bench_path))
            mod = importlib.import_module("bench_proxy")
        if hasattr(mod, "run_benchmark"):
            res = mod.run_benchmark(fucf_bin=ctx.bin, out_json=out_json)
            if isinstance(res, dict):
                if "passed" in res:
                    assert res["passed"], f"bench_proxy failed: {res}"
                for name, metrics in res.get("workloads", res).items():
                    if isinstance(metrics, dict) and "errors" in metrics:
                        assert metrics["errors"] == 0, f"workload {name} had errors: {metrics}"
                return
        proc = subprocess.run([sys.executable, bench_path, "--bin", ctx.bin, "--out-json", out_json], capture_output=True, text=True, timeout=180)
        assert proc.returncode == 0, f"bench_proxy.py failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


@register_test(
    "T4-007",
    "4",
    "r5",
    ("REQ-19", "REQ-20", "REQ-16", "REQ-17", "REQ-18"),
    "Headless browser full Dashboard & Auth UI journey (Light + Dark) (ui_check.py)",
    tags=("ui",),
)
def t4_007(ctx: TestContext) -> None:
    ui_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), "ui_check.py")
    assert os.path.exists(ui_path), f"missing {ui_path}"
    try:
        mod = importlib.import_module("ui_check")
    except ImportError:
        sys.path.insert(0, os.path.dirname(ui_path))
        mod = importlib.import_module("ui_check")
    if hasattr(mod, "run_ui_checks"):
        res = mod.run_ui_checks(fucf_bin=ctx.bin)
        if isinstance(res, dict):
            assert res.get("passed"), f"ui_check failed: {res}"
        else:
            assert res is not False, "ui_check.run_ui_checks returned False"
        return
    proc = subprocess.run([sys.executable, ui_path, "--bin", ctx.bin], capture_output=True, text=True, timeout=180)
    assert proc.returncode == 0, f"ui_check.py failed ({proc.returncode}):\n{proc.stdout}\n{proc.stderr}"


@register_test(
    "T4-008",
    "4",
    "r4",
    ("REQ-09", "REQ-15", "REQ-16", "REQ-17", "REQ-18"),
    "Auth security & abuse resilience across peers",
)
def t4_008(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4008")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.sec.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)

    # 1. Redirect URI tampering
    st_redir, h_redir, _ = c.edge(
        "peer_a",
        "/authorize?" + urllib.parse.urlencode({"response_type": "code", "client_id": cl["client_id"], "redirect_uri": "https://attacker.test/cb", "code_challenge": "abc", "code_challenge_method": "S256"}),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
    )
    assert st_redir == 400 and "location" not in h_redir

    # 2. Tampered cross-node ticket
    assert c.api("peer_b", "POST", "/auth/second_step", {"ticket": "bad.ticket", "code": "000000"}, token="")[0] == 401

    # 3. WebAuthn wrong origin + UV=0 + counter rollback
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, "https://evil.test")))[0] in (400, 403)
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin, flags=0x01)))[0] in (400, 401, 403)

    # 4. Silenced Linux.do user blocked
    prev = ctx.mock_oauth.persona
    ctx.mock_oauth.persona = "silenced"
    try:
        assert _linuxdo_oauth_login(ctx)[2]["status"] == 403
    finally:
        ctx.mock_oauth.persona = prev


@register_test(
    "T4-009",
    "4",
    "r2",
    ("REQ-10", "REQ-14"),
    "Accelerate node (jp) traffic limit + 509 + empty /cdn-cgi/limit/* + Hy2 fallback",
)
def t4_009(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4009")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    fb = ctx.create_proxy_rule({"name": f"t4009-fb-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "is_fallback": True, "priority": -100, "enabled": True})
    node_r = c.api("peer_a", "POST", "/nodes", {"name": "accel_jp", "ipv4": "203.0.113.13", "traffic_limit_gb": 0.000001})
    assert node_r[0] == 200
    nid = node_r[1]["result"]["id"]
    try:
        c.wait_converged(lambda: c.edge("accel_jp", "/page", host=f"{tag}.test")[0] in (200, 509))
        # Drive traffic until limited
        def _is_509() -> bool:
            st, _, _ = c.edge("accel_jp", "/page", host=f"{tag}.test")
            return st == 509
        c.wait_converged(_is_509, timeout=20.0)
        st_l, _, b_l = c.edge("accel_jp", "/cdn-cgi/limit/page.css", host=f"{tag}.test")
        assert st_l == 509 and b_l == b""
        # Peers remain healthy
        assert c.edge("peer_a", "/page", host=f"{tag}.test")[0] == 200
        assert c.edge("peer_b", "/page", host=f"{tag}.test")[0] == 200
    finally:
        c.api("peer_a", "DELETE", f"/nodes/{nid}")
        ctx.delete_proxy_rule(fb["id"])
        c.wait_converged(lambda: c.edge("accel_jp", "/page", host=f"{tag}.test")[0] == 200)


@register_test(
    "T4-010",
    "4",
    "r2",
    ("REQ-03", "REQ-09", "REQ-12"),
    "Lock/async deadlock regression stress test (PBKDF2 + D1 batch + Snapshot::build + H2/H3)",
)
def t4_010(ctx: TestContext) -> None:
    tag = ctx.next_tag("t4010")
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    db_id = ctx.create_d1(f"stress-{tag}")
    ctx.deploy_worker(
        f"stress-{tag}",
        """export default { async fetch(r, env) {
            await env.DB.exec("CREATE TABLE IF NOT EXISTS s(id INTEGER PRIMARY KEY AUTOINCREMENT, x TEXT)");
            await env.DB.batch([
                env.DB.prepare("INSERT INTO s(x) VALUES('a')"),
                env.DB.prepare("INSERT INTO s(x) VALUES('b')")
            ]);
            return new Response("ok");
        } }""",
        z["id"],
        f"{tag}.test/*",
        d1_bindings={"DB": db_id},
    )
    stop_evt = threading.Event()
    errors: list[str] = []
    trace_latencies_ms: list[float] = []

    def _login_hammer():
        while not stop_evt.is_set():
            try:
                c.api("peer_a", "POST", "/auth/login", {"email": ctx.admin_email, "password": "wrong-password"}, token="")
            except Exception as e:
                errors.append(f"login: {e}")

    def _d1_hammer():
        while not stop_evt.is_set():
            try:
                st, _, _ = c.edge("peer_a", "/write", host=f"{tag}.test")
                if st != 200:
                    errors.append(f"d1 status={st}")
            except Exception as e:
                errors.append(f"d1: {e}")

    def _snapshot_hammer():
        i = 0
        while not stop_evt.is_set():
            i += 1
            try:
                st, r = c.api("peer_a", "POST", f"/zones/{z['id']}/dns_records", {"type": "TXT", "name": f"s{i}", "content": "v"})
                if st == 200:
                    c.api("peer_a", "DELETE", f"/zones/{z['id']}/dns_records/{r['result']['id']}")
            except Exception as e:
                errors.append(f"snap: {e}")

    def _probe_latency():
        while not stop_evt.is_set():
            t0 = time.monotonic()
            st, _, _ = c.edge("peer_a", "/cdn-cgi/fucf-trace", host=f"{tag}.test")
            dt = (time.monotonic() - t0) * 1000.0
            trace_latencies_ms.append(dt)
            if st != 200:
                errors.append(f"trace status={st}")
            st_sys, _ = c.api("peer_a", "GET", "/system")
            if st_sys != 200:
                errors.append(f"sys status={st_sys}")
            time.sleep(0.05)

    workers = [
        threading.Thread(target=_login_hammer),
        threading.Thread(target=_login_hammer),
        threading.Thread(target=_d1_hammer),
        threading.Thread(target=_d1_hammer),
        threading.Thread(target=_snapshot_hammer),
        threading.Thread(target=_probe_latency),
    ]
    for t in workers:
        t.start()
    time.sleep(6.0)
    stop_evt.set()
    for t in workers:
        t.join(timeout=15)

    assert not errors, f"stress test errors: {errors[:10]}"
    assert len(trace_latencies_ms) >= 10
    p99 = sorted(trace_latencies_ms)[min(len(trace_latencies_ms) - 1, int(len(trace_latencies_ms) * 0.99))]
    assert p99 < 500.0, f"trace p99 {p99:.1f}ms >= 500ms (possible event-loop blocking)"


@register_test(
    "T4-011",
    "4",
    "r2",
    ("REQ-07", "REQ-10"),
    "Unix rolling release with masterless peers + accelerate node (Unix only)",
    tags=("unix_only",),
)
def t4_011(ctx: TestContext) -> None:
    if os.name == "nt":
        print("    [T4-011] skipped on Windows (Unix-only in-place exec rolling release)")
        return
    work = tempfile.mkdtemp(prefix="fucf-t4011-")
    base = os.path.join(work, "fucf")
    shutil.copy(ctx.bin, base)
    os.chmod(base, 0o755)
    try:
        out = subprocess.run([base, "release-keygen"], capture_output=True, text=True, check=True).stdout
        keys = dict(line.split("=", 1) for line in out.split())
        kf = os.path.join(work, "key")
        with open(kf, "w", encoding="utf-8") as f:
            f.write(keys["private"])
        p_rel = os.path.join(work, "rel1")
        with open(base, "rb") as f:
            prog = f.read()
        with open(p_rel, "wb") as f:
            f.write(prog + b"\n# t4-011\n")
        signed = dict(line.split("=", 1) for line in subprocess.run([base, "release-sign", kf, p_rel], capture_output=True, text=True, check=True).stdout.split())

        c = ClusterHarness(base, keep_logs=ctx.keep_logs)
        c.add_node("peer_a", ContractConfig.ROLE_PEER, "203.0.113.11", extra_args=["--release-key", keys["public"]])
        c.add_node("peer_b", ContractConfig.ROLE_PEER, "203.0.113.12", extra_args=["--release-key", keys["public"]])
        c.add_node("accel_jp", ContractConfig.ROLE_ACCELERATE, "203.0.113.13", extra_args=["--release-key", keys["public"]])
        try:
            c.start()
            with open(p_rel, "rb") as f:
                data = f.read()
            st, _ = c.api("peer_a", "PUT", f"/releases/{signed['sha256']}?signature={signed['signature']}", raw=data)
            assert st == 200
            c.wait_converged(lambda: c.api("accel_jp", "GET", "/system")[1]["result"]["exe"] == signed["sha256"], timeout=60.0)
        finally:
            c.stop()
    finally:
        shutil.rmtree(work, ignore_errors=True)


@register_test(
    "T4-012",
    "4",
    "baseline",
    ("REQ-07",),
    "Existing 152-check regression baseline (130 Windows / 152 Unix)",
    tags=("baseline",),
)
def t4_012(ctx: TestContext) -> None:
    scripts_dir = os.path.dirname(os.path.dirname(__file__))
    if scripts_dir not in sys.path:
        sys.path.insert(0, scripts_dir)
    import e2e  # type: ignore

    ran = e2e.run_baseline(ctx.bin)
    expected = 130 if os.name == "nt" else 152
    assert ran == expected, f"expected {expected} baseline checks, ran {ran}"
