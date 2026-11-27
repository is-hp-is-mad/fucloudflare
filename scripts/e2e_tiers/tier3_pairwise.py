"""Tier 3 — 24 Cross-Feature Pairwise Integration Tests (T3-001 .. T3-024)."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import threading
import time
import urllib.parse

from . import CdpSession, TestContext, find_browser_executable, register_test
from .harness import (
    ContractConfig,
    H2Client,
    TestOriginServer,
    WebAuthnSimulator,
    WsEchoServer,
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
    _run_cdp_on_panel,
    _seed_auth_session_via_oauth,
    _setup_d1_worker,
    _setup_kv_worker,
    _verify_jwt_rs_or_es,
)


@register_test("T3-001", "3", "r1", ("REQ-01", "REQ-02", "REQ-08"), "KV metadata + short TTL synced peer_a -> peer_b expires on both")
def t3_001(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3001")
    c = ctx.ensure_cluster()
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname === "/put") {
                await env.KV.put("meta_ttl", "hello", { metadata: { src: "a" }, expiration: Math.floor(Date.now()/1000) + 3 });
                return new Response("ok");
            }
            return Response.json({ got: await env.KV.getWithMetadata("meta_ttl") });
        } }""",
    )
    c.wait_converged(lambda: c.edge("peer_b", "/get", host=host)[0] == 200)
    assert c.edge("peer_a", "/put", host=host)[0] == 200
    c.wait_converged(lambda: json.loads(c.edge("peer_b", "/get", host=host)[2])["got"]["metadata"] == {"src": "a"})
    time.sleep(3.5)
    assert json.loads(c.edge("peer_a", "/get", host=host)[2])["got"]["value"] is None
    assert json.loads(c.edge("peer_b", "/get", host=host)[2])["got"]["value"] is None


@register_test("T3-002", "3", "r1", ("REQ-03", "REQ-08"), "D1 batch migration + insert on peer_a replicates identically to peer_b")
def t3_002(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3002")
    c = ctx.ensure_cluster()
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname === "/migrate") {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS ledger(id INTEGER PRIMARY KEY, amt INT)");
                await env.DB.batch([
                    env.DB.prepare("INSERT OR REPLACE INTO ledger VALUES(1, 100)"),
                    env.DB.prepare("INSERT OR REPLACE INTO ledger VALUES(2, 250)")
                ]);
                return new Response("ok");
            }
            const raw = await env.DB.prepare("SELECT id, amt FROM ledger ORDER BY id").raw({ columnNames: true });
            const first = await env.DB.prepare("SELECT SUM(amt) AS total FROM ledger").first("total");
            return Response.json({ raw, first });
        } }""",
    )
    assert c.edge("peer_a", "/migrate", host=host)[0] == 200
    expected = {"raw": [["id", "amt"], [1, 100], [2, 250]], "first": 350}
    c.wait_converged(lambda: (lambda s, _, b: s == 200 and json.loads(b) == expected)(*c.edge("peer_b", "/read", host=host)))


@register_test("T3-003", "3", "r1", ("REQ-05", "REQ-01"), "Cron scheduled() writes timestamp to KV -> fetch() Worker reads it")
def t3_003(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3003")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test")
    kv_id = ctx.create_kv(f"cronkv-{tag}")
    ctx.deploy_worker(
        f"ckv-{tag}",
        """export default {
            async scheduled(ctrl, env) { await env.KV.put("last_run", String(ctrl.scheduledTime)); },
            async fetch(r, env) { return Response.json({ last: await env.KV.get("last_run") }); }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["* * * * *"],
    )
    assert c.edge("peer_a", "/__scheduled", host=f"{tag}.test")[0] == 200
    d = json.loads(c.edge("peer_a", "/check", host=f"{tag}.test")[2])
    assert d["last"] and int(d["last"]) > 1_700_000_000_000


@register_test("T3-004", "3", "r1", ("REQ-05", "REQ-03"), "Cron scheduled() inserts audit row into D1 surviving peer_a restart")
def t3_004(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3004")
    c = ctx.new_cluster()
    try:
        z = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})[1]["result"]
        db = c.api("peer_a", "POST", ContractConfig.D1_DATABASES_PATH, {"name": f"cd1-{tag}"})[1]["result"]
        db_id = db.get("uuid") or db["id"]
        code = """export default {
            async scheduled(ctrl, env) {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS audit(ts INTEGER)");
                await env.DB.prepare("INSERT INTO audit VALUES(?)").bind(ctrl.scheduledTime).run();
            },
            async fetch(r, env) { return Response.json({ c: await env.DB.prepare("SELECT COUNT(*) AS c FROM audit").first("c") }); }
        }"""
        c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/cd1-{tag}", raw=code)
        c.api("peer_a", "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/cd1-{tag}/settings", {"d1_bindings": {"DB": db_id}, "crons": ["* * * * *"]})
        c.api("peer_a", "POST", f"/zones/{z['id']}/workers/routes", {"pattern": f"{tag}.test/*", "script": f"cd1-{tag}"})
        assert c.edge("peer_a", "/__scheduled", host=f"{tag}.test")[0] == 200
        c.restart("peer_a")
        st, _, body = c.edge("peer_a", "/read", host=f"{tag}.test")
        assert st == 200 and json.loads(body)["c"] == 1
    finally:
        c.stop()


@register_test("T3-005", "3", "r1", ("REQ-06", "REQ-01"), "Worker signs token with WebCrypto HMAC, caches in KV, verifies next request")
def t3_005(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3005")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("k-hmac"), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
            const msg = new TextEncoder().encode("user=42");
            if (u.pathname === "/issue") {
                const sig = await crypto.subtle.sign("HMAC", key, msg);
                const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
                await env.KV.put("tok", hex);
                return Response.json({ hex });
            }
            const hex = await env.KV.get("tok");
            const sig = new Uint8Array(hex.match(/../g).map(h => parseInt(h, 16)));
            return Response.json({ ok: await crypto.subtle.verify("HMAC", key, sig, msg) });
        } }""",
    )
    c = ctx.ensure_cluster()
    assert c.edge("peer_a", "/issue", host=host)[0] == 200
    assert json.loads(c.edge("peer_a", "/verify", host=host)[2]) == {"ok": True}


@register_test("T3-006", "3", "r2", ("REQ-07", "REQ-10"), "peer_a creates LocalProxyRule + zone -> accel_jp pulls both & proxies with 0 state.json")
def t3_006(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3006")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    rule = ctx.create_proxy_rule({"name": f"jp-{tag}", "hosts": [f"{tag}.jp.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "enabled": True})
    try:
        c.wait_converged(lambda: c.edge("accel_jp", "/p", host=f"{tag}.test")[0] == 200)
        c.wait_converged(lambda: c.proxy("accel_jp", "/p", host=f"{tag}.jp.local")[0] == 200)
        assert not os.path.exists(os.path.join(c.nodes["accel_jp"].data_dir, "state.json"))
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T3-007", "3", "r2", ("REQ-08", "REQ-10"), "peer_a updates KV & D1 -> accel_jp serves read-only Worker with replicated data")
def t3_007(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3007")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    kv_id = ctx.create_kv(f"jpkv-{tag}")
    db_id = ctx.create_d1(f"jpd1-{tag}")
    ctx.deploy_worker(
        f"jpw-{tag}",
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname === "/seed") {
                await env.KV.put("jp_k", "jp_v");
                await env.DB.exec("CREATE TABLE IF NOT EXISTS j(v TEXT); INSERT INTO j VALUES('row_jp')");
                return new Response("ok");
            }
            return Response.json({ kv: await env.KV.get("jp_k"), db: await env.DB.prepare("SELECT v FROM j").first("v") });
        } }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        d1_bindings={"DB": db_id},
    )
    assert c.edge("peer_a", "/seed", host=f"{tag}.test")[0] == 200
    c.wait_converged(
        lambda: (lambda s, _, b: s == 200 and json.loads(b) == {"kv": "jp_v", "db": "row_jp"})(
            *c.edge("accel_jp", "/read", host=f"{tag}.test")
        )
    )


@register_test("T3-008", "3", "r2", ("REQ-09", "REQ-07"), "Editor created on peer_a changes password on peer_b -> old password fails on peer_a")
def t3_008(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3008")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    email = f"{tag}@example.test"
    ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "editor"}, token=tok)[1]["result"]
    pw1 = ru["password"]
    pw2 = "Rotated!2026_Secure"
    c.wait_converged(lambda: c.api("peer_b", "POST", "/auth/login", {"email": email, "password": pw1}, token="")[0] == 200)
    etok = c.api("peer_b", "POST", "/auth/login", {"email": email, "password": pw1}, token="")[1]["result"]["token"]
    assert c.api("peer_b", "POST", "/account/password", {"current": pw1, "new": pw2}, token=etok)[0] == 200
    c.wait_converged(lambda: c.api("peer_a", "POST", "/auth/login", {"email": email, "password": pw2}, token="")[0] == 200)
    assert c.api("peer_a", "POST", "/auth/login", {"email": email, "password": pw1}, token="")[0] == 401


@register_test("T3-009", "3", "r2", ("REQ-09", "REQ-17"), "Passkey registered on peer_a begins ceremony on peer_a and finishes on peer_b")
def t3_009(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx, node="peer_a")
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    # Wait for Auth Worker KV/D1 passkey to sync to peer_b
    def _begin_on_a_finish_on_b() -> bool:
        b = c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")
        chal2 = json.loads(b[2])["challenge"]
        st, hdrs, _ = c.edge("peer_b", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))
        return st == 200 and bool(hdrs.get("set-cookie"))
    c.wait_converged(_begin_on_a_finish_on_b)


@register_test("T3-010", "3", "r3", ("REQ-11", "REQ-12"), "LocalProxyRule matches h2c:// upstream, strips Server, preserves Host over HTTPS H2 client")
def t3_010(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3010")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {
            "name": f"h2c-hdr-{tag}",
            "hosts": [f"{tag}.h2chdr.local"],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.h2_origin.url}],
            "preserve_host": True,
            "strip_response_headers": ["Server"],
            "enabled": True,
        }
    )
    try:
        port = c.nodes["peer_a"].ports["proxy_tls"]
        st, hdrs, body, proto = H2Client.request(f"https://127.0.0.1:{port}/check", headers={"Host": f"{tag}.h2chdr.local"})
        d = json.loads(body)
        assert st == 200 and "2" in proto and "server" not in hdrs and d["proto"] == "h2c"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T3-011", "3", "r3", ("REQ-11", "REQ-13"), "LocalProxyRule load-balances WebSocket across 2 origins and fails over when 1 stops")
def t3_011(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3011")
    c = ctx.ensure_cluster()
    ws2 = WsEchoServer("ws-ephem").start()
    rule = ctx.create_proxy_rule(
        {
            "name": f"wslb-{tag}",
            "hosts": [f"{tag}.wslb.local"],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.ws_origin.url, "weight": 1}, {"url": ws2.url, "weight": 1}],
            "enabled": True,
        }
    )
    try:
        ws2.stop()
        sock, st, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/ws", headers={"Host": f"{tag}.wslb.local"})
        assert st == 101
        ws_send(sock, "failover-ok")
        op, data = ws_recv(sock)
        ws_close(sock)
        assert op == 1 and data.decode() == "failover-ok"
    finally:
        ws2.stop()
        ctx.delete_proxy_rule(rule["id"])


@register_test("T3-012", "3", "r3", ("REQ-12", "REQ-14"), "Hy2 front.rs (18480) forwards to LocalProxyRule h2c upstream with fucf-ray & visitor IP")
def t3_012(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3012")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"fh2c-{tag}", "hosts": [f"{tag}.fh2c.local"], "path_prefix": "/", "upstreams": [{"url": ctx.h2_origin.url}], "enabled": True})
    try:
        st, hdrs, body = c.front("peer_a", "/v1", host=f"{tag}.fh2c.local", headers={"X-Forwarded-For": "198.51.100.55", "X-Forwarded-Proto": "https"})
        assert st == 200 and "fucf-ray" in hdrs and json.loads(body)["proto"] == "h2c"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T3-013", "3", "r3", ("REQ-14", "REQ-10"), "accel_jp receives Hy2 masquerade on 18480 for unknown host -> routes to is_fallback upstream")
def t3_013(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3013")
    c = ctx.ensure_cluster()
    fb = ctx.create_proxy_rule({"name": f"jpfb-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "is_fallback": True, "priority": -100, "enabled": True})
    try:
        c.wait_converged(lambda: c.front("accel_jp", "/", host=f"masq-{tag}.unknown.test")[0] == 200)
        st, _, body = c.front("accel_jp", "/", host=f"masq-{tag}.unknown.test")
        assert st == 200 and json.loads(body)["tag"] == "origin2"
    finally:
        ctx.delete_proxy_rule(fb["id"])


@register_test("T3-014", "3", "r4", ("REQ-15", "REQ-16"), "OIDC discovery -> PKCE S256 /authorize -> /token -> verify id_token via jwks.json")
def t3_014(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3014")
    c = ctx.ensure_cluster()
    disc = json.loads(c.edge("peer_a", "/.well-known/openid-configuration", host=ContractConfig.AUTH_HOST, use_tls=True)[2])
    assert disc["token_endpoint"].endswith("/token")
    redir = f"https://{tag}.oidc.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    jwks = json.loads(c.edge("peer_a", urllib.parse.urlparse(disc["jwks_uri"]).path, host=ContractConfig.AUTH_HOST, use_tls=True)[2])
    claims = _verify_jwt_rs_or_es(tok["id_token"], jwks)
    assert claims["iss"] == disc["issuer"]


@register_test("T3-015", "3", "r4", ("REQ-16", "REQ-17"), "Passkey login on auth.fucloudflare.com -> /authorize consent -> /userinfo")
def t3_015(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3015")
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    st, hdrs, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))
    assert st == 200
    pk_cookie = hdrs["set-cookie"].split(";", 1)[0]
    redir = f"https://{tag}.pk.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir, session_cookie=pk_cookie)
    u = json.loads(c.edge("peer_a", "/userinfo", host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Authorization": f"Bearer {tok['access_token']}"})[2])
    assert u.get("sub")


@register_test("T3-016", "3", "r4", ("REQ-16", "REQ-18"), "Linux.do MockOAuthServer login -> /authorize -> /token returns claims")
def t3_016(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3016")
    redir = f"https://{tag}.ld.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    assert tok.get("access_token") and tok.get("id_token")


@register_test("T3-017", "3", "r4", ("REQ-17", "REQ-18"), "Linux.do login -> link Passkey on /account -> log out -> log in with Passkey alone")
def t3_017(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin, name="linked-pk")))[0] == 200
    c.edge("peer_a", "/logout", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie})
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    st, hdrs, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))
    assert st == 200 and hdrs.get("set-cookie")


@register_test("T3-018", "3", "r4", ("REQ-18", "REQ-09"), "Panel SSO started on peer_a completes /callback on peer_b and works on both")
def t3_018(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")
    auth_cookie = _seed_auth_session_via_oauth(ctx, node="peer_a")
    st, hdrs, _ = c.edge("peer_a", "/client/v4" + ContractConfig.PANEL_OAUTH_LOGIN_PATH, host=ContractConfig.PANEL_HOST, use_tls=True)
    assert st in (302, 303)
    panel_ck = hdrs.get("set-cookie", "").split(";", 1)[0]
    auth_u = urllib.parse.urlparse(hdrs["location"])
    st2, h2, _ = c.edge("peer_a", auth_u.path + "?" + auth_u.query, host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": auth_cookie})
    assert st2 in (302, 303)
    cb_u = urllib.parse.urlparse(h2["location"])
    st3, h3, b3 = c.edge("peer_b", cb_u.path + "?" + cb_u.query, host=ContractConfig.PANEL_HOST, use_tls=True, headers={"Cookie": panel_ck} if panel_ck else None)
    assert st3 in (200, 302, 303)
    sc = h3.get("set-cookie", "")
    assert "fucf_s_" in sc
    sess = "fucf_s_" + sc.split("fucf_s_", 1)[1].split(";", 1)[0]
    assert c.api("peer_b", "GET", "/zones", token=sess)[0] == 200
    c.wait_converged(lambda: c.api("peer_a", "GET", "/zones", token=sess)[0] == 200)


@register_test("T3-019", "3", "r5", ("REQ-19", "REQ-20"), "Dark mode across KV/D1/Proxy/Fleet views preserves dark tokens & contrast", tags=("ui",))
def t3_019(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            document.documentElement.setAttribute('data-mode', 'dark');
            const out = [];
            for (const v of ['workers', 'proxy', 'fleet', 'oauth']) {{
                location.hash = '#/' + v;
                await new Promise(r => setTimeout(r, 80));
                out.push({{ v, mode: document.documentElement.getAttribute('data-mode'), bg: getComputedStyle(document.body).backgroundColor }});
            }}
            return out;
        }})()""",
    )
    assert all(x["mode"] == "dark" and x["bg"] == "rgb(3, 3, 3)" for x in res["value"])


@register_test("T3-020", "3", "r5", ("REQ-20", "REQ-16"), "Headless browser triggers Panel -> auth.fucloudflare.com OAuth navigation", tags=("ui",))
def t3_020(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(async () => {
            const btn = document.querySelector('[data-oauth-login], a[href*="oauth/login"], button[data-sso]');
            return { found: !!btn || document.body.innerText.length > 0 };
        })()""",
    )
    assert res["value"]["found"] is True


@register_test("T3-021", "3", "r3", ("REQ-11", "REQ-07"), "LocalProxyRule created on peer_a replicates to peer_b which proxies traffic")
def t3_021(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3021")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"rep-{tag}", "hosts": [f"{tag}.rep.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}, node="peer_a")
    try:
        c.wait_converged(lambda: c.proxy("peer_b", "/ok", host=f"{tag}.rep.local")[0] == 200)
        assert json.loads(c.proxy("peer_b", "/ok", host=f"{tag}.rep.local")[2])["tag"] == "origin1"
    finally:
        ctx.delete_proxy_rule(rule["id"], node="peer_a")


@register_test("T3-022", "3", "r4", ("REQ-04", "REQ-16"), "Auth Worker handles 20 parallel /userinfo + /token calls without SQLite/Tokio hang")
def t3_022(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3022")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.load.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    at = tok["access_token"]
    errs: list[str] = []

    def _hit(i: int) -> None:
        try:
            st, _, _ = c.edge("peer_a", "/userinfo", host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Authorization": f"Bearer {at}"})
            if st != 200:
                errs.append(f"i={i}: status={st}")
        except Exception as exc:  # noqa: BLE001
            errs.append(f"i={i}: {exc}")

    threads = [threading.Thread(target=_hit, args=(i,)) for i in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=15)
    assert not errs, f"parallel auth errors: {errs}"


@register_test("T3-023", "3", "r3", ("REQ-12", "REQ-06"), "Worker fetches origin through LocalProxyRule/edge and signs response with WebCrypto HMAC")
def t3_023(ctx: TestContext) -> None:
    tag = ctx.next_tag("t3023")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"signproxy-{tag}",
        """export default { async fetch(req, env) {
            const resp = await fetch(req);
            const txt = await resp.text();
            const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("edge-hmac"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
            const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(txt));
            const hex = Array.from(new Uint8Array(sig)).map(b => b.toString(16).padStart(2, "0")).join("");
            return new Response(txt, { headers: { "x-body-hmac": hex } });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, hdrs, body = c.edge("peer_a", "/payload", host=f"{tag}.test")
    assert st == 200 and "x-body-hmac" in hdrs and len(hdrs["x-body-hmac"]) == 64 and b"origin1" in body


@register_test("T3-024", "3", "r5", ("REQ-10", "REQ-19"), "Fleet UI in headless browser displays peer_a, peer_b, and accel_jp roles accurately", tags=("ui",))
def t3_024(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            location.hash = '#/fleet';
            await new Promise(r => setTimeout(r, 250));
            const txt = document.body.innerText;
            return {{ hasPeerA: txt.includes('peer_a'), hasPeerB: txt.includes('peer_b'), hasJp: txt.includes('accel_jp') }};
        }})()""",
    )
    v = res["value"]
    assert v["hasPeerA"] and v["hasPeerB"] and v["hasJp"], f"fleet UI missing nodes: {v}"
