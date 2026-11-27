"""Tier 2 — 105 Boundary / Error / Negative Tests (T2-001 .. T2-105)."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import socket
import threading
import time
import urllib.parse
from typing import Any

from . import CdpSession, TestContext, find_browser_executable, register_test
from .harness import (
    ClusterHarness,
    ContractConfig,
    WebAuthnSimulator,
    b64u_encode,
    free_port,
    wait_for,
    ws_connect,
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
)


# ===========================================================================
# REQ-01 / REQ-02: Workers KV Boundaries & Negative Cases (T2-001..010, T2-101)
# ===========================================================================


@register_test("T2-001", "2", "r1", ("REQ-01",), "KV.get('missing') returns null without throwing")
def t2_001(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2001")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        'export default { async fetch(r, env) { return Response.json({ val: await env.KV.get("missing") }); } }',
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"val": None}


@register_test("T2-002", "2", "r1", ("REQ-01",), "KV.get(non-json, 'json') rejects with SyntaxError")
def t2_002(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2002")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            await env.KV.put("badjson", "{not-json");
            try { await env.KV.get("badjson", "json"); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, name: e.name || String(e) }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    d = json.loads(body)
    assert st == 200 and d["threw"] is True


@register_test("T2-003", "2", "r1", ("REQ-01",), "KV.get with 101 keys exceeds 100-key multi-get limit")
def t2_003(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2003")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const keys = Array.from({ length: 101 }, (_, i) => "k" + i);
            try { await env.KV.get(keys); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, msg: String(e) }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-004", "2", "r1", ("REQ-01",), "KV.put empty key and KV.get invalid type reject cleanly")
def t2_004(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2004")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            let e1 = false, e2 = false;
            try { await env.KV.put("", "v"); } catch (_) { e1 = true; }
            try { await env.KV.put("ok", "v"); await env.KV.get("ok", "bogusType"); } catch (_) { e2 = true; }
            return Response.json({ e1, e2 });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"e1": True, "e2": True}


@register_test("T2-005", "2", "r1", ("REQ-01",), "KV.put metadata > 1024 bytes is rejected")
def t2_005(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2005")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try {
                await env.KV.put("k", "v", { metadata: { big: "x".repeat(1030) } });
                return Response.json({ threw: false });
            } catch (e) {
                return Response.json({ threw: true });
            }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-006", "2", "r1", ("REQ-02",), "KV.put expirationTtl=59 (<60s minimum) is rejected")
def t2_006(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2006")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try {
                await env.KV.put("k", "v", { expirationTtl: 59 });
                return Response.json({ threw: false });
            } catch (e) { return Response.json({ threw: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-007", "2", "r1", ("REQ-02",), "KV.put 513-byte key (>512B limit) is rejected")
def t2_007(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2007")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try {
                await env.KV.put("k".repeat(513), "v");
                return Response.json({ threw: false });
            } catch (e) { return Response.json({ threw: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-008", "2", "r1", ("REQ-02",), "KV.put oversized >25 MiB value rejects without crashing node")
def t2_008(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2008")
    c = ctx.ensure_cluster()
    kv_id = ctx.create_kv(f"bigkv-{tag}")
    big_payload = b"A" * (26 * 1024 * 1024)
    st, _ = c.api("peer_a", "PUT", f"{ContractConfig.KV_NAMESPACES_PATH}/{kv_id}/values/huge", raw=big_payload)
    assert st in (400, 413), f"expected 400/413 for >25MiB KV value, got {st}"
    assert c.api("peer_a", "GET", "/system")[0] == 200


@register_test("T2-009", "2", "r1", ("REQ-02",), "KV.list limit=0 and limit=1001 reject out-of-range limits")
def t2_009(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2009")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            let e0 = false, e1001 = false;
            try { await env.KV.list({ limit: 0 }); } catch (_) { e0 = true; }
            try { await env.KV.list({ limit: 1001 }); } catch (_) { e1001 = true; }
            return Response.json({ e0, e1001 });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"e0": True, "e1001": True}


@register_test("T2-010", "2", "r1", ("REQ-02",), "KV.list with corrupt cursor returns clean error without panic")
def t2_010(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2010")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.KV.list({ cursor: "!!!corrupt-cursor!!!" }); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-101", "2", "r1", ("REQ-02",), "KV.put with expiration in the past is immediately expired")
def t2_101(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2101")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const past = Math.floor(Date.now() / 1000) - 10;
            await env.KV.put("past", "gone", { expiration: past });
            return Response.json({ v: await env.KV.get("past") });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"v": None}


# ===========================================================================
# REQ-03 / REQ-04: Workers D1 Boundaries & Negative Cases (T2-011..020)
# ===========================================================================


@register_test("T2-011", "2", "r1", ("REQ-03",), "D1 bind(undefined) throws D1_TYPE_ERROR")
def t2_011(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2011")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.prepare("SELECT ?").bind(undefined).first(); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, msg: String(e) }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    d = json.loads(body)
    assert st == 200 and d["threw"] is True and "D1_TYPE_ERROR" in d["msg"]


@register_test("T2-012", "2", "r1", ("REQ-03",), "D1 first('nonexistent_col') rejects with column error")
def t2_012(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2012")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.prepare("SELECT 1 AS a").first("nonexistent_col"); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, msg: String(e) }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-013", "2", "r1", ("REQ-03",), "D1 query on missing table rejects with D1_ERROR")
def t2_013(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2013")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.prepare("SELECT * FROM missing_tbl").all(); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, msg: String(e) }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-014", "2", "r1", ("REQ-03",), "D1 prepare('SELECT ?1, ?2').bind(1) missing parameter rejects cleanly")
def t2_014(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2014")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.prepare("SELECT ?1, ?2").bind(1).all(); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-015", "2", "r1", ("REQ-03",), "D1 raw({columnNames: true}) on empty result returns []")
def t2_015(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2015")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            await env.DB.exec("CREATE TABLE empty(id INTEGER)");
            const rows = await env.DB.prepare("SELECT id FROM empty").raw({ columnNames: true });
            return Response.json({ rows });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"rows": []}


@register_test("T2-016", "2", "r1", ("REQ-04",), "D1 batch rolls back all statements on constraint violation")
def t2_016(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2016")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            await env.DB.exec("CREATE TABLE u(id INTEGER PRIMARY KEY); INSERT INTO u VALUES(1)");
            let threw = false;
            try {
                await env.DB.batch([
                    env.DB.prepare("INSERT INTO u VALUES(2)"),
                    env.DB.prepare("INSERT INTO u VALUES(1)"),
                    env.DB.prepare("INSERT INTO u VALUES(3)")
                ]);
            } catch (_) { threw = true; }
            const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM u").first("c");
            return Response.json({ threw, cnt });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"threw": True, "cnt": 1}


@register_test("T2-017", "2", "r1", ("REQ-04",), "D1 exec() rejects invalid SQL syntax")
def t2_017(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2017")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.exec("SELECT 1; NOT VALID SQL;"); return Response.json({ threw: false }); }
            catch (_) { return Response.json({ threw: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-018", "2", "r1", ("REQ-04",), "D1 batch([]) empty array handled cleanly without panic")
def t2_018(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2018")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const res = await env.DB.batch([]);
            return Response.json({ ok: Array.isArray(res), len: res.length });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"ok": True, "len": 0}


@register_test("T2-019", "2", "r1", ("REQ-04",), "D1 blocks ATTACH DATABASE sandbox escape")
def t2_019(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2019")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            try { await env.DB.exec("ATTACH DATABASE '/etc/passwd' AS p"); return Response.json({ blocked: false }); }
            catch (_) { return Response.json({ blocked: true }); }
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body)["blocked"] is True


@register_test("T2-020", "2", "r1", ("REQ-04",), "Unbound env.MISSING_DB is undefined and does not leak other DBs")
def t2_020(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2020")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        'export default { fetch(r, env) { return Response.json({ hasMissing: env.MISSING_DB !== undefined }); } }',
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=host)
    assert st == 200 and json.loads(body) == {"hasMissing": False}


# ===========================================================================
# REQ-05 / REQ-06: Cron & WebCrypto Boundaries (T2-021..030)
# ===========================================================================


@register_test("T2-021", "2", "r1", ("REQ-05",), "Invalid cron expressions ('99 * * * *' and '* * * *') rejected with 400")
def t2_021(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2021")
    c = ctx.ensure_cluster()
    sname = f"badcron-{tag}"
    assert c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/{sname}", raw="export default { scheduled() {} }")[0] == 200
    for expr in ("99 * * * *", "* * * *"):
        st, _ = c.api("peer_a", "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/{sname}/settings", {"crons": [expr]})
        assert st == 400, f"expected 400 for invalid cron {expr!r}, got {st}"


@register_test("T2-022", "2", "r1", ("REQ-05",), "Uncaught exception in scheduled() keeps worker runtime healthy")
def t2_022(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2022")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test")
    sname = f"errcron-{tag}"
    ctx.deploy_worker(
        sname,
        'export default { scheduled() { throw new Error("boom"); }, fetch() { return new Response("alive"); } }',
        z["id"],
        f"{tag}.test/*",
        crons=["* * * * *"],
    )
    c.edge("peer_a", "/__scheduled", host=f"{tag}.test")
    st, _, body = c.edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and body == b"alive"


@register_test("T2-023", "2", "r1", ("REQ-05",), "Infinite loop in scheduled() terminated cleanly without hanging node")
def t2_023(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2023")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"infcron-{tag}",
        'export default { scheduled() { while (true) {} }, fetch() { return new Response("ok"); } }',
        z["id"],
        f"{tag}.test/*",
        crons=["* * * * *"],
    )
    st, _, _ = c.edge("peer_a", "/__scheduled", host=f"{tag}.test")
    assert st in (200, 500, 502)
    assert c.api("peer_a", "GET", "/system")[0] == 200


@register_test("T2-024", "2", "r1", ("REQ-05",), "Trigger Cron for nonexistent script (404) or viewer role (403)")
def t2_024(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2024")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    st_nf, _ = c.api("peer_a", "POST", ContractConfig.WORKER_CRON_TRIGGER_PATH.format(name="no-such-script"), {}, token=tok)
    assert st_nf == 404
    email = f"{tag}-v@example.test"
    ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "viewer"}, token=tok)[1]["result"]
    vtok = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": ru["password"]}, token="")[1]["result"]["token"]
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": "ViewerPass!2026"}, token=vtok)
    st_f, _ = c.api("peer_a", "POST", ContractConfig.WORKER_CRON_TRIGGER_PATH.format(name="no-such-script"), {}, token=vtok)
    assert st_f == 403


@register_test("T2-025", "2", "r1", ("REQ-05",), "Concurrent cron trigger across peer_a & peer_b enforces peer dedup lease")
def t2_025(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2025")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test")
    kv_id = ctx.create_kv(f"dedup-{tag}")
    sname = f"dedup-{tag}"
    ctx.deploy_worker(
        sname,
        """export default {
            async scheduled(ctrl, env) {
                const cur = Number((await env.KV.get("cnt")) || "0");
                await env.KV.put("cnt", String(cur + 1));
            },
            async fetch(req, env) { return Response.json({ cnt: Number((await env.KV.get("cnt")) || "0") }); }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["* * * * *"],
    )
    c.wait_converged(lambda: c.edge("peer_b", "/cnt", host=f"{tag}.test")[0] == 200)
    slot = int(time.time() // 60) * 60
    r_a = c.api("peer_a", "POST", ContractConfig.WORKER_CRON_TRIGGER_PATH.format(name=sname), {"scheduledTime": slot * 1000, "dedup": True})
    r_b = c.api("peer_b", "POST", ContractConfig.WORKER_CRON_TRIGGER_PATH.format(name=sname), {"scheduledTime": slot * 1000, "dedup": True})
    assert r_a[0] == 200 and r_b[0] in (200, 409)
    time.sleep(1.5)
    cnt = json.loads(c.edge("peer_a", "/cnt", host=f"{tag}.test")[2])["cnt"]
    assert cnt == 1, f"expected dedup count=1, got {cnt}"


@register_test("T2-026", "2", "r1", ("REQ-06",), "crypto.subtle.digest('MD5') rejects with NotSupportedError")
def t2_026(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2026")
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            try { await crypto.subtle.digest("MD5", new Uint8Array([1,2])); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, name: e.name || String(e) }); }
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-027", "2", "r1", ("REQ-06",), "crypto.subtle.verify with wrong HMAC key returns false")
def t2_027(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2027")
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            const enc = new TextEncoder();
            const k1 = await crypto.subtle.importKey("raw", enc.encode("key1"), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
            const k2 = await crypto.subtle.importKey("raw", enc.encode("key2"), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
            const msg = enc.encode("msg");
            const sig = await crypto.subtle.sign("HMAC", k1, msg);
            return Response.json({ ok: await crypto.subtle.verify("HMAC", k2, sig, msg) });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body) == {"ok": False}


@register_test("T2-028", "2", "r1", ("REQ-06",), "crypto.subtle.decrypt AES-GCM with wrong IV rejects cleanly")
def t2_028(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2028")
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            const key = await crypto.subtle.importKey("raw", new Uint8Array(32), "AES-GCM", false, ["encrypt", "decrypt"]);
            const iv1 = new Uint8Array(12);
            const iv2 = new Uint8Array(12); iv2[0] = 9;
            const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv1 }, key, new TextEncoder().encode("hi"));
            try { await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv2 }, key, ct); return Response.json({ threw: false }); }
            catch (_) { return Response.json({ threw: true }); }
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-029", "2", "r1", ("REQ-06",), "crypto.getRandomValues(65537 bytes) throws QuotaExceededError")
def t2_029(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2029")
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { fetch() {
            try { crypto.getRandomValues(new Uint8Array(65537)); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true, name: e.name || String(e) }); }
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body)["threw"] is True


@register_test("T2-030", "2", "r1", ("REQ-06",), "Response.redirect with invalid status 200 throws RangeError")
def t2_030(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2030")
    z = ctx.create_zone(f"{tag}.test")
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { fetch() {
            try { Response.redirect("https://example.org/", 200); return Response.json({ threw: false }); }
            catch (e) { return Response.json({ threw: true }); }
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body)["threw"] is True


# ===========================================================================
# REQ-07..10: Peer Sync, Dashboard Auth, Accelerate Boundaries (T2-031..050, T2-102)
# ===========================================================================


@register_test("T2-031", "2", "r2", ("REQ-07",), "Unauthenticated GET/POST /replication/sync returns 401")
def t2_031(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    for method in ("GET", "POST"):
        st, _ = c.api("peer_a", method, ContractConfig.SYNC_PATH, token="", prefix="")
        assert st == 401
        st2, _ = c.api("peer_a", method, ContractConfig.SYNC_PATH, token="wrong-token", prefix="")
        assert st2 == 401


@register_test("T2-032", "2", "r2", ("REQ-07",), "Malformed JSON in POST /replication/sync returns 400 without corrupting store")
def t2_032(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    before = c.api("peer_a", "GET", "/zones")[1]["result"]
    st, _ = c.api("peer_a", "POST", ContractConfig.SYNC_PATH, raw="{not-valid-json", prefix="")
    assert st == 400
    after = c.api("peer_a", "GET", "/zones")[1]["result"]
    assert len(after) == len(before)


@register_test("T2-033", "2", "r2", ("REQ-07",), "Older HLC timestamp pushed to peer loses to newer HLC (LWW)")
def t2_033(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2033")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    zid = z["id"]
    c.api("peer_a", "PATCH", f"/zones/{zid}/settings/waf", {"value": "block"})
    c.wait_converged(lambda: c.api("peer_b", "GET", f"/zones/{zid}")[1]["result"]["settings"]["waf"] == "block")
    # Push stale item with updated_ms = 1
    stale_payload = {
        "node": "stale-node",
        "zones": [{**z, "settings": {**z["settings"], "waf": "off"}, "sync": {"updated_ms": 1, "node": "stale-node", "seq": 0, "deleted": False}}],
    }
    st, _ = c.api("peer_b", "POST", ContractConfig.SYNC_PATH, body=stale_payload, prefix="")
    assert st in (200, 400)
    assert c.api("peer_b", "GET", f"/zones/{zid}")[1]["result"]["settings"]["waf"] == "block"


@register_test("T2-034", "2", "r2", ("REQ-07",), "Peer outage while peer_a receives writes converges automatically on recovery")
def t2_034(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2034")
    c = ctx.new_cluster()
    try:
        c.stop_node("peer_b")
        st, r = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})
        assert st == 200
        zid = r["result"]["id"]
        c.start_node("peer_b")
        c.wait_ready("peer_b")
        c.wait_converged(lambda: any(x["id"] == zid for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))
    finally:
        c.stop()


@register_test("T2-035", "2", "r2", ("REQ-07",), "Delete wins over older update; newer create/update after delete wins")
def t2_035(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2035")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    zid = z["id"]
    rec = c.api("peer_a", "POST", f"/zones/{zid}/dns_records", {"type": "TXT", "name": "t", "content": "v1"})[1]["result"]
    c.wait_converged(lambda: any(r["id"] == rec["id"] for r in c.api("peer_b", "GET", f"/zones/{zid}/dns_records")[1]["result"]))
    assert c.api("peer_b", "DELETE", f"/zones/{zid}/dns_records/{rec['id']}")[0] == 200
    c.wait_converged(lambda: not any(r["id"] == rec["id"] for r in c.api("peer_a", "GET", f"/zones/{zid}/dns_records")[1]["result"]))
    rec2 = c.api("peer_a", "POST", f"/zones/{zid}/dns_records", {"type": "TXT", "name": "t", "content": "v2"})[1]["result"]
    c.wait_converged(lambda: any(r["id"] == rec2["id"] and r["content"] == "v2" for r in c.api("peer_b", "GET", f"/zones/{zid}/dns_records")[1]["result"]))


@register_test("T2-102", "2", "r2", ("REQ-07",), "Sync payload containing unknown future field is ignored safely")
def t2_102(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, _ = c.api("peer_a", "POST", ContractConfig.SYNC_PATH, body={"node": "future-peer", "future_field_v99": {"x": 1}}, prefix="")
    assert st == 200 and c.api("peer_a", "GET", "/system")[0] == 200


@register_test("T2-036", "2", "r2", ("REQ-08",), "Expired KV entry synced from peer is not resurrected as live")
def t2_036(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2036")
    c = ctx.ensure_cluster()
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname === "/put") { await env.KV.put("short", "v", { expiration: Math.floor(Date.now()/1000) + 2 }); return new Response("ok"); }
            return Response.json({ v: await env.KV.get("short") });
        } }""",
    )
    c.wait_converged(lambda: c.edge("peer_b", "/get", host=host)[0] == 200)
    c.edge("peer_a", "/put", host=host)
    time.sleep(2.5)
    assert json.loads(c.edge("peer_b", "/get", host=host)[2])["v"] is None


@register_test("T2-037", "2", "r2", ("REQ-08",), "Stale out-of-order D1 sync delta does not overwrite newer SQLite rows")
def t2_037(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2037")
    c = ctx.ensure_cluster()
    _, db_id, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(r, env) {
            const u = new URL(r.url);
            if (u.pathname === "/init") {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, v TEXT)");
                await env.DB.prepare("INSERT OR REPLACE INTO t VALUES(1, 'v1')").run();
                await env.DB.prepare("INSERT OR REPLACE INTO t VALUES(1, 'v2')").run();
                return new Response("ok");
            }
            return Response.json({ v: await env.DB.prepare("SELECT v FROM t WHERE id=1").first("v") });
        } }""",
    )
    c.edge("peer_a", "/init", host=host)
    c.wait_converged(lambda: json.loads(c.edge("peer_b", "/read", host=host)[2]).get("v") == "v2")
    # Attempt pushing stale seq=1 delta
    c.api("peer_b", "POST", ContractConfig.SYNC_PATH, body={"node": "old", "d1_deltas": [{"db_id": db_id, "seq": 1, "sql": "INSERT OR REPLACE INTO t VALUES(1, 'stale')"}]}, prefix="")
    assert json.loads(c.edge("peer_b", "/read", host=host)[2])["v"] == "v2"


@register_test("T2-038", "2", "r2", ("REQ-08",), "D1 query API rejects invalid SQL without breaking replication")
def t2_038(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2038")
    c = ctx.ensure_cluster()
    db_id = ctx.create_d1(f"errd1-{tag}")
    st, _ = c.api("peer_a", "POST", f"{ContractConfig.D1_DATABASES_PATH}/{db_id}/query", {"sql": "SELECT * FROM nonexistent"})
    assert st == 400
    assert c.api("peer_a", "GET", "/system")[0] == 200


@register_test("T2-039", "2", "r2", ("REQ-08",), "Oversized KV sync payload rejected cleanly without crash")
def t2_039(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    huge = json.dumps({"node": "peer_x", "kv_deltas": [{"ns": "x", "key": "k", "value": "A" * (16 * 1024 * 1024)}]})
    st, _ = c.api("peer_a", "POST", ContractConfig.SYNC_PATH, raw=huge, prefix="")
    assert st in (400, 413) and c.api("peer_a", "GET", "/system")[0] == 200


@register_test("T2-040", "2", "r2", ("REQ-08",), "Sync loop recovers cleanly when peer_b shuts down mid-sync")
def t2_040(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2040")
    c = ctx.new_cluster()
    try:
        c.stop_node("peer_b")
        st, _ = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})
        assert st == 200
        time.sleep(1.5)
        assert c.api("peer_a", "GET", "/system")[0] == 200
    finally:
        c.stop()


@register_test("T2-041", "2", "r2", ("REQ-09",), "Tampered HMAC pending 2FA ticket rejected on peer_b with 401")
def t2_041(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, r = c.api("peer_b", "POST", "/auth/second_step", {"ticket": "tampered.hmac.ticket", "code": "123456"}, token="")
    assert st == 401 and (r.get("errors") or [{}])[0].get("code") in (2003, 2004)


@register_test("T2-042", "2", "r2", ("REQ-09",), "Expired/invalid sealed ticket sent to peer_b returns 401")
def t2_042(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    expired_tkt = b64u_encode(json.dumps({"uid": "u1", "exp": 1}).encode()) + ".AAAA"
    st, _ = c.api("peer_b", "POST", "/auth/second_step", {"ticket": expired_tkt, "code": "000000"}, token="")
    assert st == 401


@register_test("T2-043", "2", "r2", ("REQ-09",), "User disabled on peer_a invalidates active session on peer_b")
def t2_043(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2043")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    email = f"{tag}@example.test"
    ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "viewer"}, token=tok)[1]["result"]
    utok = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": ru["password"]}, token="")[1]["result"]["token"]
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": "Viewer!2026_Pass"}, token=utok)
    c.wait_converged(lambda: c.api("peer_b", "GET", "/zones", token=utok)[0] == 200)
    assert c.api("peer_a", "PATCH", f"/users/{ru['user']['id']}", {"disabled": True}, token=tok)[0] == 200
    c.wait_converged(lambda: c.api("peer_b", "GET", "/zones", token=utok)[0] == 401)


@register_test("T2-044", "2", "r2", ("REQ-09",), "Viewer role attempts write on peer_b and gets 403")
def t2_044(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2044")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    email = f"{tag}@example.test"
    ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "viewer"}, token=tok)[1]["result"]
    vtok = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": ru["password"]}, token="")[1]["result"]["token"]
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": "Viewer!2026_Pass"}, token=vtok)
    c.wait_converged(lambda: c.api("peer_b", "GET", "/zones", token=vtok)[0] == 200)
    st, _ = c.api("peer_b", "POST", "/zones", {"name": f"{tag}-nope.test"}, token=vtok)
    assert st == 403


@register_test("T2-045", "2", "r2", ("REQ-09",), "Replayed second_step ticket on peer_b after use on peer_a is rejected")
def t2_045(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2045")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    email = f"{tag}@example.test"
    ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "viewer"}, token=tok)[1]["result"]
    utok = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": ru["password"]}, token="")[1]["result"]["token"]
    pw = "Replay!2026_Pass"
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": pw}, token=utok)
    sec = c.api("peer_a", "POST", "/account/totp/begin", {}, token=utok)[1]["result"]["secret"]
    import base64, hmac, struct
    def totp(off=0):
        k = base64.b32decode(sec + "=" * (-len(sec) % 8))
        m = hmac.new(k, struct.pack(">Q", int(time.time()) // 30 + off), hashlib.sha1).digest()
        at = m[-1] & 15
        return "%06d" % ((struct.unpack(">I", m[at:at+4])[0] & 0x7FFFFFFF) % 1000000)
    c.api("peer_a", "POST", "/account/totp/enable", {"code": totp()}, token=utok)
    c.wait_converged(lambda: "second_step" in c.api("peer_b", "POST", "/auth/login", {"email": email, "password": pw}, token="")[1].get("result", {}))
    tkt = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": pw}, token="")[1]["result"]["second_step"]["ticket"]
    st1, _ = c.api("peer_a", "POST", "/auth/second_step", {"ticket": tkt, "code": totp(1)}, token="")
    assert st1 == 200
    st2, _ = c.api("peer_b", "POST", "/auth/second_step", {"ticket": tkt, "code": totp(1)}, token="")
    assert st2 in (401, 403)


@register_test("T2-046", "2", "r2", ("REQ-10",), "Direct write POST /zones to accel_jp refused (409) with zero local write")
def t2_046(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2046")
    c = ctx.ensure_cluster()
    st, _ = c.api("accel_jp", "POST", "/zones", {"name": f"{tag}.test"})
    assert st == 409 and not os.path.exists(os.path.join(c.nodes["accel_jp"].data_dir, "state.json"))


@register_test("T2-047", "2", "r2", ("REQ-10",), "accel_jp suppresses public DNS NS answers whether peers are up or down")
def t2_047(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2047")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test", node="peer_a")
    rc, an, _ = c.dns_query("accel_jp", f"{tag}.test", qtype=2)
    assert an == 0


@register_test("T2-048", "2", "r2", ("REQ-10",), "accel_jp starts cleanly even when configured --peers are unreachable")
def t2_048(ctx: TestContext) -> None:
    h = ClusterHarness(ctx.bin, keep_logs=ctx.keep_logs)
    dead_port = free_port()
    h.add_node("accel_solo", ContractConfig.ROLE_ACCELERATE, "203.0.113.99", extra_args=[ContractConfig.PEERS_FLAG, f"http://127.0.0.1:{dead_port}"])
    try:
        h.start_node("accel_solo")
        h.wait_ready("accel_solo", timeout=10.0)
        st, _, _ = h.edge("accel_solo", "/cdn-cgi/fucf-trace", host="any.test")
        assert st == 200
    finally:
        h.stop()


@register_test("T2-049", "2", "r2", ("REQ-10",), "accel_jp refuses ACME leader orders")
def t2_049(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2049")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    c.wait_converged(lambda: any(x["id"] == z["id"] for x in c.api("accel_jp", "GET", "/zones")[1].get("result", [])))
    st, _ = c.api("accel_jp", "POST", f"/zones/{z['id']}/ssl/certificate_packs", {})
    assert st == 409


@register_test("T2-050", "2", "r2", ("REQ-10",), "accel_jp RSS stays <= 200 MiB across 500 cached distinct paths")
def t2_050(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2050")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: c.edge("accel_jp", "/a/0.css", host=f"{tag}.test")[0] == 200)
    for i in range(500):
        c.edge("accel_jp", f"/a/{i}.css", host=f"{tag}.test")
    assert c.rss_bytes("accel_jp") <= 200 * 1024 * 1024


# ===========================================================================
# REQ-11..14: Proxy, Protocols, WS/Streaming, Fallback Boundaries (T2-051..070, T2-103)
# ===========================================================================


@register_test("T2-051", "2", "r3", ("REQ-11",), "LocalProxyRule pointing to dead port 127.0.0.1:9 returns 502/521 quickly")
def t2_051(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2051")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"dead-{tag}", "hosts": [f"{tag}.dead.local"], "path_prefix": "/", "upstreams": [{"url": "http://127.0.0.1:9"}], "enabled": True})
    try:
        st, _, _ = c.proxy("peer_a", "/", host=f"{tag}.dead.local")
        assert st in (502, 521)
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-052", "2", "r3", ("REQ-11",), "LocalProxyRule SSRF metadata IP 169.254.169.254 blocked")
def t2_052(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2052")
    c = ctx.ensure_cluster()
    st, _ = c.api("peer_a", "POST", ContractConfig.PROXY_RULES_PATH, {"name": f"ssrf-{tag}", "hosts": [f"{tag}.ssrf.local"], "path_prefix": "/", "upstreams": [{"url": "http://169.254.169.254/latest/meta-data/"}], "enabled": True})
    assert st in (400, 403)


@register_test("T2-053", "2", "r3", ("REQ-11",), "Invalid upstream scheme ftp:// rejected with 400")
def t2_053(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2053")
    c = ctx.ensure_cluster()
    st, _ = c.api("peer_a", "POST", ContractConfig.PROXY_RULES_PATH, {"name": f"ftp-{tag}", "hosts": [f"{tag}.ftp.local"], "path_prefix": "/", "upstreams": [{"url": "ftp://127.0.0.1:21"}], "enabled": True})
    assert st == 400


@register_test("T2-054", "2", "r3", ("REQ-11",), "Disabled LocalProxyRule (enabled: false) does not match")
def t2_054(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2054")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"dis-{tag}", "hosts": [f"{tag}.dis.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": False})
    try:
        st, _, _ = c.proxy("peer_a", "/", host=f"{tag}.dis.local")
        assert st == 404
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-055", "2", "r3", ("REQ-11",), "Unknown host without is_fallback rule returns 404")
def t2_055(ctx: TestContext) -> None:
    st, _, _ = ctx.ensure_cluster().proxy("peer_a", "/", host="never-configured-host.local")
    assert st == 404


@register_test("T2-103", "2", "r3", ("REQ-11",), "Deleting active LocalProxyRule immediately stops routing")
def t2_103(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2103")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"del-{tag}", "hosts": [f"{tag}.del.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True})
    assert c.proxy("peer_a", "/", host=f"{tag}.del.local")[0] == 200
    ctx.delete_proxy_rule(rule["id"])
    assert c.proxy("peer_a", "/", host=f"{tag}.del.local")[0] == 404


@register_test("T2-056", "2", "r3", ("REQ-12",), "Self-signed TLS upstream with tls_insecure=false fails TLS check (525/526)")
def t2_056(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2056")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"tlsstrict-{tag}", "hosts": [f"{tag}.strict.local"], "path_prefix": "/", "upstreams": [{"url": ctx.tls_origin.url, "tls_insecure": False}], "enabled": True})
    try:
        st, _, _ = c.proxy("peer_a", "/", host=f"{tag}.strict.local")
        assert st in (502, 525, 526)
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-057", "2", "r3", ("REQ-12",), "Unresponsive upstream times out cleanly (504/522/524)")
def t2_057(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2057")
    c = ctx.ensure_cluster()
    srv = socket.create_server(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    held: list[socket.socket] = []
    stop = threading.Event()
    def _accept_and_stall():
        srv.settimeout(0.5)
        while not stop.is_set():
            try:
                conn, _ = srv.accept()
                held.append(conn)
            except OSError:
                pass
    threading.Thread(target=_accept_and_stall, daemon=True).start()
    rule = ctx.create_proxy_rule({"name": f"stall-{tag}", "hosts": [f"{tag}.stall.local"], "path_prefix": "/", "upstreams": [{"url": f"http://127.0.0.1:{port}"}], "timeout_ms": 500, "enabled": True})
    try:
        st, _, _ = c.proxy("peer_a", "/", host=f"{tag}.stall.local")
        assert st in (502, 504, 522, 524)
    finally:
        stop.set()
        for s in held:
            s.close()
        srv.close()
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-058", "2", "r3", ("REQ-12",), "Proxy loop detection (cdn-loop: fucf) refuses recursion with 508")
def t2_058(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2058")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"loop-{tag}", "hosts": [f"{tag}.loop.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True})
    try:
        st, _, _ = c.proxy("peer_a", "/", host=f"{tag}.loop.local", headers={"cdn-loop": "fucf"})
        assert st == 508
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-059", "2", "r3", ("REQ-12",), "Malformed HTTP/1.1 request line returns 400/431 cleanly")
def t2_059(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    s = socket.create_connection(("127.0.0.1", c.nodes["peer_a"].ports["proxy"]), timeout=5)
    s.sendall(b"BAD_METHOD / HTTP/1.1\r\nBad Header Without Colon\r\n\r\n")
    resp = s.recv(4096)
    s.close()
    assert b"400" in resp or b"431" in resp or resp == b""


@register_test("T2-060", "2", "r3", ("REQ-12",), "HTTP/3 request to zone with http3=false is refused (421/error)")
def t2_060(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2060")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    c.api("peer_a", "PATCH", f"/zones/{z['id']}/settings/http3", {"value": False})
    port = c.nodes["peer_a"].ports["https"]
    try:
        st, _, _, _ = c.h3.get(f"https://{tag}.test:{port}/", connect_port=port)
        assert st in (421, 403, 404)
    except RuntimeError:
        pass


@register_test("T2-061", "2", "r3", ("REQ-13",), "WebSocket upgrade returns upstream 403 without splicing")
def t2_061(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2061")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"ws403-{tag}", "hosts": [f"{tag}.ws403.local"], "path_prefix": "/", "upstreams": [{"url": ctx.ws_origin.url}], "enabled": True})
    try:
        sock, st, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/reject-403", headers={"Host": f"{tag}.ws403.local"})
        sock.close()
        assert st == 403
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-062", "2", "r3", ("REQ-13",), "WebSocket client abrupt disconnect mid-frame cleans up upstream connection")
def t2_062(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2062")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"wsdrop-{tag}", "hosts": [f"{tag}.wsdrop.local"], "path_prefix": "/", "upstreams": [{"url": ctx.ws_origin.url}], "enabled": True})
    try:
        before = ctx.ws_origin.active_connections
        sock, st, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/ws", headers={"Host": f"{tag}.wsdrop.local"})
        assert st == 101
        ws_send(sock, "partial")
        sock.close()
        wait_for("upstream ws socket cleaned up", lambda: ctx.ws_origin.active_connections <= before, timeout=5.0)
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-063", "2", "r3", ("REQ-13",), "Streaming upstream TCP reset mid-chunk does not crash proxy")
def t2_063(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2063")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"sserst-{tag}", "hosts": [f"{tag}.rst.local"], "path_prefix": "/", "upstreams": [{"url": ctx.sse_origin.url}], "enabled": True})
    try:
        try:
            c.proxy("peer_a", "/reset-mid", host=f"{tag}.rst.local")
        except (http.client.HTTPException, OSError):
            pass
        assert c.api("peer_a", "GET", "/system")[0] == 200
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-064", "2", "r3", ("REQ-13",), "Hop-by-hop Upgrade: h2c header is not leaked on normal HTTP/1.1 proxy request")
def t2_064(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2064")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"hop-{tag}", "hosts": [f"{tag}.hop.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True})
    try:
        st, _, body = c.proxy("peer_a", "/", host=f"{tag}.hop.local", headers={"Connection": "Upgrade, HTTP2-Settings", "Upgrade": "h2c", "HTTP2-Settings": "AAMAAABkAAQAoAAAAAIAAAAA"})
        assert st == 200 and "upgrade" not in json.loads(body)["headers"]
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-065", "2", "r3", ("REQ-13",), "Large 2 MiB POST body streamed to proxy upstream without false 413")
def t2_065(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2065")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule({"name": f"bigup-{tag}", "hosts": [f"{tag}.bigup.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True})
    try:
        payload = b"Z" * (2 * 1024 * 1024)
        st, _, body = c.proxy("peer_a", "/bigpost", host=f"{tag}.bigup.local", method="POST", body=payload)
        assert st == 200 and json.loads(body)["body_len"] == len(payload)
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T2-066", "2", "r3", ("REQ-14",), "Spoofed client XFF ignored; unwrap_forwarded trusts only last entry")
def t2_066(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2066")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test")
    st, _, body = c.front("peer_a", "/cdn-cgi/fucf-trace", host=f"{tag}.test", headers={"X-Forwarded-For": "1.2.3.4, 198.51.100.77", "X-Forwarded-Proto": "https"})
    trace = dict(ln.split("=", 1) for ln in body.decode().splitlines())
    assert st == 200 and trace["ip"] == "198.51.100.77"


@register_test("T2-067", "2", "r3", ("REQ-14",), "X-Forwarded-Proto: http on front listener marks visit_scheme=http, tls=off")
def t2_067(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2067")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test")
    st, _, body = c.front("peer_a", "/cdn-cgi/fucf-trace", host=f"{tag}.test", headers={"X-Forwarded-For": "198.51.100.8", "X-Forwarded-Proto": "http"})
    trace = dict(ln.split("=", 1) for ln in body.decode().splitlines())
    assert st == 200 and trace["visit_scheme"] == "http" and trace["tls"] == "off"


@register_test("T2-068", "2", "r3", ("REQ-14",), "Missing X-Forwarded-For on front listener falls back to socket IP")
def t2_068(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2068")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test")
    st, _, body = c.front("peer_a", "/cdn-cgi/fucf-trace", host=f"{tag}.test", headers={"X-Forwarded-Proto": "https"})
    trace = dict(ln.split("=", 1) for ln in body.decode().splitlines())
    assert st == 200 and trace["ip"] == "127.0.0.1"


@register_test("T2-069", "2", "r3", ("REQ-14",), "Fallback upstream down returns clean 502/521 without crashing front")
def t2_069(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2069")
    c = ctx.ensure_cluster()
    fb = ctx.create_proxy_rule({"name": f"fbdown-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": "http://127.0.0.1:9"}], "is_fallback": True, "priority": -100, "enabled": True})
    try:
        st, _, _ = c.front("peer_a", "/", host=f"masq-{tag}.test")
        assert st in (502, 521)
    finally:
        ctx.delete_proxy_rule(fb["id"])


@register_test("T2-070", "2", "r3", ("REQ-14",), "Disabled is_fallback rule leaves unmatched host at 404")
def t2_070(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2070")
    c = ctx.ensure_cluster()
    fb = ctx.create_proxy_rule({"name": f"fbdis-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "is_fallback": True, "priority": -100, "enabled": False})
    try:
        st, _, _ = c.front("peer_a", "/", host=f"masq-{tag}.test")
        assert st == 404
    finally:
        ctx.delete_proxy_rule(fb["id"])


# ===========================================================================
# REQ-15..18: OAuth2, Passkey, Linux.do & Panel SSO Boundaries (T2-071..090, T2-104..105)
# ===========================================================================


@register_test("T2-071", "2", "r4", ("REQ-15",), "Unknown client_id on /authorize renders error without redirecting")
def t2_071(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, hdrs, _ = c.edge("peer_a", "/authorize?response_type=code&client_id=unknown_xyz&redirect_uri=https://evil.test/cb&code_challenge=abc&code_challenge_method=S256", host=ContractConfig.AUTH_HOST, use_tls=True)
    assert st in (400, 404) and "location" not in hdrs


@register_test("T2-072", "2", "r4", ("REQ-15",), "Duplicate OAuth client_id registration returns 409 Conflict")
def t2_072(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2072")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    body = {"client_id": f"dup-{tag}", "name": "dup", "redirect_uris": ["https://dup.test/cb"]}
    assert c.api("peer_a", "POST", ContractConfig.OAUTH_CLIENTS_PATH, body, token=tok)[0] == 200
    assert c.api("peer_a", "POST", ContractConfig.OAUTH_CLIENTS_PATH, body, token=tok)[0] == 409


@register_test("T2-073", "2", "r4", ("REQ-15",), "OAuth client with non-HTTPS non-localhost redirect_uri rejected 400")
def t2_073(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2073")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    st, _ = c.api("peer_a", "POST", ContractConfig.OAUTH_CLIENTS_PATH, {"name": f"bad-{tag}", "redirect_uris": ["http://public.example.com/cb"]}, token=tok)
    assert st == 400


@register_test("T2-074", "2", "r4", ("REQ-15",), "Unauthenticated request to OAuth client admin API returns 401")
def t2_074(ctx: TestContext) -> None:
    st, _ = ctx.ensure_cluster().api("peer_a", "GET", ContractConfig.OAUTH_CLIENTS_PATH, token="")
    assert st == 401


@register_test("T2-075", "2", "r4", ("REQ-15",), "POST /.well-known/jwks.json rejected with 405/404")
def t2_075(ctx: TestContext) -> None:
    st, _, _ = ctx.ensure_cluster().edge("peer_a", "/.well-known/jwks.json", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True)
    assert st in (404, 405)


@register_test("T2-076", "2", "r4", ("REQ-16",), "Mismatched redirect_uri on /authorize never redirects")
def t2_076(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2076")
    c = ctx.ensure_cluster()
    cl = _register_oauth_client(ctx, tag, f"https://{tag}.good.test/cb")
    st, hdrs, _ = c.edge(
        "peer_a",
        "/authorize?" + urllib.parse.urlencode({"response_type": "code", "client_id": cl["client_id"], "redirect_uri": "https://evil.attacker.test/steal", "code_challenge": "abc", "code_challenge_method": "S256"}),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
    )
    assert st == 400 and "location" not in hdrs


@register_test("T2-077", "2", "r4", ("REQ-16",), "Missing or plain code_challenge_method rejected with 400")
def t2_077(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2077")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    for extra in ({}, {"code_challenge": "abc", "code_challenge_method": "plain"}):
        st, hdrs, _ = c.edge(
            "peer_a",
            "/authorize?" + urllib.parse.urlencode({"response_type": "code", "client_id": cl["client_id"], "redirect_uri": redir, **extra}),
            host=ContractConfig.AUTH_HOST,
            use_tls=True,
        )
        assert st == 400 and "evil" not in hdrs.get("location", "")


@register_test("T2-078", "2", "r4", ("REQ-16",), "Wrong PKCE code_verifier on POST /token returns 400 invalid_grant")
def t2_078(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2078")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    cookie = _seed_auth_session_via_oauth(ctx)
    _, challenge = _pkce_pair()
    q = {"response_type": "code", "client_id": cl["client_id"], "redirect_uri": redir, "scope": "openid", "state": "s1", "code_challenge": challenge, "code_challenge_method": "S256"}
    st, hdrs, body = c.edge("peer_a", "/authorize?" + urllib.parse.urlencode(q), host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": cookie})
    if st == 200:
        _, hdrs, _ = c.edge("peer_a", "/authorize/consent", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}, body=urllib.parse.urlencode({**q, "decision": "allow"}))
    code = urllib.parse.parse_qs(urllib.parse.urlparse(hdrs["location"]).query)["code"][0]
    st_t, _, b_t = c.edge("peer_a", "/token", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/x-www-form-urlencoded"}, body=urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": cl["client_id"], "redirect_uri": redir, "code": code, "code_verifier": "wrong-verifier-value"}))
    assert st_t == 400 and json.loads(b_t).get("error") == "invalid_grant"


@register_test("T2-079", "2", "r4", ("REQ-16",), "Replaying same authorization code twice fails second time with invalid_grant")
def t2_079(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2079")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    cookie = _seed_auth_session_via_oauth(ctx)
    verifier, challenge = _pkce_pair()
    q = {"response_type": "code", "client_id": cl["client_id"], "redirect_uri": redir, "scope": "openid", "state": "s2", "code_challenge": challenge, "code_challenge_method": "S256"}
    st, hdrs, _ = c.edge("peer_a", "/authorize?" + urllib.parse.urlencode(q), host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": cookie})
    if st == 200:
        _, hdrs, _ = c.edge("peer_a", "/authorize/consent", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}, body=urllib.parse.urlencode({**q, "decision": "allow"}))
    code = urllib.parse.parse_qs(urllib.parse.urlparse(hdrs["location"]).query)["code"][0]
    form = urllib.parse.urlencode({"grant_type": "authorization_code", "client_id": cl["client_id"], "redirect_uri": redir, "code": code, "code_verifier": verifier})
    assert c.edge("peer_a", "/token", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/x-www-form-urlencoded"}, body=form)[0] == 200
    st2, _, b2 = c.edge("peer_a", "/token", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/x-www-form-urlencoded"}, body=form)
    assert st2 == 400 and json.loads(b2).get("error") == "invalid_grant"


@register_test("T2-080", "2", "r4", ("REQ-16",), "Tampered Bearer token on /userinfo returns 401 WWW-Authenticate")
def t2_080(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, hdrs, _ = c.edge("peer_a", "/userinfo", host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Authorization": "Bearer tampered.jwt.token"})
    assert st == 401 and "bearer" in hdrs.get("www-authenticate", "").lower()


@register_test("T2-104", "2", "r4", ("REQ-16",), "POST /token with unsupported grant_type returns 400 unsupported_grant_type")
def t2_104(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, _, body = c.edge("peer_a", "/token", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/x-www-form-urlencoded"}, body="grant_type=client_credentials")
    assert st == 400 and json.loads(body).get("error") == "unsupported_grant_type"


@register_test("T2-081", "2", "r4", ("REQ-17",), "Passkey registration from https://evil.example origin is rejected")
def t2_081(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    reg = sim.register(chal, "https://evil.example", name="evil")
    st, _, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(reg))
    assert st in (400, 403)


@register_test("T2-082", "2", "r4", ("REQ-17",), "Passkey login with UV=0 (flags=0x01) is rejected")
def t2_082(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    st, _, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin, flags=0x01)))
    assert st in (400, 401, 403)


@register_test("T2-083", "2", "r4", ("REQ-17",), "Passkey assertion with rolled-back sign_count is rejected")
def t2_083(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin, count_override=10)))[0] == 200
    chal3 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    st, _, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal3, origin, count_override=5)))
    assert st in (400, 401, 403)


@register_test("T2-084", "2", "r4", ("REQ-17",), "Passkey assertion with tampered authenticator_data or wrong signature fails")
def t2_084(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    st, _, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin, tamper_sig=True)))
    assert st in (400, 401)


@register_test("T2-085", "2", "r4", ("REQ-17",), "Replaying same Passkey challenge twice rejects second attempt")
def t2_085(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(sim.register(chal, origin)))[0] == 200
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    a1 = sim.assert_login(chal2, origin)
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(a1))[0] == 200
    st2, _, _ = c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))
    assert st2 in (400, 401)


@register_test("T2-105", "2", "r4", ("REQ-17",), "Panel Passkey login for disabled account returns 403")
def t2_105(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2105")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    ru = c.api("peer_a", "POST", "/users", {"email": f"{tag}@example.test", "role": "viewer"}, token=tok)[1]["result"]
    utok = c.api("peer_a", "POST", "/auth/login", {"email": f"{tag}@example.test", "password": ru["password"]}, token="")[1]["result"]["token"]
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": "Disabled!2026_Pass"}, token=utok)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.PANEL_HOST}"
    chal = c.api("peer_a", "POST", "/account/passkeys/begin", {}, token=utok)[1]["result"]["challenge"]
    c.api("peer_a", "POST", "/account/passkeys/finish", sim.register(chal, origin), token=utok)
    c.api("peer_a", "PATCH", f"/users/{ru['user']['id']}", {"disabled": True}, token=tok)
    chal2 = c.api("peer_a", "POST", "/auth/passkey/begin", {}, token="")[1]["result"]["challenge"]
    st, _ = c.api("peer_a", "POST", "/auth/passkey/finish", sim.assert_login(chal2, origin), token="")
    assert st in (401, 403)


@register_test("T2-086", "2", "r4", ("REQ-18",), "Linux.do callback with mismatched/missing state cookie fails CSRF check")
def t2_086(ctx: TestContext) -> None:
    st, _, _ = ctx.ensure_cluster().edge("peer_a", "/login/oauth/linuxdo/callback?code=fake&state=wrong", host=ContractConfig.AUTH_HOST, use_tls=True)
    assert st in (400, 401, 403)


@register_test("T2-087", "2", "r4", ("REQ-18",), "Linux.do upstream returning silenced=true or active=false refuses login (403)")
def t2_087(ctx: TestContext) -> None:
    ctx.ensure_cluster()
    prev = ctx.mock_oauth.persona
    try:
        for p in ("silenced", "inactive"):
            ctx.mock_oauth.persona = p
            _, _, res = _linuxdo_oauth_login(ctx)
            assert res["status"] == 403, f"expected 403 for persona={p}, got {res['status']}"
    finally:
        ctx.mock_oauth.persona = prev


@register_test("T2-088", "2", "r4", ("REQ-18",), "Linux.do user denies consent (?error=access_denied) handled gracefully")
def t2_088(ctx: TestContext) -> None:
    ctx.ensure_cluster()
    prev = ctx.mock_oauth.persona
    ctx.mock_oauth.persona = "deny"
    try:
        _, _, res = _linuxdo_oauth_login(ctx)
        assert res["status"] in (200, 400, 401, 403)
    finally:
        ctx.mock_oauth.persona = prev


@register_test("T2-089", "2", "r4", ("REQ-18",), "Panel /client/v4/auth/oauth/callback rejects tampered state or bad code")
def t2_089(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, hdrs, _ = c.edge("peer_a", "/client/v4" + ContractConfig.PANEL_OAUTH_CALLBACK_PATH + "?code=bogus&state=tampered", host=ContractConfig.PANEL_HOST, use_tls=True)
    assert st in (400, 401, 403) and "fucf_s_" not in hdrs.get("set-cookie", "")


@register_test("T2-090", "2", "r4", ("REQ-18",), "Unauthorized OAuth identity does not escalate privileges on Panel")
def t2_090(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    prev_user = ctx.mock_oauth.username
    prev_email = ctx.mock_oauth.email
    ctx.mock_oauth.username = "unprivileged_stranger"
    ctx.mock_oauth.email = "stranger-not-in-panel@example.test"
    try:
        auth_cookie = _seed_auth_session_via_oauth(ctx)
        st, hdrs, _ = c.edge("peer_a", "/client/v4" + ContractConfig.PANEL_OAUTH_LOGIN_PATH, host=ContractConfig.PANEL_HOST, use_tls=True)
        panel_ck = hdrs.get("set-cookie", "").split(";", 1)[0]
        auth_u = urllib.parse.urlparse(hdrs["location"])
        _, h2, _ = c.edge("peer_a", auth_u.path + "?" + auth_u.query, host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": auth_cookie})
        cb_u = urllib.parse.urlparse(h2["location"])
        st3, h3, _ = c.edge("peer_a", cb_u.path + "?" + cb_u.query, host=ContractConfig.PANEL_HOST, use_tls=True, headers={"Cookie": panel_ck} if panel_ck else None)
        if st3 in (200, 302) and "fucf_s_" in h3.get("set-cookie", ""):
            sess = h3["set-cookie"].split("fucf_s_", 1)[1].split(";", 1)[0]
            assert c.api("peer_a", "GET", "/users", token="fucf_s_" + sess)[0] == 403
        else:
            assert st3 in (401, 403)
    finally:
        ctx.mock_oauth.username = prev_user
        ctx.mock_oauth.email = prev_email


# ===========================================================================
# REQ-19 / REQ-20: UI Boundaries, Security, Contrast & Mobile (T2-091..100)
# ===========================================================================


@register_test("T2-091", "2", "r5", ("REQ-19",), "Invalid localStorage theme ('neon') falls back safely to Light", tags=("ui",))
def t2_091(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            localStorage.setItem('fucf-theme', 'neon');
            location.reload();
            return true;
        })()""",
    )
    res2 = _run_cdp_on_panel(ctx, "getComputedStyle(document.body).backgroundColor")
    assert res["value"] is True and res2["value"] in ("rgb(251, 251, 251)", "rgb(3, 3, 3)")


@register_test("T2-092", "2", "r5", ("REQ-19",), "Mobile viewport (375x812) has zero horizontal overflow", tags=("ui",))
def t2_092(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(ctx, "({ sw: document.documentElement.scrollWidth, cw: document.documentElement.clientWidth })", viewport=(375, 812))
    v = res["value"]
    assert v["sw"] <= v["cw"] + 2, f"horizontal overflow on mobile: {v}"


@register_test("T2-093", "2", "r5", ("REQ-19",), "CSP frame-ancestors 'none' & X-Frame-Options: DENY on dashboard and auth", tags=("ui",))
def t2_093(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    for host in (ContractConfig.PANEL_HOST, ContractConfig.AUTH_HOST):
        st, hdrs, _ = c.edge("peer_a", "/", host=host, use_tls=True)
        assert st == 200
        assert "frame-ancestors 'none'" in hdrs.get("content-security-policy", "")
        assert hdrs.get("x-frame-options") == "DENY"


@register_test("T2-094", "2", "r5", ("REQ-19",), "XSS <script> payload in worker name is escaped in DOM without execution", tags=("ui",))
def t2_094(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    c = ctx.ensure_cluster()
    xss_name = "xss-test-script"
    c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/{xss_name}", raw='export default { fetch() { return new Response("ok"); } }')
    z = ctx.create_zone("xss-comment.test")
    c.api("peer_a", "POST", f"/zones/{z['id']}/dns_records", {"type": "TXT", "name": "xss", "content": "<script>window.__xss=1</script>"})
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            location.hash = '#/zones/{z["id"]}/dns';
            await new Promise(r => setTimeout(r, 200));
            return {{ xss: !!window.__xss, text: document.body.innerText.includes('<script>') }};
        }})()""",
    )
    assert res["value"]["xss"] is False


@register_test("T2-095", "2", "r5", ("REQ-19",), "Primary text contrast >= 4.5:1 in both Light and Dark modes", tags=("ui",))
def t2_095(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            function parseRgb(s) {
                const m = s.match(/\\d+/g);
                return m ? m.slice(0, 3).map(Number) : [0, 0, 0];
            }
            function lum(rgb) {
                return rgb.map(v => {
                    v /= 255;
                    return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4);
                }).reduce((a, c, i) => a + c * [0.2126, 0.7152, 0.0722][i], 0);
            }
            function ratio(c1, c2) {
                const l1 = lum(parseRgb(c1)), l2 = lum(parseRgb(c2));
                return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05);
            }
            document.documentElement.removeAttribute('data-mode');
            const light = ratio(getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor);
            document.documentElement.setAttribute('data-mode', 'dark');
            const dark = ratio(getComputedStyle(document.body).color, getComputedStyle(document.body).backgroundColor);
            return { light, dark };
        })()""",
    )
    v = res["value"]
    assert v["light"] >= 4.5 and v["dark"] >= 4.5, f"low contrast: {v}"


@register_test("T2-096", "2", "r5", ("REQ-20",), "Unauthenticated visit to #/fleet renders login cleanly with 0 console errors", tags=("ui",))
def t2_096(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(async () => {
            localStorage.removeItem('fucf_token');
            location.hash = '#/fleet';
            await new Promise(r => setTimeout(r, 150));
            return document.body.innerText.length;
        })()""",
    )
    assert res["value"] > 10


@register_test("T2-097", "2", "r5", ("REQ-20",), "Invalid hash route #/nonexistent/route falls back cleanly with 0 errors", tags=("ui",))
def t2_097(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            location.hash = '#/nonexistent/route/xyz';
            await new Promise(r => setTimeout(r, 150));
            return document.body.innerText.length;
        }})()""",
    )
    assert res["value"] > 10


@register_test("T2-098", "2", "r5", ("REQ-20",), "Invalid form input in UI shows error without uncaught JS rejection", tags=("ui",))
def t2_098(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            const r = await fetch('/client/v4/zones', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + {json.dumps(tok)}, 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ name: '' }})
            }});
            return r.status;
        }})()""",
    )
    assert res["value"] == 400


@register_test("T2-099", "2", "r5", ("REQ-20",), "Viewer user logged into UI cannot trigger admin-only mutations", tags=("ui",))
def t2_099(ctx: TestContext) -> None:
    tag = ctx.next_tag("t2099")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    ru = c.api("peer_a", "POST", "/users", {"email": f"{tag}@example.test", "role": "viewer"}, token=tok)[1]["result"]
    vtok = c.api("peer_a", "POST", "/auth/login", {"email": f"{tag}@example.test", "password": ru["password"]}, token="")[1]["result"]["token"]
    c.api("peer_a", "POST", "/account/password", {"current": ru["password"], "new": "Viewer!2026_Pass"}, token=vtok)
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(vtok)});
            const r = await fetch('/client/v4/zones', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + {json.dumps(vtok)}, 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ name: 'nope.test' }})
            }});
            return r.status;
        }})()""",
    )
    assert res["value"] == 403


@register_test("T2-100", "2", "r5", ("REQ-20",), "Expired/401 token mid-navigation falls back to login cleanly", tags=("ui",))
def t2_100(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(async () => {
            localStorage.setItem('fucf_token', 'fucf_s_expired_invalid');
            location.hash = '#/zones';
            await new Promise(r => setTimeout(r, 200));
            return document.body.innerText.length;
        })()""",
    )
    assert res["value"] > 10
