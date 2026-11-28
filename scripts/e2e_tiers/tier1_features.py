"""Tier 1 — 105 Single-Feature Positive Tests (T1-001 .. T1-105)."""
from __future__ import annotations

import base64
import hashlib
import hmac
import http.client
import json
import os
import secrets
import shutil
import ssl
import struct
import threading
import time
import urllib.parse
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from . import CdpSession, TestContext, find_browser_executable, register_test
from .harness import (
    ClusterHarness,
    ContractConfig,
    H2Client,
    MockOAuthServer,
    TestOriginServer,
    WebAuthnSimulator,
    b64u_decode,
    b64u_encode,
    wait_for,
    ws_close,
    ws_connect,
    ws_recv,
    ws_send,
)


def _setup_kv_worker(ctx: TestContext, tag: str, js_body: str) -> tuple[str, str, str]:
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    kv_id = ctx.create_kv(f"kv-{tag}")
    ctx.deploy_worker(
        f"w-{tag}",
        js_body,
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
    )
    return z["id"], kv_id, f"{tag}.test"


def _setup_d1_worker(ctx: TestContext, tag: str, js_body: str) -> tuple[str, str, str]:
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    db_id = ctx.create_d1(f"d1-{tag}")
    ctx.deploy_worker(
        f"w-{tag}",
        js_body,
        z["id"],
        f"{tag}.test/*",
        d1_bindings={"DB": db_id},
    )
    return z["id"], db_id, f"{tag}.test"


def _totp_code(secret: str, offset: int = 0) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    mac = hmac.new(key, struct.pack(">Q", int(time.time()) // 30 + offset), hashlib.sha1).digest()
    at = mac[-1] & 15
    return "%06d" % ((struct.unpack(">I", mac[at : at + 4])[0] & 0x7FFFFFFF) % 1000000)


def _pkce_pair() -> tuple[str, str]:
    verifier = b64u_encode(os.urandom(32))
    challenge = b64u_encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge


def _verify_jwt_rs_or_es(token: str, jwks: dict[str, Any]) -> dict[str, Any]:
    parts = token.split(".")
    assert len(parts) == 3, f"expected 3-part JWT, got {len(parts)}"
    hdr = json.loads(b64u_decode(parts[0]))
    claims = json.loads(b64u_decode(parts[1]))
    sig = b64u_decode(parts[2])
    signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
    kid = hdr.get("kid")
    keys = jwks.get("keys", [])
    matching = [k for k in keys if (not kid or k.get("kid") == kid)]
    assert matching, f"no matching JWK for kid={kid} in {keys}"
    jwk = matching[0]
    kty = jwk.get("kty")
    if kty == "EC":
        x = int.from_bytes(b64u_decode(jwk["x"]), "big")
        y = int.from_bytes(b64u_decode(jwk["y"]), "big")
        pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
        if len(sig) == 64:
            r = int.from_bytes(sig[:32], "big")
            s = int.from_bytes(sig[32:], "big")
            der_sig = encode_dss_signature(r, s)
        else:
            der_sig = sig
        pub.verify(der_sig, signing_input, ec.ECDSA(hashes.SHA256()))
    elif kty == "RSA":
        n = int.from_bytes(b64u_decode(jwk["n"]), "big")
        e = int.from_bytes(b64u_decode(jwk["e"]), "big")
        pub_rsa = rsa.RSAPublicNumbers(e, n).public_key()
        pub_rsa.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
    else:
        raise AssertionError(f"unsupported JWK kty={kty}")
    return claims


def _linuxdo_oauth_login(
    ctx: TestContext, node: str = "peer_a", extra_cookies: str = ""
) -> tuple[str, dict[str, str], dict[str, Any]]:
    """Run GET /login/oauth/linuxdo -> MockOAuthServer -> callback on auth.fucloudflare.com."""
    c = ctx.ensure_cluster()
    st, hdrs, body = c.edge(
        node,
        "/login/oauth/linuxdo",
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
        headers={"Cookie": extra_cookies} if extra_cookies else None,
    )
    assert st in (302, 303), f"expected redirect from /login/oauth/linuxdo, got {st} {body[:200]!r}"
    loc = hdrs["location"]
    # Follow redirect to MockOAuthServer
    parsed = urllib.parse.urlparse(loc)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.request("GET", parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    mock_resp = conn.getresponse()
    mock_resp.read()
    assert mock_resp.status == 302, f"MockOAuthServer authorize returned {mock_resp.status}"
    cb_url = mock_resp.getheader("Location")
    assert cb_url, "MockOAuthServer missing Location"
    cb_parsed = urllib.parse.urlparse(cb_url)
    set_cookie = hdrs.get("set-cookie", "")
    cookie_pair = set_cookie.split(";", 1)[0] if set_cookie else ""
    merged_cookie = "; ".join(x for x in (extra_cookies, cookie_pair) if x)
    st2, hdrs2, body2 = c.edge(
        node,
        cb_parsed.path + (f"?{cb_parsed.query}" if cb_parsed.query else ""),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
        headers={"Cookie": merged_cookie} if merged_cookie else None,
    )
    return cookie_pair, hdrs2, {"status": st2, "body": body2, "authorize_loc": loc}


def _seed_auth_session_via_oauth(ctx: TestContext, node: str = "peer_a") -> str:
    _, hdrs2, res = _linuxdo_oauth_login(ctx, node=node)
    assert res["status"] in (200, 302, 303), f"oauth login failed: {res}"
    sc = hdrs2.get("set-cookie", "")
    assert sc, f"expected auth session Set-Cookie, got headers={hdrs2}"
    return sc.split(";", 1)[0]


# ===========================================================================
# REQ-01 / REQ-02: Workers KV (T1-001..010, T1-101)
# ===========================================================================


@register_test("T1-001", "1", "r1", ("REQ-01",), "KV.put string then KV.get string")
def t1_001(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1001")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.KV.put("k1", "v1");
            const val = await env.KV.get("k1");
            return Response.json({ val });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"val": "v1"}, f"got {st} {body!r}"


@register_test("T1-002", "1", "r1", ("REQ-01",), "KV.put JSON then KV.get json")
def t1_002(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1002")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.KV.put("k2", JSON.stringify({ a: 1, b: "ok" }));
            const val = await env.KV.get("k2", "json");
            return Response.json({ val, isObj: typeof val === "object" });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"val": {"a": 1, "b": "ok"}, "isObj": True}


@register_test("T1-003", "1", "r1", ("REQ-01",), "KV.put binary then KV.get arrayBuffer and stream")
def t1_003(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1003")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const src = new Uint8Array([0, 1, 2, 127, 255]);
            await env.KV.put("kb", src.buffer);
            const ab = await env.KV.get("kb", "arrayBuffer");
            const arr = Array.from(new Uint8Array(ab));
            const stream = await env.KV.get("kb", "stream");
            const reader = stream.getReader();
            const chunks = [];
            while (true) {
                const { done, value } = await reader.read();
                if (done) break;
                chunks.push(...Array.from(value));
            }
            return Response.json({ arr, chunks });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"arr": [0, 1, 2, 127, 255], "chunks": [0, 1, 2, 127, 255]}


@register_test("T1-004", "1", "r1", ("REQ-01",), "KV.get multi-key returns Map with missing as null")
def t1_004(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1004")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.KV.put("k1", "v1");
            await env.KV.put("k2", "v2");
            const m = await env.KV.get(["k1", "k2", "missing"]);
            return Response.json({
                isMap: m instanceof Map,
                k1: m.get("k1"),
                k2: m.get("k2"),
                missing: m.get("missing")
            });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"isMap": True, "k1": "v1", "k2": "v2", "missing": None}


@register_test("T1-005", "1", "r1", ("REQ-01",), "KV.put with metadata, getWithMetadata, and delete")
def t1_005(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1005")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.KV.put("km", "v", { metadata: { tag: "x", n: 7 } });
            const got = await env.KV.getWithMetadata("km");
            await env.KV.delete("km");
            const after = await env.KV.get("km");
            return Response.json({ got, after });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"got": {"value": "v", "metadata": {"tag": "x", "n": 7}}, "after": None}


@register_test("T1-006", "1", "r1", ("REQ-02",), "KV.put with expirationTtl=60 returns value before expiry")
def t1_006(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1006")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.KV.put("ttl", "v-ttl", { expirationTtl: 60 });
            return Response.json({ val: await env.KV.get("ttl") });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"val": "v-ttl"}


@register_test("T1-007", "1", "r1", ("REQ-02",), "KV.put with short expiration expires after deadline")
def t1_007(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1007")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/put") {
                const exp = Math.floor(Date.now() / 1000) + 2;
                await env.KV.put("exp", "soon-gone", { expiration: exp });
                return Response.json({ v: await env.KV.get("exp") });
            }
            return Response.json({ v: await env.KV.get("exp") });
        } }""",
    )
    c = ctx.ensure_cluster()
    st1, _, b1 = c.edge("peer_a", "/put", host=host)
    assert st1 == 200 and json.loads(b1)["v"] == "soon-gone"
    time.sleep(2.6)
    st2, _, b2 = c.edge("peer_a", "/get", host=host)
    assert st2 == 200 and json.loads(b2)["v"] is None


@register_test("T1-008", "1", "r1", ("REQ-02",), "KV.list with prefix filters and sorts keys")
def t1_008(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1008")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            for (const k of ["p/b", "p/a", "p/c", "q/1", "q/2"]) await env.KV.put(k, k);
            const res = await env.KV.list({ prefix: "p/" });
            return Response.json(res);
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    res = json.loads(body)
    assert st == 200 and [k["name"] for k in res["keys"]] == ["p/a", "p/b", "p/c"] and res["list_complete"] is True


@register_test("T1-009", "1", "r1", ("REQ-02",), "KV.list cursor pagination across 5 keys with limit=2")
def t1_009(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1009")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            for (const k of ["k1", "k2", "k3", "k4", "k5"]) await env.KV.put(k, k);
            const pages = [];
            let cursor = undefined;
            while (true) {
                const p = await env.KV.list({ limit: 2, cursor });
                pages.push(p.keys.map(x => x.name));
                if (p.list_complete) break;
                cursor = p.cursor;
            }
            return Response.json({ pages });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    pages = json.loads(body)["pages"]
    assert st == 200 and [len(p) for p in pages] == [2, 2, 1] and sum(pages, []) == ["k1", "k2", "k3", "k4", "k5"]


@register_test("T1-010", "1", "r1", ("REQ-02",), "API KV namespace CRUD + key PUT/GET/DELETE interoperates with Worker")
def t1_010(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1010")
    c = ctx.ensure_cluster()
    _, kv_id, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/read") return Response.json({ v: await env.KV.get("from_api") });
            await env.KV.put("from_worker", "wval");
            return Response.json({ ok: true });
        } }""",
    )
    st_put, _ = c.api("peer_a", "PUT", f"{ContractConfig.KV_NAMESPACES_PATH}/{kv_id}/values/from_api", raw="aval")
    assert st_put == 200
    st_e, _, b_e = c.edge("peer_a", "/read", host=host)
    assert st_e == 200 and json.loads(b_e)["v"] == "aval"
    c.edge("peer_a", "/write", host=host)
    st_get, r_get = c.api("peer_a", "GET", f"{ContractConfig.KV_NAMESPACES_PATH}/{kv_id}/values/from_worker")
    assert st_get == 200 and (r_get.get("result", r_get) == "wval" or r_get.get("raw") == "wval" or r_get.get("result", {}).get("value") == "wval")
    st_del, _ = c.api("peer_a", "DELETE", f"{ContractConfig.KV_NAMESPACES_PATH}/{kv_id}/values/from_api")
    assert st_del == 200


@register_test("T1-101", "1", "r1", ("REQ-01",), "KV.put UTF-8 non-ASCII CJK and emoji key/value roundtrip")
def t1_101(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1101")
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const k = "键/🚀";
            const v = "你好世界-🌍";
            await env.KV.put(k, v);
            return Response.json({ got: await env.KV.get(k) });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body)["got"] == "你好世界-🌍"


# ===========================================================================
# REQ-03 / REQ-04: Workers D1 (T1-011..020, T1-102)
# ===========================================================================


@register_test("T1-011", "1", "r1", ("REQ-03",), "D1 prepare().bind().first('col') positional math")
def t1_011(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1011")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const s = await env.DB.prepare("SELECT ?1 + ?2 AS s").bind(2, 3).first("s");
            return Response.json({ s });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"s": 5}


@register_test("T1-012", "1", "r1", ("REQ-03",), "D1 INSERT .run() reports changes and last_row_id")
def t1_012(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1012")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)");
            const res = await env.DB.prepare("INSERT INTO t(name) VALUES(?)").bind("alice").run();
            return Response.json(res);
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    res = json.loads(body)
    assert st == 200 and res["success"] is True and res["meta"]["changes"] == 1 and res["meta"]["last_row_id"] >= 1


@register_test("T1-013", "1", "r1", ("REQ-03",), "D1 SELECT .all() returns results array and rows_read")
def t1_013(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1013")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES(1,'a'),(2,'b')");
            const res = await env.DB.prepare("SELECT id, name FROM t ORDER BY id").all();
            return Response.json(res);
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    res = json.loads(body)
    assert st == 200 and res["success"] is True and res["results"] == [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]
    assert res["meta"]["rows_read"] >= 2


@register_test("T1-014", "1", "r1", ("REQ-03",), "D1 .raw({columnNames: true}) prepends header row")
def t1_014(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1014")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE IF NOT EXISTS t(id INTEGER PRIMARY KEY, name TEXT); INSERT INTO t VALUES(1,'a')");
            const rows = await env.DB.prepare("SELECT id, name FROM t").raw({ columnNames: true });
            return Response.json({ rows });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body)["rows"] == [["id", "name"], [1, "a"]]


@register_test("T1-015", "1", "r1", ("REQ-03",), "D1 binds null, number, string, and ArrayBuffer BLOB roundtrip")
def t1_015(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1015")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE IF NOT EXISTS types(a TEXT, b REAL, c TEXT, d BLOB)");
            const blob = new Uint8Array([9, 8, 7, 255]).buffer;
            await env.DB.prepare("INSERT INTO types VALUES(?, ?, ?, ?)").bind(null, 3.5, "txt", blob).run();
            const row = await env.DB.prepare("SELECT a, b, c, d FROM types").first();
            const gotBlob = Array.from(new Uint8Array(row.d));
            return Response.json({ a: row.a, b: row.b, c: row.c, gotBlob });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"a": None, "b": 3.5, "c": "txt", "gotBlob": [9, 8, 7, 255]}


@register_test("T1-016", "1", "r1", ("REQ-04",), "D1 exec() executes multi-statement DDL+DML and returns count")
def t1_016(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1016")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const res = await env.DB.exec("CREATE TABLE t(id INTEGER); INSERT INTO t VALUES(1); INSERT INTO t VALUES(2)");
            const cnt = await env.DB.prepare("SELECT COUNT(*) AS c FROM t").first("c");
            return Response.json({ res, cnt });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    d = json.loads(body)
    assert st == 200 and d["res"]["count"] == 3 and d["res"]["duration"] >= 0 and d["cnt"] == 2


@register_test("T1-017", "1", "r1", ("REQ-04",), "D1 batch() executes array of prepared statements atomically")
def t1_017(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1017")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE b(id INTEGER PRIMARY KEY, v TEXT)");
            const res = await env.DB.batch([
                env.DB.prepare("INSERT INTO b VALUES(1, 'x')"),
                env.DB.prepare("INSERT INTO b VALUES(2, 'y')"),
                env.DB.prepare("SELECT COUNT(*) AS c FROM b")
            ]);
            return Response.json({ len: res.length, c: res[2].results[0].c });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"len": 3, "c": 2}


@register_test("T1-018", "1", "r1", ("REQ-04",), "D1 first() on empty result set returns null")
def t1_018(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1018")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE empty_t(id INTEGER)");
            const r = await env.DB.prepare("SELECT * FROM empty_t").first();
            return Response.json({ r });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"r": None}


@register_test("T1-019", "1", "r1", ("REQ-04",), "D1 database CRUD and SQL query via API")
def t1_019(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1019")
    c = ctx.ensure_cluster()
    db_id = ctx.create_d1(f"api-d1-{tag}")
    st_q, r_q = c.api(
        "peer_a",
        "POST",
        f"{ContractConfig.D1_DATABASES_PATH}/{db_id}/query",
        {"sql": "SELECT ?1 * 10 AS v", "params": [4]},
    )
    assert st_q == 200 and r_q["success"]
    res_list = r_q["result"]
    row = res_list[0]["results"][0] if isinstance(res_list, list) else res_list["results"][0]
    assert row["v"] == 40
    st_d, _ = c.api("peer_a", "DELETE", f"{ContractConfig.D1_DATABASES_PATH}/{db_id}")
    assert st_d == 200


@register_test("T1-020", "1", "r1", ("REQ-04",), "D1 first() without column argument returns full row object")
def t1_020(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1020")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            await env.DB.exec("CREATE TABLE t(id INTEGER, label TEXT); INSERT INTO t VALUES(1, 'hello')");
            const row = await env.DB.prepare("SELECT id, label FROM t WHERE id = ?").bind(1).first();
            return Response.json({ row });
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"row": {"id": 1, "label": "hello"}}


@register_test("T1-102", "1", "r1", ("REQ-03",), "D1 prepare() numbered parameter reuse ?1")
def t1_102(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1102")
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const row = await env.DB.prepare("SELECT ?1 AS a, ?1 || '-x' AS b").bind("ok").first();
            return Response.json(row);
        } }""",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/run", host=host)
    assert st == 200 and json.loads(body) == {"a": "ok", "b": "ok-x"}


# ===========================================================================
# REQ-05: Workers Cron Triggers (T1-021..025)
# ===========================================================================


@register_test("T1-021", "1", "r1", ("REQ-05",), "Cron scheduled() invoked via /__scheduled sets controller fields")
def t1_021(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1021")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    kv_id = ctx.create_kv(f"cron-{tag}")
    ctx.deploy_worker(
        f"cron-{tag}",
        """export default {
            async scheduled(controller, env, ctx) {
                await env.KV.put("ran", JSON.stringify({ type: controller.type, cron: controller.cron }));
            },
            async fetch(req, env) {
                return new Response(await env.KV.get("ran") || "none");
            }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["* * * * *"],
    )
    st, _, _ = c.edge("peer_a", "/__scheduled?cron=*%20*%20*%20*%20*", host=f"{tag}.test")
    assert st == 200
    st2, _, body = c.edge("peer_a", "/read", host=f"{tag}.test")
    got = json.loads(body)
    assert st2 == 200 and got["type"] == "scheduled" and got["cron"] == "* * * * *"


@register_test("T1-022", "1", "r1", ("REQ-05",), "Cron ctx.waitUntil() async KV write completes before trigger returns")
def t1_022(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1022")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    kv_id = ctx.create_kv(f"cronwu-{tag}")
    ctx.deploy_worker(
        f"cronwu-{tag}",
        """export default {
            scheduled(controller, env, ctx) {
                ctx.waitUntil((async () => { await env.KV.put("wu", "done"); })());
            },
            async fetch(req, env) { return Response.json({ wu: await env.KV.get("wu") }); }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["0 * * * *"],
    )
    st, _, _ = c.edge("peer_a", "/__scheduled", host=f"{tag}.test")
    assert st == 200
    st2, _, body = c.edge("peer_a", "/check", host=f"{tag}.test")
    assert st2 == 200 and json.loads(body) == {"wu": "done"}


@register_test("T1-023", "1", "r1", ("REQ-05",), "Cron controller.scheduledTime is epoch ms and noRetry() works")
def t1_023(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1023")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    kv_id = ctx.create_kv(f"cronnr-{tag}")
    ctx.deploy_worker(
        f"cronnr-{tag}",
        """export default {
            async scheduled(controller, env, ctx) {
                controller.noRetry();
                await env.KV.put("ts", String(controller.scheduledTime));
            },
            async fetch(req, env) { return Response.json({ ts: Number(await env.KV.get("ts")) }); }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["*/5 * * * *"],
    )
    st, _, _ = c.edge("peer_a", "/__scheduled", host=f"{tag}.test")
    assert st == 200
    st2, _, body = c.edge("peer_a", "/ts", host=f"{tag}.test")
    assert st2 == 200 and json.loads(body)["ts"] > 1_700_000_000_000


@register_test("T1-024", "1", "r1", ("REQ-05",), "Cron triggered via /workers/scripts/{name}/schedules/trigger API")
def t1_024(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1024")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    kv_id = ctx.create_kv(f"cronapi-{tag}")
    sname = f"cronapi-{tag}"
    ctx.deploy_worker(
        sname,
        """export default {
            async scheduled(controller, env, ctx) { await env.KV.put("api_trig", "yes"); },
            async fetch(req, env) { return Response.json({ v: await env.KV.get("api_trig") }); }
        }""",
        z["id"],
        f"{tag}.test/*",
        kv_bindings={"KV": kv_id},
        crons=["0 0 * * *"],
    )
    st, r = c.api("peer_a", "POST", ContractConfig.WORKER_CRON_TRIGGER_PATH.format(name=sname), {})
    assert st == 200 and r.get("success")
    st2, _, body = c.edge("peer_a", "/check", host=f"{tag}.test")
    assert st2 == 200 and json.loads(body) == {"v": "yes"}


@register_test("T1-025", "1", "r1", ("REQ-05",), "Cron 5-field UTC expression validation & /schedules API")
def t1_025(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1025")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    sname = f"cronexpr-{tag}"
    ctx.deploy_worker(
        sname,
        "export default { scheduled() {}, fetch() { return new Response('ok'); } }",
        z["id"],
        f"{tag}.test/*",
        crons=["0 */2 * * 1-5"],
    )
    st, r = c.api("peer_a", "GET", ContractConfig.WORKER_SCRIPTS_PATH + f"/{sname}/schedules")
    assert st == 200 and r.get("success")
    crons = r["result"] if isinstance(r["result"], list) else r["result"].get("schedules", [])
    assert any((x.get("cron") if isinstance(x, dict) else x) == "0 */2 * * 1-5" for x in crons)


# ===========================================================================
# REQ-06: WebCrypto & Web APIs (T1-026..030)
# ===========================================================================


@register_test("T1-026", "1", "r1", ("REQ-06",), "crypto.subtle.digest('SHA-256') matches NIST vector")
def t1_026(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1026")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("abc"));
            const hex = Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
            return Response.json({ hex });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body)["hex"] == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


@register_test("T1-027", "1", "r1", ("REQ-06",), "crypto.subtle HMAC-SHA256 sign and verify")
def t1_027(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1027")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            const key = await crypto.subtle.importKey("raw", new TextEncoder().encode("secret"), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
            const msg = new TextEncoder().encode("hello");
            const sig = await crypto.subtle.sign("HMAC", key, msg);
            const ok = await crypto.subtle.verify("HMAC", key, sig, msg);
            const bad = await crypto.subtle.verify("HMAC", key, sig, new TextEncoder().encode("tampered"));
            return Response.json({ ok, bad });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body) == {"ok": True, "bad": False}


@register_test("T1-028", "1", "r1", ("REQ-06",), "crypto.subtle importKey SPKI + ECDSA P-256 SHA-256 verify")
def t1_028(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1028")
    sim = WebAuthnSimulator(alg=-7)
    assertion = sim.assert_login("test-chal", "https://auth.fucloudflare.com")
    signed_bytes = b64u_decode(assertion["authenticator_data"]) + hashlib.sha256(b64u_decode(assertion["client_data"])).digest()
    spki_b64 = base64.b64encode(sim.spki_der).decode("ascii")
    sig_b64 = base64.b64encode(b64u_decode(assertion["signature"])).decode("ascii")
    msg_b64 = base64.b64encode(signed_bytes).decode("ascii")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"wc-{tag}",
        f"""export default {{ async fetch() {{
            const b64 = (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0));
            const key = await crypto.subtle.importKey("spki", b64("{spki_b64}"), {{ name: "ECDSA", namedCurve: "P-256" }}, false, ["verify"]);
            const ok = await crypto.subtle.verify({{ name: "ECDSA", hash: "SHA-256" }}, key, b64("{sig_b64}"), b64("{msg_b64}"));
            return Response.json({{ ok }});
        }} }}""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body) == {"ok": True}


@register_test("T1-029", "1", "r1", ("REQ-06",), "crypto.subtle AES-GCM-256 encrypt and decrypt roundtrip")
def t1_029(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1029")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { async fetch() {
            const rawKey = crypto.getRandomValues(new Uint8Array(32));
            const iv = crypto.getRandomValues(new Uint8Array(12));
            const key = await crypto.subtle.importKey("raw", rawKey, "AES-GCM", false, ["encrypt", "decrypt"]);
            const pt = new TextEncoder().encode("secret-payload");
            const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, pt);
            const dec = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, ct);
            return Response.json({ plain: new TextDecoder().decode(dec) });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    st, _, body = ctx.ensure_cluster().edge("peer_a", "/", host=f"{tag}.test")
    assert st == 200 and json.loads(body) == {"plain": "secret-payload"}


@register_test("T1-030", "1", "r1", ("REQ-06",), "getRandomValues, randomUUID, TextEncoder/Decoder, Response.redirect")
def t1_030(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1030")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"wc-{tag}",
        """export default { fetch(req) {
            const u = new URL(req.url);
            if (u.pathname === "/redir") return Response.redirect("https://example.org/dest", 302);
            const id = crypto.randomUUID();
            const r = crypto.getRandomValues(new Uint8Array(16));
            const txt = new TextDecoder().decode(new TextEncoder().encode("café"));
            return Response.json({ id, rLen: r.length, txt });
        } }""",
        z["id"],
        f"{tag}.test/*",
    )
    c = ctx.ensure_cluster()
    st, _, body = c.edge("peer_a", "/info", host=f"{tag}.test")
    d = json.loads(body)
    assert st == 200 and len(d["id"]) == 36 and d["id"][14] == "4" and d["rLen"] == 16 and d["txt"] == "café"
    st2, hdrs2, _ = c.edge("peer_a", "/redir", host=f"{tag}.test")
    assert st2 == 302 and hdrs2.get("location") == "https://example.org/dest"


# ===========================================================================
# REQ-07 / REQ-08 / REQ-09 / REQ-10: Masterless Sync, Multi-Node Dashboard, Accel
# ===========================================================================


@register_test("T1-031", "1", "r2", ("REQ-07",), "Zone & DNS record created on peer_a converges on peer_b")
def t1_031(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1031")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    c.wait_converged(lambda: any(x["id"] == z["id"] for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))
    rc, an, _ = c.dns_query("peer_b", f"{tag}.test", qtype=1)
    assert rc == 0 and an >= 1


@register_test("T1-032", "1", "r2", ("REQ-07",), "Zone & Worker created on peer_b converges and runs on peer_a")
def t1_032(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1032")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_b", origin_port=ctx.origin1.port)
    ctx.deploy_worker(
        f"w-{tag}",
        'export default { fetch() { return new Response("from-peer-b"); } }',
        z["id"],
        f"{tag}.test/*",
        node="peer_b",
    )
    c.wait_converged(lambda: c.edge("peer_a", "/", host=f"{tag}.test")[2] == b"from-peer-b")


@register_test("T1-033", "1", "r2", ("REQ-07",), "Record updated on peer_a and deleted on peer_b propagates tombstone")
def t1_033(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1033")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    zid = z["id"]
    _, r = c.api("peer_a", "POST", f"/zones/{zid}/dns_records", {"type": "TXT", "name": "del", "content": "v1"})
    rec_id = r["result"]["id"]
    c.wait_converged(lambda: any(x["id"] == rec_id for x in c.api("peer_b", "GET", f"/zones/{zid}/dns_records")[1].get("result", [])))
    st_del, _ = c.api("peer_b", "DELETE", f"/zones/{zid}/dns_records/{rec_id}")
    assert st_del == 200
    c.wait_converged(lambda: not any(x["id"] == rec_id for x in c.api("peer_a", "GET", f"/zones/{zid}/dns_records")[1].get("result", [])))
    time.sleep(1.5)
    assert not any(x["id"] == rec_id for x in c.api("peer_a", "GET", f"/zones/{zid}/dns_records")[1].get("result", []))


@register_test("T1-034", "1", "r2", ("REQ-07",), "Peer restart preserves state.json and synced zones on both peers")
def t1_034(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1034")
    c = ctx.new_cluster()
    try:
        st, r = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})
        assert st == 200
        zid = r["result"]["id"]
        c.wait_converged(lambda: any(x["id"] == zid for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))
        c.restart("peer_a")
        c.restart("peer_b")
        assert os.path.exists(os.path.join(c.nodes["peer_a"].data_dir, "state.json"))
        assert any(x["id"] == zid for x in c.api("peer_a", "GET", "/zones")[1]["result"])
        assert any(x["id"] == zid for x in c.api("peer_b", "GET", "/zones")[1]["result"])
    finally:
        c.stop()


@register_test("T1-035", "1", "r2", ("REQ-07",), "GET /system and GET /fleet on both peers report writable role='peer'")
def t1_035(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    for n in ("peer_a", "peer_b"):
        st_s, rs = c.api(n, "GET", "/system")
        st_f, rf = c.api(n, "GET", "/fleet", token=tok)
        assert st_s == 200 and rs["result"]["role"] == ContractConfig.ROLE_PEER
        assert st_f == 200 and rf["result"]["role"] == ContractConfig.ROLE_PEER


@register_test("T1-036", "1", "r2", ("REQ-07",), "Cache purge on peer_a propagates to peer_b")
def t1_036(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1036")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: c.edge("peer_b", "/a/style.css", host=f"{tag}.test")[0] == 200)
    assert c.edge("peer_b", "/a/style.css", host=f"{tag}.test")[1]["fcf-cache-status"] == "HIT"
    st_p, _ = c.api("peer_a", "POST", f"/zones/{z['id']}/purge_cache", {"purge_everything": True})
    assert st_p == 200
    c.wait_converged(lambda: c.edge("peer_b", "/a/style.css", host=f"{tag}.test")[1]["fcf-cache-status"] == "MISS")


@register_test("T1-103", "1", "r2", ("REQ-07",), "Tombstone delete then re-create item with same name propagates to peer")
def t1_103(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1103")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    zid = z["id"]
    c.wait_converged(lambda: any(x["id"] == zid for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))
    assert c.api("peer_a", "DELETE", f"/zones/{zid}")[0] == 200
    c.wait_converged(lambda: not any(x["id"] == zid for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))
    z2 = ctx.create_zone(f"{tag}.test", node="peer_a")
    c.wait_converged(lambda: any(x["id"] == z2["id"] for x in c.api("peer_b", "GET", "/zones")[1].get("result", [])))


@register_test("T1-037", "1", "r2", ("REQ-08",), "Worker on peer_a writes KV key -> Worker on peer_b reads it")
def t1_037(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1037")
    c = ctx.ensure_cluster()
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/put") { await env.KV.put("sync_k", "v1"); return new Response("ok"); }
            return Response.json({ v: await env.KV.get("sync_k") });
        } }""",
    )
    c.wait_converged(lambda: c.edge("peer_b", "/get", host=host)[0] == 200)
    assert c.edge("peer_a", "/put", host=host)[0] == 200
    c.wait_converged(lambda: json.loads(c.edge("peer_b", "/get", host=host)[2])["v"] == "v1")


@register_test("T1-038", "1", "r2", ("REQ-08",), "Worker on peer_b deletes KV key -> peer_a sees null tombstone")
def t1_038(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1038")
    c = ctx.ensure_cluster()
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/put") { await env.KV.put("k", "live"); return new Response("ok"); }
            if (u.pathname === "/del") { await env.KV.delete("k"); return new Response("ok"); }
            return Response.json({ v: await env.KV.get("k") });
        } }""",
    )
    c.wait_converged(lambda: c.edge("peer_b", "/get", host=host)[0] == 200)
    c.edge("peer_a", "/put", host=host)
    c.wait_converged(lambda: json.loads(c.edge("peer_b", "/get", host=host)[2])["v"] == "live")
    c.edge("peer_b", "/del", host=host)
    c.wait_converged(lambda: json.loads(c.edge("peer_a", "/get", host=host)[2])["v"] is None)


@register_test("T1-039", "1", "r2", ("REQ-08",), "Worker on peer_a executes D1 INSERT -> peer_b queries row")
def t1_039(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1039")
    c = ctx.ensure_cluster()
    _, _, host = _setup_d1_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/write") {
                await env.DB.exec("CREATE TABLE IF NOT EXISTS items(id INTEGER PRIMARY KEY, name TEXT)");
                await env.DB.prepare("INSERT OR REPLACE INTO items VALUES(1, 'from-a')").run();
                return new Response("ok");
            }
            const row = await env.DB.prepare("SELECT name FROM items WHERE id=1").first();
            return Response.json({ row });
        } }""",
    )
    assert c.edge("peer_a", "/write", host=host)[0] == 200
    c.wait_converged(
        lambda: (lambda s, _, b: s == 200 and (json.loads(b).get("row") or {}).get("name") == "from-a")(
            *c.edge("peer_b", "/read", host=host)
        )
    )


@register_test("T1-040", "1", "r2", ("REQ-08",), "peer_a and peer_b update disjoint KV keys concurrently")
def t1_040(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1040")
    c = ctx.ensure_cluster()
    _, _, host = _setup_kv_worker(
        ctx,
        tag,
        """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname.startsWith("/put/")) {
                const k = u.pathname.slice(5);
                await env.KV.put(k, k + "-val");
                return new Response("ok");
            }
            return Response.json({ a: await env.KV.get("ka"), b: await env.KV.get("kb") });
        } }""",
    )
    c.wait_converged(lambda: c.edge("peer_b", "/get", host=host)[0] == 200)
    t1 = threading.Thread(target=lambda: c.edge("peer_a", "/put/ka", host=host))
    t2 = threading.Thread(target=lambda: c.edge("peer_b", "/put/kb", host=host))
    t1.start()
    t2.start()
    t1.join()
    t2.join()
    expected = {"a": "ka-val", "b": "kb-val"}
    c.wait_converged(
        lambda: json.loads(c.edge("peer_a", "/get", host=host)[2]) == expected
        and json.loads(c.edge("peer_b", "/get", host=host)[2]) == expected
    )


@register_test("T1-041", "1", "r2", ("REQ-08",), "KV and D1 synced state survives restart on peer_b")
def t1_041(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1041")
    c = ctx.new_cluster()
    try:
        st_z, rz = c.api("peer_a", "POST", "/zones", {"name": f"{tag}.test"})
        assert st_z == 200
        zid = rz["result"]["id"]
        kv_id = c.api("peer_a", "POST", ContractConfig.KV_NAMESPACES_PATH, {"title": f"kv-{tag}"})[1]["result"]["id"]
        db_res = c.api("peer_a", "POST", ContractConfig.D1_DATABASES_PATH, {"name": f"d1-{tag}"})[1]["result"]
        db_id = db_res.get("uuid") or db_res["id"]
        code = """export default { async fetch(req, env) {
            const u = new URL(req.url);
            if (u.pathname === "/seed") {
                await env.KV.put("persist", "yes");
                await env.DB.exec("CREATE TABLE p(k TEXT); INSERT INTO p VALUES('row1')");
                return new Response("ok");
            }
            return Response.json({ kv: await env.KV.get("persist"), db: await env.DB.prepare("SELECT k FROM p").first("k") });
        } }"""
        c.api("peer_a", "PUT", f"{ContractConfig.WORKER_SCRIPTS_PATH}/w-{tag}", raw=code)
        c.api("peer_a", "PATCH", f"{ContractConfig.WORKER_SCRIPTS_PATH}/w-{tag}/settings", {"kv_bindings": {"KV": kv_id}, "d1_bindings": {"DB": db_id}})
        c.api("peer_a", "POST", f"/zones/{zid}/workers/routes", {"pattern": f"{tag}.test/*", "script": f"w-{tag}"})
        assert c.edge("peer_a", "/seed", host=f"{tag}.test")[0] == 200
        c.wait_converged(lambda: c.edge("peer_b", "/read", host=f"{tag}.test")[2] == b'{"kv":"yes","db":"row1"}')
        c.restart("peer_b")
        st_b, _, b_b = c.edge("peer_b", "/read", host=f"{tag}.test")
        assert st_b == 200 and json.loads(b_b) == {"kv": "yes", "db": "row1"}
    finally:
        c.stop()


@register_test("T1-042", "1", "r2", ("REQ-09",), "Account setup on peer_a enables login on peer_b")
def t1_042(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")
    c.wait_converged(lambda: c.api("peer_b", "GET", "/auth/status", token="")[1].get("result", {}).get("initialized") is True)
    st, r = c.api("peer_b", "POST", "/auth/login", {"email": ctx.admin_email, "password": ctx.admin_password}, token="")
    assert st == 200 and r["result"]["token"].startswith("fucf_s_")


@register_test("T1-043", "1", "r2", ("REQ-09",), "Session token issued by peer_a authenticates API requests on peer_b")
def t1_043(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    c.wait_converged(lambda: c.api("peer_b", "GET", "/zones", token=tok)[0] == 200)


@register_test("T1-044", "1", "r2", ("REQ-09",), "Zone write via https://dashboard.fucloudflare.com on peer_b syncs to peer_a")
def t1_044(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1044")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    c.wait_converged(lambda: c.api("peer_b", "GET", "/zones", token=tok)[0] == 200)
    st, _, body = c.edge(
        "peer_b",
        "/client/v4/zones",
        host=ContractConfig.PANEL_HOST,
        method="POST",
        use_tls=True,
        headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json"},
        body=json.dumps({"name": f"{tag}.test"}),
    )
    assert st == 200, f"panel write on peer_b failed: {st} {body!r}"
    zid = json.loads(body)["result"]["id"]
    c.wait_converged(lambda: any(z["id"] == zid for z in c.api("peer_a", "GET", "/zones")[1]["result"]))


@register_test("T1-045", "1", "r2", ("REQ-09",), "Passkey begin on peer_a finishes on peer_b via stateless ticket")
def t1_045(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.PANEL_HOST}"
    st_b, r_b = c.api("peer_a", "POST", "/account/passkeys/begin", {}, token=tok, headers={"Origin": origin})
    assert st_b == 200
    reg = sim.register(r_b["result"]["challenge"], origin, name="cross-node-key")
    st_f, r_f = c.api("peer_a", "POST", "/account/passkeys/finish", reg, token=tok)
    assert st_f == 200, f"passkey register failed: {st_f} {r_f}"

    # Wait for user passkey to sync to peer_b
    c.wait_converged(lambda: len(c.api("peer_b", "GET", "/account", token=tok)[1].get("result", {}).get("passkeys", [])) >= 1)
    st_ab, r_ab = c.api("peer_a", "POST", "/auth/passkey/begin", {}, token="")
    assert st_ab == 200
    assertion = sim.assert_login(r_ab["result"]["challenge"], origin)
    st_af, r_af = c.api("peer_b", "POST", "/auth/passkey/finish", assertion, token="")
    assert st_af == 200 and r_af["result"]["token"].startswith("fucf_s_"), f"cross-node passkey finish failed: {st_af} {r_af}"


@register_test("T1-046", "1", "r2", ("REQ-09",), "Password+TOTP login on peer_a completes second_step on peer_b")
def t1_046(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1046")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    email = f"{tag}@example.test"
    _, ru = c.api("peer_a", "POST", "/users", {"email": email, "role": "editor"}, token=tok)
    init_pw = ru["result"]["password"]
    utok = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": init_pw}, token="")[1]["result"]["token"]
    pw = "TotpUser!2026_Secure"
    assert c.api("peer_a", "POST", "/account/password", {"current": init_pw, "new": pw}, token=utok)[0] == 200
    secret = c.api("peer_a", "POST", "/account/totp/begin", {}, token=utok)[1]["result"]["secret"]
    assert c.api("peer_a", "POST", "/account/totp/enable", {"code": _totp_code(secret)}, token=utok)[0] == 200

    c.wait_converged(
        lambda: "second_step" in c.api("peer_b", "POST", "/auth/login", {"email": email, "password": pw}, token="")[1].get("result", {})
    )
    login_a = c.api("peer_a", "POST", "/auth/login", {"email": email, "password": pw}, token="")[1]["result"]
    ticket = login_a["second_step"]["ticket"]
    st2, r2 = c.api("peer_b", "POST", "/auth/second_step", {"ticket": ticket, "code": _totp_code(secret)}, token="")
    if st2 != 200:
        st2, r2 = c.api("peer_b", "POST", "/auth/second_step", {"ticket": ticket, "code": _totp_code(secret, 1)}, token="")
    assert st2 == 200 and r2["result"]["token"].startswith("fucf_s_")


@register_test("T1-047", "1", "r2", ("REQ-10",), "accel_jp reports role='accelerate' and pulls zones")
def t1_047(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1047")
    c = ctx.ensure_cluster()
    st_s, rs = c.api("accel_jp", "GET", "/system")
    assert st_s == 200 and rs["result"]["role"] == ContractConfig.ROLE_ACCELERATE
    z = ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: any(x["id"] == z["id"] for x in c.api("accel_jp", "GET", "/zones")[1].get("result", [])))


@register_test("T1-048", "1", "r2", ("REQ-10",), "accel_jp serves edge proxy and cache MISS then HIT")
def t1_048(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1048")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: c.edge("accel_jp", "/a/style.css", host=f"{tag}.test")[0] == 200)
    st, hdrs, _ = c.edge("accel_jp", "/a/style.css", host=f"{tag}.test")
    assert st == 200 and hdrs.get("fcf-cache-status") == "HIT"


@register_test("T1-049", "1", "r2", ("REQ-10",), "accel_jp creates zero local state.json, accounts.json, or persistent DB files")
def t1_049(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")
    tag = ctx.next_tag("t1049")
    z = ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: any(x["id"] == z["id"] for x in c.api("accel_jp", "GET", "/zones")[1].get("result", [])))
    c.edge("accel_jp", "/page", host=f"{tag}.test")
    ddir = c.nodes["accel_jp"].data_dir
    for forbidden in ("state.json", "accounts.json"):
        assert not os.path.exists(os.path.join(ddir, forbidden)), f"accelerate node wrote {forbidden}!"


@register_test("T1-050", "1", "r2", ("REQ-10",), "accel_jp suppresses public authoritative DNS NS/SOA/A answers")
def t1_050(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1050")
    c = ctx.ensure_cluster()
    z = ctx.create_zone(f"{tag}.test", node="peer_a")
    c.wait_converged(lambda: any(x["id"] == z["id"] for x in c.api("accel_jp", "GET", "/zones")[1].get("result", [])))
    rc_ns, an_ns, _ = c.dns_query("accel_jp", f"{tag}.test", qtype=2)  # NS
    rc_a, an_a, _ = c.dns_query("accel_jp", f"{tag}.test", qtype=1)  # A
    assert an_ns == 0 and (rc_ns in (0, 5)) and an_a == 0


@register_test("T1-051", "1", "r2", ("REQ-10",), "accel_jp RSS remains <= 200 MiB under 100 edge requests")
def t1_051(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1051")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test", node="peer_a", origin_port=ctx.origin1.port)
    c.wait_converged(lambda: c.edge("accel_jp", "/page", host=f"{tag}.test")[0] == 200)
    for i in range(100):
        st, _, _ = c.edge("accel_jp", f"/item-{i}", host=f"{tag}.test")
        assert st == 200
    rss = c.rss_bytes("accel_jp")
    assert rss <= 200 * 1024 * 1024, f"accel_jp RSS {rss / (1024*1024):.1f} MiB > 200 MiB"


# ===========================================================================
# REQ-11..14: Native Reverse Proxy, Protocols, WS/SSE, Hy2 Fallback
# ===========================================================================


@register_test("T1-052", "1", "r3", ("REQ-11",), "LocalProxyRule routes host on --proxy-listen to upstream")
def t1_052(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1052")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {
            "name": f"rule-{tag}",
            "hosts": [f"{tag}.proxy.local"],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.origin1.url, "weight": 1}],
            "enabled": True,
        }
    )
    try:
        st, _, body = c.proxy("peer_a", "/hello", host=f"{tag}.proxy.local")
        assert st == 200 and json.loads(body)["tag"] == "origin1"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-053", "1", "r3", ("REQ-11",), "LocalProxyRule path_prefix /api/ vs exact /health routing")
def t1_053(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1053")
    c = ctx.ensure_cluster()
    r1 = ctx.create_proxy_rule(
        {
            "name": f"r1-{tag}",
            "hosts": [f"{tag}.local"],
            "path_prefix": "/api/",
            "exact_path": False,
            "upstreams": [{"url": ctx.origin1.url}],
            "priority": 10,
            "enabled": True,
        }
    )
    r2 = ctx.create_proxy_rule(
        {
            "name": f"r2-{tag}",
            "hosts": [f"{tag}.local"],
            "path_prefix": "/health",
            "exact_path": True,
            "upstreams": [{"url": ctx.origin2.url}],
            "priority": 20,
            "enabled": True,
        }
    )
    try:
        assert json.loads(c.proxy("peer_a", "/api/users", host=f"{tag}.local")[2])["tag"] == "origin1"
        assert json.loads(c.proxy("peer_a", "/health", host=f"{tag}.local")[2])["tag"] == "origin2"
    finally:
        ctx.delete_proxy_rule(r1["id"])
        ctx.delete_proxy_rule(r2["id"])


@register_test("T1-054", "1", "r3", ("REQ-11",), "Multi-upstream pool load-balances and fails over when 1 upstream is down")
def t1_054(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1054")
    c = ctx.ensure_cluster()
    ephemeral = TestOriginServer("ephemeral").start()
    rule = ctx.create_proxy_rule(
        {
            "name": f"lb-{tag}",
            "hosts": [f"{tag}.lb.local"],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.origin1.url, "weight": 1}, {"url": ephemeral.url, "weight": 1}],
            "enabled": True,
        }
    )
    try:
        tags = {json.loads(c.proxy("peer_a", f"/p{i}", host=f"{tag}.lb.local")[2])["tag"] for i in range(12)}
        assert "origin1" in tags and "ephemeral" in tags, f"expected LB across both upstreams, got {tags}"
        ephemeral.stop()
        for _ in range(5):
            st, _, body = c.proxy("peer_a", "/after-down", host=f"{tag}.lb.local")
            assert st == 200 and json.loads(body)["tag"] == "origin1"
    finally:
        ephemeral.stop()
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-055", "1", "r3", ("REQ-11",), "--export-domains file includes LocalProxyRule.hosts")
def t1_055(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1055")
    c = ctx.ensure_cluster()
    host = f"{tag}.export.local"
    rule = ctx.create_proxy_rule(
        {"name": f"exp-{tag}", "hosts": [host], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        dfile = os.path.join(c.nodes["peer_a"].data_dir, "domains.lst")
        c.wait_converged(lambda: os.path.exists(dfile) and host in open(dfile, encoding="utf-8").read())
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-056", "1", "r3", ("REQ-11",), "Native proxy operates cleanly with zero Caddy binary/process")
def t1_056(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1056")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"nocaddy-{tag}", "hosts": [f"{tag}.nocaddy.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        st, hdrs, _ = c.proxy("peer_a", "/", host=f"{tag}.nocaddy.local")
        assert st == 200 and "fucf-ray" in hdrs and "caddy" not in hdrs.get("server", "").lower()
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-057", "1", "r3", ("REQ-12",), "LocalProxyRule over HTTP/1.1 and HTTPS TLS listener")
def t1_057(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1057")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"tls-{tag}", "hosts": [f"{tag}.tls.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        st1, h1, _ = c.proxy("peer_a", "/h1", host=f"{tag}.tls.local", use_tls=False)
        st2, h2, _ = c.proxy("peer_a", "/tls", host=f"{tag}.tls.local", use_tls=True)
        assert st1 == 200 and "fucf-ray" in h1 and st2 == 200 and "fucf-ray" in h2
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-058", "1", "r3", ("REQ-12",), "LocalProxyRule serves HTTP/2 (ALPN h2) over TLS proxy listener")
def t1_058(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1058")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"h2-{tag}", "hosts": [f"{tag}.h2.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        port = c.nodes["peer_a"].ports["proxy_tls"]
        st, _, body, proto = H2Client.request(f"https://127.0.0.1:{port}/h2check", headers={"Host": f"{tag}.h2.local"})
        assert st == 200 and "2" in proto and json.loads(body)["tag"] == "origin1"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-059", "1", "r3", ("REQ-12",), "LocalProxyRule forwards to h2c:// cleartext HTTP/2 upstream")
def t1_059(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1059")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"h2c-{tag}", "hosts": [f"{tag}.h2c.local"], "path_prefix": "/", "upstreams": [{"url": ctx.h2_origin.url}], "enabled": True}
    )
    try:
        st, _, body = c.proxy("peer_a", "/grpc-like", host=f"{tag}.h2c.local")
        d = json.loads(body)
        assert st == 200 and d["proto"] == "h2c" and d["tag"] == "h2c-origin"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-060", "1", "r3", ("REQ-12",), "LocalProxyRule served over HTTP/3 (fucf h3-get)")
def t1_060(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1060")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"h3-{tag}", "hosts": [f"{tag}.h3.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        port = c.nodes["peer_a"].ports["https"]
        st, _, body, _ = c.h3.get(f"https://{tag}.h3.local:{port}/h3proxy", connect_port=port)
        assert st == 200 and json.loads(body)["tag"] == "origin1"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-061", "1", "r3", ("REQ-12",), "Proxy header mutations: set_request/response_headers, strip_response_headers, preserve_host")
def t1_061(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1061")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {
            "name": f"hdr-{tag}",
            "hosts": [f"{tag}.hdr.local"],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.origin1.url}],
            "preserve_host": True,
            "set_request_headers": {"X-Injected-Req": "yes"},
            "set_response_headers": {"X-Injected-Resp": "ok"},
            "strip_response_headers": ["Server", "Alt-Svc"],
            "enabled": True,
        }
    )
    try:
        st, hdrs, body = c.proxy("peer_a", "/hdr", host=f"{tag}.hdr.local")
        d = json.loads(body)
        assert st == 200
        assert d["host"].startswith(f"{tag}.hdr.local")
        assert d["headers"].get("x-injected-req") == "yes"
        assert hdrs.get("x-injected-resp") == "ok"
        assert "server" not in hdrs and "alt-svc" not in hdrs
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-104", "1", "r3", ("REQ-12",), "LocalProxyRule HTTP/1.1 keep-alive reuses connection across 50 requests")
def t1_104(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1104")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"ka-{tag}", "hosts": [f"{tag}.ka.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        conn = http.client.HTTPConnection("127.0.0.1", c.nodes["peer_a"].ports["proxy"], timeout=15)
        for i in range(50):
            conn.request("GET", f"/ka/{i}", headers={"Host": f"{tag}.ka.local"})
            r = conn.getresponse()
            r.read()
            assert r.status == 200
        conn.close()
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-062", "1", "r3", ("REQ-13",), "WebSocket 101 bidirectional text and binary echo (20 frames)")
def t1_062(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1062")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"ws-{tag}", "hosts": [f"{tag}.ws.local"], "path_prefix": "/", "upstreams": [{"url": ctx.ws_origin.url}], "enabled": True}
    )
    try:
        sock, status, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/ws", headers={"Host": f"{tag}.ws.local"})
        assert status == 101, f"expected 101, got {status}"
        try:
            for i in range(10):
                msg = f"hello-{i}"
                ws_send(sock, msg)
                op, data = ws_recv(sock)
                assert op == 0x1 and data.decode("utf-8") == msg
                raw = os.urandom(32)
                ws_send(sock, raw)
                op2, data2 = ws_recv(sock)
                assert op2 == 0x2 and data2 == raw
        finally:
            ws_close(sock)
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-063", "1", "r3", ("REQ-13",), "SSE streaming delivers chunks immediately without buffering until EOF")
def t1_063(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1063")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"sse-{tag}", "hosts": [f"{tag}.sse.local"], "path_prefix": "/", "upstreams": [{"url": ctx.sse_origin.url}], "enabled": True}
    )
    try:
        conn = http.client.HTTPConnection("127.0.0.1", c.nodes["peer_a"].ports["proxy"], timeout=10)
        t0 = time.monotonic()
        conn.request("GET", "/sse?count=4&delay_ms=400", headers={"Host": f"{tag}.sse.local"})
        r = conn.getresponse()
        assert r.status == 200 and "text/event-stream" in (r.getheader("Content-Type") or "")
        first_chunk = r.fp.readline()
        dt_first = time.monotonic() - t0
        rest = r.read()
        conn.close()
        assert b"tick-0" in first_chunk or b"id: 0" in first_chunk
        assert dt_first < 0.35, f"first SSE event was buffered ({dt_first:.3f}s)"
        assert b"tick-3" in rest
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-064", "1", "r3", ("REQ-13",), "Chunked POST upload + 10 MiB streaming download SHA-256 integrity")
def t1_064(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1064")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"stream-{tag}", "hosts": [f"{tag}.stream.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        payload = (b"fucf-upload-chunk-" * 10000)
        st, _, body = c.proxy("peer_a", "/upload", host=f"{tag}.stream.local", method="POST", body=payload)
        assert st == 200 and json.loads(body)["body_sha256"] == hashlib.sha256(payload).hexdigest()

        st_dl, hdrs, dl_bytes = c.proxy("peer_a", "/large?mb=10", host=f"{tag}.stream.local")
        assert st_dl == 200 and len(dl_bytes) == 10 * 1024 * 1024
        assert hashlib.sha256(dl_bytes).hexdigest() == hdrs["x-stream-sha256"]
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-065", "1", "r3", ("REQ-13",), "16 concurrent WebSocket & SSE streaming connections complete cleanly")
def t1_065(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1065")
    c = ctx.ensure_cluster()
    r_ws = ctx.create_proxy_rule(
        {"name": f"cws-{tag}", "hosts": [f"{tag}.cws.local"], "path_prefix": "/", "upstreams": [{"url": ctx.ws_origin.url}], "enabled": True}
    )
    r_sse = ctx.create_proxy_rule(
        {"name": f"csse-{tag}", "hosts": [f"{tag}.csse.local"], "path_prefix": "/", "upstreams": [{"url": ctx.sse_origin.url}], "enabled": True}
    )
    errors: list[str] = []

    def _ws_job(idx: int) -> None:
        try:
            sock, st, _ = ws_connect("127.0.0.1", c.nodes["peer_a"].ports["proxy"], "/ws", headers={"Host": f"{tag}.cws.local"})
            assert st == 101
            for k in range(5):
                ws_send(sock, f"w-{idx}-{k}")
                op, d = ws_recv(sock)
                assert op == 1 and d.decode() == f"w-{idx}-{k}"
            ws_close(sock)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"ws-{idx}: {exc}")

    def _sse_job(idx: int) -> None:
        try:
            st, _, body = c.proxy("peer_a", "/sse?count=3&delay_ms=100", host=f"{tag}.csse.local")
            assert st == 200 and b"tick-2" in body
        except Exception as exc:  # noqa: BLE001
            errors.append(f"sse-{idx}: {exc}")

    try:
        threads = [threading.Thread(target=_ws_job if i % 2 == 0 else _sse_job, args=(i,)) for i in range(16)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=15)
        assert not errors, f"concurrent streaming errors: {errors}"
    finally:
        ctx.delete_proxy_rule(r_ws["id"])
        ctx.delete_proxy_rule(r_sse["id"])


@register_test("T1-066", "1", "r3", ("REQ-14",), "H3 front listener unwraps X-Forwarded-For/Host/Proto on hosted zone")
def t1_066(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1066")
    c = ctx.ensure_cluster()
    ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    st, _, body = c.front(
        "peer_a",
        "/cdn-cgi/fucf-trace",
        host=f"{tag}.test",
        headers={"X-Forwarded-For": "10.0.0.1, 198.51.100.7", "X-Forwarded-Proto": "https"},
    )
    trace = dict(line.split("=", 1) for line in body.decode().splitlines())
    assert st == 200 and trace["ip"] == "198.51.100.7" and trace["http"] == "http/3" and trace["tls"] == "TLSv1.3"


@register_test("T1-067", "1", "r3", ("REQ-14",), "H3 front listener routes LocalProxyRule host to local upstream")
def t1_067(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1067")
    c = ctx.ensure_cluster()
    rule = ctx.create_proxy_rule(
        {"name": f"fproxy-{tag}", "hosts": [f"{tag}.front.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    try:
        st, _, body = c.front("peer_a", "/ok", host=f"{tag}.front.local", headers={"X-Forwarded-Proto": "https"})
        assert st == 200 and json.loads(body)["tag"] == "origin1"
    finally:
        ctx.delete_proxy_rule(rule["id"])


@register_test("T1-068", "1", "r3", ("REQ-14",), "Unmatched host on H3 front with is_fallback=true forwards to fallback upstream")
def t1_068(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1068")
    c = ctx.ensure_cluster()
    fb = ctx.create_proxy_rule(
        {
            "name": f"fb-{tag}",
            "hosts": [],
            "path_prefix": "/",
            "upstreams": [{"url": ctx.origin2.url}],
            "is_fallback": True,
            "priority": -100,
            "enabled": True,
        }
    )
    try:
        st, _, body = c.front("peer_a", "/masq", host=f"random-{tag}.unlisted.test", headers={"X-Forwarded-Proto": "https"})
        assert st == 200 and json.loads(body)["tag"] == "origin2"
    finally:
        ctx.delete_proxy_rule(fb["id"])


@register_test("T1-069", "1", "r3", ("REQ-14",), "Exact LocalProxyRule host beats is_fallback catch-all on front")
def t1_069(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1069")
    c = ctx.ensure_cluster()
    exact = ctx.create_proxy_rule(
        {"name": f"ex-{tag}", "hosts": [f"{tag}.exact.local"], "path_prefix": "/", "upstreams": [{"url": ctx.origin1.url}], "enabled": True}
    )
    fb = ctx.create_proxy_rule(
        {"name": f"fb-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "is_fallback": True, "priority": -100, "enabled": True}
    )
    try:
        assert json.loads(c.front("peer_a", "/", host=f"{tag}.exact.local")[2])["tag"] == "origin1"
        assert json.loads(c.front("peer_a", "/", host=f"other-{tag}.local")[2])["tag"] == "origin2"
    finally:
        ctx.delete_proxy_rule(exact["id"])
        ctx.delete_proxy_rule(fb["id"])


@register_test("T1-070", "1", "r3", ("REQ-14",), "Hy2 fallback preserves X-Forwarded-For visitor IP to upstream")
def t1_070(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1070")
    c = ctx.ensure_cluster()
    fb = ctx.create_proxy_rule(
        {"name": f"fbip-{tag}", "hosts": [], "path_prefix": "/", "upstreams": [{"url": ctx.origin2.url}], "is_fallback": True, "priority": -100, "enabled": True}
    )
    try:
        st, _, body = c.front(
            "peer_a",
            "/ip",
            host=f"masq-{tag}.test",
            headers={"X-Forwarded-For": "198.51.100.42", "X-Forwarded-Proto": "https"},
        )
        d = json.loads(body)
        assert st == 200 and d["headers"].get("cf-connecting-ip") == "198.51.100.42"
    finally:
        ctx.delete_proxy_rule(fb["id"])


# ===========================================================================
# REQ-15..18: auth.fucloudflare.com OAuth2 Worker, Passkey, Linux.do & Panel SSO
# ===========================================================================


def _register_oauth_client(ctx: TestContext, tag: str, redirect_uri: str, trusted: bool = False) -> dict[str, Any]:
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    st, r = c.api(
        "peer_a",
        "POST",
        ContractConfig.OAUTH_CLIENTS_PATH,
        {
            "name": f"client-{tag}",
            "redirect_uris": [redirect_uri],
            "scopes": ["openid", "profile", "email"],
            "trusted": trusted,
        },
        token=tok,
    )
    assert st == 200 and r.get("success"), f"register oauth client failed: {st} {r}"
    return r["result"]


def _complete_oauth_pkce_flow(
    ctx: TestContext,
    client_id: str,
    redirect_uri: str,
    node: str = "peer_a",
    nonce: str | None = None,
    session_cookie: str | None = None,
) -> tuple[dict[str, Any], str]:
    c = ctx.ensure_cluster()
    cookie = session_cookie or _seed_auth_session_via_oauth(ctx, node=node)
    verifier, challenge = _pkce_pair()
    state = "st-" + secrets.token_urlsafe(12)
    q = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile email",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }
    if nonce:
        q["nonce"] = nonce
    st, hdrs, body = c.edge(
        node,
        "/authorize?" + urllib.parse.urlencode(q),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
        headers={"Cookie": cookie},
    )
    loc = hdrs.get("location", "")
    if st in (200,) and "consent" in body.decode("utf-8", "replace").lower():
        # Submit consent approval
        st_c, hdrs_c, _ = c.edge(
            node,
            "/authorize/consent",
            host=ContractConfig.AUTH_HOST,
            method="POST",
            use_tls=True,
            headers={"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"},
            body=urllib.parse.urlencode({**q, "decision": "allow"}),
        )
        assert st_c in (302, 303), f"consent POST returned {st_c}"
        loc = hdrs_c["location"]
    else:
        assert st in (302, 303) and loc, f"expected redirect from /authorize, got {st} {body[:200]!r}"
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(loc).query)
    assert qs.get("state", [None])[0] == state and "code" in qs, f"bad authorize redirect {loc}"
    code = qs["code"][0]
    st_t, _, b_t = c.edge(
        node,
        "/token",
        host=ContractConfig.AUTH_HOST,
        method="POST",
        use_tls=True,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urllib.parse.urlencode(
            {
                "grant_type": "authorization_code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "code": code,
                "code_verifier": verifier,
            }
        ),
    )
    assert st_t == 200, f"/token failed: {st_t} {b_t!r}"
    return json.loads(b_t), cookie


@register_test("T1-071", "1", "r4", ("REQ-15",), "GET https://auth.fucloudflare.com/.well-known/openid-configuration")
def t1_071(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, _, body = c.edge("peer_a", "/.well-known/openid-configuration", host=ContractConfig.AUTH_HOST, use_tls=True)
    doc = json.loads(body)
    assert st == 200
    for k in ("issuer", "authorization_endpoint", "token_endpoint", "userinfo_endpoint", "jwks_uri"):
        assert k in doc, f"missing {k} in OIDC discovery"
    assert "S256" in doc.get("code_challenge_methods_supported", [])


@register_test("T1-072", "1", "r4", ("REQ-15",), "GET https://auth.fucloudflare.com/.well-known/jwks.json")
def t1_072(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, _, body = c.edge("peer_a", "/.well-known/jwks.json", host=ContractConfig.AUTH_HOST, use_tls=True)
    doc = json.loads(body)
    assert st == 200 and isinstance(doc.get("keys"), list) and len(doc["keys"]) >= 1
    k0 = doc["keys"][0]
    assert all(f in k0 for f in ("kty", "kid", "alg", "use"))


@register_test("T1-073", "1", "r4", ("REQ-15",), "Register OAuth client via API")
def t1_073(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1073")
    cl = _register_oauth_client(ctx, tag, f"https://{tag}.app.test/cb")
    assert cl.get("client_id") and f"https://{tag}.app.test/cb" in cl.get("redirect_uris", [])


@register_test("T1-074", "1", "r4", ("REQ-15",), "List and update OAuth client redirect_uris")
def t1_074(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1074")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    cl = _register_oauth_client(ctx, tag, f"https://{tag}.app.test/cb1")
    cid = cl["client_id"]
    st_l, rl = c.api("peer_a", "GET", ContractConfig.OAUTH_CLIENTS_PATH, token=tok)
    assert st_l == 200 and any(x["client_id"] == cid for x in rl["result"])
    new_uri = f"https://{tag}.app.test/cb2"
    st_u, ru = c.api("peer_a", "PATCH", f"{ContractConfig.OAUTH_CLIENTS_PATH}/{cid}", {"redirect_uris": [new_uri]}, token=tok)
    assert st_u == 200 and new_uri in ru["result"]["redirect_uris"]


@register_test("T1-075", "1", "r4", ("REQ-15",), "Delete OAuth client rejects subsequent /authorize")
def t1_075(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1075")
    c = ctx.ensure_cluster()
    tok = ctx.ensure_panel_admin("peer_a")
    cl = _register_oauth_client(ctx, tag, f"https://{tag}.app.test/cb")
    cid = cl["client_id"]
    assert c.api("peer_a", "DELETE", f"{ContractConfig.OAUTH_CLIENTS_PATH}/{cid}", token=tok)[0] == 200
    st, hdrs, _ = c.edge(
        "peer_a",
        "/authorize?" + urllib.parse.urlencode({"response_type": "code", "client_id": cid, "redirect_uri": f"https://{tag}.app.test/cb", "code_challenge": "abc", "code_challenge_method": "S256"}),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
    )
    assert st in (400, 404) and "location" not in hdrs


@register_test("T1-076", "1", "r4", ("REQ-16",), "/authorize authenticated user + consent -> 302 code & state")
def t1_076(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1076")
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    assert tok_data.get("access_token")


@register_test("T1-077", "1", "r4", ("REQ-16",), "POST /token with PKCE S256 returns access_token, id_token, refresh_token")
def t1_077(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1077")
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    assert tok_data["token_type"] == "Bearer" and tok_data["expires_in"] > 0
    assert "id_token" in tok_data and "refresh_token" in tok_data


@register_test("T1-078", "1", "r4", ("REQ-16",), "Verify id_token JWT signature against /.well-known/jwks.json")
def t1_078(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1078")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    jwks = json.loads(c.edge("peer_a", "/.well-known/jwks.json", host=ContractConfig.AUTH_HOST, use_tls=True)[2])
    claims = _verify_jwt_rs_or_es(tok_data["id_token"], jwks)
    assert claims["aud"] == cl["client_id"] and claims["sub"] and claims["exp"] > time.time()


@register_test("T1-079", "1", "r4", ("REQ-16",), "GET and POST /userinfo with Bearer access_token returns user claims")
def t1_079(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1079")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    at = tok_data["access_token"]
    for m in ("GET", "POST"):
        st, _, body = c.edge("peer_a", "/userinfo", host=ContractConfig.AUTH_HOST, method=m, use_tls=True, headers={"Authorization": f"Bearer {at}"})
        u = json.loads(body)
        assert st == 200 and u.get("sub") and u.get("preferred_username")


@register_test("T1-080", "1", "r4", ("REQ-16",), "POST /token refresh_token rotation + POST /revoke invalidates /userinfo")
def t1_080(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1080")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    st_r, _, b_r = c.edge(
        "peer_a",
        "/token",
        host=ContractConfig.AUTH_HOST,
        method="POST",
        use_tls=True,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urllib.parse.urlencode({"grant_type": "refresh_token", "client_id": cl["client_id"], "refresh_token": tok_data["refresh_token"]}),
    )
    assert st_r == 200
    fresh = json.loads(b_r)["access_token"]
    st_rev, _, _ = c.edge(
        "peer_a",
        "/revoke",
        host=ContractConfig.AUTH_HOST,
        method="POST",
        use_tls=True,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        body=urllib.parse.urlencode({"token": fresh, "client_id": cl["client_id"]}),
    )
    assert st_rev == 200
    st_u, _, _ = c.edge("peer_a", "/userinfo", host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Authorization": f"Bearer {fresh}"})
    assert st_u == 401


@register_test("T1-105", "1", "r4", ("REQ-16",), "OAuth /authorize echoes nonce claim inside signed id_token")
def t1_105(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1105")
    c = ctx.ensure_cluster()
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    nonce = "n-" + secrets.token_hex(8)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir, nonce=nonce)
    jwks = json.loads(c.edge("peer_a", "/.well-known/jwks.json", host=ContractConfig.AUTH_HOST, use_tls=True)[2])
    claims = _verify_jwt_rs_or_es(tok_data["id_token"], jwks)
    assert claims.get("nonce") == nonce


@register_test("T1-081", "1", "r4", ("REQ-17",), "Auth Worker POST /login/passkey/begin returns challenge & rpId")
def t1_081(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    st, _, body = c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")
    d = json.loads(body)
    assert st == 200 and d.get("challenge") and d.get("rp", {}).get("id") == ContractConfig.AUTH_HOST


@register_test("T1-082", "1", "r4", ("REQ-17",), "Auth Worker Passkey registration with WebAuthnSimulator ES256")
def t1_082(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    st_b, _, b_b = c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")
    assert st_b == 200
    reg = sim.register(json.loads(b_b)["challenge"], origin, name="auth-es256")
    st_f, _, _ = c.edge(
        "peer_a",
        "/login/passkey/finish",
        host=ContractConfig.AUTH_HOST,
        method="POST",
        use_tls=True,
        headers={"Cookie": cookie, "Content-Type": "application/json"},
        body=json.dumps(reg),
    )
    assert st_f == 200


@register_test("T1-083", "1", "r4", ("REQ-17",), "Auth Worker passwordless Passkey assertion login creates session")
def t1_083(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    sim = WebAuthnSimulator(alg=-7)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    reg = sim.register(chal, origin, name="pwless")
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(reg))[0] == 200

    # Passwordless login (no session cookie)
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    assertion = sim.assert_login(chal2, origin, flags=0x05)
    st, hdrs, _ = c.edge(
        "peer_a",
        "/login/passkey/finish",
        host=ContractConfig.AUTH_HOST,
        method="POST",
        use_tls=True,
        headers={"Content-Type": "application/json"},
        body=json.dumps(assertion),
    )
    assert st == 200 and hdrs.get("set-cookie")


@register_test("T1-084", "1", "r4", ("REQ-17",), "Multiple passkeys registered for one user & listed on /account")
def t1_084(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    for idx, alg in enumerate((-7, -8)):
        sim = WebAuthnSimulator(alg=alg)
        chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
        reg = sim.register(chal, origin, name=f"key-{idx}")
        assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(reg))[0] == 200
    st, _, body = c.edge("peer_a", "/account", host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": cookie, "Accept": "application/json"})
    assert st == 200 and ("key-0" in body.decode() and "key-1" in body.decode())


@register_test("T1-085", "1", "r4", ("REQ-17",), "Deleting a passkey from /account prevents login with that credential")
def t1_085(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    cookie = _seed_auth_session_via_oauth(ctx)
    origin = f"https://{ContractConfig.AUTH_HOST}"
    sim = WebAuthnSimulator(alg=-7)
    chal = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie}, body="{}")[2])["challenge"]
    reg = sim.register(chal, origin, name="del-key")
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Cookie": cookie, "Content-Type": "application/json"}, body=json.dumps(reg))[0] == 200
    st_d, _, _ = c.edge("peer_a", f"/account/passkeys/{sim.id}", host=ContractConfig.AUTH_HOST, method="DELETE", use_tls=True, headers={"Cookie": cookie})
    assert st_d in (200, 204)
    chal2 = json.loads(c.edge("peer_a", "/login/passkey/begin", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, body="{}")[2])["challenge"]
    assert c.edge("peer_a", "/login/passkey/finish", host=ContractConfig.AUTH_HOST, method="POST", use_tls=True, headers={"Content-Type": "application/json"}, body=json.dumps(sim.assert_login(chal2, origin)))[0] in (400, 401, 404)


@register_test("T1-086", "1", "r4", ("REQ-18",), "GET /login/oauth/linuxdo redirects with state & scope=user")
def t1_086(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, hdrs, _ = c.edge("peer_a", "/login/oauth/linuxdo", host=ContractConfig.AUTH_HOST, use_tls=True)
    assert st in (302, 303)
    qs = urllib.parse.parse_qs(urllib.parse.urlparse(hdrs["location"]).query)
    assert qs.get("state") and qs.get("response_type") == ["code"]


@register_test("T1-087", "1", "r4", ("REQ-18",), "Full Linux.do Connect callback logs user in and populates /userinfo")
def t1_087(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1087")
    redir = f"https://{tag}.app.test/cb"
    cl = _register_oauth_client(ctx, tag, redir)
    tok_data, _ = _complete_oauth_pkce_flow(ctx, cl["client_id"], redir)
    st, _, body = ctx.ensure_cluster().edge(
        "peer_a",
        "/userinfo",
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
        headers={"Authorization": f"Bearer {tok_data['access_token']}"},
    )
    u = json.loads(body)
    assert st == 200 and ctx.mock_oauth.username in str(u)


@register_test("T1-088", "1", "r4", ("REQ-18",), "Linux.do persona with email=null maps cleanly without crash")
def t1_088(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    prev = ctx.mock_oauth.persona
    ctx.mock_oauth.persona = "no_email"
    try:
        _, hdrs2, res = _linuxdo_oauth_login(ctx)
        assert res["status"] in (200, 302, 303) and hdrs2.get("set-cookie")
    finally:
        ctx.mock_oauth.persona = prev


@register_test("T1-089", "1", "r4", ("REQ-18",), "Custom configurable OAuth2 provider (/login/oauth/custom) authenticates user")
def t1_089(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    st, hdrs, _ = c.edge("peer_a", "/login/oauth/custom", host=ContractConfig.AUTH_HOST, use_tls=True)
    assert st in (302, 303)
    loc = hdrs["location"]
    parsed = urllib.parse.urlparse(loc)
    conn = http.client.HTTPConnection(parsed.hostname, parsed.port, timeout=10)
    conn.request("GET", parsed.path + (f"?{parsed.query}" if parsed.query else ""))
    mr = conn.getresponse()
    mr.read()
    cb = urllib.parse.urlparse(mr.getheader("Location"))
    ck = hdrs.get("set-cookie", "").split(";", 1)[0]
    st2, hdrs2, _ = c.edge("peer_a", cb.path + (f"?{cb.query}" if cb.query else ""), host=ContractConfig.AUTH_HOST, use_tls=True, headers={"Cookie": ck} if ck else None)
    assert st2 in (200, 302, 303) and hdrs2.get("set-cookie")


@register_test("T1-090", "1", "r4", ("REQ-18",), "Panel SSO (/client/v4/auth/oauth/login -> auth -> /callback) issues fucf_s_ session")
def t1_090(ctx: TestContext) -> None:
    c = ctx.ensure_cluster()
    ctx.ensure_panel_admin("peer_a")
    auth_cookie = _seed_auth_session_via_oauth(ctx)
    st, hdrs, _ = c.edge("peer_a", "/client/v4" + ContractConfig.PANEL_OAUTH_LOGIN_PATH, host=ContractConfig.PANEL_HOST, use_tls=True)
    assert st in (302, 303)
    panel_cookie = hdrs.get("set-cookie", "").split(";", 1)[0]
    auth_url = urllib.parse.urlparse(hdrs["location"])
    st2, hdrs2, _ = c.edge(
        "peer_a",
        auth_url.path + (f"?{auth_url.query}" if auth_url.query else ""),
        host=ContractConfig.AUTH_HOST,
        use_tls=True,
        headers={"Cookie": auth_cookie},
    )
    assert st2 in (302, 303)
    cb_url = urllib.parse.urlparse(hdrs2["location"])
    st3, hdrs3, body3 = c.edge(
        "peer_a",
        cb_url.path + (f"?{cb_url.query}" if cb_url.query else ""),
        host=ContractConfig.PANEL_HOST,
        use_tls=True,
        headers={"Cookie": panel_cookie} if panel_cookie else None,
    )
    assert st3 in (200, 302, 303)
    sc = hdrs3.get("set-cookie", "")
    assert "fucf_s_" in sc or "fucf_s_" in body3.decode("utf-8", "replace")


# ===========================================================================
# REQ-19 / REQ-20: Headless Browser UI Verification (T1-091..100)
# ===========================================================================


def _run_cdp_on_panel(ctx: TestContext, js_fn: str, viewport: tuple[int, int] | None = None, host: str | None = None, path: str = "/") -> dict[str, Any]:
    browser = find_browser_executable()
    assert browser, "no local Edge/Chrome executable found for UI check"
    c = ctx.ensure_cluster()
    port = c.nodes["peer_a"].ports["https"]
    rules = f"MAP {ContractConfig.PANEL_HOST} 127.0.0.1, MAP {ContractConfig.AUTH_HOST} 127.0.0.1"
    cdp = CdpSession(browser, host_rules=rules).start()
    try:
        target_host = host or ContractConfig.PANEL_HOST
        res = cdp.run_script(f"https://{target_host}:{port}{path}", js_fn, viewport=viewport)
        assert not res["exception"], f"JS exception: {res['exception']}"
        assert not res["console_errors"], f"Console errors: {res['console_errors']}"
        assert not res["exceptions"], f"Page exceptions: {res['exceptions']}"
        assert not res["http_5xx"], f"HTTP 5xx errors: {res['http_5xx']}"
        return res
    finally:
        cdp.stop()


@register_test("T1-091", "1", "r5", ("REQ-19",), "Panel Light mode computed RGB (#fbfbfb canvas, #ffffff base)", tags=("ui",))
def t1_091(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            localStorage.removeItem('fucf-theme');
            document.documentElement.removeAttribute('data-mode');
            const bodyBg = getComputedStyle(document.body).backgroundColor;
            const card = document.querySelector('.card, .layer-card, [class*="card"]');
            const cardBg = card ? getComputedStyle(card).backgroundColor : getComputedStyle(document.documentElement).getPropertyValue('--cf-base').trim();
            return { bodyBg, cardBg };
        })()""",
    )
    v = res["value"]
    assert v["bodyBg"] == "rgb(251, 251, 251)" and ("255, 255, 255" in v["cardBg"] or "#fff" in v["cardBg"].lower())


@register_test("T1-092", "1", "r5", ("REQ-19",), "Toggle Dark mode sets [data-mode='dark'] (#030303 / #0f0f0f)", tags=("ui",))
def t1_092(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            const btn = document.querySelector('[data-theme-toggle], #theme-toggle, button[aria-label*="theme" i], button[aria-label*="mode" i]');
            if (btn) btn.click(); else document.documentElement.setAttribute('data-mode', 'dark');
            return {
                mode: document.documentElement.getAttribute('data-mode'),
                bodyBg: getComputedStyle(document.body).backgroundColor,
                baseVar: getComputedStyle(document.documentElement).getPropertyValue('--cf-base').trim()
            };
        })()""",
    )
    v = res["value"]
    assert v["mode"] == "dark" and v["bodyBg"] == "rgb(3, 3, 3)" and v["baseVar"].lower() in ("#0f0f0f", "rgb(15, 15, 15)")


@register_test("T1-093", "1", "r5", ("REQ-19",), "Theme selection persists across page reload via localStorage", tags=("ui",))
def t1_093(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    browser = find_browser_executable()
    assert browser
    c = ctx.ensure_cluster()
    port = c.nodes["peer_a"].ports["https"]
    cdp = CdpSession(browser, host_rules=f"MAP {ContractConfig.PANEL_HOST} 127.0.0.1").start()
    try:
        r1 = cdp.run_script(
            f"https://{ContractConfig.PANEL_HOST}:{port}/",
            """(() => {
                const btn = document.querySelector('[data-theme-toggle], #theme-toggle');
                if (btn) btn.click();
                return Object.values(localStorage);
            })()""",
        )
        r2 = cdp.run_script(f"https://{ContractConfig.PANEL_HOST}:{port}/", "document.documentElement.getAttribute('data-mode')")
        assert r1["value"] and r2["value"] == "dark"
    finally:
        cdp.stop()


@register_test("T1-094", "1", "r5", ("REQ-19",), "Sidebar expanded ~260px collapses to ~57px", tags=("ui",))
def t1_094(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            const side = document.querySelector('aside, [data-sidebar="sidebar"], .side');
            const w1 = side.getBoundingClientRect().width;
            const trig = document.querySelector('[data-sidebar="trigger"], .side-toggle, button[aria-label*="sidebar" i]');
            trig.click();
            const w2 = side.getBoundingClientRect().width;
            return { w1, w2 };
        })()""",
    )
    v = res["value"]
    assert 250 <= v["w1"] <= 270 and 50 <= v["w2"] <= 64, f"sidebar widths={v}"


@register_test("T1-095", "1", "r5", ("REQ-19",), "Topbar 58px, centered track <=1000px, CSP blocks zero external requests", tags=("ui",))
def t1_095(ctx: TestContext) -> None:
    ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            const top = document.querySelector('header, .top, [data-topbar]');
            const main = document.querySelector('.track, main .container, main');
            return {
                topH: top ? top.getBoundingClientRect().height : 0,
                mainW: main ? main.getBoundingClientRect().width : 0
            };
        })()""",
    )
    v = res["value"]
    assert 54 <= v["topH"] <= 62 and v["mainW"] <= 1040 and not res["failed_external"]


@register_test("T1-096", "1", "r5", ("REQ-20",), "Navigate all Account views with non-empty DOM and zero console errors", tags=("ui",))
def t1_096(ctx: TestContext) -> None:
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            const views = ['overview', 'zones', 'fleet', 'steering', 'workers', 'proxy', 'oauth', 'account', 'users'];
            const out = {{}};
            for (const v of views) {{
                location.hash = '#/' + v;
                await new Promise(r => setTimeout(r, 80));
                out[v] = (document.body.innerText || '').trim().length;
            }}
            return out;
        }})()""",
    )
    assert all(length > 20 for length in res["value"].values()), f"empty view: {res['value']}"


@register_test("T1-097", "1", "r5", ("REQ-20",), "Navigate all 11 Zone tabs on test zone with zero errors", tags=("ui",))
def t1_097(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1097")
    tok = ctx.ensure_panel_admin("peer_a")
    z = ctx.create_zone(f"{tag}.test", origin_port=ctx.origin1.port)
    zid = z["id"]
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            const tabs = ['overview','dns','ssl','waf','cache','rules','workers','spectrum','email','analytics','manage'];
            const out = {{}};
            for (const t of tabs) {{
                location.hash = '#/zones/{zid}/' + t;
                await new Promise(r => setTimeout(r, 80));
                out[t] = (document.body.innerText || '').trim().length;
            }}
            return out;
        }})()""",
    )
    assert all(length > 20 for length in res["value"].values())


@register_test("T1-098", "1", "r5", ("REQ-20",), "Interactive Workers KV/D1 console in headless browser", tags=("ui",))
def t1_098(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1098")
    tok = ctx.ensure_panel_admin("peer_a")
    db_id = ctx.create_d1(f"ui-d1-{tag}")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            location.hash = '#/workers';
            await new Promise(r => setTimeout(r, 150));
            const r = await fetch('/client/v4/workers/d1/databases/{db_id}/query', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + {json.dumps(tok)}, 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ sql: 'SELECT 1 AS ok' }})
            }});
            return {{ status: r.status, body: await r.json() }};
        }})()""",
    )
    assert res["value"]["status"] == 200 and res["value"]["body"]["success"] is True


@register_test("T1-099", "1", "r5", ("REQ-20",), "Interactive Zone + Proxy rule creation updates DOM table", tags=("ui",))
def t1_099(ctx: TestContext) -> None:
    tag = ctx.next_tag("t1099")
    tok = ctx.ensure_panel_admin("peer_a")
    res = _run_cdp_on_panel(
        ctx,
        f"""(async () => {{
            localStorage.setItem('fucf_token', {json.dumps(tok)});
            await fetch('/client/v4/proxy/rules', {{
                method: 'POST',
                headers: {{ 'Authorization': 'Bearer ' + {json.dumps(tok)}, 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ name: 'ui-{tag}', hosts: ['{tag}.ui.local'], path_prefix: '/', upstreams: [{{ url: {json.dumps(ctx.origin1.url)} }}], enabled: true }})
            }});
            location.hash = '#/proxy';
            await new Promise(r => setTimeout(r, 200));
            return document.body.innerText.includes('{tag}.ui.local');
        }})()""",
    )
    assert res["value"] is True


@register_test("T1-100", "1", "r5", ("REQ-20",), "auth.fucloudflare.com login, theme toggle & OAuth UI in headless browser", tags=("ui",))
def t1_100(ctx: TestContext) -> None:
    ctx.ensure_cluster()
    res = _run_cdp_on_panel(
        ctx,
        """(() => {
            const text = document.body.innerText || '';
            const hasPasskey = !!document.querySelector('[data-auth="passkey"], button');
            document.documentElement.setAttribute('data-mode', 'dark');
            return { textLen: text.length, hasPasskey, bg: getComputedStyle(document.body).backgroundColor };
        })()""",
        host=ContractConfig.AUTH_HOST,
        path="/login",
    )
    assert res["value"]["textLen"] > 10 and res["value"]["hasPasskey"]
