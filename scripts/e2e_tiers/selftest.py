"""Offline self-verification of test helpers, simulators, and 4-tier test matrix.

Never mocks `fucf` itself; verifies only test infrastructure and matrix invariants.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import ssl
import urllib.parse

from . import load_all_tiers
from .harness import (
    H2OriginServer,
    MockOAuthServer,
    SseOriginServer,
    TestOriginServer,
    WebAuthnSimulator,
    WsEchoServer,
    b64u_decode,
    cbor_encode,
    free_port,
    rss_bytes,
    ws_close,
    ws_connect,
    ws_recv,
    ws_send,
)


def _check_matrix() -> None:
    tests = load_all_tiers()
    ids = [t.id for t in tests]
    assert len(ids) == len(set(ids)), "duplicate test IDs found!"

    by_tier = {"1": 0, "2": 0, "3": 0, "4": 0}
    reqs_by_tier: dict[str, set[str]] = {"1": set(), "2": set(), "3": set(), "4": set()}
    for t in tests:
        by_tier[t.tier] += 1
        reqs_by_tier[t.tier].update(t.reqs)

    assert by_tier["1"] == 105 and by_tier["1"] >= 100, f"Tier 1 count={by_tier['1']}"
    assert by_tier["2"] == 105 and by_tier["2"] >= 100, f"Tier 2 count={by_tier['2']}"
    assert by_tier["3"] == 24 and by_tier["3"] >= 20, f"Tier 3 count={by_tier['3']}"
    assert by_tier["4"] == 12 and by_tier["4"] >= 10, f"Tier 4 count={by_tier['4']}"
    assert len(tests) == 246, f"Total new tests={len(tests)}"

    expected_reqs = {f"REQ-{i:02d}" for i in range(1, 21)}
    for tier in ("1", "2", "3"):
        missing = expected_reqs - reqs_by_tier[tier]
        assert not missing, f"Tier {tier} missing requirements: {sorted(missing)}"
    print(f"  ok   matrix verified: T1={by_tier['1']} T2={by_tier['2']} T3={by_tier['3']} T4={by_tier['4']} (total={len(tests)}, all 20 REQs covered)")


def _check_cbor_and_webauthn() -> None:
    enc = cbor_encode({"fmt": "none", "attStmt": {}, "n": 1, "neg": -7, "b": b"\x01\x02", "arr": [True, False, None]})
    assert isinstance(enc, bytes) and len(enc) > 10

    for alg in (-7, -8, -257):
        sim = WebAuthnSimulator(alg=alg)
        origin = "https://auth.fucloudflare.com"
        reg = sim.register("chal-reg-123", origin, flags=0x45, name=f"key-{alg}")
        assert reg["alg"] == alg
        ad_reg = b64u_decode(reg["authenticator_data"])
        assert ad_reg[:32] == hashlib.sha256(b"auth.fucloudflare.com").digest()
        assert (ad_reg[32] & 0x45) == 0x45

        a = sim.assert_login("chal-auth-456", origin, flags=0x05)
        ad = b64u_decode(a["authenticator_data"])
        cd = b64u_decode(a["client_data"])
        sig = b64u_decode(a["signature"])
        assert WebAuthnSimulator.verify_assertion(sim.spki_der, alg, ad, cd, sig)

        bad = sim.assert_login("chal-auth-456", origin, tamper_sig=True)
        assert not WebAuthnSimulator.verify_assertion(
            sim.spki_der,
            alg,
            b64u_decode(bad["authenticator_data"]),
            b64u_decode(bad["client_data"]),
            b64u_decode(bad["signature"]),
        )
    print("  ok   CBOR encoder & WebAuthnSimulator (ES256, Ed25519, RS256) verified")


def _check_mock_oauth() -> None:
    srv = MockOAuthServer().start()
    try:
        conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=5)
        redir = "https://auth.fucloudflare.com/login/oauth/linuxdo/callback"
        q = urllib.parse.urlencode({"client_id": srv.client_id, "redirect_uri": redir, "response_type": "code", "state": "st1"})
        conn.request("GET", "/oauth2/authorize?" + q)
        r = conn.getresponse()
        r.read()
        assert r.status == 302
        code = urllib.parse.parse_qs(urllib.parse.urlparse(r.getheader("Location")).query)["code"][0]

        basic = base64.b64encode(f"{srv.client_id}:{srv.client_secret}".encode()).decode()
        body = urllib.parse.urlencode({"grant_type": "authorization_code", "code": code, "redirect_uri": redir})
        conn.request("POST", "/oauth2/token", body=body, headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
        rt = conn.getresponse()
        tok = json.loads(rt.read())
        assert rt.status == 200 and tok["access_token"]

        # Replay code rejected
        conn.request("POST", "/oauth2/token", body=body, headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
        rt2 = conn.getresponse()
        assert rt2.status == 400 and json.loads(rt2.read())["error"] == "invalid_grant"

        conn.request("GET", "/api/user", headers={"Authorization": f"Bearer {tok['access_token']}"})
        ru = conn.getresponse()
        u = json.loads(ru.read())
        assert ru.status == 200 and u["username"] == srv.username and u["email"] == srv.email

        # Test no_email and silenced personas
        srv.persona = "no_email"
        conn.request("GET", "/oauth2/authorize?" + q)
        r_ne = conn.getresponse()
        r_ne.read()
        c_ne = urllib.parse.parse_qs(urllib.parse.urlparse(r_ne.getheader("Location")).query)["code"][0]
        conn.request("POST", "/oauth2/token", body=urllib.parse.urlencode({"grant_type": "authorization_code", "code": c_ne, "redirect_uri": redir}), headers={"Authorization": f"Basic {basic}", "Content-Type": "application/x-www-form-urlencoded"})
        t_ne = json.loads(conn.getresponse().read())["access_token"]
        conn.request("GET", "/api/user", headers={"Authorization": f"Bearer {t_ne}"})
        assert "email" not in json.loads(conn.getresponse().read())

        srv.persona = "deny"
        conn.request("GET", "/oauth2/authorize?" + q)
        r_deny = conn.getresponse()
        r_deny.read()
        assert r_deny.status == 302 and "error=access_denied" in r_deny.getheader("Location")
        conn.close()
    finally:
        srv.stop()
    print("  ok   MockOAuthServer (authorize, Basic token, replay reject, personas) verified")


def _check_origins_and_ws_and_sse() -> None:
    o1 = TestOriginServer("o1").start()
    o_tls = TestOriginServer("otls", use_tls=True).start()
    ws_srv = WsEchoServer("ws1").start()
    sse_srv = SseOriginServer("sse1").start()
    h2_srv = H2OriginServer("h2c1").start()
    try:
        c = http.client.HTTPConnection("127.0.0.1", o1.port, timeout=5)
        c.request("GET", "/large?mb=1")
        r = c.getresponse()
        data = r.read()
        assert r.status == 200 and hashlib.sha256(data).hexdigest() == r.getheader("X-Stream-SHA256")
        c.close()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ct = http.client.HTTPSConnection("127.0.0.1", o_tls.port, timeout=5, context=ctx)
        ct.request("GET", "/ping")
        rt = ct.getresponse()
        assert rt.status == 200 and json.loads(rt.read())["tag"] == "otls"
        ct.close()

        sock, st, _ = ws_connect("127.0.0.1", ws_srv.port, "/echo")
        assert st == 101
        ws_send(sock, "selftest-msg")
        op, payload = ws_recv(sock)
        assert op == 1 and payload == b"selftest-msg"
        ws_close(sock)

        sock403, st403, _ = ws_connect("127.0.0.1", ws_srv.port, "/reject-403")
        sock403.close()
        assert st403 == 403

        cs = http.client.HTTPConnection("127.0.0.1", sse_srv.port, timeout=5)
        cs.request("GET", "/sse?count=2&delay_ms=20")
        rs = cs.getresponse()
        assert rs.status == 200 and b"tick-1-sse1" in rs.read()
        cs.close()

        assert h2_srv.port > 0 and free_port(dual_udp=True) > 0
        assert rss_bytes(os.getpid()) > 0
    finally:
        o1.stop()
        o_tls.stop()
        ws_srv.stop()
        sse_srv.stop()
        h2_srv.stop()
    print("  ok   TestOriginServer (HTTP/TLS/stream), WsEchoServer, SseOriginServer, H2OriginServer, rss_bytes verified")


def run_selftest() -> int:
    print("running e2e_tiers.selftest...")
    _check_matrix()
    _check_cbor_and_webauthn()
    _check_mock_oauth()
    _check_origins_and_ws_and_sse()
    print("e2e_tiers.selftest: ALL OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(run_selftest())
