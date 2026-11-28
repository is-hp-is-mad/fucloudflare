import test from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker from "./worker.js";

function makeKv() {
  const store = new Map();
  return {
    async get(key, opts) {
      const entry = store.get(String(key));
      if (!entry) return null;
      if (entry.exp && Date.now() / 1000 > entry.exp) {
        store.delete(String(key));
        return null;
      }
      const type = typeof opts === "string" ? opts : (opts && opts.type) || "text";
      if (type === "json") return JSON.parse(entry.val);
      return entry.val;
    },
    async put(key, val, opts = {}) {
      if (opts.expirationTtl !== undefined && opts.expirationTtl < 60) {
        throw new Error("KV expirationTtl must be >= 60");
      }
      const exp = opts.expirationTtl ? Date.now() / 1000 + opts.expirationTtl : null;
      store.set(String(key), { val: String(val), exp, metadata: opts.metadata || null });
    },
    async delete(key) {
      store.delete(String(key));
    },
    async list({ prefix = "" } = {}) {
      const keys = [];
      for (const k of store.keys()) {
        if (k.startsWith(prefix)) keys.push({ name: k });
      }
      return { keys, list_complete: true };
    },
  };
}

function makeD1() {
  const db = new DatabaseSync(":memory:");
  class Stmt {
    constructor(sql, params = []) {
      this.sql = sql;
      this.params = params;
    }
    bind(...vals) {
      for (const v of vals) {
        if (v === undefined) throw new TypeError("D1_TYPE_ERROR: undefined not supported");
      }
      return new Stmt(this.sql, vals);
    }
    async first(col) {
      const row = db.prepare(this.sql).get(...this.params);
      if (!row) return null;
      return col ? row[col] : Object.assign({}, row);
    }
    async run() {
      const upper = this.sql.trim().toUpperCase();
      if (upper.startsWith("SELECT")) {
        const results = db.prepare(this.sql).all(...this.params).map((r) => Object.assign({}, r));
        return { results, success: true, meta: {} };
      }
      const info = db.prepare(this.sql).run(...this.params);
      return { results: [], success: true, meta: { changes: info.changes } };
    }
    async all() {
      return this.run();
    }
  }
  let execCalls = 0;
  return {
    get execCalls() { return execCalls; },
    prepare(sql) {
      return new Stmt(sql);
    },
    async exec(sql) {
      execCalls++;
      db.exec(sql);
      return { count: 1 };
    },
  };
}

function makeEnv(extra = {}) {
  return Object.assign(
    {
      AUTH_KV: makeKv(),
      AUTH_DB: makeD1(),
      LINUXDO_CLIENT_ID: "ld-client-123",
      LINUXDO_CLIENT_SECRET: "ld-secret-456",
    },
    extra
  );
}

function extractCookie(res, name) {
  const sc = res.headers.get("set-cookie") || "";
  const m = new RegExp(name + "=([^;]+)").exec(sc);
  return m ? `${name}=${m[1]}` : "";
}

async function sha256B64u(str) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(str));
  return Buffer.from(digest).toString("base64url");
}

function p1363ToDer(sig64) {
  const encodeInt = (bytes) => {
    let i = 0;
    while (i < bytes.length - 1 && bytes[i] === 0) i++;
    let s = bytes.subarray(i);
    if (s[0] & 0x80) s = Buffer.concat([Buffer.from([0]), s]);
    return Buffer.concat([Buffer.from([0x02, s.length]), s]);
  };
  const r = encodeInt(Buffer.from(sig64.subarray(0, 32)));
  const s = encodeInt(Buffer.from(sig64.subarray(32, 64)));
  return Buffer.concat([Buffer.from([0x30, r.length + s.length]), r, s]);
}

function encodeCborAttestation(authData) {
  // CBOR map { "fmt": "none", "attStmt": {}, "authData": bstr }
  const encStr = (s) => {
    const b = Buffer.from(s, "utf8");
    return Buffer.concat([Buffer.from([0x60 | b.length]), b]);
  };
  const lenHdr = (major, len) => {
    if (len < 24) return Buffer.from([(major << 5) | len]);
    if (len < 256) return Buffer.from([(major << 5) | 24, len]);
    return Buffer.from([(major << 5) | 25, len >> 8, len & 0xff]);
  };
  return Buffer.concat([
    Buffer.from([0xa3]),
    encStr("fmt"), encStr("none"),
    encStr("attStmt"), Buffer.from([0xa0]),
    encStr("authData"), lenHdr(2, authData.length), authData,
  ]);
}

function encodeCoseP256(x, y) {
  // CBOR map { 1: 2, 3: -7, -1: 1, -2: bstr(32), -3: bstr(32) }
  return Buffer.concat([
    Buffer.from([0xa5]),
    Buffer.from([0x01, 0x02]), // 1: 2 (EC2)
    Buffer.from([0x03, 0x26]), // 3: -7 (ES256)
    Buffer.from([0x20, 0x01]), // -1: 1 (P-256)
    Buffer.from([0x21, 0x58, 0x20]), Buffer.from(x), // -2: x
    Buffer.from([0x22, 0x58, 0x20]), Buffer.from(y), // -3: y
  ]);
}

test("OIDC discovery and JWKS endpoints", async () => {
  const env = makeEnv();
  const discRes = await worker.fetch(new Request("https://auth.fucloudflare.com/.well-known/openid-configuration"), env, {});
  assert.equal(discRes.status, 200);
  const disc = await discRes.json();
  assert.equal(disc.issuer, "https://auth.fucloudflare.com");
  assert.equal(disc.authorization_endpoint, "https://auth.fucloudflare.com/authorize");
  assert.equal(disc.token_endpoint, "https://auth.fucloudflare.com/token");
  assert.equal(disc.userinfo_endpoint, "https://auth.fucloudflare.com/userinfo");
  assert.deepEqual(disc.code_challenge_methods_supported, ["S256"]);

  const jwksRes = await worker.fetch(new Request("https://auth.fucloudflare.com/.well-known/jwks.json"), env, {});
  assert.equal(jwksRes.status, 200);
  const jwks = await jwksRes.json();
  assert.equal(jwks.keys.length, 1);
  assert.equal(jwks.keys[0].kty, "EC");
  assert.equal(jwks.keys[0].crv, "P-256");
  assert.equal(jwks.keys[0].alg, "ES256");
});

test("Register, password login, OAuth2 PKCE authorize -> token -> userinfo -> refresh -> revoke", async () => {
  const env = makeEnv();

  // Register
  const regRes = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: "alice@example.com",
      username: "alice",
      name: "Alice",
      password: "super-secret-password",
    }),
  }), env, {});
  assert.equal(regRes.status, 201);
  const cookie = extractCookie(regRes, "fucf_auth_sid");
  assert.ok(cookie.startsWith("fucf_auth_sid="));

  // Duplicate register -> 409
  const dupRes = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "alice@example.com", username: "alice2", password: "super-secret-password" }),
  }), env, {});
  assert.equal(dupRes.status, 409);

  // Wrong password -> 401
  const badPwRes = await worker.fetch(new Request("https://auth.fucloudflare.com/login/password", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: "alice", password: "wrong" }),
  }), env, {});
  assert.equal(badPwRes.status, 401);

  // Authorize with PKCE S256
  const codeVerifier = "verifier-random-string-1234567890-abcdef";
  const codeChallenge = await sha256B64u(codeVerifier);
  const authUrl = new URL("https://auth.fucloudflare.com/authorize");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", "dashboard-fucloudflare");
  authUrl.searchParams.set("redirect_uri", "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback");
  authUrl.searchParams.set("scope", "openid profile email offline_access");
  authUrl.searchParams.set("state", "st-xyz");
  authUrl.searchParams.set("nonce", "nonce-123");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const authRes = await worker.fetch(new Request(authUrl.toString(), { headers: { cookie } }), env, {});
  assert.equal(authRes.status, 302);
  const redirLoc = new URL(authRes.headers.get("location"));
  assert.equal(redirLoc.origin, "https://dashboard.fucloudflare.com");
  assert.equal(redirLoc.searchParams.get("state"), "st-xyz");
  const code = redirLoc.searchParams.get("code");
  assert.ok(code);

  // Wrong PKCE verifier -> 400
  const badTokRes = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      client_id: "dashboard-fucloudflare",
      redirect_uri: "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback",
      code_verifier: "wrong-verifier",
    }).toString(),
  }), env, {});
  assert.equal(badTokRes.status, 400);

  // Note: code is single-use, so re-authorize for valid exchange
  const authRes2 = await worker.fetch(new Request(authUrl.toString(), { headers: { cookie } }), env, {});
  const code2 = new URL(authRes2.headers.get("location")).searchParams.get("code");

  const tokRes = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code2,
      client_id: "dashboard-fucloudflare",
      redirect_uri: "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback",
      code_verifier: codeVerifier,
    }).toString(),
  }), env, {});
  assert.equal(tokRes.status, 200);
  const tokens = await tokRes.json();
  assert.ok(tokens.access_token);
  assert.ok(tokens.id_token);
  assert.ok(tokens.refresh_token);
  assert.equal(tokens.token_type, "Bearer");

  // Userinfo
  const uiRes = await worker.fetch(new Request("https://auth.fucloudflare.com/userinfo", {
    headers: { authorization: "Bearer " + tokens.access_token },
  }), env, {});
  assert.equal(uiRes.status, 200);
  const ui = await uiRes.json();
  assert.equal(ui.email, "alice@example.com");
  assert.equal(ui.preferred_username, "alice");

  // Refresh token
  const rtRes = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: tokens.refresh_token,
      client_id: "dashboard-fucloudflare",
    }).toString(),
  }), env, {});
  assert.equal(rtRes.status, 200);
  const rtTokens = await rtRes.json();
  assert.ok(rtTokens.access_token);
  assert.notEqual(rtTokens.refresh_token, tokens.refresh_token);

  // Revoke access token & verify userinfo returns 401
  const revRes = await worker.fetch(new Request("https://auth.fucloudflare.com/revoke", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ token: rtTokens.access_token }).toString(),
  }), env, {});
  assert.equal(revRes.status, 200);

  const uiRevoked = await worker.fetch(new Request("https://auth.fucloudflare.com/userinfo", {
    headers: { authorization: "Bearer " + rtTokens.access_token },
  }), env, {});
  assert.equal(uiRevoked.status, 401);
});

test("Passkey WebAuthn registration and assertion", async () => {
  const env = makeEnv();
  const regRes = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "bob@example.com", username: "bob", password: "password1234" }),
  }), env, {});
  const cookie = extractCookie(regRes, "fucf_auth_sid");

  // Begin passkey registration
  const beginReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/begin", {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: "{}",
  }), env, {});
  assert.equal(beginReg.status, 200);
  const regOpts = await beginReg.json();

  // Generate ECDSA P-256 keypair simulating authenticator
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const x = rawPub.subarray(1, 33);
  const y = rawPub.subarray(33, 65);
  const cose = encodeCoseP256(x, y);
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const rpHash = Buffer.from(await crypto.subtle.digest("SHA-256", Buffer.from("auth.fucloudflare.com")));
  const flags = Buffer.from([0x41]); // UP + AT
  const signCount = Buffer.from([0, 0, 0, 1]);
  const aaguid = Buffer.alloc(16);
  const credIdLen = Buffer.from([0, credId.length]);
  const authData = Buffer.concat([rpHash, flags, signCount, aaguid, credIdLen, credId, cose]);
  const attestationObject = encodeCborAttestation(authData);

  const clientDataReg = Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge: regOpts.publicKey.challenge,
    origin: "https://auth.fucloudflare.com",
  }));

  const finReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/finish", {
    method: "POST",
    headers: { cookie, "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: regOpts.challenge_id,
      name: "Test YubiKey",
      response: {
        clientDataJSON: clientDataReg.toString("base64url"),
        attestationObject: attestationObject.toString("base64url"),
      },
    }),
  }), env, {});
  assert.equal(finReg.status, 200);
  const finRegJson = await finReg.json();
  assert.equal(finRegJson.ok, true);

  // Begin passkey login
  const beginLogin = await worker.fetch(new Request("https://auth.fucloudflare.com/login/passkey/begin", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: "{}",
  }), env, {});
  assert.equal(beginLogin.status, 200);
  const loginOpts = await beginLogin.json();

  const clientDataAuth = Buffer.from(JSON.stringify({
    type: "webauthn.get",
    challenge: loginOpts.publicKey.challenge,
    origin: "https://auth.fucloudflare.com",
  }));
  const authDataLogin = Buffer.concat([rpHash, Buffer.from([0x01]), Buffer.from([0, 0, 0, 2])]);
  const clientHash = Buffer.from(await crypto.subtle.digest("SHA-256", clientDataAuth));
  const signedBytes = Buffer.concat([authDataLogin, clientHash]);
  const sig64 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, signedBytes));
  const sigDer = p1363ToDer(sig64);

  const finLogin = await worker.fetch(new Request("https://auth.fucloudflare.com/login/passkey/finish", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: loginOpts.challenge_id,
      rawId: Buffer.from(credId).toString("base64url"),
      response: {
        clientDataJSON: clientDataAuth.toString("base64url"),
        authenticatorData: authDataLogin.toString("base64url"),
        signature: sigDer.toString("base64url"),
      },
    }),
  }), env, {});
  assert.equal(finLogin.status, 200);
  const pkCookie = extractCookie(finLogin, "fucf_auth_sid");
  assert.ok(pkCookie.startsWith("fucf_auth_sid="));
});

test("Linux.do Connect OAuth2 login and account page Kumo UI + CSP", async () => {
  const env = makeEnv();
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u === "https://connect.linux.do/oauth2/token") {
      return new Response(JSON.stringify({ access_token: "ld-access-tok" }), { status: 200 });
    }
    if (u === "https://connect.linux.do/api/user") {
      return new Response(JSON.stringify({
        id: 4242,
        username: "linuxdoer",
        name: "LinuxDo User",
        email: "ld@example.com",
        avatar_template: "/user_avatar/linux.do/linuxdoer/{size}/1.png",
      }), { status: 200 });
    }
    throw new Error("Unexpected fetch: " + u);
  };

  try {
    const startRes = await worker.fetch(new Request("https://auth.fucloudflare.com/login/oauth/linuxdo?return_to=%2Faccount"), env, {});
    assert.equal(startRes.status, 302);
    const loc = new URL(startRes.headers.get("location"));
    assert.equal(loc.origin, "https://connect.linux.do");
    const state = loc.searchParams.get("state");
    assert.ok(state);

    const cbRes = await worker.fetch(new Request(`https://auth.fucloudflare.com/login/oauth/linuxdo/callback?code=ldcode&state=${state}`), env, {});
    assert.equal(cbRes.status, 302);
    const cookie = extractCookie(cbRes, "fucf_auth_sid");
    assert.ok(cookie.startsWith("fucf_auth_sid="));

    const accRes = await worker.fetch(new Request("https://auth.fucloudflare.com/account", { headers: { cookie } }), env, {});
    assert.equal(accRes.status, 200);
    const csp = accRes.headers.get("content-security-policy") || "";
    assert.ok(csp.includes("frame-ancestors 'none'"));
    const html = await accRes.text();
    assert.ok(html.includes("LinuxDo User"));
    assert.ok(html.includes("data-mode"));
    assert.ok(html.includes("#d97757"), "the panel's clay accent");
    assert.ok(html.includes('data-l="zh"') && html.includes('data-l="en"'), "both languages");
    assert.ok(html.includes("通行密钥") && html.includes("Passkeys"));
  } finally {
    globalThis.fetch = origFetch;
  }
});

test("Consent flow, edge cases, confidential client Basic auth, account management & logout", async () => {
  const env = makeEnv();

  // Register user
  const regRes = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "carol@example.com", username: "carol", password: "password1234" }),
  }), env, {});
  const cookie = extractCookie(regRes, "fucf_auth_sid");

  // Insert an untrusted confidential client
  const secretHashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode("top-secret"));
  const secretHash = Buffer.from(secretHashBuf).toString("hex");
  await env.AUTH_DB.prepare(
    "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, require_pkce, trusted, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?)"
  ).bind("app-untrusted", secretHash, "Untrusted App", JSON.stringify(["https://app.example.com/cb"]), "openid email", 1000).run();

  // Unknown client -> 400
  const unkRes = await worker.fetch(new Request("https://auth.fucloudflare.com/authorize?response_type=code&client_id=nope&redirect_uri=https://app.example.com/cb"), env, {});
  assert.equal(unkRes.status, 400);

  // Unregistered redirect_uri -> 400
  const badRedir = await worker.fetch(new Request("https://auth.fucloudflare.com/authorize?response_type=code&client_id=app-untrusted&redirect_uri=https://evil.example.com/cb"), env, {});
  assert.equal(badRedir.status, 400);

  // Missing PKCE -> 302 error=invalid_request
  const noPkce = await worker.fetch(new Request("https://auth.fucloudflare.com/authorize?response_type=code&client_id=app-untrusted&redirect_uri=https://app.example.com/cb&state=s1"), env, {});
  assert.equal(noPkce.status, 302);
  assert.equal(new URL(noPkce.headers.get("location")).searchParams.get("error"), "invalid_request");

  // prompt=none when logged out -> 302 error=login_required
  const codeVerifier = "carol-verifier-1234567890-abcdef";
  const codeChallenge = await sha256B64u(codeVerifier);
  const promptNone = await worker.fetch(new Request(`https://auth.fucloudflare.com/authorize?response_type=code&client_id=app-untrusted&redirect_uri=https://app.example.com/cb&code_challenge=${codeChallenge}&code_challenge_method=S256&prompt=none&state=s2`), env, {});
  assert.equal(promptNone.status, 302);
  assert.equal(new URL(promptNone.headers.get("location")).searchParams.get("error"), "login_required");

  // Logged-in untrusted client -> renders consent page
  const consentPageRes = await worker.fetch(new Request(`https://auth.fucloudflare.com/authorize?response_type=code&client_id=app-untrusted&redirect_uri=https://app.example.com/cb&code_challenge=${codeChallenge}&code_challenge_method=S256&state=s3`, {
    headers: { cookie },
  }), env, {});
  assert.equal(consentPageRes.status, 200);
  const consentHtml = await consentPageRes.text();
  assert.ok(consentHtml.includes("Authorize Untrusted App"));
  const m = /name="pending_id"\s+value="([^"]+)"/.exec(consentHtml);
  assert.ok(m);
  const pendingId = m[1];

  // Submit consent allow
  const allowRes = await worker.fetch(new Request("https://auth.fucloudflare.com/authorize/consent", {
    method: "POST",
    headers: { cookie, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ pending_id: pendingId, decision: "allow" }).toString(),
  }), env, {});
  assert.equal(allowRes.status, 302);
  const code = new URL(allowRes.headers.get("location")).searchParams.get("code");
  assert.ok(code);

  // Token exchange using Basic auth
  const basic = Buffer.from("app-untrusted:top-secret").toString("base64");
  const tokRes = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: {
      authorization: "Basic " + basic,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.example.com/cb",
      code_verifier: codeVerifier,
    }).toString(),
  }), env, {});
  assert.equal(tokRes.status, 200);

  // Replay code -> 400 invalid_grant
  const replayRes = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: {
      authorization: "Basic " + basic,
      "content-type": "application/x-www-form-urlencoded",
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: "https://app.example.com/cb",
      code_verifier: codeVerifier,
    }).toString(),
  }), env, {});
  assert.equal(replayRes.status, 400);

  // Login page check
  const loginRes = await worker.fetch(new Request("https://auth.fucloudflare.com/login"), env, {});
  assert.equal(loginRes.status, 200);
  const loginHtml = await loginRes.text();
  assert.ok(loginHtml.includes("Continue with Linux.do Connect"));

  // Logout clears session
  const logoutRes = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "POST",
    headers: { cookie, accept: "application/json" },
  }), env, {});
  assert.equal(logoutRes.status, 200);
  const accAfterLogout = await worker.fetch(new Request("https://auth.fucloudflare.com/account", { headers: { cookie } }), env, {});
  assert.equal(accAfterLogout.status, 302);
});

test("Security & OAuth2 regressions: SSO pending return_to, open redirect, refresh client auth, scope escalation, schema exec once, identity conflict", async () => {
  const env = makeEnv();

  // 1. ensureSchema only runs db.exec once even across multiple requests
  await worker.fetch(new Request("https://auth.fucloudflare.com/.well-known/openid-configuration"), env, {});
  await worker.fetch(new Request("https://auth.fucloudflare.com/.well-known/jwks.json"), env, {});
  assert.equal(env.AUTH_DB.execCalls, 1);

  // 2. /authorize while logged out preserves pending_id in Linux.do OAuth button
  const codeVerifier = "sso-verifier-1234567890-abcdef";
  const codeChallenge = await sha256B64u(codeVerifier);
  const authUrl = new URL("https://auth.fucloudflare.com/authorize");
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", "dashboard-fucloudflare");
  authUrl.searchParams.set("redirect_uri", "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback");
  authUrl.searchParams.set("scope", "openid profile email");
  authUrl.searchParams.set("state", "sso-st");
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  const loginPromptRes = await worker.fetch(new Request(authUrl.toString()), env, {});
  assert.equal(loginPromptRes.status, 200);
  const loginPromptHtml = await loginPromptRes.text();
  const ldHrefMatch = /href="(\/login\/oauth\/linuxdo\?[^"]+)"/.exec(loginPromptHtml);
  assert.ok(ldHrefMatch, "Linux.do button should include return_to query param");
  const ldHref = ldHrefMatch[1].replace(/&amp;/g, "&");
  assert.ok(ldHref.includes("return_to=%2Fauthorize%3Fpending%3D"));

  // 3. Open redirect blocked on /register, /login/password, /login/oauth/:provider
  const regEvil = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      email: "dave@example.com",
      username: "dave",
      password: "password1234",
      return_to: "//evil.com/phish",
    }),
  }), env, {});
  assert.equal(regEvil.status, 201);
  assert.equal((await regEvil.json()).redirect, "/account");
  const daveCookie = extractCookie(regEvil, "fucf_auth_sid");

  const loginEvil = await worker.fetch(new Request("https://auth.fucloudflare.com/login/password", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      identifier: "dave",
      password: "password1234",
      return_to: "https://evil.com",
    }),
  }), env, {});
  assert.equal(loginEvil.status, 200);
  assert.equal((await loginEvil.json()).redirect, "/account");

  // 4. Confidential client refresh_token requires client_secret
  const secretHash = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode("sec-123"))).toString("hex");
  await env.AUTH_DB.prepare(
    "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, require_pkce, trusted, created_at) VALUES (?, ?, ?, ?, ?, 1, 0, ?)"
  ).bind("conf-app", secretHash, "Conf App", JSON.stringify(["https://conf.example.com/cb"]), "openid profile", 1000).run();

  // Authorize with scope=openid (untrusted)
  const cAuth1 = await worker.fetch(new Request(
    `https://auth.fucloudflare.com/authorize?response_type=code&client_id=conf-app&redirect_uri=https://conf.example.com/cb&scope=openid&code_challenge=${codeChallenge}&code_challenge_method=S256&state=s1`,
    { headers: { cookie: daveCookie } }
  ), env, {});
  assert.equal(cAuth1.status, 200);
  const p1 = /name="pending_id"\s+value="([^"]+)"/.exec(await cAuth1.text())[1];
  const allow1 = await worker.fetch(new Request("https://auth.fucloudflare.com/authorize/consent", {
    method: "POST",
    headers: { cookie: daveCookie, "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ pending_id: p1, decision: "allow" }).toString(),
  }), env, {});
  const code1 = new URL(allow1.headers.get("location")).searchParams.get("code");

  const tok1 = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code: code1,
      client_id: "conf-app",
      client_secret: "sec-123",
      redirect_uri: "https://conf.example.com/cb",
      code_verifier: codeVerifier,
    }).toString(),
  }), env, {});
  assert.equal(tok1.status, 200);
  const rt1 = (await tok1.json()).refresh_token;

  // Refresh without secret -> 401 invalid_client
  const badRt = await worker.fetch(new Request("https://auth.fucloudflare.com/token", {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: rt1,
      client_id: "conf-app",
    }).toString(),
  }), env, {});
  assert.equal(badRt.status, 401);

  // 5. Scope escalation requires fresh consent (and prompt=none returns consent_required)
  const escPromptNone = await worker.fetch(new Request(
    `https://auth.fucloudflare.com/authorize?response_type=code&client_id=conf-app&redirect_uri=https://conf.example.com/cb&scope=openid%20profile&code_challenge=${codeChallenge}&code_challenge_method=S256&prompt=none&state=esc`,
    { headers: { cookie: daveCookie } }
  ), env, {});
  assert.equal(escPromptNone.status, 302);
  assert.equal(new URL(escPromptNone.headers.get("location")).searchParams.get("error"), "consent_required");
});

test("Security audit fixes: IDOR session revoke, unverified OAuth email, duplicate passkey 409, backslash redirect, signCount rollback, CSRF & GET /logout 405, spent_tokens replay, PBKDF2 & no dynamic callback", async () => {
  const env = makeEnv();

  // Register Alice and Bob
  const aliceReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "alice@example.com", username: "alice", password: "password1234" }),
  }), env, {});
  assert.equal(aliceReg.status, 201);
  const aliceCookie = extractCookie(aliceReg, "fucf_auth_sid");
  const aliceSid = decodeURIComponent(aliceCookie.split("=")[1]);

  const bobReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: "bob@example.com", username: "bob", password: "password1234" }),
  }), env, {});
  assert.equal(bobReg.status, 201);
  const bobCookie = extractCookie(bobReg, "fucf_auth_sid");
  const bobSid = decodeURIComponent(bobCookie.split("=")[1]);

  // 1. Password hash uses PBKDF2 in Node WebCrypto
  const aliceRow = await env.AUTH_DB.prepare("SELECT id, password_hash FROM users WHERE email = ?").bind("alice@example.com").first();
  assert.ok(aliceRow.password_hash.startsWith("pbkdf2$600000$"));

  // 2. Dynamic requestOrigin + "/callback" is NOT registered
  const dynCb = await worker.fetch(new Request(
    "https://auth.fucloudflare.com/authorize?response_type=code&client_id=dashboard-fucloudflare&redirect_uri=https://auth.fucloudflare.com/callback&code_challenge=abc&code_challenge_method=S256"
  ), env, {});
  assert.equal(dynCb.status, 400);

  // 3. IDOR in POST /account/session/revoke
  const idorRes = await worker.fetch(new Request("https://auth.fucloudflare.com/account/session/revoke", {
    method: "POST",
    headers: { cookie: aliceCookie, "content-type": "application/json" },
    body: JSON.stringify({ sid: bobSid }),
  }), env, {});
  assert.equal(idorRes.status, 403);
  // Bob's session must still be active
  const bobAcc = await worker.fetch(new Request("https://auth.fucloudflare.com/account", { headers: { cookie: bobCookie } }), env, {});
  assert.equal(bobAcc.status, 200);

  // Non-existent session -> 404
  const missingSessRes = await worker.fetch(new Request("https://auth.fucloudflare.com/account/session/revoke", {
    method: "POST",
    headers: { cookie: aliceCookie, "content-type": "application/json" },
    body: JSON.stringify({ sid: "non-existent-sid" }),
  }), env, {});
  assert.equal(missingSessRes.status, 404);

  // 4. Open redirect via backslash & control chars
  const bsLogin = await worker.fetch(new Request("https://auth.fucloudflare.com/login/password", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: "alice", password: "password1234", return_to: "/\\evil.com" }),
  }), env, {});
  assert.equal(bsLogin.status, 200);
  assert.equal((await bsLogin.json()).redirect, "/account");

  const ctrlLogin = await worker.fetch(new Request("https://auth.fucloudflare.com/login/password", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ identifier: "alice", password: "password1234", return_to: "/foo\x07bar" }),
  }), env, {});
  assert.equal(ctrlLogin.status, 200);
  assert.equal((await ctrlLogin.json()).redirect, "/account");

  // 5. GET /logout -> 405 & cross-origin POST CSRF -> 403
  const getLogout = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "GET",
    headers: { cookie: aliceCookie },
  }), env, {});
  assert.equal(getLogout.status, 405);

  const csrfLogout = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "POST",
    headers: { cookie: aliceCookie, origin: "https://evil.example" },
  }), env, {});
  assert.equal(csrfLogout.status, 403);

  const csrfNullOrigin = await worker.fetch(new Request("https://auth.fucloudflare.com/account/session/revoke", {
    method: "POST",
    headers: { cookie: aliceCookie, origin: "null", "content-type": "application/json" },
    body: JSON.stringify({ sid: aliceSid }),
  }), env, {});
  assert.equal(csrfNullOrigin.status, 403);

  const csrfBadToken = await worker.fetch(new Request("https://auth.fucloudflare.com/account/session/revoke", {
    method: "POST",
    headers: { cookie: aliceCookie, "x-csrf-token": "wrong-token", "content-type": "application/json" },
    body: JSON.stringify({ sid: aliceSid }),
  }), env, {});
  assert.equal(csrfBadToken.status, 403);

  // 6. Federated identity unverified email auto-link block + OAuth state spent_tokens replay
  const origFetch = globalThis.fetch;
  globalThis.fetch = async (url) => {
    const u = String(url);
    if (u === "https://connect.linux.do/oauth2/token") {
      return new Response(JSON.stringify({ access_token: "ld-tok" }), { status: 200 });
    }
    if (u === "https://connect.linux.do/api/user") {
      return new Response(JSON.stringify({
        id: 99999,
        username: "attacker",
        name: "Attacker",
        email: "alice@example.com",
        // email_verified NOT true
      }), { status: 200 });
    }
    throw new Error("Unexpected fetch: " + u);
  };
  try {
    const stRes = await worker.fetch(new Request("https://auth.fucloudflare.com/login/oauth/linuxdo"), env, {});
    const st = new URL(stRes.headers.get("location")).searchParams.get("state");
    // Snapshot KV state to simulate concurrent replay before KV delete
    const savedState = await env.AUTH_KV.get("oauth_state:" + st);

    const cb1 = await worker.fetch(new Request(`https://auth.fucloudflare.com/login/oauth/linuxdo/callback?code=c1&state=${st}`), env, {});
    assert.equal(cb1.status, 302);

    // Attacker must NOT be linked to Alice's user_id
    const fedRow = await env.AUTH_DB.prepare("SELECT user_id FROM federated_identities WHERE id = ?").bind("linuxdo:99999").first();
    assert.ok(fedRow);
    assert.notEqual(fedRow.user_id, aliceRow.id);

    // Restore KV state to simulate race condition; spent_tokens must still block replay
    await env.AUTH_KV.put("oauth_state:" + st, savedState, { expirationTtl: 600 });
    const cbReplay = await worker.fetch(new Request(`https://auth.fucloudflare.com/login/oauth/linuxdo/callback?code=c1&state=${st}`), env, {});
    assert.equal(cbReplay.status, 400);
  } finally {
    globalThis.fetch = origFetch;
  }

  // 7. Duplicate passkey registration -> 409 & signCount rollback -> 401
  const beginReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/begin", {
    method: "POST",
    headers: { cookie: aliceCookie, "content-type": "application/json" },
    body: "{}",
  }), env, {});
  const regOpts = await beginReg.json();
  const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
  const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
  const cose = encodeCoseP256(rawPub.subarray(1, 33), rawPub.subarray(33, 65));
  const credId = crypto.getRandomValues(new Uint8Array(16));
  const rpHash = Buffer.from(await crypto.subtle.digest("SHA-256", Buffer.from("auth.fucloudflare.com")));
  const authData = Buffer.concat([rpHash, Buffer.from([0x41]), Buffer.from([0, 0, 0, 5]), Buffer.alloc(16), Buffer.from([0, credId.length]), credId, cose]);
  const attestationObject = encodeCborAttestation(authData);
  const clientDataReg = Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge: regOpts.publicKey.challenge,
    origin: "https://auth.fucloudflare.com",
  }));

  const finReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/finish", {
    method: "POST",
    headers: { cookie: aliceCookie, "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: regOpts.challenge_id,
      response: { clientDataJSON: clientDataReg.toString("base64url"), attestationObject: attestationObject.toString("base64url") },
    }),
  }), env, {});
  assert.equal(finReg.status, 200);

  // Bob attempts to register the same credential ID -> 409
  const bobBegin = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/begin", {
    method: "POST",
    headers: { cookie: bobCookie, "content-type": "application/json" },
    body: "{}",
  }), env, {});
  const bobOpts = await bobBegin.json();
  const bobClientData = Buffer.from(JSON.stringify({
    type: "webauthn.create",
    challenge: bobOpts.publicKey.challenge,
    origin: "https://auth.fucloudflare.com",
  }));
  const bobFin = await worker.fetch(new Request("https://auth.fucloudflare.com/register/passkey/finish", {
    method: "POST",
    headers: { cookie: bobCookie, "content-type": "application/json" },
    body: JSON.stringify({
      challenge_id: bobOpts.challenge_id,
      response: { clientDataJSON: bobClientData.toString("base64url"), attestationObject: attestationObject.toString("base64url") },
    }),
  }), env, {});
  assert.equal(bobFin.status, 409);

  // signCount rollback: stored=5, attempt signCount=0 and signCount=5 -> 401
  for (const badCount of [0, 5, 3]) {
    const bl = await worker.fetch(new Request("https://auth.fucloudflare.com/login/passkey/begin", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: "{}",
    }), env, {});
    const lo = await bl.json();
    const cd = Buffer.from(JSON.stringify({ type: "webauthn.get", challenge: lo.publicKey.challenge, origin: "https://auth.fucloudflare.com" }));
    const ad = Buffer.concat([rpHash, Buffer.from([0x01]), Buffer.from([0, 0, 0, badCount])]);
    const ch = Buffer.from(await crypto.subtle.digest("SHA-256", cd));
    const sig64 = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, kp.privateKey, Buffer.concat([ad, ch])));
    const fl = await worker.fetch(new Request("https://auth.fucloudflare.com/login/passkey/finish", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        challenge_id: lo.challenge_id,
        rawId: Buffer.from(credId).toString("base64url"),
        response: {
          clientDataJSON: cd.toString("base64url"),
          authenticatorData: ad.toString("base64url"),
          signature: p1363ToDer(sig64).toString("base64url"),
        },
      }),
    }), env, {});
    assert.equal(fl.status, 401);
  }

  // 8. pending_auth single-use replay on GET /authorize?pending=... (trusted client)
  const cc = await sha256B64u("pending-replay-verifier-1234567890");
  const unauthAuth = await worker.fetch(new Request(
    `https://auth.fucloudflare.com/authorize?response_type=code&client_id=dashboard-fucloudflare&redirect_uri=https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback&code_challenge=${cc}&code_challenge_method=S256&state=p1`
  ), env, {});
  assert.equal(unauthAuth.status, 200);
  const pHtml = await unauthAuth.text();
  const pMatch = /pending=([A-Za-z0-9_-]+)/.exec(pHtml);
  assert.ok(pMatch);
  const pId = pMatch[1];
  const savedPending = await env.AUTH_KV.get("pending_auth:" + pId);
  const resAuth1 = await worker.fetch(new Request(`https://auth.fucloudflare.com/authorize?pending=${pId}`, {
    headers: { cookie: aliceCookie },
  }), env, {});
  assert.equal(resAuth1.status, 302);
  await env.AUTH_KV.put("pending_auth:" + pId, savedPending, { expirationTtl: 600 });
  const resAuthReplay = await worker.fetch(new Request(`https://auth.fucloudflare.com/authorize?pending=${pId}`, {
    headers: { cookie: aliceCookie },
  }), env, {});
  assert.equal(resAuthReplay.status, 400);

  // 9. Referer / Sec-Fetch-Site CSRF & POST /logout csrf_token validation
  const csrfReferer = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "POST",
    headers: { cookie: aliceCookie, referer: "https://evil.example/form" },
  }), env, {});
  assert.equal(csrfReferer.status, 403);

  const csrfSecFetch = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "POST",
    headers: { cookie: aliceCookie, "sec-fetch-site": "cross-site" },
  }), env, {});
  assert.equal(csrfSecFetch.status, 403);

  const csrfLogoutToken = await worker.fetch(new Request("https://auth.fucloudflare.com/logout", {
    method: "POST",
    headers: { cookie: aliceCookie, "x-csrf-token": "wrong-logout-token" },
  }), env, {});
  assert.equal(csrfLogoutToken.status, 403);

  // 10. Boa runtime fallback (no crypto.subtle.deriveBits) -> hmac256$10000$
  const origDeriveBits = crypto.subtle.deriveBits;
  Object.defineProperty(crypto.subtle, "deriveBits", { value: undefined, configurable: true });
  try {
    const boaReg = await worker.fetch(new Request("https://auth.fucloudflare.com/register", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: "boa@example.com", username: "boauser", password: "password1234" }),
    }), env, {});
    assert.equal(boaReg.status, 201);
    const boaRow = await env.AUTH_DB.prepare("SELECT password_hash FROM users WHERE email = ?").bind("boa@example.com").first();
    assert.ok(boaRow.password_hash.startsWith("hmac256$10000$"));
    const boaLogin = await worker.fetch(new Request("https://auth.fucloudflare.com/login/password", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ identifier: "boauser", password: "password1234" }),
    }), env, {});
    assert.equal(boaLogin.status, 200);
  } finally {
    Object.defineProperty(crypto.subtle, "deriveBits", { value: origDeriveBits, configurable: true });
  }
});

test("Admin: registration switch, roles, apps and providers are set on the auth site", async () => {
  const env = makeEnv({ LINUXDO_CLIENT_ID: "", LINUXDO_CLIENT_SECRET: "" });
  const base = "https://auth.fucloudflare.com";
  const reg = async (username) => {
    const r = await worker.fetch(new Request(base + "/register", {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `${username}@example.com`, username, password: "a long password here" }),
    }), env, {});
    return r;
  };
  const r1 = await reg("boss");
  assert.equal(r1.status, 201);
  const boss = extractCookie(r1, "fucf_auth_sid");
  const r2 = await reg("someone");
  const someone = extractCookie(r2, "fucf_auth_sid");

  // not an admin yet: the page says so, the API refuses
  const denied = await worker.fetch(new Request(base + "/admin", { headers: { cookie: boss } }), env, {});
  assert.equal(denied.status, 403);
  await env.AUTH_DB.prepare("UPDATE users SET role = 'admin' WHERE username = ?").bind("boss").run();

  const page = await worker.fetch(new Request(base + "/admin", { headers: { cookie: boss } }), env, {});
  assert.equal(page.status, 200);
  const html = await page.text();
  assert.ok(html.includes("管理") && html.includes("Administration") && html.includes("someone"));
  const csrf = /var csrfToken = "([^"]+)"/.exec(html)[1];
  const acc = await (await worker.fetch(new Request(base + "/account", { headers: { cookie: boss } }), env, {})).text();
  assert.ok(acc.includes('href="/admin"'), "admins see the way to the admin page");

  const api = (cookie, data, token = csrf) => worker.fetch(new Request(base + "/admin/api", {
    method: "POST",
    headers: Object.assign({ "content-type": "application/json", origin: base, cookie }, token ? { "x-csrf-token": token } : {}),
    body: JSON.stringify(data),
  }), env, {});
  assert.equal((await api(someone, { action: "registration", value: "closed" })).status, 403, "only admins");
  assert.equal((await api(boss, { action: "registration", value: "closed" }, "")).status, 403, "the CSRF token is required");

  // close registration: no sign-up, no new users through a provider, the tab is gone
  assert.equal((await api(boss, { action: "registration", value: "closed" })).status, 200);
  const closed = await reg("latecomer");
  assert.equal(closed.status, 403);
  assert.equal((await closed.json()).error, "registration_closed");
  const login = await (await worker.fetch(new Request(base + "/login"), env, {})).text();
  assert.ok(login.includes('class="tabs hidden"'));
  const withError = await (await worker.fetch(new Request(base + "/login?error=registration_closed"), env, {})).text();
  assert.ok(withError.includes("注册已关闭"));
  assert.equal((await api(boss, { action: "registration", value: "open" })).status, 200);
  assert.equal((await reg("latecomer")).status, 201);

  // roles: the last admin stays
  const ids = Object.fromEntries(((await env.AUTH_DB.prepare("SELECT id, username FROM users").all()).results).map((u) => [u.username, u.id]));
  assert.equal((await api(boss, { action: "role", id: ids.boss, role: "user" })).status, 409);
  assert.equal((await api(boss, { action: "role", id: ids.someone, role: "admin" })).status, 200);
  assert.equal((await env.AUTH_DB.prepare("SELECT role FROM users WHERE id = ?").bind(ids.someone).first()).role, "admin");

  // apps: a confidential client gets its secret once, stored only as a hash
  const created = await api(boss, { action: "client-create", name: "Blog", redirect_uris: ["https://blog.example.com/cb"], scopes: "openid email", confidential: true });
  assert.equal(created.status, 200);
  const c = await created.json();
  assert.ok(c.client_id.startsWith("app_") && c.client_secret.startsWith("sec_"));
  const row = await env.AUTH_DB.prepare("SELECT client_secret_hash, require_pkce FROM oauth_clients WHERE client_id = ?").bind(c.client_id).first();
  assert.ok(row.client_secret_hash && row.client_secret_hash !== c.client_secret && row.require_pkce === 0);
  assert.equal((await api(boss, { action: "client-create", name: "Bad", redirect_uris: ["http://evil.example.com/cb"] })).status, 400, "plain http only for localhost");
  assert.equal((await api(boss, { action: "client-delete", id: "dashboard-fucloudflare" })).status, 403, "the dashboard's client stays");
  assert.equal((await api(boss, { action: "client-delete", id: c.client_id })).status, 200);

  // providers: saved, shown on the sign-in page, secret kept when editing, can be switched off
  const prov = { action: "provider-save", id: "linuxdo", name: "Linux.do Connect", authorize_url: "https://connect.linux.do/oauth2/authorize",
    token_url: "https://connect.linux.do/oauth2/token", userinfo_url: "https://connect.linux.do/api/user", client_id: "cid", client_secret: "csecret", scopes: "read" };
  assert.equal((await api(boss, prov)).status, 200);
  assert.ok((await (await worker.fetch(new Request(base + "/login"), env, {})).text()).includes("Continue with Linux.do Connect"));
  assert.equal((await api(boss, Object.assign({}, prov, { editing: true, client_secret: "", name: "Linux.do" }))).status, 200);
  assert.equal((await env.AUTH_DB.prepare("SELECT client_secret FROM oauth_providers WHERE id = 'linuxdo'").first()).client_secret, "csecret");
  assert.equal((await api(boss, { action: "provider-toggle", id: "linuxdo", enabled: false })).status, 200);
  assert.ok(!(await (await worker.fetch(new Request(base + "/login"), env, {})).text()).includes("Linux.do"));
});
