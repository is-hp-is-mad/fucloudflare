// auth.fucloudflare.com — Self-contained OAuth 2.0 / OIDC Provider Worker
// Compatible with fucf Boa JS runtime (WebCrypto, KV, D1, Fetch API).
// Endpoints:
//   GET  /.well-known/openid-configuration
//   GET  /.well-known/jwks.json
//   GET  /authorize
//   POST /authorize/consent
//   POST /token
//   POST /revoke
//   GET|POST /userinfo
//   GET  /login
//   POST /login/password
//   POST /register
//   POST /logout
//   POST /login/passkey/begin
//   POST /login/passkey/finish
//   POST /register/passkey/begin
//   POST /register/passkey/finish
//   GET  /login/oauth/:provider
//   GET  /login/oauth/:provider/callback
//   GET  /account
//   POST /account/passkey/delete
//   POST /account/identity/unlink
//   POST /account/session/revoke
//   GET  /healthz

const COOKIE_SID = "fucf_auth_sid";
const SESSION_TTL = 86400 * 7; // 7 days
const CODE_TTL = 300; // 5 minutes
const CHALLENGE_TTL = 300; // 5 minutes
const STATE_TTL = 600; // 10 minutes
const ACCESS_TTL = 3600; // 1 hour
const REFRESH_TTL = 86400 * 30; // 30 days
const PBKDF_ITERS = 10000;
const PBKDF2_ITERS = 600000;

const _enc = new TextEncoder();
const _dec = new TextDecoder();
const _migratedDbs = new WeakSet();

// ---- Encoding & Crypto Helpers ----

function b64uEncode(input) {
  const u8 = input instanceof Uint8Array
    ? input
    : input instanceof ArrayBuffer
      ? new Uint8Array(input)
      : _enc.encode(String(input));
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uDecode(str) {
  let s = String(str).replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64Encode(u8) {
  let bin = "";
  for (let i = 0; i < u8.length; i++) bin += String.fromCharCode(u8[i]);
  return btoa(bin);
}

function b64Decode(str) {
  const bin = atob(String(str));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function randomToken(bytes = 32) {
  const buf = new Uint8Array(bytes);
  crypto.getRandomValues(buf);
  return b64uEncode(buf);
}

function hexEncode(buf) {
  const u8 = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u8.length; i++) s += u8[i].toString(16).padStart(2, "0");
  return s;
}

async function sha256(data) {
  const bytes = typeof data === "string" ? _enc.encode(data) : data;
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function sha256Hex(data) {
  return hexEncode(await sha256(data));
}

async function sha256B64u(data) {
  return b64uEncode(await sha256(data));
}

function timingSafeEqual(a, b) {
  const sa = String(a);
  const sb = String(b);
  if (sa.length !== sb.length) return false;
  let diff = 0;
  for (let i = 0; i < sa.length; i++) diff |= sa.charCodeAt(i) ^ sb.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256Iter(saltHex, password, iters) {
  const key = await crypto.subtle.importKey(
    "raw",
    _enc.encode(String(password)),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  let acc = _enc.encode(saltHex);
  for (let i = 0; i < iters; i++) {
    acc = new Uint8Array(await crypto.subtle.sign("HMAC", key, acc));
  }
  return hexEncode(acc);
}

async function hashPassword(password, existingSaltHex) {
  const saltHex = existingSaltHex || hexEncode(crypto.getRandomValues(new Uint8Array(16)));
  if (typeof crypto.subtle.deriveBits === "function") {
    try {
      const baseKey = await crypto.subtle.importKey(
        "raw",
        _enc.encode(String(password)),
        { name: "PBKDF2" },
        false,
        ["deriveBits"]
      );
      const bits = await crypto.subtle.deriveBits(
        {
          name: "PBKDF2",
          salt: _enc.encode(saltHex),
          iterations: PBKDF2_ITERS,
          hash: "SHA-256",
        },
        baseKey,
        256
      );
      return "pbkdf2$" + PBKDF2_ITERS + "$" + saltHex + "$" + hexEncode(new Uint8Array(bits));
    } catch (_) {}
  }
  try {
    const derived = await hmacSha256Iter(saltHex, password, PBKDF_ITERS);
    return "hmac256$" + PBKDF_ITERS + "$" + saltHex + "$" + derived;
  } catch (_) {
    let acc = _enc.encode(saltHex + ":" + String(password));
    for (let i = 0; i < PBKDF_ITERS; i++) {
      acc = new Uint8Array(await crypto.subtle.digest("SHA-256", acc));
    }
    return "sha256$" + PBKDF_ITERS + "$" + saltHex + "$" + hexEncode(acc);
  }
}

async function verifyPassword(password, storedHash) {
  if (!storedHash || typeof storedHash !== "string") return false;
  const parts = storedHash.split("$");
  if (parts.length !== 4) return false;
  const scheme = parts[0];
  const iters = parseInt(parts[1], 10);
  const saltHex = parts[2];
  const expected = parts[3];
  if (!iters || iters < 1 || !saltHex || !expected) return false;

  if (scheme === "pbkdf2") {
    if (typeof crypto.subtle.deriveBits !== "function") return false;
    const baseKey = await crypto.subtle.importKey(
      "raw",
      _enc.encode(String(password)),
      { name: "PBKDF2" },
      false,
      ["deriveBits"]
    );
    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt: _enc.encode(saltHex),
        iterations: iters,
        hash: "SHA-256",
      },
      baseKey,
      256
    );
    return timingSafeEqual(hexEncode(new Uint8Array(bits)), expected);
  }

  if (scheme === "hmac256") {
    const derived = await hmacSha256Iter(saltHex, password, iters);
    return timingSafeEqual(derived, expected);
  }

  if (scheme === "sha256") {
    let acc = _enc.encode(saltHex + ":" + String(password));
    for (let i = 0; i < iters; i++) {
      acc = new Uint8Array(await crypto.subtle.digest("SHA-256", acc));
    }
    return timingSafeEqual(hexEncode(acc), expected);
  }

  return false;
}

// ---- Signing Key & JWT (ES256 P-256) ----

async function getSigningKey(env) {
  const kvKey = "jwks:signing_key:v1";
  let stored = await env.AUTH_KV.get(kvKey, { type: "json" });
  if (!stored) {
    const kp = await crypto.subtle.generateKey(
      { name: "ECDSA", namedCurve: "P-256" },
      true,
      ["sign", "verify"]
    );
    const pkcs8 = new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey));
    const rawPub = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
    if (rawPub.length !== 65 || rawPub[0] !== 0x04) {
      throw new Error("Unexpected P-256 public key format");
    }
    const x = b64uEncode(rawPub.subarray(1, 33));
    const y = b64uEncode(rawPub.subarray(33, 65));
    const kid = (await sha256B64u(rawPub)).slice(0, 16);
    stored = {
      kid,
      pkcs8_b64: b64Encode(pkcs8),
      raw_pub_b64: b64Encode(rawPub),
      jwk: { kty: "EC", crv: "P-256", x, y, use: "sig", alg: "ES256", kid },
    };
    await env.AUTH_KV.put(kvKey, JSON.stringify(stored));
  }
  const privateKey = await crypto.subtle.importKey(
    "pkcs8",
    b64Decode(stored.pkcs8_b64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["sign"]
  );
  const publicKey = await crypto.subtle.importKey(
    "raw",
    b64Decode(stored.raw_pub_b64),
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["verify"]
  );
  return { kid: stored.kid, jwk: stored.jwk, privateKey, publicKey };
}

async function signJwt(env, payload, extraHeader) {
  const key = await getSigningKey(env);
  const header = Object.assign({ alg: "ES256", typ: "JWT", kid: key.kid }, extraHeader || {});
  const signingInput = b64uEncode(JSON.stringify(header)) + "." + b64uEncode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    key.privateKey,
    _enc.encode(signingInput)
  );
  return signingInput + "." + b64uEncode(sig);
}

async function verifyJwt(env, token) {
  const parts = String(token || "").split(".");
  if (parts.length !== 3) return null;
  let header, payload;
  try {
    header = JSON.parse(_dec.decode(b64uDecode(parts[0])));
    payload = JSON.parse(_dec.decode(b64uDecode(parts[1])));
  } catch (_) {
    return null;
  }
  if (!header || header.alg !== "ES256") return null;
  const key = await getSigningKey(env);
  if (header.kid && header.kid !== key.kid) return null;
  const sigBytes = b64uDecode(parts[2]);
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    key.publicKey,
    sigBytes,
    _enc.encode(parts[0] + "." + parts[1])
  );
  if (!ok) return null;
  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp === "number" && payload.exp < now) return null;
  return payload;
}

// ---- Minimal CBOR & WebAuthn Helpers ----

function cborDecode(u8) {
  let pos = 0;
  function readLen(ai) {
    if (ai < 24) return ai;
    if (ai === 24) return u8[pos++];
    if (ai === 25) { const v = (u8[pos] << 8) | u8[pos + 1]; pos += 2; return v; }
    if (ai === 26) {
      const v = ((u8[pos] << 24) >>> 0) + (u8[pos + 1] << 16) + (u8[pos + 2] << 8) + u8[pos + 3];
      pos += 4;
      return v;
    }
    throw new Error("Unsupported CBOR length");
  }
  function parse() {
    if (pos >= u8.length) throw new Error("Unexpected end of CBOR");
    const b = u8[pos++];
    const major = b >> 5;
    const ai = b & 0x1f;
    if (major === 0) return readLen(ai);
    if (major === 1) return -1 - readLen(ai);
    if (major === 2) {
      const len = readLen(ai);
      const slice = u8.subarray(pos, pos + len);
      pos += len;
      return slice;
    }
    if (major === 3) {
      const len = readLen(ai);
      const slice = u8.subarray(pos, pos + len);
      pos += len;
      return _dec.decode(slice);
    }
    if (major === 4) {
      const len = readLen(ai);
      const arr = [];
      for (let i = 0; i < len; i++) arr.push(parse());
      return arr;
    }
    if (major === 5) {
      const len = readLen(ai);
      const obj = {};
      for (let i = 0; i < len; i++) {
        const k = parse();
        obj[String(k)] = parse();
      }
      return obj;
    }
    if (major === 7) {
      if (ai === 20) return false;
      if (ai === 21) return true;
      if (ai === 22) return null;
    }
    throw new Error("Unsupported CBOR major type " + major);
  }
  return parse();
}

// Convert ASN.1 DER ECDSA signature to 64-byte IEEE P1363 (r || s)
function derSigToP1363(der) {
  if (!(der instanceof Uint8Array)) throw new Error("Invalid ECDSA signature");
  if (der.length === 64 && der[0] !== 0x30) return der;
  if (der.length < 8 || der[0] !== 0x30) {
    throw new Error("Invalid ECDSA DER signature");
  }
  let idx = 2;
  if (der[1] & 0x80) {
    const lenBytes = der[1] & 0x7f;
    if (lenBytes === 0 || lenBytes > 2 || 2 + lenBytes >= der.length) {
      throw new Error("Invalid ECDSA DER length");
    }
    idx = 2 + lenBytes;
  }
  if (idx + 2 >= der.length || der[idx] !== 0x02) throw new Error("Expected INTEGER r");
  const rLen = der[idx + 1];
  if (rLen === 0 || idx + 2 + rLen + 2 >= der.length) throw new Error("Invalid INTEGER r length");
  const rBytes = der.subarray(idx + 2, idx + 2 + rLen);
  idx = idx + 2 + rLen;
  if (der[idx] !== 0x02) throw new Error("Expected INTEGER s");
  const sLen = der[idx + 1];
  if (sLen === 0 || idx + 2 + sLen > der.length) throw new Error("Invalid INTEGER s length");
  const sBytes = der.subarray(idx + 2, idx + 2 + sLen);

  const out = new Uint8Array(64);
  const copyPad = (src, dstOff) => {
    let s = src;
    while (s.length > 32 && s[0] === 0) s = s.subarray(1);
    if (s.length > 32) throw new Error("ECDSA coordinate > 32 bytes");
    out.set(s, dstOff + (32 - s.length));
  };
  copyPad(rBytes, 0);
  copyPad(sBytes, 32);
  return out;
}

function parseAttestationAuthData(authData) {
  if (authData.length < 55) throw new Error("authData too short");
  const rpIdHash = authData.subarray(0, 32);
  const flags = authData[32];
  const signCount = ((authData[33] << 24) >>> 0) + (authData[34] << 16) + (authData[35] << 8) + authData[36];
  if ((flags & 0x40) === 0) throw new Error("Missing attestedCredentialData flag");
  // aaguid: 37..53
  const credIdLen = (authData[53] << 8) | authData[54];
  const credId = authData.subarray(55, 55 + credIdLen);
  const coseBytes = authData.subarray(55 + credIdLen);
  const cose = cborDecode(coseBytes);
  // COSE EC2: 1=kty(2), 3=alg(-7), -1=crv(1=P-256), -2=x, -3=y
  if (cose["1"] !== 2 || cose["-1"] !== 1) {
    throw new Error("Only EC2 P-256 passkeys are supported");
  }
  const x = cose["-2"];
  const y = cose["-3"];
  if (!(x instanceof Uint8Array) || !(y instanceof Uint8Array) || x.length !== 32 || y.length !== 32) {
    throw new Error("Invalid COSE P-256 coordinates");
  }
  const rawPub = new Uint8Array(65);
  rawPub[0] = 0x04;
  rawPub.set(x, 1);
  rawPub.set(y, 33);
  return { rpIdHash, flags, signCount, credId, rawPub, alg: cose["3"] || -7 };
}

// ---- D1 Schema & Lazy Migration ----

async function ensureSchema(env) {
  const db = env.AUTH_DB;
  if (!db) throw new Error("AUTH_DB binding is not configured");
  if (_migratedDbs.has(db)) return;
  const hasClients = await db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='oauth_clients'")
    .first();
  const hasSpent = await db
    .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='spent_tokens'")
    .first();
  if (hasClients && hasSpent) {
    _migratedDbs.add(db);
    return;
  }
  if (hasClients && !hasSpent) {
    await db.exec("CREATE TABLE IF NOT EXISTS spent_tokens (jti TEXT PRIMARY KEY, expires_at INTEGER NOT NULL);");
    _migratedDbs.add(db);
    return;
  }
  await db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      email TEXT UNIQUE,
      username TEXT,
      name TEXT,
      picture TEXT,
      role TEXT NOT NULL DEFAULT 'user',
      password_hash TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret_hash TEXT,
      name TEXT NOT NULL,
      redirect_uris TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT 'openid profile email',
      require_pkce INTEGER NOT NULL DEFAULT 1,
      trusted INTEGER NOT NULL DEFAULT 0,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS passkeys (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      name TEXT NOT NULL DEFAULT 'Passkey',
      public_key_b64 TEXT NOT NULL,
      alg INTEGER NOT NULL DEFAULT -7,
      sign_count INTEGER NOT NULL DEFAULT 0,
      transports TEXT,
      created_at INTEGER NOT NULL,
      last_used_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS federated_identities (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      provider TEXT NOT NULL,
      provider_user_id TEXT NOT NULL,
      email TEXT,
      username TEXT,
      name TEXT,
      avatar_url TEXT,
      raw_json TEXT,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS consents (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      scope TEXT NOT NULL,
      created_at INTEGER NOT NULL,
      updated_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS tokens (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      client_id TEXT NOT NULL,
      token_type TEXT NOT NULL,
      scope TEXT NOT NULL,
      revoked INTEGER NOT NULL DEFAULT 0,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS oauth_providers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      authorize_url TEXT NOT NULL,
      token_url TEXT NOT NULL,
      userinfo_url TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT 'read',
      enabled INTEGER NOT NULL DEFAULT 1,
      created_at INTEGER NOT NULL
    );
    CREATE TABLE IF NOT EXISTS spent_tokens (
      jti TEXT PRIMARY KEY,
      expires_at INTEGER NOT NULL
    );
  `);

  const now = Math.floor(Date.now() / 1000);
  const existing = await db.prepare("SELECT client_id FROM oauth_clients WHERE client_id = ?")
    .bind("dashboard-fucloudflare").first();
  if (!existing) {
    const redirects = [
      "https://dashboard.fucloudflare.com/client/v4/auth/oauth/callback",
      "http://127.0.0.1:8787/client/v4/auth/oauth/callback",
      "http://localhost:8787/client/v4/auth/oauth/callback",
    ];
    if (env.PANEL_ORIGIN) {
      redirects.push(String(env.PANEL_ORIGIN).replace(/\/$/, "") + "/client/v4/auth/oauth/callback");
    }
    await db.prepare(
      "INSERT INTO oauth_clients (client_id, client_secret_hash, name, redirect_uris, scopes, require_pkce, trusted, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).bind(
      "dashboard-fucloudflare",
      null,
      "fucloudflare Dashboard",
      JSON.stringify(redirects),
      "openid profile email offline_access",
      1,
      1,
      now
    ).run();
  }
  _migratedDbs.add(db);
}

// ---- HTTP / Cookie / Session Helpers ----

function parseCookies(request) {
  const hdr = request.headers.get("cookie") || "";
  const out = {};
  hdr.split(";").forEach((part) => {
    const idx = part.indexOf("=");
    if (idx > 0) {
      const k = part.slice(0, idx).trim();
      const v = part.slice(idx + 1).trim();
      if (k) out[k] = decodeURIComponent(v);
    }
  });
  return out;
}

function makeCookie(name, value, maxAge, urlObj) {
  const secure = urlObj.protocol === "https:" ? "; Secure" : "";
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}${secure}`;
}

function clearCookie(name, urlObj) {
  const secure = urlObj.protocol === "https:" ? "; Secure" : "";
  return `${name}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0${secure}`;
}

function securityHeaders(extra) {
  const h = new Headers({
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
    "content-security-policy":
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self' https: http:;",
  });
  if (extra) {
    Object.keys(extra).forEach((k) => h.set(k, extra[k]));
  }
  return h;
}

function htmlResponse(html, status = 200, extraHeaders = {}) {
  const headers = securityHeaders(Object.assign({ "content-type": "text/html; charset=utf-8", "cache-control": "no-store" }, extraHeaders));
  return new Response(html, { status, headers });
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  const headers = securityHeaders(Object.assign({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store" }, extraHeaders));
  return new Response(JSON.stringify(data), { status, headers });
}

function escapeHtml(s) {
  return String(s === null || s === undefined ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function safeReturnTo(val, fallback = "/account") {
  if (typeof val !== "string") return fallback;
  const trimmed = val.trim();
  if (
    !trimmed.startsWith("/") ||
    trimmed.startsWith("//") ||
    trimmed.includes("\\") ||
    /[\x00-\x1f\x7f]/.test(trimmed)
  ) {
    return fallback;
  }
  try {
    const parsed = new URL(trimmed, "https://placeholder.invalid");
    if (parsed.origin !== "https://placeholder.invalid") return fallback;
  } catch (_) {
    return fallback;
  }
  return trimmed;
}

function verifySameOrigin(request, url) {
  const origin = request.headers.get("origin");
  if (origin) {
    if (origin === "null") return false;
    try {
      return new URL(origin).origin === url.origin;
    } catch (_) {
      return false;
    }
  }
  const referer = request.headers.get("referer");
  if (referer) {
    try {
      return new URL(referer).origin === url.origin;
    } catch (_) {
      return false;
    }
  }
  const secFetchSite = (request.headers.get("sec-fetch-site") || "").toLowerCase();
  if (secFetchSite && secFetchSite !== "same-origin" && secFetchSite !== "none") {
    return false;
  }
  return true;
}

async function consumeSingleUseToken(env, jti, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  try {
    await env.AUTH_DB.prepare(
      "INSERT INTO spent_tokens (jti, expires_at) VALUES (?, ?)"
    ).bind(jti, now + ttlSeconds).run();
    return true;
  } catch (_) {
    return false;
  }
}

async function parseRequestParams(request) {
  const ct = (request.headers.get("content-type") || "").toLowerCase();
  const raw = await request.text();
  if (ct.includes("application/json")) {
    return raw ? JSON.parse(raw) : {};
  }
  const sp = new URLSearchParams(raw);
  const out = {};
  sp.forEach((v, k) => { out[k] = v; });
  return out;
}

async function getSession(request, env) {
  const cookies = parseCookies(request);
  const sid = cookies[COOKIE_SID];
  if (!sid) return null;
  const sess = await env.AUTH_KV.get("session:" + sid, { type: "json" });
  if (!sess || !sess.user_id) return null;
  const now = Math.floor(Date.now() / 1000);
  if (sess.expires_at && sess.expires_at < now) return null;
  const user = await env.AUTH_DB.prepare(
    "SELECT id, email, username, name, picture, role, created_at FROM users WHERE id = ?"
  ).bind(sess.user_id).first();
  if (!user) return null;
  return { sid, sess, user };
}

async function createSession(env, request, userId, amr = ["pwd"]) {
  const sid = randomToken(24);
  const csrfToken = randomToken(24);
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = now + SESSION_TTL;
  const sess = {
    sid,
    csrf_token: csrfToken,
    user_id: userId,
    amr,
    ua: (request.headers.get("user-agent") || "").slice(0, 120),
    ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "",
    created_at: now,
    expires_at: expiresAt,
  };
  await env.AUTH_KV.put("session:" + sid, JSON.stringify(sess), { expirationTtl: SESSION_TTL });
  await env.AUTH_KV.put(`sess_idx:${userId}:${sid}`, JSON.stringify({ sid, ua: sess.ua, ip: sess.ip, created_at: now }), { expirationTtl: SESSION_TTL });
  return sid;
}

async function getUserProviders(env, userId) {
  const res = await env.AUTH_DB.prepare(
    "SELECT id, provider, provider_user_id, email, username, name, avatar_url, created_at FROM federated_identities WHERE user_id = ?"
  ).bind(userId).all();
  return (res && res.results) || [];
}

async function listConfiguredOAuthProviders(env) {
  const providers = [];
  if (env.LINUXDO_CLIENT_ID && env.LINUXDO_CLIENT_SECRET) {
    providers.push({
      id: "linuxdo",
      name: "Linux.do Connect",
      authorize_url: "https://connect.linux.do/oauth2/authorize",
      token_url: "https://connect.linux.do/oauth2/token",
      userinfo_url: "https://connect.linux.do/api/user",
      client_id: env.LINUXDO_CLIENT_ID,
      client_secret: env.LINUXDO_CLIENT_SECRET,
      scopes: "read",
    });
  }
  if (env.GITHUB_CLIENT_ID && env.GITHUB_CLIENT_SECRET) {
    providers.push({
      id: "github",
      name: "GitHub",
      authorize_url: "https://github.com/login/oauth/authorize",
      token_url: "https://github.com/login/oauth/access_token",
      userinfo_url: "https://api.github.com/user",
      client_id: env.GITHUB_CLIENT_ID,
      client_secret: env.GITHUB_CLIENT_SECRET,
      scopes: "read:user user:email",
    });
  }
  if (env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET) {
    providers.push({
      id: "google",
      name: "Google",
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "https://oauth2.googleapis.com/token",
      userinfo_url: "https://openidconnect.googleapis.com/v1/userinfo",
      client_id: env.GOOGLE_CLIENT_ID,
      client_secret: env.GOOGLE_CLIENT_SECRET,
      scopes: "openid email profile",
    });
  }
  const rows = await env.AUTH_DB.prepare(
    "SELECT id, name, authorize_url, token_url, userinfo_url, client_id, client_secret, scopes FROM oauth_providers WHERE enabled = 1"
  ).all();
  if (rows && Array.isArray(rows.results)) {
    for (const r of rows.results) {
      const idx = providers.findIndex((p) => p.id === r.id);
      if (idx >= 0) providers[idx] = r;
      else providers.push(r);
    }
  }
  return providers;
}

// ---- UI: the fucloudflare panel's look (warm neutrals, clay, serif titles) ----

const UI_CSS = `
:root{color-scheme:light;
  --g000:#fff;--g050:#faf9f5;--g100:#f5f4ed;--g150:#f0eee6;--g200:#e8e6dc;--g250:#dedcd1;--g300:#d1cfc5;--g400:#b0aea5;--g450:#9c9a92;
  --g500:#87867f;--g600:#5e5d59;--g650:#4d4c48;--g700:#3d3d3a;--g750:#30302e;--g800:#262624;--g850:#1f1e1d;--g950:#141413;
  --clay:#d97757;--clay-hover:#c6613f;--clay-dark:#c46849;--ease:cubic-bezier(.165,.85,.45,1);
  --canvas:var(--g050);--base:var(--g000);--tint:var(--g150);--control:var(--g000);--interact:var(--g250);
  --line:var(--g300);--hairline:var(--g200);--hover:var(--g150);
  --fg:var(--g950);--strong:var(--g950);--sub:var(--g600);--placeholder:var(--g450);--link:#b4532e;
  --pri-bg:var(--g950);--pri-fg:var(--g050);
  --ok:#3f6b2a;--ok-tint:rgba(120,140,93,.16);--bad:#b53b30;--bad-fill:#bf4d43;--bad-tint:rgba(191,77,67,.1);
  --info-tint:rgba(217,119,87,.12);
  --shadow:0 2px 8px rgba(0,0,0,.04);
  --sans:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Helvetica Neue","PingFang SC","Hiragino Sans GB","Noto Sans SC","Microsoft YaHei",sans-serif;
  --serif:ui-serif,"Iowan Old Style","Palatino Linotype",Georgia,"Songti SC","Noto Serif SC","Source Han Serif SC",serif;
  --mono:ui-monospace,"SF Mono","Cascadia Mono",Consolas,monospace}
:root[data-mode="dark"]{color-scheme:dark;
  --canvas:var(--g800);--base:var(--g750);--tint:var(--g700);--control:var(--g750);--interact:var(--g650);
  --line:var(--g650);--hairline:var(--g700);--hover:var(--g800);
  --fg:var(--g100);--strong:var(--g050);--sub:var(--g400);--placeholder:var(--g500);--link:#e5937a;
  --pri-bg:var(--g050);--pri-fg:var(--g950);
  --ok:#a9c48a;--ok-tint:rgba(143,174,110,.18);--bad:#f0877b;--bad-fill:#c9574c;--bad-tint:rgba(201,87,76,.2);
  --info-tint:rgba(217,119,87,.18);--shadow:0 2px 8px rgba(0,0,0,.2)}
*{box-sizing:border-box}
html,body{margin:0;min-height:100dvh;overflow-x:clip}
body{font:14px/1.55 var(--sans);background:var(--canvas);color:var(--fg);-webkit-font-smoothing:antialiased}
html[data-lang=zh] [data-l=en],html[data-lang=en] [data-l=zh]{display:none}
a{color:var(--link);text-decoration:none}a:hover{text-decoration:underline;text-underline-offset:3px}
.hidden{display:none!important}
.top{display:flex;align-items:center;justify-content:space-between;gap:12px;height:56px;padding:0 20px;border-bottom:1px solid var(--hairline)}
.brand{display:flex;align-items:center;gap:10px;color:var(--strong);font:500 17px/1 var(--serif);letter-spacing:-.01em;text-decoration:none}
.brand:hover{text-decoration:none}
.mark{display:grid;place-items:center;width:28px;height:28px;border-radius:8px;background:var(--clay);color:#fff;flex:none}
.tools{display:flex;align-items:center;gap:4px}
main{width:min(30rem,100%);margin:0 auto;padding:40px 16px 64px}
main.wide{width:min(46rem,100%)}
h1{font:500 28px/1.2 var(--serif);letter-spacing:-.015em;color:var(--strong);margin:0 0 6px}
h2{font:500 19px/1.3 var(--serif);letter-spacing:-.01em;color:var(--strong);margin:0}
.sub{color:var(--sub);font-size:13.5px;margin:0 0 20px}
.card{background:var(--base);border:1px solid var(--hairline);border-radius:16px;box-shadow:var(--shadow);margin-bottom:18px}
.card>.hd{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:16px 20px;border-bottom:1px solid var(--hairline)}
.card>.bd{padding:6px 20px}
.login{background:var(--base);border:.5px solid var(--line);border-radius:32px;padding:32px 28px;
  box-shadow:0 4px 24px rgba(0,0,0,.016),0 4px 32px rgba(0,0,0,.016),0 2px 64px rgba(0,0,0,.012),0 16px 32px rgba(0,0,0,.012)}
.stack{display:grid;gap:10px}
button,.btn{position:relative;display:inline-flex;align-items:center;justify-content:center;gap:8px;height:36px;padding:0 16px;border:0;border-radius:.6rem;
  background:var(--control);color:var(--fg);font:500 14px/1 var(--sans);cursor:pointer;white-space:nowrap;text-decoration:none;-webkit-user-select:none;user-select:none;
  backface-visibility:hidden;box-shadow:0 0 0 0 var(--control),0 0 0 1px var(--line);
  transition:color .1s ease-in-out,background-color .2s ease-in-out,box-shadow .2s ease-in-out,transform .15s var(--ease)}
button:hover,.btn:hover{text-decoration:none;color:var(--strong);box-shadow:0 0 0 1px var(--control),0 0 0 2px var(--line)}
button:active:not(:disabled),.btn:active{transform:scale(.985)}
button:focus-visible,.btn:focus-visible{outline:2px solid var(--clay-dark);outline-offset:3px}
button:disabled{opacity:.5;cursor:not-allowed}
.pri,.danger{overflow:hidden;background:var(--pri-bg);color:var(--pri-fg);box-shadow:none;will-change:transform}
.pri::after,.danger::after{content:"";position:absolute;inset:0;opacity:0;transform:translateY(8px);background:radial-gradient(at bottom,rgba(255,255,255,.2),transparent);transition:opacity .2s,transform .2s;pointer-events:none}
.pri:hover:not(:disabled),.danger:hover:not(:disabled){color:var(--pri-fg);box-shadow:none;transform:scaleY(1.015) scaleX(1.005)}
.pri:hover::after,.danger:hover::after{opacity:1;transform:translateY(0)}
.danger,.danger:hover:not(:disabled){background:var(--bad-fill);color:#fff}
.outbad{background:transparent;color:var(--bad);box-shadow:0 0 0 1px color-mix(in srgb,var(--bad-fill) 55%,transparent)}
.outbad:hover:not(:disabled){color:var(--bad);background:var(--bad-tint);box-shadow:0 0 0 2px color-mix(in srgb,var(--bad-fill) 55%,transparent)}
.ghost{background:transparent;box-shadow:none;color:var(--sub);padding:0 10px}
.ghost:hover:not(:disabled){background:var(--hover);box-shadow:none;color:var(--strong)}
.sm{height:30px;padding:0 12px;font-size:13px;border-radius:8px}
.wide-btn{width:100%;height:44px;font-size:15px}
.brandbtn{background:var(--clay-hover);color:#fff;box-shadow:none;overflow:hidden}
.brandbtn:hover:not(:disabled){color:#fff;box-shadow:0 0 0 2px var(--clay-hover)}
.divider{display:flex;align-items:center;gap:12px;margin:20px 0;color:var(--placeholder);font-size:12.5px}
.divider::before,.divider::after{content:"";flex:1;height:1px;background:var(--hairline)}
.tabs{display:flex;gap:4px;padding:4px;border-radius:12px;background:var(--tint);margin-bottom:16px}
.tab{flex:1;height:32px;background:transparent;box-shadow:none;color:var(--sub);font-size:13.5px;border-radius:9px}
.tab:hover:not(:disabled){background:transparent;box-shadow:none;color:var(--strong)}
.tab.on,.tab.on:hover{background:var(--base);color:var(--strong);box-shadow:0 1px 3px rgba(0,0,0,.08),0 0 0 .5px var(--line)}
label{display:block;font-size:13px;font-weight:500;color:var(--strong);margin:12px 0 6px}
input{width:100%;height:40px;padding:0 12px;border:1px solid var(--line);border-radius:.6rem;background:var(--control);color:var(--fg);font:14px/1.4 var(--sans);transition:border-color .2s}
input::placeholder{color:var(--placeholder)}
input:hover:not(:focus){border-color:var(--interact)}
input:focus{outline:1px solid var(--clay-dark);outline-offset:2px;border-color:var(--clay-dark)}
form .wide-btn{margin-top:18px}
.alert{padding:11px 14px;border-radius:12px;margin-bottom:14px;font-size:13.5px;background:var(--bad-tint);color:var(--bad);border:1px solid color-mix(in srgb,var(--bad-fill) 30%,transparent)}
.alert.ok{background:var(--ok-tint);color:var(--ok);border-color:color-mix(in srgb,var(--ok) 30%,transparent)}
.tag{display:inline-flex;align-items:center;gap:5px;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:500;background:var(--tint);color:var(--sub);white-space:nowrap;vertical-align:1px}
.tag.ok{background:var(--ok-tint);color:var(--ok)}
.tag.pri{background:color-mix(in srgb,var(--clay) 14%,transparent);color:var(--clay-hover)}
.row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:14px 0;border-bottom:1px solid var(--hairline)}
.row:last-child{border-bottom:0}
.row b{display:block;font-weight:500;color:var(--strong)}
.row small{display:block;margin-top:2px;color:var(--sub);font-size:12.5px;overflow-wrap:anywhere}
.mono{font-family:var(--mono);font-size:12px}
.empty{padding:18px 0;color:var(--sub);font-size:13.5px}
.who{display:flex;align-items:center;gap:14px}
.avatar{display:grid;place-items:center;width:44px;height:44px;border-radius:50%;background:color-mix(in srgb,var(--clay) 16%,transparent);color:var(--clay-hover);font:500 18px/1 var(--serif);flex:none}
.scopes{list-style:none;margin:0 0 22px;padding:0;border:1px solid var(--hairline);border-radius:12px}
.scopes li{padding:12px 14px;border-bottom:1px solid var(--hairline)}
.scopes li:last-child{border-bottom:0}
.scopes code{font-family:var(--mono);font-size:12px;color:var(--sub)}
.actions{display:flex;gap:10px}.actions button{flex:1;height:42px}
.app{display:flex;align-items:center;gap:12px;margin-bottom:18px}
.app i{display:grid;place-items:center;width:40px;height:40px;border-radius:10px;background:var(--tint);color:var(--sub);font:500 16px/1 var(--serif);font-style:normal}
.foot{margin-top:18px;text-align:center;font-size:12.5px;color:var(--placeholder)}
@media (max-width:520px){.login{border-radius:24px;padding:26px 20px}main{padding-top:24px}.top{padding:0 12px}.hide-sm{display:none}}
@media (prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
`;

// Both languages; CSS shows the chosen one.
function t(zh, en) {
  return `<span data-l="zh">${escapeHtml(zh)}</span><span data-l="en">${escapeHtml(en)}</span>`;
}

const MARK_SVG = '<svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor" aria-hidden="true"><path d="M6.5 18h11a3.2 3.2 0 0 0 .4-6.37A4.8 4.8 0 0 0 8.8 10.2a3.5 3.5 0 0 0-3.4 2.75A2.7 2.7 0 0 0 6.5 18z"/></svg>';
const KEY_SVG = '<svg viewBox="0 0 24 24" width="17" height="17" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="8" cy="15" r="4"/><path d="M10.8 12.2 20 3M16 7l3 3M14 9l2 2"/></svg>';

// Theme and language before first paint; then the switches.
const HEAD_SCRIPT = `(function(){var d=document.documentElement;
try{var m=localStorage.getItem("cf_theme")||"auto";var dk=m==="dark"||(m==="auto"&&matchMedia("(prefers-color-scheme:dark)").matches);d.setAttribute("data-mode",dk?"dark":"light");
var l=localStorage.getItem("fucf_lang");if(l!=="zh"&&l!=="en")l=/^zh/i.test(navigator.language||"zh")?"zh":"en";d.setAttribute("data-lang",l);d.lang=l==="en"?"en":"zh-CN";}catch(e){d.setAttribute("data-mode","light");d.setAttribute("data-lang","zh");}})();`;

const SWITCH_SCRIPT = `(function(){var d=document.documentElement;
var order=["auto","light","dark"],names={auto:["跟随系统","Auto"],light:["浅色","Light"],dark:["深色","Dark"]};
function mode(){try{return localStorage.getItem("cf_theme")||"auto"}catch(e){return "auto"}}
function paint(){var m=mode(),dk=m==="dark"||(m==="auto"&&matchMedia("(prefers-color-scheme:dark)").matches);d.setAttribute("data-mode",dk?"dark":"light");
var b=document.getElementById("theme");if(b)b.innerHTML='<span data-l="zh">'+names[m][0]+'</span><span data-l="en">'+names[m][1]+'</span>';}
window.__setTheme=function(m){try{localStorage.setItem("cf_theme",m)}catch(e){}paint()};
var tb=document.getElementById("theme");if(tb)tb.onclick=function(){__setTheme(order[(order.indexOf(mode())+1)%3])};
var lb=document.getElementById("lang");if(lb)lb.onclick=function(){var n=d.getAttribute("data-lang")==="en"?"zh":"en";d.setAttribute("data-lang",n);d.lang=n==="en"?"en":"zh-CN";try{localStorage.setItem("fucf_lang",n)}catch(e){}};
matchMedia("(prefers-color-scheme:dark)").addEventListener("change",function(){if(mode()==="auto")paint()});paint();
window.L=function(zh,en){return d.getAttribute("data-lang")==="en"?en:zh};})();`;

function renderShell(title, bodyHtml, { wide = false, navRight = "" } = {}) {
  return `<!DOCTYPE html>
<html lang="zh-CN" data-lang="zh" data-mode="light">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>${escapeHtml(title)} · fucloudflare</title>
<style>${UI_CSS}</style>
<script>${HEAD_SCRIPT}</script>
</head>
<body>
<header class="top">
  <a class="brand" href="/account"><span class="mark">${MARK_SVG}</span><span>fucloudflare <span class="hide-sm" style="color:var(--sub)">${t("账户", "Account")}</span></span></a>
  <div class="tools">
    ${navRight}
    <button type="button" class="ghost sm" id="lang" aria-label="Language / 语言"><span data-l="zh">English</span><span data-l="en">中文</span></button>
    <button type="button" class="ghost sm" id="theme" aria-label="Theme / 主题">${t("跟随系统", "Auto")}</button>
  </div>
</header>
<main class="${wide ? "wide" : ""}">
${bodyHtml}
</main>
<script>${SWITCH_SCRIPT}</script>
</body>
</html>`;
}

// What the browser side of WebAuthn needs on every page that uses it.
const B64U_SCRIPT = `
  function b64uToBuf(s) {
    s = s.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  function bufToB64u(buf) {
    var u8 = new Uint8Array(buf), s = "";
    for (var i = 0; i < u8.length; i++) s += String.fromCharCode(u8[i]);
    return btoa(s).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  // a challenge is either base64url bytes or a text token
  function challengeBuf(c) {
    if (/^[A-Za-z0-9_-]+$/.test(c)) { try { return b64uToBuf(c); } catch (e) {} }
    return new TextEncoder().encode(c).buffer;
  }`;

function renderLoginPage({ providers, returnTo, pendingId, errorMsg }) {
  const nextTarget = pendingId
    ? `/authorize?pending=${encodeURIComponent(pendingId)}`
    : safeReturnTo(returnTo, "/account");

  const oauthButtons = providers.map((p) => {
    const qs = new URLSearchParams();
    qs.set("return_to", nextTarget);
    const cls = p.id === "linuxdo" ? "btn wide-btn brandbtn" : "btn wide-btn";
    return `<a class="${cls}" href="/login/oauth/${encodeURIComponent(p.id)}?${qs.toString()}">${t(`使用 ${p.name} 继续`, `Continue with ${p.name}`)}</a>`;
  }).join("\n");

  const body = `
<div class="login">
  <h1>${t("登录 fucloudflare", "Sign in to fucloudflare")}</h1>
  <p class="sub">${t("一个账户登录面板及所有接入的应用。", "One account for the dashboard and every connected app.")}</p>
  <div id="auth-err" class="alert${errorMsg ? "" : " hidden"}" role="alert">${escapeHtml(errorMsg || "")}</div>

  <div class="stack">
    <button type="button" id="btn-passkey" class="pri wide-btn">${KEY_SVG}${t("使用通行密钥登录", "Sign in with a passkey")}</button>
    ${oauthButtons}
  </div>

  <div class="divider">${t("或使用邮箱和密码", "or use email and password")}</div>

  <div class="tabs" role="tablist">
    <button type="button" class="tab on" id="tab-login" role="tab">${t("登录", "Sign in")}</button>
    <button type="button" class="tab" id="tab-register" role="tab">${t("注册", "Create account")}</button>
  </div>

  <form id="form-login">
    <label for="login-id">${t("邮箱或用户名", "Email or username")}</label>
    <input id="login-id" name="identifier" required autocomplete="username webauthn">
    <label for="login-pw">${t("密码", "Password")}</label>
    <input id="login-pw" name="password" type="password" required autocomplete="current-password">
    <button type="submit" class="pri wide-btn">${t("登录", "Sign in")}</button>
  </form>

  <form id="form-register" class="hidden">
    <label for="reg-email">${t("邮箱", "Email")}</label>
    <input id="reg-email" name="email" type="email" required autocomplete="email">
    <label for="reg-user">${t("用户名", "Username")}</label>
    <input id="reg-user" name="username" required autocomplete="username">
    <label for="reg-name">${t("显示名称（可选）", "Display name (optional)")}</label>
    <input id="reg-name" name="name" autocomplete="name">
    <label for="reg-pw">${t("密码（至少 8 位）", "Password (at least 8 characters)")}</label>
    <input id="reg-pw" name="password" type="password" minlength="8" required autocomplete="new-password">
    <button type="submit" class="pri wide-btn">${t("创建账户", "Create account")}</button>
  </form>
</div>
<p class="foot">${t("由 fucloudflare 提供的 OAuth 2.0 / OpenID Connect 登录", "OAuth 2.0 / OpenID Connect sign-in by fucloudflare")}</p>
<script>
(function() {
  var nextUrl = ${JSON.stringify(nextTarget)};
  var errBox = document.getElementById("auth-err");
  function showErr(msg) {
    errBox.textContent = msg;
    errBox.classList.remove("hidden");
  }
  ${B64U_SCRIPT}
  function busy(btn, on) { btn.disabled = on; }

  function pick(login) {
    document.getElementById("tab-login").classList.toggle("on", login);
    document.getElementById("tab-register").classList.toggle("on", !login);
    document.getElementById("form-login").classList.toggle("hidden", !login);
    document.getElementById("form-register").classList.toggle("hidden", login);
    errBox.classList.add("hidden");
  }
  document.getElementById("tab-login").onclick = function() { pick(true); };
  document.getElementById("tab-register").onclick = function() { pick(false); };

  async function post(path, data) {
    var r = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(data) });
    var d = {};
    try { d = await r.json(); } catch (e) {}
    return { ok: r.ok, d: d };
  }

  document.getElementById("form-login").onsubmit = async function(e) {
    e.preventDefault();
    errBox.classList.add("hidden");
    var btn = this.querySelector("button[type=submit]"); busy(btn, true);
    try {
      var res = await post("/login/password", {
        identifier: document.getElementById("login-id").value,
        password: document.getElementById("login-pw").value,
        return_to: nextUrl
      });
      if (!res.ok) return showErr(res.d.error || L("登录失败", "Sign in failed"));
      location.href = res.d.redirect || nextUrl;
    } finally { busy(btn, false); }
  };

  document.getElementById("form-register").onsubmit = async function(e) {
    e.preventDefault();
    errBox.classList.add("hidden");
    var btn = this.querySelector("button[type=submit]"); busy(btn, true);
    try {
      var res = await post("/register", {
        email: document.getElementById("reg-email").value,
        username: document.getElementById("reg-user").value,
        name: document.getElementById("reg-name").value,
        password: document.getElementById("reg-pw").value,
        return_to: nextUrl
      });
      if (!res.ok) return showErr(res.d.error || L("注册失败", "Registration failed"));
      location.href = res.d.redirect || nextUrl;
    } finally { busy(btn, false); }
  };

  document.getElementById("btn-passkey").onclick = async function() {
    errBox.classList.add("hidden");
    if (!window.PublicKeyCredential) return showErr(L("这个浏览器不支持通行密钥。", "This browser does not support passkeys."));
    var btn = this; busy(btn, true);
    try {
      var begin = await post("/login/passkey/begin", {});
      if (!begin.ok) return showErr(begin.d.error || L("无法开始通行密钥登录", "Could not start passkey sign-in"));
      var beginData = begin.d;
      var pk = beginData.publicKey;
      pk.challenge = challengeBuf(pk.challenge);
      if (pk.allowCredentials) {
        pk.allowCredentials = pk.allowCredentials.map(function(c) {
          return Object.assign({}, c, { id: b64uToBuf(c.id) });
        });
      }
      var cred = await navigator.credentials.get({ publicKey: pk });
      var fin = await post("/login/passkey/finish", {
        challenge_id: beginData.challenge_id,
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        response: {
          clientDataJSON: bufToB64u(cred.response.clientDataJSON),
          authenticatorData: bufToB64u(cred.response.authenticatorData),
          signature: bufToB64u(cred.response.signature),
          userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
        },
        return_to: nextUrl
      });
      if (!fin.ok) return showErr(fin.d.error || L("通行密钥验证失败", "Passkey verification failed"));
      location.href = fin.d.redirect || nextUrl;
    } catch (err) {
      showErr(err && err.name === "NotAllowedError" ? L("已取消或超时。", "Cancelled or timed out.") : (err && err.message) || L("通行密钥登录已取消", "Passkey sign-in cancelled"));
    } finally { busy(btn, false); }
  };
})();
</script>
`;
  return renderShell("登录 Sign in", body);
}

function renderConsentPage({ client, user, scope, pendingId, csrfToken = "" }) {
  const scopes = scope.split(/\s+/).filter(Boolean);
  const scopeDesc = {
    openid: ["确认你的身份", "Confirm who you are (OpenID)"],
    profile: ["读取你的名称、用户名和头像", "Read your name, username and avatar"],
    email: ["读取你的邮箱地址", "Read your email address"],
    offline_access: ["在你离线时保持访问（刷新令牌）", "Keep access while you are away (refresh token)"],
  };
  const items = scopes.map((s) => {
    const [zh, en] = scopeDesc[s] || ["访问所请求的权限", "Access the requested scope"];
    return `<li>${t(zh, en)}<br><code>${escapeHtml(s)}</code></li>`;
  }).join("");
  const initial = escapeHtml((client.name || "?").trim().slice(0, 1).toUpperCase());

  const body = `
<div class="login">
  <div class="app"><i>${initial}</i><div><b style="color:var(--strong);font-weight:500">${escapeHtml(client.name)}</b><br><small style="color:var(--sub)">${t("请求访问你的 fucloudflare 账户", "wants to access your fucloudflare account")}</small></div></div>
  <h1>${t(`授权 ${client.name}`, `Authorize ${client.name}`)}</h1>
  <p class="sub">${t("当前登录：", "Signed in as ")}<b style="color:var(--strong);font-weight:500">${escapeHtml(user.email || user.username || user.id)}</b></p>
  <p style="margin:0 0 10px;font-size:13.5px">${t("它将能够：", "It will be able to:")}</p>
  <ul class="scopes">${items}</ul>
  <form method="POST" action="/authorize/consent" class="actions">
    <input type="hidden" name="pending_id" value="${escapeHtml(pendingId)}">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <button type="submit" name="decision" value="deny">${t("拒绝", "Deny")}</button>
    <button type="submit" name="decision" value="allow" class="pri">${t("允许", "Allow")}</button>
  </form>
</div>
<p class="foot">${t("授权后可随时在账户页撤销会话。", "You can revoke access any time from your account page.")}</p>
`;
  return renderShell("授权 Authorize", body);
}

function renderAccountPage({ user, passkeys, identities, sessions, allProviders, csrfToken = "" }) {
  const linkedMap = {};
  identities.forEach((i) => { linkedMap[i.provider] = i; });

  const passkeyRows = passkeys.length
    ? passkeys.map((pk) => `
      <div class="row">
        <div><b>${escapeHtml(pk.name)}</b><small><span class="mono">${escapeHtml(pk.id.slice(0, 16))}…</span> · ${t(`已使用 ${pk.sign_count} 次`, `used ${pk.sign_count} times`)}</small></div>
        <button type="button" class="outbad sm" data-action="del-passkey" data-id="${escapeHtml(pk.id)}">${t("删除", "Remove")}</button>
      </div>`).join("")
    : `<p class="empty">${t("还没有通行密钥。添加一个，下次用指纹、面容或安全密钥直接登录。", "No passkeys yet. Add one to sign in with your fingerprint, face or security key.")}</p>`;

  const identityRows = allProviders.map((p) => {
    const linked = linkedMap[p.id];
    if (linked) {
      return `
      <div class="row">
        <div><b>${escapeHtml(p.name)} <span class="tag ok">${t("已连接", "Connected")}</span></b><small>${escapeHtml(linked.username || linked.email || linked.provider_user_id)}</small></div>
        <button type="button" class="outbad sm" data-action="unlink-provider" data-id="${escapeHtml(p.id)}">${t("解除绑定", "Unlink")}</button>
      </div>`;
    }
    return `
      <div class="row">
        <div><b>${escapeHtml(p.name)}</b><small>${t("未连接", "Not connected")}</small></div>
        <a class="btn sm" href="/login/oauth/${encodeURIComponent(p.id)}?return_to=%2Faccount">${t("连接", "Connect")}</a>
      </div>`;
  }).join("") || `<p class="empty">${t("还没有配置第三方登录。", "No external sign-in providers are configured.")}</p>`;

  const sessionRows = sessions.map((s) => `
    <div class="row">
      <div><b><span class="mono">${escapeHtml(s.sid.slice(0, 10))}…</span> ${s.current ? `<span class="tag pri">${t("当前", "This device")}</span>` : ""}</b>
        <small>${escapeHtml(s.ip || "?")} · ${escapeHtml((s.ua || "Browser").slice(0, 72))}</small></div>
      <button type="button" class="outbad sm" data-action="revoke-session" data-id="${escapeHtml(s.sid)}">${s.current ? t("退出", "Sign out") : t("撤销", "Revoke")}</button>
    </div>
  `).join("") || `<p class="empty">${t("没有活动会话。", "No active sessions.")}</p>`;

  const display = user.name || user.username || user.email || "";
  const body = `
<div class="card"><div class="hd">
  <div class="who"><span class="avatar">${escapeHtml(display.trim().slice(0, 1).toUpperCase() || "?")}</span>
    <div><h1 style="font-size:24px;margin:0">${escapeHtml(display)}</h1>
    <p class="sub" style="margin:2px 0 0">${escapeHtml(user.email || "")} <span class="tag">${escapeHtml(user.role)}</span></p></div></div>
  <form method="POST" action="/logout" style="margin:0">
    <input type="hidden" name="csrf_token" value="${escapeHtml(csrfToken)}">
    <button type="submit" class="sm">${t("退出登录", "Sign out")}</button>
  </form>
</div></div>

<div class="card">
  <div class="hd"><h2>${t("通行密钥", "Passkeys")}</h2><button type="button" id="btn-add-pk" class="pri sm">${t("添加通行密钥", "Add a passkey")}</button></div>
  <div class="bd"><div id="pk-msg" class="alert hidden" style="margin-top:12px"></div>${passkeyRows}</div>
</div>

<div class="card">
  <div class="hd"><h2>${t("已连接的账户", "Connected accounts")}</h2></div>
  <div class="bd">${identityRows}</div>
</div>

<div class="card">
  <div class="hd"><h2>${t("登录会话", "Sessions")}</h2></div>
  <div class="bd">${sessionRows}</div>
</div>

<script>
(function() {
  var csrfToken = ${JSON.stringify(csrfToken)};
  ${B64U_SCRIPT}
  var msgEl = document.getElementById("pk-msg");
  function showMsg(txt, ok) {
    msgEl.textContent = txt;
    msgEl.className = "alert" + (ok ? " ok" : "");
  }

  document.getElementById("btn-add-pk").onclick = async function() {
    if (!window.PublicKeyCredential) return showMsg(L("这个浏览器不支持通行密钥。", "This browser does not support passkeys."));
    var btn = this; btn.disabled = true;
    try {
      var r1 = await fetch("/register/passkey/begin", { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrfToken }, body: "{}" });
      var d1 = await r1.json();
      if (!r1.ok) return showMsg(d1.error || L("无法开始添加通行密钥", "Could not start adding a passkey"));
      var pk = d1.publicKey;
      pk.challenge = challengeBuf(pk.challenge);
      pk.user.id = b64uToBuf(pk.user.id);
      if (pk.excludeCredentials) pk.excludeCredentials = pk.excludeCredentials.map(function(c) { return Object.assign({}, c, { id: b64uToBuf(c.id) }); });
      var cred = await navigator.credentials.create({ publicKey: pk });
      var r2 = await fetch("/register/passkey/finish", {
        method: "POST",
        headers: { "content-type": "application/json", "x-csrf-token": csrfToken },
        body: JSON.stringify({
          challenge_id: d1.challenge_id,
          name: L("通行密钥", "Passkey") + " (" + new Date().toISOString().slice(0, 10) + ")",
          id: cred.id,
          rawId: bufToB64u(cred.rawId),
          response: {
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            attestationObject: bufToB64u(cred.response.attestationObject)
          }
        })
      });
      var d2 = await r2.json();
      if (!r2.ok) return showMsg(d2.error || L("添加通行密钥失败", "Adding the passkey failed"));
      location.reload();
    } catch (e) {
      showMsg(e && e.name === "NotAllowedError" ? L("已取消或超时。", "Cancelled or timed out.") : (e && e.message) || L("已取消", "Cancelled"));
    } finally { btn.disabled = false; }
  };

  var confirmText = {
    "del-passkey": ["删除这个通行密钥？", "Remove this passkey?"],
    "unlink-provider": ["解除与这个账户的绑定？", "Unlink this account?"],
    "revoke-session": ["撤销这个会话？", "Revoke this session?"]
  };
  var paths = { "del-passkey": ["/account/passkey/delete", "id"], "unlink-provider": ["/account/identity/unlink", "provider"], "revoke-session": ["/account/session/revoke", "sid"] };
  document.addEventListener("click", async function(e) {
    var btn = e.target && e.target.closest ? e.target.closest("[data-action]") : null;
    if (!btn) return;
    var act = btn.getAttribute("data-action");
    if (!paths[act] || !confirm(L(confirmText[act][0], confirmText[act][1]))) return;
    var body = {}; body[paths[act][1]] = btn.getAttribute("data-id") || "";
    btn.disabled = true;
    await fetch(paths[act][0], { method: "POST", headers: { "content-type": "application/json", "x-csrf-token": csrfToken }, body: JSON.stringify(body) });
    location.reload();
  });
})();
</script>
`;
  return renderShell("账户 Account", body, { wide: true });
}

// ---- OAuth2 / OIDC Core Logic ----

async function issueAuthCodeAndRedirect(env, pending, userId, amr) {
  const code = randomToken(32);
  const now = Math.floor(Date.now() / 1000);
  await env.AUTH_KV.put(
    "auth_code:" + code,
    JSON.stringify({
      code,
      client_id: pending.client_id,
      redirect_uri: pending.redirect_uri,
      user_id: userId,
      scope: pending.scope,
      nonce: pending.nonce || null,
      code_challenge: pending.code_challenge || null,
      code_challenge_method: pending.code_challenge_method || null,
      auth_time: now,
      amr: amr || ["pwd"],
    }),
    { expirationTtl: CODE_TTL }
  );
  const redir = new URL(pending.redirect_uri);
  redir.searchParams.set("code", code);
  if (pending.state) redir.searchParams.set("state", pending.state);
  return Response.redirect(redir.toString(), 302);
}

async function handleAuthorize(request, env, url) {
  const sp = url.searchParams;
  let pendingId = sp.get("pending");
  let params;

  if (pendingId) {
    params = await env.AUTH_KV.get("pending_auth:" + pendingId, { type: "json" });
    if (!params) return jsonResponse({ error: "invalid_request", error_description: "Expired authorization request" }, 400);
  } else {
    const responseType = sp.get("response_type");
    const clientId = sp.get("client_id");
    const redirectUri = sp.get("redirect_uri");
    const scope = sp.get("scope") || "openid profile email";
    const state = sp.get("state") || "";
    const codeChallenge = sp.get("code_challenge") || "";
    const codeChallengeMethod = sp.get("code_challenge_method") || "";
    const nonce = sp.get("nonce") || "";
    const prompt = sp.get("prompt") || "";

    if (!clientId || !redirectUri) {
      return jsonResponse({ error: "invalid_request", error_description: "client_id and redirect_uri are required" }, 400);
    }
    const client = await env.AUTH_DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(clientId).first();
    if (!client) {
      return jsonResponse({ error: "unauthorized_client", error_description: "Unknown client_id" }, 400);
    }
    let allowedRedirects = [];
    try { allowedRedirects = JSON.parse(client.redirect_uris); } catch (_) {}
    if (!allowedRedirects.includes(redirectUri)) {
      return jsonResponse({ error: "invalid_request", error_description: "redirect_uri not registered" }, 400);
    }
    if (responseType !== "code") {
      const errUrl = new URL(redirectUri);
      errUrl.searchParams.set("error", "unsupported_response_type");
      if (state) errUrl.searchParams.set("state", state);
      return Response.redirect(errUrl.toString(), 302);
    }
    if (client.require_pkce && (!codeChallenge || codeChallengeMethod !== "S256")) {
      const errUrl = new URL(redirectUri);
      errUrl.searchParams.set("error", "invalid_request");
      errUrl.searchParams.set("error_description", "PKCE S256 is required");
      if (state) errUrl.searchParams.set("state", state);
      return Response.redirect(errUrl.toString(), 302);
    }
    params = {
      client_id: clientId,
      redirect_uri: redirectUri,
      scope,
      state,
      code_challenge: codeChallenge,
      code_challenge_method: codeChallengeMethod,
      nonce,
      prompt,
    };
    pendingId = randomToken(18);
    await env.AUTH_KV.put("pending_auth:" + pendingId, JSON.stringify(params), { expirationTtl: STATE_TTL });
  }

  const session = await getSession(request, env);
  if (!session || params.prompt === "login") {
    if (params.prompt === "none") {
      const errUrl = new URL(params.redirect_uri);
      errUrl.searchParams.set("error", "login_required");
      if (params.state) errUrl.searchParams.set("state", params.state);
      return Response.redirect(errUrl.toString(), 302);
    }
    const providers = await listConfiguredOAuthProviders(env);
    return htmlResponse(renderLoginPage({ providers, pendingId }));
  }

  const client = await env.AUTH_DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(params.client_id).first();
  const consentId = `${session.user.id}:${params.client_id}`;
  const existingConsent = await env.AUTH_DB.prepare("SELECT scope FROM consents WHERE id = ?").bind(consentId).first();
  const requestedScopes = String(params.scope || "").split(/\s+/).filter(Boolean);
  const consentedScopes = existingConsent ? String(existingConsent.scope || "").split(/\s+/).filter(Boolean) : [];
  const hasAllConsented = existingConsent && requestedScopes.every((s) => consentedScopes.includes(s));

  if (((client && client.trusted === 1) || hasAllConsented) && params.prompt !== "consent") {
    if (!(await consumeSingleUseToken(env, "pending_auth:" + pendingId, STATE_TTL))) {
      return jsonResponse({ error: "invalid_request", error_description: "pending_id already used" }, 400);
    }
    await env.AUTH_KV.delete("pending_auth:" + pendingId);
    return issueAuthCodeAndRedirect(env, params, session.user.id, session.sess.amr);
  }

  if (params.prompt === "none") {
    if (!(await consumeSingleUseToken(env, "pending_auth:" + pendingId, STATE_TTL))) {
      return jsonResponse({ error: "invalid_request", error_description: "pending_id already used" }, 400);
    }
    await env.AUTH_KV.delete("pending_auth:" + pendingId);
    const errUrl = new URL(params.redirect_uri);
    errUrl.searchParams.set("error", "consent_required");
    if (params.state) errUrl.searchParams.set("state", params.state);
    return Response.redirect(errUrl.toString(), 302);
  }

  return htmlResponse(renderConsentPage({
    client: client || { name: params.client_id },
    user: session.user,
    scope: params.scope,
    pendingId,
    csrfToken: session.sess.csrf_token || "",
  }));
}

async function handleAuthorizeConsent(request, env) {
  const session = await getSession(request, env);
  if (!session) return jsonResponse({ error: "login_required" }, 401);
  const body = await parseRequestParams(request);
  const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
  if (suppliedCsrf && (!session.sess.csrf_token || !timingSafeEqual(suppliedCsrf, session.sess.csrf_token))) {
    return jsonResponse({ error: "invalid_csrf_token" }, 403);
  }
  const pendingId = body.pending_id;
  if (!pendingId) return jsonResponse({ error: "invalid_request", error_description: "missing pending_id" }, 400);
  const pending = await env.AUTH_KV.get("pending_auth:" + pendingId, { type: "json" });
  if (!pending) return jsonResponse({ error: "invalid_request", error_description: "expired pending_id" }, 400);
  if (!(await consumeSingleUseToken(env, "pending_auth:" + pendingId, STATE_TTL))) {
    return jsonResponse({ error: "invalid_request", error_description: "pending_id already used" }, 400);
  }
  await env.AUTH_KV.delete("pending_auth:" + pendingId);

  if (body.decision === "deny") {
    const errUrl = new URL(pending.redirect_uri);
    errUrl.searchParams.set("error", "access_denied");
    if (pending.state) errUrl.searchParams.set("state", pending.state);
    return Response.redirect(errUrl.toString(), 302);
  }

  const now = Math.floor(Date.now() / 1000);
  const consentId = `${session.user.id}:${pending.client_id}`;
  await env.AUTH_DB.prepare(
    "INSERT OR REPLACE INTO consents (id, user_id, client_id, scope, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(consentId, session.user.id, pending.client_id, pending.scope, now, now).run();

  return issueAuthCodeAndRedirect(env, pending, session.user.id, session.sess.amr);
}

async function mintTokenSet(env, issuer, user, clientId, scope, nonce, authTime, amr) {
  const now = Math.floor(Date.now() / 1000);
  const jti = randomToken(16);
  const providers = (await getUserProviders(env, user.id)).map((p) => ({
    provider: p.provider,
    username: p.username,
    id: p.provider_user_id,
  }));

  const accessPayload = {
    iss: issuer,
    sub: user.id,
    aud: clientId,
    exp: now + ACCESS_TTL,
    iat: now,
    jti,
    scope,
    role: user.role || "user",
  };
  const accessToken = await signJwt(env, accessPayload);

  const idPayload = {
    iss: issuer,
    sub: user.id,
    aud: clientId,
    exp: now + ACCESS_TTL,
    iat: now,
    auth_time: authTime || now,
    amr: amr || ["pwd"],
    email: user.email || null,
    name: user.name || user.username || null,
    preferred_username: user.username || user.email || user.id,
    role: user.role || "user",
    picture: user.picture || null,
    providers,
  };
  if (nonce) idPayload.nonce = nonce;
  const idToken = await signJwt(env, idPayload);

  const refreshToken = randomToken(32);
  const refreshHash = await sha256Hex(refreshToken);
  const refreshJti = randomToken(16);
  await env.AUTH_KV.put(
    "refresh:" + refreshHash,
    JSON.stringify({ jti: refreshJti, user_id: user.id, client_id: clientId, scope, expires_at: now + REFRESH_TTL }),
    { expirationTtl: REFRESH_TTL }
  );
  await env.AUTH_DB.prepare(
    "INSERT INTO tokens (id, user_id, client_id, token_type, scope, revoked, expires_at, created_at) VALUES (?, ?, ?, ?, ?, 0, ?, ?)"
  ).bind(refreshJti, user.id, clientId, "refresh", scope, now + REFRESH_TTL, now).run();

  return {
    access_token: accessToken,
    id_token: idToken,
    refresh_token: refreshToken,
    token_type: "Bearer",
    expires_in: ACCESS_TTL,
    scope,
  };
}

async function handleToken(request, env, url) {
  const body = await parseRequestParams(request);
  let clientId = body.client_id || "";
  let clientSecret = body.client_secret || "";
  const authHdr = request.headers.get("authorization") || "";
  if (authHdr.toLowerCase().startsWith("basic ")) {
    try {
      const dec = atob(authHdr.slice(6).trim());
      const i = dec.indexOf(":");
      if (i >= 0) {
        clientId = decodeURIComponent(dec.slice(0, i));
        clientSecret = decodeURIComponent(dec.slice(i + 1));
      }
    } catch (_) {}
  }

  const grantType = body.grant_type;
  const issuer = env.ISSUER || url.origin;

  if (grantType === "authorization_code") {
    const code = body.code;
    if (!code) return jsonResponse({ error: "invalid_request", error_description: "missing code" }, 400);
    const codeData = await env.AUTH_KV.get("auth_code:" + code, { type: "json" });
    if (!codeData) return jsonResponse({ error: "invalid_grant", error_description: "invalid or expired code" }, 400);
    if (!(await consumeSingleUseToken(env, "auth_code:" + code, CODE_TTL))) {
      return jsonResponse({ error: "invalid_grant", error_description: "code already used" }, 400);
    }
    await env.AUTH_KV.delete("auth_code:" + code);

    if (clientId && codeData.client_id !== clientId) {
      return jsonResponse({ error: "invalid_grant", error_description: "client_id mismatch" }, 400);
    }
    const effectiveClientId = clientId || codeData.client_id;
    const client = await env.AUTH_DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(effectiveClientId).first();
    if (!client) return jsonResponse({ error: "invalid_client" }, 401);
    if (client.client_secret_hash) {
      if (!clientSecret || !(await sha256Hex(clientSecret).then((h) => timingSafeEqual(h, client.client_secret_hash)))) {
        return jsonResponse({ error: "invalid_client" }, 401);
      }
    }
    if (body.redirect_uri && body.redirect_uri !== codeData.redirect_uri) {
      return jsonResponse({ error: "invalid_grant", error_description: "redirect_uri mismatch" }, 400);
    }
    if (codeData.code_challenge) {
      const verifier = body.code_verifier || "";
      if (!verifier) return jsonResponse({ error: "invalid_grant", error_description: "missing code_verifier" }, 400);
      const computed = await sha256B64u(verifier);
      if (!timingSafeEqual(computed, codeData.code_challenge)) {
        return jsonResponse({ error: "invalid_grant", error_description: "PKCE verification failed" }, 400);
      }
    }
    const user = await env.AUTH_DB.prepare("SELECT id, email, username, name, picture, role FROM users WHERE id = ?")
      .bind(codeData.user_id).first();
    if (!user) return jsonResponse({ error: "invalid_grant", error_description: "user not found" }, 400);

    const tokens = await mintTokenSet(env, issuer, user, effectiveClientId, codeData.scope, codeData.nonce, codeData.auth_time, codeData.amr);
    return jsonResponse(tokens);
  }

  if (grantType === "refresh_token") {
    const rt = body.refresh_token;
    if (!rt) return jsonResponse({ error: "invalid_request", error_description: "missing refresh_token" }, 400);
    const rtHash = await sha256Hex(rt);
    const rtData = await env.AUTH_KV.get("refresh:" + rtHash, { type: "json" });
    if (!rtData) return jsonResponse({ error: "invalid_grant", error_description: "invalid or expired refresh_token" }, 400);

    const dbTok = await env.AUTH_DB.prepare("SELECT revoked FROM tokens WHERE id = ?").bind(rtData.jti).first();
    if (dbTok && dbTok.revoked === 1) {
      return jsonResponse({ error: "invalid_grant", error_description: "token revoked" }, 400);
    }
    if (clientId && clientId !== rtData.client_id) {
      return jsonResponse({ error: "invalid_grant", error_description: "client_id mismatch" }, 400);
    }
    const rtClient = await env.AUTH_DB.prepare("SELECT * FROM oauth_clients WHERE client_id = ?").bind(rtData.client_id).first();
    if (!rtClient) return jsonResponse({ error: "invalid_client" }, 401);
    if (rtClient.client_secret_hash) {
      if (!clientSecret || !(await sha256Hex(clientSecret).then((h) => timingSafeEqual(h, rtClient.client_secret_hash)))) {
        return jsonResponse({ error: "invalid_client" }, 401);
      }
    }

    if (!(await consumeSingleUseToken(env, "refresh:" + rtData.jti, REFRESH_TTL))) {
      return jsonResponse({ error: "invalid_grant", error_description: "token already used" }, 400);
    }
    await env.AUTH_KV.delete("refresh:" + rtHash);
    await env.AUTH_DB.prepare("UPDATE tokens SET revoked = 1 WHERE id = ?").bind(rtData.jti).run();

    const user = await env.AUTH_DB.prepare("SELECT id, email, username, name, picture, role FROM users WHERE id = ?")
      .bind(rtData.user_id).first();
    if (!user) return jsonResponse({ error: "invalid_grant" }, 400);

    const tokens = await mintTokenSet(env, issuer, user, rtData.client_id, rtData.scope, null, null, ["rt"]);
    return jsonResponse(tokens);
  }

  return jsonResponse({ error: "unsupported_grant_type" }, 400);
}

async function handleRevoke(request, env) {
  const body = await parseRequestParams(request);
  const tok = body.token;
  if (tok) {
    const rtHash = await sha256Hex(tok);
    const rtData = await env.AUTH_KV.get("refresh:" + rtHash, { type: "json" });
    if (rtData) {
      await env.AUTH_KV.delete("refresh:" + rtHash);
      await env.AUTH_DB.prepare("UPDATE tokens SET revoked = 1 WHERE id = ?").bind(rtData.jti).run();
    } else {
      const payload = await verifyJwt(env, tok);
      if (payload && payload.jti) {
        await env.AUTH_KV.put("revoked_jti:" + payload.jti, "1", { expirationTtl: ACCESS_TTL });
      }
    }
  }
  return jsonResponse({ revoked: true });
}

async function handleUserinfo(request, env) {
  const auth = request.headers.get("authorization") || "";
  if (!auth.toLowerCase().startsWith("bearer ")) {
    return jsonResponse({ error: "invalid_token" }, 401, { "www-authenticate": 'Bearer error="invalid_token"' });
  }
  const token = auth.slice(7).trim();
  const payload = await verifyJwt(env, token);
  if (!payload || !payload.sub) {
    return jsonResponse({ error: "invalid_token" }, 401, { "www-authenticate": 'Bearer error="invalid_token"' });
  }
  if (payload.jti && await env.AUTH_KV.get("revoked_jti:" + payload.jti)) {
    return jsonResponse({ error: "invalid_token" }, 401);
  }
  const user = await env.AUTH_DB.prepare("SELECT id, email, username, name, picture, role FROM users WHERE id = ?")
    .bind(payload.sub).first();
  if (!user) return jsonResponse({ error: "invalid_token" }, 401);
  const providers = (await getUserProviders(env, user.id)).map((p) => ({
    provider: p.provider,
    username: p.username,
    id: p.provider_user_id,
  }));
  return jsonResponse({
    sub: user.id,
    email: user.email,
    name: user.name || user.username,
    preferred_username: user.username || user.email || user.id,
    role: user.role || "user",
    picture: user.picture || null,
    providers,
  });
}

// ---- WebAuthn Passkey Endpoints ----

async function handlePasskeyLoginBegin(request, env, url) {
  const challenge = randomToken(32);
  const challengeId = randomToken(18);
  const rpId = url.hostname;
  await env.AUTH_KV.put(
    "webauthn_chal:" + challengeId,
    JSON.stringify({ challenge, type: "auth", rp_id: rpId, origin: url.origin }),
    { expirationTtl: CHALLENGE_TTL }
  );
  return jsonResponse({
    challenge_id: challengeId,
    publicKey: {
      challenge,
      rpId,
      timeout: 60000,
      userVerification: "preferred",
      allowCredentials: [],
    },
  });
}

async function handlePasskeyLoginFinish(request, env, url) {
  const body = await parseRequestParams(request);
  const chalId = body.challenge_id;
  if (!chalId || !body.response || !body.rawId) {
    return jsonResponse({ error: "invalid_request" }, 400);
  }
  const chal = await env.AUTH_KV.get("webauthn_chal:" + chalId, { type: "json" });
  if (!chal || chal.type !== "auth") return jsonResponse({ error: "invalid_challenge" }, 400);
  if (!(await consumeSingleUseToken(env, "webauthn_chal:" + chalId, CHALLENGE_TTL))) {
    return jsonResponse({ error: "invalid_challenge", error_description: "challenge already used" }, 400);
  }
  await env.AUTH_KV.delete("webauthn_chal:" + chalId);

  const clientDataBytes = b64uDecode(body.response.clientDataJSON);
  const clientData = JSON.parse(_dec.decode(clientDataBytes));
  if (clientData.type !== "webauthn.get" || clientData.challenge !== chal.challenge || clientData.origin !== chal.origin) {
    return jsonResponse({ error: "clientDataJSON verification failed" }, 400);
  }

  const authData = b64uDecode(body.response.authenticatorData);
  if (authData.length < 37) return jsonResponse({ error: "invalid authenticatorData" }, 400);
  const expectedRpHash = await sha256(chal.rp_id);
  for (let i = 0; i < 32; i++) {
    if (authData[i] !== expectedRpHash[i]) return jsonResponse({ error: "rpIdHash mismatch" }, 400);
  }
  if ((authData[32] & 0x01) === 0) return jsonResponse({ error: "user presence flag missing" }, 400);
  const signCount = ((authData[33] << 24) >>> 0) + (authData[34] << 16) + (authData[35] << 8) + authData[36];

  const credId = String(body.rawId);
  const pk = await env.AUTH_DB.prepare("SELECT * FROM passkeys WHERE id = ?").bind(credId).first();
  if (!pk) return jsonResponse({ error: "passkey not registered" }, 401);

  const clientHash = await sha256(clientDataBytes);
  const signedData = new Uint8Array(authData.length + clientHash.length);
  signedData.set(authData, 0);
  signedData.set(clientHash, authData.length);

  const pubKey = await crypto.subtle.importKey(
    "raw",
    b64Decode(pk.public_key_b64),
    { name: "ECDSA", namedCurve: "P-256" },
    false,
    ["verify"]
  );
  const sig64 = derSigToP1363(b64uDecode(body.response.signature));
  const ok = await crypto.subtle.verify(
    { name: "ECDSA", hash: "SHA-256" },
    pubKey,
    sig64,
    signedData
  );
  if (!ok) return jsonResponse({ error: "passkey signature invalid" }, 401);

  if ((signCount !== 0 || pk.sign_count !== 0) && signCount <= pk.sign_count) {
    return jsonResponse({ error: "passkey sign_count rollback detected" }, 401);
  }

  const now = Math.floor(Date.now() / 1000);
  await env.AUTH_DB.prepare("UPDATE passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?")
    .bind(signCount, now, credId).run();

  const sid = await createSession(env, request, pk.user_id, ["hwk", "pop"]);
  return jsonResponse(
    { ok: true, redirect: safeReturnTo(body.return_to, "/account") },
    200,
    { "set-cookie": makeCookie(COOKIE_SID, sid, SESSION_TTL, url) }
  );
}

async function handlePasskeyRegisterBegin(request, env, url) {
  const session = await getSession(request, env);
  if (!session) return jsonResponse({ error: "unauthorized" }, 401);

  const challenge = randomToken(32);
  const challengeId = randomToken(18);
  const rpId = url.hostname;
  await env.AUTH_KV.put(
    "webauthn_chal:" + challengeId,
    JSON.stringify({ challenge, type: "reg", user_id: session.user.id, rp_id: rpId, origin: url.origin }),
    { expirationTtl: CHALLENGE_TTL }
  );
  return jsonResponse({
    challenge_id: challengeId,
    publicKey: {
      challenge,
      rp: { name: "fucloudflare Auth", id: rpId },
      user: {
        id: b64uEncode(session.user.id),
        name: session.user.email || session.user.username || session.user.id,
        displayName: session.user.name || session.user.username || session.user.email || "User",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
      timeout: 60000,
      attestation: "none",
    },
  });
}

async function handlePasskeyRegisterFinish(request, env) {
  const session = await getSession(request, env);
  if (!session) return jsonResponse({ error: "unauthorized" }, 401);
  const body = await parseRequestParams(request);
  const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
  if (suppliedCsrf && (!session.sess.csrf_token || !timingSafeEqual(suppliedCsrf, session.sess.csrf_token))) {
    return jsonResponse({ error: "invalid_csrf_token" }, 403);
  }
  const chalId = body.challenge_id;
  if (!chalId || !body.response) return jsonResponse({ error: "invalid_request" }, 400);
  const chal = await env.AUTH_KV.get("webauthn_chal:" + chalId, { type: "json" });
  if (!chal || chal.type !== "reg" || chal.user_id !== session.user.id) {
    return jsonResponse({ error: "invalid_challenge" }, 400);
  }
  if (!(await consumeSingleUseToken(env, "webauthn_chal:" + chalId, CHALLENGE_TTL))) {
    return jsonResponse({ error: "invalid_challenge", error_description: "challenge already used" }, 400);
  }
  await env.AUTH_KV.delete("webauthn_chal:" + chalId);

  const clientData = JSON.parse(_dec.decode(b64uDecode(body.response.clientDataJSON)));
  if (clientData.type !== "webauthn.create" || clientData.challenge !== chal.challenge || clientData.origin !== chal.origin) {
    return jsonResponse({ error: "clientDataJSON verification failed" }, 400);
  }

  const att = cborDecode(b64uDecode(body.response.attestationObject));
  if (!att || !(att.authData instanceof Uint8Array)) {
    return jsonResponse({ error: "invalid attestationObject" }, 400);
  }
  const parsed = parseAttestationAuthData(att.authData);
  if ((parsed.flags & 0x01) === 0) {
    return jsonResponse({ error: "user presence flag missing" }, 400);
  }
  const expectedRpHash = await sha256(chal.rp_id);
  for (let i = 0; i < 32; i++) {
    if (parsed.rpIdHash[i] !== expectedRpHash[i]) return jsonResponse({ error: "rpIdHash mismatch" }, 400);
  }

  const credId = b64uEncode(parsed.credId);
  const existingCred = await env.AUTH_DB.prepare("SELECT user_id FROM passkeys WHERE id = ?").bind(credId).first();
  if (existingCred) {
    return jsonResponse({ error: "credential_already_registered" }, 409);
  }
  const now = Math.floor(Date.now() / 1000);
  await env.AUTH_DB.prepare(
    "INSERT INTO passkeys (id, user_id, name, public_key_b64, alg, sign_count, transports, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    credId,
    session.user.id,
    String(body.name || "Passkey").slice(0, 64),
    b64Encode(parsed.rawPub),
    parsed.alg,
    parsed.signCount,
    JSON.stringify(body.transports || []),
    now,
    now
  ).run();

  return jsonResponse({ ok: true, id: credId });
}

// ---- External OAuth2 Providers (Linux.do Connect, GitHub, Google, Custom) ----

async function handleExternalOAuthStart(request, env, url, providerId) {
  const providers = await listConfiguredOAuthProviders(env);
  const prov = providers.find((p) => p.id === providerId);
  if (!prov) return jsonResponse({ error: "unknown_provider" }, 404);

  const session = await getSession(request, env);
  const state = randomToken(24);
  const returnTo = safeReturnTo(url.searchParams.get("return_to"), "/account");
  await env.AUTH_KV.put(
    "oauth_state:" + state,
    JSON.stringify({
      state,
      provider: providerId,
      return_to: returnTo,
      link_user_id: session ? session.user.id : null,
      created_at: Math.floor(Date.now() / 1000),
    }),
    { expirationTtl: STATE_TTL }
  );

  const callbackUrl = `${url.origin}/login/oauth/${encodeURIComponent(providerId)}/callback`;
  const authUrl = new URL(prov.authorize_url);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("client_id", prov.client_id);
  authUrl.searchParams.set("redirect_uri", callbackUrl);
  authUrl.searchParams.set("scope", prov.scopes || "read");
  authUrl.searchParams.set("state", state);
  return Response.redirect(authUrl.toString(), 302);
}

function normalizeExternalProfile(providerId, raw) {
  const id = String(raw.sub || raw.id || raw.user_id || raw.uid || "");
  const username = raw.username || raw.login || raw.preferred_username || raw.nickname || "";
  const name = raw.name || raw.display_name || username || "";
  const rawEmail = typeof raw.email === "string" ? raw.email.trim() : "";
  const emailVerified = raw.email_verified === true;
  const email = rawEmail || (username ? `${username}@${providerId}.local` : null);
  let avatar = raw.picture || raw.avatar_url || "";
  if (!avatar && raw.avatar_template && providerId === "linuxdo") {
    avatar = "https://linux.do" + String(raw.avatar_template).replace("{size}", "120");
  }
  return { id, username, name, email, emailVerified, avatar };
}

async function handleExternalOAuthCallback(request, env, url, providerId) {
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!code || !state) return jsonResponse({ error: "invalid_callback" }, 400);

  const st = await env.AUTH_KV.get("oauth_state:" + state, { type: "json" });
  if (!st || st.provider !== providerId) return jsonResponse({ error: "invalid_state" }, 400);
  if (!(await consumeSingleUseToken(env, "oauth_state:" + state, STATE_TTL))) {
    return jsonResponse({ error: "invalid_state", error_description: "state already used" }, 400);
  }
  await env.AUTH_KV.delete("oauth_state:" + state);

  const providers = await listConfiguredOAuthProviders(env);
  const prov = providers.find((p) => p.id === providerId);
  if (!prov) return jsonResponse({ error: "unknown_provider" }, 404);

  const callbackUrl = `${url.origin}/login/oauth/${encodeURIComponent(providerId)}/callback`;
  const tokenBody = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: callbackUrl,
    client_id: prov.client_id,
    client_secret: prov.client_secret,
  });
  const tokRes = await fetch(prov.token_url, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      accept: "application/json",
      "user-agent": "fucloudflare-auth/1.0",
    },
    body: tokenBody.toString(),
  });
  if (!tokRes.ok) {
    return jsonResponse({ error: "token_exchange_failed", status: tokRes.status }, 502);
  }
  const tokData = await tokRes.json();
  const accessToken = tokData.access_token;
  if (!accessToken) return jsonResponse({ error: "missing_access_token" }, 502);

  const userRes = await fetch(prov.userinfo_url, {
    method: "GET",
    headers: {
      authorization: "Bearer " + accessToken,
      accept: "application/json",
      "user-agent": "fucloudflare-auth/1.0",
    },
  });
  if (!userRes.ok) {
    return jsonResponse({ error: "userinfo_failed", status: userRes.status }, 502);
  }
  const rawUser = await userRes.json();
  const profile = normalizeExternalProfile(providerId, rawUser);
  if (!profile.id) return jsonResponse({ error: "missing_provider_user_id" }, 502);

  const now = Math.floor(Date.now() / 1000);
  const fedId = `${providerId}:${profile.id}`;
  const existingFed = await env.AUTH_DB.prepare("SELECT user_id FROM federated_identities WHERE id = ?").bind(fedId).first();

  if (existingFed && st.link_user_id && existingFed.user_id !== st.link_user_id) {
    return jsonResponse({ error: "identity_already_linked" }, 409);
  }

  let userId = st.link_user_id || (existingFed && existingFed.user_id) || null;
  if (!userId && profile.emailVerified && profile.email && !profile.email.endsWith(`@${providerId}.local`)) {
    const byEmail = await env.AUTH_DB.prepare("SELECT id FROM users WHERE lower(email) = lower(?)").bind(profile.email).first();
    if (byEmail) userId = byEmail.id;
  }
  if (!userId) {
    userId = crypto.randomUUID();
    const verifiedEmail = (profile.emailVerified && profile.email && !profile.email.endsWith(`@${providerId}.local`))
      ? profile.email.toLowerCase()
      : null;
    await env.AUTH_DB.prepare(
      "INSERT INTO users (id, email, username, name, picture, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, ?, 'user', NULL, ?, ?)"
    ).bind(userId, verifiedEmail, profile.username || profile.id, profile.name, profile.avatar || null, now, now).run();
  }

  await env.AUTH_DB.prepare(
    "INSERT OR REPLACE INTO federated_identities (id, user_id, provider, provider_user_id, email, username, name, avatar_url, raw_json, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
  ).bind(
    fedId,
    userId,
    providerId,
    profile.id,
    profile.email,
    profile.username,
    profile.name,
    profile.avatar,
    JSON.stringify(rawUser).slice(0, 4096),
    now,
    now
  ).run();

  const sid = await createSession(env, request, userId, [providerId]);
  const redirPath = safeReturnTo(st.return_to, "/account");
  return new Response(null, {
    status: 302,
    headers: securityHeaders({
      location: url.origin + redirPath,
      "set-cookie": makeCookie(COOKIE_SID, sid, SESSION_TTL, url),
    }),
  });
}

// ---- Local Password, Register, Account, Logout ----

async function handlePasswordLogin(request, env, url) {
  const body = await parseRequestParams(request);
  const identifier = String(body.identifier || "").trim().toLowerCase();
  const password = String(body.password || "");
  if (!identifier || !password) return jsonResponse({ error: "Email/username and password are required" }, 400);

  const user = await env.AUTH_DB.prepare(
    "SELECT * FROM users WHERE lower(email) = ? OR lower(username) = ?"
  ).bind(identifier, identifier).first();
  if (!user || !(await verifyPassword(password, user.password_hash))) {
    return jsonResponse({ error: "Invalid credentials" }, 401);
  }
  const sid = await createSession(env, request, user.id, ["pwd"]);
  return jsonResponse(
    { ok: true, redirect: safeReturnTo(body.return_to, "/account") },
    200,
    { "set-cookie": makeCookie(COOKIE_SID, sid, SESSION_TTL, url) }
  );
}

async function handleRegister(request, env, url) {
  const body = await parseRequestParams(request);
  const email = String(body.email || "").trim().toLowerCase();
  const username = String(body.username || "").trim();
  const name = String(body.name || username).trim();
  const password = String(body.password || "");
  if (!email || !username || password.length < 8) {
    return jsonResponse({ error: "Valid email, username, and password (>= 8 chars) are required" }, 400);
  }
  const dup = await env.AUTH_DB.prepare("SELECT id FROM users WHERE lower(email) = ? OR lower(username) = ?")
    .bind(email, username.toLowerCase()).first();
  if (dup) return jsonResponse({ error: "Email or username already exists" }, 409);

  const userId = crypto.randomUUID();
  const pwHash = await hashPassword(password);
  const now = Math.floor(Date.now() / 1000);
  await env.AUTH_DB.prepare(
    "INSERT INTO users (id, email, username, name, picture, role, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?, NULL, 'user', ?, ?, ?)"
  ).bind(userId, email, username, name, pwHash, now, now).run();

  const sid = await createSession(env, request, userId, ["pwd"]);
  return jsonResponse(
    { ok: true, redirect: safeReturnTo(body.return_to, "/account") },
    201,
    { "set-cookie": makeCookie(COOKIE_SID, sid, SESSION_TTL, url) }
  );
}

async function handleAccountPage(request, env) {
  const session = await getSession(request, env);
  if (!session) return Response.redirect(new URL(request.url).origin + "/login?return_to=%2Faccount", 302);

  const pkRes = await env.AUTH_DB.prepare("SELECT id, name, sign_count, created_at FROM passkeys WHERE user_id = ?")
    .bind(session.user.id).all();
  const passkeys = (pkRes && pkRes.results) || [];
  const identities = await getUserProviders(env, session.user.id);
  const allProviders = await listConfiguredOAuthProviders(env);

  const sessList = await env.AUTH_KV.list({ prefix: `sess_idx:${session.user.id}:` });
  const sessions = [];
  if (sessList && Array.isArray(sessList.keys)) {
    for (const k of sessList.keys) {
      const s = await env.AUTH_KV.get(k.name, { type: "json" });
      if (s) sessions.push(Object.assign({}, s, { current: s.sid === session.sid }));
    }
  }
  return htmlResponse(renderAccountPage({
    user: session.user,
    passkeys,
    identities,
    sessions,
    allProviders,
    csrfToken: session.sess.csrf_token || "",
  }));
}

async function handleLogout(request, env, url) {
  const cookies = parseCookies(request);
  const sid = cookies[COOKIE_SID];
  if (sid) {
    const sess = await env.AUTH_KV.get("session:" + sid, { type: "json" });
    if (sess) {
      let body = {};
      try { body = await parseRequestParams(request); } catch (_) {}
      const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
      if (suppliedCsrf && (!sess.csrf_token || !timingSafeEqual(suppliedCsrf, sess.csrf_token))) {
        return jsonResponse({ error: "invalid_csrf_token" }, 403);
      }
    }
    await env.AUTH_KV.delete("session:" + sid);
    if (sess && sess.user_id) {
      await env.AUTH_KV.delete(`sess_idx:${sess.user_id}:${sid}`);
    }
  }
  const accept = request.headers.get("accept") || "";
  if (accept.includes("application/json")) {
    return jsonResponse({ ok: true }, 200, { "set-cookie": clearCookie(COOKIE_SID, url) });
  }
  return new Response(null, {
    status: 302,
    headers: securityHeaders({ location: "/login", "set-cookie": clearCookie(COOKIE_SID, url) }),
  });
}

// ---- Main Router ----

export default {
  async fetch(request, env, _ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    if (path === "/healthz" && method === "GET") {
      return jsonResponse({ ok: true, service: "auth.fucloudflare.com" });
    }

    await ensureSchema(env);
    const issuer = env.ISSUER || url.origin;

    const csrfProtectedPostPaths = new Set([
      "/authorize/consent",
      "/login/password",
      "/register",
      "/logout",
      "/login/passkey/begin",
      "/login/passkey/finish",
      "/register/passkey/begin",
      "/register/passkey/finish",
      "/account/passkey/delete",
      "/account/identity/unlink",
      "/account/session/revoke",
    ]);
    if (method === "POST" && csrfProtectedPostPaths.has(path) && !verifySameOrigin(request, url)) {
      return jsonResponse({ error: "csrf_origin_mismatch" }, 403);
    }

    if (path === "/.well-known/openid-configuration" && method === "GET") {
      return jsonResponse({
        issuer,
        authorization_endpoint: issuer + "/authorize",
        token_endpoint: issuer + "/token",
        userinfo_endpoint: issuer + "/userinfo",
        revocation_endpoint: issuer + "/revoke",
        jwks_uri: issuer + "/.well-known/jwks.json",
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["ES256"],
        scopes_supported: ["openid", "profile", "email", "offline_access"],
        token_endpoint_auth_methods_supported: ["none", "client_secret_post", "client_secret_basic"],
        code_challenge_methods_supported: ["S256"],
        claims_supported: ["sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "email", "name", "preferred_username", "role", "picture", "providers"],
      });
    }

    if (path === "/.well-known/jwks.json" && method === "GET") {
      const key = await getSigningKey(env);
      return jsonResponse({ keys: [key.jwk] }, 200, { "cache-control": "public, max-age=300" });
    }

    if (path === "/authorize" && method === "GET") return handleAuthorize(request, env, url);
    if (path === "/authorize/consent" && method === "POST") return handleAuthorizeConsent(request, env);
    if (path === "/token" && method === "POST") return handleToken(request, env, url);
    if (path === "/revoke" && method === "POST") return handleRevoke(request, env);
    if (path === "/userinfo" && (method === "GET" || method === "POST")) return handleUserinfo(request, env);

    if (path === "/login" && method === "GET") {
      const providers = await listConfiguredOAuthProviders(env);
      return htmlResponse(renderLoginPage({
        providers,
        returnTo: url.searchParams.get("return_to") || "/account",
        pendingId: url.searchParams.get("pending") || "",
      }));
    }
    if (path === "/login/password" && method === "POST") return handlePasswordLogin(request, env, url);
    if (path === "/register" && method === "POST") return handleRegister(request, env, url);
    if (path === "/logout" && method === "POST") return handleLogout(request, env, url);
    if (path === "/logout") return jsonResponse({ error: "method_not_allowed" }, 405, { allow: "POST" });

    if (path === "/login/passkey/begin" && method === "POST") return handlePasskeyLoginBegin(request, env, url);
    if (path === "/login/passkey/finish" && method === "POST") return handlePasskeyLoginFinish(request, env, url);
    if (path === "/register/passkey/begin" && method === "POST") return handlePasskeyRegisterBegin(request, env, url);
    if (path === "/register/passkey/finish" && method === "POST") return handlePasskeyRegisterFinish(request, env);

    const oauthCbMatch = /^\/login\/oauth\/([a-zA-Z0-9_-]+)\/callback$/.exec(path);
    if (oauthCbMatch && method === "GET") {
      return handleExternalOAuthCallback(request, env, url, oauthCbMatch[1]);
    }
    const oauthStartMatch = /^\/login\/oauth\/([a-zA-Z0-9_-]+)$/.exec(path);
    if (oauthStartMatch && method === "GET") {
      return handleExternalOAuthStart(request, env, url, oauthStartMatch[1]);
    }

    if ((path === "/" || path === "/account") && method === "GET") return handleAccountPage(request, env);

    if (path === "/account/passkey/delete" && method === "POST") {
      const session = await getSession(request, env);
      if (!session) return jsonResponse({ error: "unauthorized" }, 401);
      const body = await parseRequestParams(request);
      const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
      if (suppliedCsrf && (!session.sess.csrf_token || !timingSafeEqual(suppliedCsrf, session.sess.csrf_token))) {
        return jsonResponse({ error: "invalid_csrf_token" }, 403);
      }
      await env.AUTH_DB.prepare("DELETE FROM passkeys WHERE id = ? AND user_id = ?")
        .bind(String(body.id || ""), session.user.id).run();
      return jsonResponse({ ok: true });
    }
    if (path === "/account/identity/unlink" && method === "POST") {
      const session = await getSession(request, env);
      if (!session) return jsonResponse({ error: "unauthorized" }, 401);
      const body = await parseRequestParams(request);
      const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
      if (suppliedCsrf && (!session.sess.csrf_token || !timingSafeEqual(suppliedCsrf, session.sess.csrf_token))) {
        return jsonResponse({ error: "invalid_csrf_token" }, 403);
      }
      await env.AUTH_DB.prepare("DELETE FROM federated_identities WHERE provider = ? AND user_id = ?")
        .bind(String(body.provider || ""), session.user.id).run();
      return jsonResponse({ ok: true });
    }
    if (path === "/account/session/revoke" && method === "POST") {
      const session = await getSession(request, env);
      if (!session) return jsonResponse({ error: "unauthorized" }, 401);
      const body = await parseRequestParams(request);
      const suppliedCsrf = request.headers.get("x-csrf-token") || body.csrf_token;
      if (suppliedCsrf && (!session.sess.csrf_token || !timingSafeEqual(suppliedCsrf, session.sess.csrf_token))) {
        return jsonResponse({ error: "invalid_csrf_token" }, 403);
      }
      const targetSid = String(body.sid || "");
      if (!targetSid) return jsonResponse({ error: "invalid_request" }, 400);
      const targetSess = await env.AUTH_KV.get("session:" + targetSid, { type: "json" });
      if (!targetSess) return jsonResponse({ error: "session_not_found" }, 404);
      if (targetSess.user_id !== session.user.id) return jsonResponse({ error: "forbidden" }, 403);
      await env.AUTH_KV.delete("session:" + targetSid);
      await env.AUTH_KV.delete(`sess_idx:${session.user.id}:${targetSid}`);
      return jsonResponse({ ok: true });
    }

    return jsonResponse({ error: "not_found" }, 404);
  },
};
