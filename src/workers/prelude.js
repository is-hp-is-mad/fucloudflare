// Runtime prelude for fucf workers: a small implementation of the Fetch API
// surface (Headers, Request, Response, URL, fetch) on top of host functions:
// __fetch(json) -> json, __bodyText(id) -> string, __bodyBytes(id) ->
// ArrayBuffer, __bodyPut(ArrayBuffer) -> id, __textBytes(string) ->
// ArrayBuffer, __log(string), and the crypto / KV / D1 ones (see mod.rs).
(function () {
  "use strict";
  const lower = (s) => String(s).toLowerCase();

  class Headers {
    constructor(init) {
      this._h = [];
      if (init instanceof Headers) init._h.forEach((e) => this.append(e[0], e[1]));
      else if (Array.isArray(init)) init.forEach((e) => this.append(e[0], e[1]));
      else if (init) Object.keys(init).forEach((k) => this.append(k, init[k]));
    }
    append(k, v) { this._h.push([lower(k), String(v)]); }
    set(k, v) { this.delete(k); this.append(k, v); }
    get(k) {
      k = lower(k);
      const v = this._h.filter((e) => e[0] === k).map((e) => e[1]);
      return v.length ? v.join(", ") : null;
    }
    has(k) { k = lower(k); return this._h.some((e) => e[0] === k); }
    delete(k) { k = lower(k); this._h = this._h.filter((e) => e[0] !== k); }
    forEach(fn, thisArg) { this._h.forEach((e) => fn.call(thisArg, e[1], e[0], this)); }
    entries() { return this._h.map((e) => [e[0], e[1]])[Symbol.iterator](); }
    keys() { return this._h.map((e) => e[0])[Symbol.iterator](); }
    values() { return this._h.map((e) => e[1])[Symbol.iterator](); }
    [Symbol.iterator]() { return this.entries(); }
  }

  class URLSearchParams {
    constructor(init, url) {
      this._p = [];
      this._url = url || null;
      const dec = (s) => decodeURIComponent(s.replace(/\+/g, " "));
      if (typeof init === "string") {
        init.replace(/^\?/, "").split("&").filter(Boolean).forEach((kv) => {
          const i = kv.indexOf("=");
          this._p.push(i < 0 ? [dec(kv), ""] : [dec(kv.slice(0, i)), dec(kv.slice(i + 1))]);
        });
      } else if (init instanceof URLSearchParams) this._p = init._p.map((e) => [e[0], e[1]]);
      else if (init) Object.keys(init).forEach((k) => this._p.push([k, String(init[k])]));
    }
    _sync() { if (this._url) { const s = this.toString(); this._url.search = s ? "?" + s : ""; } }
    get(k) { const e = this._p.find((e) => e[0] === k); return e ? e[1] : null; }
    getAll(k) { return this._p.filter((e) => e[0] === k).map((e) => e[1]); }
    has(k) { return this._p.some((e) => e[0] === k); }
    set(k, v) {
      const i = this._p.findIndex((e) => e[0] === k);
      this._p = this._p.filter((e, j) => e[0] !== k || j === i);
      if (i < 0) this._p.push([k, String(v)]); else this._p.find((e) => e[0] === k)[1] = String(v);
      this._sync();
    }
    append(k, v) { this._p.push([k, String(v)]); this._sync(); }
    delete(k) { this._p = this._p.filter((e) => e[0] !== k); this._sync(); }
    forEach(fn, thisArg) { this._p.forEach((e) => fn.call(thisArg, e[1], e[0], this)); }
    entries() { return this._p.map((e) => [e[0], e[1]])[Symbol.iterator](); }
    keys() { return this._p.map((e) => e[0])[Symbol.iterator](); }
    [Symbol.iterator]() { return this.entries(); }
    toString() { return this._p.map((e) => encodeURIComponent(e[0]) + "=" + encodeURIComponent(e[1])).join("&"); }
  }

  const URL_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):\/\/([^\/?#]*)([^?#]*)(\?[^#]*)?(#.*)?$/;
  class URL {
    constructor(input, base) {
      let s = String(input);
      let m = URL_RE.exec(s);
      if (!m && base !== undefined) {
        const b = new URL(base);
        if (s.startsWith("//")) s = b.protocol + s;
        else if (s.startsWith("/")) s = b.origin + s;
        else if (s.startsWith("?")) s = b.origin + b.pathname + s;
        else s = b.origin + b.pathname.replace(/[^\/]*$/, "") + s;
        m = URL_RE.exec(s);
      }
      if (!m) throw new TypeError("Invalid URL: " + input);
      this.protocol = m[1].toLowerCase() + ":";
      const at = m[2].lastIndexOf("@");
      const hostport = at < 0 ? m[2] : m[2].slice(at + 1);
      const pm = /^(.*?)(?::(\d+))?$/.exec(hostport);
      this.hostname = pm[1].toLowerCase();
      this.port = pm[2] || "";
      this.pathname = m[3] || "/";
      this.search = m[4] && m[4] !== "?" ? m[4] : "";
      this.hash = m[5] && m[5] !== "#" ? m[5] : "";
    }
    get host() { return this.hostname + (this.port ? ":" + this.port : ""); }
    set host(v) { const pm = /^(.*?)(?::(\d+))?$/.exec(String(v)); this.hostname = pm[1]; this.port = pm[2] || ""; }
    get origin() { return this.protocol + "//" + this.host; }
    get href() { return this.origin + this.pathname + this.search + this.hash; }
    get searchParams() { return new URLSearchParams(this.search, this); }
    toString() { return this.href; }
    toJSON() { return this.href; }
  }

  // Bodies are strings (`_text`) or opaque host-side byte buffers (`_bodyId`),
  // so binary bodies pass through a worker untouched. An ArrayBuffer or a view
  // (Uint8Array, DataView, ...) is copied to the host when the body is made,
  // as the Fetch API snapshots it then.
  function putBytes(data) {
    const u8 = toUint8(data);
    const whole = u8.buffer instanceof ArrayBuffer && u8.byteOffset === 0 && u8.byteLength === u8.buffer.byteLength;
    const exact = whole ? u8.buffer : u8.slice().buffer;
    return __bodyPut(exact);
  }
  function initBody(self, body) {
    self._text = null;
    self._bodyId = null;
    self.bodyUsed = false;
    if (body === null || body === undefined) return;
    if (body && body.__bodyOf) {
      self._text = body.__bodyOf._text;
      self._bodyId = body.__bodyOf._bodyId;
    } else if (body instanceof ArrayBuffer || ArrayBuffer.isView(body)) self._bodyId = putBytes(body);
    else self._text = String(body);
  }
  function takeBody(self) {
    if (self.bodyUsed) throw new TypeError("Body has already been used");
    self.bodyUsed = true;
  }
  const bodyMethods = {
    text() {
      try { takeBody(this); } catch (e) { return Promise.reject(e); }
      if (this._text !== null) return Promise.resolve(this._text);
      if (this._bodyId !== null) return Promise.resolve(__bodyText(this._bodyId));
      return Promise.resolve("");
    },
    json() { return this.text().then(JSON.parse); },
    arrayBuffer() {
      try {
        takeBody(this);
        if (this._bodyId !== null) return Promise.resolve(__bodyBytes(this._bodyId));
        if (this._text !== null) return Promise.resolve(__textBytes(this._text));
        return Promise.resolve(new ArrayBuffer(0));
      } catch (e) { return Promise.reject(e); }
    },
    bytes() { return this.arrayBuffer().then((b) => new Uint8Array(b)); },
  };
  const bodyGetter = {
    get() { return this._text === null && this._bodyId === null ? null : { __bodyOf: this }; },
    configurable: true,
  };

  class Request {
    constructor(input, init) {
      init = init || {};
      const from = input instanceof Request ? input : null;
      this.url = from ? from.url : new URL(String(input)).href;
      this.method = String(init.method || (from ? from.method : "GET")).toUpperCase();
      this.headers = new Headers(init.headers || (from ? from.headers : undefined));
      this.redirect = init.redirect || (from ? from.redirect : "follow");
      this.cf = from ? from.cf : {};
      if ("body" in init) initBody(this, init.body);
      else if (from) initBody(this, { __bodyOf: from });
      else initBody(this, null);
    }
    clone() { return new Request(this); }
  }
  Object.assign(Request.prototype, bodyMethods);
  Object.defineProperty(Request.prototype, "body", bodyGetter);

  class Response {
    constructor(body, init) {
      init = init || {};
      this.status = init.status === undefined ? 200 : Number(init.status);
      if (!(this.status >= 200 && this.status <= 599)) throw new RangeError("Invalid status " + init.status);
      this.statusText = init.statusText || "";
      this.headers = new Headers(init.headers);
      this.url = "";
      initBody(this, body);
      if (typeof body === "string" && !this.headers.has("content-type")) {
        this.headers.set("content-type", "text/plain;charset=UTF-8");
      }
    }
    get ok() { return this.status >= 200 && this.status < 300; }
    clone() {
      const r = new Response(null, this);
      r._text = this._text; r._bodyId = this._bodyId; r.url = this.url;
      return r;
    }
    static json(data, init) {
      const r = new Response(JSON.stringify(data), init);
      if (!(init && init.headers && new Headers(init.headers).has("content-type"))) {
        r.headers.set("content-type", "application/json");
      }
      return r;
    }
    static redirect(url, status) {
      const code = status === undefined ? 302 : Number(status);
      if (![301, 302, 303, 307, 308].includes(code)) {
        throw new RangeError("Invalid redirect status " + status);
      }
      return new Response(null, { status: code, headers: { location: String(url) } });
    }
  }
  Object.assign(Response.prototype, bodyMethods);
  Object.defineProperty(Response.prototype, "body", bodyGetter);

  function fetch(input, init) {
    try {
      const req = new Request(input, init);
      const out = JSON.parse(__fetch(JSON.stringify({
        method: req.method, url: req.url, headers: req.headers._h, body: req._text, bodyId: req._bodyId,
      })));
      const res = new Response(null, { status: out.status, headers: out.headers });
      res._bodyId = out.bodyId;
      res.url = req.url;
      return Promise.resolve(res);
    } catch (e) {
      return Promise.reject(e);
    }
  }

  const fmt = (args) => args.map((a) => {
    if (typeof a === "string") return a;
    if (a instanceof Error) return String(a.stack || a);
    try { return JSON.stringify(a); } catch (e) { return String(a); }
  }).join(" ");
  const console = {};
  ["log", "info", "warn", "error", "debug"].forEach((level) => {
    console[level] = (...args) => __log(level + ": " + fmt(args));
  });

  let listener = null;
  // ---- Base64 / UTF-8 / TypedArray helpers ----
  const B64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  function bytesToB64(bytes) {
    const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let out = "";
    for (let i = 0; i < u8.length; i += 3) {
      const a = u8[i], b = i + 1 < u8.length ? u8[i + 1] : 0, c = i + 2 < u8.length ? u8[i + 2] : 0;
      const n = (a << 16) | (b << 8) | c;
      out += B64_CHARS[(n >> 18) & 63] + B64_CHARS[(n >> 12) & 63] +
        (i + 1 < u8.length ? B64_CHARS[(n >> 6) & 63] : "=") +
        (i + 2 < u8.length ? B64_CHARS[n & 63] : "=");
    }
    return out;
  }
  function b64ToBytes(b64) {
    const s = String(b64).replace(/[\r\n\s]/g, "").replace(/=+$/, "");
    const out = new Uint8Array(Math.floor((s.length * 3) / 4));
    let p = 0;
    for (let i = 0; i < s.length; i += 4) {
      const c1 = B64_CHARS.indexOf(s[i]), c2 = B64_CHARS.indexOf(s[i + 1]);
      const c3 = i + 2 < s.length ? B64_CHARS.indexOf(s[i + 2]) : 0;
      const c4 = i + 3 < s.length ? B64_CHARS.indexOf(s[i + 3]) : 0;
      if (c1 < 0 || c2 < 0 || c3 < 0 || c4 < 0) throw new TypeError("Invalid base64");
      const n = (c1 << 18) | (c2 << 12) | (c3 << 6) | c4;
      out[p++] = (n >> 16) & 255;
      if (i + 2 < s.length) out[p++] = (n >> 8) & 255;
      if (i + 3 < s.length) out[p++] = n & 255;
    }
    return out.subarray(0, p);
  }
  function toUint8(data) {
    if (data instanceof Uint8Array) return data;
    if (data instanceof ArrayBuffer) return new Uint8Array(data);
    if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    throw new TypeError("Expected BufferSource");
  }

  class TextEncoder {
    constructor() { this.encoding = "utf-8"; }
    encode(input) {
      const s = input === undefined ? "" : String(input);
      const out = [];
      for (let i = 0; i < s.length; i++) {
        let cp = s.charCodeAt(i);
        if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < s.length) {
          const lo = s.charCodeAt(i + 1);
          if (lo >= 0xdc00 && lo <= 0xdfff) {
            cp = 0x10000 + ((cp - 0xd800) << 10) + (lo - 0xdc00);
            i++;
          }
        }
        if (cp < 0x80) out.push(cp);
        else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
        else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
        else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      }
      return new Uint8Array(out);
    }
  }
  class TextDecoder {
    constructor(label) {
      this.encoding = (label || "utf-8").toLowerCase();
      if (this.encoding !== "utf-8" && this.encoding !== "utf8") {
        throw new RangeError("Unsupported encoding: " + label);
      }
    }
    decode(input) {
      if (input === undefined || input === null) return "";
      const u8 = toUint8(input);
      let out = "";
      for (let i = 0; i < u8.length;) {
        const b0 = u8[i++];
        if (b0 < 0x80) { out += String.fromCharCode(b0); continue; }
        let cp;
        if ((b0 & 0xe0) === 0xc0 && i < u8.length) {
          cp = ((b0 & 0x1f) << 6) | (u8[i++] & 0x3f);
        } else if ((b0 & 0xf0) === 0xe0 && i + 1 < u8.length) {
          cp = ((b0 & 0x0f) << 12) | ((u8[i++] & 0x3f) << 6) | (u8[i++] & 0x3f);
        } else if ((b0 & 0xf8) === 0xf0 && i + 2 < u8.length) {
          cp = ((b0 & 0x07) << 18) | ((u8[i++] & 0x3f) << 12) | ((u8[i++] & 0x3f) << 6) | (u8[i++] & 0x3f);
        } else { out += "\ufffd"; continue; }
        if (cp <= 0xffff) out += String.fromCharCode(cp);
        else {
          cp -= 0x10000;
          out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff));
        }
      }
      return out;
    }
  }
  const _enc = new TextEncoder();
  const _dec = new TextDecoder();

  if (typeof globalThis.btoa !== "function") {
    globalThis.btoa = (s) => bytesToB64(new Uint8Array(String(s).split("").map((c) => c.charCodeAt(0) & 255)));
  }
  if (typeof globalThis.atob !== "function") {
    globalThis.atob = (s) => Array.from(b64ToBytes(s)).map((b) => String.fromCharCode(b)).join("");
  }

  // ---- WebCrypto ----
  function normAlg(alg) {
    if (typeof alg === "string") return { name: alg };
    return Object.assign({}, alg);
  }
  function hashName(alg) {
    if (!alg || !alg.hash) return undefined;
    return typeof alg.hash === "string" ? alg.hash : alg.hash.name;
  }
  class CryptoKey {
    constructor(type, extractable, algorithm, usages, format, keyB64, pubB64) {
      this.type = type;
      this.extractable = !!extractable;
      this.algorithm = algorithm;
      this.usages = Array.isArray(usages) ? usages.slice() : [];
      this._format = format;
      this._keyB64 = keyB64;
      this._pubB64 = pubB64 || null;
    }
  }
  const crypto = {
    getRandomValues(arr) {
      if (!arr || typeof arr.byteLength !== "number" || !ArrayBuffer.isView(arr)) {
        throw new TypeError("Expected TypedArray");
      }
      const bytes = b64ToBytes(__cryptoRandom(arr.byteLength));
      const view = new Uint8Array(arr.buffer, arr.byteOffset, arr.byteLength);
      view.set(bytes);
      return arr;
    },
    randomUUID() {
      const b = b64ToBytes(__cryptoRandom(16));
      b[6] = (b[6] & 0x0f) | 0x40;
      b[8] = (b[8] & 0x3f) | 0x80;
      const hex = Array.from(b).map((x) => x.toString(16).padStart(2, "0")).join("");
      return hex.slice(0, 8) + "-" + hex.slice(8, 12) + "-" + hex.slice(12, 16) + "-" + hex.slice(16, 20) + "-" + hex.slice(20);
    },
    subtle: {
      digest(alg, data) {
        try {
          const a = normAlg(alg);
          const b64 = __cryptoDigest(a.name, bytesToB64(toUint8(data)));
          return Promise.resolve(b64ToBytes(b64).buffer);
        } catch (e) { return Promise.reject(e); }
      },
      importKey(format, keyData, alg, extractable, usages) {
        try {
          const a = normAlg(alg);
          let keyB64;
          if (format === "jwk") keyB64 = bytesToB64(_enc.encode(JSON.stringify(keyData)));
          else keyB64 = bytesToB64(toUint8(keyData));
          let type = "secret";
          if (format === "pkcs8") type = "private";
          else if (format === "spki") type = "public";
          else if (format === "jwk" && keyData && keyData.kty !== "oct") type = keyData.d ? "private" : "public";
          if (format === "jwk" && keyData && keyData.kty === "oct" && keyData.k) {
            const raw = b64ToBytes(keyData.k.replace(/-/g, "+").replace(/_/g, "/"));
            return Promise.resolve(new CryptoKey("secret", extractable, a, usages, "raw", bytesToB64(raw)));
          }
          return Promise.resolve(new CryptoKey(type, extractable, a, usages, format, keyB64));
        } catch (e) { return Promise.reject(e); }
      },
      exportKey(format, key) {
        try {
          if (!key || !key.extractable) throw new Error("Key is not extractable");
          if (format === "raw" && key._format === "raw") return Promise.resolve(b64ToBytes(key._keyB64).buffer);
          if (format === "raw" && key._pubB64) return Promise.resolve(b64ToBytes(key._pubB64).buffer);
          if (format === "pkcs8" && key._format === "pkcs8") return Promise.resolve(b64ToBytes(key._keyB64).buffer);
          if (format === "spki" && key._format === "spki") return Promise.resolve(b64ToBytes(key._keyB64).buffer);
          if (format === "jwk" && key._format === "raw") {
            const k = key._keyB64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
            return Promise.resolve({ kty: "oct", k, ext: true, key_ops: key.usages });
          }
          throw new Error("Unsupported exportKey format: " + format);
        } catch (e) { return Promise.reject(e); }
      },
      generateKey(alg, extractable, usages) {
        try {
          const a = normAlg(alg);
          const name = a.name.toUpperCase();
          if (name === "AES-GCM") {
            const len = (a.length || 256) / 8;
            return Promise.resolve(new CryptoKey("secret", extractable, a, usages, "raw", __cryptoRandom(len)));
          }
          if (name === "HMAC") {
            const len = a.length ? Math.ceil(a.length / 8) : 32;
            return Promise.resolve(new CryptoKey("secret", extractable, a, usages, "raw", __cryptoRandom(len)));
          }
          if (name === "ECDSA") {
            const curve = a.namedCurve || "P-256";
            const kp = JSON.parse(__cryptoGenerateEc(curve));
            const priv = new CryptoKey("private", extractable, a, usages.filter((u) => u === "sign"), "pkcs8", kp.pkcs8_b64, kp.raw_pub_b64);
            const pub = new CryptoKey("public", true, a, usages.filter((u) => u === "verify"), "raw", kp.raw_pub_b64, kp.raw_pub_b64);
            return Promise.resolve({ privateKey: priv, publicKey: pub });
          }
          throw new Error("Unsupported generateKey algorithm: " + a.name);
        } catch (e) { return Promise.reject(e); }
      },
      sign(alg, key, data) {
        try {
          const a = normAlg(alg);
          const ka = normAlg(key.algorithm || a);
          const b64 = __cryptoSign(JSON.stringify({
            alg: a.name,
            hash: hashName(a) || hashName(ka),
            curve: ka.namedCurve || a.namedCurve,
            key_format: key._format,
            key_b64: key._keyB64,
            data_b64: bytesToB64(toUint8(data)),
          }));
          return Promise.resolve(b64ToBytes(b64).buffer);
        } catch (e) { return Promise.reject(e); }
      },
      verify(alg, key, signature, data) {
        try {
          const a = normAlg(alg);
          const ka = normAlg(key.algorithm || a);
          const ok = __cryptoVerify(JSON.stringify({
            alg: a.name,
            hash: hashName(a) || hashName(ka),
            curve: ka.namedCurve || a.namedCurve,
            key_format: key._format,
            key_b64: key._keyB64,
            sig_b64: bytesToB64(toUint8(signature)),
            data_b64: bytesToB64(toUint8(data)),
          }));
          return Promise.resolve(!!ok);
        } catch (e) { return Promise.reject(e); }
      },
      encrypt(alg, key, data) {
        try {
          const a = normAlg(alg);
          const b64 = __cryptoEncrypt(JSON.stringify({
            key_b64: key._keyB64,
            iv_b64: bytesToB64(toUint8(a.iv)),
            aad_b64: a.additionalData ? bytesToB64(toUint8(a.additionalData)) : null,
            data_b64: bytesToB64(toUint8(data)),
          }));
          return Promise.resolve(b64ToBytes(b64).buffer);
        } catch (e) { return Promise.reject(e); }
      },
      decrypt(alg, key, data) {
        try {
          const a = normAlg(alg);
          const b64 = __cryptoDecrypt(JSON.stringify({
            key_b64: key._keyB64,
            iv_b64: bytesToB64(toUint8(a.iv)),
            aad_b64: a.additionalData ? bytesToB64(toUint8(a.additionalData)) : null,
            data_b64: bytesToB64(toUint8(data)),
          }));
          return Promise.resolve(b64ToBytes(b64).buffer);
        } catch (e) { return Promise.reject(e); }
      },
      deriveBits(alg, baseKey, length) {
        try {
          const a = normAlg(alg);
          const b64 = __cryptoDeriveBits(JSON.stringify({
            alg: a.name,
            hash: hashName(a) || "SHA-256",
            key_b64: baseKey._keyB64,
            salt_b64: a.salt ? bytesToB64(toUint8(a.salt)) : "",
            iterations: a.iterations || 0,
            length_bits: length,
          }));
          return Promise.resolve(b64ToBytes(b64).buffer);
        } catch (e) { return Promise.reject(e); }
      },
    },
  };

  // ---- KV & D1 Binding Builders ----
  function decodeKvVal(b64, type) {
    if (b64 === null || b64 === undefined) return null;
    const u8 = b64ToBytes(b64);
    if (!type || type === "text") return _dec.decode(u8);
    if (type === "json") return JSON.parse(_dec.decode(u8));
    if (type === "arrayBuffer") return u8.buffer;
    if (type === "stream") {
      return {
        getReader() {
          let done = false;
          return {
            read() {
              if (done) return Promise.resolve({ done: true, value: undefined });
              done = true;
              return Promise.resolve({ done: false, value: u8 });
            },
            releaseLock() {},
          };
        },
      };
    }
    throw new TypeError("Unsupported KV type: " + type);
  }

  function makeKvBinding(nsId) {
    const parseType = (opts) => (typeof opts === "string" ? opts : (opts && opts.type) || "text");
    return {
      get(keyOrKeys, opts) {
        try {
          const t = parseType(opts);
          if (Array.isArray(keyOrKeys)) {
            const rows = JSON.parse(__kvGet(JSON.stringify({ ns_id: nsId, keys: keyOrKeys.map(String) })));
            const m = new Map();
            rows.forEach((r) => m.set(r.key, decodeKvVal(r.value_b64, t)));
            return Promise.resolve(m);
          }
          const rows = JSON.parse(__kvGet(JSON.stringify({ ns_id: nsId, keys: [String(keyOrKeys)] })));
          return Promise.resolve(decodeKvVal(rows[0].value_b64, t));
        } catch (e) { return Promise.reject(e); }
      },
      getWithMetadata(keyOrKeys, opts) {
        try {
          const t = parseType(opts);
          if (Array.isArray(keyOrKeys)) {
            const rows = JSON.parse(__kvGet(JSON.stringify({ ns_id: nsId, keys: keyOrKeys.map(String) })));
            const m = new Map();
            rows.forEach((r) => m.set(r.key, { value: decodeKvVal(r.value_b64, t), metadata: r.metadata ?? null, cacheStatus: null }));
            return Promise.resolve(m);
          }
          const rows = JSON.parse(__kvGet(JSON.stringify({ ns_id: nsId, keys: [String(keyOrKeys)] })));
          return Promise.resolve({
            value: decodeKvVal(rows[0].value_b64, t),
            metadata: rows[0].metadata ?? null,
            cacheStatus: null,
          });
        } catch (e) { return Promise.reject(e); }
      },
      put(key, value, opts) {
        try {
          opts = opts || {};
          let value_b64;
          if (typeof value === "string") value_b64 = bytesToB64(_enc.encode(value));
          else value_b64 = bytesToB64(toUint8(value));
          __kvPut(JSON.stringify({
            ns_id: nsId,
            key: String(key),
            value_b64,
            expiration: opts.expiration,
            expirationTtl: opts.expirationTtl,
            metadata: opts.metadata,
          }));
          return Promise.resolve();
        } catch (e) { return Promise.reject(e); }
      },
      delete(key) {
        try {
          __kvDelete(JSON.stringify({ ns_id: nsId, key: String(key) }));
          return Promise.resolve();
        } catch (e) { return Promise.reject(e); }
      },
      list(opts) {
        try {
          opts = opts || {};
          return Promise.resolve(JSON.parse(__kvList(JSON.stringify({
            ns_id: nsId,
            prefix: opts.prefix,
            limit: opts.limit,
            cursor: opts.cursor,
          }))));
        } catch (e) { return Promise.reject(e); }
      },
    };
  }

  function encodeD1Param(v) {
    if (v === undefined) throw new TypeError("D1_TYPE_ERROR: Type 'undefined' not supported for value");
    if (v === null || typeof v === "boolean" || typeof v === "number" || typeof v === "string") return v;
    if (v instanceof ArrayBuffer || ArrayBuffer.isView(v)) return { __d1_blob: bytesToB64(toUint8(v)) };
    throw new TypeError("D1_TYPE_ERROR: Unsupported parameter type");
  }
  function decodeD1Val(v) {
    if (v && typeof v === "object" && !Array.isArray(v) && typeof v.__d1_blob === "string") {
      return b64ToBytes(v.__d1_blob).buffer;
    }
    if (Array.isArray(v)) return v.map(decodeD1Val);
    if (v && typeof v === "object") {
      const out = {};
      Object.keys(v).forEach((k) => { out[k] = decodeD1Val(v[k]); });
      return out;
    }
    return v;
  }
  function makeD1Binding(dbId) {
    class D1PreparedStatement {
      constructor(sql, params) {
        this._sql = String(sql);
        this._params = params || [];
      }
      bind(...vals) {
        const encoded = vals.map(encodeD1Param);
        return new D1PreparedStatement(this._sql, encoded);
      }
      first(col) {
        try {
          const res = JSON.parse(__d1Query(JSON.stringify({
            db_id: dbId, sql: this._sql, params: this._params, first_col: col === undefined ? "" : String(col),
          })));
          return Promise.resolve(decodeD1Val(res));
        } catch (e) { return Promise.reject(e); }
      }
      run() {
        try {
          const res = JSON.parse(__d1Query(JSON.stringify({ db_id: dbId, sql: this._sql, params: this._params })));
          return Promise.resolve(decodeD1Val(res));
        } catch (e) { return Promise.reject(e); }
      }
      all() { return this.run(); }
      raw(opts) {
        try {
          const res = JSON.parse(__d1Query(JSON.stringify({
            db_id: dbId, sql: this._sql, params: this._params, raw: true, column_names: !!(opts && opts.columnNames),
          })));
          return Promise.resolve(decodeD1Val(res));
        } catch (e) { return Promise.reject(e); }
      }
    }
    return {
      prepare(sql) { return new D1PreparedStatement(sql, []); },
      batch(stmts) {
        try {
          const payload = stmts.map((s) => ({ sql: s._sql, params: s._params }));
          const res = JSON.parse(__d1Batch(JSON.stringify({ db_id: dbId, statements: payload })));
          return Promise.resolve(decodeD1Val(res));
        } catch (e) { return Promise.reject(e); }
      },
      exec(sql) {
        try {
          return Promise.resolve(JSON.parse(__d1Exec(JSON.stringify({ db_id: dbId, sql: String(sql) }))));
        } catch (e) { return Promise.reject(e); }
      },
    };
  }
  function buildEnv(envJson) {
    const raw = JSON.parse(envJson);
    // Backward compatibility: if __env is a plain { KEY: "val" } object without __vars, return it directly.
    if (!raw || typeof raw !== "object" || (!raw.__vars && !raw.__kv && !raw.__d1)) return raw;
    const env = Object.assign({}, raw.__vars || {});
    if (raw.__kv) Object.keys(raw.__kv).forEach((b) => { env[b] = makeKvBinding(raw.__kv[b]); });
    if (raw.__d1) Object.keys(raw.__d1).forEach((b) => { env[b] = makeD1Binding(raw.__d1[b]); });
    return env;
  }

  Object.assign(globalThis, {
    Headers, Request, Response, URL, URLSearchParams, fetch, console,
    TextEncoder, TextDecoder, crypto, CryptoKey,
    addEventListener(type, fn) { if (type === "fetch") listener = fn; },
  });

  globalThis.__run = function (reqJson, envJson) {
    const r = JSON.parse(reqJson);
    const request = new Request(r.url, { method: r.method, headers: r.headers });
    if (r.hasBody) request._bodyId = 0;
    request.cf = r.cf;
    const env = buildEnv(envJson);
    const waits = [];
    const ctx = { waitUntil(x) { waits.push(Promise.resolve(x)); }, passThroughOnException() {} };
    let p;
    try {
      const d = globalThis.__default;
      if (d && typeof d.fetch === "function") p = d.fetch(request, env, ctx);
      else if (listener) {
        let responded;
        listener({ request, waitUntil() {}, passThroughOnException() {}, respondWith(x) { responded = x; } });
        p = responded === undefined ? fetch(request) : responded;
      } else throw new Error("the script has no fetch handler");
    } catch (e) {
      p = Promise.reject(e);
    }
    Promise.resolve(p).then((res) => {
      if (!(res instanceof Response)) throw new TypeError("the fetch handler did not return a Response");
      return Promise.all(waits).then(() => {
        globalThis.__out = JSON.stringify({
          status: res.status, headers: res.headers._h, body: res._text, bodyId: res._bodyId,
        });
      });
    }).catch((e) => {
      globalThis.__err = String((e && e.stack) || e);
    });
  };

  globalThis.__runEmail = function (msgJson, envJson) {
    const m = JSON.parse(msgJson);
    const env = buildEnv(envJson);
    const waits = [];
    const ctx = { waitUntil(x) { waits.push(Promise.resolve(x)); }, passThroughOnException() {} };
    const forwards = [];
    let rejectReason = null;
    const rawHolder = { _text: null, _bodyId: 0 };
    const message = {
      from: m.from,
      to: m.to,
      headers: new Headers(m.headers),
      rawSize: m.rawSize,
      raw: {
        __bodyOf: rawHolder,
        text() { return Promise.resolve(__bodyText(0)); },
      },
      forward(rcptTo) {
        forwards.push(String(rcptTo));
        return Promise.resolve();
      },
      setReject(reason) {
        rejectReason = String(reason || "rejected");
      },
    };
    let p;
    try {
      const d = globalThis.__default;
      if (d && typeof d.email === "function") p = d.email(message, env, ctx);
      else throw new Error("the script has no email handler");
    } catch (e) {
      p = Promise.reject(e);
    }
    Promise.resolve(p).then(() => Promise.all(waits)).then(() => {
      globalThis.__out = JSON.stringify({ reject: rejectReason, forwards });
    }).catch((e) => {
      globalThis.__err = String((e && e.stack) || e);
    });
  };

  globalThis.__runScheduled = function (ctrlJson, envJson) {
    const c = JSON.parse(ctrlJson);
    const env = buildEnv(envJson);
    const waits = [];
    const ctx = { waitUntil(x) { waits.push(Promise.resolve(x)); }, passThroughOnException() {} };
    const controller = {
      cron: c.cron,
      type: "scheduled",
      scheduledTime: c.scheduledTime,
      noRetry() {},
    };
    let p;
    try {
      const d = globalThis.__default;
      if (d && typeof d.scheduled === "function") p = d.scheduled(controller, env, ctx);
      else throw new Error("the script has no scheduled handler");
    } catch (e) {
      p = Promise.reject(e);
    }
    Promise.resolve(p).then(() => Promise.all(waits)).then(() => {
      globalThis.__out = JSON.stringify({ ok: true });
    }).catch((e) => {
      globalThis.__err = String((e && e.stack) || e);
    });
  };
})();
