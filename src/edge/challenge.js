(function () {
  "use strict";
  var CFG = JSON.parse(document.getElementById("fc").textContent);
  var box = document.getElementById("box"), cb = document.getElementById("cb"), msg = document.getElementById("msg");
  var t0 = performance.now(), shown = 0, sol = null, solMs = 0, sig = null, clk = null;
  function state(s) { box.setAttribute("data-state", s); }

  // what a person leaves behind: pointer movement, touches, keys, scrolling
  var ev = { moves: 0, dist: 0, lx: -1, ly: -1, first: 0, keys: 0, touch: 0, scroll: 0 };
  function moved(e) {
    if (!e.isTrusted) return;
    ev.moves++;
    if (!ev.first) ev.first = performance.now() - t0;
    if (ev.lx >= 0) ev.dist += Math.hypot(e.clientX - ev.lx, e.clientY - ev.ly);
    ev.lx = e.clientX; ev.ly = e.clientY;
  }
  addEventListener("pointermove", moved, { passive: true });
  addEventListener("touchstart", function (e) { if (e.isTrusted) ev.touch++; }, { passive: true });
  addEventListener("keydown", function (e) { if (e.isTrusted) ev.keys++; });
  addEventListener("scroll", function () { ev.scroll++; }, { passive: true });

  // proof of work: sha256(ticket + ":" + n) with CFG.b leading zero bits
  var K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
  function sha(m) {
    var l = m.length, w = ((l + 9 + 63) >> 6) << 4, W = new Uint32Array(w), X = new Uint32Array(64), i;
    for (i = 0; i < l; i++) W[i >> 2] |= m[i] << (24 - (i & 3) * 8);
    W[l >> 2] |= 0x80 << (24 - (l & 3) * 8);
    W[w - 1] = l * 8;
    var H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
    for (var o = 0; o < w; o += 16) {
      for (i = 0; i < 16; i++) X[i] = W[o + i];
      for (i = 16; i < 64; i++) {
        var p = X[i - 15], q = X[i - 2];
        var s0 = (p >>> 7 | p << 25) ^ (p >>> 18 | p << 14) ^ (p >>> 3), s1 = (q >>> 17 | q << 15) ^ (q >>> 19 | q << 13) ^ (q >>> 10);
        X[i] = (X[i - 16] + s0 + X[i - 7] + s1) | 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (i = 0; i < 64; i++) {
        var S1 = (e >>> 6 | e << 26) ^ (e >>> 11 | e << 21) ^ (e >>> 25 | e << 7), ch = (e & f) ^ (~e & g);
        var t1 = (h + S1 + ch + K[i] + X[i]) | 0;
        var S0 = (a >>> 2 | a << 30) ^ (a >>> 13 | a << 19) ^ (a >>> 22 | a << 10), mj = (a & b) ^ (a & c) ^ (b & c);
        var t2 = (S0 + mj) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b; b = a; a = (t1 + t2) | 0;
      }
      H[0] = (H[0] + a) | 0; H[1] = (H[1] + b) | 0; H[2] = (H[2] + c) | 0; H[3] = (H[3] + d) | 0;
      H[4] = (H[4] + e) | 0; H[5] = (H[5] + f) | 0; H[6] = (H[6] + g) | 0; H[7] = (H[7] + h) | 0;
    }
    return H;
  }
  function zeros(H) {
    var n = 0;
    for (var i = 0; i < 8; i++) { var z = Math.clz32(H[i]); n += z; if (z < 32) break; }
    return n;
  }
  var pre = new TextEncoder().encode(CFG.t + ":");
  function work(done) {
    var n = 0, start = performance.now();
    (function step() {
      var until = performance.now() + 40;
      while (performance.now() < until) {
        for (var k = 0; k < 256; k++, n++) {
          var s = String(n), m = new Uint8Array(pre.length + s.length);
          m.set(pre);
          for (var j = 0; j < s.length; j++) m[pre.length + j] = s.charCodeAt(j);
          if (zeros(sha(m)) >= CFG.b) { done(n, performance.now() - start); return; }
        }
      }
      setTimeout(step, 0);
    })();
  }

  // the environment, the way automation gives itself away
  function native(f) {
    try { return typeof f === "function" && /\{\s*\[native code\]\s*\}\s*$/.test(Function.prototype.toString.call(f)); } catch (e) { return false; }
  }
  function environment() {
    var n = navigator, s = {};
    function g(k, f) { try { s[k] = f(); } catch (e) { s[k] = null; } }
    g("wd", function () { return n.webdriver === true; });
    g("auto", function () {
      var found = [], names = ["__playwright__binding__", "__pwInitScripts", "_phantom", "callPhantom", "__nightmare", "domAutomation",
        "domAutomationController", "_selenium", "__selenium_unwrapped", "__webdriver_evaluate", "__driver_evaluate", "__webdriver_script_fn",
        "__fxdriver_unwrapped", "_Selenium_IDE_Recorder", "__lastWatirAlert", "Cypress", "__puppeteer_evaluation_script__"];
      for (var i = 0; i < names.length; i++) if (names[i] in window) found.push(names[i]);
      var keys = Object.getOwnPropertyNames(window).concat(Object.getOwnPropertyNames(document));
      for (var j = 0; j < keys.length; j++) if (/^\$?cdc_|^\$wdc_|^__webdriver/i.test(keys[j])) found.push(keys[j]);
      return found.slice(0, 8);
    });
    g("ua", function () { return n.userAgent; });
    g("uad", function () {
      var u = n.userAgentData;
      return u ? { m: !!u.mobile, p: u.platform || "", b: (u.brands || []).map(function (x) { return x.brand; }).slice(0, 4) } : null;
    });
    g("langs", function () { return (n.languages || []).length; });
    g("plug", function () { return n.plugins ? n.plugins.length : -1; });
    g("hc", function () { return n.hardwareConcurrency || 0; });
    g("scr", function () { return [screen.width, screen.height, screen.availWidth, screen.availHeight, screen.colorDepth]; });
    g("win", function () { return [innerWidth, innerHeight, outerWidth, outerHeight]; });
    g("tz", function () { return Intl.DateTimeFormat().resolvedOptions().timeZone || ""; });
    g("touch", function () { return n.maxTouchPoints || 0; });
    g("chrome", function () { return typeof window.chrome === "object" && window.chrome !== null; });
    g("own", function () { return Object.getOwnPropertyNames(n).length; });
    g("wdp", function () { var d = Object.getOwnPropertyDescriptor(Navigator.prototype, "webdriver"); return d ? native(d.get) : null; });
    g("nat", function () {
      var list = [Function.prototype.toString, HTMLCanvasElement.prototype.toDataURL, n.permissions && n.permissions.query,
        Element.prototype.getBoundingClientRect, Date.prototype.getTimezoneOffset, n.__lookupGetter__ && Navigator.prototype.__lookupGetter__("languages")];
      var bad = 0;
      for (var i = 0; i < list.length; i++) if (list[i] && !native(list[i])) bad++;
      return bad;
    });
    g("gl", function () {
      var c = document.createElement("canvas"), x = c.getContext("webgl") || c.getContext("experimental-webgl");
      if (!x) return "";
      var e = x.getExtension("WEBGL_debug_renderer_info");
      return e ? x.getParameter(e.UNMASKED_VENDOR_WEBGL) + " / " + x.getParameter(e.UNMASKED_RENDERER_WEBGL) : String(x.getParameter(x.RENDERER));
    });
    g("cdp", function () {
      // a debugger protocol client (what drives headless browsers) asks for the stack of what is logged
      var hit = false, e = new Error("");
      Object.defineProperty(e, "stack", { configurable: true, get: function () { hit = true; return ""; } });
      console.debug(e);
      return hit;
    });
    g("notif", function () { return typeof Notification === "undefined" ? null : Notification.permission; });
    return s;
  }
  // headless browsers deny notifications while claiming that they would ask
  function permissions(s, next) {
    try {
      navigator.permissions.query({ name: "notifications" }).then(function (p) { s.perm = p.state; next(); }, function () { next(); });
    } catch (e) { next(); }
  }

  function post(mode, then) {
    var x = new XMLHttpRequest();
    x.open("POST", CFG.v);
    x.setRequestHeader("content-type", "application/json");
    x.onload = function () { var r = {}; try { r = JSON.parse(x.responseText); } catch (e) {} then(r); };
    x.onerror = function () { then({ ok: false, code: "network" }); };
    x.send(JSON.stringify({
      t: CFG.t, n: sol, m: mode, ms: Math.round(solMs), s: sig, c: mode === "click" ? clk : null,
      ev: { moves: ev.moves, dist: Math.round(ev.dist), first: Math.round(ev.first), keys: ev.keys, touch: ev.touch, scroll: ev.scroll, age: Math.round(performance.now() - t0) }
    }));
  }
  function answered(r) {
    if (r.ok) { state("done"); setTimeout(function () { location.reload(); }, 500); }
    else if (r.need === "click") ready();
    else { state("fail"); if (msg && r.code) msg.textContent = r.code; }
  }
  function ready() { state("ready"); shown = performance.now(); cb.disabled = false; }
  cb.addEventListener("click", function (e) {
    if (cb.disabled) { e.preventDefault(); return; }
    cb.disabled = true;
    clk = { trusted: e.isTrusted, dt: Math.round(performance.now() - shown), detail: e.detail, pt: e.pointerType || "", x: Math.round(e.offsetX || 0), y: Math.round(e.offsetY || 0) };
    state("verifying");
    post("click", answered);
  });
  var retry = document.getElementById("retry");
  if (retry) retry.addEventListener("click", function () { location.reload(); });

  sig = environment();
  permissions(sig, function () {
    work(function (found, ms) {
      sol = found; solMs = ms;
      if (CFG.c) ready(); else post("auto", answered);
    });
  });
})();
