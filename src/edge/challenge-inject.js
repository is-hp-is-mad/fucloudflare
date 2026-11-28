
  // ---- the script in a site's pages ----
  if (window.__fcf) return;
  window.__fcf = true;
  var TICKET = "/cdn-cgi/challenge-platform/ticket", KEY = "fcf-pass", FRESH = 25 * 60 * 1000;
  var zh = /^zh/i.test(navigator.language || "");
  function t(a, b) { return zh ? a : b; }
  function passedLately() { try { return Date.now() - Number(sessionStorage.getItem(KEY) || 0) < FRESH; } catch (e) { return false; } }
  function remember() { try { sessionStorage.setItem(KEY, String(Date.now())); } catch (e) {} }

  // one check at a time, whoever asks for it
  var pending = null;
  function solve(cfg, mayAsk) {
    if (pending) return pending;
    pending = new Promise(function (resolve) {
      collect(function (s) {
        work(cfg, function (n, ms) {
          if (cfg.c && mayAsk) { widget(cfg, n, ms, s, resolve); return; }
          post(cfg, report(cfg, n, ms, "auto", s, null), function (r) {
            if (r.ok) { remember(); resolve(true); }
            else if (r.need === "click" && mayAsk) widget(cfg, n, ms, s, resolve);
            else resolve(false);
          });
        });
      });
    });
    pending.then(function () { pending = null; });
    return pending;
  }

  // the box to click, over the page, in a shadow root of its own
  function widget(cfg, n, ms, s, resolve) {
    var host = document.createElement("div");
    host.setAttribute("data-fcf", "");
    var root = host.attachShadow ? host.attachShadow({ mode: "closed" }) : host;
    root.innerHTML = "<style>" +
      ":host,div{all:initial}.o{position:fixed;inset:0;z-index:2147483647;display:flex;align-items:center;justify-content:center;background:rgba(20,20,19,.45);font:15px/1.4 system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif}" +
      ".c{display:flex;flex-direction:column;gap:12px;background:#faf9f5;color:#141413;border-radius:14px;padding:20px 22px;min-width:280px;max-width:92vw;box-shadow:0 12px 40px rgba(0,0,0,.25)}" +
      ".h{font-weight:600}.b{display:flex;align-items:center;justify-content:space-between;gap:12px;border:1px solid #d9d6cc;border-radius:10px;padding:12px 14px;background:#fff}" +
      "label{display:flex;align-items:center;gap:10px;cursor:pointer}input{width:24px;height:24px;accent-color:#c46849;cursor:pointer}" +
      ".m{font:600 12px ui-monospace,Consolas,monospace;color:#c46849}.e{color:#b5462a;font-size:13px;min-height:1em}" +
      "@media (prefers-color-scheme:dark){.c{background:#262624;color:#faf9f5}.b{background:#1f1e1d;border-color:#3d3d3a}}" +
      "</style><div class=\"o\" role=\"dialog\" aria-modal=\"true\"><div class=\"c\"><div class=\"h\">" + t("请确认你是真人", "Verify you are human") + "</div>" +
      "<div class=\"b\"><label><input type=\"checkbox\" id=\"x\"><span>" + t("确认您是真人", "I am human") + "</span></label><span class=\"m\">fucf</span></div>" +
      "<div class=\"e\" id=\"e\"></div></div></div>";
    (document.body || document.documentElement).appendChild(host);
    var box = root.querySelector ? root.querySelector("#x") : host.querySelector("#x"), err = root.querySelector ? root.querySelector("#e") : host.querySelector("#e");
    var shown = performance.now();
    box.addEventListener("click", function (e) {
      box.disabled = true;
      post(cfg, report(cfg, n, ms, "click", s, clickOf(e, shown)), function (r) {
        if (r.ok) { remember(); host.remove(); resolve(true); }
        else { err.textContent = t("验证失败：", "Verification failed: ") + (r.code || "?"); setTimeout(function () { host.remove(); resolve(false); }, 2500); }
      });
    });
  }

  function sameOrigin(url) { try { return new URL(url, location.href).origin === location.origin; } catch (e) { return false; } }

  // fetch: a challenged request is settled and sent again, the page never knows
  var of = window.fetch;
  if (of) {
    window.fetch = function (input, init) {
      var req;
      try { req = new Request(input, init); } catch (e) { return of.apply(this, arguments); }
      var again = null;
      try { again = req.clone(); } catch (e) {}
      return of.call(window, req).then(function (r) {
        if (r.headers.get("fcf-mitigated") !== "challenge" || !sameOrigin(r.url) || !again) return r;
        return r.clone().json().then(function (j) { return j && j.challenge ? solve(j.challenge, true) : false; }, function () { return false; })
          .then(function (ok) { return ok ? of.call(window, again) : r; });
      });
    };
  }

  // XHR: cannot be answered twice; the check is settled so that the next one goes through
  var send = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function () {
    var x = this;
    x.addEventListener("load", function () {
      try {
        if (x.getResponseHeader("fcf-mitigated") === "challenge" && sameOrigin(x.responseURL || location.href)) {
          var j = JSON.parse(x.responseText);
          if (j && j.challenge) solve(j.challenge, true);
        }
      } catch (e) {}
    });
    return send.apply(this, arguments);
  };

  // in the background, when the page is idle: passed before anything is asked
  function quietly() {
    if (passedLately()) return;
    of.call(window, TICKET, { credentials: "same-origin", cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (cfg) { if (cfg && cfg.t) solve(cfg, false); }, function () {});
  }
  if (of) {
    var idle = window.requestIdleCallback || function (f) { setTimeout(f, 1500); };
    if (document.readyState === "complete") idle(quietly); else addEventListener("load", function () { idle(quietly); });
  }
})();
