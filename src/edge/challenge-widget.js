
  // ---- the widget a site puts into its own pages ----
  // Every element with a data-sitekey (32 lowercase hex digits; other kinds
  // of sitekey belong to other checks and are left alone) gets a box. The
  // puzzle and the answer stay on the page's own host. A browser that passes
  // gets a token, written into a hidden fcf-challenge-response field inside
  // the element (so inside the form around it), and an fcf-challenge-success
  // event; fcf-challenge-expired and fcf-challenge-error tell the rest.
  if (window.fcfChallenge) return;
  // the answer goes back to this same host, to the one path the edge answers on
  var TICKET = "/cdn-cgi/challenge-platform/widget/ticket", ANSWER = "/cdn-cgi/challenge-platform/widget/verify", FIELD = "fcf-challenge-response";
  // a token lives five minutes: a new one is fetched a little before that
  var REFRESH = 290 * 1000;
  var zh = /^zh/i.test(navigator.language || "");
  function t(a, b) { return zh ? a : b; }
  var CSS = ":host{all:initial;display:inline-block}" +
    ".b{display:flex;align-items:center;justify-content:space-between;gap:12px;box-sizing:border-box;width:300px;max-width:100%;min-height:65px;padding:10px 14px;" +
    "border:1px solid #d9d6cc;border-radius:10px;background:#faf9f5;color:#141413;font:14px/1.4 system-ui,-apple-system,'PingFang SC','Microsoft YaHei',sans-serif}" +
    "label{display:flex;align-items:center;gap:10px;cursor:pointer}input{width:22px;height:22px;margin:0;accent-color:#c46849;cursor:pointer}" +
    ".s{display:none}.b[data-state=working] .s-working,.b[data-state=ready] .s-ready,.b[data-state=verifying] .s-verifying,.b[data-state=done] .s-done,.b[data-state=fail] .s-fail{display:inline}" +
    ".b[data-state=working] input,.b[data-state=verifying] input{opacity:.4}.b[data-state=done] input{accent-color:#2f7a52}" +
    ".m{display:flex;flex-direction:column;align-items:flex-end;font:600 12px ui-monospace,Consolas,monospace;color:#c46849}" +
    ".m small{font:11px system-ui,sans-serif;color:#87867f;font-weight:400}.x{flex:1}.e{font:12px ui-monospace,Consolas,monospace;color:#b5462a}" +
    "button{display:none;font:inherit;font-size:12px;color:#c46849;background:none;border:0;padding:0;cursor:pointer;text-decoration:underline}.b[data-state=fail] button{display:inline}" +
    "@media (prefers-color-scheme:dark){.b{background:#262624;color:#faf9f5;border-color:#3d3d3a}}";

  function emit(w, name, token) {
    try { w.el.dispatchEvent(new CustomEvent(name, { bubbles: true, detail: { token: token || "" } })); } catch (e) {}
  }
  function state(w, st) { w.box.setAttribute("data-state", st); }
  function fail(w, code) {
    clearTimeout(w.timer);
    w.input.value = "";
    w.cb.checked = false; w.cb.disabled = true;
    w.err.textContent = code || "";
    state(w, "fail");
    emit(w, "fcf-challenge-error");
  }
  function answered(w, r) {
    if (r && r.ok && typeof r.token === "string") {
      w.input.value = r.token;
      w.cb.checked = true; w.cb.disabled = true;
      state(w, "done");
      emit(w, "fcf-challenge-success", r.token);
      w.timer = setTimeout(function () { w.input.value = ""; emit(w, "fcf-challenge-expired"); start(w); }, REFRESH);
    } else if (r && r.need === "click") {
      w.cb.checked = false; w.cb.disabled = false;
      w.shown = performance.now();
      state(w, "ready");
    } else fail(w, (r && r.code) || "failed");
  }
  function start(w) {
    clearTimeout(w.timer);
    w.input.value = ""; w.err.textContent = "";
    w.cb.checked = false; w.cb.disabled = true;
    state(w, "working");
    var x = new XMLHttpRequest();
    x.open("GET", TICKET + "?sitekey=" + encodeURIComponent(w.sitekey));
    x.onload = function () {
      var cfg = null;
      try { cfg = JSON.parse(x.responseText); } catch (e) {}
      if (x.status !== 200 || !cfg || typeof cfg.t !== "string" || cfg.v !== ANSWER) { fail(w, (cfg && cfg.code) || "unavailable"); return; }
      w.cfg = cfg;
      collect(function (s) {
        w.sig = s;
        work(cfg, function (n, ms) {
          w.sol = n; w.ms = ms;
          if (cfg.c) answered(w, { need: "click" });
          else post(cfg, report(cfg, n, ms, "auto", s, null), function (r) { answered(w, r); });
        });
      });
    };
    x.onerror = function () { fail(w, "network"); };
    x.send();
  }

  function mount(el) {
    if (!el || el.__fcfWidget || !el.getAttribute) return;
    var sitekey = el.getAttribute("data-sitekey") || "";
    if (!/^[0-9a-f]{32}$/.test(sitekey)) return;
    var host = document.createElement("div");
    var root = host.attachShadow ? host.attachShadow({ mode: "closed" }) : host;
    root.innerHTML = "<style>" + CSS + "</style><div class=\"b\" data-state=\"working\" role=\"group\" aria-live=\"polite\">" +
      "<label><input type=\"checkbox\" disabled><span><span class=\"s s-working\">" + t("正在验证…", "Verifying…") + "</span>" +
      "<span class=\"s s-ready\">" + t("确认您是真人", "Verify you are human") + "</span><span class=\"s s-verifying\">" + t("正在验证…", "Verifying…") + "</span>" +
      "<span class=\"s s-done\">" + t("成功", "Success") + "</span><span class=\"s s-fail\">" + t("验证失败", "Verification failed") + "</span></span></label>" +
      "<span class=\"x\"><span class=\"e\"></span> <button type=\"button\">" + t("重试", "Try again") + "</button></span>" +
      "<span class=\"m\">fucf<small>" + t("人机验证", "human check") + "</small></span></div>";
    var q = function (sel) { return root.querySelector ? root.querySelector(sel) : host.querySelector(sel); };
    // the field goes into the element itself (not the shadow root), so that the form around it sends it
    var input = document.createElement("input");
    input.type = "hidden"; input.name = FIELD; input.value = "";
    el.appendChild(host);
    el.appendChild(input);
    var w = { el: el, sitekey: sitekey, input: input, box: q(".b"), cb: q("input"), err: q(".e"), timer: 0, cfg: null, sol: 0, ms: 0, sig: null, shown: 0 };
    el.__fcfWidget = w;
    w.cb.addEventListener("click", function (e) {
      if (w.cb.disabled || !w.cfg) { e.preventDefault(); return; }
      w.cb.disabled = true;
      state(w, "verifying");
      post(w.cfg, report(w.cfg, w.sol, w.ms, "click", w.sig, clickOf(e, w.shown)), function (r) { answered(w, r); });
    });
    q("button").addEventListener("click", function (e) { e.preventDefault(); start(w); });
    start(w);
  }
  function scan() {
    var list = document.querySelectorAll("[data-sitekey]");
    for (var i = 0; i < list.length; i++) mount(list[i]);
  }

  window.fcfChallenge = {
    // for elements added after the page loaded
    render: function (el) { mount(el); },
    // a new token (after a form was sent: each token is accepted once)
    reset: function (el) { var w = el && el.__fcfWidget; if (w) start(w); },
    getResponse: function (el) { var w = el && el.__fcfWidget; return w ? w.input.value : ""; }
  };
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", scan); else scan();
})();
