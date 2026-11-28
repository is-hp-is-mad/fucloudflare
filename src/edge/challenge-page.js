
  // ---- the challenge page ----
  var CFG = JSON.parse(document.getElementById("fc").textContent);
  var box = document.getElementById("box"), cb = document.getElementById("cb"), msg = document.getElementById("msg");
  var shown = 0, sol = null, solMs = 0, sig = null;
  function state(st) { box.setAttribute("data-state", st); }
  function answered(r) {
    if (r.ok) { state("done"); setTimeout(function () { location.reload(); }, 500); }
    else if (r.need === "click") ready();
    else { state("fail"); if (msg && r.code) msg.textContent = r.code; }
  }
  function ready() { state("ready"); shown = performance.now(); cb.disabled = false; }
  cb.addEventListener("click", function (e) {
    if (cb.disabled) { e.preventDefault(); return; }
    cb.disabled = true;
    var clk = clickOf(e, shown);
    state("verifying");
    post(CFG, report(CFG, sol, solMs, "click", sig, clk), answered);
  });
  var retry = document.getElementById("retry");
  if (retry) retry.addEventListener("click", function () { location.reload(); });

  collect(function (s) {
    sig = s;
    work(CFG, function (found, ms) {
      sol = found; solMs = ms;
      if (CFG.c) ready(); else post(CFG, report(CFG, sol, solMs, "auto", sig, null), answered);
    });
  });
})();
