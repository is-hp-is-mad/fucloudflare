// Screenshots of the panel and the edge's own pages, for reviewing the UI
// without a browser at hand (CI uploads them as an artifact).
//   node scripts/ui/shots.mjs <panel-url> <session-token> <zone-id> <out-dir> [error-page.html ...]
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";

const [panel, token, zone, out, ...pages] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const browser = await chromium.launch();
const views = [
  ["overview", "#/overview"], ["zones", "#/zones"], ["zone-overview", `#/zone/${zone}/overview`],
  ["zone-dns", `#/zone/${zone}/dns`], ["zone-analytics", `#/zone/${zone}/analytics`], ["fleet", "#/fleet"],
  ["steering", "#/steering"], ["account", "#/account"],
];
for (const [mode, scheme] of [["light", "light"], ["dark", "dark"]]) {
  for (const [vp, size] of [["desktop", { width: 1440, height: 900 }], ["mobile", { width: 390, height: 844 }]]) {
    const ctx = await browser.newContext({ viewport: size, colorScheme: scheme, deviceScaleFactor: vp === "mobile" ? 2 : 1 });
    const page = await ctx.newPage();
    await page.addInitScript(([m]) => { try { localStorage.setItem("cf_theme_mode", m); } catch {} }, [mode]);
    // signed out
    await page.goto(panel, { waitUntil: "networkidle" });
    await page.screenshot({ path: `${out}/${mode}-${vp}-login.png` });
    // signed in
    await page.evaluate(t => localStorage.setItem("fucf_token", t), token);
    for (const [name, hash] of views) {
      await page.goto(panel + hash, { waitUntil: "networkidle" });
      await page.waitForTimeout(400);
      await page.screenshot({ path: `${out}/${mode}-${vp}-${name}.png`, fullPage: vp === "desktop" });
    }
    if (vp === "desktop") {
      // a primary button while hovered and an open drawer
      await page.goto(panel + "#/zones", { waitUntil: "networkidle" });
      const pri = page.locator("button.pri").first();
      if (await pri.count()) {
        await pri.hover(); await page.waitForTimeout(300);
        await page.screenshot({ path: `${out}/${mode}-${vp}-button-hover.png`, clip: await pri.evaluate(e => { const r = e.getBoundingClientRect(); return { x: Math.max(0, r.x - 24), y: Math.max(0, r.y - 24), width: r.width + 48, height: r.height + 48 }; }) });
        await pri.click(); await page.waitForTimeout(500);
        await page.screenshot({ path: `${out}/${mode}-${vp}-drawer.png` });
      }
    }
    for (const f of pages) {
      await page.goto(pathToFileURL(resolve(f)).href);
      const base = f.split("/").pop().replace(/\.html$/, "");
      await page.screenshot({ path: `${out}/${mode}-${vp}-edge-${base}.png` });
    }
    await ctx.close();
  }
}
await browser.close();
console.log("screenshots in", out);
