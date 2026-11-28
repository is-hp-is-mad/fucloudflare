// Drive the edge's human check with headless Chromium (Playwright): it has to
// be caught as automation, after doing the proof of work correctly.
// usage: node challenge-check.mjs <edge base, e.g. http://example.com:18080> <out dir>
import { chromium } from "playwright";
import fs from "node:fs";

const [base, out] = process.argv.slice(2);
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ args: ["--host-resolver-rules=MAP example.com 127.0.0.1"] });
let failed = false;
for (const [path, name] of [["/guarded-js", "js"], ["/guarded-click", "click"]]) {
  for (const scheme of ["light", "dark"]) {
    const page = await browser.newPage({ colorScheme: scheme, locale: "zh-CN", viewport: { width: 900, height: 720 } });
    const answers = [];
    page.on("response", async r => { if (r.url().includes("/cdn-cgi/challenge-platform/verify")) answers.push({ status: r.status(), body: await r.text() }); });
    await page.goto(base + path);
    if (name === "click") {
      await page.waitForSelector("#box[data-state=ready]", { timeout: 30000 });
      await page.screenshot({ path: `${out}/challenge-${name}-ready-${scheme}.png` });
      await page.mouse.move(120, 300); await page.mouse.move(160, 330, { steps: 8 });
      await page.click(".fc-cb");
    }
    await page.waitForSelector("#box[data-state=fail], #box[data-state=done]", { timeout: 30000 });
    await page.screenshot({ path: `${out}/challenge-${name}-result-${scheme}.png` });
    const last = answers[answers.length - 1] || {};
    console.log(name, scheme, JSON.stringify(answers));
    const code = (() => { try { return JSON.parse(last.body).code; } catch { return ""; } })();
    if (last.status !== 403 || ["bad_work", "bad_ticket", "other_visitor", "expired", "unreadable", ""].includes(code || "")) {
      console.error(`headless Chromium was not caught as automation on ${path} (or the work was wrong): ${JSON.stringify(last)}`);
      failed = true;
    }
    await page.close();
  }
}
await browser.close();
process.exit(failed ? 1 : 0);
