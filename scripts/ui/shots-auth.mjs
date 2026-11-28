// Screenshots of the auth worker's pages as fucf serves them (CI).
//   node scripts/ui/shots-auth.mjs <origin e.g. http://auth.example.com:18080> <session cookie "name=value"> <out-dir>
import { chromium } from "playwright";
import { mkdirSync } from "node:fs";

const [origin, cookie, out] = process.argv.slice(2);
mkdirSync(out, { recursive: true });
const host = new URL(origin).hostname;
const browser = await chromium.launch({ args: [`--host-resolver-rules=MAP ${host} 127.0.0.1`] });
const [cname, ...rest] = cookie.split("=");
for (const scheme of ["light", "dark"]) {
  for (const lang of ["zh", "en"]) {
    for (const [vp, size] of [["desktop", { width: 1280, height: 860 }], ["mobile", { width: 390, height: 844 }]]) {
      const ctx = await browser.newContext({ viewport: size, colorScheme: scheme, deviceScaleFactor: vp === "mobile" ? 2 : 1 });
      await ctx.addInitScript(l => { try { localStorage.setItem("fucf_lang", l); } catch {} }, lang);
      const page = await ctx.newPage();
      const tag = `${scheme}-${lang}-${vp}`;
      await page.goto(origin + "/login", { waitUntil: "networkidle" });
      await page.screenshot({ path: `${out}/auth-${tag}-login.png`, fullPage: true });
      if (vp === "desktop") {
        await page.click("#tab-register"); await page.waitForTimeout(200);
        await page.screenshot({ path: `${out}/auth-${tag}-register.png`, fullPage: true });
        await page.click("#tab-login");
        await page.fill("#login-id", "nobody"); await page.fill("#login-pw", "wrong password");
        await page.click("#form-login button[type=submit]"); await page.waitForTimeout(600);
        await page.screenshot({ path: `${out}/auth-${tag}-login-error.png`, fullPage: true });
      }
      await ctx.addCookies([{ name: cname, value: rest.join("="), domain: host, path: "/", secure: false, httpOnly: true }]);
      await page.goto(origin + "/account", { waitUntil: "networkidle" });
      await page.screenshot({ path: `${out}/auth-${tag}-account.png`, fullPage: true });
      await ctx.close();
    }
  }
}
await browser.close();
console.log("auth screenshots in", out);
