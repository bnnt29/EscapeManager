// GitHub-Pages demo (tools/demo/demo.js, built by scripts/build_demo.py): the manager runs against simulated
// boards in the browser. Checks: the fleet renders, actions persist in sessionStorage only, localStorage stays
// empty, a new tab starts from the defaults, and the build keeps manager.html untouched.
import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import * as H from "./helpers.mjs";

const NAMES = ["Dummy-Kamera-0001", "Dummy-Laser-0001", "Dummy-Kamera-0002", "Dummy-Laser-0002", "Dummy-Schloss-0003", "Dummy-Sensor-0003"];

describe("GitHub-Pages demo (simulated boards in the browser)", { concurrency: false }, () => {
  let chromium;
  let executablePath;
  let browser;
  let server;
  let base;
  let out;
  let skip = false;

  before(async () => {
    chromium = await H.loadPlaywright();
    executablePath = H.findChromium();
    if (!chromium) skip = "playwright-core is not installed (cd test/manager && npm install)";
    else if (!executablePath) skip = "no Chromium found under ~/.cache/ms-playwright/";
    if (skip) { console.log("# demo.test.mjs SKIPPED: " + skip); return; }
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "em-demo-"));
    out = path.join(dir, "index.html");
    execFileSync("python3", [path.join(H.root, "scripts", "build_demo.py"), "--out", out], { stdio: "pipe" });
    const html = fs.readFileSync(out);
    server = http.createServer((req, res) => {
      if (req.url.split("?")[0] !== "/") { res.writeHead(404); res.end(); return; }
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
    });
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    base = `http://127.0.0.1:${server.address().port}`;
    browser = await chromium.launch({ executablePath, headless: true });
  });

  after(async () => {
    await browser?.close();
    await new Promise((resolve) => (server ? server.close(resolve) : resolve()));
  });

  async function openDemo() {
    const context = await browser.newContext();
    const page = await context.newPage();
    const problems = [];
    page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
    page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
    await page.goto(base + "/");
    return { context, page, problems };
  }

  const fleetOf = (page) => page.evaluate(() => JSON.parse(sessionStorage.getItem("em.demo.fleet") || "null"));
  const comp = (fleet, name) => fleet.boards.flatMap((b) => b.comps).find((c) => c.name === name);

  it("shows all six simulated components, three boards", async (t) => {
    if (skip) return t.skip(skip);
    const { context, page, problems } = await openDemo();
    try {
      await page.waitForFunction((names) => names.every((n) => document.body.innerText.includes(n)), NAMES, { timeout: 20000 });
      for (const name of NAMES) assert.ok(await page.locator(".card", { hasText: name }).count() >= 1, name);
      assert.deepEqual(problems, []);
    } finally { await context.close(); }
  });

  it("an action changes the simulated puzzle and is kept in sessionStorage only", async (t) => {
    if (skip) return t.skip(skip);
    const { context, page, problems } = await openDemo();
    try {
      await page.waitForFunction(() => document.body.innerText.includes("Dummy-Kamera-0001"), null, { timeout: 20000 });
      await page.locator(".card", { hasText: "Dummy-Kamera-0001" }).getByRole("button", { name: "next_step", exact: true }).click();
      await page.waitForFunction(() => {
        const f = JSON.parse(sessionStorage.getItem("em.demo.fleet") || "null");
        return f && f.boards[0].comps[0].step === 1;
      }, null, { timeout: 15000 });
      assert.equal((await fleetOf(page)).boards[0].comps[0].step, 1);

      // The real localStorage (what storageState() reads) stays empty; the page's settings live in sessionStorage.
      const storage = await context.storageState();
      assert.ok(storage.origins.every((o) => (o.localStorage || []).length === 0), JSON.stringify(storage.origins));
      const sessionKeys = await page.evaluate(() => Object.keys(sessionStorage));
      assert.ok(sessionKeys.includes("em.demo.fleet"), sessionKeys.join(","));
      assert.deepEqual(problems, []);
    } finally { await context.close(); }
  });

  it("a new tab starts from the default fleet (session state is per tab)", async (t) => {
    if (skip) return t.skip(skip);
    const { context, page, problems } = await openDemo();
    try {
      await page.waitForFunction(() => document.body.innerText.includes("Dummy-Kamera-0001"), null, { timeout: 20000 });
      const fleet = await fleetOf(page);
      assert.equal(comp(fleet, "Dummy-Kamera-0001").step, 0);
      assert.equal(comp(fleet, "Dummy-Laser-0001").step, 2);
      assert.equal(comp(fleet, "Dummy-Sensor-0003").error, true);
      assert.deepEqual(problems, []);
    } finally { await context.close(); }
  });

  it("sealed writes work: rename, plan skeleton with revision check, room-level sync", async (t) => {
    if (skip) return t.skip(skip);
    const { context, page, problems } = await openDemo();
    try {
      await page.waitForFunction(() => document.body.innerText.includes("Dummy-Kamera-0001"), null, { timeout: 20000 });
      // Encrypted POST exactly like the manager: AES-GCM with k_req, AAD "EM2|req|did|path|t"; answer opened with k_resp.
      const sent = await page.evaluate(async () => {
        const C = window.EscapeCrypto;
        const keys = C.deriveKeys("EscapeManager-Private-WLAN-Default-Token", 2048);
        const did = "de0000000001";
        const send = async (path, obj) => {
          const t = (await (await fetch(location.origin + "/security.json")).json()).time >>> 0;   // device clock, not epoch time
          const ivBytes = C.randomBytes(12);
          const iv = C.b64uEncode(ivBytes);
          const ct = C.gcmSeal(keys.req, ivBytes, `EM2|req|${did}|${path}|${t}`, JSON.stringify(obj));
          const body = JSON.stringify({ v: 2, t, iv, ct: C.b64uEncode(ct) });
          const res = await fetch(location.origin + path, { method: "POST", body, headers: { "Content-Type": "text/plain" } });
          const env = await res.json();
          const plain = C.gcmOpen(keys.resp, C.b64uDecode(env.iv), `EM2|resp|${did}|${path}|${iv}|${res.status}`, C.b64uDecode(env.ct));
          return { status: res.status, body: plain ? JSON.parse(C.utf8Decode(plain)) : null };
        };
        return {
          rename: await send("/config", { id: 0, name: "Dummy-Kamera-9999", room: "Dummy-Raum" }),
          skeleton: await send("/plan-skeleton", { room: "Dummy-Raum", baseRev: 0, sk: { schema: 1, planId: "demo" } }),
          same: await send("/plan-skeleton", { room: "Dummy-Raum", baseRev: 0, sk: { schema: 1, planId: "demo" } }),
          conflict: await send("/plan-skeleton", { room: "Dummy-Raum", baseRev: 0, sk: { schema: 1, planId: "other" } }),
          notHosted: await send("/plan-skeleton", { room: "Nirgendwo", baseRev: 0, sk: { schema: 1 } }),
          setup: await send("/setup", { ssid: "Demo-WLAN", pass: "geheim123", token: "neues-demo-token-1" }),
          badSetup: await send("/setup", { ssid: "EscapeSetup-abc", pass: "geheim123" }),
        };
      });
      assert.deepEqual(sent.rename, { status: 200, body: { ok: true } });
      assert.equal(sent.skeleton.status, 200);
      assert.equal(sent.skeleton.body.rev, 1);
      assert.equal(sent.same.body.rev, 1, "same content is accepted without a new revision");
      assert.equal(sent.conflict.status, 409);
      assert.equal(sent.conflict.body.code, "rev_conflict");
      assert.equal(sent.conflict.body.rev, 1);
      assert.deepEqual(sent.setup, { status: 200, body: { ok: true } }, "accepted ...");
      assert.equal(sent.badSetup.status, 400, "... invalid input refused");
      assert.equal(sent.notHosted.status, 422);
      assert.equal(sent.notHosted.body.code, "room_not_hosted");
      const fleet = await fleetOf(page);
      assert.equal(fleet.boards[0].comps[0].name, "Dummy-Kamera-9999");
      assert.equal(fleet.skeletons["Dummy-Raum"].rev, 1);
      assert.equal(JSON.stringify(fleet).includes("Demo-WLAN"), false, "hardware settings are not stored");
      assert.deepEqual(problems, []);
    } finally { await context.close(); }
  });

  it("the build leaves manager.html untouched and inserts the demo first in <head>", async (t) => {
    if (skip) return t.skip(skip);
    const source = fs.readFileSync(path.join(H.root, "src/manager/manager.html"), "utf8");
    const built = fs.readFileSync(out, "utf8");
    assert.ok(built.includes("EscapeManager") && built.includes("<head>\n<script>\n/*"), "demo script first in head");
    assert.ok(built.length > source.length);
    assert.ok(built.includes(source.slice(source.indexOf("<head>") + 6)), "rest of the manager is unchanged");
  });
});
