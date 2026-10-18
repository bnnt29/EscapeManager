// Browser end-to-end tests of src/manager/manager.html against real C++ simulators
// (the same portable device core as the firmware) on loopback ports 9200-9299 / UDP 14220.
//
//   cd test/manager && npm install      # playwright-core (uses the Chromium from ~/.cache/ms-playwright)
//   node --test test/manager/
//
// The file is skipped with a clear message when playwright-core, Chromium or the simulator
// (g++ with OpenSSL headers) are missing.
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import * as H from "./helpers.mjs";
import { startStub } from "./stub.mjs";

const chromium = await H.loadPlaywright();
const executablePath = H.findChromium();
let skip = false;
if (!chromium) skip = "playwright-core is not installed (cd test/manager && npm install)";
else if (!executablePath) skip = "no Chromium found under ~/.cache/ms-playwright/chromium-*/ or chromium_headless_shell-*/";
else {
  const buildError = H.ensureSimulator();
  if (buildError) skip = buildError;
}
if (skip) console.log(`# e2e.test.mjs SKIPPED: ${skip}`);

const TOKEN_OK = "EscapeManager-Private-WLAN-Default-Token";

describe("manager.html end-to-end", { skip }, () => {
  let browser;
  const sims = new Set();

  before(async () => {
    browser = await chromium.launch({ executablePath, headless: true });
  });

  after(async () => {
    await browser?.close();
    await H.stopAllSims();
  });

  /** Three simulators: two components in one room (different names), one in another room without battery. */
  async function startNetwork(extra = {}) {
    const tag = H.randomTag();
    const rooms = { a: `EM-${tag}-A`, b: `EM-${tag}-B` };
    const names = { laser: `Laser-${tag}`, kamera: `Kamera-${tag}`, tuer: `Tuer-${tag}` };
    const laser = await H.startSim({ components: [`${names.laser}:${rooms.a}:laser-${tag}`] });
    const kamera = await H.startSim({ components: [`${names.kamera}:${rooms.a}:cam-${tag}`] });
    const tuer = await H.startSim({ components: [`${names.tuer}:${rooms.b}:door-${tag}`], battery: 0 });
    return { tag, rooms, names, laser, kamera, tuer, ...extra };
  }

  /** New page that records page errors; localStorage presets are applied before the page's own code runs. */
  async function openPage(url, { storage = {}, session = {}, hash = "" } = {}) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const problems = [];
    const network = [];
    page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
    page.on("console", (message) => {
      // Failed requests to killed devices are logged by Chromium itself, not by the page.
      if (message.type() === "error" && !/Failed to load resource|net::ERR_/.test(message.text())) problems.push("console.error: " + message.text());
    });
    page.on("request", (request) => network.push({ url: request.url(), method: request.method(), at: Date.now() }));
    page.on("dialog", (dialog) => dialog.accept().catch(() => {})); // confirm()
    await page.addInitScript(([local, sessionValues]) => {
      for (const [key, value] of Object.entries(local)) if (localStorage.getItem("__init_" + key) === null) { localStorage.setItem(key, value); localStorage.setItem("__init_" + key, "1"); }
      for (const [key, value] of Object.entries(sessionValues)) if (sessionStorage.getItem("__init_" + key) === null) { sessionStorage.setItem(key, value); sessionStorage.setItem("__init_" + key, "1"); }
    }, [{ "em.pollMs": "1000", ...storage }, session]);
    await page.goto(url + "/" + hash);
    return { context, page, problems, network, close: () => context.close() };
  }

  const snapshot = (page) => page.evaluate(() => window.__em.snapshot());

  async function until(page, description, fn, arg, timeout = 15000) {
    try {
      await page.waitForFunction(fn, arg, { timeout, polling: 100 });
    } catch (error) {
      let state = "";
      try { const snap = await snapshot(page); state = JSON.stringify({ plan: snap.plan, devices: snap.devices.length, records: snap.records.filter((r) => r.failCount || r.tokenMismatch) }).slice(0, 1500); } catch { /* page gone */ }
      throw new Error(`timeout waiting for: ${description}\n${state}\n${error.message}`);
    }
  }

  /** Every message also lands in the activity log (localStorage, written at most once a second); more robust than reading short-lived toasts. */
  async function expectLogged(page, pattern, timeout = 8000) {
    const deadline = Date.now() + timeout;
    let text = "";
    while (Date.now() < deadline) {
      text = await page.evaluate(() => JSON.parse(localStorage.getItem("em.log") || "[]").map((e) => e.text).join("\n"));
      if (pattern.test(text)) return;
      await H.sleep(200);
    }
    assert.match(text, pattern);
  }

  const card = (page, name) => page.locator(".card", { hasText: name });
  const cardStep = (page, name) => card(page, name).locator(".steps span").last();

  async function waitForCards(page, names) {
    for (const name of names) await card(page, name).first().waitFor({ timeout: 20000 });
  }

  const ownRequests = (network, sim, pathPart) => network.filter((r) => r.url.startsWith(sim.base + pathPart));

  /** Opens #/plan and selects the room (the room list re-renders with every poll, so retry). */
  async function openPlan(page, room) {
    await page.evaluate(() => { location.hash = "#/plan"; });
    for (let i = 0; i < 25; i++) {
      const plan = (await snapshot(page)).plan;
      if (plan.room === room && plan.loaded) return;
      await page.locator("#viewPlan select").selectOption(room, { timeout: 1000 }).catch(() => {});
      await H.sleep(300);
    }
    throw new Error("could not open the plan view of " + room + ": " + JSON.stringify((await snapshot(page)).plan) + " select: " +
      await page.locator("#viewPlan select").evaluate((el) => `${el.value} disabled=${el.disabled} options=${[...el.options].map((o) => o.value)}`).catch((e) => e.message));
  }

  test("(a) all components of all devices appear; no battery shown as 0%", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      // device-level fields are filled from the address that was polled, never from a document
      const snap = await snapshot(p.page);
      for (const [name, sim] of [[net.names.laser, net.laser], [net.names.kamera, net.kamera], [net.names.tuer, net.tuer]]) {
        const device = snap.devices.find((d) => d.key.endsWith("|" + name));
        assert.ok(device, name);
        assert.equal(device.ip, "127.0.0.1");
        assert.equal(device.httpPort, sim.port);
        assert.equal(device.did, sim.did);
        assert.equal(device.online, true);
        assert.equal(device.totalSteps, 5);
      }
      assert.equal(snap.devices.find((d) => d.key.endsWith(net.names.tuer)).battery, null);
      assert.equal(snap.devices.find((d) => d.key.endsWith(net.names.laser)).battery, 100);
      // battery: shown for the full one, completely absent (and never "0%") for --battery 0
      assert.equal(await card(p.page, net.names.tuer).locator(".battery").count(), 0);
      assert.equal(await card(p.page, net.names.laser).locator(".battery").innerText(), "100%");
      assert.ok(!(await card(p.page, net.names.tuer).innerText()).includes("0%"));
      // the header names the configured source (not some other origin) and a device count
      const conn = await p.page.locator("#connInfo").innerText();
      assert.ok(conn.includes(net.laser.base), conn);
      assert.ok(!conn.includes("Quelle nicht erreichbar"), conn);
      assert.match(await p.page.locator("#connDot").getAttribute("class"), /ok/);
      // all three have one /security.json request each (cached promise), the bootstrap set is persisted per origin
      for (const sim of [net.laser, net.kamera, net.tuer]) assert.equal(ownRequests(p.network, sim, "/security.json").length, 1, sim.base);
      await until(p.page, "peer set persisted", ([key, ports]) => {
        const saved = JSON.parse(localStorage.getItem(key) || "[]");
        return ports.every((port) => saved.some((peer) => peer.port === port));
      }, [`em.peers.${net.laser.base}`, [net.kamera.port, net.tuer.port]]);
      // toast container is a polite live region
      await p.page.evaluate(() => window.__em.snapshot()); // keeps the page busy a moment
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(b) actions show up quickly: own click and a change made by another manager (seq-driven)", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      await cardStep(p.page, net.names.laser).waitFor();
      // own click on the device the page was loaded from
      const t0 = Date.now();
      await card(p.page, net.names.laser).getByRole("button", { name: "next_step", exact: true }).click();
      await until(p.page, "laser step 1/5", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")), net.names.laser, 5000);
      const ownMs = Date.now() - t0;
      assert.ok(ownMs < 4000, `own action took ${ownMs} ms`);

      // a change made by someone else on ANOTHER device reaches the page through peers.json seq, well before the 30 s refresh
      const before = ownRequests(p.network, net.tuer, "/status.json").length;
      const t1 = Date.now();
      H.emClient(net.kamera.hostPort, ["action", "0", "next_step"]);
      await until(p.page, "kamera step 1/5", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")), net.names.kamera, 8000);
      const foreignMs = Date.now() - t1;
      assert.ok(foreignMs < 8000, `foreign change took ${foreignMs} ms`);
      // ...without re-reading devices that did not change
      await H.sleep(4000);
      assert.equal(ownRequests(p.network, net.tuer, "/status.json").length, before, "unchanged device must not be refetched");
      assert.ok(Date.now() - p.network[0].at < 30000, "test must finish before the safety refresh could explain the update");
      // the same device can also be driven from the detail page; disabled buttons while busy etc. do not throw
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(c) the origin dies: the page keeps updating the others and marks the origin's cards offline", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base, { storage: { "em.offlineMs": "8000" } });
    try {
      await waitForCards(p.page, Object.values(net.names));
      await H.sleep(2000); // let the first peers.json merge settle
      await net.laser.stop();
      // others keep updating through peers.json of another device
      H.emClient(net.kamera.hostPort, ["action", "0", "next_step"]);
      await until(p.page, "kamera updated without the origin", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")), net.names.kamera, 15000);
      const snap = await snapshot(p.page);
      assert.notEqual(snap.peersViaBase, net.laser.base);
      // any reachable device may serve peers.json (other simulators on the shared UDP port count too)
      assert.ok(snap.records.some((r) => r.base === snap.peersViaBase && r.failCount === 0), snap.peersViaBase);
      // the origin's card turns offline after offlineMs, the others stay online
      await until(p.page, "laser card offline", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && c.classList.contains("offline")), net.names.laser, 40000);
      assert.equal(await card(p.page, net.names.kamera).evaluate((c) => c.classList.contains("offline")), false);
      assert.equal(await card(p.page, net.names.tuer).evaluate((c) => c.classList.contains("offline")), false);
      assert.match(await p.page.locator("#connInfo").innerText(), /verbunden/);
      // once the dead origin has been probed at its turn of the round robin the header says so
      await until(p.page, "dead source named in the header", (base) => document.querySelector("#connInfo").textContent.includes(base + " (Quelle nicht erreichbar, Ersatz: http"), net.laser.base, 60000);
      // the dead origin is retried with exponential backoff, not hammered at every poll (1 s here)
      const mark = Date.now();
      await H.sleep(8000);
      const origin = (await snapshot(p.page)).records.find((r) => r.base === net.laser.base);
      assert.ok(origin.failCount >= 1, JSON.stringify(origin));
      const attempts = p.network.filter((r) => r.url.startsWith(net.laser.base) && r.at >= mark).length;
      assert.ok(attempts <= 5, `${attempts} requests to the dead origin in 8 s`);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(d) wrong token: 'Token passt nicht', last-known data stays but is never live", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#tokenInput").fill("a-wrong-token-for-this-test");
      await p.page.locator("#dlgCloseBtn").click();
      await until(p.page, "token mismatch badges", (names) => names.every((name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && c.classList.contains("offline") && c.textContent.includes("Token passt nicht"))),
      Object.values(net.names), 20000);
      assert.match(await p.page.locator("#noticeBar").innerText(), /Token passt nicht/);
      assert.match(await p.page.locator("#connInfo").innerText(), /Token passt nicht/);
      const snap = await snapshot(p.page);
      assert.ok(snap.records.filter((r) => r.did).every((r) => r.tokenMismatch || r.base.includes(":9201")), JSON.stringify(snap.records));
      // actions are disabled and a change made behind its back is NOT shown as live
      assert.equal(await card(p.page, net.names.kamera).getByRole("button", { name: "next_step", exact: true }).isDisabled(), true);
      H.emClient(net.kamera.hostPort, ["action", "0", "next_step"]);
      await H.sleep(4000);
      assert.match(await cardStep(p.page, net.names.kamera).innerText(), /0\s*\/\s*5/);
      // fixing the token brings live data back
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#tokenInput").fill(TOKEN_OK);
      await p.page.locator("#dlgCloseBtn").click();
      await until(p.page, "recovered", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && !c.classList.contains("offline") && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")),
      net.names.kamera, 20000);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(d2) a device with another token is never displayed from unauthenticated data", async () => {
    const tag = H.randomTag();
    const sim = await H.startSim({ components: [`Gast-${tag}:EM-${tag}-C:guest-${tag}`], token: "custom-token-of-another-venue-42" });
    const p = await openPage(sim.base);
    try {
      await until(p.page, "token mismatch notice", () => /Token passt nicht/.test(document.querySelector("#noticeBar")?.textContent || ""), null, 15000);
      assert.equal(await p.page.locator(".card").count(), 0, "no card from a device that fails MAC verification");
      assert.ok((await snapshot(p.page)).devices.every((d) => !d.key.includes(`Gast-${tag}`)));
      assert.match(await p.page.locator("#noticeBar").innerText(), new RegExp(`127\\.0\\.0\\.1:${sim.port}`));
      // with the right token it works
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#tokenInput").fill("custom-token-of-another-venue-42");
      await p.page.locator("#dlgCloseBtn").click();
      await card(p.page, `Gast-${tag}`).first().waitFor({ timeout: 15000 });
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(e) skeleton save/load round trip, unknown fields survive, rev conflict dialog, foreign schema is read-only", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const p = await openPage(net.laser.base);
    const page = p.page;
    const readBlob = (sim) => H.emClient(sim.hostPort, ["skeleton", room]);
    try {
      await waitForCards(page, [net.names.laser, net.names.kamera]);
      // 404 no_plan is "no plan yet", not an error
      await openPlan(page, room);
      await until(page, "plan view without plan", () => window.__em.snapshot().plan.loaded && window.__em.snapshot().plan.rev === 0, null).catch(async (error) => {
        throw new Error(error.message.slice(0, 200) + " | plan view: " + (await page.locator("#viewPlan").innerText()) + " | toasts: " + (await page.locator("#toastStack").innerText()));
      });
      assert.match(await page.locator("#viewPlan").innerText(), /kein Ablaufplan gespeichert/);

      // edit + save through the page: POST to every ONLINE device of the room
      await page.locator("label.planModeControl").click();
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved rev 1", () => window.__em.snapshot().plan.rev === 1 && !window.__em.snapshot().plan.saving, null);
      await expectLogged(page, /Ablaufplan gespeichert/);
      for (const sim of [net.laser, net.kamera]) {
        const blob = readBlob(sim);
        assert.equal(blob.rev, 1, `${sim.base}: ${JSON.stringify(blob)} toasts: ${await page.locator("#toastStack").innerText()}`);
        assert.equal(blob.room, room);
        assert.equal(blob.sk.layers.length, 1);
        assert.equal(blob.sk.schema, 1);
      }
      assert.equal(H.emClient(net.tuer.hostPort, ["skeleton", room]).code, "no_plan"); // the other room's device does not host it
      // aria-live toast region
      assert.equal(await page.locator("#toastStack").getAttribute("aria-live"), "polite");

      // another manager writes a skeleton with an unknown field; the page loads it and must preserve the field on save
      const foreign = { schema: 1, planId: "other", room, layers: [{ id: "L1", name: "Fremd", lanes: [], color: "red" }], dummies: [], variables: [], futureThing: { keep: [1, 2, 3], me: "verbatim" } };
      for (const sim of [net.laser, net.kamera]) {
        assert.equal(H.emClient(sim.hostPort, ["post", "/plan-skeleton", JSON.stringify({ room, baseRev: 1, sk: foreign })]).status, 200);
      }
      await page.locator("#planSaveBtn").waitFor();
      await page.locator("#viewPlan").getByRole("button", { name: "Neu laden", exact: true }).click(); // confirm() is auto-accepted
      await until(page, "reloaded rev 2", () => window.__em.snapshot().plan.rev === 2, null);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved rev 3", () => window.__em.snapshot().plan.rev === 3 && !window.__em.snapshot().plan.saving, null);
      const preserved = readBlob(net.laser);
      assert.equal(preserved.rev, 3);
      assert.deepEqual(preserved.sk.futureThing, foreign.futureThing);
      assert.equal(preserved.sk.layers[0].color, "red", "unknown fields inside layers survive too");
      assert.equal(preserved.sk.layers.length, 2);

      // conflict: somebody bumps the revision between load and save -> dialog; "Überschreiben" retries with their revision
      const bump = (rev, layers) => {
        for (const sim of [net.laser, net.kamera]) {
          const res = H.emClient(sim.hostPort, ["post", "/plan-skeleton", JSON.stringify({ room, baseRev: rev, sk: { ...foreign, planId: "bump" + rev, layers } })]);
          assert.equal(res.status, 200, JSON.stringify(res));
        }
      };
      bump(3, [{ id: "L1", name: "Bump", lanes: [] }]);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await page.locator("#skeletonConflictDlg[open]").waitFor({ timeout: 10000 });
      assert.match(await page.locator("#skeletonConflictText").innerText(), /zwischenzeitlich geändert \(Revision 4\)/);
      await page.getByRole("button", { name: "Überschreiben" }).click();
      await until(page, "overwritten rev 5", () => window.__em.snapshot().plan.rev === 5 && !window.__em.snapshot().plan.saving, null);
      assert.equal(readBlob(net.kamera).rev, 5);
      assert.ok(readBlob(net.laser).sk.layers.length >= 2);

      // conflict again: "Neu laden" drops the edits and shows the other state
      bump(5, [{ id: "L1", name: "Bump", lanes: [] }, { id: "L2", name: "Bump2", lanes: [] }, { id: "L3", name: "Bump3", lanes: [] }]);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await page.locator("#skeletonConflictDlg[open]").waitFor({ timeout: 10000 });
      await page.locator("#skeletonConflictDlg").getByRole("button", { name: "Neu laden", exact: true }).click();
      await until(page, "reloaded after conflict", () => window.__em.snapshot().plan.rev === 6 && window.__em.snapshot().plan.layers === 3, null);
      assert.equal(readBlob(net.laser).rev, 6, "reload must not write anything");

      // foreign schema: opens read-only, never written back
      const future = { ...foreign, schema: 2, layers: [{ id: "L1", name: "Zukunft", lanes: [] }] };
      for (const sim of [net.laser, net.kamera]) H.emClient(sim.hostPort, ["post", "/plan-skeleton", JSON.stringify({ room, baseRev: 6, sk: future })]);
      await page.locator("#viewPlan").getByRole("button", { name: "Neu laden", exact: true }).click();
      await until(page, "foreign schema flagged", () => window.__em.snapshot().plan.foreignSchema === true, null);
      for (let attempt = 0; attempt < 5; attempt++) { // the toolbar re-renders with live data: retry a click that hit a replaced button
        await page.locator("#planSaveBtn").click({ timeout: 2000 }).catch(() => {});
        if (await expectLogged(page, /neueren Manager-Version/, 1500).then(() => true, () => false)) break;
      }
      await expectLogged(page, /neueren Manager-Version/, 500);
      assert.equal(readBlob(net.laser).rev, 7);
      assert.equal(readBlob(net.laser).sk.schema, 2);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(e2) a failed plan load is not 'no plan' and blocks saving", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const p = await openPage(net.laser.base, { storage: { "em.offlineMs": "60000" } });
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await net.kamera.stop(); // still "online" for offlineMs, but unreachable
      await net.laser.stop();
      await openPlan(page, net.rooms.b); // the other room is fine (its device is still up)
      await openPlan(page, room);        // first load of the dead room fails
      await until(page, "load failure visible", () => /konnte nicht geladen werden/.test(document.querySelector("#viewPlan")?.textContent || ""), null);
      assert.equal((await snapshot(page)).plan.rev, null, "unknown revision, not 0");
      await page.locator("label.planModeControl").click();
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await H.sleep(500);
      await expectLogged(page, /unbekannt \(Laden fehlgeschlagen\)/);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(f) a malformed hash falls back to the grid view and does not break the page", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base, { hash: "#/component/%E0%A4%A/x" });
    try {
      await waitForCards(p.page, Object.values(net.names));
      assert.equal(await p.page.locator("#viewGrid").isVisible(), true);
      assert.equal(await p.page.locator("#viewDetail").isVisible(), false);
      // a valid detail route still works afterwards, and so does going back to the malformed one
      await p.page.evaluate(([room, name]) => { location.hash = "#/component/" + encodeURIComponent(room) + "/" + encodeURIComponent(name); }, [net.rooms.a, net.names.laser]);
      await p.page.locator("#viewDetail h2", { hasText: net.names.laser }).waitFor();
      await p.page.evaluate(() => { location.hash = "#/component/%E0%A4%A/x"; });
      await p.page.locator("#viewGrid").waitFor({ state: "visible" });
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(g) settings are clamped, identical toasts are merged, the log is written at most once a second", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#pollInput").fill("10");
      await p.page.locator("#offlineInput").fill("1");
      await p.page.locator("#dlgCloseBtn").click();
      assert.deepEqual(await p.page.evaluate(() => [localStorage.getItem("em.pollMs"), localStorage.getItem("em.offlineMs")]), ["1000", "2000"]);
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#pollInput").fill("999999");
      await p.page.locator("#offlineInput").fill("5000");
      await p.page.locator("#dlgCloseBtn").click();
      assert.deepEqual(await p.page.evaluate(() => [localStorage.getItem("em.pollMs"), localStorage.getItem("em.offlineMs")]), ["60000", "120000"]);
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#pollInput").fill("1000");
      await p.page.locator("#offlineInput").fill("15000");
      await p.page.locator("#dlgCloseBtn").click();

      // identical toasts within 5 s are merged into one (counter), at most 4 visible
      await p.page.locator("#settingsBtn").click();
      await p.page.locator("#sourceInput").fill("keine url");
      for (let i = 0; i < 3; i++) await p.page.locator("#dlgCloseBtn").click(); // invalid: the dialog stays open and complains
      await p.page.locator("#dlgCloseBtn").evaluate((button) => button.closest("dialog").close());
      const merged = p.page.locator("#toastStack .toast", { hasText: "Gerätequelle muss" });
      assert.equal(await merged.count(), 1);
      assert.match(await merged.innerText(), /×3/);
      // the log is written to localStorage at most once a second, however many messages arrive
      await p.page.evaluate(() => {
        window.__logWrites = [];
        const original = Storage.prototype.setItem;
        Storage.prototype.setItem = function (key, value) { if (key === "em.log") window.__logWrites.push(Date.now()); return original.call(this, key, value); };
      });
      const before = await p.page.evaluate(() => JSON.parse(localStorage.getItem("em.log") || "[]").length);
      const startedAt = Date.now();
      const buttons = p.page.locator(".card .actions button");
      const total = await buttons.count();
      assert.ok(total >= 9, "buttons: " + total);
      for (let i = 0; i < total; i++) await buttons.nth(i).click({ noWaitAfter: true }).catch(() => {}); // cards re-render, some clicks may miss: fine
      await H.sleep(2500);
      const writes = await p.page.evaluate(() => window.__logWrites);
      const after = await p.page.evaluate(() => JSON.parse(localStorage.getItem("em.log") || "[]").length);
      assert.ok(after - before >= 5, `log entries: ${after - before}`);
      for (let i = 1; i < writes.length; i++) assert.ok(writes[i] - writes[i - 1] >= 900, `log writes ${writes[i] - writes[i - 1]} ms apart`);
      assert.ok(writes.length <= Math.ceil((Date.now() - startedAt) / 1000) + 1, `${writes.length} log writes in ${Date.now() - startedAt} ms`);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(i) room conflict: non-modal banner with a button; only ONLINE devices count", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-C`;
    const first = await H.startSim({ components: [`ConfA-${tag}:${room}:same-${tag}`] });
    const second = await H.startSim({ components: [`ConfB-${tag}:${room}:same-${tag}`] });
    const p = await openPage(first.base, { storage: { "em.offlineMs": "8000" } });
    try {
      await waitForCards(p.page, [`ConfA-${tag}`, `ConfB-${tag}`]);
      const banner = p.page.locator('#noticeBar [data-notice="conflict"]');
      await banner.waitFor({ timeout: 10000 });
      assert.equal(await p.page.locator("#roomConflictDlg").evaluate((dialog) => dialog.open), false, "no automatic modal dialog");
      await banner.getByRole("button", { name: "Details" }).click();
      assert.equal(await p.page.locator("#roomConflictDlg").evaluate((dialog) => dialog.open), true);
      const text = await p.page.locator("#roomConflictList").innerText();
      assert.ok(text.includes(`ConfA-${tag}`) && text.includes(`ConfB-${tag}`) && text.includes(`same-${tag}`), text);
      await p.page.locator("#roomConflictCloseBtn").click();
      // the second device dies: an offline duplicate is no conflict any more
      await second.stop();
      await banner.waitFor({ state: "detached", timeout: 45000 });
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(j) polling pauses while the tab is hidden and resumes immediately when it is shown", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      const setHidden = (hidden) => p.page.evaluate((value) => {
        Object.defineProperty(document, "hidden", { configurable: true, get: () => value });
        document.dispatchEvent(new Event("visibilitychange"));
      }, hidden);
      await H.sleep(1500); // let in-flight requests finish
      await setHidden(true);
      await H.sleep(1200);
      const mark = Date.now();
      await H.sleep(4000);
      const during = p.network.filter((r) => r.at >= mark && /\/(peers|status)\.json/.test(r.url));
      assert.equal(during.length, 0, "no polling while hidden: " + during.map((r) => r.url).join(" "));
      const shown = Date.now();
      await setHidden(false);
      await until(p.page, "immediate poll after showing", () => true, null);
      await H.sleep(400);
      assert.ok(p.network.some((r) => r.at >= shown && /\/peers\.json/.test(r.url)), "peers.json fetched right after the tab became visible");
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  // ---- protocol edge cases with a scripted fake device (see stub.mjs) -----------------------------------

  const stubCard = (page, stub) => page.locator(".card", { hasText: stub.name });
  const click = (page, stub) => stubCard(page, stub).getByRole("button", { name: "next_step", exact: true }).click();

  test("(h1) a device that is too new is read-only: no POST is ever sent to it", async () => {
    const stub = await startStub({ proto: 3, pmin: 3 });
    const p = await openPage(stub.base);
    try {
      await stubCard(p.page, stub).first().waitFor({ timeout: 15000 });
      await stubCard(p.page, stub).getByText("Gerät zu neu").waitFor();
      assert.equal(await stubCard(p.page, stub).getByRole("button", { name: "next_step", exact: true }).isDisabled(), true);
      assert.match(await p.page.locator("#noticeBar").innerText(), /Protokollstufe/);
      // even a forced attempt through the page's own transport is refused locally
      await p.page.evaluate(() => { document.querySelector(".card .actions button").disabled = false; });
      await click(p.page, stub);
      await p.page.locator("#toastStack .toast.err").first().waitFor();
      await expectLogged(p.page, /Protokoll/);
      await H.sleep(500);
      assert.equal(stub.state.posts.length, 0, "no POST to a too-new device");
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close(); await stub.stop();
    }
  });

  test("(h2) 409 stale_time: clock is resynchronised and the request retried exactly once with a fresh IV", async () => {
    const skewed = await startStub({ clockSkewMs: 0 });
    const q = await openPage(skewed.base);
    try {
      await stubCard(q.page, skewed).first().waitFor({ timeout: 15000 });
      // make the device's real clock differ from what it advertised in security.json
      await skewed.setSkew(60000);
      await click(q.page, skewed);
      await expectLogged(q.page, /gesendet/);
      assert.equal(skewed.state.posts.length, 2, JSON.stringify(skewed.state.posts));
      assert.notEqual(skewed.state.posts[0].iv, skewed.state.posts[1].iv, "retry uses a fresh IV");
      assert.ok(Math.abs(skewed.state.posts[1].t - skewed.state.posts[1].at) <= 15000, "second attempt carries the device's time");
      assert.equal(skewed.state.posts[1].plain.action, "next_step");
      // permanently wrong clock: still only ONE retry, then an error that names the problem
      skewed.state.posts.length = 0;
      skewed.setAlwaysStale(true);
      await click(q.page, skewed);
      await q.page.locator("#toastStack .toast.err").first().waitFor({ timeout: 8000 });
      assert.equal(skewed.state.posts.length, 2);
      await expectLogged(q.page, /Gerätezeit nicht synchron/);
      assert.deepEqual(q.problems, []);
    } finally {
      await q.close(); await skewed.stop();
    }
  });

  // (A verified GET frame proves the token matches, so the flag set by this artificial 401 is cleared again
  // by the next poll - the assertions therefore look at the moment right after the POST.)
  test("(h3) an unopenable 401 means token mismatch: German toast, badge, no retry loop", async () => {
    const stub = await startStub({ postMode: "unopenable401" });
    const p = await openPage(stub.base);
    try {
      await stubCard(p.page, stub).first().waitFor({ timeout: 15000 });
      await click(p.page, stub);
      await until(p.page, "token mismatch after 401", () => /Token passt nicht/.test(document.querySelector(".card")?.textContent || ""), null, 8000);
      await expectLogged(p.page, /Token passt nicht/);
      assert.equal(stub.state.posts.length, 1, "exactly one attempt");
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close(); await stub.stop();
    }
  });

  test("(h4) reads: with a token every GET carries a nonce; without a token viewer mode only on non-strict devices", async () => {
    const stub = await startStub();
    const p = await openPage(stub.base);
    try {
      await stubCard(p.page, stub).first().waitFor({ timeout: 15000 });
      const reads = stub.state.gets.filter((u) => /^\/(status|peers)\.json/.test(u));
      assert.ok(reads.length >= 2);
      assert.ok(reads.every((u) => /[?&]nonce=[A-Za-z0-9_-]{16,64}(&|$)/.test(u)), reads.join(" "));
    } finally {
      await p.close(); await stub.stop();
    }
    const open = await startStub();
    const viewer = await openPage(open.base, { session: { "em.token": "" } });
    try {
      await stubCard(viewer.page, open).first().waitFor({ timeout: 15000 });
      const reads = open.state.gets.filter((u) => /^\/(status|peers)\.json/.test(u));
      assert.ok(reads.length >= 2 && reads.every((u) => !u.includes("nonce")), "viewer mode reads are plain: " + reads.join(" "));
      assert.equal(await stubCard(viewer.page, open).getByRole("button", { name: "next_step", exact: true }).count(), 1);
      await click(viewer.page, open);
      await viewer.page.locator("#toastStack .toast.err").first().waitFor();
      await expectLogged(viewer.page, /Kein Auth-Token/);
      assert.equal(open.state.posts.length, 0);
    } finally {
      await viewer.close(); await open.stop();
    }
    const strict = await startStub({ strictGet: true });
    const blocked = await openPage(strict.base, { session: { "em.token": "" } });
    try {
      await until(blocked.page, "strict device refused without token", () => /Token eintragen|authentifizierte/.test(document.querySelector("#connInfo")?.textContent || ""), null, 10000);
      assert.equal(await blocked.page.locator(".card").count(), 0);
      assert.ok(strict.state.gets.every((u) => !/^\/(status|peers)\.json/.test(u)), "no unauthenticated read of a strict device");
      assert.deepEqual(blocked.problems, []);
    } finally {
      await blocked.close(); await strict.stop();
    }
  });
});
