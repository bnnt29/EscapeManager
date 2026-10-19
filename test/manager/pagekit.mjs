// Shared browser helpers of plan.test.mjs and render.test.mjs (the older test files keep their own copies).
// Chromium via playwright-core, simulators via helpers.mjs (HTTP ports 9500-9599 / UDP 14250 through
// EM_TEST_PORT_BASE / EM_TEST_UDP_PORT, defaults 9200 / 14220).
import assert from "node:assert/strict";
import * as H from "./helpers.mjs";

/** Returns { chromium, executablePath, skip } ("" = run); prints a clear message when skipped. */
export async function prerequisites(fileName) {
  const chromium = await H.loadPlaywright();
  const executablePath = H.findChromium();
  let skip = false;
  if (!chromium) skip = "playwright-core is not installed (cd test/manager && npm install)";
  else if (!executablePath) skip = "no Chromium found under ~/.cache/ms-playwright/";
  else {
    const buildError = H.ensureSimulator();
    if (buildError) skip = buildError;
  }
  if (skip) console.log(`# ${fileName} SKIPPED: ${skip}`);
  return { chromium, executablePath, skip };
}

export const TOKEN_DEFAULT = "EscapeManager-Private-WLAN-Default-Token";

/** Test kit bound to a browser getter; call once per describe block. */
export function pageKit(getBrowser) {
  /**
   * New page that records page errors / unhandled rejections / console errors (problems).
   * confirm()/prompt(): p.dialogs.accept (default true) decides; p.dialogs.seen lists the messages;
   * p.dialogs.promptText answers prompt().
   */
  async function openPage(url, { storage = {}, hash = "" } = {}) {
    const context = await getBrowser().newContext();
    const page = await context.newPage();
    const problems = [];
    const network = [];
    const dialogs = { accept: true, seen: [], promptText: "Platzhalter-Test" };
    page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
    page.on("console", (message) => {
      if (message.type() === "error" && !/Failed to load resource|net::ERR_/.test(message.text())) problems.push("console.error: " + message.text());
    });
    page.on("request", (request) => network.push({ url: request.url(), method: request.method(), at: Date.now() }));
    page.on("dialog", (dialog) => {
      dialogs.seen.push(`${dialog.type()}: ${dialog.message()}`);
      (dialogs.accept ? dialog.accept(dialog.type() === "prompt" ? dialogs.promptText : undefined) : dialog.dismiss()).catch(() => {});
    });
    await page.addInitScript((local) => {
      if (window !== window.top) return; // sandboxed state iframes have no storage
      for (const [key, value] of Object.entries(local)) if (localStorage.getItem("__init_" + key) === null) { localStorage.setItem(key, value); localStorage.setItem("__init_" + key, "1"); }
    }, { "em.pollMs": "1000", ...storage });
    await page.goto(url + "/" + hash);
    return { context, page, problems, network, dialogs, close: () => context.close() };
  }

  const snapshot = (page) => page.evaluate(() => window.__em.snapshot());
  const planDetail = (page) => page.evaluate(() => window.__em.planDetail());

  async function until(page, description, fn, arg, timeout = 15000) {
    try {
      await page.waitForFunction(fn, arg, { timeout, polling: 100 });
    } catch (error) {
      let state = "";
      try { const snap = await snapshot(page); state = JSON.stringify({ plan: snap.plan, devices: snap.devices.length }).slice(0, 800); } catch { /* page gone */ }
      throw new Error(`timeout waiting for: ${description}\n${state}\n${error.message}`);
    }
  }

  const card = (page, name) => page.locator(".card", { hasText: name });

  async function waitForCards(page, names) {
    for (const name of names) await card(page, name).first().waitFor({ timeout: 20000 });
  }

  /** Opens #/plan and selects the room (retry: the toolbar is rebuilt with live data). */
  async function openPlan(page, room) {
    await page.evaluate(() => { location.hash = "#/plan"; });
    for (let i = 0; i < 25; i++) {
      const plan = (await snapshot(page)).plan;
      if (plan.room === room && plan.loaded && !plan.loading) return;
      await page.locator("#viewPlan .planToolbar select").selectOption(room, { timeout: 1000 }).catch(() => {});
      await H.sleep(300);
    }
    throw new Error("could not open the plan view of " + room + ": " + JSON.stringify((await snapshot(page)).plan));
  }

  async function enterEditMode(page) {
    if ((await snapshot(page)).plan.mode === "edit") return;
    await page.locator("label.planModeControl").click();
    await until(page, "edit mode", () => window.__em.snapshot().plan.mode === "edit", null);
    await page.locator("#planSaveBtn").waitFor();
  }

  /** Stores a skeleton (revision baseRev -> baseRev+1) on every given simulator, like another manager would. */
  function seedSkeleton(sims, room, sk, baseRev = 0) {
    for (const sim of sims) {
      const res = H.emClient(sim.hostPort, ["post", "/plan-skeleton", JSON.stringify({ room, baseRev, sk })]);
      assert.equal(res.status, 200, JSON.stringify(res));
    }
  }

  function seedSlice(sim, id, plan) {
    const res = H.emClient(sim.hostPort, ["post", "/plan", JSON.stringify({ id, plan })]);
    assert.equal(res.status, 200, JSON.stringify(res));
  }

  /** The browser must not have reported anything (errors, unhandled rejections). */
  const noProblems = (p) => assert.deepEqual(p.problems, []);

  /** Polls the stored activity log (localStorage, written at most once a second). */
  async function readLog(page) {
    return page.evaluate(() => JSON.parse(localStorage.getItem("em.log") || "[]"));
  }

  return { openPage, snapshot, planDetail, until, card, waitForCards, openPlan, enterEditMode, seedSkeleton, seedSlice, noProblems, readLog };
}

/** Two rooms: A hosts the "laser" and "kamera" components (two simulators), B hosts "tuer". */
export async function startNetwork({ totalSteps = 5 } = {}) {
  const tag = H.randomTag();
  const rooms = { a: `EM-${tag}-A`, b: `EM-${tag}-B` };
  const ids = { laser: `laser-${tag}`, kamera: `cam-${tag}`, tuer: `door-${tag}` };
  const names = { laser: `Laser-${tag}`, kamera: `Kamera-${tag}`, tuer: `Tuer-${tag}` };
  const laser = await H.startSim({ components: [`${names.laser}:${rooms.a}:${ids.laser}`], totalSteps });
  const kamera = await H.startSim({ components: [`${names.kamera}:${rooms.a}:${ids.kamera}`], totalSteps });
  const tuer = await H.startSim({ components: [`${names.tuer}:${rooms.b}:${ids.tuer}`], battery: 0, totalSteps });
  const sims = [laser, kamera, tuer];
  // Each test stops its own simulators: devices of earlier tests would otherwise show up as peers.
  return { tag, rooms, ids, names, laser, kamera, tuer, roomA: [laser, kamera], stopAll: () => Promise.all(sims.map((sim) => sim.stop())) };
}
