// Rendering / accessibility tests (manager.html, Chromium + C++ simulators): stable DOM across polls,
// focus, tabs, detail page, log view, own-action log entries. HTTP ports 9500-9599 / UDP 14250 through
//   EM_TEST_PORT_BASE=9500 EM_TEST_UDP_PORT=14250 node --test test/manager/render.test.mjs
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import * as H from "./helpers.mjs";
import { prerequisites, pageKit, startNetwork } from "./pagekit.mjs";

const { chromium, executablePath, skip } = await prerequisites("render.test.mjs");

describe("manager.html rendering and accessibility", { skip }, () => {
  let browser;
  before(async () => { browser = await chromium.launch({ executablePath, headless: true }); });
  after(async () => { await browser?.close(); await H.stopAllSims(); });
  const K = pageKit(() => browser);
  const { openPage, snapshot, until, card, waitForCards, noProblems, readLog } = K;

  test("(7) cards: the same DOM node, no iframe reload, no DOM churn and kept focus across polls", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const sim = await H.startSim({ components: [`Html-${tag}:${room}:html-${tag}`, `Zweit-${tag}:${room}:zwei-${tag}`], htmlState: true });
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [`Html-${tag}`, `Zweit-${tag}`]);
      await page.locator(".card iframe.state-frame").first().waitFor();
      await H.sleep(2500); // let the first renders settle
      const focusTarget = card(page, `Html-${tag}`).getByRole("button", { name: "reset", exact: true });
      await focusTarget.focus();
      await page.evaluate((name) => {
        const el = [...document.querySelectorAll(".card")].find((c) => c.textContent.includes(name));
        window.__card = el;
        window.__frame = el.querySelector("iframe");
        window.__frameLoads = 0;
        window.__frame.addEventListener("load", () => { window.__frameLoads++; });
        window.__focused = document.activeElement;
        window.__mutations = 0;
        new MutationObserver((records) => { window.__mutations += records.length; }).observe(document.getElementById("grid"), { childList: true });
        new MutationObserver((records) => { window.__tabMutations = (window.__tabMutations || 0) + records.length; }).observe(document.getElementById("tabs"), { childList: true });
      }, `Html-${tag}`);
      await H.sleep(4500); // at least four poll/render cycles
      const result = await page.evaluate((name) => ({
        sameCard: [...document.querySelectorAll(".card")].find((c) => c.textContent.includes(name)) === window.__card,
        connected: window.__card.isConnected,
        sameFrame: window.__card.querySelector("iframe") === window.__frame,
        frameLoads: window.__frameLoads,
        mutations: window.__mutations,
        tabMutations: window.__tabMutations || 0,
        focusKept: document.activeElement === window.__focused && window.__focused.isConnected,
      }), `Html-${tag}`);
      assert.deepEqual(result, { sameCard: true, connected: true, sameFrame: true, frameLoads: 0, mutations: 0, tabMutations: 0, focusKept: true });
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(7b) a card that does change keeps the focus on its action button", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      const button = card(page, net.names.laser).getByRole("button", { name: "next_step", exact: true });
      await button.focus();
      await page.keyboard.press("Enter");
      await until(page, "card shows 1 / 5", (name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")), net.names.laser);
      await until(page, "action finished, button enabled", (name) => {
        const c = [...document.querySelectorAll(".card")].find((x) => x.textContent.includes(name));
        const b = c && [...c.querySelectorAll("button")].find((x) => x.textContent === "next_step");
        return b && !b.disabled;
      }, net.names.laser);
      await H.sleep(500);
      assert.equal(await page.evaluate(() => document.activeElement?.textContent), "next_step", "focus stayed on the action button of the rebuilt card");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(8) tabs: tablist/tab roles, aria-selected, arrow keys, Enter/Space; finished tab stays readable", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      assert.equal(await page.locator("#tabs").getAttribute("role"), "tablist");
      const tabs = page.locator("#tabs button[role=tab]");
      assert.equal(await tabs.count(), 3);
      assert.deepEqual(await tabs.evaluateAll((els) => els.map((el) => [el.dataset.room, el.getAttribute("aria-selected"), el.tabIndex])),
        [["__all__", "true", 0], [net.rooms.a, "false", -1], [net.rooms.b, "false", -1]]);
      await tabs.first().focus();
      await page.keyboard.press("ArrowRight");
      assert.equal(await page.evaluate(() => document.activeElement.dataset.room), net.rooms.a);
      await page.keyboard.press("End");
      assert.equal(await page.evaluate(() => document.activeElement.dataset.room), net.rooms.b);
      await page.keyboard.press("ArrowRight"); // wraps around
      assert.equal(await page.evaluate(() => document.activeElement.dataset.room), "__all__");
      await page.keyboard.press("ArrowLeft");
      assert.equal(await page.evaluate(() => document.activeElement.dataset.room), net.rooms.b);
      await page.keyboard.press("Home");
      await page.keyboard.press("ArrowRight");
      // arrows only move the focus; Enter selects
      assert.equal(await page.locator('#tabs [role=tab][aria-selected="true"]').getAttribute("data-room"), "__all__");
      await page.keyboard.press("Enter");
      await until(page, "room A selected", (room) => document.querySelector('#tabs [aria-selected="true"]')?.dataset.room === room, net.rooms.a);
      assert.equal(await page.evaluate(() => document.activeElement.dataset.room), net.rooms.a, "focus survives the rebuild of the tabs");
      await until(page, "only room A cards", (names) => [...document.querySelectorAll(".card")].length === 2 && names.every((n) => [...document.querySelectorAll(".card")].some((c) => c.textContent.includes(n))), [net.names.laser, net.names.kamera]);
      await page.keyboard.press("ArrowRight");
      await page.keyboard.press("Space");
      await until(page, "room B selected", (room) => document.querySelector('#tabs [aria-selected="true"]')?.dataset.room === room, net.rooms.b);
      assert.equal(await page.locator(".card").count(), 1);
      // the "finished" mark keeps the active tab readable (white on blue) and is not colour only
      const style = await page.evaluate(() => {
        const tab = document.querySelector('#tabs [aria-selected="true"]');
        tab.classList.add("finished");
        tab.querySelector(".tick").hidden = false;
        const cs = getComputedStyle(tab);
        return { color: cs.color, tick: tab.querySelector(".tick").textContent.trim() };
      });
      assert.equal(style.color, "rgb(255, 255, 255)");
      assert.equal(style.tick, "✓");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(R2/P11) detail page: re-rendered only when the device changed, keeps input and focus; limits, labels, busy buttons", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await page.evaluate((hash) => { location.hash = hash; }, `#/component/${encodeURIComponent(net.rooms.a)}/${encodeURIComponent(net.names.laser)}`);
      await page.locator("#viewDetail h2", { hasText: net.names.laser }).waitFor();
      // limits from security.json, labels linked to their inputs
      assert.equal(await page.locator("#detail-name").getAttribute("maxlength"), "32");
      assert.equal(await page.locator("#detail-room").getAttribute("maxlength"), "32");
      assert.equal(await page.locator("#detail-riddle").getAttribute("maxlength"), "32");
      await page.getByLabel("Name", { exact: true }).fill(net.names.laser + "-neu"); // found through label[for]
      assert.equal(await page.getByLabel("Rätsel-ID", { exact: true }).count() >= 1, true);
      await page.locator("#detail-name").focus();
      await page.evaluate(() => { window.__h2 = document.querySelector("#viewDetail h2"); window.__detailMutations = 0;
        new MutationObserver((r) => { window.__detailMutations += r.length; }).observe(document.getElementById("viewDetail"), { childList: true, subtree: true }); });
      await H.sleep(3500);
      assert.deepEqual(await page.evaluate(() => [document.querySelector("#viewDetail h2") === window.__h2, window.__detailMutations, document.activeElement.id]), [true, 0, "detail-name"],
        "no re-render while nothing changed, focus stays");
      // the device changes (another manager): the page re-renders but keeps the typed text and the focus
      H.emClient(net.laser.hostPort, ["action", "0", "next_step"]);
      await until(page, "re-rendered with the new step", () => /Schritt 1 \/ 5/.test(document.querySelector("#viewDetail")?.textContent || ""), null);
      assert.deepEqual(await page.evaluate(() => [document.querySelector("#viewDetail h2") === window.__h2, document.getElementById("detail-name").value, document.activeElement.id]),
        [false, net.names.laser + "-neu", "detail-name"]);

      // busy state survives a re-render: the rebuilt save button stays disabled while its request runs
      await page.route("**/config", async (route) => { await H.sleep(2500); await route.continue().catch(() => {}); });
      const save = () => page.getByRole("button", { name: "Konfiguration speichern" });
      await page.locator('[data-edit-key="config:label"]').fill("Langsam");
      await save().click();
      assert.equal(await save().isDisabled(), true);
      H.emClient(net.laser.hostPort, ["action", "0", "next_step"]); // forces a re-render during the request
      await until(page, "re-rendered during the request", () => /Schritt 2 \/ 5/.test(document.querySelector("#viewDetail")?.textContent || ""), null);
      assert.equal(await save().isDisabled(), true, "rebuilt button is still disabled");
      await until(page, "save finished", () => [...document.querySelectorAll("button")].some((b) => b.textContent === "Konfiguration speichern" && !b.disabled), null, 10000);
      await until(page, "success toast", () => /Konfiguration an .* gesendet/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(A1/A4) header and card controls are real buttons with names; log filter keeps focus while entries arrive", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      assert.equal(await page.locator("h1 > button#appTitle").getAttribute("aria-label"), "EscapeManager – zur Übersicht");
      assert.equal(await page.locator(".card .gearBtn").first().evaluate((el) => el.tagName), "BUTTON");
      assert.match(await page.locator(".card .gearBtn").first().getAttribute("aria-label"), /Details/);
      await page.locator("#appTitle").click();
      assert.equal(await page.evaluate(() => location.hash), "#/");

      await page.evaluate(() => { location.hash = "#/log"; });
      await page.locator("#logFilterSelect").waitFor();
      assert.equal(await page.locator('label[for="logFilterSelect"]').count(), 1, "the filter has a label");
      await page.locator("#logFilterSelect").focus();
      await page.evaluate(() => { window.__select = document.getElementById("logFilterSelect"); });
      const rowsBefore = await page.locator("#logList .logEntry").count();
      H.emClient(net.kamera.hostPort, ["action", "0", "next_step"]); // foreign action -> event notice -> log entry
      await until(page, "new log entry", (n) => document.querySelectorAll("#logList .logEntry").length > n, rowsBefore, 20000);
      assert.deepEqual(await page.evaluate(() => [document.getElementById("logFilterSelect") === window.__select, document.activeElement === window.__select]), [true, true],
        "the filter element is not rebuilt: an open dropdown stays open and keeps its focus");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(A5) an own action appears once in the log (the device's echo event is not logged again)", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      for (const action of ["next_step", "toggle_error"]) { // different texts: identical toasts within 5 s are merged
        await card(page, net.names.laser).getByRole("button", { name: action, exact: true }).click();
        await H.sleep(1500);
        await until(page, "button enabled again", ([name, label]) => [...document.querySelectorAll(".card")].some((c) => c.textContent.includes(name) &&
          [...c.querySelectorAll("button")].some((b) => b.textContent === label && !b.disabled)), [net.names.laser, action]);
      }
      await H.sleep(3500); // more polls; the log is flushed at most once a second
      const texts = (await readLog(page)).map((e) => e.text);
      for (const action of ["next_step", "toggle_error"]) {
        assert.equal(texts.filter((t) => t.includes(`"${action}" an`)).length, 1, texts.join(" | "));
      }
      assert.equal(texts.filter((t) => /ausgefuehrt|ausgeführt/.test(t)).length, 0, "no second entry for the same action: " + texts.join(" | "));
      // a foreign action IS reported (once)
      H.emClient(net.kamera.hostPort, ["action", "0", "next_step"]);
      await until(page, "foreign event logged", () => JSON.parse(localStorage.getItem("em.log") || "[]").some((e) => /ausgef/.test(e.text)), null, 20000);
      await H.sleep(2500);
      const foreign = (await readLog(page)).filter((e) => /ausgef/.test(e.text));
      assert.equal(foreign.length, 1, JSON.stringify(foreign));
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(A2/A3) static: dead code and obsolete UI texts are gone", () => {
    const full = fs.readFileSync(H.managerHtml, "utf8");
    const html = full.split("\n").filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line)).join("\n"); // comments are not UI texts
    for (const name of ["getRoomSkeleton", "skeletonCache", "tabsViewModel", "lastTabsFingerprint", "planSkeletonCache", "getCachedPlanSkeleton", "invalidateRoomPlanCache"]) {
      assert.equal(html.includes(name), false, name + " should be removed");
    }
    assert.equal((html.match(/function planStructureSnapshot\(/g) || []).length, 1, "one planStructureSnapshot");
    assert.equal(html.includes('steps.innerHTML = ""'), false);
    for (const text of ["Geraetequelle", "vertrauenswuerdige", "warte auf nächsten Broadcast", "Slave", "Live-Feed", "Custom-Config-Werte", "Hinweis fuer Spieler", "Dummy-Objekt"]) {
      assert.equal(html.includes(text), false, `"${text}" should not appear in the UI file`);
    }
    // user-visible strings use umlauts instead of ae/ue/oe spellings
    const strings = [...html.matchAll(/(?:textContent|title|placeholder)\s*=\s*"([^"]*)"/g)].map((m) => m[1]);
    for (const s of strings) assert.doesNotMatch(s, /\b(Geraet|fuer|Raetsel|uebernehm|pruef|waehl|loesch|zurueck)/i, s);
  });
});
