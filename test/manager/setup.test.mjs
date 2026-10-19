// "Geräte-Setup" (PROTOCOL.md 5.8): the manager pushes Wi-Fi settings and tokens to several devices over the
// network. Chromium + C++ simulators started with --setup (and one without: no cap "setup"). HTTP ports from
// EM_TEST_PORT_BASE, UDP port EM_TEST_UDP_PORT + 2:
//   EM_TEST_PORT_BASE=9700 EM_TEST_UDP_PORT=14270 node --test test/manager/setup.test.mjs
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import * as H from "./helpers.mjs";
import { prerequisites, pageKit } from "./pagekit.mjs";
import { connect, DEFAULT_TOKEN } from "./editkit.mjs";

const { chromium, executablePath, skip } = await prerequisites("setup.test.mjs");

const UDP = H.UDP_PORT + 2;
const E = "Edit-Token-For-The-Tests-01";
const T2 = "Fleet-Token-Number-Two-2026";

describe("manager.html device setup", { skip }, () => {
  let browser;
  before(async () => { browser = await chromium.launch({ executablePath, headless: true }); });
  after(async () => { await browser?.close(); await H.stopAllSims(); });
  const K = pageKit(() => browser);
  const { openPage, snapshot, until, waitForCards, noProblems } = K;

  const device = (opts) => H.startSim({ udpPort: UDP, portBase: H.PORT_BASE + 40, ...opts });
  const toasts = (page) => page.locator("#toastStack").innerText().catch(() => "");
  const requests = (p, re, method) => p.network.filter((r) => re.test(r.url) && (!method || r.method === method));

  async function openSetup(page) {
    await page.locator("#setupBtn").waitFor({ state: "visible", timeout: 20000 });
    await page.locator("#setupBtn").click();
    await page.locator("#setupDlg").waitFor({ state: "visible" });
  }
  const rowOf = (page, name) => page.locator("#setupDevices label.checkRow", { hasText: name });
  const fill = async (page, values) => {
    for (const [id, value] of Object.entries(values)) await page.locator(id).fill(value);
  };
  const send = (page) => page.locator("#setupSendBtn").click();
  const results = (page) => page.locator("#setupResult li").allInnerTexts();
  const waitDone = (page) => page.locator("#setupSummary").waitFor({ state: "visible", timeout: 30000 });
  const setEditTokenInUi = async (page, value) => {
    await page.locator("#settingsBtn").click();
    await page.locator("#editTokenInput").fill(value);
    await page.locator("#dlgCloseBtn").click();
  };
  const sessionToken = (page, key = "em.token") => page.evaluate((k) => sessionStorage.getItem(k), key);
  // the manager's normal token: the stored one, or the public default when it was never changed
  const currentToken = async (page) => (await sessionToken(page)) ?? DEFAULT_TOKEN;
  const waitProof = (page, did, state) => until(page, `edit proof ${state} for ${did}`, ([d, s]) => window.__em.snapshot().records.some((r) => r.did === d && r.editProof === s), [did, state]);

  /** Two --setup devices in room A, one without the cap in room B. */
  async function fleet(extraA = {}, extraB = {}) {
    const tag = H.randomTag();
    const rooms = { a: `EM-${tag}-A`, b: `EM-${tag}-B` };
    const names = { laser: `Laser-${tag}`, kamera: `Kamera-${tag}`, tuer: `Tuer-${tag}` };
    const laser = await device({ components: [`${names.laser}:${rooms.a}:laser-${tag}`], setup: true, ...extraA });
    const kamera = await device({ components: [`${names.kamera}:${rooms.a}:cam-${tag}`], setup: true, ...extraB });
    const tuer = await device({ components: [`${names.tuer}:${rooms.b}:door-${tag}`] });
    return { tag, rooms, names, laser, kamera, tuer, stopAll: () => Promise.all([laser, kamera, tuer].map((s) => s.stop())) };
  }

  const answersTo = async (sim, token) => {
    try { await (await connect(sim, { token })).status(); return true; } catch { return false; }
  };

  test("(1) the button appears only with a device that advertises cap 'setup'; only such devices are offered, named with room and did", async () => {
    const tag = H.randomTag();
    const plain = await device({ components: [`Tuer-${tag}:EM-${tag}-B:door-${tag}`] });
    const p = await openPage(plain.base);
    try {
      await waitForCards(p.page, [`Tuer-${tag}`]);
      await H.sleep(2500);
      assert.equal(await p.page.locator("#setupBtn").isVisible(), false, "no device with the cap: no button");
    } finally { await p.close(); await plain.stop(); }

    const net = await fleet();
    const q = await openPage(net.tuer.base); // served by the device WITHOUT the cap; the others are discovered as peers
    try {
      await waitForCards(q.page, Object.values(net.names));
      await openSetup(q.page);
      const rows = await q.page.locator("#setupDevices label.checkRow").allInnerTexts();
      assert.equal(rows.length, 2, "two devices with the cap: " + JSON.stringify(rows));
      assert.ok(rows.some((r) => r.includes(net.names.laser) && r.includes(net.rooms.a) && r.includes(net.laser.did)), rows.join(" | "));
      assert.ok(rows.some((r) => r.includes(net.names.kamera) && r.includes(net.kamera.did)));
      assert.ok(!rows.some((r) => r.includes(net.names.tuer)), "the device without the cap is not offered");
      for (const box of await q.page.locator("#setupDevices input[type=checkbox]").all()) assert.equal(await box.isChecked(), true, "default: all checked");
      // the warning text is there, and there is no way to remove the normal token
      const text = await q.page.locator("#setupDlg").innerText();
      assert.match(text, /Falsche WLAN-Daten: Geräte fallen nach 30 s auf die alten Daten zurück/);
      assert.match(text, /Geräte, die noch nicht umgestellt sind, benötigen weiterhin das alte Token/);
      assert.match(text, /Bearbeiten-Token entfernen/);
      assert.doesNotMatch(text.replace(/Bearbeiten-Token entfernen/g, ""), /Token entfernen/);
      noProblems(q);
    } finally { await q.close(); await net.stopAll(); }
  });

  test("(2) a token change reaches ONLY the selected devices; the manager switches to the new token afterwards", async () => {
    const net = await fleet();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      await rowOf(page, net.names.kamera).locator("input").uncheck();
      await fill(page, { "#setupToken": T2 });
      await send(page);
      await waitDone(page);
      assert.deepEqual((await results(page)).map((t) => t.replace(/\s+/g, " ")), [`✓ ${net.names.laser} (${net.laser.did}): übernommen`]);
      assert.match(await page.locator("#setupSummary").innerText(), /1 von 1 Gerät\(en\) umgestellt\. Der Manager verwendet jetzt das neue Token\./);
      assert.equal(await sessionToken(page), T2, "the manager's own token follows (this tab only)");
      assert.equal((await page.evaluate(() => JSON.stringify({ ...localStorage }))).includes(T2), false);

      assert.equal(await answersTo(net.laser, T2), true, "the selected device runs the new token");
      assert.equal(await answersTo(net.laser, DEFAULT_TOKEN), false);
      assert.equal(await answersTo(net.kamera, DEFAULT_TOKEN), true, "the device that was not selected is untouched");
      assert.equal(await answersTo(net.kamera, T2), false);
      assert.equal((await (await connect(net.laser, { token: T2 })).security).token, "custom");

      // the manager keeps working with the new token against the changed device ...
      await K.card(page, net.names.laser).locator(".badge", { hasText: "Token passt nicht" }).waitFor({ state: "detached", timeout: 15000 }).catch(() => {});
      await until(page, "laser online again", (name) => [...document.querySelectorAll(".card")].some((c) => c.textContent.includes(name) && !c.classList.contains("offline") && !/Token passt nicht/.test(c.textContent)), net.names.laser);
      // ... and the one still on the old token is flagged
      await K.card(page, net.names.kamera).locator(".badge", { hasText: "Token passt nicht" }).waitFor({ timeout: 20000 });
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(3) several devices: each is changed one after another with the OLD token, the manager switches only after all were handled", async () => {
    const net = await fleet();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      await fill(page, { "#setupToken": T2 });
      await send(page);
      await waitDone(page);
      assert.equal((await results(page)).filter((t) => t.startsWith("✓")).length, 2, (await results(page)).join(" | "));
      // had the manager switched early, the second device would have been written with the new (wrong) token
      assert.equal(await answersTo(net.laser, T2), true);
      assert.equal(await answersTo(net.kamera, T2), true);
      assert.equal(await answersTo(net.laser, DEFAULT_TOKEN), false);
      assert.equal(await answersTo(net.kamera, DEFAULT_TOKEN), false);
      assert.equal(await sessionToken(page), T2);
      assert.match(await page.locator("#setupSummary").innerText(), /2 von 2 Gerät\(en\) umgestellt\. Der Manager verwendet jetzt das neue Token\./);
      // both devices are readable with the new token (and nobody complained about a token mismatch while it happened)
      await until(page, "both online", (names) => names.every((name) => [...document.querySelectorAll(".card")].some((c) => c.textContent.includes(name) && !/Token passt nicht|nicht erreichbar/.test(c.textContent))), [net.names.laser, net.names.kamera], 20000);
      assert.doesNotMatch(await toasts(page), /Token passt nicht zu Gerät/);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(4) invalid input is blocked in the page: nothing is sent", async () => {
    const net = await fleet();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      const error = () => page.locator("#setupError").innerText();
      const attempt = async (values, expected, { open = false, remove = false } = {}) => {
        if ((await page.locator("#setupOpenWifi").isChecked()) !== open) await page.locator("#setupOpenWifi").setChecked(open);
        if ((await page.locator("#setupEditRemove").isChecked()) !== remove) await page.locator("#setupEditRemove").setChecked(remove);
        for (const id of ["#setupSsid", "#setupPass", "#setupToken", "#setupEditToken"]) if (!(await page.locator(id).isDisabled())) await page.locator(id).fill("");
        for (const [id, value] of Object.entries(values)) if (!(await page.locator(id).isDisabled())) await page.locator(id).fill(value);
        await send(page);
        assert.match(await error(), expected, JSON.stringify(values));
        assert.equal(await page.locator("#setupError").isVisible(), true);
      };
      await attempt({}, /Nichts zu ändern/);
      await attempt({ "#setupSsid": "a".repeat(33), "#setupPass": "password-ok-1" }, /höchstens 32 Bytes/);
      await attempt({ "#setupSsid": "ä".repeat(17), "#setupPass": "password-ok-1" }, /höchstens 32 Bytes/); // bytes, not characters
      await attempt({ "#setupSsid": "EscapeSetup-aabbccddeeff", "#setupPass": "password-ok-1" }, /Setup-WLAN/);
      await attempt({ "#setupSsid": "MeinWLAN" }, /ausdrücklich „offenes WLAN/); // an untouched password field never means 'open'
      await attempt({ "#setupSsid": "MeinWLAN", "#setupPass": "1234567" }, /8 bis 63 Zeichen/);
      await attempt({ "#setupSsid": "MeinWLAN", "#setupPass": "x".repeat(64) }, /8 bis 63 Zeichen/);
      await attempt({ "#setupSsid": "MeinWLAN", "#setupPass": "pässwort-1234" }, /8 bis 63 Zeichen/);
      await attempt({ "#setupPass": "password-ok-1" }, /WLAN-Name fehlt/);
      await attempt({}, /WLAN-Name fehlt/, { open: true });
      await attempt({ "#setupToken": "1234567" }, /Token: 8 bis 128 Zeichen/);
      await attempt({ "#setupToken": "has a space 1234" }, /Token: 8 bis 128 Zeichen.*ohne Leerzeichen/);
      await attempt({ "#setupToken": "x".repeat(129) }, /Token: 8 bis 128 Zeichen/);
      await attempt({ "#setupEditToken": "short" }, /Bearbeiten-Token: 8 bis 128 Zeichen/);
      // no device selected
      for (const box of await page.locator("#setupDevices input[type=checkbox]").all()) await box.uncheck();
      await attempt({ "#setupToken": T2 }, /Kein Gerät ausgewählt/);
      assert.deepEqual(requests(p, /\/setup$/, "POST"), [], "nothing reached the network");
      assert.deepEqual(p.dialogs.seen, [], "not even a confirmation was asked");
      assert.equal(await answersTo(net.laser, DEFAULT_TOKEN), true);

      // the same rules, exhaustively, in the page's own validator
      const v = (form) => page.evaluate((f) => window.__em.validateSetupForTest({ ssid: "", pass: "", openWifi: false, token: "", editToken: "", editRemove: false, ...f }), form);
      assert.deepEqual((await v({ ssid: "ä".repeat(16), pass: "12345678" })).body, { ssid: "ä".repeat(16), pass: "12345678" }, "32 bytes are fine");
      assert.deepEqual((await v({ ssid: "x", openWifi: true })).body, { ssid: "x", pass: "" }, "explicit open network");
      assert.match((await v({ ssid: "x", openWifi: true, pass: "12345678" })).error, /Passwort-Feld muss leer sein/);
      assert.deepEqual((await v({ editRemove: true })).body, { editToken: "" });
      assert.match((await v({ editRemove: true, editToken: E })).error, /entweder ein neues eintragen oder entfernen/);
      assert.deepEqual((await v({ ssid: "x\ty", pass: "12345678" })).error.length > 0, true, "control characters");
      assert.deepEqual((await v({ pass: "p".repeat(63), ssid: "x" })).body, { ssid: "x", pass: "p".repeat(63) });
      assert.deepEqual((await v({ token: "~".repeat(128) })).body, { token: "~".repeat(128) });
      assert.deepEqual((await v({ token: "a".repeat(8), editToken: "b".repeat(8) })).body, { token: "a".repeat(8), editToken: "b".repeat(8) });
      assert.deepEqual(Object.keys((await v({ ssid: "x", pass: "12345678", token: T2, editToken: E })).body), ["ssid", "pass", "token", "editToken"], "ssid and pass together, then the tokens");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(5) Wi-Fi settings: SSID and password go out together; an open network is an explicit choice; the password is never logged", async () => {
    const net = await fleet();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      await rowOf(page, net.names.kamera).locator("input").uncheck();
      await fill(page, { "#setupSsid": "Escape-WLAN", "#setupPass": "geheim-1234" });
      await send(page);
      await waitDone(page);
      assert.match((await results(page))[0], /übernommen/);
      assert.match(net.laser.log, /setup: wifi ssid=Escape-WLAN/);
      assert.ok(!net.laser.log.includes("geheim-1234"), "the password is not logged");
      assert.ok(!net.kamera.log.includes("setup: wifi"), "the unselected device was not touched");
      assert.equal(await page.locator("#setupPass").inputValue(), "", "secrets are cleared after sending");
      assert.equal(await currentToken(page), DEFAULT_TOKEN, "no token change requested: the manager's token is unchanged");
      assert.match(await page.locator("#setupSummary").innerText(), /Neue WLAN-Daten: .*30 s/);

      // open network: only with the explicit checkbox (the password field is then disabled)
      await fill(page, { "#setupSsid": "Offenes-WLAN" });
      await page.locator("#setupOpenWifi").check();
      assert.equal(await page.locator("#setupPass").isDisabled(), true);
      await send(page);
      await until(page, "second run done", () => /Offenes-WLAN/.test(document.querySelector("#setupSummary")?.textContent || "") || document.querySelectorAll("#setupResult li").length > 0, null);
      await until(page, "open network sent", () => !document.querySelector("#setupSendBtn").disabled, null);
      assert.match(net.laser.log, /setup: wifi ssid=Offenes-WLAN/);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(6) a device with an edit token: skipped ('nicht erlaubt') without the manager's edit token, written with it; the others are still changed", async () => {
    const net = await fleet({ editToken: E }); // Laser is protected, Kamera is not
    const p = await openPage(net.kamera.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      await until(page, "note shown", () => /nicht erlaubt: Bearbeiten-Token fehlt – wird übersprungen/.test(document.querySelector("#setupDevices")?.textContent || ""), null);
      assert.ok(!(await rowOf(page, net.names.kamera).innerText()).includes("nicht erlaubt"), "only the protected device carries the note");
      await fill(page, { "#setupToken": T2 });
      await send(page);
      await waitDone(page);
      const lines = (await results(page)).map((t) => t.replace(/\s+/g, " "));
      assert.ok(lines.includes(`– ${net.names.laser} (${net.laser.did}): nicht erlaubt – Bearbeiten-Token fehlt`), lines.join(" | "));
      assert.ok(lines.includes(`✓ ${net.names.kamera} (${net.kamera.did}): übernommen`), lines.join(" | "));
      const summary = await page.locator("#setupSummary").innerText();
      assert.match(summary, /1 von 2 Gerät\(en\) umgestellt, 1 nicht\./);
      assert.match(summary, new RegExp(`Noch mit dem alten Token laufen: ${net.names.laser}`));
      assert.equal(await sessionToken(page), T2, "at least one device accepted: the manager switches");
      assert.equal(await answersTo(net.laser, DEFAULT_TOKEN), true, "the protected device was not touched");
      assert.equal(await answersTo(net.kamera, T2), true);
      assert.equal(await page.locator("#setupSummary").evaluate((e) => e.classList.contains("warn")), true);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(6b) with the edit token the protected device is changed too (edit keys); when nobody accepts, the manager keeps its token", async () => {
    const net = await fleet({ editToken: E }, { editToken: E });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      // without the edit token nobody can be written: nothing accepted, the token stays
      await openSetup(page);
      await fill(page, { "#setupToken": T2 });
      await send(page);
      await waitDone(page);
      assert.match(await page.locator("#setupSummary").innerText(), /0 von 2 Gerät\(en\) umgestellt, 2 nicht\. Kein Gerät hat das neue Token übernommen – der Manager behält sein bisheriges Token\./);
      assert.equal(await currentToken(page), DEFAULT_TOKEN);
      await page.locator("#setupCloseBtn").click();

      await setEditTokenInUi(page, E);
      await waitProof(page, net.laser.did, "ok");
      await waitProof(page, net.kamera.did, "ok");
      await openSetup(page);
      assert.equal((await page.locator("#setupDevices .note").allInnerTexts()).join("").trim(), "", "no notes: both are writable");
      await fill(page, { "#setupToken": T2 });
      await send(page);
      await waitDone(page);
      assert.equal((await results(page)).filter((t) => t.startsWith("✓")).length, 2, (await results(page)).join(" | "));
      assert.equal(await answersTo(net.laser, T2), true);
      assert.equal(await answersTo(net.kamera, T2), true);
      assert.equal(await sessionToken(page), T2);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(7) changing the edit token: written with the old edit keys, then the manager's edit token follows and is proven again", async () => {
    const E2 = "Second-Edit-Token-2026-xyz";
    const net = await fleet({ editToken: E });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await setEditTokenInUi(page, E);
      await waitProof(page, net.laser.did, "ok");
      await openSetup(page);
      await rowOf(page, net.names.kamera).locator("input").uncheck();
      await fill(page, { "#setupEditToken": E2 });
      await send(page);
      await waitDone(page);
      assert.match(await page.locator("#setupSummary").innerText(), /1 von 1 Gerät\(en\) umgestellt\. Der Manager verwendet jetzt das neue Bearbeiten-Token\./);
      assert.equal(await sessionToken(page, "em.editToken"), E2);
      assert.equal(await currentToken(page), DEFAULT_TOKEN, "the normal token is untouched");
      const dev = await connect(net.laser);
      assert.equal((await dev.proof(E2)).ok, true, "the device now holds the new edit token");
      assert.equal((await dev.proof(E)).ok, false);
      await waitProof(page, net.laser.did, "ok"); // proven again for the new token
      await page.locator("#setupCloseBtn").click();
      assert.equal(await page.locator("#badgeEditProblem").isVisible(), false);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(8) removing the edit token: the manager drops its own only when no known device keeps one", async () => {
    const net = await fleet({ editToken: E }, { editToken: E });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await setEditTokenInUi(page, E);
      await waitProof(page, net.laser.did, "ok");
      await waitProof(page, net.kamera.did, "ok");

      await openSetup(page);
      await rowOf(page, net.names.kamera).locator("input").uncheck();
      await page.locator("#setupEditRemove").check();
      assert.equal(await page.locator("#setupEditToken").isDisabled(), true);
      await send(page);
      await waitDone(page);
      assert.equal((await connect(net.laser)).security.edit, "unset");
      assert.equal((await (await connect(net.laser)).security).caps.includes("edit"), true);
      assert.equal((await connect(net.kamera)).security.edit, "custom");
      assert.match(await page.locator("#setupSummary").innerText(), /Das Bearbeiten-Token bleibt im Manager eingetragen, weil noch Geräte eines haben \(1\)\./);
      assert.equal(await sessionToken(page, "em.editToken"), E);
      await page.locator("#setupCloseBtn").click();

      // the second one: now no device has one any more
      await openSetup(page);
      await rowOf(page, net.names.laser).locator("input").uncheck();
      await page.locator("#setupEditRemove").check();
      await send(page);
      await waitDone(page);
      assert.equal((await connect(net.kamera)).security.edit, "unset");
      assert.match(await page.locator("#setupSummary").innerText(), /Kein Gerät hat mehr ein Bearbeiten-Token; der Manager hat seines entfernt\./);
      assert.equal(await sessionToken(page, "em.editToken"), null);
      assert.equal((await snapshot(page)).cfg.hasEditToken, false);
      // and the plan editor sends again with only the normal token
      await page.locator("#setupCloseBtn").click();
      await H.sleep(500);
      assert.equal(await page.locator("#badgeEditMissing").isVisible(), false);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(9) setting an edit token on devices that had none: they become protected, the manager adopts it and can send plans afterwards", async () => {
    const net = await fleet();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openSetup(page);
      await fill(page, { "#setupEditToken": E });
      await send(page);
      await waitDone(page);
      assert.equal((await connect(net.laser)).security.edit, "custom");
      assert.equal((await connect(net.kamera)).security.edit, "custom");
      assert.equal(await sessionToken(page, "em.editToken"), E);
      await page.locator("#setupCloseBtn").click();
      await waitProof(page, net.laser.did, "ok");
      await waitProof(page, net.kamera.did, "ok");
      assert.equal(await page.locator("#badgeEditMissing").isVisible(), false);
      assert.equal(await page.locator("#badgeEditProblem").isVisible(), false);
      // the devices now demand the edit keys for edit paths: a normal-key write is refused
      const normal = await connect(net.laser);
      assert.equal((await normal.post("/plan", { id: 0, plan: null })).status, 403);
      assert.equal((await (await connect(net.laser, { editToken: E })).post("/plan", { id: 0, plan: null }, { edit: true })).status, 200);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });
});
