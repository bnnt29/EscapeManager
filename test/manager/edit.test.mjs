// Plan-edit token in the manager (PROTOCOL.md 3.1): the token only decides who may SEND plans to devices;
// the editor itself always works locally. Chromium + C++ simulators started with --edit-token, plus the
// protocol stub for situations a real device cannot produce (stale/lying device state, old firmware,
// unusable stored token, clock steps). HTTP ports from EM_TEST_PORT_BASE, UDP port EM_TEST_UDP_PORT + 1:
//   EM_TEST_PORT_BASE=9700 EM_TEST_UDP_PORT=14270 node --test test/manager/edit.test.mjs
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import * as H from "./helpers.mjs";
import { prerequisites, pageKit } from "./pagekit.mjs";
import { startStub } from "./stub.mjs";
import { connect, keySet } from "./editkit.mjs";

const { chromium, executablePath, skip } = await prerequisites("edit.test.mjs");

const UDP = H.UDP_PORT + 1;           // own discovery port: simulators of other test files never join this fleet
const E = "Edit-Token-For-The-Tests-01";
const E_WRONG = "Another-Edit-Token-For-Tests";
const NORMAL = "Normal-Token-For-The-Tests-1";
const b64u = (buf) => Buffer.from(buf).toString("base64url");

const vectors = JSON.parse(fs.readFileSync(path.join(H.root, "test/fixtures/proto2/vectors.json"), "utf8"));

describe("manager.html plan-edit token", { skip }, () => {
  let browser;
  before(async () => { browser = await chromium.launch({ executablePath, headless: true }); });
  after(async () => { await browser?.close(); await H.stopAllSims(); });
  const K = pageKit(() => browser);
  const { openPage, snapshot, until, waitForCards, openPlan, enterEditMode, noProblems } = K;

  const device = (opts) => H.startSim({ udpPort: UDP, portBase: H.PORT_BASE + 20, ...opts });
  const names = (tag) => ({ laser: `Laser-${tag}`, kamera: `Kamera-${tag}` });

  const sendGate = async (page) => (await snapshot(page)).plan;
  const saveBtn = (page) => page.locator("#planSaveBtn");
  const banner = (page) => page.locator("#planLocalOnly");
  const toasts = (page) => page.locator("#toastStack").innerText().catch(() => "");

  async function setEditTokenInUi(page, value) {
    await page.locator("#settingsBtn").click();
    await page.locator("#editTokenInput").fill(value);
    await page.locator("#dlgCloseBtn").click();
  }

  const proofOf = async (page, did) => (await snapshot(page)).records.find((r) => r.did === did)?.editProof;
  const waitProof = (page, did, state) => until(page, `edit proof ${state} for ${did}`, ([d, s]) => window.__em.snapshot().records.some((r) => r.did === d && r.editProof === s), [did, state]);
  // the gate's answer AND the button/banner showing it (they follow with the next render)
  const waitSendAllowed = (page, allowed) => until(page, `sendAllowed=${allowed}`, (a) => {
    const button = document.querySelector("#planSaveBtn"), note = document.querySelector("#planLocalOnly");
    return window.__em.snapshot().plan.sendAllowed === a && !!button && button.disabled === !a && !!note && note.hidden === a;
  }, allowed);
  const requests = (p, re, method) => p.network.filter((r) => re.test(r.url) && (!method || r.method === method));
  const addLayer = async (page) => {
    const before = (await snapshot(page)).plan.layers;
    await page.locator(".planAddLayerBtn").click();
    await until(page, "layer added", (n) => window.__em.snapshot().plan.layers === n + 1, before);
  };

  async function savedRev(page, rev) {
    await until(page, `saved rev ${rev}`, (r) => window.__em.snapshot().plan.rev === r && !window.__em.snapshot().plan.saving, rev);
  }

  test("(1) device with edit token, manager without: banner + disabled save, everything local keeps working, nothing is sent or stored", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      await enterEditMode(page);
      await addLayer(page);

      // the send button is disabled (not hidden), with the reason as tooltip; a banner says what is going on
      await until(page, "banner shown", () => document.querySelector("#planLocalOnly") && !document.querySelector("#planLocalOnly").hidden, null);
      assert.equal(await saveBtn(page).isDisabled(), true);
      assert.equal(await saveBtn(page).isVisible(), true, "disabled, not hidden");
      const text = await banner(page).innerText();
      assert.match(text, /^Nur lokal: Änderungen werden nicht auf Geräte übertragen und gehen beim Neuladen verloren\./);
      assert.match(text, /Zum Senden wird das Bearbeiten-Token benötigt \(Geräte: .*Laser-/);
      assert.equal(await saveBtn(page).getAttribute("title"), text, "the tooltip carries the same reason");
      const gate = await sendGate(page);
      assert.equal(gate.sendAllowed, false);
      assert.deepEqual(gate.sendBlocked.map((b) => b.code), ["missing"]);

      // header: informational badge (no problem badge); the device detail shows the state
      await page.locator("#badgeEditMissing").waitFor({ state: "visible" });
      assert.equal((await page.locator("#badgeEditMissing").innerText()).trim(), "Bearbeiten-Token fehlt");
      assert.equal(await page.locator("#badgeEditProblem").isVisible(), false);

      // local work: edit, export, import all work without permission
      assert.equal((await snapshot(page)).plan.dirty, true);
      const download = page.waitForEvent("download");
      await page.getByRole("button", { name: "Als JSON herunterladen" }).click();
      const exported = JSON.parse(fs.readFileSync(await (await download).path(), "utf8"));
      assert.equal(exported.layers.length, 1, "the local layer is in the export");
      await page.locator("#viewPlan input[type=file]").setInputFiles({ name: "plan.json", mimeType: "application/json",
        buffer: Buffer.from(JSON.stringify({ planId: "local-only", room, layers: [{ id: "X1", name: "Importiert", lanes: [] }, { id: "X2", name: "Zwei", lanes: [] }], variables: [], nodes: {} })) });
      await until(page, "import applied", () => window.__em.planDetail().layers.length === 2, null);
      assert.equal((await sendGate(page)).sendAllowed, false);

      // nothing went to the device, and the plan is not kept in the browser's storage
      await H.sleep(1500);
      assert.deepEqual(requests(p, /\/plan(-skeleton)?$|\/setup$/, "POST"), [], "no edit-path request was made");
      const dev = await connect(sim);
      assert.equal(await dev.skeleton(room), null, "the device has no plan");
      const stored = await page.evaluate(() => JSON.stringify([{ ...localStorage }, { ...sessionStorage }]));
      assert.ok(!stored.includes("Importiert") && !stored.includes("local-only"), "no plan data in web storage");
      assert.equal(await page.evaluate(() => sessionStorage.getItem("em.editToken")), null);

      // device detail: the state is spelled out
      await page.evaluate(([r, name]) => { location.hash = "#/component/" + encodeURIComponent(r) + "/" + encodeURIComponent(name); }, [room, n.laser]);
      await page.locator("#viewDetail .kv").waitFor();
      assert.match(await page.locator("#viewDetail .kv").innerText(), /Bearbeiten-Token\s+gesetzt – im Manager nicht eingetragen/);

      // reloading the page loses the local changes (the plan is read from the devices again)
      await page.evaluate(() => { location.hash = "#/"; });
      await page.reload();
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      assert.equal((await snapshot(page)).plan.layers, 0);
      assert.equal((await snapshot(page)).plan.dirty, false);
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(2) the right edit token (settings): proof once, save enabled, the plan arrives stamped with the edit MAC", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    // seed a plan the way an authorised manager would (edit keys), including a slice for the component
    const dev = await connect(sim, { editToken: E });
    assert.equal((await dev.post("/plan-skeleton", { room, baseRev: 0, sk: { schema: 1, planId: "p2", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }], dummies: [], variables: [] } }, { edit: true })).status, 200);
    assert.equal((await dev.post("/plan", { id: 0, plan: { planId: "p2", layer: "L1", lane: "A1", connections: [], variables: [] } }, { edit: true })).status, 200);
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      await enterEditMode(page);
      await addLayer(page);
      assert.equal(await saveBtn(page).isDisabled(), true, "no edit token yet");

      await setEditTokenInUi(page, E);
      await waitProof(page, sim.did, "ok");
      await waitSendAllowed(page, true);
      assert.equal(await saveBtn(page).isDisabled(), false);
      assert.equal(await banner(page).isVisible(), false);
      assert.equal(await page.locator("#badgeEditMissing").isVisible(), false);
      assert.equal(await page.locator("#badgeEditProblem").isVisible(), false);
      assert.equal((await sendGate(page)).sendMessage, "");

      await saveBtn(page).click();
      await savedRev(page, 2);
      const toast = await toasts(page);
      assert.match(toast, /Ablaufplan gespeichert: 2 ok/);
      assert.doesNotMatch(toast, /fehlgeschlagen/);

      // what really arrived: the new revision, stamped with emac = HMAC(ek_mac, "EM2|skel|room|rev|hash")
      const blob = await dev.skeleton(room);
      assert.equal(blob.rev, 2);
      assert.equal(blob.sk.layers.length, 2);
      const mac = crypto.createHmac("sha256", keySet(E, { edit: true }).mac).update(`EM2|skel|${room}|${blob.rev}|${blob.hash}`).digest();
      assert.equal(blob.emac, b64u(mac), "the device stamped the skeleton it stored for the authorised write");
      const status = await dev.status();
      assert.equal(status.components[0].plan.layer, "L1", "the component slice was written too");

      // the edit token lives in this tab's sessionStorage only (like the normal token), never in localStorage
      assert.equal(await page.evaluate(() => sessionStorage.getItem("em.editToken")), E);
      assert.ok(!(await page.evaluate(() => JSON.stringify({ ...localStorage }))).includes(E));
      // the proof happened once per (device, token): not once per poll
      await H.sleep(4500);
      assert.equal(requests(p, /\/edit\.json/).length, 1, requests(p, /\/edit\.json/).map((r) => r.url).join(" "));
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(3) a wrong edit token: proof failure message, still disabled; the right one afterwards re-checks and enables", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      await enterEditMode(page);
      await addLayer(page);
      await setEditTokenInUi(page, E_WRONG);
      await waitProof(page, sim.did, "bad");
      await until(page, "failure toast", () => /Bearbeiten-Token passt nicht zu diesem Gerät: Laser-/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      await page.locator("#badgeEditProblem").waitFor({ state: "visible" });
      assert.match(await page.locator("#badgeEditProblem").innerText(), /Bearbeiten-Token passt nicht: 1 Gerät/);
      assert.equal(await page.locator("#badgeEditMissing").isVisible(), false, "a token is set: not 'missing'");
      assert.equal(await saveBtn(page).isDisabled(), true);
      assert.match(await banner(page).innerText(), /Nur lokal: .*Bearbeiten-Token passt nicht zu: .*Laser-/);
      assert.deepEqual((await sendGate(page)).sendBlocked.map((b) => b.code), ["bad"]);
      assert.equal(requests(p, /\/edit\.json/).length, 1, "one proof for this token");
      // detail view
      await page.evaluate(([r, name]) => { location.hash = "#/component/" + encodeURIComponent(r) + "/" + encodeURIComponent(name); }, [room, n.laser]);
      await page.locator("#viewDetail .kv").waitFor();
      assert.match(await page.locator("#viewDetail .kv").innerText(), /Bearbeiten-Token\s+gesetzt – passt nicht zum eingetragenen Token/);
      await page.evaluate(() => { location.hash = "#/plan"; });

      // the correct token: re-checked because the token changed
      await setEditTokenInUi(page, E);
      await waitProof(page, sim.did, "ok");
      await waitSendAllowed(page, true);
      assert.equal(requests(p, /\/edit\.json/).length, 2, "re-checked once for the new token");
      assert.equal(await saveBtn(page).isDisabled(), false);
      await page.locator("#badgeEditProblem").waitFor({ state: "hidden" });
      assert.equal((await (await connect(sim)).skeleton(room)), null, "nothing was written meanwhile");
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(4) mixed fleet: one protected and one unprotected device host the room -> nothing is sent until the edit token is set (all or nothing)", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const open = await device({ components: [`${n.kamera}:${room}:cam-${tag}`] });
    const closed = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const p = await openPage(open.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser, n.kamera]);
      await openPlan(page, room);
      await enterEditMode(page);
      await addLayer(page);
      await waitSendAllowed(page, false);
      const gate = await sendGate(page);
      assert.deepEqual(gate.sendBlocked.map((b) => b.label.split(" ")[0]), [n.laser], "only the protected device is named: " + JSON.stringify(gate.sendBlocked));
      const text = await banner(page).innerText();
      assert.ok(text.includes(n.laser) && !text.includes(n.kamera), text);
      assert.equal(await saveBtn(page).isDisabled(), true);
      await H.sleep(1000);
      assert.equal(await (await connect(open)).skeleton(room), null, "not even the unprotected device was written");

      await setEditTokenInUi(page, E);
      await waitSendAllowed(page, true);
      assert.equal(await saveBtn(page).isDisabled(), false);
      await saveBtn(page).click();
      await savedRev(page, 1);
      assert.doesNotMatch(await toasts(page), /fehlgeschlagen/);
      const a = await (await connect(open)).skeleton(room);
      const b = await (await connect(closed)).skeleton(room);
      assert.equal(a.rev, 1);
      assert.equal(b.rev, 1);
      assert.equal(a.hash, b.hash, "both devices hold the same bytes");
      assert.equal(a.emac, undefined, "a device without an edit token does not stamp");
      assert.equal(typeof b.emac, "string", "the protected device does");
      noProblems(p);
    } finally { await p.close(); await open.stop(); await closed.stop(); }
  });

  test("(4b) applyPlanVariables stays on the normal token and works without the edit token", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      await enterEditMode(page);
      const brightness = page.locator(".planVarRow", { hasText: "brightness" }).first();
      await brightness.locator("input[type=number]").fill("77");
      await until(page, "variable enabled", (id) => window.__em.planDetail().nodes[id].variables.brightness?.enabled === true, `laser-${tag}`);
      assert.equal(await saveBtn(page).isDisabled(), true, "plan sending is blocked ...");
      await page.getByRole("button", { name: "Variablen anwenden" }).click();
      await until(page, "variables applied", () => /Variablen angewendet: 1 ok/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      const status = await (await connect(sim)).status();
      assert.equal(status.components[0].customConfig.find((c) => c.key === "brightness").value, "77", "... but device configuration is not");
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(5) a device without an edit token ('unset') is the normal state: no badge, no banner, save works with the normal token only", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`] });
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await openPlan(page, room);
      await enterEditMode(page);
      await addLayer(page);
      await waitSendAllowed(page, true);
      assert.equal(await saveBtn(page).isDisabled(), false);
      assert.equal(await banner(page).isVisible(), false);
      for (const id of ["#badgeEditMissing", "#badgeEditProblem"]) assert.equal(await page.locator(id).isVisible(), false, id);
      await page.evaluate(([r, name]) => { location.hash = "#/component/" + encodeURIComponent(r) + "/" + encodeURIComponent(name); }, [room, n.laser]);
      await page.locator("#viewDetail .kv").waitFor();
      assert.match(await page.locator("#viewDetail .kv").innerText(), /Bearbeiten-Token\s+nicht gesetzt/);
      await page.evaluate(() => { location.hash = "#/plan"; });
      await saveBtn(page).click();
      await savedRev(page, 1);
      assert.equal((await (await connect(sim)).skeleton(room)).rev, 1);
      assert.equal(requests(p, /\/edit\.json/).length, 0, "no proof for a device without an edit token");
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });

  test("(6) edit token from the URL fragment (#/...?edit=): validated, applied after the device allowed tokens in links, removed from the address, never sent", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const good = await openPage(sim.base, { hash: `#/plan?edit=${encodeURIComponent(E)}` });
    try {
      await waitProof(good.page, sim.did, "ok");
      assert.equal(await good.page.evaluate(() => location.hash), "#/plan", "the token is gone from the address bar");
      assert.equal(await good.page.evaluate(() => sessionStorage.getItem("em.editToken")), E);
      assert.equal((await snapshot(good.page)).cfg.hasEditToken, true);
      assert.ok(good.network.every((r) => !r.url.includes(E) && !r.url.includes("edit=")), "the fragment never reaches a server");
      noProblems(good);
    } finally { await good.close(); }
    // both tokens in one link
    const both = await openPage(sim.base, { hash: `#/?token=${encodeURIComponent(H.randomTag() + "-not-the-token")}&edit=${encodeURIComponent(E)}` });
    try {
      await until(both.page, "fragment consumed", () => !location.hash.includes("edit="), null);
      assert.equal(await both.page.evaluate(() => sessionStorage.getItem("em.editToken")), E);
      assert.notEqual(await both.page.evaluate(() => sessionStorage.getItem("em.token")), null);
    } finally { await both.close(); }
    // too short: rejected with the same length rule as the settings, nothing stored, the link stays for a retry
    const bad = await openPage(sim.base, { hash: "#/?edit=short" });
    try {
      await until(bad.page, "toast", () => /URL-Bearbeiten-Token muss 8 bis 128 Zeichen lang sein/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      assert.equal(await bad.page.evaluate(() => sessionStorage.getItem("em.editToken")), null);
      assert.equal((await snapshot(bad.page)).cfg.hasEditToken, false);
    } finally { await bad.close(); await sim.stop(); }
  });

  test("(7) settings: edit token field (8..128, warning below 20), PROTOCOL.md instead of the old ENCRYPTION.md reference", async () => {
    const stub = await startStub();
    const p = await openPage(stub.base);
    const page = p.page;
    try {
      await waitForCards(page, ["Stub"]);
      await page.locator("#settingsBtn").click();
      const dialog = await page.locator("#settingsDlg").innerText();
      assert.match(dialog, /Bearbeiten-Token \(optional\) – erlaubt das Senden von Plänen an Geräte/);
      assert.doesNotMatch(await page.locator("#settingsDlg").innerHTML(), /ENCRYPTION/);
      assert.match(dialog, /PROTOCOL\.md Abschnitt 3/);
      assert.equal(await page.locator("#editTokenInput").getAttribute("type"), "password");
      assert.equal(await page.locator("#editTokenWarn").isVisible(), false);
      await page.locator("#editTokenInput").fill("12345678");
      assert.equal(await page.locator("#editTokenWarn").isVisible(), true, "8..19 characters warn");
      await page.locator("#editTokenInput").fill("x".repeat(20));
      assert.equal(await page.locator("#editTokenWarn").isVisible(), false);
      // out of range: not accepted, the dialog stays open
      await page.locator("#editTokenInput").fill("short");
      await page.locator("#dlgCloseBtn").click();
      assert.equal(await page.locator("#settingsDlg").evaluate((d) => d.open), true);
      assert.match(await toasts(page), /Bearbeiten-Token muss 8 bis 128 Zeichen lang sein/);
      await page.locator("#editTokenInput").fill("x".repeat(129));
      await page.locator("#dlgCloseBtn").click();
      assert.equal(await page.locator("#settingsDlg").evaluate((d) => d.open), true);
      await page.locator("#editTokenInput").fill("");
      await page.locator("#dlgCloseBtn").click();
      assert.equal(await page.locator("#settingsDlg").evaluate((d) => d.open), false, "empty = no edit token is fine");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(8) the envelope, the answer and the proof frame built by the page equal the shared vectors", async () => {
    const stub = await startStub();
    const p = await openPage(stub.base);
    const page = p.page;
    const v = vectors.edit;
    try {
      await waitForCards(page, ["Stub"]);
      const common = { token: v.normalToken, editToken: v.editToken, iterations: vectors.kdf.iter, did: vectors.did, path: v.post.path };
      const sealed = (edit) => page.evaluate((a) => window.__em.sealPostForTest(a), { ...common, t: v.post.t, iv: v.post.iv, plaintext: v.post.plaintext, edit });
      assert.equal(await sealed(true), v.post.envelope, "edit-keyed envelope, k:e last");
      assert.equal(await sealed(false), v.post.normalEnvelope, "normal envelope has no k");
      const opened = await page.evaluate((a) => window.__em.openResponseForTest(a), { ...common, iv: v.post.iv, status: v.postResponse.status, envelope: v.postResponse.envelope });
      assert.deepEqual(opened, { text: v.postResponse.plaintext, key: "edit" });
      assert.equal(await page.evaluate((a) => window.__em.openResponseForTest(a), { ...common, editToken: v.editToken + "x", iv: v.post.iv, status: v.postResponse.status, envelope: v.postResponse.envelope }), null, "wrong edit token does not open it");
      const proof = (frame, extra = {}) => page.evaluate((a) => window.__em.verifyEditFrameForTest(a), { editToken: v.editToken, iterations: vectors.kdf.iter, did: vectors.did, nonce: v.proof.nonce, frame, ...extra });
      assert.equal(await proof(v.proof.frame), true);
      assert.equal(await proof(v.proof.frame.replace('"edit":"custom"', '"edit":"unset"')), false, "tampered document");
      assert.equal(await proof(v.proof.frame, { nonce: v.proof.nonce + "x" }), false, "another nonce");
      assert.equal(await proof(v.proof.frame, { did: "aabbccddee00" }), false, "another device");
      assert.equal(await proof(v.proof.frame, { editToken: v.normalToken }), false, "the normal token is not the edit token");
      assert.equal(await proof('{"doc":{"proto":2,"edit":"custom"},"mac":"AAAA"}'), false, "short mac");
      assert.equal(await proof("not a frame"), false, "garbage");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  // ---- situations a real simulator cannot produce: the protocol stub --------------------------------

  async function saveFromStub(stub, { editToken = "" } = {}) {
    const p = await openPage(stub.base);
    const page = p.page;
    await waitForCards(page, ["Stub"]);
    if (editToken) await setEditTokenInUi(page, editToken);
    await openPlan(page, "StubRoom");
    await enterEditMode(page);
    await addLayer(page);
    return p;
  }

  test("(9) a device that wants an edit token but did not say so: the 403 edit_required becomes a clear German message", async () => {
    const stub = await startStub({ editToken: E, publishEdit: "unset" }); // lies in security.json/status.json
    const p = await saveFromStub(stub);
    const page = p.page;
    try {
      await waitSendAllowed(page, true); // the page believes "unset"
      await saveBtn(page).click();
      await until(page, "failure toast", () => /Dieses Gerät verlangt das Bearbeiten-Token/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      assert.match(await toasts(page), /Ablaufplan gespeichert: 0 ok, 1 fehlgeschlagen/);
      const post = stub.state.posts.find((r) => r.path === "/plan-skeleton");
      assert.equal(post.k, undefined, "sealed with the normal keys, as the device claimed 'unset'");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(10) 409 stale_time on an edit request: clock resynchronised, retried ONCE with the edit keys", async () => {
    const stub = await startStub({ editToken: E });
    const p = await saveFromStub(stub, { editToken: E });
    const page = p.page;
    try {
      await waitProof(page, stub.did, "ok");
      await waitSendAllowed(page, true);
      stub.setSkew(60000); // the device clock jumps: the manager's offset is now wrong
      await saveBtn(page).click();
      await savedRev(page, 1);
      assert.match(await toasts(page), /Ablaufplan gespeichert: 2 ok/);
      const skeletonPosts = stub.state.posts.filter((r) => r.path === "/plan-skeleton");
      assert.equal(skeletonPosts.length, 2, "one stale attempt, one retry: " + JSON.stringify(skeletonPosts));
      assert.deepEqual(skeletonPosts.map((r) => r.k), ["e", "e"], "both attempts carry k:e");
      assert.equal(skeletonPosts[0].plain, undefined, "the stale one was not even opened");
      assert.equal(skeletonPosts[1].role, "edit");
      assert.equal(stub.state.posts.filter((r) => r.path === "/plan").every((r) => r.k === "e" && r.role === "edit"), true);
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(10b) a clock that never converges is not retried more than once, also with the edit keys", async () => {
    const stub = await startStub({ editToken: E });
    const p = await saveFromStub(stub, { editToken: E });
    const page = p.page;
    try {
      await waitProof(page, stub.did, "ok");
      stub.setAlwaysStale(true);
      await saveBtn(page).click();
      await until(page, "failure", () => /fehlgeschlagen/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      assert.equal(stub.state.posts.filter((r) => r.path === "/plan-skeleton").length, 2, "exactly one retry");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(11) the device removed its edit token meanwhile: the 401 is read as 'state changed', re-read once, retried with the normal keys", async () => {
    const stub = await startStub({ editToken: E });
    const p = await saveFromStub(stub, { editToken: E });
    const page = p.page;
    try {
      await waitProof(page, stub.did, "ok");
      await waitSendAllowed(page, true);
      stub.setEdit({ token: "", state: "unset" }); // not announced by any status change
      await saveBtn(page).click();
      await savedRev(page, 1);
      assert.match(await toasts(page), /Ablaufplan gespeichert: 2 ok/);
      const posts = stub.state.posts.filter((r) => r.path === "/plan-skeleton");
      assert.deepEqual(posts.map((r) => r.k), ["e", undefined]);
      assert.equal(posts[1].role, "normal");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(11b) the proof is repeated when the device restarts (boot changes) or its edit token changes; never for an unchanged device", async () => {
    const stub = await startStub({ editToken: E });
    const p = await openPage(stub.base);
    const page = p.page;
    try {
      await waitForCards(page, ["Stub"]);
      await setEditTokenInUi(page, E);
      await waitProof(page, stub.did, "ok");
      await H.sleep(3500); // several poll cycles: still exactly one proof
      assert.equal(requests(p, /\/edit\.json/).length, 1);
      stub.setBoot(2);
      await until(page, "second proof", () => performance.getEntriesByType("resource").filter((r) => r.name.includes("/edit.json")).length === 2, null, 20000);
      await waitProof(page, stub.did, "ok");
      // the device's edit token was replaced meanwhile: the next proof (after a restart) fails
      stub.setEdit({ token: E_WRONG });
      stub.setBoot(3);
      await waitProof(page, stub.did, "bad");
      assert.equal(requests(p, /\/edit\.json/).length, 3);
      await page.locator("#badgeEditProblem").waitFor({ state: "visible" });
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(12) a stored edit token the device cannot use ('invalid'): sending is blocked for everybody, shown on card, detail and header", async () => {
    const stub = await startStub({ editState: "invalid" });
    const p = await openPage(stub.base);
    const page = p.page;
    try {
      await waitForCards(page, ["Stub"]);
      await setEditTokenInUi(page, E); // even with an edit token
      await K.card(page, "Stub").locator(".badge", { hasText: "Bearbeiten-Token ungültig – Plan-Senden gesperrt" }).waitFor();
      await page.locator("#badgeEditProblem").waitFor({ state: "visible" });
      assert.match(await page.locator("#badgeEditProblem").innerText(), /Bearbeiten-Token ungültig: 1 Gerät/);
      await openPlan(page, "StubRoom");
      await enterEditMode(page);
      await addLayer(page);
      assert.equal(await saveBtn(page).isDisabled(), true);
      assert.match(await banner(page).innerText(), /Nur lokal: .*Bearbeiten-Token ungültig – Plan-Senden gesperrt \(Geräte: Stub/);
      assert.deepEqual((await sendGate(page)).sendBlocked.map((b) => b.code), ["invalid"]);
      await page.evaluate(() => { location.hash = "#/component/StubRoom/Stub"; });
      await page.locator("#viewDetail .kv").waitFor();
      assert.match(await page.locator("#viewDetail .kv").innerText(), /Bearbeiten-Token\s+ungültig – Plan-Senden gesperrt/);
      assert.equal(stub.state.posts.length, 0, "nothing was sent");
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(13) older firmware (no cap 'edit', no edit field): normal keys exactly as before, even when the manager has an edit token", async () => {
    const stub = await startStub({ caps: ["plan", "cfg"] });
    const p = await saveFromStub(stub, { editToken: E });
    const page = p.page;
    try {
      await waitSendAllowed(page, true);
      assert.equal(await saveBtn(page).isDisabled(), false);
      await saveBtn(page).click();
      await savedRev(page, 1);
      assert.match(await toasts(page), /Ablaufplan gespeichert: 2 ok/);
      const posts = stub.state.posts.filter((r) => r.path === "/plan-skeleton" || r.path === "/plan");
      assert.equal(posts.length, 2);
      assert.ok(posts.every((r) => r.k === undefined && r.role === "normal"), JSON.stringify(posts));
      assert.equal(requests(p, /\/edit\.json/).length, 0);
      for (const id of ["#badgeEditMissing", "#badgeEditProblem"]) assert.equal(await page.locator(id).isVisible(), false, id);
      noProblems(p);
    } finally { await p.close(); await stub.stop(); }
  });

  test("(14) a skeleton with an emac is read and ignored: viewing/leaving edit mode never writes, a real save never carries an emac", async () => {
    const tag = H.randomTag();
    const room = `EM-${tag}-R`;
    const n = names(tag);
    const sim = await device({ components: [`${n.laser}:${room}:laser-${tag}`], editToken: E });
    const dev = await connect(sim, { editToken: E });
    const sk = { schema: 1, planId: "p14", room, futureField: { keep: [1, 2] }, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }], dummies: [], variables: [] };
    assert.equal((await dev.post("/plan-skeleton", { room, baseRev: 0, sk }, { edit: true })).status, 200);
    const before = await dev.skeleton(room);
    assert.equal(typeof before.emac, "string");
    const p = await openPage(sim.base);
    const page = p.page;
    try {
      await waitForCards(page, [n.laser]);
      await setEditTokenInUi(page, E);
      await openPlan(page, room);
      await enterEditMode(page);
      await H.sleep(1500);
      await page.locator("label.planModeControl").click(); // back to view mode
      await until(page, "view mode", () => window.__em.snapshot().plan.mode === "view", null);
      await H.sleep(1500);
      assert.deepEqual(requests(p, /\/plan(-skeleton)?$/, "POST"), [], "nothing is written while only looking");
      assert.deepEqual(await dev.skeleton(room), before, "the stored blob is byte-for-byte the same incl. emac");
      // a real edit: the new blob is stamped by the DEVICE; the page sends only {room, baseRev, sk}
      await enterEditMode(page);
      await addLayer(page);
      await waitSendAllowed(page, true);
      await saveBtn(page).click();
      await savedRev(page, 2);
      const after = await dev.skeleton(room);
      assert.deepEqual(after.sk.futureField, { keep: [1, 2] }, "unknown fields are kept");
      assert.notEqual(after.emac, before.emac);
      assert.equal(after.emac, b64u(crypto.createHmac("sha256", keySet(E, { edit: true }).mac).update(`EM2|skel|${room}|${after.rev}|${after.hash}`).digest()));
      noProblems(p);
    } finally { await p.close(); await sim.stop(); }
  });
});
