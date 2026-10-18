// Tests of the manager UI self-upgrade (PROTOCOL.md section 8) and the token UX badges.
// Browser tests use loopback HTTP ports 9400-9499 and UDP discovery port 14240 (own range, so
// that other test runs on the same machine do not interfere).
//
//   node --test test/manager/
//
// The browser part is skipped with a clear message when playwright-core, Chromium or the
// simulator (g++ with OpenSSL headers) are missing; the pure unit tests always run.
import { test, describe, before, after, afterEach } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { spawnSync } from "node:child_process";
import * as H from "./helpers.mjs";
import { startStub } from "./stub.mjs";

const PORT_BASE = 9400;
const UDP_PORT = 14240;
const net = { portBase: PORT_BASE, udpPort: UDP_PORT };

const html = fs.readFileSync(H.managerHtml, "utf8");
const sha8 = (buffer) => crypto.createHash("sha256").update(buffer).digest("hex").slice(0, 8);

// ---- 1. pure unit tests: semver copies, version constants ----------------------------------------

describe("self-upgrade: version helpers", () => {
  const copies = [...html.matchAll(/\/\*EM-SEMVER-BEGIN\*\/([\s\S]*?)\/\*EM-SEMVER-END\*\//g)].map((m) => m[1]);

  test("the boot stage and the app each carry a copy of semverGreater, and the copies are identical", () => {
    assert.equal(copies.length, 2);
    assert.equal(copies[0].trim(), copies[1].trim());
    assert.ok(html.indexOf("EM-SEMVER-BEGIN") < html.indexOf("EM-CRYPTO-BEGIN"), "boot stage must come before the crypto bundle");
  });

  const table = [
    ["2.0.1", "2.0.0", true], ["2.0.0", "2.0.0", false], ["2.0.0", "2.0.1", false],
    ["2.1.0", "2.0.9", true], ["2.0.9", "2.1.0", false], ["3.0.0", "2.9.9", true],
    ["2.10.0", "2.9.0", true], ["2.9.0", "2.10.0", false], // numeric, not lexical
    ["10.0.0", "9.0.0", true], ["9.0.0", "10.0.0", false],
    ["0.0.1", "0.0.0", true], ["1.2.3", "1.2.3", false],
    ["2.0", "1.0.0", false], ["2", "1.0.0", false], ["2.0.0.1", "2.0.0", false], ["", "2.0.0", false],
    ["abc", "2.0.0", false], ["2.0.1", "bogus", false], ["2.0.1-beta", "2.0.0", false], ["v2.0.1", "2.0.0", false],
    ["2.0.1 ", "2.0.0", false], [" 2.0.1", "2.0.0", false], ["2.0.1\n", "2.0.0", false], ["2.0.-1", "2.0.0", false],
    ["1000000.0.0", "2.0.0", false], // more than 6 digits per field is not a version
    [undefined, "2.0.0", false], [null, "2.0.0", false], [201, "2.0.0", false], [{}, "2.0.0", false], [["2.0.1"], "2.0.0", false],
  ];

  copies.forEach((code, index) => {
    const semverGreater = new Function(code + "; return semverGreater;")();
    test(`semverGreater table (${index === 0 ? "boot stage" : "app"} copy)`, () => {
      for (const [a, b, expected] of table) assert.equal(semverGreater(a, b), expected, `semverGreater(${JSON.stringify(a)}, ${JSON.stringify(b)})`);
    });
  });

  test("UI_VERSION is the same in the boot stage, the app and EscapeVersion.hpp, and is exposed as window.UI_VERSION", () => {
    const boot = html.match(/var UI_VERSION = "(\d+\.\d+\.\d+)"/);
    const app = html.match(/const UI_VERSION = "(\d+\.\d+\.\d+)"/);
    const header = fs.readFileSync(path.join(H.root, "src/protocol/EscapeVersion.hpp"), "utf8").match(/\bUI = "(\d+\.\d+\.\d+)"/);
    assert.ok(boot && app && header);
    assert.equal(boot[1], app[1]);
    assert.equal(app[1], header[1]);
    assert.match(html, /window\.UI_VERSION = UI_VERSION;/);
    // the download check looks for exactly this line, so it must exist in this shape
    assert.ok(html.includes(`UI_VERSION = "${app[1]}"`));
  });

  test("the boot stage is the very first script of the document", () => {
    assert.equal(html.indexOf("<script>"), html.indexOf("<script>\n// UI-Selbstupgrade, Stufe 1"), "first <script> is the boot stage");
    assert.ok(html.indexOf("<script>") < html.indexOf("<style>"));
  });
});

// ---- browser tests -----------------------------------------------------------------------------

const chromium = await H.loadPlaywright();
const executablePath = H.findChromium();
let skip = false;
if (!chromium) skip = "playwright-core is not installed (cd test/manager && npm install)";
else if (!executablePath) skip = "no Chromium found under ~/.cache/ms-playwright/chromium-*/ or chromium_headless_shell-*/";
else {
  const buildError = H.ensureSimulator();
  if (buildError) skip = buildError;
}
if (skip) console.log(`# selfupgrade.test.mjs browser tests SKIPPED: ${skip}`);

/**
 * Simulator build that announces UI version 2.0.1 (EscapeVersion::UI is a compile-time constant, so a
 * second binary is built from a patched copy of the sources; ~5 s, cached in the temp directory).
 */
function buildNewerSimulator(version) {
  const dir = path.join(os.tmpdir(), "em-selfupgrade-sim-" + version);
  const binary = path.join(dir, "sim");
  const sourcesRoot = path.join(H.root, "src");
  const newest = Math.max(...walk(sourcesRoot).filter((f) => /\.(cpp|hpp|h)$/.test(f)).map((f) => fs.statSync(f).mtimeMs));
  if (fs.existsSync(binary) && fs.statSync(binary).mtimeMs >= newest) return binary;
  fs.rmSync(dir, { recursive: true, force: true });
  fs.mkdirSync(dir, { recursive: true });
  fs.cpSync(sourcesRoot, path.join(dir, "src"), { recursive: true, filter: (file) => !/(\.o|\.gz|\.pyc)$|__pycache__|[\\/]output([\\/]|$)|escape_component_(sim|serial_host)$/.test(file) });
  const headerPath = path.join(dir, "src/protocol/EscapeVersion.hpp");
  const header = fs.readFileSync(headerPath, "utf8");
  const patched = header.replace(/(\bUI = ")[^"]*(")/, `$1${version}$2`);
  assert.notEqual(patched, header, "EscapeVersion.hpp must contain the UI constant");
  fs.writeFileSync(headerPath, patched);
  const protocol = fs.readdirSync(path.join(dir, "src/protocol")).filter((f) => f.endsWith(".cpp")).map((f) => path.join(dir, "src/protocol", f));
  const sources = ["src/sim/escape_component_sim.cpp", "src/sim/OpenSslCryptoBackend.cpp", "src/net/Device.cpp", "src/net/Net.cpp"].map((f) => path.join(dir, f));
  const result = spawnSync("g++", ["-std=c++17", "-O1", "-pthread", "-o", binary, ...sources, ...protocol, "-lcrypto"], { cwd: dir, encoding: "utf8" });
  if (result.error || result.status !== 0) throw new Error("newer simulator build failed: " + (result.error?.message || result.stderr.slice(-400)));
  return binary;
}

function walk(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(full));
    else out.push(full);
  }
  return out;
}

const NEW_VERSION = "2.0.1";
const TOKEN_DEFAULT = "EscapeManager-Private-WLAN-Default-Token";
const TOKEN_CUSTOM = "some-long-custom-token-value";

describe("manager.html UI self-upgrade and token badges (browser)", { skip }, () => {
  let browser;
  let workDir;
  let newerHtmlPath;   // repository manager.html with UI_VERSION = "2.0.1"
  let newerHtml;       // its text
  let newerHash;       // first 8 hex of SHA-256 over its bytes
  let newerBinary;     // simulator announcing ui "2.0.1"
  const stubs = new Set();

  before(async () => {
    workDir = fs.mkdtempSync(path.join(os.tmpdir(), "em-selfupgrade-"));
    newerHtml = html.replaceAll('UI_VERSION = "2.0.0"', `UI_VERSION = "${NEW_VERSION}"`);
    assert.notEqual(newerHtml, html);
    newerHtmlPath = path.join(workDir, "manager-2.0.1.html");
    fs.writeFileSync(newerHtmlPath, newerHtml);
    newerHash = sha8(fs.readFileSync(newerHtmlPath));
    newerBinary = buildNewerSimulator(NEW_VERSION);
    browser = await chromium.launch({ executablePath, headless: true });
  });

  // Every test starts from an empty network: sims of earlier tests would otherwise announce their
  // UI to the next test's page through the shared UDP port.
  async function stopDevices() {
    await H.stopAllSims();
    for (const s of stubs) await s.stop().catch(() => {});
    stubs.clear();
  }
  afterEach(stopDevices);

  after(async () => {
    await browser?.close();
    await stopDevices();
    if (workDir) fs.rmSync(workDir, { recursive: true, force: true });
  });

  async function stub(options = {}) {
    const s = await startStub({ listenPort: await H.freePort(PORT_BASE), ...options });
    stubs.add(s);
    return s;
  }

  /** Sim A serves the repository UI; sim B serves (and announces) UI 2.0.1. */
  async function startPair({ token = "" } = {}) {
    const tag = H.randomTag();
    const a = await H.startSim({ components: [`Alpha-${tag}:EM-${tag}:alpha-${tag}`], token, ...net });
    const b = await H.startSim({ components: [`Beta-${tag}:EM-${tag}:beta-${tag}`], token, html: newerHtmlPath, binary: newerBinary, ...net });
    return { tag, a, b };
  }

  /** New page in `context` (default: a fresh one); presets are applied once per origin before the page's own code runs. */
  async function openPage(url, { storage = {}, session = {}, hash = "", context = null } = {}) {
    context = context || await browser.newContext();
    const page = await context.newPage();
    const problems = [];
    const network = [];
    const navigations = [];
    page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
    page.on("console", (message) => {
      if (message.type() === "error" && !/Failed to load resource|net::ERR_/.test(message.text())) problems.push("console.error: " + message.text());
    });
    page.on("request", (request) => network.push({ url: request.url(), method: request.method(), at: Date.now() }));
    page.on("framenavigated", (frame) => { if (frame === page.mainFrame()) navigations.push(frame.url()); });
    page.on("dialog", (dialog) => dialog.accept().catch(() => {}));
    await page.addInitScript(([local, sessionValues]) => {
      for (const [key, value] of Object.entries(local)) if (localStorage.getItem("__init_" + key) === null) { localStorage.setItem(key, value); localStorage.setItem("__init_" + key, "1"); }
      for (const [key, value] of Object.entries(sessionValues)) if (sessionStorage.getItem("__init_" + key) === null) { sessionStorage.setItem(key, value); sessionStorage.setItem("__init_" + key, "1"); }
    }, [{ "em.pollMs": "1000", ...storage }, session]);
    await page.goto(url + "/" + hash);
    return { context, page, problems, network, navigations, close: () => context.close() };
  }

  async function until(page, description, fn, arg, timeout = 20000) {
    try {
      await page.waitForFunction(fn, arg, { timeout, polling: 100 });
    } catch (error) {
      let state = "";
      try {
        state = JSON.stringify(await page.evaluate(() => ({ ui: window.__em?.snapshot().ui, version: window.UI_VERSION, title: document.title, trial: localStorage.getItem("em.ui.trial"),
          cache: !!localStorage.getItem("em.ui.cache"), bad: localStorage.getItem("em.ui.bad"), swapped: sessionStorage.getItem("em.ui.swapped"), log: localStorage.getItem("em.log") }))).slice(0, 1500);
      } catch { /* page gone */ }
      throw new Error(`timeout waiting for: ${description}\n${state}\n${error.message}`);
    }
  }

  /** Every message also lands in the activity log (localStorage, written at most once a second). */
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

  // (never print a cache entry in an assertion message: it is the whole 230 kB UI)
  const hasCache = (page) => page.evaluate(() => localStorage.getItem("em.ui.cache") !== null);
  const readCache = (page) => page.evaluate(() => JSON.parse(localStorage.getItem("em.ui.cache") || "null"));
  const store = (page, key) => page.evaluate((k) => localStorage.getItem(k), key);
  const rootRequests = (network, sim) => network.filter((r) => r.url === sim.base + "/").length;

  /** Lets the page run a few polls. */
  const settle = (ms = 4000) => H.sleep(ms);

  const waitForVersion = (page, version) => until(page, `UI_VERSION === ${version}`, (v) => window.UI_VERSION === v && !!document.getElementById("settingsBtn"), version);
  const card = (page, name) => page.locator(".card", { hasText: name });

  test("(2) the newest UI in the network is cached, announced without swapping, and swapped in on reload (once per boot, no loops)", async () => {
    const { tag, a, b } = await startPair();
    const p = await openPage(a.base);
    try {
      // within a few polls: B's UI is downloaded, verified against the authenticated uih and cached
      await until(p.page, "cache entry", () => !!localStorage.getItem("em.ui.cache"));
      const cache = await readCache(p.page);
      assert.equal(cache.ver, NEW_VERSION);
      assert.equal(cache.hash, newerHash, "stored hash is the SHA-256 prefix of the file B serves");
      assert.equal(cache.html, newerHtml, "stored text is exactly what B served");
      const served = await (await fetch(b.base + "/")).text();
      assert.equal(sha8(Buffer.from(served)), cache.hash);
      assert.equal((await (await fetch(b.base + "/security.json")).json()).uih, cache.hash);
      // the running page is NOT swapped; a non-modal notice offers the reload
      assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0");
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.ui.swapped")), null);
      const notice = p.page.locator('#noticeBar [data-notice="ui"]');
      await notice.waitFor({ timeout: 8000 });
      assert.equal((await notice.locator("span").innerText()).trim(), `Neue Oberfläche ${NEW_VERSION} verfügbar – wird beim nächsten Laden verwendet`);
      assert.equal((await notice.locator("button").innerText()).trim(), "Jetzt neu laden");
      assert.equal(await p.page.evaluate(() => document.querySelector("dialog[open]")), null, "no modal dialog");
      assert.equal(await p.page.evaluate(() => window.__em.snapshot().ui.pending), NEW_VERSION);
      // fetched once only, not at every poll
      await settle(3500);
      assert.equal(rootRequests(p.network, b), 1, "B's UI is downloaded once");
      assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0", "still not swapped");

      // settings dialog names the running UI and its source
      await p.page.locator("#settingsBtn").click();
      assert.equal((await p.page.locator("#settingsUiVersion").innerText()).trim(), "2.0.0");
      assert.equal((await p.page.locator("#settingsUiSource").innerText()).trim(), "ausgeliefert");
      await p.page.locator("#dlgCloseBtn").click();

      // reload: the cached UI replaces the served one; the trial flag stays until its first successful poll
      await p.page.reload();
      await waitForVersion(p.page, NEW_VERSION);
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.ui.swapped")), "1");
      assert.deepEqual(await p.page.evaluate(() => window.__emUiSwapped), { ver: NEW_VERSION, hash: newerHash });
      await until(p.page, "first successful poll clears the trial flag", () => localStorage.getItem("em.ui.trial") === null);
      await card(p.page, `Alpha-${tag}`).first().waitFor({ timeout: 20000 });
      await card(p.page, `Beta-${tag}`).first().waitFor({ timeout: 20000 });
      assert.equal(await hasCache(p.page), true, "the swapped page's own boot stage did not touch the cache");
      assert.equal(await p.page.locator('#noticeBar [data-notice="ui"]').count(), 0, "nothing newer to announce");
      assert.equal(await p.page.evaluate(() => window.__em.snapshot().ui.source), "cache");
      assert.equal(await p.page.evaluate(() => document.querySelectorAll("#settingsBtn").length), 1, "the document was replaced, not appended to");
      await p.page.locator("#settingsBtn").click();
      assert.equal((await p.page.locator("#settingsUiVersion").innerText()).trim(), NEW_VERSION);
      assert.equal((await p.page.locator("#settingsUiSource").innerText()).trim(), "aus Cache");
      await p.page.locator("#dlgCloseBtn").click();

      // reloads in the same session: stable, no navigation loop, the page keeps working
      for (let i = 0; i < 2; i++) {
        await p.page.reload();
        await waitForVersion(p.page, NEW_VERSION);
        await until(p.page, "trial confirmed again", () => localStorage.getItem("em.ui.trial") === null);
      }
      const before = p.navigations.length;
      await settle(2500);
      assert.equal(p.navigations.length, before, "no further navigations (no reload loop)");
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }
  });

  test("(2b) a swapped-session marker prevents any swap (a written page never re-checks itself)", async () => {
    const { a } = await startPair();
    const cache = JSON.stringify({ ver: NEW_VERSION, hash: newerHash, html: newerHtml });
    const p = await openPage(a.base, { storage: { "em.ui.cache": cache }, session: { "em.ui.swapped": "1" } });
    try {
      await H.sleep(1500);
      assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0");
      assert.equal(await store(p.page, "em.ui.trial"), null);
      assert.equal(await hasCache(p.page), true, "cache is left alone");
      // the served page still announces what is waiting, and "Jetzt neu laden" clears the marker
      const notice = p.page.locator('#noticeBar [data-notice="ui"]');
      await notice.waitFor({ timeout: 8000 });
      await notice.locator("button").click();
      await waitForVersion(p.page, NEW_VERSION);
    } finally {
      await p.close();
    }
  });

  test("(2c) a cache that is not newer than the served UI is dropped at boot", async () => {
    const { a } = await startPair();
    for (const ver of ["2.0.0", "1.9.9", "garbage"]) {
      const cache = JSON.stringify({ ver, hash: "0123abcd", html: "<!DOCTYPE html><html><body>old</body></html>" });
      const p = await openPage(a.base, { storage: { "em.ui.cache": cache } });
      try {
        await H.sleep(300);
        assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0", ver);
        // (the running app may re-download B's newer UI afterwards, but never keeps the stale entry)
        const entry = await readCache(p.page);
        assert.ok(!entry || entry.html !== "<!DOCTYPE html><html><body>old</body></html>", `stale cache ${ver} was removed`);
      } finally {
        await p.close();
      }
    }
  });

  test("(3) a download whose hash or content does not match the authenticated announcement is discarded", async () => {
    const origin = await H.startSim({ components: [`Origin-${H.randomTag()}:EM-origin:o-1`], ...net });
    const goodHash = newerHash;
    const cases = [
      { name: "wrong hash", ui: NEW_VERSION, uih: "deadbeef", html: Buffer.from(newerHtml) },
      { name: "right hash, content lacks the announced UI_VERSION line", ui: NEW_VERSION, uih: sha8(Buffer.from(html)), html: Buffer.from(html) },
      { name: "right hash, but announced version differs from the content", ui: "2.0.2", uih: goodHash, html: Buffer.from(newerHtml) },
      { name: "invalid UTF-8", ui: NEW_VERSION, uih: sha8(Buffer.concat([Buffer.from(newerHtml), Buffer.from([0xc3, 0x28])])), html: Buffer.concat([Buffer.from(newerHtml), Buffer.from([0xc3, 0x28])]) },
    ];
    for (const spec of cases) {
      const device = await stub({ ui: spec.ui, uih: spec.uih, html: spec.html });
      const p = await openPage(origin.base, { storage: { "em.source": device.base } });
      try {
        await until(p.page, `${spec.name}: stub device polled`, () => window.__em.snapshot().devices.some((d) => d.online && d.key.includes("Stub")));
        for (let i = 0; i < 150 && device.state.gets.filter((g) => g === "/").length < 1; i++) await H.sleep(100); // the page itself came from the origin sim
        assert.equal(device.state.gets.filter((g) => g === "/").length, 1, `${spec.name}: download attempted`);
        await settle(3500);
        assert.equal(await hasCache(p.page), false, `${spec.name}: nothing cached`);
        assert.equal(await p.page.locator('#noticeBar [data-notice="ui"]').count(), 0, `${spec.name}: no notice`);
        assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0");
        assert.equal(device.state.gets.filter((g) => g === "/").length, 1, `${spec.name}: fetched once, not at every poll`);
        await expectLogged(p.page, /Neue Oberfläche .* verworfen/);
        assert.deepEqual(p.problems, []);
      } finally {
        await p.close();
        await device.stop();
        stubs.delete(device);
      }
    }
  });

  test("(3b) a correct download from a stub is accepted; never downloaded in viewer mode or from a device whose answers cannot be authenticated", async () => {
    const origin = await H.startSim({ components: [`Origin-${H.randomTag()}:EM-origin:o-1`], ...net });
    const good = await stub({ ui: NEW_VERSION, uih: newerHash, html: Buffer.from(newerHtml) });
    // positive control
    let p = await openPage(origin.base, { storage: { "em.source": good.base } });
    try {
      await until(p.page, "stub's UI cached", () => !!localStorage.getItem("em.ui.cache"));
      assert.equal((await readCache(p.page)).hash, newerHash);
    } finally {
      await p.close();
    }
    // viewer mode: ui/uih came without a MAC, so nothing is fetched and nothing cached
    p = await openPage(origin.base, { storage: { "em.source": good.base }, session: { "em.token": "" } });
    try {
      await until(p.page, "stub polled in viewer mode", () => window.__em.snapshot().devices.some((d) => d.key.includes("Stub")));
      const before = good.state.gets.filter((g) => g === "/").length;
      await settle(3500);
      assert.equal(good.state.gets.filter((g) => g === "/").length, before, "no download in viewer mode");
      assert.equal(await hasCache(p.page), false);
      assert.equal(await p.page.evaluate(() => window.__em.snapshot().cfg.hasToken), false);
    } finally {
      await p.close();
    }
    // wrong token: MAC check fails, so ui/uih of that device are never believed
    p = await openPage(origin.base, { storage: { "em.source": good.base }, session: { "em.token": "a-completely-different-token-123" } });
    try {
      await until(p.page, "token mismatch detected", () => window.__em.snapshot().records.some((r) => r.tokenMismatch));
      const before = good.state.gets.filter((g) => g === "/").length;
      await settle(2500);
      assert.equal(good.state.gets.filter((g) => g === "/").length, before, "no download from a device that fails the MAC check");
      assert.equal(await hasCache(p.page), false);
    } finally {
      await p.close();
    }
  });

  test("(4) crash fallback: a swapped UI that never confirms is marked bad on the next boot, the served UI is used and that hash is not retried", async () => {
    const { a, b } = await startPair();
    // plant a cache entry for B's real hash whose text crashes at start (the boot stage trusts localStorage;
    // the app verified the hash when it stored the entry)
    const crashing = `<!DOCTYPE html><html><head><title>crash</title></head><body><p id="crashed">crashed</p><script>window.UI_VERSION = "${NEW_VERSION}"; throw new Error("boom");</script></body></html>`;
    const cache = JSON.stringify({ ver: NEW_VERSION, hash: newerHash, html: crashing });
    const first = await openPage(a.base, { storage: { "em.ui.cache": cache } });
    const context = first.context;
    try {
      await until(first.page, "swapped page shows up", () => !!document.getElementById("crashed"));
      assert.equal(await first.page.evaluate(() => window.UI_VERSION), NEW_VERSION);
      assert.equal(await store(first.page, "em.ui.trial"), newerHash, "trial flag stays set: the page never confirmed");
      await H.sleep(1500);
      assert.equal(await store(first.page, "em.ui.trial"), newerHash);
      assert.ok(first.problems.some((m) => /boom/.test(m)));

      // second boot (new tab = new session, same browser profile): stale trial -> bad, cache dropped, served UI
      const second = await openPage(a.base, { context });
      try {
        await waitForVersion(second.page, "2.0.0");
        assert.equal(await store(second.page, "em.ui.trial"), null);
        assert.deepEqual(JSON.parse(await store(second.page, "em.ui.bad")), [newerHash]);
        assert.equal(await second.page.evaluate(() => !!document.getElementById("crashed")), false);
        // B announces exactly that hash: it must not be downloaded again
        await until(second.page, "B seen", () => window.__em.snapshot().devices.length >= 2);
        await settle(4000);
        assert.equal(rootRequests(second.network, b), 0, "bad hash is not downloaded again");
        assert.equal(await hasCache(second.page), false);
        assert.equal(await second.page.locator('#noticeBar [data-notice="ui"]').count(), 0);
        // a third boot stays on the served UI as well
        await second.page.reload();
        await waitForVersion(second.page, "2.0.0");
        assert.equal(await hasCache(second.page), false);
        assert.deepEqual(second.problems, []);
      } finally {
        await second.page.close();
      }
    } finally {
      await first.close();
    }
  });

  test("(4b) crash fallback inside one session: reload after a failed swap drops the open trial through the app", async () => {
    const { a, b } = await startPair();
    const crashing = `<!DOCTYPE html><html><body><p id="crashed">crashed</p><script>window.UI_VERSION = "${NEW_VERSION}"; throw new Error("boom");</script></body></html>`;
    const p = await openPage(a.base, { storage: { "em.ui.cache": JSON.stringify({ ver: NEW_VERSION, hash: newerHash, html: crashing }) } });
    try {
      await until(p.page, "swapped page shows up", () => !!document.getElementById("crashed"));
      await p.page.reload(); // session marker is still set: the boot stage steps aside, the served app cleans up
      await waitForVersion(p.page, "2.0.0");
      await until(p.page, "trial recorded as bad", (hash) => localStorage.getItem("em.ui.trial") === null && localStorage.getItem("em.ui.bad") === JSON.stringify([hash]), newerHash);
      await settle(3500);
      assert.equal(rootRequests(p.network, b), 0);
    } finally {
      await p.close();
    }
  });

  test("(5) pinServed: no swap, no download, and the checkbox switches auto-update off and clears the cache", async () => {
    const { a, b } = await startPair();
    // (a) pinned from the start: a cache entry is not used, B's UI is not downloaded
    const cache = JSON.stringify({ ver: NEW_VERSION, hash: newerHash, html: newerHtml });
    let p = await openPage(a.base, { storage: { "em.ui.cache": cache, "em.ui.pinServed": "1" } });
    try {
      await H.sleep(1000);
      assert.equal(await p.page.evaluate(() => window.UI_VERSION), "2.0.0");
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.ui.swapped")), null);
      assert.equal(await store(p.page, "em.ui.trial"), null);
      await until(p.page, "B seen", () => window.__em.snapshot().devices.length >= 2);
      await settle(3500);
      assert.equal(rootRequests(p.network, b), 0, "pinned: no download");
      assert.equal(await p.page.locator('#noticeBar [data-notice="ui"]').count(), 0, "pinned: no notice");
      await p.page.locator("#settingsBtn").click();
      assert.equal(await p.page.locator("#pinServedInput").isChecked(), true);
      // switching it off lets the next status check fetch B's UI
      await p.page.locator("#pinServedInput").uncheck();
      assert.equal(await store(p.page, "em.ui.pinServed"), null);
      await p.page.locator("#dlgCloseBtn").click();
      await p.page.locator("#reloadAllBtn").click(); // re-reads every status, which evaluates the announcements again
      await until(p.page, "unpinned: B's UI is cached", () => !!localStorage.getItem("em.ui.cache"));
    } finally {
      await p.close();
    }
    // (b) switching it on removes an existing cache entry and the notice immediately
    p = await openPage(a.base);
    try {
      await until(p.page, "cache entry", () => !!localStorage.getItem("em.ui.cache"));
      await p.page.locator('#noticeBar [data-notice="ui"]').waitFor({ timeout: 8000 });
      await p.page.locator("#settingsBtn").click();
      assert.equal(await p.page.locator("#pinServedInput").isChecked(), false);
      assert.match(await p.page.locator("label[for=pinServedInput]").innerText(), /Ausgelieferte Version verwenden \(Auto-Update aus dem Netzwerk aus\)/);
      await p.page.locator("#pinServedInput").check();
      assert.equal(await store(p.page, "em.ui.pinServed"), "1");
      assert.equal(await hasCache(p.page), false, "cache cleared");
      await p.page.locator("#dlgCloseBtn").click();
      await until(p.page, "notice gone", () => !document.querySelector('#noticeBar [data-notice="ui"]'));
      const before = rootRequests(p.network, b);
      await settle(3500);
      assert.equal(rootRequests(p.network, b), before, "no further download while pinned");
      assert.equal(await hasCache(p.page), false);
      await p.page.reload();
      await waitForVersion(p.page, "2.0.0");
    } finally {
      await p.close();
    }
  });

  test("(6) default-token badge and token problem badge", async () => {
    const tag = H.randomTag();
    const defaultSim = await H.startSim({ components: [`Def-${tag}:EM-${tag}-D:def-${tag}`], ...net });
    const customSim = await H.startSim({ components: [`Cus-${tag}:EM-${tag}-C:cus-${tag}`], token: TOKEN_CUSTOM, ...net });
    const tooltip = "Geeignet für ein eigenes, abgeschottetes Escape-Room-WLAN. Für gemeinsame Netze einen eigenen Token setzen (Einstellungen).";
    const visible = (page, selector) => page.locator(selector).isVisible();

    // default token: info badge, no problem badge, no modal and no toast about it
    let p = await openPage(defaultSim.base);
    try {
      await card(p.page, `Def-${tag}`).first().waitFor({ timeout: 20000 });
      const badge = p.page.locator("#badgeDefaultToken");
      assert.equal(await badge.isVisible(), true);
      assert.equal((await badge.innerText()).trim(), "Standard-Token aktiv");
      assert.equal(await badge.getAttribute("title"), tooltip);
      assert.equal(await visible(p.page, "#badgeTokenProblem"), false);
      assert.equal(await p.page.locator("dialog[open]").count(), 0);
      assert.equal(await p.page.locator(".toast").filter({ hasText: /Standard/ }).count(), 0);
      assert.equal(await p.page.evaluate(() => JSON.parse(localStorage.getItem("em.log") || "[]").filter((e) => /Standard-Token/.test(e.text)).length), 0);
    } finally {
      await p.close();
    }

    // custom token on both sides: no badge at all (also after the device status was read: token "custom")
    p = await openPage(customSim.base, { session: { "em.token": TOKEN_CUSTOM } });
    try {
      await card(p.page, `Cus-${tag}`).first().waitFor({ timeout: 20000 });
      await settle(3500);
      assert.equal(await visible(p.page, "#badgeDefaultToken"), false);
      assert.equal(await visible(p.page, "#badgeTokenProblem"), false);
      assert.deepEqual(p.problems, []);
    } finally {
      await p.close();
    }

    // default manager token against a custom-token device: mismatch -> problem badge (the default badge shows because the manager's token is the default)
    p = await openPage(customSim.base);
    try {
      await p.page.locator("#badgeTokenProblem").waitFor({ state: "visible", timeout: 20000 });
      assert.equal((await p.page.locator("#badgeTokenProblem").innerText()).trim(), "Token-Problem: 1 Gerät(e) schreibgeschützt");
      assert.equal(await visible(p.page, "#badgeDefaultToken"), true);
    } finally {
      await p.close();
    }

    // a device that reports token "default" shows the badge even when the manager runs a custom token
    p = await openPage(defaultSim.base, { session: { "em.token": TOKEN_CUSTOM } });
    try {
      await until(p.page, "device status was read", () => !!window.__em.snapshot().records.length);
      await p.page.locator("#badgeTokenProblem").waitFor({ state: "visible", timeout: 20000 });
      assert.equal(await visible(p.page, "#badgeDefaultToken"), true, "device reports token default");
    } finally {
      await p.close();
    }
  });

  test("(6b) settings dialog: short-token warning and provisioning hint", async () => {
    const sim = await H.startSim({ components: [`Cfg-${H.randomTag()}:EM-cfg:cfg-1`], ...net });
    const p = await openPage(sim.base);
    try {
      await p.page.locator("#settingsBtn").click();
      const warning = p.page.locator("#tokenWarn");
      assert.equal(await warning.isVisible(), false, "the default token is 39 characters long");
      assert.equal((await warning.innerText()).trim(), "Token unter 20 Zeichen: leichter zu erraten");
      const field = p.page.locator("#tokenInput");
      const cases = [["", false], ["abcdefg", false], ["abcdefgh", true], ["abcdefghijklmnopqrs", true], ["abcdefghijklmnopqrst", false], ["x".repeat(60), false], ["12345678", true]];
      for (const [value, shown] of cases) {
        await field.fill(value);
        assert.equal(await warning.isVisible(), shown, `token of ${value.length} characters`);
      }
      assert.match(await p.page.locator("#settingsDlg").innerText(), /pio run -e update-auth-token/);
      // a short token can still be saved (warning only)
      await field.fill("abcdefghij");
      await p.page.locator("#dlgCloseBtn").click();
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.token")), "abcdefghij");
    } finally {
      await p.close();
    }
  });

  test("(6c) token in the URL fragment: validated before it is removed, applied only when /security.json allows it", async () => {
    const tag = H.randomTag();
    const sim = await H.startSim({ components: [`Frag-${tag}:EM-${tag}:frag-1`], token: TOKEN_CUSTOM, ...net });
    // too short: the fragment stays (retry possible), no token applied
    let p = await openPage(sim.base, { hash: "#/?token=abc" });
    try {
      await H.sleep(800);
      assert.equal(await p.page.evaluate(() => location.hash), "#/?token=abc");
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.token")), null);
    } finally {
      await p.close();
    }
    // too long: same
    p = await openPage(sim.base, { hash: "#/?token=" + "t".repeat(129) });
    try {
      await H.sleep(800);
      assert.ok((await p.page.evaluate(() => location.hash)).includes("token="));
    } finally {
      await p.close();
    }
    // valid: applied, removed from the address bar, device readable
    p = await openPage(sim.base, { hash: "#/?token=" + TOKEN_CUSTOM });
    try {
      await card(p.page, `Frag-${tag}`).first().waitFor({ timeout: 20000 });
      assert.ok(!(await p.page.evaluate(() => location.hash)).includes("token="));
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.token")), TOKEN_CUSTOM);
      assert.equal(await p.page.locator("#badgeDefaultToken").isVisible(), false);
    } finally {
      await p.close();
    }
    // the device forbids it (allowTokenInUrl:false): token ignored, fragment removed
    const denying = await stub({ allowTokenInUrl: false });
    p = await openPage(denying.base, { hash: "#/?token=" + TOKEN_CUSTOM });
    try {
      await until(p.page, "fragment removed", () => !location.hash.includes("token="));
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.token")), null, "token not applied");
      await expectLogged(p.page, /Token-Übernahme aus Links ist auf diesem Server deaktiviert/);
    } finally {
      await p.close();
    }
    // the device cannot be asked (nothing listens): the fragment stays so that a reload can retry
    const deadPort = await H.freePort(PORT_BASE);
    p = await openPage(sim.base, { hash: "#/?token=" + TOKEN_CUSTOM, storage: { "em.source": `http://127.0.0.1:${deadPort}` } });
    try {
      await H.sleep(1500);
      assert.ok((await p.page.evaluate(() => location.hash)).includes("token="), "kept for a retry");
      assert.equal(await p.page.evaluate(() => sessionStorage.getItem("em.token")), null);
    } finally {
      await p.close();
    }
  });

  test("(7) action names allow umlauts up to 24 UTF-8 bytes; state frames carry a CSP", async () => {
    const actions = ["next_step", "Tür öffnen", "ä".repeat(12), "ä".repeat(13), "<b>x</b>", "a".repeat(25), "über_-.x", "ok:colon"];
    const device = await stub({ actions });
    let p = await openPage(device.base);
    try {
      await card(p.page, "Stub").first().waitFor({ timeout: 20000 });
      const names = await card(p.page, "Stub").first().locator("button").allInnerTexts();
      const shown = names.map((n) => n.trim());
      for (const expected of ["next_step", "Tür öffnen", "ä".repeat(12), "über_-.x"]) assert.ok(shown.includes(expected), `${expected} shown in ${JSON.stringify(shown)}`);
      for (const rejected of ["ä".repeat(13), "<b>x</b>", "a".repeat(25), "ok:colon"]) assert.ok(!shown.includes(rejected), `${rejected} not shown`);
    } finally {
      await p.close();
    }
    const sim = await H.startSim({ components: [`Html-${H.randomTag()}:EM-html:h-1`], htmlState: true, ...net });
    p = await openPage(sim.base);
    try {
      const frame = p.page.locator("iframe.state-frame").first();
      await frame.waitFor({ state: "attached", timeout: 20000 });
      const srcdoc = await frame.getAttribute("srcdoc");
      assert.ok(srcdoc.startsWith(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`), srcdoc.slice(0, 160));
      assert.equal(await frame.getAttribute("sandbox"), "");
    } finally {
      await p.close();
    }
  });
});
