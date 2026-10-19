// Browser tests of tools/setup/setup.html (Web Serial provisioning page) against a FAKE board.
// Chromium comes from playwright-core of test/manager (no dependency of its own):
//   node --test test/setup/
// The page is opened from file:// like an operator would; navigator.serial is replaced by a fake that
// plays the firmware's serial protocol (HardwareEsp32::processSerialLine incl. the exact framing).
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
// EM_SETUP_HTML: test another file (e.g. a variant with one rule reverted, to check that a test can fail)
const htmlPath = process.env.EM_SETUP_HTML ? path.resolve(process.env.EM_SETUP_HTML) : path.resolve(here, "..", "..", "tools", "setup", "setup.html");

function findChromium() {
  const cache = path.join(os.homedir(), ".cache", "ms-playwright");
  if (!fs.existsSync(cache)) return null;
  const candidates = [];
  for (const dir of fs.readdirSync(cache)) {
    if (/^chromium-\d+$/.test(dir)) candidates.push(path.join(cache, dir, "chrome-linux64", "chrome"), path.join(cache, dir, "chrome-linux", "chrome"));
    if (/^chromium_headless_shell-\d+$/.test(dir)) candidates.push(path.join(cache, dir, "chrome-headless-shell-linux64", "chrome-headless-shell"));
  }
  return candidates.find((file) => fs.existsSync(file)) || null;
}
async function loadChromium() {
  try { return (await import(new URL("../manager/node_modules/playwright-core/index.mjs", import.meta.url).href)).chromium; } catch { return null; }
}
const chromium = await loadChromium();
const executablePath = findChromium();
const skip = !chromium ? "playwright-core not found (test/manager/node_modules)" : !executablePath ? "no Chromium found under ~/.cache/ms-playwright/" : false;
if (skip) console.log(`# setup.test.mjs SKIPPED: ${skip}`);

/** Runs inside the page BEFORE its own scripts: a fake navigator.serial with a simulated ESP32. */
function installFakeBoard(scenario) {
  if (scenario.missing) { Object.defineProperty(navigator, "serial", { value: undefined, configurable: true }); return; }
  const enc = new TextEncoder(), strict = new TextDecoder("utf-8", { fatal: true }), loose = new TextDecoder();
  const fake = (window.__fake = {
    // bootNoise: log text without newline printed at (re)boot; ignoreAfterBoot: commands swallowed after each boot;
    // prefix/eol: wrapped around every answer; errors: {COMMAND: reason}; silent: [COMMAND] never answered;
    // restart: "stay" (USB-UART bridge) | "drop" (port vanishes, back after dropMs)
    cfg: { bootNoise: "", ignoreAfterBoot: 0, prefix: "", eol: "\n", errors: {}, silent: [], restart: "stay", dropMs: 500, cancel: false, openFails: false, oldInfo: false, ...scenario.cfg },
    state: { did: "7e57aabbccdd", fw: "2.1.1", proto: 2, ssid: "Mein Netz äö", pass: "alt-passwort", token: null, edit: null, wifi: "connected", ip: "192.168.4.77", setup: "open", ...scenario.state },
    lines: [], opens: [], closes: 0, requests: 0, boots: 0, unavailableUntil: 0,
  });
  const state = fake.state;
  let sinceBoot = 0, inbuf = "";
  const port = { isOpen: false, dropped: false, chunks: [], reader: null, readerLocked: false, writerLocked: false };

  const flush = () => {
    const r = port.reader;
    if (!r || !r.pending) return;
    const take = () => { const p = r.pending; r.pending = null; return p; };
    if (r.done) take().resolve({ done: true, value: undefined });
    else if (port.dropped) take().reject(new DOMException("The device has been lost.", "NetworkError"));
    else if (port.chunks.length) take().resolve({ done: false, value: port.chunks.shift() });
  };
  const emit = (text) => { port.chunks.push(enc.encode(text)); flush(); };
  const answer = (text) => setTimeout(() => emit(fake.cfg.prefix + text + fake.cfg.eol), 5);
  const decode = (text, max) => {
    if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text) || text.length % 4) return null;
    try {
      const bytes = Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
      return bytes.length > max ? null : strict.decode(bytes);
    } catch { return null; }
  };
  const restart = () => setTimeout(() => { // the firmware restarts ~100 ms after the OK line
    sinceBoot = 0; fake.boots++;
    if (fake.cfg.restart === "drop") { port.dropped = true; fake.unavailableUntil = Date.now() + fake.cfg.dropMs; flush(); }
    else if (fake.cfg.bootNoise) emit(fake.cfg.bootNoise);
  }, 100);

  function respond(line) {
    const space = line.indexOf(" ");
    const cmd = space < 0 ? line : line.slice(0, space), arg = space < 0 ? "" : line.slice(space + 1);
    if (fake.cfg.silent.includes(cmd)) return null;
    if (cmd === "ESCAPE_INFO") {
      const s = state, common = `ESCAPE_INFO_OK did=${s.did} fw=${s.fw} proto=${s.proto} token=${s.token === null ? "default" : "custom"}`;
      return fake.cfg.oldInfo ? `${common} ip=${s.ip} heap=123456`
        : `${common} edit=${s.edit === null ? "unset" : "custom"} ip=${s.ip} heap=123456 wifi=${s.wifi} setup=${s.setup} ssid=${s.ssid}`;
    }
    const fail = (name, fallback) => `${name}_ERROR ${fake.cfg.errors[cmd] || fallback}`;
    const ok = (name, apply) => { if (fake.cfg.errors[cmd]) return fail(name); apply(); restart(); return name + "_OK"; };
    if (cmd === "ESCAPE_WIFI") {
      const sp = arg.indexOf(" "); // firmware: strchr(copy, ' ') -> no space = format error (so an empty password needs the trailing space)
      if (line === "ESCAPE_WIFI" || sp < 0) return fail("ESCAPE_WIFI", "format");
      const ssid = decode(arg.slice(0, sp), 32), rest = arg.slice(sp + 1), pass = rest === "" ? "" : decode(rest, 63);
      if (ssid === null || ssid === "" || pass === null) return fail("ESCAPE_WIFI", "encoding");
      return ok("ESCAPE_WIFI", () => { state.ssid = ssid; state.pass = pass; });
    }
    if (cmd === "ESCAPE_AUTH_TOKEN" || cmd === "ESCAPE_EDIT_TOKEN") {
      const value = decode(arg, 128), key = cmd === "ESCAPE_AUTH_TOKEN" ? "token" : "edit";
      if (value === null) return fail(cmd, "encoding");
      if (!/^[\x21-\x7e]{8,128}$/.test(value)) return fail(cmd, "length-or-characters");
      return ok(cmd, () => { state[key] = value; });
    }
    if (cmd === "ESCAPE_CLEAR_EDIT_TOKEN") return ok(cmd, () => { state.edit = null; });
    if (cmd === "ESCAPE_CLEAR_AUTH_TOKEN") return ok(cmd, () => { state.token = null; });
    return null;
  }
  function receive(bytes) {
    inbuf += loose.decode(bytes, { stream: true });
    for (let i = inbuf.indexOf("\n"); i >= 0; i = inbuf.indexOf("\n")) {
      const line = inbuf.slice(0, i).replace(/\r/g, "");
      inbuf = inbuf.slice(i + 1);
      if (!line) continue;
      fake.lines.push(line);
      if (line[0] !== "E" || sinceBoot++ < fake.cfg.ignoreAfterBoot) continue; // still booting: swallowed
      const reply = respond(line);
      if (reply) answer(reply);
    }
  }

  Object.defineProperties(port, Object.getOwnPropertyDescriptors({ // (not Object.assign: it would run the getters)
    async open(options) {
      if (port.isOpen) throw new DOMException("The port is already open.", "InvalidStateError");
      if (fake.cfg.openFails || Date.now() < fake.unavailableUntil) throw new DOMException("Failed to open serial port.", "NetworkError");
      fake.opens.push(options && options.baudRate);
      Object.assign(port, { isOpen: true, dropped: false, chunks: [] });
      inbuf = "";
      if (fake.cfg.bootNoise) port.chunks.push(enc.encode(fake.cfg.bootNoise));
    },
    async close() {
      if (!port.isOpen) throw new DOMException("The port is already closed.", "InvalidStateError");
      if (port.readerLocked || port.writerLocked) throw new TypeError("Cannot close a port while its streams are locked");
      port.isOpen = false; fake.closes++;
    },
    get readable() {
      return !port.isOpen ? null : { getReader() {
        port.readerLocked = true;
        const r = (port.reader = { done: false, pending: null,
          read: () => new Promise((resolve, reject) => { r.pending = { resolve, reject }; flush(); }),
          cancel: async () => { r.done = true; flush(); },
          releaseLock: () => { port.readerLocked = false; } });
        return r;
      } };
    },
    get writable() {
      return !port.isOpen ? null : { getWriter() {
        port.writerLocked = true;
        return {
          write: async (chunk) => {
            if (port.dropped || !port.isOpen) throw new DOMException("The device has been lost.", "NetworkError");
            receive(chunk);
          },
          releaseLock: () => { port.writerLocked = false; },
        };
      } };
    },
  }));
  Object.defineProperty(navigator, "serial", { configurable: true, value: {
    requestPort: async () => {
      fake.requests++;
      if (fake.cfg.cancel) throw new DOMException("No port selected by the user.", "NotFoundError");
      return port;
    },
  } });
}

const b64 = (text) => Buffer.from(text, "utf8").toString("base64");
const L = { ssid: "WLAN-Name (SSID)", pass: "WLAN-Passwort", token: "Token (normal)", edit: "Bearbeiten-Token (Plan bearbeiten)", open: "offenes WLAN (ohne Passwort)", clearEdit: "Bearbeiten-Token entfernen", reveal: "Eingaben anzeigen" };
const FAST = { resendMs: 150, timeoutMs: 6000, restartMs: 150, reopenMs: 3000 };

describe("setup.html (Web Serial setup page)", { skip }, () => {
  let browser;
  before(async () => { browser = await chromium.launch({ executablePath, headless: true }); });
  after(async () => { await browser?.close(); });

  /** Opens the page like an operator (file://) with the fake board; `timings: null` keeps the real 1.5 s / 35 s. */
  async function open(scenario = {}, { timings = {} } = {}) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const problems = [], requests = [];
    page.on("pageerror", (error) => problems.push("pageerror: " + error.message));
    page.on("console", (message) => { if (message.type() === "error") problems.push("console.error: " + message.text()); });
    page.on("request", (request) => requests.push(request.url()));
    await page.addInitScript(installFakeBoard, scenario);
    await page.goto(pathToFileURL(htmlPath).href);
    if (timings) await page.evaluate((t) => Object.assign(window.EscapeSetup.config, t), { ...FAST, ...timings });
    const api = {
      page, problems, requests, close: () => context.close(),
      field: (name) => page.getByLabel(L[name], { exact: true }),
      button: (name) => page.getByRole("button", { name, exact: true }),
      disabled: (selector) => page.$eval(selector, (el) => el.disabled), // (isDisabled() ignores fieldsets)
      text: async (selector) => (await page.locator(selector).textContent()).trim(),
      fake: () => page.evaluate(() => ({ lines: window.__fake.lines.slice(), opens: window.__fake.opens.slice(), closes: window.__fake.closes, state: { ...window.__fake.state }, requests: window.__fake.requests })),
      setCfg: (cfg) => page.evaluate((c) => Object.assign(window.__fake.cfg, c), cfg),
      /** waits until neither a connect nor a write is running */
      idle: () => page.waitForFunction(() => !document.getElementById("settings").disabled || !document.getElementById("connect").disabled, null, { timeout: 20000 }),
      async connect() {
        await api.button("Verbinden").click();
        await page.waitForFunction(() => document.getElementById("v-did").textContent !== "–", null, { timeout: 10000 });
      },
      async apply() { await api.button("Auf das Gerät schreiben").click(); await api.idle(); },
      steps: () => page.locator("#steps li").allTextContents(),
      everything: () => page.evaluate(() => document.documentElement.textContent),
    };
    return api;
  }
  const check = (p) => assert.deepEqual(p.problems, [], "no page errors / console errors");
  const commands = (fake) => fake.lines.filter((line) => !line.startsWith("ESCAPE_INFO"));

  test("without navigator.serial: clear message with the pio alternative, nothing is usable", async () => {
    const p = await open({ missing: true });
    try {
      const alert = p.page.locator("#unsupported");
      assert.equal(await alert.isVisible(), true);
      assert.equal(await alert.getAttribute("role"), "alert");
      const text = await alert.textContent();
      assert.match(text, /Chrome/); assert.match(text, /Edge/); assert.match(text, /Firefox/);
      assert.match(text, /pio run -e set-wifi/); assert.match(text, /pio run -e update-auth-token/);
      assert.equal(await p.button("Verbinden").isDisabled(), true);
      assert.equal(await p.disabled("#settings"), true);
      assert.match(await p.text("#status"), /Web Serial/);
      check(p);
    } finally { await p.close(); }
  });

  test("connect: opens 115200 baud, sends ESCAPE_INFO, shows the parsed answer in a table", async () => {
    const p = await open();
    try {
      await p.connect();
      const fake = await p.fake();
      assert.deepEqual(fake.opens, [115200]);
      assert.equal(fake.lines[0], "ESCAPE_INFO");
      assert.equal(await p.text("#v-did"), "7e57aabbccdd");
      assert.match(await p.text("#v-fw"), /2\.1\.1.*Protokoll 2/);
      assert.match(await p.text("#v-token"), /Standard/);
      assert.match(await p.text("#v-edit"), /nicht gesetzt/);
      assert.equal(await p.text("#v-ip"), "192.168.4.77");
      assert.match(await p.text("#v-wifi"), /verbunden/);
      assert.match(await p.text("#v-setup"), /offenes Einrichtungs-WLAN/);
      assert.equal(await p.text("#v-ssid"), "Mein Netz äö");
      assert.equal(await p.button("Verbinden").isDisabled(), true);
      assert.equal(await p.button("Trennen").isDisabled(), false);
      assert.equal(await p.disabled("#settings"), false);
      // table with row headers; the status area is a polite live region
      assert.equal(await p.page.locator("#info th[scope=row]").count(), 8);
      assert.equal(await p.page.locator("#status").getAttribute("aria-live"), "polite");
      assert.equal(await p.page.locator("#status").getAttribute("role"), "status");
      check(p);
    } finally { await p.close(); }
  });

  test("INFO parsing: log text before the answer, SSID with spaces/'='/'ssid=' as the rest of the line, old firmware without the new fields", async () => {
    const weird = "  a  b=c ssid=d ";
    let p = await open({ cfg: { prefix: "I (77) wifi: " }, state: { ssid: weird, ip: "0.0.0.0", wifi: "failed", token: "x", edit: "y", setup: "host" } });
    try {
      await p.connect();
      assert.equal(await p.page.locator("#v-ssid").textContent(), weird);
      assert.match(await p.text("#v-ip"), /nicht verbunden/);
      assert.match(await p.text("#v-wifi"), /fehlgeschlagen/);
      assert.match(await p.text("#v-token"), /eigenes Token/);
      assert.match(await p.text("#v-setup"), /Host/);
      check(p);
    } finally { await p.close(); }
    p = await open({ cfg: { oldInfo: true } });
    try {
      await p.connect();
      assert.equal(await p.text("#v-ssid"), "–");
      assert.equal(await p.text("#v-edit"), "–");
      assert.match(await p.text("#status"), /Bearbeiten-Token/); // hint: old firmware
      check(p);
    } finally { await p.close(); }
  });

  test("all four settings: exact UTF-8 base64 payloads in the order Wi-Fi, token, edit token; inputs cleared; no secret on the page", async () => {
    const ssid = "Café-Netz", pass = "pa ss=word-123", token = "Tok-ABCDEFGHIJKLMNOPQRSTUVWXYZ-1", edit = "Edit-ABCDEFGHIJKLMNOPQRSTUVWXYZ-2";
    const p = await open();
    try {
      await p.connect();
      await p.field("ssid").fill(ssid);
      await p.field("pass").fill(pass);
      await p.field("token").fill(token);
      await p.field("edit").fill(edit);
      await p.apply();
      const fake = await p.fake();
      assert.deepEqual(fake.lines, [
        "ESCAPE_INFO",
        `ESCAPE_WIFI ${Buffer.from("Café-Netz", "utf8").toString("base64")} ${b64(pass)}`,
        `ESCAPE_AUTH_TOKEN ${b64(token)}`,
        `ESCAPE_EDIT_TOKEN ${b64(edit)}`,
        "ESCAPE_INFO", // after the restart: refresh of the table
      ]);
      assert.equal(b64(ssid), "Q2Fmw6ktTmV0eg==");
      assert.deepEqual([fake.state.ssid, fake.state.pass, fake.state.token, fake.state.edit], [ssid, pass, token, edit]);
      const steps = await p.steps();
      assert.equal(steps.length, 3);
      for (const step of steps) assert.match(step, /gespeichert, das Gerät startet neu/);
      for (const name of ["ssid", "pass", "token", "edit"]) assert.equal(await p.field(name).inputValue(), "", name + " cleared");
      assert.equal(await p.text("#v-ssid"), ssid);
      assert.match(await p.text("#v-token"), /eigenes Token/);
      assert.match(await p.text("#v-edit"), /eigenes Token/);
      const page = await p.everything();
      for (const secret of [pass, token, edit, b64(pass), b64(token), b64(edit)]) assert.ok(!page.includes(secret), "secret on the page: " + secret.slice(0, 6));
      check(p);
    } finally { await p.close(); }
  });

  test("open network: checkbox sends an EMPTY password argument exactly like device_storage.py (trailing space)", async () => {
    const p = await open();
    try {
      await p.connect();
      await p.field("ssid").fill("Offen");
      await p.field("open").check();
      assert.equal(await p.field("pass").isDisabled(), true);
      await p.apply();
      const fake = await p.fake();
      assert.deepEqual(commands(fake), [`ESCAPE_WIFI ${b64("Offen")} `]);
      assert.ok(commands(fake)[0].endsWith(" "));
      assert.equal(fake.state.pass, "");
      assert.equal(fake.state.ssid, "Offen");
      assert.match((await p.steps())[0], /gespeichert/);
      assert.equal(await p.field("open").isChecked(), false);
      assert.equal(await p.field("pass").isDisabled(), false);
      check(p);
    } finally { await p.close(); }
  });

  test("only the filled fields are sent; edit token can be removed, the normal token cannot", async () => {
    const p = await open({ state: { token: "alt-token-1234", edit: "alt-edit-1234" } });
    try {
      await p.connect();
      await p.field("token").fill("nur-dieses-token-ist-neu-1234");
      await p.apply();
      assert.deepEqual(commands(await p.fake()), [`ESCAPE_AUTH_TOKEN ${b64("nur-dieses-token-ist-neu-1234")}`]);
      await p.field("clearEdit").check();
      assert.equal(await p.field("edit").isDisabled(), true);
      await p.apply();
      const fake = await p.fake();
      assert.deepEqual(commands(fake).slice(1), ["ESCAPE_CLEAR_EDIT_TOKEN"]);
      assert.equal(fake.state.edit, null);
      assert.ok(!fake.lines.some((line) => line.startsWith("ESCAPE_CLEAR_AUTH_TOKEN")));
      assert.ok(!fake.lines.some((line) => line.startsWith("ESCAPE_WIFI")));
      const labels = await p.page.evaluate(() => [...document.querySelectorAll("label")].map((l) => l.textContent.trim()));
      assert.ok(labels.includes(L.clearEdit));
      assert.ok(!labels.some((text) => /^Token entfernen/.test(text)), "no option to remove the normal token");
      check(p);
    } finally { await p.close(); }
  });

  test("limits accepted exactly like the firmware: 32-byte SSID, 63-char password, 128-char token, 8-char edit token", async () => {
    const ssid = "é".repeat(16), pass = "p".repeat(63), token = "t".repeat(128), edit = "e".repeat(8);
    const p = await open();
    try {
      await p.connect();
      await p.field("ssid").fill(ssid);
      await p.field("pass").fill(pass);
      await p.field("token").fill(token);
      await p.field("edit").fill(edit);
      await p.apply();
      const fake = await p.fake();
      assert.deepEqual(commands(fake), [`ESCAPE_WIFI ${b64(ssid)} ${b64(pass)}`, `ESCAPE_AUTH_TOKEN ${b64(token)}`, `ESCAPE_EDIT_TOKEN ${b64(edit)}`]);
      assert.deepEqual([fake.state.ssid, fake.state.pass, fake.state.token, fake.state.edit], [ssid, pass, token, edit]);
      check(p);
    } finally { await p.close(); }
  });

  test("invalid input is blocked in the browser: no command is sent, the field is marked and the error announced", async () => {
    const p = await open();
    const long = (n, c = "x") => c.repeat(n);
    const cases = [
      ["SSID 34 bytes", { ssid: long(17, "é"), pass: "12345678" }, "ssid", /34 Bytes/],
      ["SSID control character", { ssid: "ab\u0001cd", pass: "12345678" }, "ssid", /Steuerzeichen/],
      ["SSID reserved prefix", { ssid: "EscapeSetup-1A2B", pass: "12345678" }, "ssid", /EscapeSetup-/],
      ["password without SSID", { pass: "12345678" }, "ssid", /fehlt/],
      ["open network without SSID", { open: true }, "ssid", /fehlt/],
      ["SSID without password", { ssid: "Netz" }, "pass", /Passwort fehlt/],
      ["password 7 characters", { ssid: "Netz", pass: "1234567" }, "pass", /8 bis 63/],
      ["password 64 characters", { ssid: "Netz", pass: long(64) }, "pass", /8 bis 63/],
      ["password with umlaut", { ssid: "Netz", pass: "pässwörter" }, "pass", /ASCII/],
      ["token 7 characters", { token: "1234567" }, "token", /8 bis 128/],
      ["token 129 characters", { token: long(129) }, "token", /8 bis 128/],
      ["token with a space", { token: "abcd efghijkl" }, "token", /Leerzeichen/],
      ["token with umlaut", { token: "tökentökentöken" }, "token", /ASCII/],
      ["edit token too short", { edit: "short" }, "edit", /8 bis 128/],
      ["valid Wi-Fi + invalid token: nothing at all is sent", { ssid: "Gut", pass: "12345678", token: "x" }, "token", /8 bis 128/],
    ];
    try {
      await p.connect();
      for (const [name, values, field, message] of cases) {
        await p.field("open").setChecked(false); // re-enables the password field
        for (const key of ["ssid", "pass", "token", "edit"]) await p.field(key).fill(values[key] || "");
        if (values.open) await p.field("open").check();
        await p.button("Auf das Gerät schreiben").click();
        assert.deepEqual((await p.fake()).lines, ["ESCAPE_INFO"], name + ": nothing sent");
        assert.equal(await p.field(field).getAttribute("aria-invalid"), "true", name + ": aria-invalid");
        assert.match(await p.text("#n-" + field), message, name + ": field message");
        assert.equal(await p.page.locator("#status").getAttribute("data-kind"), "error", name + ": status is an error");
        assert.match(await p.text("#status"), message, name + ": announced in the live region");
        assert.equal(await p.page.evaluate(() => document.activeElement.id), field, name + ": focus on the first invalid field");
        assert.equal(await p.disabled("#settings"), false);
      }
      await p.field("open").setChecked(false);
      for (const key of ["ssid", "pass", "token", "edit"]) await p.field(key).fill("");
      await p.button("Auf das Gerät schreiben").click();
      assert.match(await p.text("#status"), /Nichts zu tun/);
      assert.deepEqual((await p.fake()).lines, ["ESCAPE_INFO"]);
      check(p);
    } finally { await p.close(); }
  });

  test("a token below 20 characters is allowed with the manager's warning", async () => {
    const token = "kurz-aber-ok-12"; // 15 characters
    const p = await open();
    try {
      await p.connect();
      await p.field("token").fill(token);
      assert.match(await p.text("#n-token"), /kürzer als 20 Zeichen – leichter zu erraten/);
      assert.equal(await p.field("token").getAttribute("aria-invalid"), null);
      await p.field("token").press("Enter"); // keyboard: Enter submits the form
      await p.idle();
      assert.deepEqual(commands(await p.fake()), [`ESCAPE_AUTH_TOKEN ${b64(token)}`]);
      assert.match(await p.text("#log"), /kürzer als 20 Zeichen – leichter zu erraten/);
      assert.ok(!(await p.everything()).includes(token));
      check(p);
    } finally { await p.close(); }
  });

  test("a board that is still booting (log noise without newline, first command swallowed) is re-sent to until it answers; the answer follows log text", async () => {
    const token = "resend-token-0123456789-abc", edit = "resend-edit-0123456789-abc";
    const p = await open({ cfg: { bootNoise: "I (123) boot: noisy log line without newline ", ignoreAfterBoot: 1 } });
    try {
      await p.connect(); // INFO #1 swallowed, INFO #2 answered in the same line as the noise
      assert.ok((await p.fake()).lines.filter((l) => l === "ESCAPE_INFO").length >= 2);
      assert.equal(await p.text("#v-did"), "7e57aabbccdd");
      await p.field("token").fill(token);
      await p.field("edit").fill(edit);
      await p.apply(); // after the token's restart the board swallows the first command again (edit token, then INFO)
      const fake = await p.fake();
      const sent = (name) => fake.lines.filter((l) => l.startsWith(name));
      assert.ok(sent("ESCAPE_EDIT_TOKEN").length >= 2, "edit token re-sent while the board boots");
      assert.deepEqual([...new Set(sent("ESCAPE_EDIT_TOKEN"))], [`ESCAPE_EDIT_TOKEN ${b64(edit)}`], "same payload every time");
      assert.deepEqual([...new Set(sent("ESCAPE_AUTH_TOKEN"))], [`ESCAPE_AUTH_TOKEN ${b64(token)}`]);
      assert.equal(fake.state.token, token);
      assert.equal(fake.state.edit, edit);
      for (const step of await p.steps()) assert.match(step, /gespeichert/);
      check(p);
    } finally { await p.close(); }
  });

  test("answers prefixed with log text and CRLF line ends are recognised", async () => {
    const p = await open({ cfg: { prefix: "I (9) boot: ", eol: "\r\n" } });
    try {
      await p.connect();
      await p.field("token").fill("prefix-token-0123456789");
      await p.apply();
      assert.match((await p.steps())[0], /gespeichert/);
      assert.equal((await p.fake()).state.token, "prefix-token-0123456789");
      check(p);
    } finally { await p.close(); }
  });

  test("an ERROR answer stops the sequence: reason shown, rest not sent, failed fields stay, finished fields are cleared", async () => {
    const p = await open({ cfg: { errors: { ESCAPE_AUTH_TOKEN: "storage" } } });
    try {
      await p.connect();
      await p.field("ssid").fill("Netz-1");
      await p.field("pass").fill("geheim-1234");
      await p.field("token").fill("fehler-token-0123456789");
      await p.field("edit").fill("fehler-edit-0123456789");
      await p.apply();
      let fake = await p.fake();
      assert.deepEqual(commands(fake).map((l) => l.split(" ")[0]), ["ESCAPE_WIFI", "ESCAPE_AUTH_TOKEN"], "no resend after an error, edit token never sent");
      const steps = await p.steps();
      assert.match(steps[0], /gespeichert/);
      assert.match(steps[1], /abgelehnt.*Speicherfehler/);
      assert.match(steps[2], /nicht gesendet/);
      assert.equal(await p.field("ssid").inputValue(), "");
      assert.equal(await p.field("token").inputValue(), "fehler-token-0123456789");
      assert.equal(await p.field("edit").inputValue(), "fehler-edit-0123456789");
      assert.equal(await p.page.locator("#status").getAttribute("data-kind"), "error");
      // the other reason codes read well, too (fields are still filled: just try again)
      for (const [reason, text] of [["length-or-characters", /Länge oder Zeichen/], ["encoding", /Kodierung/]]) {
        await p.setCfg({ errors: { ESCAPE_AUTH_TOKEN: reason } });
        await p.apply();
        assert.match((await p.steps())[0], text);
      }
      // the board is fine again: the same input now goes through, edit token afterwards
      await p.setCfg({ errors: {} });
      await p.apply();
      fake = await p.fake();
      assert.equal(fake.state.token, "fehler-token-0123456789");
      assert.equal(fake.state.edit, "fehler-edit-0123456789");
      const page = await p.everything();
      for (const secret of ["geheim-1234", "fehler-token-0123456789", "fehler-edit-0123456789"]) assert.ok(!page.includes(secret));
      check(p);
    } finally { await p.close(); }
  });

  test("Wi-Fi errors: the firmware's 'format' answer (no space) maps to a readable reason", async () => {
    const p = await open({ cfg: { errors: { ESCAPE_WIFI: "format" } } });
    try {
      await p.connect();
      await p.field("ssid").fill("Netz");
      await p.field("pass").fill("12345678");
      await p.apply();
      assert.match((await p.steps())[0], /falsches Format/);
      assert.equal(await p.field("ssid").inputValue(), "Netz");
      check(p);
    } finally { await p.close(); }
  });

  test("the port vanishes after every OK (restart): read errors are expected, the page reopens it and carries on", async () => {
    const p = await open({ cfg: { restart: "drop", dropMs: 600 } }, { timings: { reopenMs: 5000 } });
    try {
      await p.connect();
      await p.field("ssid").fill("Neues-Netz");
      await p.field("pass").fill("12345678");
      await p.field("token").fill("drop-token-0123456789");
      await p.apply();
      const fake = await p.fake();
      assert.deepEqual(fake.lines.map((l) => l.split(" ")[0]), ["ESCAPE_INFO", "ESCAPE_WIFI", "ESCAPE_AUTH_TOKEN", "ESCAPE_INFO"]);
      assert.equal(fake.opens.length, 3, "connect + reopen after the Wi-Fi restart + reopen for the final check");
      assert.deepEqual(new Set(fake.opens), new Set([115200]));
      for (const step of await p.steps()) assert.match(step, /gespeichert, das Gerät startet neu/);
      assert.equal(await p.text("#v-ssid"), "Neues-Netz");
      assert.equal(await p.page.locator("#status").getAttribute("data-kind"), "info");
      check(p);
    } finally { await p.close(); }
  });

  test("the port never comes back after the restart: written steps stay 'gespeichert', the rest is reported as lost, no crash", async () => {
    const p = await open({ cfg: { restart: "drop", dropMs: 1e9 } }, { timings: { reopenMs: 700 } });
    try {
      await p.connect();
      await p.field("ssid").fill("Netz");
      await p.field("pass").fill("12345678");
      await p.field("token").fill("verloren-token-0123456789");
      await p.apply();
      const steps = await p.steps();
      assert.match(steps[0], /gespeichert/);
      assert.match(steps[1], /Verbindung zum Gerät verloren/);
      assert.match(await p.text("#status"), /nicht mehr erreichbar/);
      assert.equal(await p.button("Verbinden").isDisabled(), false);
      assert.equal(await p.disabled("#settings"), true);
      assert.equal(await p.field("token").inputValue(), "verloren-token-0123456789", "unsent token stays");
      assert.equal((await p.fake()).state.ssid, "Netz");
      check(p);
    } finally { await p.close(); }
    // a single write whose confirmation read-back fails is not a failure of the write
    const q = await open({ cfg: { restart: "drop", dropMs: 1e9 } }, { timings: { reopenMs: 700 } });
    try {
      await q.connect();
      await q.field("token").fill("einzeln-token-0123456789");
      await q.apply();
      assert.match((await q.steps())[0], /gespeichert/);
      assert.equal(await q.field("token").inputValue(), "");
      assert.match(await q.text("#status"), /nicht mehr erreichbar/);
      check(q);
    } finally { await q.close(); }
  });

  test("a board that never answers: re-sent every interval, then a timeout message", async () => {
    const p = await open({ cfg: { silent: ["ESCAPE_AUTH_TOKEN"] } }, { timings: { timeoutMs: 900 } });
    try {
      await p.connect();
      await p.field("token").fill("stumm-token-0123456789");
      await p.apply();
      assert.match((await p.steps())[0], /keine Antwort innerhalb von/);
      assert.ok((await p.fake()).lines.filter((l) => l.startsWith("ESCAPE_AUTH_TOKEN")).length >= 3);
      assert.equal(await p.field("token").inputValue(), "stumm-token-0123456789");
      assert.equal(await p.disabled("#settings"), false, "still connected, can try again");
      check(p);
    } finally { await p.close(); }
  });

  test("real timings are the firmware tool's: re-send every 1.5 s, give up after 35 s, 115200 baud", async () => {
    const p = await open({}, { timings: null });
    try {
      assert.deepEqual(await p.page.evaluate(() => ({ ...window.EscapeSetup.config })), { baud: 115200, resendMs: 1500, timeoutMs: 35000, restartMs: 2000, reopenMs: 20000 });
      check(p);
    } finally { await p.close(); }
  });

  test("Trennen releases the port; Verbinden works again; cancelling the port chooser and a busy port are explained", async () => {
    const p = await open();
    try {
      await p.connect();
      await p.field("token").fill("wird-nicht-gesendet-123");
      await p.button("Trennen").click();
      let fake = await p.fake();
      assert.equal(fake.closes, 1, "port closed (fake throws when a stream is still locked)");
      assert.equal(await p.text("#v-did"), "–");
      assert.equal(await p.button("Verbinden").isDisabled(), false);
      assert.equal(await p.disabled("#settings"), true);
      await p.connect();
      assert.equal((await p.fake()).opens.length, 2);
      await p.button("Trennen").click();
      await p.setCfg({ cancel: true });
      await p.button("Verbinden").click();
      await p.page.waitForFunction(() => /Kein Port ausgewählt/.test(document.getElementById("status").textContent));
      assert.equal(await p.page.locator("#status").getAttribute("data-kind"), "info");
      await p.setCfg({ cancel: false, openFails: true });
      await p.button("Verbinden").click();
      await p.page.waitForFunction(() => /lässt sich nicht öffnen/.test(document.getElementById("status").textContent));
      assert.equal(await p.button("Verbinden").isDisabled(), false);
      check(p);
    } finally { await p.close(); }
  });

  test("offline and self-contained: no network request, no external resource, no secret in any log", async () => {
    const html = fs.readFileSync(htmlPath, "utf8");
    assert.ok(html.split("\n").length < 600, "page stays small");
    assert.doesNotMatch(html, /<(script|link|img|iframe|source|audio|video)\b[^>]*\b(src|href)\s*=/i);
    assert.doesNotMatch(html, /@import|url\(|\bfetch\(|XMLHttpRequest|WebSocket|sendBeacon|localStorage|sessionStorage/);
    const p = await open();
    try {
      await p.connect();
      await p.field("ssid").fill("Log-Netz");
      await p.field("pass").fill("Log-Passwort-1");
      await p.field("token").fill("Log-Token-0123456789-x");
      await p.field("edit").fill("Log-Edit-0123456789-y");
      await p.field("reveal").check();
      assert.equal(await p.field("pass").getAttribute("type"), "text");
      await p.field("reveal").uncheck();
      assert.equal(await p.field("pass").getAttribute("type"), "password");
      await p.apply();
      const log = await p.text("#log");
      assert.ok(log.length > 50, "there is a log");
      for (const secret of ["Log-Passwort-1", "Log-Token-0123456789-x", "Log-Edit-0123456789-y"]) {
        assert.ok(!log.includes(secret) && !log.includes(b64(secret)), "secret in the log: " + secret);
      }
      assert.deepEqual(p.requests, [pathToFileURL(htmlPath).href]);
      check(p);
    } finally { await p.close(); }
  });

  test("accessibility: every control has a label, hints are linked, fields use no browser autofill", async () => {
    const p = await open();
    try {
      await p.connect();
      for (const name of Object.keys(L)) assert.equal(await p.field(name).count(), 1, "label " + name);
      const report = await p.page.evaluate(() => [...document.querySelectorAll("input")].map((input) => ({
        id: input.id, named: input.labels.length === 1, describedBy: (input.getAttribute("aria-describedby") || "").split(" ").filter(Boolean).every((id) => document.getElementById(id)),
        autofill: input.type === "checkbox" || ["off", "new-password"].includes(input.getAttribute("autocomplete")),
      })));
      for (const row of report) assert.deepEqual(row, { id: row.id, named: true, describedBy: true, autofill: true });
      assert.equal(await p.page.locator("html").getAttribute("lang"), "de");
      assert.equal(await p.page.locator("#form button[type=submit]").count(), 1);
      check(p);
    } finally { await p.close(); }
  });
});
