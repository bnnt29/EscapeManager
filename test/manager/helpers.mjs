// Shared helpers of the manager end-to-end tests: finds Chromium, builds/starts the C++
// simulator on loopback ports 9200-9299 (UDP discovery port 14220), runs scripts/em_client.mjs.
// Parallel runs (other agents) pick their own range: EM_TEST_PORT_BASE=9400 EM_TEST_UDP_PORT=14240,
// or per call via the startSim options portBase/udpPort.
import fs from "node:fs";
import os from "node:os";
import net from "node:net";
import path from "node:path";
import crypto from "node:crypto";
import { spawn, spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

export const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
// EM_TEST_HTML: serve another UI file (e.g. a variant with one fix reverted, to check that a test can fail)
export const managerHtml = process.env.EM_TEST_HTML ? path.resolve(process.env.EM_TEST_HTML) : path.join(root, "src/manager/manager.html");
export const simBinary = path.join(root, ".sim-build/escape_component_sim");
export const PORT_BASE = Number(process.env.EM_TEST_PORT_BASE) || 9200;
export const UDP_PORT = Number(process.env.EM_TEST_UDP_PORT) || 14220;

export function findChromium() {
  const cache = path.join(os.homedir(), ".cache", "ms-playwright");
  if (!fs.existsSync(cache)) return null;
  const candidates = [];
  for (const dir of fs.readdirSync(cache)) {
    if (/^chromium-\d+$/.test(dir)) candidates.push(path.join(cache, dir, "chrome-linux64", "chrome"), path.join(cache, dir, "chrome-linux", "chrome"));
    if (/^chromium_headless_shell-\d+$/.test(dir)) candidates.push(path.join(cache, dir, "chrome-headless-shell-linux64", "chrome-headless-shell"));
  }
  return candidates.find((file) => fs.existsSync(file)) || null;
}

export async function loadPlaywright() {
  try {
    return (await import("playwright-core")).chromium;
  } catch {
    return null;
  }
}

/** Builds the simulator once (see the task description); returns an error string or "". */
export function ensureSimulator() {
  const sources = ["src/sim/escape_component_sim.cpp", "src/sim/OpenSslCryptoBackend.cpp", "src/net/Device.cpp", "src/net/Net.cpp"]
    .map((file) => path.join(root, file));
  const protocolDir = path.join(root, "src/protocol");
  const protocol = fs.readdirSync(protocolDir).filter((f) => f.endsWith(".cpp")).map((f) => path.join(protocolDir, f));
  if (fs.existsSync(simBinary)) {
    const built = fs.statSync(simBinary).mtimeMs;
    const newest = Math.max(...[...sources, ...protocol].map((f) => fs.statSync(f).mtimeMs));
    if (built >= newest) return "";
  }
  fs.mkdirSync(path.dirname(simBinary), { recursive: true });
  const result = spawnSync("g++", ["-std=c++17", "-O1", "-pthread", "-o", simBinary, ...sources, ...protocol, "-lcrypto"], { cwd: root, encoding: "utf8" });
  if (result.error || result.status !== 0) return "simulator build failed: " + (result.error?.message || result.stderr.slice(-400));
  return "";
}

function portFree(port) {
  return new Promise((resolve) => {
    const server = net.createServer();
    server.once("error", () => resolve(false));
    server.listen(port, "0.0.0.0", () => server.close(() => resolve(true)));
  });
}

const taken = new Set();
export async function freePort(portBase = PORT_BASE) {
  for (let attempt = 0; attempt < 200; attempt++) {
    const port = portBase + Math.floor(Math.random() * 100);
    if (taken.has(port) || !(await portFree(port))) continue;
    taken.add(port);
    return port;
  }
  throw new Error(`no free port in ${portBase}-${portBase + 99}`);
}

export const randomTag = () => crypto.randomBytes(2).toString("hex");

const running = new Set();

/**
 * Starts one simulator on loopback; stop() ends exactly this process.
 * Optional: html (UI file to serve, default the repository's manager.html), binary (another
 * simulator build, e.g. one announcing a different UI version), portBase, udpPort, htmlState
 * (puzzle state is an HTML document), editToken (plan-edit token, PROTOCOL.md 3.1: --edit-token),
 * setup (--setup: POST /setup is accepted and the cap "setup" is advertised).
 * The child's environment blanks ESCAPE_AUTH_TOKEN / ESCAPE_EDIT_TOKEN, so a developer shell cannot
 * change the tokens a test expects.
 */
export async function startSim({ components, battery = 100, token = "", totalSteps = 5, html = managerHtml, binary = simBinary, portBase = PORT_BASE, udpPort = UDP_PORT, htmlState = false, editToken = "", setup = false }) {
  for (let attempt = 0; attempt < 5; attempt++) {
    const port = await freePort(portBase);
    const did = "7e57" + crypto.randomBytes(4).toString("hex");
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "em-e2e-"));
    const args = ["--ip", "127.0.0.1", "--no-mdns", "--udp-port", String(udpPort), "--manager-html", html,
      "--http-port", String(port), "--did", did, "--state-dir", stateDir, "--battery", String(battery), "--total-steps", String(totalSteps)];
    if (token) args.push("--token", token);
    if (editToken) args.push("--edit-token", editToken);
    if (setup) args.push("--setup");
    if (htmlState) args.push("--html-state");
    for (const spec of components) args.push("--component", spec);
    const proc = spawn(binary, args, { cwd: root, stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, ESCAPE_AUTH_TOKEN: "", ESCAPE_EDIT_TOKEN: "" } });
    let log = "";
    proc.stdout.on("data", (d) => { log += d; });
    proc.stderr.on("data", (d) => { log += d; });
    const exited = new Promise((resolve) => proc.once("exit", (code, signal) => resolve({ code, signal })));
    const sim = {
      port, did, proc, base: `http://127.0.0.1:${port}`, hostPort: `127.0.0.1:${port}`, stateDir,
      get log() { return log; },
      async stop() {
        if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGTERM");
        await Promise.race([exited, new Promise((resolve) => setTimeout(resolve, 3000))]);
        if (proc.exitCode === null && proc.signalCode === null) proc.kill("SIGKILL");
        running.delete(sim);
        fs.rmSync(stateDir, { recursive: true, force: true });
      },
    };
    running.add(sim);
    const deadline = Date.now() + 6000;
    let up = false;
    while (Date.now() < deadline && proc.exitCode === null) {
      try {
        const res = await fetch(sim.base + "/security.json", { signal: AbortSignal.timeout(500) });
        if (res.ok) { up = true; break; }
      } catch { /* not listening yet */ }
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    if (up) return sim;
    await sim.stop(); // e.g. "cannot listen" because another agent took the port meanwhile
  }
  throw new Error("could not start a simulator");
}

export async function stopAllSims() {
  for (const sim of [...running]) await sim.stop();
}

// Never leave simulators behind, even when the test run is interrupted (only OUR child processes).
function killOurSims() {
  for (const sim of running) {
    try { sim.proc.kill("SIGKILL"); } catch { /* already gone */ }
  }
}
process.on("exit", killOurSims);
for (const signal of ["SIGINT", "SIGTERM", "SIGHUP"]) {
  process.on(signal, () => { killOurSims(); process.exit(1); });
}

/** Runs scripts/em_client.mjs against a device (default token unless given). Returns parsed JSON. */
export function emClient(hostPort, args, { token } = {}) {
  const full = [path.join(root, "scripts/em_client.mjs"), hostPort, ...(token ? ["--token", token] : []), ...args];
  const result = spawnSync("node", full, { encoding: "utf8", timeout: 20000 });
  if (result.status !== 0) throw new Error(`em_client ${args.join(" ")} failed: ${result.stderr || result.stdout}`);
  return JSON.parse(result.stdout);
}

export const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
