#!/usr/bin/env node
// Black-box smoke test of one or two EscapeManager devices (real ESP32 boards OR the
// simulators). Needs only Node >= 18. Usage is printed in the comment block below and with --help.
//
//   node scripts/hw_smoke.mjs <hostA[:port]> [<hostB[:port]>] [--token T] [--edit-token E] [--mdns] [--soak MINUTES] [--no-hostile]
//
// Tokens default to the [secrets] section of the untracked secrets.ini (auth_token, edit_token).
//
// With two devices in the SAME room it also checks discovery and skeleton sync between
// them. --mdns additionally resolves escapemanager.local with the OS resolver and lists
// every address it returns (shared mDNS record). --soak keeps polling for N minutes and
// reports latency drift and whether the uptime ever went backwards (reboot).
// Hostile-input checks are on by default (they must never reboot the device); skip them
// with --no-hostile.
import net from "node:net";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { Device, SECRET_TOKEN, SECRET_EDIT_TOKEN } from "./em_client.mjs";

const args = process.argv.slice(2);
const flag = (name) => { const i = args.indexOf(name); if (i < 0) return false; args.splice(i, 1); return true; };
const opt = (name) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const token = opt("--token") ?? SECRET_TOKEN;  // default: [secrets] auth_token of secrets.ini, else the public default
const editToken = opt("--edit-token") ?? SECRET_EDIT_TOKEN;
const soakMinutes = Number(opt("--soak") ?? 0);
const wantMdns = flag("--mdns");
const hostile = !flag("--no-hostile");
const hosts = args;
if (!hosts.length) { console.error("usage: hw_smoke.mjs <host[:port]> [<host[:port]>] [--token T] [--mdns] [--soak MIN] [--no-hostile]"); process.exit(2); }

let failures = 0;
const results = [];
function check(name, ok, detail = "") {
  results.push({ name, ok, detail });
  if (!ok) failures++;
  console.log(`${ok ? "PASS" : "FAIL"}  ${name}${detail ? "  -- " + detail : ""}`);
  return ok;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const splitHost = (h) => { const [host, port] = h.replace(/^https?:\/\//, "").split(":"); return { host, port: Number(port || 80) }; };

/** Raw HTTP exchange; resolves with {status, headers, body(Buffer), raw} or {error}. */
function rawRequest(target, bytes, { readMs = 4000, end = false } = {}) {
  const { host, port } = splitHost(target);
  return new Promise((resolve) => {
    const chunks = [];
    const s = net.connect({ host, port });
    let done = false;
    const finish = (extra = {}) => {
      if (done) return; done = true; s.destroy();
      const raw = Buffer.concat(chunks);
      const i = raw.indexOf("\r\n\r\n");
      const head = i >= 0 ? raw.subarray(0, i).toString("latin1") : raw.toString("latin1");
      const status = Number((head.match(/^HTTP\/1\.[01] (\d+)/) || [])[1] || 0);
      resolve({ status, head, body: i >= 0 ? raw.subarray(i + 4) : Buffer.alloc(0), raw, ...extra });
    };
    s.setTimeout(readMs, () => finish({ timeout: true }));
    s.on("data", (d) => chunks.push(d));
    s.on("close", () => finish({ closed: true }));
    s.on("error", (e) => finish({ error: e.code || e.message }));
    s.on("connect", () => { try { if (bytes) s.write(bytes); if (end) s.end(); } catch { /* ignore */ } });
  });
}

async function uptime(dev) { return (await dev.get("/status.json")).doc.up; }

async function perDevice(label, target, other) {
  console.log(`\n== ${label}: ${target}`);
  const dev = new Device(target, token, editToken);
  let sec;
  try { sec = await dev.init(); } catch (e) { check(`${label}: reachable`, false, e.message); return null; }
  check(`${label}: reachable, proto 2`, sec.proto === 2 && sec.pmin <= 2, JSON.stringify({ proto: sec.proto, pmin: sec.pmin, fw: sec.fw }));
  check(`${label}: token state shown`, ["default", "custom", "invalid"].includes(sec.token), sec.token);
  check(`${label}: security limits published`, sec.limits && sec.limits.body === 12288 && sec.limits.skeleton === 6144);

  const t0 = Date.now();
  let status;
  try { status = (await dev.get("/status.json")).doc; } catch (e) { check(`${label}: authenticated status`, false, e.message); return dev; }
  check(`${label}: authenticated status (MAC verified)`, status.did === sec.did && Array.isArray(status.components) && status.components.length > 0, `${Date.now() - t0} ms, ${status.components.length} component(s)`);
  check(`${label}: no battery field is never 0`, status.battery === undefined || status.battery > 0, String(status.battery));
  check(`${label}: uih matches security.json`, status.uih === sec.uih);

  // UI delivery + ETag
  const ui = await fetch(dev.base + "/", { cache: "no-store" });
  const html = Buffer.from(await ui.arrayBuffer());
  const hash = crypto.createHash("sha256").update(html).digest("hex").slice(0, 8);
  check(`${label}: UI served and hash matches uih`, ui.status === 200 && hash === sec.uih, `${html.length} bytes decoded, hash ${hash} vs ${sec.uih}`);
  const etag = ui.headers.get("etag");
  const cond = await rawRequest(target, `GET / HTTP/1.1\r\nHost: x\r\nIf-None-Match: ${etag}\r\n\r\n`);
  check(`${label}: conditional UI request -> 304`, cond.status === 304, `status ${cond.status}, etag ${etag}`);

  // write path: pick an action
  const comp = status.components[0];
  const action = (comp.actions || []).includes("next_step") ? "next_step" : (comp.actions || [])[0];
  if (action) {
    const before = (await dev.get("/status.json")).doc.seq;
    const r = await dev.post("/action", { id: 0, action });
    check(`${label}: secure POST /action`, r.status === 200 && r.authenticated, JSON.stringify(r.body));
    const after = (await dev.get("/status.json")).doc.seq;
    check(`${label}: seq increased after the write`, after > before, `${before} -> ${after}`);
  } else {
    console.log(`SKIP  ${label}: no actions announced`);
  }

  // wrong token
  const bad = new Device(target, "this-is-not-the-venue-token");
  await bad.init();
  let rejected = false;
  try { await bad.get("/status.json"); } catch { rejected = true; }
  check(`${label}: wrong token cannot verify reads`, rejected);
  let wrongPost = null;
  try { wrongPost = await bad.post("/action", { id: 0, action: action || "x" }); } catch (e) { wrongPost = { status: 0, error: e.message }; }
  check(`${label}: wrong token cannot write`, wrongPost.status === 401 || wrongPost.status === 0, JSON.stringify(wrongPost.status));

  // stale / replayed request
  const stale = await dev.post("/action", { id: 0, action: action || "x" }, { t: (dev.deviceTime() + 120000) >>> 0, retryStale: false });
  check(`${label}: stale timestamp -> authenticated 409`, stale.status === 409 && stale.body.code === "stale_time", JSON.stringify(stale.body));

  // unknown routes and methods
  check(`${label}: unknown path -> 404`, (await rawRequest(target, "GET /nope HTTP/1.1\r\n\r\n")).status === 404);
  check(`${label}: bad method -> 405`, (await rawRequest(target, "BREW / HTTP/1.1\r\n\r\n")).status === 405);

  // latency
  const times = [];
  for (let i = 0; i < 20; i++) { const s = Date.now(); await dev.get("/status.json"); times.push(Date.now() - s); }
  times.sort((a, b) => a - b);
  const median = times[10], p95 = times[18];
  check(`${label}: authenticated status latency`, median < 400, `median ${median} ms, p95 ${p95} ms`);

  if (hostile) await hostileChecks(label, target, dev);
  return dev;
}

async function hostileChecks(label, target, dev) {
  console.log(`-- ${label}: hostile input (the device must neither reboot nor stall)`);
  const up0 = await uptime(dev);
  const post = (len, body) => `POST /action HTTP/1.1\r\nContent-Length: ${len}\r\n\r\n${body}`;
  const flood = "[" + "0,".repeat(5999) + "0]";
  let r = await rawRequest(target, post(flood.length, flood));
  check(`${label}: 12 KB JSON array flood rejected`, r.status === 400 || r.status === 401, `status ${r.status}`);
  const big = "x".repeat(12 * 1024 + 1);
  r = await rawRequest(target, post(big.length, big));
  check(`${label}: body over the limit -> 413 before buffering`, r.status === 413, `status ${r.status}`);
  r = await rawRequest(target, `POST /action HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n`);
  check(`${label}: 10 MB announced -> 413`, r.status === 413, `status ${r.status}`);
  r = await rawRequest(target, post(5000, "[".repeat(5000)));
  check(`${label}: deep nesting rejected`, r.status === 400 || r.status === 401, `status ${r.status}`);
  r = await rawRequest(target, post(3000, crypto.randomBytes(3000).toString("latin1")));
  check(`${label}: binary garbage rejected`, r.status === 400 || r.status === 401, `status ${r.status}`);
  r = await rawRequest(target, `GET /${"a".repeat(900)} HTTP/1.1\r\n\r\n`);
  check(`${label}: oversized header/URL rejected`, [400, 414, 431].includes(r.status), `status ${r.status}`);
  r = await rawRequest(target, "POST /action HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
  check(`${label}: chunked requests refused`, r.status === 501, `status ${r.status}`);

  // idle (speculative) connections must not block real requests
  const { host, port } = splitHost(target);
  const idle = [net.connect({ host, port }), net.connect({ host, port }), net.connect({ host, port })];
  idle.forEach((s) => s.on("error", () => {}));
  await sleep(300);
  const s0 = Date.now();
  let ok = false;
  try { await dev.get("/status.json"); ok = true; } catch { ok = false; }
  check(`${label}: real request served with 3 idle connections open`, ok, `${Date.now() - s0} ms`);
  idle.forEach((s) => s.destroy());

  // slowloris: trickle one byte per second; the server must drop it by itself
  const slow = net.connect({ host, port });
  slow.on("error", () => {});
  let dropped = false;
  slow.on("close", () => { dropped = true; });
  const start = Date.now();
  while (!dropped && Date.now() - start < 15000) { try { slow.write("G"); } catch { /* ignore */ } await sleep(1000); }
  check(`${label}: slow client dropped by the device`, dropped, `${Date.now() - start} ms`);
  slow.destroy();

  await sleep(500);
  const up1 = await uptime(dev);
  check(`${label}: no reboot during hostile input`, up1 > up0, `uptime ${up0} -> ${up1} ms`);
}

async function pair(a, b, devA, devB) {
  console.log(`\n== pair: ${a} <-> ${b}`);
  const peersA = (await devA.get("/peers.json")).doc;
  const peersB = (await devB.get("/peers.json")).doc;
  const hasB = (peersA.peers || []).some((p) => p.did === devB.security.did);
  const hasA = (peersB.peers || []).some((p) => p.did === devA.security.did);
  check("pair: A discovered B", hasB, `${(peersA.peers || []).length} peer(s)`);
  check("pair: B discovered A", hasA, `${(peersB.peers || []).length} peer(s)`);
  const statusA = (await devA.get("/status.json")).doc, statusB = (await devB.get("/status.json")).doc;
  const roomsA = new Set(statusA.components.map((c) => c.room)), room = statusB.components.map((c) => c.room).find((r) => roomsA.has(r));
  if (!room) { console.log("SKIP  pair: devices share no room, skeleton sync not tested"); return; }
  const sk = { planId: "smoke-" + Date.now(), layers: [], note: "hw_smoke" };
  const idx = (await devA.get("/plan-skeleton.json")).doc;
  const cur = (idx.rooms || []).find((x) => x.room === room);
  const w = await devA.post("/plan-skeleton", { room, baseRev: cur ? cur.rev : 0, sk }, { edit: devA.security.edit === "custom" });
  check("pair: skeleton write on A accepted", w.status === 200 && w.body.rev >= 1, JSON.stringify(w.body));
  let synced = false; const t0 = Date.now();
  while (Date.now() - t0 < 30000 && !synced) {
    await sleep(1500);
    const bi = (await devB.get("/plan-skeleton.json")).doc;
    synced = (bi.rooms || []).some((x) => x.room === room && x.rev === w.body.rev && x.hash === w.body.hash);
  }
  check("pair: skeleton synced A -> B (same rev and hash)", synced, `${Date.now() - t0} ms`);
  const blobA = (await devA.get("/plan-skeleton.json", "room=" + encodeURIComponent(room))).doc;
  const blobB = (await devB.get("/plan-skeleton.json", "room=" + encodeURIComponent(room))).doc;
  check("pair: stored blobs are identical", JSON.stringify(blobA) === JSON.stringify(blobB));
  const conflict = await devB.post("/plan-skeleton", { room, baseRev: Math.max(0, w.body.rev - 1), sk: { planId: "stale-writer" } }, { edit: devB.security.edit === "custom" });
  check("pair: stale writer gets rev_conflict", conflict.status === 409 && conflict.body.code === "rev_conflict", JSON.stringify(conflict.body));
}

function mdnsCheck() {
  console.log("\n== mDNS (shared record escapemanager.local)");
  let out = "";
  try { out = execFileSync("getent", ["ahostsv4", "escapemanager.local"], { encoding: "utf8", timeout: 8000 }); } catch (e) { out = ""; }
  const addrs = [...new Set(out.split("\n").map((l) => l.trim().split(/\s+/)[0]).filter((a) => /^\d+\.\d+\.\d+\.\d+$/.test(a)))];
  check("mDNS: escapemanager.local resolves", addrs.length > 0, addrs.join(", ") || "no answer (is avahi/nss-mdns installed?)");
  let avahi = "";
  try { avahi = execFileSync("avahi-resolve", ["-4", "-n", "escapemanager.local"], { encoding: "utf8", timeout: 8000 }).trim(); } catch { /* avahi-utils missing */ }
  if (avahi) console.log("INFO  avahi-resolve: " + avahi.replace(/\s+/g, " "));
  console.log("INFO  A shared record may return several addresses (one per device); resolvers often return only the first.");
}

async function soak(devs) {
  console.log(`\n== soak ${soakMinutes} min`);
  const end = Date.now() + soakMinutes * 60000;
  const last = devs.map(() => 0);
  const lat = devs.map(() => []);
  let reboots = 0, errors = 0;
  while (Date.now() < end) {
    for (let i = 0; i < devs.length; i++) {
      const s = Date.now();
      try {
        const up = (await devs[i].get("/status.json")).doc.up;
        lat[i].push(Date.now() - s);
        if (up < last[i]) reboots++;
        last[i] = up;
      } catch { errors++; }
    }
    await sleep(2000);
  }
  for (let i = 0; i < devs.length; i++) {
    const a = lat[i].slice(0, Math.max(1, lat[i].length >> 2)), b = lat[i].slice(-Math.max(1, lat[i].length >> 2));
    const avg = (x) => Math.round(x.reduce((p, c) => p + c, 0) / x.length);
    check(`soak: device ${i + 1} latency stable`, avg(b) < avg(a) * 3 + 50, `first quarter ${avg(a)} ms, last quarter ${avg(b)} ms, n=${lat[i].length}`);
  }
  check("soak: no reboots", reboots === 0, `${reboots}`);
  check("soak: no failed reads", errors === 0, `${errors}`);
}

const devs = [];
for (let i = 0; i < hosts.length; i++) devs.push(await perDevice(`device ${i + 1}`, hosts[i], hosts[1 - i]));
if (devs.length >= 2 && devs[0] && devs[1]) { await sleep(2000); await pair(hosts[0], hosts[1], devs[0], devs[1]); }
if (wantMdns) mdnsCheck();
if (soakMinutes > 0) await soak(devs.filter(Boolean));

console.log(`\n${results.length - failures}/${results.length} checks passed${failures ? `, ${failures} FAILED` : ""}`);
process.exit(failures ? 1 : 0);
