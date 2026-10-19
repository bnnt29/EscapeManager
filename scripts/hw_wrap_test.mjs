#!/usr/bin/env node
// Exercises the 32-bit millisecond clock wrap (49.7 days) on two REAL devices within a minute.
//
//   pio run -e esp-dummy-wrap -t upload --upload-port <portA>      (clock starts 65 s before the wrap)
//   pio run -e esp-dummy-wrap -t upload --upload-port <portB>
//   node scripts/hw_wrap_test.mjs <ipA> <ipB>                       (start right after both boards are up)
//
// Checks writes before/after the wrap, a replay that straddles it, request timestamps that have already
// wrapped, an idle connection spanning it, peer liveness, and skeleton sync afterwards. Found a real bug
// (deadlines initialised to 0 and compared as signed differences) that the PC tests had missed.
import net from "node:net";
import crypto from "node:crypto";
import { Device } from "./em_client.mjs";
const [ipA, ipB] = process.argv.slice(2);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const ok = (n, c, d = "") => console.log((c ? "PASS " : "FAIL ") + n + (d ? "  -- " + d : ""));
const b64u = (b) => Buffer.from(b).toString("base64url");
async function up(dev) { return (await dev.get("/status.json")).doc.up; }
const A = new Device(ipA), B = new Device(ipB); await A.init(); await B.init();
let a0 = await up(A);
console.log("device clock of A at start:", a0.toString(16).padStart(8, "0"), "(0xFFFF0000 + uptime => wraps in", ((0x100000000 - a0) / 1000).toFixed(1), "s)");
if (a0 < 0xFFF00000) { console.log("clock is not in the pre-wrap range: flash with -DESCAPE_CLOCK_OFFSET_MS=0xFFFF0000UL and run right after boot"); process.exit(2); }
const seal = (dev, path, body, t) => { const iv = crypto.randomBytes(12); const c = crypto.createCipheriv("aes-256-gcm", dev.keys.req, iv); c.setAAD(Buffer.from(`EM2|req|${dev.security.did}|${path}|${t}`)); const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body))), c.final(), c.getAuthTag()]); return JSON.stringify({ v: 2, t, iv: b64u(iv), ct: b64u(ct) }); };
const send = async (dev, ip, path, env) => { const r = await fetch(`http://${ip}${path}`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: env }); let code = "?"; try { const j = JSON.parse(await r.text()); if (j.ct) { const raw = Buffer.from(j.ct, "base64url"); const d = crypto.createDecipheriv("aes-256-gcm", dev.keys.resp, Buffer.from(j.iv, "base64url")); d.setAAD(Buffer.from(`EM2|resp|${dev.security.did}|${path}|${JSON.parse(env).iv}|${r.status}`)); d.setAuthTag(raw.subarray(raw.length - 16)); code = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString()).code || "ok"; } else code = j.code || "?"; } catch { /* ignore */ } return { status: r.status, code }; };

// wait until ~6 s before the wrap, then prepare the cross-wrap tests
let now;
while (true) { now = await up(A); if (now > 0xFFFFFFFF - 7000 && now < 0xFFFFFFFF - 5500) break; if (now < 0x80000000) { console.log("already wrapped"); process.exit(2); } await sleep(300); }
console.log("6 s before the wrap, A clock =", now.toString(16));
// 1. an idle connection that spans the wrap must still be dropped by the idle timeout
const idle = net.connect({ host: ipA, port: 80 }); idle.on("error", () => {}); let idleClosedAt = null; const idleStart = Date.now(); idle.on("close", () => { idleClosedAt = Date.now() - idleStart; });
// 2. replay accepted before the wrap and replayed after it
const envBefore = seal(A, "/action", { id: 0, action: "next_step" }, A.deviceTime());
const r1 = await send(A, ipA, "/action", envBefore);
ok("POST just before the wrap accepted", r1.status === 200, JSON.stringify(r1));
// 3. a request stamped 4 s into the future whose timestamp is already past the wrap (small number) while the device clock is not
const t4 = (A.deviceTime() + 4000) >>> 0;
const r2 = await send(A, ipA, "/action", seal(A, "/action", { id: 0, action: "next_step" }, t4));
ok("timestamp that has wrapped while the device clock has not yet: accepted", r2.status === 200 || (t4 > 0x80000000), `t=${t4.toString(16)} -> ${JSON.stringify(r2)}`);
const t4b = (A.deviceTime() + 8000) >>> 0;
console.log("   (request stamped 8 s ahead:", t4b.toString(16) + ")");
const r2b = await send(A, ipA, "/action", seal(A, "/action", { id: 0, action: "next_step" }, t4b));
ok("request stamped 8 s ahead (crosses the wrap) accepted", r2b.status === 200, JSON.stringify(r2b));
// wait for the wrap
while (await up(A) > 0x80000000) await sleep(250);
const nowAfter = await up(A);
ok("the device clock wrapped", nowAfter < 0x10000, `clock now ${nowAfter} ms`);
const r3 = await send(A, ipA, "/action", envBefore);
ok("replay of the pre-wrap envelope AFTER the wrap rejected as replay (not as stale)", r3.status === 409 && r3.code === "replay", JSON.stringify(r3));
await sleep(16000);
const r4 = await send(A, ipA, "/action", envBefore);
ok("replay 17 s later is stale_time", r4.status === 409 && r4.code === "stale_time", JSON.stringify(r4));
ok("idle connection spanning the wrap was dropped by the device", idleClosedAt !== null && idleClosedAt < 12000, idleClosedAt === null ? "still open" : idleClosedAt + " ms");
// 4. normal operation after the wrap
const w = await A.post("/action", { id: 0, action: "next_step" });
ok("normal write after the wrap", w.status === 200, JSON.stringify(w.body));
const peersA = (await A.get("/peers.json")).doc; const pb = peersA.peers.find((p) => p.did === B.security.did);
ok("A still sees B as a live peer after the wrap", !!pb && pb.age < 10000, pb ? `age ${pb.age} ms` : "missing");
const upB = await up(B); console.log("   B clock:", upB.toString(16), "(B wraps at its own moment)");
// 5. skeleton write + sync after the wrap (peer table, backoff and announcements all use the wrapped clock)
const room = (await A.get("/status.json")).doc.components[0].room;
const idx = (await A.get("/plan-skeleton.json")).doc.rooms.find((r) => r.room === room);
const wr = await A.post("/plan-skeleton", { room, baseRev: idx ? idx.rev : 0, sk: { planId: "after-wrap", n: Date.now() } });
ok("skeleton write after the wrap", wr.status === 200, JSON.stringify(wr.body));
let synced = false; const t0 = Date.now();
while (Date.now() - t0 < 40000 && !synced) { await sleep(1500); const bi = (await B.get("/plan-skeleton.json")).doc; synced = bi.rooms.some((r) => r.room === room && r.rev === wr.body.rev && r.hash === wr.body.hash); }
ok("skeleton synced A -> B across the wrap", synced, `${Date.now() - t0} ms`);
// 6. keep going until B has wrapped too, with traffic on both
const endB = Date.now() + 70000; let bWrapped = false, errs = 0, prev = await up(B);
while (Date.now() < endB) { try { const u = await up(B); if (u < prev && prev > 0x80000000) bWrapped = true; prev = u; await A.get("/status.json"); } catch { errs++; } await sleep(700); }
ok("B wrapped as well and kept answering", bWrapped && errs === 0, `bWrapped=${bWrapped}, errors=${errs}`);
const pa = (await B.get("/peers.json")).doc.peers.find((p) => p.did === A.security.did);
ok("B still sees A after both wrapped", !!pa && pa.age < 10000, pa ? `age ${pa.age} ms` : "missing");
idle.destroy();
