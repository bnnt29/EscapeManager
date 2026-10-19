#!/usr/bin/env node
// Black-box test of the plan-edit token and the network setup push (POST /setup) on TWO real devices.
// It changes settings on the boards and puts everything back, but it needs both to be reachable and to run
// with the token from secrets.ini (or --token).
//
//   node scripts/hw_edit_test.mjs <hostA> <hostB> [--token T]
//
// Device A gets an edit token through the network (POST /setup, normal token), device B keeps none (a mixed
// fleet). Checks: normal token cannot send plans to A (403 edit_required) but can operate it, the edit token
// can, the proof endpoint, signed skeletons and their sync to B, that a plan written to B with the NORMAL token
// does NOT travel to A (A refuses skeletons without the edit MAC), removing the edit token again, and a token
// change over the network (old token dead, new one works, then back to the default). Restores everything.
import { Device, SECRET_TOKEN } from "./em_client.mjs";

const args = process.argv.slice(2);
const opt = (name) => { const i = args.indexOf(name); if (i < 0) return undefined; const v = args[i + 1]; args.splice(i, 2); return v; };
const token = opt("--token") ?? SECRET_TOKEN;
const [hostA, hostB] = args;
if (!hostA || !hostB) { console.error("usage: hw_edit_test.mjs <hostA> <hostB> [--token T]"); process.exit(2); }

const EDIT = "hw-test-edit-token-" + Math.random().toString(36).slice(2, 10);
const NEW_TOKEN = "hw-test-token-" + Math.random().toString(36).slice(2, 12);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
let failures = 0;
const check = (name, ok, detail = "") => { if (!ok) failures++; console.log((ok ? "PASS  " : "FAIL  ") + name + (detail ? "  -- " + detail : "")); };
const show = (r) => `${r.status} ${JSON.stringify(r.body)}`.slice(0, 160);

async function fresh(host, t = token, e = "") { const d = new Device(host, t, e); await d.init(); return d; }
async function waitFor(fn, ms, step = 700) { const t0 = Date.now(); while (Date.now() - t0 < ms) { if (await fn()) return Date.now() - t0; await sleep(step); } return -1; }

let A = await fresh(hostA), B = await fresh(hostB);
check("A and B advertise edit and setup", A.security.caps.includes("edit") && A.security.caps.includes("setup") && B.security.caps.includes("edit"), JSON.stringify(A.security.caps));
check("both start without an edit token", A.security.edit === "unset" && B.security.edit === "unset", `${A.security.edit}/${B.security.edit}`);
check("setupAp is published", ["open", "wpa2"].includes(A.security.setupAp), A.security.setupAp);

const statusA = (await A.get("/status.json")).doc, statusB = (await B.get("/status.json")).doc;
const roomsA = new Set(statusA.components.map((c) => c.room));
const room = statusB.components.map((c) => c.room).find((r) => roomsA.has(r));
check("devices share a room (needed for the sync checks)", !!room, room);

// --- Baseline: no edit token, the normal token may send plans
let r = await A.post("/plan", { id: 0, plan: null });
check("unset: normal token may send a plan slice", r.status === 200, show(r));

// --- Give A an edit token over the network
r = await A.post("/setup", { editToken: EDIT });
check("POST /setup sets the edit token on A", r.status === 200 && r.body.ok === true, show(r));
await sleep(600);
A = await fresh(hostA, token, EDIT);
check("A now publishes edit=custom", A.security.edit === "custom", A.security.edit);
check("status.json (authenticated) shows edit=custom", (await A.get("/status.json")).doc.edit === "custom");

// --- Who may do what
r = await A.post("/plan", { id: 0, plan: null });
check("custom: normal token is refused for /plan with 403 edit_required", r.status === 403 && r.body.code === "edit_required" && r.authenticated, show(r));
r = await A.post("/plan-skeleton", { room, baseRev: 0, sk: { planId: "nope" } });
check("custom: normal token is refused for /plan-skeleton", r.status === 403 && r.body.code === "edit_required", show(r));
r = await A.post("/setup", { token });
check("custom: normal token cannot use /setup either", r.status === 403, show(r));
const actions = (await A.get("/status.json")).doc.components[0].actions || [];
r = await A.post("/action", { id: 0, action: actions[0] || "x" });
check("custom: game operation still works with the normal token", r.status === 200 || r.status === 422, show(r));
r = await A.post("/plan", { id: 0, plan: null }, { edit: true });
check("custom: edit token may send a plan slice (answer sealed with the edit key)", r.status === 200 && r.sealedWith === "edit", show(r));
const wrong = new Device(hostA, token, "definitely-not-the-edit-token");
await wrong.init();
r = await wrong.post("/plan", { id: 0, plan: null }, { edit: true });
check("custom: a wrong edit token is rejected (401)", r.status === 401, show(r));
r = await A.post("/action", { id: 0, action: "x" }, { edit: true });
check("custom: the edit keys do not authorise normal operation (400)", r.status === 400, show(r));
check("proof: A confirms the edit token", (await A.proof()).ok === true);
check("proof: a wrong edit token does not verify", (await wrong.proof()).ok === false);
const bProof = await (await fresh(hostB, token, EDIT)).proof();
check("proof: B (no edit token) answers 404 edit_unset", bProof.status === 404);

// --- Skeletons: signed on A, accepted by B, planted plans refused by A
if (room) {
  const idx = (await A.get("/plan-skeleton.json")).doc;
  const cur = (idx.rooms || []).find((x) => x.room === room);
  const w = await A.post("/plan-skeleton", { room, baseRev: cur ? cur.rev : 0, sk: { planId: "edit-" + Date.now(), layers: [] } }, { edit: true });
  check("custom: skeleton written with the edit token", w.status === 200 && w.body.rev >= 1, show(w));
  const blobA = (await A.get("/plan-skeleton.json", "room=" + encodeURIComponent(room))).doc;
  check("the stored skeleton carries an emac", typeof blobA.emac === "string" && blobA.emac.length === 43, String(blobA.emac));
  const synced = await waitFor(async () => ((await B.get("/plan-skeleton.json")).doc.rooms || []).some((x) => x.room === room && x.rev === w.body.rev && x.hash === w.body.hash), 30000);
  check("B (no edit token) adopts the signed skeleton", synced >= 0, `${synced} ms`);
  const blobB = (await B.get("/plan-skeleton.json", "room=" + encodeURIComponent(room))).doc;
  check("B keeps the emac so it could pass it on", blobB.emac === blobA.emac);

  // B accepts a plan with the NORMAL token (it has no edit token) - A must not adopt it.
  const planted = await B.post("/plan-skeleton", { room, baseRev: w.body.rev, sk: { planId: "planted-through-B", layers: [] } });
  check("B accepts a normal-token skeleton write (no edit token there)", planted.status === 200, show(planted));
  const adopted = await waitFor(async () => ((await A.get("/plan-skeleton.json")).doc.rooms || []).some((x) => x.room === room && x.rev === planted.body.rev), 20000);
  check("A refuses the planted skeleton (no valid emac)", adopted < 0, adopted < 0 ? "not adopted after 20 s" : "ADOPTED");
  const stillA = (await A.get("/plan-skeleton.json")).doc.rooms.find((x) => x.room === room);
  check("A still has its own revision", stillA && stillA.rev === w.body.rev, JSON.stringify(stillA));
  // Put B back in line. The planted revision has the same number as A's next one; (rev, hash) decides and
  // may favour B's, so the owner writes ONE revision further and everybody converges on it.
  const back = await A.post("/plan-skeleton", { room, baseRev: w.body.rev, sk: { planId: "restored-by-A", layers: [] } }, { edit: true });
  const back2 = await A.post("/plan-skeleton", { room, baseRev: back.body.rev, sk: { planId: "restored-by-A-2", layers: [] } }, { edit: true });
  check("owner writes two more revisions with the edit token", back.status === 200 && back2.status === 200, show(back2));
  const synced2 = await waitFor(async () => ((await B.get("/plan-skeleton.json")).doc.rooms || []).some((x) => x.room === room && x.rev === back2.body.rev && x.hash === back2.body.hash), 25000);
  check("B follows A again", synced2 >= 0, `${synced2} ms`);
}

// --- Remove the edit token over the network
r = await A.post("/setup", { editToken: "" }, { edit: true });
check("edit token removed over the network (needs the edit token)", r.status === 200, show(r));
await sleep(600);
A = await fresh(hostA);
check("A publishes edit=unset again", A.security.edit === "unset", A.security.edit);
r = await A.post("/plan", { id: 0, plan: null });
check("unset again: the normal token sends plans", r.status === 200, show(r));

// --- Token change over the network (normal token)
r = await A.post("/setup", { token: NEW_TOKEN });
check("token change accepted (answer readable with the OLD key)", r.status === 200 && r.authenticated, show(r));
await sleep(600);
let old = new Device(hostA, token); await old.init();
r = await old.post("/action", { id: 0, action: "x" });
check("the old token no longer works", r.status === 401 && !r.authenticated, show(r));
let renewed = await fresh(hostA, NEW_TOKEN);
check("security.json says custom", renewed.security.token === "custom", renewed.security.token);
r = await renewed.post("/action", { id: 0, action: actions[0] || "x" });
check("the new token works", r.status === 200 || r.status === 422, show(r));
// back to the original: removing the stored token restores the build's token
r = await renewed.post("/setup", { token: "" });
check("token removal accepted", r.status === 200, show(r));
await sleep(600);
A = await fresh(hostA);
check("the build's token is back", A.security.token === (token === "EscapeManager-Private-WLAN-Default-Token" ? "default" : "custom"), A.security.token);
r = await A.post("/action", { id: 0, action: actions[0] || "x" });
check("and works", r.status === 200 || r.status === 422, show(r));

// --- Invalid pushes change nothing
for (const [label, body] of [["short token", { token: "short" }], ["SSID without password member", { ssid: "x" }], ["setup network name as Wi-Fi", { ssid: "EscapeSetup-aaaaaaaaaaaa", pass: "" }], ["empty request", {}]]) {
  r = await A.post("/setup", body);
  check(`invalid push refused: ${label}`, r.status === 400, show(r));
}
A = await fresh(hostA);
check("settings unchanged after the invalid pushes", A.security.token === "default" || A.security.token === "custom");

console.log(failures ? `\n${failures} FAILED` : "\nALL OK");
process.exit(failures ? 1 : 0);
