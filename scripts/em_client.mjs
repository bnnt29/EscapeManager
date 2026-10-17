#!/usr/bin/env node
// Reference proto-2 client for tools and integration tests (Node >= 18, no dependencies).
//
//   node scripts/em_client.mjs <host[:port]> [--token T] security|status|peers|skeleton [room]
//   node scripts/em_client.mjs <host[:port]> [--token T] action <id> <name>
//   node scripts/em_client.mjs <host[:port]> [--token T] post <path> '<json>'
//   node scripts/em_client.mjs <host[:port]> ui        (prints UI version, hash check)
//
// As a module it exports `Device` (see below) for scripted tests.
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";

const DEFAULT_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function deriveKeys(token, kdf = { iter: 2048 }) {
  const master = crypto.pbkdf2Sync(Buffer.from(token), "EscapeManager/2/token", kdf.iter, 32, "sha256");
  const k = (info) => Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), Buffer.from(info), 32));
  return { req: k("EM2 req"), resp: k("EM2 resp"), mac: k("EM2 mac") };
}

export class Device {
  constructor(host, token = DEFAULT_TOKEN) {
    this.base = host.startsWith("http") ? host : "http://" + host;
    this.token = token;
  }

  async init() {
    const t0 = Date.now();
    const res = await fetch(this.base + "/security.json", { cache: "no-store" });
    this.security = await res.json();
    this.clockOffset = this.security.time - (Date.now() + t0) / 2; // device time ~ local time + offset
    this.keys = deriveKeys(this.token, this.security.kdf);
    return this.security;
  }

  deviceTime() {
    return (Math.round(Date.now() + this.clockOffset) >>> 0);
  }

  /** Authenticated GET. Returns {status, doc} and throws if the MAC does not verify. */
  async get(path, query = "") {
    const nonce = b64u(crypto.randomBytes(16));
    const res = await fetch(`${this.base}${path}?nonce=${nonce}${query ? "&" + query : ""}`, { cache: "no-store" });
    const text = await res.text();
    const tail = text.lastIndexOf(',"mac":"');
    if (!text.startsWith('{"doc":') || tail < 0 || !text.endsWith('"}')) throw new Error(`unframed response (${res.status}): ${text.slice(0, 120)}`);
    const doc = text.slice(7, tail);
    const mac = text.slice(tail + 8, -2);
    const expected = b64u(crypto.createHmac("sha256", this.keys.mac).update(`EM2|get|${this.security.did}|${path}|${nonce}|${res.status}|${doc}`).digest());
    if (mac !== expected) throw new Error("MAC mismatch (wrong token?)");
    return { status: res.status, doc: JSON.parse(doc) };
  }

  async post(path, body, { t, retryStale = true } = {}) {
    const iv = crypto.randomBytes(12);
    const tt = t ?? this.deviceTime();
    const c = crypto.createCipheriv("aes-256-gcm", this.keys.req, iv);
    c.setAAD(Buffer.from(`EM2|req|${this.security.did}|${path}|${tt}`));
    const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body))), c.final(), c.getAuthTag()]);
    const res = await fetch(this.base + path, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify({ v: 2, t: tt, iv: b64u(iv), ct: b64u(ct) }),
    });
    const text = await res.text();
    let env;
    try { env = JSON.parse(text); } catch { throw new Error(`unparsable response (${res.status}): ${text.slice(0, 120)}`); }
    if (!env.ct) return { status: res.status, body: env, authenticated: false };
    const raw = Buffer.from(env.ct, "base64url");
    const d = crypto.createDecipheriv("aes-256-gcm", this.keys.resp, Buffer.from(env.iv, "base64url"));
    d.setAAD(Buffer.from(`EM2|resp|${this.security.did}|${path}|${b64u(iv)}|${res.status}`));
    d.setAuthTag(raw.subarray(raw.length - 16));
    const plain = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString());
    if (res.status === 409 && plain.code === "stale_time" && retryStale) {
      this.clockOffset = plain.time - Date.now();
      return this.post(path, body, { retryStale: false });
    }
    return { status: res.status, body: plain, authenticated: true };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const host = args.shift();
  let token = DEFAULT_TOKEN;
  const ti = args.indexOf("--token");
  if (ti >= 0) { token = args[ti + 1]; args.splice(ti, 2); }
  const cmd = args.shift();
  if (!host || !cmd) { console.error("usage: em_client.mjs <host[:port]> [--token T] <cmd> ..."); process.exit(2); }
  const dev = new Device(host, token);
  const sec = await dev.init();
  const show = (v) => console.log(JSON.stringify(v, null, 2));
  switch (cmd) {
    case "security": return show(sec);
    case "status": return show((await dev.get("/status.json")).doc);
    case "peers": return show((await dev.get("/peers.json")).doc);
    case "skeleton": return show((await dev.get("/plan-skeleton.json", args[0] ? "room=" + encodeURIComponent(args[0]) : "")).doc);
    case "action": return show(await dev.post("/action", { id: Number(args[0]), action: args[1] }));
    case "post": return show(await dev.post(args[0], JSON.parse(args[1])));
    case "ui": {
      const r = await fetch(dev.base + "/");
      const html = Buffer.from(await r.arrayBuffer());
      const h = crypto.createHash("sha256").update(html).digest("hex").slice(0, 8);
      return console.log(`ui ${sec.ui} announced=${sec.uih} actual=${h} ${h === sec.uih ? "OK" : "MISMATCH"} (${html.length} bytes after decoding)`);
    }
    default: console.error("unknown command " + cmd); process.exit(2);
  }
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) main().catch((e) => { console.error("error:", e.message); process.exit(1); });
