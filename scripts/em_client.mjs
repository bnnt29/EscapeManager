#!/usr/bin/env node
// Reference proto-2 client for tools and integration tests (Node >= 18, no dependencies).
//
//   node scripts/em_client.mjs <host[:port]> [--token T] security|status|peers|skeleton [room]
//   node scripts/em_client.mjs <host[:port]> [--token T] action <id> <name>
//   node scripts/em_client.mjs <host[:port]> [--token T] post <path> '<json>'
//   node scripts/em_client.mjs <host[:port]> [--token T] [--edit-token E] post --edit /plan '<json>'
//   node scripts/em_client.mjs <host[:port]> [--edit-token E] proof        (does the device have this edit token?)
//
// Tokens default to the [secrets] section of the untracked secrets.ini (auth_token, edit_token), else the
// public default token / no edit token.
//   node scripts/em_client.mjs <host[:port]> ui        (prints UI version, hash check)
//
// As a module it exports `Device` (see below) for scripted tests.
import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import { secrets } from "./secrets.mjs";

export const DEFAULT_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
export const SECRET_TOKEN = secrets.auth_token || DEFAULT_TOKEN;
export const SECRET_EDIT_TOKEN = secrets.edit_token || "";
const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function deriveKeys(token, kdf = { iter: 2048 }, edit = false) {
  const master = crypto.pbkdf2Sync(Buffer.from(token), edit ? "EscapeManager/2/edit-token" : "EscapeManager/2/token", kdf.iter, 32, "sha256");
  const k = (info) => Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), Buffer.from(info), 32));
  return { req: k("EM2 req"), resp: k("EM2 resp"), mac: k("EM2 mac") };
}

export class Device {
  constructor(host, token = SECRET_TOKEN, editToken = "") {
    this.base = host.startsWith("http") ? host : "http://" + host;
    this.token = token;
    this.editToken = editToken;
  }

  async init() {
    const t0 = Date.now();
    const res = await fetch(this.base + "/security.json", { cache: "no-store" });
    this.security = await res.json();
    this.clockOffset = this.security.time - (Date.now() + t0) / 2; // device time ~ local time + offset
    this.keys = deriveKeys(this.token, this.security.kdf);
    this.editKeys = this.editToken ? deriveKeys(this.editToken, this.security.kdf, true) : null;
    return this.security;
  }

  /** GET /edit.json: does this device have the edit token this client knows? { status, ok }. */
  async proof() {
    const nonce = b64u(crypto.randomBytes(16));
    const res = await fetch(`${this.base}/edit.json?nonce=${nonce}`, { cache: "no-store" });
    const text = await res.text();
    const tail = text.lastIndexOf(',"mac":"');
    if (res.status !== 200 || tail < 0 || !this.editKeys) return { status: res.status, ok: false };
    const doc = text.slice(7, tail);
    const expected = b64u(crypto.createHmac("sha256", this.editKeys.mac).update(`EM2|eget|${this.security.did}|/edit.json|${nonce}|200|${doc}`).digest());
    return { status: res.status, ok: text.slice(tail + 8, -2) === expected };
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

  /** POST. `edit: true` seals with the edit keys ("k":"e", needed for /plan, /plan-skeleton, /setup on a device with an edit token). */
  async post(path, body, { t, retryStale = true, edit = false } = {}) {
    const iv = crypto.randomBytes(12);
    const tt = t ?? this.deviceTime();
    const reqKeys = edit ? this.editKeys : this.keys;
    const c = crypto.createCipheriv("aes-256-gcm", reqKeys.req, iv);
    c.setAAD(Buffer.from(`EM2|req|${this.security.did}|${path}|${tt}`));
    const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(body))), c.final(), c.getAuthTag()]);
    const res = await fetch(this.base + path, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: JSON.stringify(edit ? { v: 2, t: tt, iv: b64u(iv), ct: b64u(ct), k: "e" } : { v: 2, t: tt, iv: b64u(iv), ct: b64u(ct) }),
    });
    const text = await res.text();
    let env;
    try { env = JSON.parse(text); } catch { throw new Error(`unparsable response (${res.status}): ${text.slice(0, 120)}`); }
    if (!env.ct) return { status: res.status, body: env, authenticated: false };
    const raw = Buffer.from(env.ct, "base64url");
    // Success of an edit request is sealed with the edit response key; errors before authentication with the normal one.
    let plain = null, sealedWith = null;
    for (const [name, keys] of edit ? [["edit", this.editKeys], ["normal", this.keys]] : [["normal", this.keys]]) {
      try {
        const d = crypto.createDecipheriv("aes-256-gcm", keys.resp, Buffer.from(env.iv, "base64url"));
        d.setAAD(Buffer.from(`EM2|resp|${this.security.did}|${path}|${b64u(iv)}|${res.status}`));
        d.setAuthTag(raw.subarray(raw.length - 16));
        plain = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString());
        sealedWith = name;
        break;
      } catch { /* try the next key set */ }
    }
    if (plain === null) return { status: res.status, body: env, authenticated: false, sealedWith: null };
    if (res.status === 409 && plain.code === "stale_time" && retryStale) {
      this.clockOffset = plain.time - Date.now();
      return this.post(path, body, { retryStale: false, edit });
    }
    return { status: res.status, body: plain, authenticated: true, sealedWith };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const host = args.shift();
  let token = SECRET_TOKEN, editToken = SECRET_EDIT_TOKEN;
  const ti = args.indexOf("--token");
  if (ti >= 0) { token = args[ti + 1]; args.splice(ti, 2); }
  const ei = args.indexOf("--edit-token");
  if (ei >= 0) { editToken = args[ei + 1]; args.splice(ei, 2); }
  const edit = args.includes("--edit");
  if (edit) args.splice(args.indexOf("--edit"), 1);
  const cmd = args.shift();
  if (!host || !cmd) { console.error("usage: em_client.mjs <host[:port]> [--token T] <cmd> ..."); process.exit(2); }
  const dev = new Device(host, token, editToken);
  const sec = await dev.init();
  const show = (v) => console.log(JSON.stringify(v, null, 2));
  switch (cmd) {
    case "security": return show(sec);
    case "status": return show((await dev.get("/status.json")).doc);
    case "peers": return show((await dev.get("/peers.json")).doc);
    case "skeleton": return show((await dev.get("/plan-skeleton.json", args[0] ? "room=" + encodeURIComponent(args[0]) : "")).doc);
    case "action": return show(await dev.post("/action", { id: Number(args[0]), action: args[1] }));
    case "post": {
      const r = await dev.post(args[0], JSON.parse(args[1]), { edit });
      show(r);
      if (!r.authenticated) process.exitCode = 1; // the answer could not be opened with this client's keys (wrong token?)
      return;
    }
    case "proof": return show(await dev.proof());
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
