// A small proto-2 client for tests of the plan-edit token (PROTOCOL.md 3.1) and POST /setup (5.8), written
// against the protocol text with Node's crypto only (independent of the page's bundle and of
// scripts/em_client.mjs, which knows only the normal token). Used to seed devices that have an edit token,
// to read back what the page really stored, and to ask the proof endpoint directly.
import crypto from "node:crypto";

export const DEFAULT_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
const b64u = (buf) => Buffer.from(buf).toString("base64url");

export function keySet(token, { edit = false, iter = 2048 } = {}) {
  const master = crypto.pbkdf2Sync(Buffer.from(token), edit ? "EscapeManager/2/edit-token" : "EscapeManager/2/token", iter, 32, "sha256");
  const k = (info) => Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), Buffer.from(info), 32));
  return { req: k("EM2 req"), resp: k("EM2 resp"), mac: k("EM2 mac") };
}

export class TestDevice {
  /** base: "http://127.0.0.1:port"; token / editToken are what THIS client knows ("" = none). */
  constructor(base, { token = DEFAULT_TOKEN, editToken = "" } = {}) {
    this.base = base;
    this.token = token;
    this.editToken = editToken;
  }

  async init() {
    const t0 = Date.now();
    this.security = await (await fetch(this.base + "/security.json", { cache: "no-store" })).json();
    this.clockOffset = this.security.time - (Date.now() + t0) / 2;
    this.keys = keySet(this.token, { iter: this.security.kdf.iter });
    this.editKeys = this.editToken ? keySet(this.editToken, { edit: true, iter: this.security.kdf.iter }) : null;
    return this.security;
  }

  deviceTime() { return Math.round(Date.now() + this.clockOffset) >>> 0; }

  /** Authenticated GET with the NORMAL keys. Returns { status, doc }. */
  async get(path, query = "") {
    const nonce = b64u(crypto.randomBytes(16));
    const res = await fetch(`${this.base}${path}?nonce=${nonce}${query ? "&" + query : ""}`, { cache: "no-store" });
    const text = await res.text();
    const tail = text.lastIndexOf(',"mac":"');
    if (!text.startsWith('{"doc":') || tail < 0) throw new Error(`unframed response (${res.status}): ${text.slice(0, 120)}`);
    const doc = text.slice(7, tail);
    const expected = b64u(crypto.createHmac("sha256", this.keys.mac).update(`EM2|get|${this.security.did}|${path}|${nonce}|${res.status}|${doc}`).digest());
    if (text.slice(tail + 8, -2) !== expected) throw new Error("MAC mismatch");
    return { status: res.status, doc: JSON.parse(doc) };
  }

  /** GET /edit.json?nonce=..; returns { status, ok, text } where ok = the frame verifies with the edit mac key. */
  async proof(editToken = this.editToken) {
    const nonce = b64u(crypto.randomBytes(16));
    const res = await fetch(`${this.base}/edit.json?nonce=${nonce}`, { cache: "no-store" });
    const text = await res.text();
    const tail = text.lastIndexOf(',"mac":"');
    if (res.status !== 200 || tail < 0) return { status: res.status, ok: false, text };
    const doc = text.slice(7, tail);
    const keys = keySet(editToken, { edit: true, iter: this.security.kdf.iter });
    const expected = b64u(crypto.createHmac("sha256", keys.mac).update(`EM2|eget|${this.security.did}|/edit.json|${nonce}|200|${doc}`).digest());
    return { status: res.status, ok: text.slice(tail + 8, -2) === expected, text };
  }

  /**
   * POST; edit:true seals with the edit keys and adds "k":"e". The answer is opened with the edit response key
   * first, then with the normal one. Returns { status, body, authenticated, sealedWith }.
   */
  async post(path, body, { edit = false, retryStale = true } = {}) {
    const iv = crypto.randomBytes(12);
    const t = this.deviceTime();
    const keys = edit ? this.editKeys : this.keys;
    const c = crypto.createCipheriv("aes-256-gcm", keys.req, iv);
    c.setAAD(Buffer.from(`EM2|req|${this.security.did}|${path}|${t}`));
    const ct = Buffer.concat([c.update(Buffer.from(typeof body === "string" ? body : JSON.stringify(body))), c.final(), c.getAuthTag()]);
    const envelope = { v: 2, t, iv: b64u(iv), ct: b64u(ct) };
    if (edit) envelope.k = "e";
    const res = await fetch(this.base + path, { method: "POST", headers: { "Content-Type": "text/plain" }, body: JSON.stringify(envelope) });
    const text = await res.text();
    const env = JSON.parse(text);
    if (!env.ct) return { status: res.status, body: env, authenticated: false, sealedWith: null };
    const raw = Buffer.from(env.ct, "base64url");
    const candidates = edit ? [["edit", this.editKeys.resp], ["normal", this.keys.resp]] : [["normal", this.keys.resp]];
    for (const [name, key] of candidates) {
      try {
        const d = crypto.createDecipheriv("aes-256-gcm", key, Buffer.from(env.iv, "base64url"));
        d.setAAD(Buffer.from(`EM2|resp|${this.security.did}|${path}|${b64u(iv)}|${res.status}`));
        d.setAuthTag(raw.subarray(raw.length - 16));
        const plain = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString());
        if (res.status === 409 && plain.code === "stale_time" && retryStale) {
          this.clockOffset = plain.time - Date.now();
          return this.post(path, body, { edit, retryStale: false });
        }
        return { status: res.status, body: plain, authenticated: true, sealedWith: name };
      } catch { /* wrong key: try the next one */ }
    }
    return { status: res.status, body: env, authenticated: false, sealedWith: null };
  }

  /** Stored skeleton blob of a room (normal keys), or null when none. */
  async skeleton(room) {
    const { status, doc } = await this.get("/plan-skeleton.json", "room=" + encodeURIComponent(room));
    return status === 200 ? doc : null;
  }

  async status() { return (await this.get("/status.json")).doc; }
}

/** Opens a client for a simulator started by helpers.startSim. */
export async function connect(sim, tokens = {}) {
  const device = new TestDevice(sim.base, tokens);
  await device.init();
  return device;
}
