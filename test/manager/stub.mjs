// A minimal fake proto-2 device (Node http + Node crypto, independent of the manager's bundle)
// for protocol edge cases the real simulator cannot produce: too-new devices, skewed clocks,
// unopenable 401s, strict reads. Serves manager.html at "/" so the page can load from it.
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { deriveKeys } from "../../scripts/em_client.mjs";
import { managerHtml } from "./helpers.mjs";
import { keySet } from "./editkit.mjs";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

// Plan-edit token (PROTOCOL.md 3.1): editToken sets a real edit token (state "custom", cap "edit"), editState
// "invalid" simulates an unusable stored one; publishEdit overrides what /security.json and /status.json CLAIM
// (a stale or lying device); caps overrides the advertised capabilities (default: plan, cfg and, when the device
// has an edit state, edit). setEdit() changes the real state at run time.
export async function startStub({ did = "5748" + crypto.randomBytes(4).toString("hex"), token = "EscapeManager-Private-WLAN-Default-Token", proto = 2, pmin = 2,
  strictGet = false, clockSkewMs = 0, postMode = "ok", name = "Stub", room = "StubRoom",
  ui = "2.0.0", uih = "00000000", html = null, listenPort = 0, actions = ["next_step"], allowTokenInUrl = true,
  editToken = "", editState = "", publishEdit = null, caps = null } = {}) {
  const keys = deriveKeys(token, { iter: 2048 });
  const edit = { token: editToken, state: editState || (editToken ? "custom" : "unset"), publish: publishEdit, keys: null };
  const refreshEditKeys = () => { edit.keys = edit.state === "custom" && edit.token ? keySet(edit.token, { edit: true }) : null; };
  refreshEditKeys();
  const publishedEdit = () => edit.publish ?? edit.state;
  const advertisedCaps = () => caps ?? (edit.state !== "unset" || edit.token || edit.publish ? ["plan", "cfg", "edit"] : ["plan", "cfg"]);
  const startedAt = Date.now() - 100000;
  let skew = clockSkewMs;
  let alwaysStale = false;
  const deviceNow = () => (Date.now() - startedAt + skew) >>> 0;
  const state = { posts: [], gets: [], step: 0, boot: 1, bump: 0 };
  let server;

  const securityDoc = () => JSON.stringify({ proto, pmin, fw: "9.9.9", ui, uih, did, time: deviceNow(), token: "custom", writable: true,
    strictGet, allowTokenInUrl, ...(advertisedCaps().includes("edit") ? { edit: publishedEdit() } : {}),
    kdf: { alg: "pbkdf2-sha256", iter: 2048 }, caps: advertisedCaps(),
    limits: { body: 12288, skeleton: 6144, plan: 512, name: 32, room: 32, riddle: 32 } });
  const statusDoc = () => JSON.stringify({ proto, pmin, fw: "9.9.9", ui, uih, did, ip: "127.0.0.1", port: server.address().port, boot: state.boot, seq: 1 + state.step + state.bump, up: deviceNow(),
    token: "custom", ...(advertisedCaps().includes("edit") ? { edit: publishedEdit() } : {}), components: [{ id: 0, uuid: did + "-0", riddleId: "stub-v1", name, room, errors: [], actions, planActions: [],
      puzzle: { step: state.step, totalSteps: 5, state: "stub", isHtml: false } }] });
  const peersDoc = (port) => JSON.stringify({ proto, self: { did, ip: "127.0.0.1", port, proto, seq: 1 + state.step + state.bump, uih, skh: "00000000", age: 0 }, peers: [] });

  const docFor = (path, port) => path === "/status.json" ? statusDoc() : path === "/peers.json" ? peersDoc(port)
    : path === "/plan-skeleton.json" ? JSON.stringify({ proto, rooms: [] }) : null;

  const seal = (key, aad, plain, ivBytes = crypto.randomBytes(12)) => {
    const c = crypto.createCipheriv("aes-256-gcm", key, ivBytes);
    c.setAAD(Buffer.from(aad));
    const ct = Buffer.concat([c.update(Buffer.from(plain)), c.final(), c.getAuthTag()]);
    return { iv: b64u(ivBytes), ct: b64u(ct) };
  };

  server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://x");
    const send = (status, body, type = "application/json") => { res.writeHead(status, { "Content-Type": type, "Access-Control-Allow-Origin": "*" }); res.end(body); };
    if (req.method === "GET") {
      state.gets.push(req.url);
      if (url.pathname === "/") return send(200, html ?? fs.readFileSync(managerHtml), "text/html; charset=utf-8");
      if (url.pathname === "/security.json") return send(200, securityDoc());
      if (url.pathname === "/edit.json") {
        const nonce = url.searchParams.get("nonce");
        if (!edit.keys) return send(404, '{"ok":false,"code":"edit_unset","error":"no edit token set"}');
        if (!nonce) return send(400, '{"ok":false,"code":"bad_request","error":"nonce required"}');
        const doc = '{"proto":2,"edit":"custom"}';
        const mac = b64u(crypto.createHmac("sha256", edit.keys.mac).update(`EM2|eget|${did}|/edit.json|${nonce}|200|${doc}`).digest());
        return send(200, `{"doc":${doc},"mac":"${mac}"}`);
      }
      const doc = docFor(url.pathname, server.address().port);
      if (doc === null) return send(404, '{"ok":false,"code":"not_found"}');
      const nonce = url.searchParams.get("nonce");
      if (!nonce) return strictGet ? send(401, '{"ok":false,"code":"auth_required"}') : send(200, doc);
      const mac = b64u(crypto.createHmac("sha256", keys.mac).update(`EM2|get|${did}|${url.pathname}|${nonce}|200|${doc}`).digest());
      return send(200, `{"doc":${doc},"mac":"${mac}"}`);
    }
    if (req.method === "POST") {
      let body = "";
      req.on("data", (d) => { body += d; });
      req.on("end", () => {
        const envelope = JSON.parse(body);
        const record = { path: url.pathname, iv: envelope.iv, t: envelope.t, v: envelope.v, k: envelope.k, at: deviceNow() };
        state.posts.push(record);
        const reqIv = Buffer.from(envelope.iv, "base64url");
        const raw = Buffer.from(envelope.ct, "base64url");
        const respond = (status, obj, key = keys.resp) => {
          const sealed = seal(key, `EM2|resp|${did}|${url.pathname}|${envelope.iv}|${status}`, JSON.stringify(obj));
          send(status, JSON.stringify({ v: 2, iv: sealed.iv, ct: sealed.ct }));
        };
        if (postMode === "unopenable401") return respond(401, { ok: false, code: "auth_failed" }, crypto.randomBytes(32));
        const isEditPath = ["/plan", "/plan-skeleton", "/setup"].includes(url.pathname);
        const role = envelope.k === undefined ? "normal" : envelope.k === "e" ? "edit" : "bad";
        if (role === "bad" || (role === "edit" && !isEditPath)) return respond(400, { ok: false, code: "bad_envelope" });
        if (isEditPath && edit.state === "invalid") return respond(503, { ok: false, code: "read_only" });
        const drift = (envelope.t - deviceNow()) | 0;
        if (alwaysStale || Math.abs(drift) > 15000) return respond(409, { ok: false, code: "stale_time", time: deviceNow() });
        if (role === "edit" && !edit.keys) return respond(401, { ok: false, code: "auth_failed" }); // normal key: nobody holds an edit key here
        try {
          const d = crypto.createDecipheriv("aes-256-gcm", role === "edit" ? edit.keys.req : keys.req, reqIv);
          d.setAAD(Buffer.from(`EM2|req|${did}|${url.pathname}|${envelope.t}`));
          d.setAuthTag(raw.subarray(raw.length - 16));
          const plain = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString());
          record.plain = plain;
          record.role = role;
          if (role === "normal" && isEditPath && edit.keys) return respond(403, { ok: false, code: "edit_required" });
          if (url.pathname === "/action" && plain.action === "next_step") state.step = Math.min(5, state.step + 1);
          const answer = url.pathname === "/plan-skeleton" && Number.isInteger(plain.baseRev) ? { ok: true, rev: plain.baseRev + 1, hash: "00000000" } : { ok: true };
          return respond(200, answer, role === "edit" ? edit.keys.resp : keys.resp);
        } catch {
          // A request sealed with the wrong EDIT key is still answered under the normal key (PROTOCOL.md 3.1).
          return respond(401, { ok: false, code: "auth_failed" }, role === "edit" ? keys.resp : crypto.randomBytes(32));
        }
      });
      return;
    }
    send(204, "");
  });
  await new Promise((resolve) => server.listen(listenPort, "127.0.0.1", resolve));
  const port = server.address().port;
  return { port, did, base: `http://127.0.0.1:${port}`, state, name, room,
    setSkew: (ms) => { skew = ms; }, setAlwaysStale: (on) => { alwaysStale = on; },
    setBoot: (boot) => { state.boot = boot; state.bump++; }, // a restart: new boot counter, new seq
    setEdit: ({ token: nextToken = edit.token, state: nextState = nextToken ? "custom" : "unset", publish = null } = {}) => {
      edit.token = nextToken; edit.state = nextState; edit.publish = publish; refreshEditKeys();
    },
    stop: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }) };
}
