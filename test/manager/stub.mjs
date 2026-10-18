// A minimal fake proto-2 device (Node http + Node crypto, independent of the manager's bundle)
// for protocol edge cases the real simulator cannot produce: too-new devices, skewed clocks,
// unopenable 401s, strict reads. Serves manager.html at "/" so the page can load from it.
import http from "node:http";
import crypto from "node:crypto";
import fs from "node:fs";
import { deriveKeys } from "../../scripts/em_client.mjs";
import { managerHtml } from "./helpers.mjs";

const b64u = (buf) => Buffer.from(buf).toString("base64url");

export async function startStub({ did = "5748" + crypto.randomBytes(4).toString("hex"), token = "EscapeManager-Private-WLAN-Default-Token", proto = 2, pmin = 2,
  strictGet = false, clockSkewMs = 0, postMode = "ok", name = "Stub", room = "StubRoom",
  ui = "2.0.0", uih = "00000000", html = null, listenPort = 0, actions = ["next_step"], allowTokenInUrl = true } = {}) {
  const keys = deriveKeys(token, { iter: 2048 });
  const startedAt = Date.now() - 100000;
  let skew = clockSkewMs;
  let alwaysStale = false;
  const deviceNow = () => (Date.now() - startedAt + skew) >>> 0;
  const state = { posts: [], gets: [], step: 0 };
  let server;

  const securityDoc = () => JSON.stringify({ proto, pmin, fw: "9.9.9", ui, uih, did, time: deviceNow(), token: "custom", writable: true,
    strictGet, allowTokenInUrl, kdf: { alg: "pbkdf2-sha256", iter: 2048 }, caps: ["plan", "cfg"],
    limits: { body: 12288, skeleton: 6144, plan: 512, name: 32, room: 32, riddle: 32 } });
  const statusDoc = () => JSON.stringify({ proto, pmin, fw: "9.9.9", ui, uih, did, ip: "127.0.0.1", port: server.address().port, boot: 1, seq: 1 + state.step, up: deviceNow(),
    token: "custom", components: [{ id: 0, uuid: did + "-0", riddleId: "stub-v1", name, room, errors: [], actions, planActions: [],
      puzzle: { step: state.step, totalSteps: 5, state: "stub", isHtml: false } }] });
  const peersDoc = (port) => JSON.stringify({ proto, self: { did, ip: "127.0.0.1", port, proto, seq: 1 + state.step, uih, skh: "00000000", age: 0 }, peers: [] });

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
        const record = { path: url.pathname, iv: envelope.iv, t: envelope.t, v: envelope.v, at: deviceNow() };
        state.posts.push(record);
        const reqIv = Buffer.from(envelope.iv, "base64url");
        const raw = Buffer.from(envelope.ct, "base64url");
        const respond = (status, obj, key = keys.resp) => {
          const sealed = seal(key, `EM2|resp|${did}|${url.pathname}|${envelope.iv}|${status}`, JSON.stringify(obj));
          send(status, JSON.stringify({ v: 2, iv: sealed.iv, ct: sealed.ct }));
        };
        if (postMode === "unopenable401") return respond(401, { ok: false, code: "auth_failed" }, crypto.randomBytes(32));
        const drift = (envelope.t - deviceNow()) | 0;
        if (alwaysStale || Math.abs(drift) > 15000) return respond(409, { ok: false, code: "stale_time", time: deviceNow() });
        try {
          const d = crypto.createDecipheriv("aes-256-gcm", keys.req, reqIv);
          d.setAAD(Buffer.from(`EM2|req|${did}|${url.pathname}|${envelope.t}`));
          d.setAuthTag(raw.subarray(raw.length - 16));
          const plain = JSON.parse(Buffer.concat([d.update(raw.subarray(0, raw.length - 16)), d.final()]).toString());
          record.plain = plain;
          if (url.pathname === "/action" && plain.action === "next_step") state.step = Math.min(5, state.step + 1);
          return respond(200, { ok: true });
        } catch {
          return respond(401, { ok: false, code: "auth_failed" }, crypto.randomBytes(32));
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
    stop: () => new Promise((resolve) => { server.closeAllConnections?.(); server.close(resolve); }) };
}
