/*
 * GitHub-Pages-Demo: simulierte Geraete im Browser.
 *
 * Wird von scripts/build_demo.py als ERSTES Skript in <head> der Manager-Seite eingefuegt (das ist eine
 * eigene Datei, manager.html bleibt unveraendert). Es macht drei Dinge:
 *
 *  1. Speicher: localStorage zeigt auf sessionStorage. Nichts landet dauerhaft im Browser, und die Seite
 *     uebernimmt keine zwischengespeicherte Oberflaeche anderer github.io-Seiten.
 *  2. Netz: window.fetch wird ersetzt, BEVOR die Manager-Skripte laufen (sie merken sich fetch beim Start).
 *     Anfragen an die Adressen der simulierten Geraete werden hier beantwortet (Protokoll 2, PROTOCOL.md):
 *     signierte GET-Rahmen, versiegelte POSTs mit der Kryptografie der Seite (window.EscapeCrypto).
 *     Unbekannte Geraete-Adressen schlagen fehl wie ausgeschaltete Geraete.
 *  3. Geraete: drei Dummy-Boards mit Komponenten (Puzzle-Schritte, Aktionen, Umbenennen, Konfiguration,
 *     Ablaufplaene). Der Zustand bleibt nur in sessionStorage (Schluessel em.demo.fleet).
 *
 * Hardware-Einstellungen (POST /setup: WLAN, Tokens) werden angenommen, aber NICHT gespeichert. Die
 * simulierten Geraete nehmen das Token, mit dem die Seite gerade arbeitet (sessionStorage em.token);
 * dadurch sperrt sich die Demo nicht aus, wenn jemand ein Token eintraegt.
 */
(() => {
  "use strict";

  // ---- 1. Speicher -----------------------------------------------------------------------------------------
  // Muss vor dem ersten Manager-Skript stehen. Ohne ueberschreibbares localStorage laeuft die Demo trotzdem,
  // der Test (test/manager/demo.test.mjs) prueft aber, dass der Browser-Speicher leer bleibt.
  Object.defineProperty(window, "localStorage", { configurable: true, get: () => window.sessionStorage });

  const DEFAULT_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
  const UI_VERSION = "2.1.1";
  const ITER = 2048;
  const TOTAL = 5;
  const ACTIONS = ["next_step", "reset", "solve", "toggle_error", "drain_battery"];
  const PLAN_ACTIONS = ["reset", "complete"];
  const LIMITS = { body: 12288, skeleton: 6144, plan: 512, name: 32, room: 32, riddle: 32 };
  const CONFIG = [
    { key: "brightness", type: "range", min: 0, max: 100 },
    { key: "label", type: "text", maxLength: 32 },
    { key: "difficulty", type: "select", options: ["easy", "medium", "hard"] },
  ];
  const STORE_KEY = "em.demo.fleet";
  const BOOT_AT = Date.now();
  const session = window.sessionStorage;
  const realFetch = window.fetch.bind(window);
  const crypto_ = () => window.EscapeCrypto;   // von der Kryptografie-Stufe der Seite; erst zur Laufzeit gebraucht

  // ---- Geraete-Modell -------------------------------------------------------------------------------------
  const comp = (name, room, riddleId, step, error = false) => ({
    name, room, riddleId, step, error, plan: null, evtSeq: 0, evtMsg: "",
    config: { brightness: "50", label: "", difficulty: "medium" },
  });

  // base null = das Board, von dem die Seite geladen wurde (die Seite ist das erste Geraet).
  const BOARD_DEFS = [
    { did: "de0000000001", base: null, battery: 100, comps: [
      comp("Dummy-Kamera-0001", "Dummy-Raum", "dummy-camera-0001", 0),
      comp("Dummy-Laser-0001", "Dummy-Raum", "dummy-laser-0001", 2),
    ] },
    { did: "de0000000002", base: "http://10.0.0.12:80", battery: 100, comps: [
      comp("Dummy-Kamera-0002", "Dummy-Raum", "dummy-camera-0002", 1),
      comp("Dummy-Laser-0002", "Dummy-Raum", "dummy-laser-0002", 0),
    ] },
    { did: "de0000000003", base: "http://10.0.0.13:80", battery: 12, comps: [
      comp("Dummy-Schloss-0003", "Dummy-Raum-2", "dummy-lock-0003", 3),
      comp("Dummy-Sensor-0003", "Dummy-Raum-2", "dummy-sensor-0003", 0, true),
    ] },
  ];

  function freshFleet() {
    return {
      v: 1,
      boards: BOARD_DEFS.map((d) => ({
        did: d.did, base: d.base, battery: d.battery, seq: 1,
        comps: d.comps.map((c) => ({ ...c, config: { ...c.config } })),
      })),
      skeletons: {},   // Raum -> { rev, hash, sk (rohe Bytes des Ablaufplans) }
    };
  }

  function loadFleet() {
    try {
      const raw = session.getItem(STORE_KEY);
      if (raw) {
        const fleet = JSON.parse(raw);
        if (fleet && fleet.v === 1 && Array.isArray(fleet.boards) && fleet.boards.length === BOARD_DEFS.length) return fleet;
      }
    } catch (_) { /* beschaedigter Stand: neu anlegen */ }
    return freshFleet();
  }

  let fleet = loadFleet();
  function save() {
    try { session.setItem(STORE_KEY, JSON.stringify(fleet)); } catch (_) { /* voll: Demo laeuft ohne Speichern weiter */ }
  }
  save();

  const originOf = (b) => (b.base ? new URL(b.base).origin : location.origin);
  const boardFor = (origin) => fleet.boards.find((b) => originOf(b) === origin) || null;
  const portOf = (b) => { const u = new URL(originOf(b)); return Number(u.port) || (u.protocol === "https:" ? 443 : 80); };
  const roomsOf = (b) => [...new Set(b.comps.map((c) => c.room))].sort();
  const deviceNow = () => (Date.now() - BOOT_AT) >>> 0;
  const b64u = (bytes) => crypto_().b64uEncode(bytes);
  const hex8 = (n) => (n >>> 0).toString(16).padStart(8, "0");
  function fnv1a(bytes) {
    let h = 0x811c9dc5;
    for (let i = 0; i < bytes.length; i++) { h ^= bytes[i]; h = Math.imul(h, 0x01000193); }
    return h >>> 0;
  }
  const hashOf = (text) => hex8(fnv1a(crypto_().utf8Encode(text)));   // wie SkeletonStore: FNV-1a 32 ueber die UTF-8-Bytes
  const byteLength = (text) => crypto_().utf8Encode(text).length;

  // Token der Sitzung (wie die Seite selbst). Leer = Betrachtermodus ohne Schluessel.
  function keysNow() {
    const raw = session.getItem("em.token");
    const token = raw === null ? DEFAULT_TOKEN : raw;
    return token ? crypto_().deriveKeys(token, ITER) : null;
  }

  function changed(b) { b.seq += 1; save(); }

  function pruneSkeletons() {
    for (const room of Object.keys(fleet.skeletons)) {
      if (!fleet.boards.some((b) => roomsOf(b).includes(room))) delete fleet.skeletons[room];
    }
  }

  // ---- Dokumente (Klartext-JSON) ---------------------------------------------------------------------------
  function securityDoc(b) {
    const raw = session.getItem("em.token");
    return {
      proto: 2, pmin: 2, fw: UI_VERSION, ui: UI_VERSION, uih: "00000000", did: b.did, time: deviceNow(),
      token: raw === null || raw === DEFAULT_TOKEN ? "default" : "custom",
      writable: true, strictGet: false, allowTokenInUrl: true,
      kdf: { alg: "pbkdf2-sha256", iter: ITER }, caps: ["plan", "cfg", "setup"], setupAp: "none", limits: LIMITS,
    };
  }

  function configOf(c) {
    return CONFIG.map((spec) => ({ ...spec, value: c.config[spec.key] }));
  }

  function pictureOf(c) {
    const done = c.step >= TOTAL;
    let s = '<svg xmlns="http://www.w3.org/2000/svg" width="276" height="60" viewBox="0 0 276 60">';
    for (let i = 0; i < TOTAL; i++) {
      const x = 14 + i * 52;
      const current = !done && i === c.step;
      const fill = done ? "#2e9e5b" : i < c.step ? "#4a90d9" : "#eeeeee";
      const stroke = current ? "#4a90d9" : "#bbbbbb";
      s += `<rect x="${x}" y="8" width="44" height="32" rx="4" fill="${fill}" stroke="${stroke}" stroke-width="${current ? 3 : 1}"/>`;
      s += `<text x="${x + 22}" y="30" font-size="14" text-anchor="middle" font-family="sans-serif" fill="${i < c.step || done ? "#fff" : "#555"}">${i + 1}</text>`;
    }
    if (c.error) s += '<rect x="2" y="2" width="272" height="56" fill="none" stroke="#d33" stroke-width="2"/>';
    s += `<text x="138" y="56" font-size="12" text-anchor="middle" font-family="sans-serif" fill="#333">${done ? "gelöst" : "Schritt " + c.step + " von " + TOTAL}</text></svg>`;
    return s;
  }

  function componentDoc(b, c, id) {
    const doc = {
      id, uuid: b.did + "-" + id, riddleId: c.riddleId, name: c.name, room: c.room,
      errors: c.error ? ["sensor_timeout"] : [], actions: ACTIONS, planActions: PLAN_ACTIONS,
      puzzle: { step: c.step, totalSteps: TOTAL, state: pictureOf(c), isHtml: true },
      customConfig: configOf(c),
    };
    if (c.step < TOTAL) doc.tip = "Nächste Aktion: next_step";
    if (c.plan) doc.plan = c.plan;
    if (c.evtSeq > 0) { doc.evtSeq = c.evtSeq; doc.evtMsg = c.evtMsg; }
    return doc;
  }

  function statusDoc(b) {
    const raw = session.getItem("em.token");
    const u = new URL(originOf(b));
    const doc = {
      proto: 2, pmin: 2, fw: UI_VERSION, ui: UI_VERSION, uih: "00000000", did: b.did,
      ip: u.hostname, port: portOf(b), boot: 1, seq: b.seq, up: deviceNow(),
      token: raw === null || raw === DEFAULT_TOKEN ? "default" : "custom",
      components: b.comps.map((c, id) => componentDoc(b, c, id)),
    };
    if (b.battery > 0) doc.battery = b.battery;
    return doc;
  }

  function skeletonIndex(b) {
    const rooms = roomsOf(b).filter((r) => fleet.skeletons[r]).map((r) => ({ room: r, rev: fleet.skeletons[r].rev, hash: fleet.skeletons[r].hash }));
    return { proto: 2, rooms };
  }

  function skhOf(b) {
    const rows = roomsOf(b).filter((r) => fleet.skeletons[r]).map((r) => [hashOf(r), fleet.skeletons[r].rev, fleet.skeletons[r].hash]);
    return hashOf(JSON.stringify(rows));
  }

  function peerEntry(b) {
    const u = new URL(originOf(b));
    return { did: b.did, ip: u.hostname, port: portOf(b), proto: 2, seq: b.seq, uih: "00000000", skh: skhOf(b), age: 0 };
  }

  // Peers nur ueber http (wie der Manager sie ohnehin nutzt); eine https-Seite kann nicht zu ihnen.
  function peersDoc(b) {
    const peers = fleet.boards.filter((o) => o !== b && originOf(o).startsWith("http://")).map(peerEntry);
    return { proto: 2, self: peerEntry(b), peers };
  }

  // ---- Befehle (Protokoll 4.2) -----------------------------------------------------------------------------
  const ok = (body = {}) => ({ status: 200, body: { ok: true, ...body } });
  const fail = (status, code, error = "") => ({ status, body: { ok: false, code, error } });
  const validText = (value, max) => typeof value === "string" && value.length >= 1 && value.length <= max;
  const compAt = (b, id) => (Number.isInteger(id) && id >= 0 && id < b.comps.length ? b.comps[id] : null);
  const idOf = (plain) => (plain.id === undefined ? 0 : plain.id);
  const eventOn = (c, message) => { c.evtSeq += 1; c.evtMsg = message.slice(0, 64); };

  function doAction(b, plain) {
    const c = compAt(b, idOf(plain));
    if (!c) return fail(400, "bad_id", "unknown component");
    const name = plain.action;
    if (typeof name !== "string" || name.length < 1 || name.length > 24) return fail(400, "bad_action", "bad action");
    if (!ACTIONS.includes(name)) return fail(422, "rejected", "unknown action");
    if (name === "next_step") c.step = Math.min(TOTAL, c.step + 1);
    else if (name === "reset") { c.step = 0; c.error = false; }
    else if (name === "solve") c.step = TOTAL;
    else if (name === "toggle_error") c.error = !c.error;
    else if (name === "drain_battery") b.battery = Math.max(0, b.battery - 10);
    eventOn(c, `Aktion "${name}" ausgeführt`);
    changed(b);
    return ok();
  }

  function doPlanAction(b, plain) {
    const c = compAt(b, idOf(plain));
    if (!c) return fail(400, "bad_id", "unknown component");
    if (plain.action === "reset") { c.step = 0; c.error = false; eventOn(c, "Ablaufplan-Fortschritt zurückgesetzt"); }
    else if (plain.action === "complete") { c.step = TOTAL; eventOn(c, "Ablaufplan-Komponente abgeschlossen"); }
    else return fail(400, "bad_action", "bad plan action");
    changed(b);
    return ok();
  }

  function doConfig(b, plain) {
    const c = compAt(b, idOf(plain));
    if (!c) return fail(400, "bad_id", "unknown component");
    const hasName = plain.name !== undefined;
    const hasRoom = plain.room !== undefined;
    if (hasName !== hasRoom) return fail(400, "bad_request", "name and room go together");
    if (hasName && (!validText(plain.name, LIMITS.name) || !validText(plain.room, LIMITS.room))) return fail(400, "bad_request", "name or room");
    if (plain.riddleId !== undefined && !validText(plain.riddleId, LIMITS.riddle)) return fail(400, "bad_request", "riddleId");
    const values = {};
    if (plain.config !== undefined) {
      if (!plain.config || typeof plain.config !== "object" || Array.isArray(plain.config)) return fail(400, "bad_request", "config");
      for (const key of Object.keys(plain.config)) {
        const spec = CONFIG.find((s) => s.key === key);
        if (!spec) return fail(400, "bad_request", "unknown config key");
        const raw = typeof plain.config[key] === "number" ? String(plain.config[key]) : plain.config[key];
        if (typeof raw !== "string") return fail(400, "bad_request", "config value");
        const valid = spec.type === "range" ? /^-?\d+$/.test(raw) && Number(raw) >= spec.min && Number(raw) <= spec.max
          : spec.type === "text" ? raw.length <= spec.maxLength && raw.length <= 48
          : spec.options.includes(raw);
        if (!valid) return fail(400, "bad_request", "invalid value for " + key);
        values[key] = raw;
      }
    }
    // Alles geprueft: jetzt anwenden.
    const changes = [];
    if (hasName) { c.name = plain.name; c.room = plain.room; changes.push("Name/Raum geändert"); }
    if (plain.riddleId !== undefined) { c.riddleId = plain.riddleId; changes.push("Rätsel-ID geändert"); }
    if (Object.keys(values).length) { Object.assign(c.config, values); changes.push("Konfiguration geändert"); }
    if (changes.length) eventOn(c, changes.join(", "));
    pruneSkeletons();
    changed(b);
    return ok();
  }

  function doPlanSlice(b, plain) {
    const c = compAt(b, idOf(plain));
    if (!c) return fail(400, "bad_id", "unknown component");
    if (plain.plan === null) { c.plan = null; eventOn(c, "Ablaufplan-Zuordnung entfernt"); }
    else if (plain.plan && typeof plain.plan === "object" && !Array.isArray(plain.plan)) {
      if (byteLength(JSON.stringify(plain.plan)) > LIMITS.plan) return fail(413, "too_large", "plan too large");
      c.plan = plain.plan;
      eventOn(c, "Ablaufplan aktualisiert");
    } else return fail(400, "bad_request", "plan");
    changed(b);
    return ok();
  }

  function doSkeleton(b, plain, text) {
    if (!validText(plain.room, LIMITS.room)) return fail(400, "bad_request", "room");
    const room = plain.room;
    if (!Number.isInteger(plain.baseRev) || plain.baseRev < 0) return fail(400, "bad_request", "baseRev");
    if (!plain.sk || typeof plain.sk !== "object" || Array.isArray(plain.sk)) return fail(400, "bad_request", "sk");
    // Der Manager schickt {"room":..,"baseRev":..,"sk":<rohe Bytes>} - "sk" ist das letzte Mitglied.
    const raw = text.slice(text.indexOf('"sk":') + 5, text.length - 1);
    if (byteLength(raw) > LIMITS.skeleton) return fail(413, "too_large", "skeleton too large");
    if (!roomsOf(b).includes(room)) return fail(422, "room_not_hosted", "no component in this room");
    const hash = hashOf(raw);
    const cur = fleet.skeletons[room];
    if (cur && cur.hash === hash) return ok({ rev: cur.rev, hash });   // gleicher Stand: idempotent
    const currentRev = cur ? cur.rev : 0;
    if (plain.baseRev !== currentRev) {
      return { status: 409, body: { ok: false, code: "rev_conflict", error: "revision differs", rev: currentRev, hash: cur ? cur.hash : "00000000" } };
    }
    if (!cur && Object.keys(fleet.skeletons).length >= 4) return fail(422, "room_limit", "too many rooms");
    fleet.skeletons[room] = { rev: currentRev + 1, hash, sk: raw };
    for (const other of fleet.boards) if (roomsOf(other).includes(room)) other.seq += 1;   // alle Geraete des Raums haben den Stand
    save();
    return ok({ rev: currentRev + 1, hash });
  }

  // Geraete-Setup: Eingaben werden geprueft wie im Geraet, dann verworfen (keine Speicherung, siehe Kopf).
  function doSetup(plain) {
    const hasSsid = plain.ssid !== undefined;
    const hasPass = plain.pass !== undefined;
    if (hasSsid !== hasPass) return fail(400, "bad_request", "ssid and pass go together");
    if (hasSsid && (!validText(plain.ssid, 32) || plain.ssid.startsWith("EscapeSetup-"))) return fail(400, "bad_request", "ssid");
    if (hasPass && !(plain.pass === "" || (plain.pass.length >= 8 && plain.pass.length <= 63))) return fail(400, "bad_request", "pass");
    for (const token of [plain.token, plain.editToken]) {
      if (token !== undefined && token !== "" && !/^[\x21-\x7e]{8,128}$/.test(token)) return fail(400, "bad_request", "token");
    }
    return ok();
  }

  function routePost(b, path, text, plain) {
    switch (path) {
      case "/action": return doAction(b, plain);
      case "/plan-action": return doPlanAction(b, plain);
      case "/config": return doConfig(b, plain);
      case "/plan": return doPlanSlice(b, plain);
      case "/plan-skeleton": return doSkeleton(b, plain, text);
      case "/setup": return doSetup(plain);
      default: return fail(404, "not_found", "unknown path");
    }
  }

  // ---- HTTP-Antworten -------------------------------------------------------------------------------------
  const jsonReply = (status, text) => new Response(status === 204 ? null : text, {
    status, headers: { "Content-Type": "application/json; charset=utf-8" },
  });

  function getReply(b, url) {
    const path = url.pathname;
    if (path === "/favicon.ico") return jsonReply(204, null);
    if (path === "/security.json") return jsonReply(200, JSON.stringify(securityDoc(b)));
    if (path === "/edit.json") return jsonReply(404, '{"ok":false,"code":"edit_unset","error":"no edit token set"}');
    let status = 200;
    let docText;
    if (path === "/status.json") docText = JSON.stringify(statusDoc(b));
    else if (path === "/peers.json") docText = JSON.stringify(peersDoc(b));
    else if (path === "/plan-skeleton.json") {
      const room = url.searchParams.get("room");
      if (room === null) docText = JSON.stringify(skeletonIndex(b));
      else if (roomsOf(b).includes(room) && fleet.skeletons[room]) {
        const s = fleet.skeletons[room];
        docText = `{"room":${JSON.stringify(room)},"rev":${s.rev},"hash":"${s.hash}","sk":${s.sk}}`;
      } else {
        status = 404;
        docText = '{"ok":false,"code":"no_plan","error":"no plan stored"}';
      }
    } else return jsonReply(404, '{"ok":false,"code":"not_found","error":"unknown path"}');

    const nonce = url.searchParams.get("nonce");
    if (nonce === null) return jsonReply(status, docText);      // ohne Nonce nur im Betrachtermodus
    if (!/^[A-Za-z0-9_-]{16,64}$/.test(nonce)) return jsonReply(400, '{"ok":false,"code":"bad_request","error":"bad nonce"}');
    const keys = keysNow();
    if (!keys) return jsonReply(401, '{"ok":false,"code":"auth_required","error":"token required"}');
    const mac = b64u(crypto_().hmacSha256(keys.mac, `EM2|get|${b.did}|${path}|${nonce}|${status}|${docText}`));
    return jsonReply(status, `{"doc":${docText},"mac":"${mac}"}`);
  }

  function postReply(b, url, text) {
    const path = url.pathname;
    const keys = keysNow();
    if (!keys) return jsonReply(401, '{"ok":false,"code":"auth_required","error":"token required"}');
    const plainError = (code) => jsonReply(400, JSON.stringify({ ok: false, code, error: code }));
    let env;
    try { env = JSON.parse(text); } catch (_) { env = null; }
    if (!env || typeof env !== "object") return plainError("bad_envelope");
    const editPath = ["/plan", "/plan-skeleton", "/setup"].includes(path);
    if (env.k !== undefined && env.k !== "e") return plainError("bad_envelope");
    if (env.k === "e" && !editPath) return plainError("bad_envelope");
    if (env.v !== 2 || typeof env.iv !== "string" || typeof env.ct !== "string" || !Number.isInteger(env.t)) return plainError("bad_envelope");
    const iv = crypto_().b64uDecode(env.iv);
    const ct = crypto_().b64uDecode(env.ct);
    if (!iv || iv.length !== 12 || !ct || ct.length < 16) return plainError("bad_envelope");

    // Ab hier ist der Umschlag lesbar: Antworten sind versiegelt (Schluessel k_resp, AAD mit Status).
    const respond = (status, body, key = keys.resp) => {
      const replyIv = crypto_().randomBytes(12);
      const sealed = crypto_().gcmSeal(key, replyIv, `EM2|resp|${b.did}|${path}|${env.iv}|${status}`, JSON.stringify(body));
      return jsonReply(status, JSON.stringify({ v: 2, iv: b64u(replyIv), ct: b64u(sealed) }));
    };
    if (env.k === "e") return respond(401, { ok: false, code: "auth_failed", error: "no edit token" });   // kein Bearbeiten-Token gesetzt
    const drift = (env.t - deviceNow()) | 0;
    if (Math.abs(drift) > 15000) return respond(409, { ok: false, code: "stale_time", error: "clock", time: deviceNow() });
    const bytes = crypto_().gcmOpen(keys.req, iv, `EM2|req|${b.did}|${path}|${env.t}`, ct);
    if (!bytes) return respond(401, { ok: false, code: "auth_failed", error: "auth" }, crypto_().randomBytes(32));
    let plainText = "";
    let plain = null;
    try { plainText = crypto_().utf8Decode(bytes); plain = JSON.parse(plainText); } catch (_) { plain = null; }
    if (!plain || typeof plain !== "object" || Array.isArray(plain)) return respond(400, { ok: false, code: "bad_request", error: "body" });
    const result = routePost(b, path, plainText, plain);
    return respond(result.status, result.body);
  }

  async function deviceFetch(b, url, init) {
    await new Promise((resolve) => setTimeout(resolve, 40));   // wie ein Netz: nie sofort
    const method = String(init.method || "GET").toUpperCase();
    if (method === "GET") return getReply(b, url);
    if (method === "POST") return postReply(b, url, String(init.body ?? ""));
    return jsonReply(405, '{"ok":false,"code":"not_found","error":"method"}');
  }

  // ---- 2. Netz ----------------------------------------------------------------------------------------------
  window.fetch = function demoFetch(input, init = {}) {
    let url;
    try { url = new URL(typeof input === "string" ? input : input.url, location.href); } catch (_) { return realFetch(input, init); }
    const board = boardFor(url.origin);
    if (board) return deviceFetch(board, url, init);
    if ((url.protocol === "http:" || url.protocol === "https:") && url.origin !== location.origin) {
      return Promise.reject(new TypeError("Failed to fetch"));   // unbekanntes Geraet: wie ausgeschaltet
    }
    return realFetch(input, init);
  };

  // ---- 3. Oberflaeche der Demo -----------------------------------------------------------------------------
  function banner() {
    const bar = document.createElement("div");
    bar.id = "em-demo-banner";
    bar.setAttribute("role", "status");
    bar.style.cssText = "position:fixed;left:0;right:0;bottom:0;z-index:2147483000;background:#1d3557;color:#fff;" +
      "font:13px/1.4 system-ui,sans-serif;padding:6px 10px;display:flex;gap:10px;align-items:center;flex-wrap:wrap";
    const text = document.createElement("span");
    text.textContent = "Demo mit simulierten Geräten. Änderungen bleiben nur in diesem Tab; WLAN- und Token-Einstellungen werden nicht gespeichert.";
    const reset = document.createElement("button");
    reset.type = "button";
    reset.textContent = "Demo zurücksetzen";
    reset.addEventListener("click", () => {
      try { session.removeItem(STORE_KEY); } catch (_) { /* nichts zu tun */ }
      location.reload();
    });
    bar.append(text, reset);
    document.body.append(bar);
  }
  document.addEventListener("DOMContentLoaded", banner);
})();
