# EscapeManager wire protocol, level 2 ("proto 2")

This document is the normative description of everything that travels between
devices (ESP32 firmware, C++ simulator, Python component) and managers
(`manager.html`). Code that disagrees with this document is wrong. The shared
test vectors in `test/fixtures/proto2/` are generated from it by an
independent implementation (`scripts/gen_vectors.mjs`, Node's crypto) and are
checked by every implementation.

All integers are unsigned unless noted. All text is UTF-8. `b64u` is base64url
without padding (canonical: unused trailing bits must be zero).

## 1. Compatibility contract

Proto 2 is a clean baseline: there is no compatibility with pre-2 firmware.
From here on every release follows these rules; fleets are **not** guaranteed
to run a single version.

1. Every device publishes `proto` (highest wire level it speaks), `pmin`
   (lowest it still accepts), `fw` (firmware semver) and `ui`/`uih` (version and
   hash of its embedded `manager.html`).
2. The outer frame field `v` of every envelope is the protocol level used for
   that frame. Receivers accept `pmin <= v <= proto`. Senders use the highest
   level supported by both sides (`min(own proto, peer proto)`), provided it is
   `>=` the peer's `pmin`; otherwise the peer is shown read-only as "too new/old".
3. Changes are additive: unknown fields are ignored everywhere (devices, managers,
   Python); fields are never removed or retyped inside the support window; new
   endpoints are advertised in `caps` and a manager treats a `404` for an
   endpoint it does not strictly need as "unsupported", not as an error.
4. Opaque data (plan skeleton, component plan slice, custom config values) is
   stored and returned byte-for-byte. Managers must preserve unknown fields when
   they edit it. Skeletons carry `schema`; a manager that does not know a skeleton's
   `schema` opens it read-only and never overwrites it.
5. Skeleton convergence is decided by `(rev, hash)`, never by uptime or by who
   wrote last.
6. Persistent storage carries `nvsver`. Migrations only move forward, can be
   repeated, and keep their source data for one release so a downgrade still works.
7. Support window: a release speaks to the previous two proto levels
   (`pmin >= proto - 2`).
8. `test/fixtures/proto<N>/` is frozen when a level ships; CI runs current code
   against all supported levels.

## 2. Identity and counters

| Name | Meaning |
|---|---|
| `did` | Device id: 12 lowercase hex chars of the Wi-Fi MAC (fallback: eFuse MAC). One per board. |
| component `uuid` | `<did>-<index>` (stable per board+component). |
| component `riddleId` | Puzzle type id, set by the sketch or by the operator (max 32 chars). |
| `boot` | Persistent boot counter (increments once per boot, stored in NVS; random if storage fails). |
| `ctr` | Announcement counter, starts at 1 each boot. |
| `seq` | Change counter of the device, incremented whenever observable state changes (`markDirty`, events, mutations). |
| `time` / `t` | Device clock in milliseconds since boot, `uint32`, wraps after 49.7 days. Comparisons use signed 32-bit differences. |

## 3. Keys

```
token   = 8..128 printable ASCII (0x21..0x7e); default token = EscapeConfig::AUTH_TOKEN
master  = PBKDF2-HMAC-SHA256(token, salt = "EscapeManager/2/token", iterations = 2048, dkLen = 32)
k_req   = HKDF-SHA256(ikm = master, salt = "", info = "EM2 req",  L = 32)
k_resp  = HKDF-SHA256(ikm = master, salt = "", info = "EM2 resp", L = 32)
k_mac   = HKDF-SHA256(ikm = master, salt = "", info = "EM2 mac",  L = 32)
```

`iterations` is published as `kdf.iter` in `/security.json`; a manager uses the
published value (and refuses values above 100000).

### Token states
* `default`: no token provisioned; the public repository default is used. Fully
  functional, intended for a closed escape-room network.
* `custom`: provisioned over serial (`TOKEN` command / `pio run -e update-auth-token`)
  or at build time. Tokens shorter than 20 characters are accepted (minimum 8)
  but managers and tools warn.
* `invalid`: a stored token exists but is unreadable or corrupt. The device is
  read-only (`writable:false`) and reports `token:"invalid"`; it does **not** fall
  back to the default token.

## 4. Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| GET | `/` | none | `manager.html` (gzip), `ETag: "<uih>"`, `Cache-Control: no-cache` |
| GET | `/security.json` | none | Versions, clock, KDF parameters, limits, token state |
| GET | `/status.json` | optional frame | Own components and device fields |
| GET | `/peers.json` | optional frame | Self plus discovered peers |
| GET | `/plan-skeleton.json` | optional frame | Index of stored room skeletons; `?room=<urlencoded>` returns one |
| POST | `/action` `/plan-action` `/config` `/plan` `/plan-skeleton` | AEAD envelope | Mutations |
| OPTIONS | any POST path | none | CORS preflight |

CORS: `Access-Control-Allow-Origin` is echoed only for the origins `null`,
`localhost`, loopback, `*.local`, and private IPv4 ranges (10/8, 172.16/12,
192.168/16). Requests without `Origin` are served.

### 4.1 Authenticated GET frame

A GET with query `nonce=<16..64 chars [A-Za-z0-9_-]>` is answered in this exact
byte layout (no whitespace anywhere outside `doc`):

```
{"doc":<DOC>,"mac":"<b64u 32 bytes>"}
mac = HMAC-SHA256(k_mac, "EM2|get|" + did + "|" + path + "|" + nonce + "|" + status + "|" + DOC)
```

`path` excludes the query string. `status` is the decimal HTTP status. A client
verifies by slicing the exact bytes between `{"doc":` and the last `,"mac":"`.
Without `nonce` the response is the bare `DOC` (viewer mode); a device in strict
mode (`EscapeConfig::STRICT_GET`) answers `401 {"code":"auth_required"}` instead.

### 4.2 POST envelope

Request body:
```
{"v":2,"t":<u32>,"iv":"<b64u 12 bytes>","ct":"<b64u ciphertext||tag16>"}
AAD  = "EM2|req|" + did + "|" + path + "|" + t
key  = k_req, AES-256-GCM, plaintext = JSON text of the command
```
The device checks in this order: size, frame fields, `|t - now| <= 15000 ms` (signed
32-bit), AEAD decrypt (tag verifies token, `did`, path, `t`), then the replay cache
(the 12-byte IV; 64 entries, kept for the time window, **fail closed**: when full
of fresh entries the request is refused with `429 rate_limited`). The IV enters
the cache only after the tag verified.

Response body (also for errors, as long as the IV could be read):
```
{"v":2,"iv":"<b64u 12 bytes, random>","ct":"<b64u ciphertext||tag16>"}
AAD  = "EM2|resp|" + did + "|" + path + "|" + <request iv b64u> + "|" + status
key  = k_resp, plaintext = response JSON
```
The HTTP status code equals `status`. Failures before the IV is readable (garbage,
oversized) produce an unauthenticated `{"ok":false,"code":...}`; a manager
shows these but never trusts or retries on them, except `auth_failed`, which is
reported as "token does not match".

If the device answers `409 stale_time` (authenticated, contains `time`), the
manager re-synchronises its clock offset from `time` and retries **once** with a
fresh IV.

### 4.3 UDP announcement (port 4210, broadcast)

```
{"doc":<DOC>,"mac":"<b64u>"}
mac = HMAC-SHA256(k_mac, "EM2|udp|" + DOC)
DOC = {"v":2,"did":"..","ip":"a.b.c.d","port":80,"boot":5,"ctr":123,"seq":17,
       "pmin":2,"uih":"1a2b3c4d","sk":[["<room8hex>",<rev>,"<hash8hex>"],...]}
```
Receivers drop packets larger than 600 bytes before any crypto work; require that
`ip` equals the datagram's source address; and keep, per `did`, the last
`(boot, ctr)`, accepting only strictly larger pairs (lexicographic). `sk` lists the
rooms for which the sender stores a skeleton. A peer entry expires
`PEER_TIMEOUT_MS` after its last accepted announcement.

## 5. Documents

### 5.1 `/security.json` (unauthenticated)
```
{"proto":2,"pmin":2,"fw":"2.0.0","ui":"2.0.0","uih":"1a2b3c4d","did":"..","time":123456,
 "token":"default|custom|invalid","writable":true,"strictGet":false,"allowTokenInUrl":true,
 "kdf":{"alg":"pbkdf2-sha256","iter":2048},"caps":["plan","cfg"],
 "limits":{"body":12288,"skeleton":6144,"plan":512,"name":32,"room":32,"riddle":32}}
```

### 5.2 `/status.json` DOC
```
{"proto":2,"pmin":2,"fw":"..","ui":"..","uih":"..","did":"..","ip":"..","port":80,
 "boot":5,"seq":17,"up":123456,"battery":87,"token":"default",
 "components":[ <component>, ... ]}
```
`battery` is omitted when there is no battery. By convention `0` and `-1` both mean
"no battery / unknown" (a device with an empty battery is switched off and cannot
report it); the firmware never sends values `<= 0`.

Component:
```
{"id":0,"uuid":"..","riddleId":"..","name":"..","room":"..",
 "errors":[".."],"actions":[".."],"planActions":["reset","complete"],
 "feed":"http(s)://..","tip":"..",
 "puzzle":{"step":1,"totalSteps":5,"state":"..","isHtml":false},
 "customConfig":[{"key":"..","type":"range|text|select","min":0,"max":9,"maxLength":8,"options":[".."],"value":".."}],
 "plan":{...opaque slice...},"evtSeq":3,"evtMsg":".."}
```
`feed`, `tip`, `puzzle`, `customConfig`, `plan`, `evtSeq`, `evtMsg` are optional.
`feed` must start with `http://` or `https://`.

### 5.3 `/peers.json` DOC
```
{"proto":2,"self":<entry>,"peers":[<entry>,...]}
entry = {"did":"..","ip":"..","port":80,"proto":2,"seq":17,"uih":"..","age":1200,"sk":[[room8,rev,hash8],...]}
```
`age` is milliseconds since the last accepted announcement (0 for `self`).

### 5.4 Plan skeleton

Stored per room (only for rooms with a local component). Blob:
`{"room":"..","rev":3,"hash":"<fnv1a32 of sk bytes, 8 hex>","sk":{...}}`

* `GET /plan-skeleton.json` DOC: `{"proto":2,"rooms":[{"room":"..","rev":3,"hash":".."}]}`
* `GET /plan-skeleton.json?room=R`: the blob; `404 {"code":"no_plan"}` if absent.
* `POST /plan-skeleton` plaintext: `{"room":"..","baseRev":N,"sk":{...}}`. The device
  stores it as revision `N+1` iff its current revision equals `N` (a room without a
  stored skeleton has revision 0). Otherwise `409 {"code":"rev_conflict","rev":cur,"hash":".."}`,
  except when the posted `sk` has the same hash as the stored one: then `200` with the
  current revision (idempotent retry). `422 room_not_hosted` if no local component
  is in that room. `413` if `sk` exceeds the limit.
* The room key is `fnv1a32(room UTF-8)` as 8 hex chars (`room8` in `sk` lists).
* Sync: if a peer announces `(rev, hash)` for a room the device hosts and
  `(rev, hash) > (own rev, own hash)` lexicographically, the device fetches
  `GET /plan-skeleton.json?room=R` (authenticated frame), checks that `room`
  matches, recomputes `hash` from `sk` and stores the blob unchanged. Failures back
  off for 10 s per (peer, room).

### 5.5 Mutations (plaintext of the POST envelope)

| Path | Body | Success |
|---|---|---|
| `/action` | `{"id":0,"action":"open"}` | `200 {"ok":true}`; `422 {"ok":false,"code":"rejected"}` |
| `/plan-action` | `{"id":0,"action":"reset"\|"complete"}` | same; `422 unsupported` if not announced in `planActions` |
| `/config` | `{"id":0,"name":"..","room":"..","riddleId":"..","config":{"key":"value"}}` | `200 {"ok":true}`; everything is validated before anything is applied |
| `/plan` | `{"id":0,"plan":{...}\|null}` | `200`; `413` if `plan` exceeds 512 bytes |
| `/plan-skeleton` | see 5.4 | see 5.4 |

There are no blocking locks. Concurrent writers are detected through `seq`
(for status) and `rev`/`baseRev` (for skeletons).

### 5.6 Error body
`{"ok":false,"code":"<machine code>","error":"<short english text>"}` plus optional
fields (`rev`, `hash`, `time`). Codes: `bad_request`, `bad_id`, `bad_action`,
`unsupported`, `rejected`, `too_large`, `rev_conflict`, `room_not_hosted`,
`stale_time`, `replay`, `rate_limited`, `read_only`, `not_found`, `no_plan`,
`storage_full`, `auth_failed`, `auth_required`, `bad_envelope`. Managers translate codes
into text themselves.

## 6. Limits (`EscapeConfig`, mirrored in `/security.json` `limits`)

Body 12288 B (envelope) · skeleton 6144 B · plan slice 512 B · name/room/riddleId 32 ·
tip 512 · state 1664 · feed 96 · actions 8×24 · errors 4×32 · custom configs 4 ·
JSON depth 16 · JSON DOM nodes 160 (small bodies only; skeleton, plan and envelope
are scanned without building a tree) · POST rate: per-source token bucket plus a
global budget · peer table default 64 entries.

## 7. mDNS

Every device answers `A` queries for `escapemanager.local` with its own address as a
**shared record** (cache-flush bit cleared, TTL 15 s), so a client may hold several
addresses and fail over when one device disappears. Multicast answers are delayed
randomly by 20–120 ms; answers are suppressed when the query's known-answer section
already lists our address with at least half the TTL; queries with the unicast bit
get an immediate unicast answer. Devices never probe or rename.

## 8. Manager UI distribution

`/` serves the UI embedded in the firmware. A manager reads `ui`/`uih` from every
peer's authenticated `/status.json`. If a peer has a higher `ui` (semver compare),
the manager fetches `/` from that peer, verifies that `SHA-256(gunzipped body)`
starts with the authenticated `uih`, caches it in `localStorage`, and switches on
the next load. A start-up trial flag falls back to the served version if the new UI
fails to initialise.
