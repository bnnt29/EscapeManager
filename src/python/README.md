# Python implementation (proto 2)

`escape_component.py` is a complete EscapeManager device in one file: a port of the C++ reference
(`src/protocol`, `src/net`) that implements [PROTOCOL.md](../../PROTOCOL.md) exactly - AES-256-GCM POST
envelopes, HMAC-framed GET documents and UDP announcements, replay protection, rate limiting, peer discovery,
plan-skeleton sync and the shared mDNS record. A Python component, an ESP32 and the C++ simulator
interoperate; `test/python/test_interop.py` proves it against the C++ simulator and `scripts/em_client.mjs`.

```sh
python3 -m pip install -r src/python/requirements.txt     # cryptography>=41.0 (AES-GCM); everything else is stdlib
```

## Using it

```python
from escape_component import EscapeComponent, PlanAction, CustomConfigDef   # or: from EscapeManager.src.python import ...

component = EscapeComponent(http_port=8080)                 # token: the public default; state in ~/.escape-manager/python-8080
laser = component.add_component("Laser-1", "Raum-A", "laser-v1")   # (name, room, riddle id = puzzle TYPE)

state = {"step": 0}
component.on_actions(laser, lambda: ["reset", "next_step"])
component.on_action(laser, lambda action: handle(action))          # True = executed
component.on_puzzle(laser, lambda: (state["step"], 5, "Schritt %d von 5" % state["step"], False))
component.on_errors(laser, lambda: [])
component.on_tip(laser, lambda: "Dreh den Schluessel")
component.on_battery(lambda: 87)                                    # <= 0 = no battery / unknown (not reported)
component.on_plan_action(laser, lambda action: True)                # announces reset + complete
component.on_custom_config(laser, lambda: [CustomConfigDef("brightness", "range", "50", 0, 100)])
component.on_custom_config_set(laser, lambda key, value: True)      # called AFTER validation against the schema

component.begin()          # derives the keys (PBKDF2, a few ms), opens HTTP / UDP / mDNS; raises OSError if the HTTP port is taken
try:
    while True:
        component.loop()   # cooperative and bounded: discovery, announcements, mDNS, skeleton sync; never blocks
        # ... your game logic; call component.mark_dirty() after observable changes, push_event(id, "text") for the log
finally:
    component.close()
```

`begin(background=True)` runs `loop()` in a thread for you. `EscapeComponent` is a context manager.

### Constructor

| Argument | Meaning |
|---|---|
| `auth_token` | `None` (or the public default) = token state `default`; any other text = `custom`. A token outside 8..128 bytes, or `token_state=TokenState.INVALID`, makes the device **read-only** (`writable:false`, `token:"invalid"`); it never falls back to the default token. Tokens < 20 characters work but log a warning. |
| `http_port`, `udp_port` | `udp_port=0` disables discovery. |
| `local_ip`, `broadcast_ip` | Announced address / broadcast target (default: the LAN address; loopback uses `127.255.255.255`). |
| `did` | 12 lowercase hex characters. Default: generated once (locally administered MAC style) and persisted. |
| `state_dir` / `storage` | Where boot counter, device id, component names/rooms, riddle ids, plan slices and skeletons live (`FileStorage`: one file per key, atomic temp-file + rename). Default `~/.escape-manager/python-<http_port>`; pass `storage=MemoryStorage()` for a volatile device. |
| `manager_html` | UI served at `/` (raw or gzip bytes/str). Served gzipped with `ETag: "<uih>"` (304 on `If-None-Match`); `uih` is the SHA-256 prefix of the **uncompressed** document. |
| `mdns_enabled`, `mdns_hostname`, `mdns_port` | Shared A record `escapemanager.local` (cache-flush bit cleared, TTL 15 s, 20-120 ms random delay, known-answer suppression, unicast answers for QU queries). |

`add_component(name, room, riddle_id=None)` returns the component id (0-based) or `255` beyond four components;
the `on_*` calls ignore invalid ids. Names and rooms an operator saved override the defaults, and the riddle id
is persisted on first start - `riddle-<16 hex>` unless you pass one (it is **not** derived from the board, so a
replacement board can be given the original's id).

Changes from the previous Python API: `add_component(name, room, riddle_id)` (the uuid is now `<did>-<index>`);
`PeerInfo`/`PeerAddress`/`status_changed` and the "lock until fetched" mechanism are gone (managers detect
concurrent writes with `seq` and `rev`/`baseRev`); `peers()` returns `PeerEntry` objects.

### Threading and robustness

* HTTP runs in worker threads: at most 8 connections (the 9th is answered `503`), header block <= 1024 B
  (`431`), per-path body limit decided from `Content-Length` **before** any body byte is read (`413`; garbage or
  negative lengths are `400`), idle timeout 5 s, whole-request timeout 10 s, `Connection: close`, `Expect:
  100-continue`, `HEAD`/`OPTIONS`, CORS exactly as `originAllowed` in `src/protocol/Http.cpp`. Every handler
  failure becomes a JSON `500` (authenticated if the request was), never a dropped connection.
* One re-entrant lock protects all shared state (replay cache, skeleton store, peers, `seq`, components).
  **Your callbacks run while it is held**: keep them short, and do not wait for another thread that calls back
  into the component. Exceptions in callbacks are logged and treated as "nothing/rejected".
* UDP datagrams > 600 bytes or not starting with `{"doc":` are dropped before any parsing or crypto; `OSError`s
  while sending/receiving never stop `loop()`. Skeleton sync runs in one short-lived worker thread (3 s deadline,
  10 s back-off per peer and room), so `loop()` never blocks.
* POST rate limit: per-source token bucket (burst 12, one token per 250 ms; failed authentication costs 4) plus
  30 POSTs/s globally. Replay cache: 64 IVs, fail closed (`429 rate_limited`), entries only after the tag verified.

### Library pieces (all importable from `escape_component`)

`SecureTransport` (both device and manager side: `seal_request`, `open_response`, `open_document_frame`, ...),
`derive_keys`, `b64u_encode/decode` (strict), `fnv1a32`, `SkeletonStore`, `PeerTable`, `parse_announcement`,
`parse_mdns_query/build_mdns_answer`, `HttpServer`, the handlers `handle_action/_plan_action/_config/_plan/_plan_skeleton`
and the document builders. `find_fields` is the raw-slice scanner (like `EscapeJson::findField`): skeletons, plan
slices and config values are stored and returned byte for byte, never re-serialised.

## Simulator

`src/sim/escape_component_sim.py` has the command line of the C++ simulator (`--http-port --udp-port --did --ip
--broadcast --component NAME:ROOM[:RIDDLE] --token --manager-html --state-dir --no-mdns --mdns-port
--mdns-hostname --battery --total-steps --html-state`; run it with `--help`):

```sh
python3 src/sim/escape_component_sim.py --http-port 8080
python3 src/sim/escape_component_sim.py --http-port 8081 --did 111111111111 --component Tuer:Raum-B:door-v1
```

## Tests

```sh
python3 -m venv /tmp/opencode/pyenv && /tmp/opencode/pyenv/bin/pip install cryptography pytest
/tmp/opencode/pyenv/bin/python -m pytest test/python -q
```

`test_crypto.py` checks every vector of `test/fixtures/proto2/vectors.json` byte for byte (key schedule, POST
envelope, response envelope, GET frame, UDP frame, FNV-1a, base64url strictness) plus tamper/replay/stale/wrong
path/wrong did cases; `test_protocol.py`/`test_store.py` mirror the C++ handler and store tests;
`test_http.py` is the hardening suite (oversized bodies without reading, garbage lengths, slow clients,
connection limit, 200 junk UDP datagrams); `test_discovery.py` runs several devices in one process;
`test_interop.py` needs `node` and the C++ simulator (skipped with the build command otherwise).
In-process tests use HTTP ports 9100-9199 and the shared discovery port 14210 with a random per-run token.
