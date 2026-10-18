# HARDWARE_TODO – everything that still has to be verified on real ESP32 boards

Context for whoever continues (also future-me): the proto-2 rewrite (branch `rework/proto2`) was developed
while two ESP32 boards were connected; they were disconnected before the work was finished. Everything that
can be simulated is covered by automated tests (see README → Development). This file lists what **cannot** be
simulated and was **not** (or only partly) verified on hardware, with exact commands and acceptance criteria.
Work through it top to bottom; tick items in this file as you go and commit the result.

## 0. State of the two boards when they were disconnected

| Board | Port (Linux) | Chip | Device id (MAC) | Flash content now |
|---|---|---|---|---|
| A | `/dev/ttyACM0` | ESP32-D0WD-V3 rev 3.1 | `e05a1bd04a04` | `esp-dummy` from an **early** proto-2 build (UI hash `4c5df11a` = the old, pre-proto-2 manager UI). **Outdated; reflash.** |
| B | `/dev/ttyACM1` | ESP32-D0WD-V3 rev 3.0 | (not recorded) | The Unity test runner of `pio test -e esp32-test` (from before the network layer existed). **Reflash.** |

Both boards still hold NVS data written by the *old* firmware (`escfg` namespace in `plan_nvs`: names, rooms,
riddle ids, tokens if any). The keys the new code uses (`name<i>`, `room<i>`, `riddle<i>`, `plan<i>`,
`authtoken`) are the same, the obsolete `planskel` blob is deleted on first start. To test from a clean state
run `ESCAPE_DEVICE_PORT=… pio run -e reset-persistent-storage` (needs the **new** firmware to be running).

Wi-Fi: the development network was used via the untracked `secrets.ini`
(`-DESCAPE_WIFI_SSID/-DESCAPE_WIFI_PASSWORD`); recreate it from `secrets.ini.example` or provision with
`pio run -e set-wifi`. The credentials were removed from git history (rewritten), but the router password was
**not** changed – see the note at the end of this file.

Toolchain notes: use PlatformIO's Python with `intelhex` (`~/.platformio/penv/bin/python -m pip install intelhex`;
the packaged esptool needs it on Python 3.14). The pinned platform is `espressif32@6.12.0` (Arduino-ESP32 2.0.17).

## 1. What WAS verified on hardware (baseline numbers)

Measured with the demo firmware on board A and the Unity runner on board B before they were disconnected.
**Caveat: these predate several later changes** (eviction of idle/draining HTTP connections, replay cache 80,
separate UDP rate limiter, serial-provisioning fix, final UI), so treat them as a baseline to compare against.

| Item | Result |
|---|---|
| Unity core tests on the ESP32 (`pio test -e esp32-test`, mbedTLS backend) | 71/71 passed (JSON, base64, crypto/transport, skeleton store, peers, HTTP parser, mDNS codec, rate limiter, protocol handlers) |
| Wi-Fi connects in the background, `begin()` returns immediately | OK |
| Authenticated `GET /status.json`, `/security.json`, UI download with matching hash, secure `POST /action` | OK (Node reference client `scripts/em_client.mjs`) |
| Wrong token | reads fail the MAC check, writes get 401 |
| Hostile input (12 KB JSON array, deep nesting, binary garbage, body > 12 KB, 100 KB body) | 400/413, **no reboot** (the old firmware aborted and rebooted on a 3 KB array) |
| Free heap after boot / after hostile input | 245 KB / min 220 KB (old firmware: 197 KB / 188 KB) |
| Static RAM / flash of the demo firmware | 48.5 KB / 944 KB (old: 78.8 KB / 986 KB) |
| `loop()` duration (idle) | avg 0.12–0.16 ms, max 5–9 ms (old: avg 1.0 ms, max 6 ms) |
| Loop-task stack high-water mark | min 4748 bytes free of 8192 after fixing a 4 KB stack temporary (before the fix: 1308 bytes on `GET /status.json`) |
| Crypto timings (spike) | PBKDF2-HMAC-SHA256: 1000 it = 112 ms (2048 it ≈ 230 ms); AES-256-GCM 4 KB = 3.2 ms; HMAC-SHA256 4 KB = 1.6 ms; ECDH P-256 ≈ 190 ms per scalar multiplication (this is why ECDH was dropped) |

## 2. Reflash and run the automated hardware checks (do this first)

```sh
cd /path/to/EscapeManager && git checkout rework/proto2          # or main once merged
cp secrets.ini.example secrets.ini && $EDITOR secrets.ini       # or provision with `pio run -e set-wifi`
~/.platformio/penv/bin/pio test -e esp32-test --upload-port /dev/ttyACM1 --test-port /dev/ttyACM1
~/.platformio/penv/bin/pio run -e esp-dummy -t upload --upload-port /dev/ttyACM0
~/.platformio/penv/bin/pio run -e esp-dummy -t upload --upload-port /dev/ttyACM1
```

* [ ] `esp32-test`: all tests pass (currently 71 in `test/test_core`; the suite also runs on the PC).
* [ ] Serial monitor shows `EscapeManager 2.0.0 (proto 2) did=… token=default components=2`, then `Wi-Fi up, IP …`.
* [ ] Find both IPs (serial `[stats]`/log, router, or `pio run -e device-info`) and run the black-box suite:

```sh
node scripts/hw_smoke.mjs <ipA> <ipB> --mdns          # ~2 minutes; exit code 0 = all checks passed
node scripts/hw_smoke.mjs <ipA> <ipB> --soak 60       # also keeps polling for 60 minutes (latency drift, reboots)
```

  The suite checks versions/limits, MAC-verified reads, UI hash and `304`, secure writes, wrong token, stale
  timestamp (`409 stale_time`), 404/405, latency, hostile inputs (must not reboot), 3 idle connections not
  blocking real requests, slowloris dropped, **discovery between the two boards** and **skeleton sync between
  them** (same room needed: both dummies use room `Dummy-Raum`), stale-writer `409 rev_conflict`, and (with `--mdns`)
  resolution of `escapemanager.local`. It passes 58/58 against two PC simulators; any failure on hardware is a
  real difference between lwIP/ESP32 and the PC.
* [ ] `[stats]` lines on the serial console while the suite runs: **free heap min ≥ 150 KB, loop-task stack HWM ≥ 3000 bytes,
  `loop max` ≤ 20 ms** (typical ≤ 10 ms). Record the numbers here: ______________________________

## 3. Items that were never run on hardware

### 3.1 Shared mDNS name (the "any device can be the server" requirement) – spike S1
The library answers `A` queries for `escapemanager.local` with its own address as a *shared* record (cache-flush bit
cleared, TTL 15 s, random 20–120 ms delay, known-answer suppression) instead of using ESP-IDF's mDNS, which renames
colliding hostnames (`_mdns_mangle_name` is in the linked `libmdns.a`). This has only been tested on the PC.
* [ ] Both boards running: `getent ahostsv4 escapemanager.local` and `avahi-resolve -4 -n escapemanager.local` return
  an address of a board (ideally both over repeated queries; resolvers often return only the first).
* [ ] Power off the board that answers; within ~15–30 s (TTL) the name resolves to the other board and
  `http://escapemanager.local/` loads from it (hard-reload the page; the already open manager page keeps working through its other devices).
* [ ] Client matrix (note result per client): Linux (avahi / systemd-resolved), macOS, iOS/iPadOS Safari, Windows 10/11,
  Android Chrome (`.local` often does **not** resolve on Android – then use the device IP; the manager lists every device).
* [ ] Wi-Fi modem sleep: with the default power saving the board may miss multicast queries until the next DTIM. If the
  name is slow or flaky, rebuild with `-DESCAPE_WIFI_NO_SLEEP` (library-owned Wi-Fi only) and compare.
* [ ] Conflict with a host program that uses ESPmDNS: both bind UDP 5353 with SO_REUSE*; `DeviceOptions::mdnsPort = 0`
  turns the library's responder off. Verify the combination in the real host (jail_controller does not use ESPmDNS).
* [ ] After a Wi-Fi drop/reconnect the multicast group is re-joined (address change triggers it; verify also when the
  IP stays the same – lwIP must re-send the IGMP join when the netif comes back).
* If lwIP rejects `IP_ADD_MEMBERSHIP`/`IP_MULTICAST_IF` on the socket the serial log stays silent (mDNS is best effort):
  check `escapemanager.local` really resolves, do not assume.

### 3.2 Network layer on lwIP (src/net)
Written against the BSD socket API, tested on POSIX only. Verify on the board (most is covered by `hw_smoke`):
* [ ] `UdpSocket::openBroadcast` – `SO_REUSEPORT` may not exist on lwIP (guarded by `#ifdef`), `SO_BROADCAST` works, directed
  broadcast (`ip | ~mask`) reaches the other board (router/AP client isolation can block it – check the AP setting).
* [ ] `HttpClient` non-blocking `connect` (`EINPROGRESS`, `select()` + `SO_ERROR`) – used for skeleton sync. Sync between
  boards worked in `hw_smoke` ("skeleton synced A -> B")? If not, look here first.
* [ ] `HttpServer`: `accept`, `shutdown(SHUT_WR)` + draining, 2 connection slots, eviction of draining/silent connections.
  Open the manager page in Chrome and Firefox with 5+ devices and watch for `503`/aborted fetches in the console
  (speculative preconnects must not block real requests).
* [ ] Socket budget: lwIP defaults to 10 sockets (`CONFIG_LWIP_MAX_SOCKETS`). The library uses at most 6 (listen, 2 connections,
  UDP, mDNS, 1 client). With a host program that opens its own sockets check that `accept` does not start failing.
* [ ] Large responses: the UI (79 KB gzipped) is sent in 2.9 KB slices per `loop()` call – measure that a UI download does not stretch
  `loop()` beyond the budget (`[stats] loop max` while loading the page).

### 3.3 Wi-Fi ownership and reconnect (`HardwareEsp32::startWifi/service`)
* [ ] Library-owned: credentials from NVS (`pio run -e set-wifi`) → connects in the background; from build flags → connects.
* [ ] No credentials at all: `begin()` and `loop()` stay fast, log says "no Wi-Fi credentials", nothing blocks.
* [ ] Wrong password, then fix with `set-wifi`: recovers after the restart.
* [ ] Access point reboot while running: the board reconnects (driver auto-reconnect plus the 15 s → 60 s back-off in `service()`), announcements and
  mDNS resume, the manager shows the device again.
* [ ] Host-managed: a sketch that calls `WiFi.begin(...)` **before** `component.begin()` must be detected (`startWifi()` logs
  "using the host program's Wi-Fi connection" and never calls `WiFi.begin`/`WiFi.mode` itself). The detection
  heuristic (`WiFi.getMode() & STA` and status connected or non-empty SSID) is untested – also try a sketch that calls
  `WiFi.begin` *after* `component.begin()`.

### 3.4 NVS and persistence (`HardwareEsp32`, `SkeletonStore`)
* [ ] With the `partitions.csv` of this repo (`plan_nvs` present): names/rooms/riddle ids survive a reboot; a skeleton saved from the manager survives a reboot and
  is replicated; the boot counter increments (`status.json` → `boot`).
* [ ] **Without** a `plan_nvs` partition (default NVS is 20 KB): saving skeletons for several rooms eventually answers
  `500 storage_full` – confirm the manager shows a readable error and nothing else breaks.
* [ ] `reset-persistent-storage` clears both partitions; the board comes back with default token, default names, no skeletons; its
  announcements are ignored for ≤ 20 s (its boot counter restarted below the peers' remembered value) and then accepted.
* [ ] `token:"invalid"`: provision a token, then corrupt it (e.g. a tiny sketch doing `Preferences p; p.begin("escfg", false, "plan_nvs"); p.putString("authtoken","x");`),
  reboot: `/security.json` must say `"token":"invalid","writable":false`, writes → 503 `read_only`, the manager shows the problem badge.
* [ ] Power loss during a skeleton write (pull USB while saving repeatedly): afterwards the board still has either the old or the new skeleton (never none/garbage).
* [ ] Flash wear: `boot` and `plan<i>`/`name<i>` writes only happen on change/boot; confirm no write storms on the serial log during normal polling.

### 3.5 Serial provisioning with the real tools
`test/tools/test_device_storage.py` tests the script against a fake board; the real firmware side is untested.
* [ ] `pio run -e device-info` prints `ESCAPE_INFO_OK did=… fw=2.0.0 proto=2 token=… ip=… heap=…`.
* [ ] `ESCAPE_AUTH_TOKEN='a-long-random-token-1234' pio run -e update-auth-token` → board restarts, `token=custom`; the manager with the default token now shows
  "Token passt nicht" for that board and cannot read it; with the new token everything works. A mixed network (one board custom, one default) works only per token
  (UDP announcements of the other token are ignored – no peers) – confirm this is the behaviour you want.
* [ ] `set-wifi` stores credentials and the board uses them. `reset-persistent-storage` refuses without an explicit port.
* [ ] **Fixed just before disconnecting, never run on a board:** the serial reader used to stop at the first byte that was not `E` (a newline blocked it).
  It now consumes every line; the tool sends a leading `\n`. Confirm commands work when the host program prints/ignores Serial.
* [ ] A host sketch that reads `Serial` itself must call `component.setSerialProvisioning(false)`; verify its input is then untouched.

### 3.6 Security behaviour that needs real timing
* [ ] Replay: record a valid POST envelope (e.g. with `tcpdump` or by logging in `em_client.mjs`) and resend it: `409 replay`, and after 15 s `409 stale_time`.
* [ ] Clock handling: the manager takes the device clock from `/security.json`; confirm POSTs work right after boot and after the clock differs much from the PC (it must,
  the device clock starts at 0 on boot).
* [ ] Rate limits: a flood of POSTs with a wrong token (`for i in $(seq 100); do …`) gets `429`; legitimate requests from another host stay possible; the UDP limiter
  is separate (a spoofed UDP flood must not block a manager's POSTs).
* [ ] PBKDF2 key derivation in `begin()` takes ~230 ms with 2048 iterations – confirm the host's setup() tolerates it (watchdog, LED start-up animation).

### 3.7 Long runs
* [ ] 24 h soak: `node scripts/hw_smoke.mjs <ipA> <ipB> --soak 1440`; watch `[stats]` min free heap (no downward trend), no reboots, latency stable,
  peers stay discovered, no log spam.
* [ ] `millis()` wraps after 49.7 days. All time comparisons use unsigned/signed 32-bit arithmetic and are unit-tested across the wrap on the PC; a real
  wrap cannot be waited for. If wanted, build a variant that starts the clock near `0xFFFF0000` and watch the announcements, replay window and peer expiry.
* [ ] Memory with the maximum configuration: 4 components, every field at its limit (tip 512, state 1664, 8 actions, 4 custom configs, 512 B plan slice),
  fetch `status.json` in a loop – measure heap min and `loop max`.

### 3.8 Coexistence with the real host program (`/games/Projekte/jail_controller`)
`jail_manager.cpp` was compiled and linked against the new library on the PC build machine (no errors, only the host's own `Component::*` symbols were missing because the
LED code was left out). Not run on hardware:
* [ ] Flash jail_controller with the new library; puzzles work; the manager shows both components; `onBattery` returning `0` shows **no** battery badge (by design).
* [ ] The NeoPixel animations stay smooth while the manager polls (the HTTP slice budget is 4 ms per `loop()`; measure the longest gap between host loop iterations on the scope/serial).
* [ ] `markDirty()` is called by `syncEscapeManagerState()` every loop: cheap, but check that `seq` does not climb at 100 Hz (that would make every manager refetch constantly).
  If it does, the host should only call it on change.
* [ ] Its `platformio.ini` (already adapted by the owner) builds with PlatformIO under Python ≤ 3.13; under Python 3.14 even a project with only `NeoPixelBus` as dependency fails
  with "Python version must be between 3.10 and 3.13" (pioarduino platform), unrelated to this library.

### 3.9 UI self-upgrade across real devices
Only tested with PC simulators in Chromium.
* [ ] Build a second UI version (set `UI_VERSION = "2.0.1"` in `manager.html` **and** `EscapeVersion::UI`, run `python3 scripts/build_ui.py`), flash it on board B only. Open
  `http://<ipA>/` (old UI): banner "Neue Oberfläche 2.0.1 verfügbar" appears, reload swaps to 2.0.1, the settings dialog shows source "aus Cache".
* [ ] Verify the swap also in **Firefox** and **Safari** (the swap uses `document.open/write/close` after detaching the old document; only Chromium was tested).
* [ ] Break the cached UI on purpose (devtools: edit `localStorage["em.ui.cache"].html` so it throws) → next boot falls back to the served UI and never retries that hash.

### 3.10 Build variants not verified
* [ ] `pio run -e esp-dummy-arduino3` (Arduino-ESP32 3.x via pioarduino) – needs Python ≤ 3.13; never compiled. The library should compile with both cores; fix
  API differences (`esp_mac.h`, `WiFi` events, `Preferences`) if it does not.
* [ ] CI (`.github/workflows/ci.yml`) has never run on GitHub; check the first run (the `manager` job installs Chromium through `playwright-core`; the `secrets` job needs the
  gitleaks action).

## 4. Deliberately postponed / not implemented

* **OTA updates** (M9 in the plan): not implemented. The partition table keeps two OTA slots for the host program. A streaming, token-authenticated `POST /ota` and a
  version overview in the manager would fit the "fleet is never updated all at once" scenario.
* **Per-room skeleton cleanup** removes skeletons of rooms without a local component at start-up and after `/config` changes (`SkeletonStore::keepOnly`). The serial host works around
  `Device::begin()` doing this before its components are known (see the comment in `escape_component_serial_host.cpp`); a `DeviceOptions` flag would be cleaner.
* **HTTPS** is not offered (ESP32 resources); the manager page is plain HTTP and brings its own crypto because `crypto.subtle` is unavailable there.
* `HttpServer` has 2 connection slots (`EscapeConfig::MAX_HTTP_CONNECTIONS`); raising it costs a little RAM and a socket each – only if the browser test in 3.2 shows contention.
* A real-hardware variant of the network tests (`test/test_net` runs on the PC only). `scripts/hw_smoke.mjs` is the substitute.

## 5. Open points that are not hardware related

* **Git history:** the old Wi-Fi password was scrubbed from all commits and branches (`git filter-repo`), and the rewrite was force-pushed. Clones, forks and GitHub's cached
  commits may still contain it, and **the router password was deliberately not changed**; the leak is therefore not fully contained.
* The `main` branch is the pre-rewrite line; `rework/proto2` is the new line. Merge when the hardware checks above pass.
