# HARDWARE_TODO – hardware verification record and what is still open

Two ESP32-D0WD-V3 boards (A: `e05a1bd04a04`, `/dev/ttyACM0`; B: `0cb81501c400`, `/dev/ttyACM1`) were used
with a real access point, the real `jail_controller` program, and Chromium and Firefox. Everything that can be
simulated is covered by automated tests (README → Development). This file records what was checked **on the
boards**, the bugs that checking found, and what is still open. Re-run any of it with the commands given.

Reproduce the basic flow:

```sh
cp secrets.ini.example secrets.ini && $EDITOR secrets.ini        # or: ESCAPE_WIFI_SSID=… ESCAPE_WIFI_PASSWORD=… pio run -e set-wifi
pio test -e esp32-test --upload-port <portB> --test-port <portB>  # core tests on the chip (80)
pio run -e esp-dummy -t upload --upload-port <portA>              # same for portB
node scripts/hw_smoke.mjs <ipA> <ipB> --mdns                      # black-box suite, ~2 min (59 checks)
```

Toolchain notes: PlatformIO's Python needs `intelhex` (`~/.platformio/penv/bin/python -m pip install intelhex`) on
Python 3.14; the pinned platform is `espressif32@6.12.0` (Arduino-ESP32 2.0.17). Never `pkill -f` while serial
loggers run: kill by PID. A `/dev/ttyACM*` port can be held in reset through the RTS line (this is how "power off"
was simulated).

## 1. Verified on hardware

### Functional
| Check | Result |
|---|---|
| Core unit tests on the chip (mbedTLS backend), including the mutation fuzzers and the exhaustive bit-flip sweep | 80/80 |
| `scripts/hw_smoke.mjs` with two boards | 59/59 (status/security/limits, MAC-verified reads, UI hash and `304`, secure writes, wrong token, stale timestamp, 404/405, hostile input, idle and slow clients, **discovery and skeleton sync between the boards over Wi-Fi**, `rev_conflict`, mDNS) |
| Real manager UI in Chromium against both boards | 4 components found, action reflected in 150–290 ms, 0 failed requests, 0 console errors |
| Shared mDNS record `escapemanager.local` | both boards answer (TTL 15 s, cache-flush bit clear); the resolver returns one of them |
| mDNS failover | board holding the name switched off (RTS) → name resolves to the other board and the page loads from it after **5.1 s** |
| Rejoin | peer expires from the other board's list after 15–19 s; the board is accepted again **3.3–3.7 s** after release; the NVS boot counter persists across resets (28→29, 7→8) |
| Power loss during skeleton writes | 12 hard resets while writing continuously (~100 writes): never missing, corrupt, inconsistent or going backwards; no acknowledged write lost |
| Provisioning with the real tools | `device-info`, `set-wifi` (wrong password → no connection, no spam, loop unaffected; right password → on the network 4 s later), `update-auth-token`, `reset-persistent-storage` (refuses without an explicit port) |
| Custom token | reads fail the MAC, writes 401, boards ignore each other's announcements (mixed tokens = separate networks); the manager shows "Token passt nicht" and the problem badge |
| No Wi-Fi credentials at all | `begin()` returns at once, one log line, `loop()` avg 77 µs / max 0.15 ms |
| Host-managed Wi-Fi (`examples/host_wifi`) | both orders work (host connects before or after `component.begin()`); the library never overrides the host's connection |
| Security timing | exact replay → `409 replay`; same envelope 17 s later → `409 stale_time`; timestamp 1 h ahead refused; bad-token flood → `401` then `429`, recovers; 1000 junk UDP datagrams do not block POSTs from the same address |
| UI self-upgrade across boards | board A (UI 2.0.0) fetched UI 2.0.1 from board B in ~1 s, hash matched the authenticated announcement, no automatic swap, reload runs the cached UI against the real boards; works in **Chromium and Firefox** (`test/manager/manual_firefox_selfupgrade.py`) |
| Real host program `jail_controller` (copy with timing instrumentation, no LEDs/buttons attached) | builds against the library, runs, both components appear, its SVG puzzle displays render in the sandboxed iframe, battery returns 0 → no battery shown |
| 32-bit clock wrap (`scripts/hw_wrap_test.mjs`, env `esp-dummy-wrap`) | across the real wrap: writes before/after, a replay straddling it (`replay`, later `stale_time`), a timestamp that had already wrapped, an idle connection spanning it, peers alive, skeleton sync, both boards wrapping with 0 errors |
| Default NVS (no `plan_nvs` partition, env `esp-dummy-defaultnvs`) | about **one** 6 KB plan (or two ~3 KB) fit; further/larger writes → `500 storage_full`, stored plans stay intact, device healthy. The library prints a hint at start-up |

### Resources (esp-dummy, 240 MHz)
| Metric | Result |
|---|---|
| Static RAM / flash | 48.5 KB / 944 KB (before the rewrite: 78.8 KB / 986 KB) |
| Free heap | ~245 KB idle; lowest 196–216 KB under the black-box suite |
| `begin()` blocking time | **251 ms** (key derivation); was 602 ms before sockets were deferred until the network is up (the first `socket()` call blocks ~350 ms while the Wi-Fi stack starts, 1 ms afterwards) |
| `loop()` | idle avg 0.12–0.16 ms; serving a request up to ~16 ms; flash writes stall it 27 ms (small skeleton) to 70–81 ms (6 KB). Over 29 min: 4 windows above 20 ms, all explained by NVS writes |
| Loop-task stack | ≥ 4.3 KB free of 8 KB in every run (a 4 KB temporary was removed; before: 1.3 KB free) |
| 29-minute soak (2 boards polled every 2 s + a real manager page open) | 0 reboots, 0 failed reads in 641 polls per board, free heap drift +1.4 KB / −3.2 KB, latency stable, browser saw 4 devices throughout |
| Worst-case configuration (`esp-dummy-max`: 4 components, every text field at its limit, HTML state, 8 actions, 4 custom configs, 512 B plan slices, 6 KB skeletons) | status document 12.4 KB; heap never below 124 KB, largest free block ≥ 70 KB, stack ≥ 4.3 KB free; `loop()` worst 68 ms (document build + signing); 1–8 concurrent readers: **0 errors**, ~9 full documents/s, p95 ≤ 1.06 s at 8 clients |
| Latency of an idle device (request after 2 s of silence) | radio always on (default now): median 60 / 35 ms; with the default Wi-Fi modem sleep it was 244 / 48 ms |
| `jail_controller` loop | the host's own loop takes 41 ms (NeoPixel); the library adds avg 0.66–0.9 ms, spikes ≤ 10 ms idle and 22–29 ms under test traffic |

## 2. Bugs the hardware work found (all fixed, with tests where they can run on the PC)

1. **Host-managed Wi-Fi was not detected** while the host's connection was still being established
   (`WiFi.SSID()` only reports an *established* link): a library with its own credentials overrode the host's
   `WiFi.begin()`. Now detected through the driver's STA config.
2. **`markDirty()` called on every loop** (as `jail_controller` does) made `seq` climb at the loop rate (24/s) and
   the device announce every 300 ms forever. `markDirty()` is now a flag; at most every 500 ms the state is
   fingerprinted and `seq` bumps only on a real change (C++ and Python, with tests).
3. **HTTP server under concurrent clients:** Nagle + delayed ACK (worst full request 1389 → 332 ms,
   `TCP_NODELAY`), `503`/reset replies when all slots were busy (newcomers now wait in a listen backlog of 6),
   eviction of *fresh* silent connections caused `ECONNRESET` for 3+ clients (grace period of 1 s).
4. **First `socket()` call blocked ~350 ms** inside `begin()` (lwIP/Wi-Fi start): sockets now open when the
   network is up (`begin()` 602 → 251 ms); a taken HTTP port is reported once and retried every 5 s.
5. **Wi-Fi modem sleep** added 100–200 ms to the first request after a quiet moment: radio always on for
   library-owned Wi-Fi (opt-out `-DESCAPE_WIFI_ALLOW_SLEEP`).
6. **Deadlines initialised to 0 stalled features near the 32-bit clock wrap** (HTTP socket opening and the host
   hint check waited until the counter wrapped). Found by the wrap test; fixed with "armed" flags and covered by
   PC tests in C++ and Python.
7. The first host-change check counted as "nothing changed": a manager that had already seen `seq` 1 would not
   refetch. The first check now counts as a change.
8. Earlier: serial provisioning stopped at the first non-`E` byte; demo boards shared riddle ids (spurious
   room-conflict banner); the maintenance tool needed a leading newline.

## 3. Still open (needs equipment or access I did not have)

- **Wi-Fi link loss / access-point reboot.** The reconnect logic (driver auto-reconnect plus back-off 15 → 60 s in
  `HardwareEsp32::service`) is only exercised with a *wrong password*, not with a link that disappears and
  comes back. Needs control of the AP: unplug it for a minute and check that the boards reconnect, announce
  again and the manager shows them again; check that mDNS re-joins when the IP stays the same.
- **mDNS on other clients.** Only Linux (nss-mdns via `getent`, and a raw multicast query) was checked. Still to
  check: macOS, iOS/iPadOS, Windows 10/11 and Android Chrome (`.local` often does not resolve on Android: use the
  device IP; the manager lists every device). A shared record may return several addresses; resolvers often
  use only the first.
- **Safari / WebKit.** The UI swap and everything else was verified in Chromium and Firefox; the WebKit build
  from Playwright's cache needs system libraries (`libmanette`) that are not installed here.
- **Soak length and real 49.7-day wrap.** 29 minutes soak plus the accelerated wrap test; a 24 h soak
  (`node scripts/hw_smoke.mjs <ipA> <ipB> --soak 1440`, watch `[stats]` for a downward heap trend) was not run.
- **`jail_controller` on its real wiring** (LED strip, buttons, relays): the program was run on a bare dev board.
  Worth measuring with the real strip that animation timing stays smooth (the library adds avg < 1 ms with
  rare 10–30 ms spikes; NVS writes stall ~80 ms at most, only when an operator saves a plan).
- **Real power cuts / brown-out** (the tests used hard CPU resets through the RTS line, which also interrupts
  flash writes, but a collapsing supply can behave differently).
- **More than two devices on one network** (peer table 64 entries, announcement load, several browsers).
  8 concurrent clients on one board were fine; many boards were not available.
- **Battery operation with `-DESCAPE_WIFI_ALLOW_SLEEP`** (power draw and latency not measured).
- **`pio run -e esp-dummy-arduino3`** (Arduino-ESP32 3.x via pioarduino) needs PlatformIO under Python ≤ 3.13
  (this machine has 3.14 only); never compiled. Same limitation blocks `jail_controller`'s own `pio run` from
  resolving registry libraries here (unrelated to this library).
- **GitHub CI** (`.github/workflows/ci.yml`) has never run on GitHub; check the first run (the `manager` job
  installs Chromium through `playwright-core`; the `secrets` job needs the gitleaks action).
- **Long-term flash wear** (NVS write counts over weeks); the code writes only on change and once per boot.

## 4. Deliberately postponed / not implemented

* **OTA updates** (M9 in the plan): not implemented. The partition table keeps two OTA slots for the host program.
  A streaming, token-authenticated `POST /ota` and a version overview in the manager would fit the "fleet is
  never updated all at once" scenario.
* `SkeletonStore::keepOnly` runs in `Device::begin()`; the serial host works around that (its components arrive
  asynchronously). A `DeviceOptions` flag would be cleaner.
* **HTTPS** is not offered (ESP32 resources); the manager page is plain HTTP and ships its own crypto because
  `crypto.subtle` is unavailable there.
* `MAX_HTTP_CONNECTIONS` is 2 (the measured behaviour with 8 clients is queueing, not errors). Raise it only if
  the median latency under several browsers matters more than a socket each.
* TCP connections are not kept alive (`Connection: close`): a fresh connection per request pays TCP slow start
  (~150 ms for a 12 KB document, less for typical 3–6 KB ones). The manager mostly avoids this by refetching only
  when `seq` changes.

## 5. Not hardware related

* **Git history:** the old Wi-Fi password was scrubbed from all commits and branches (`git filter-repo`) and the
  rewrite was force-pushed. Clones, forks and GitHub's cache of old commits may still contain it, and **the
  router password was deliberately not changed**: the leak is not fully contained. A bundle of the original
  history was saved outside the repository.
* `main` is the pre-rewrite line; `rework/proto2` is the new line. Merge it when you are satisfied.
