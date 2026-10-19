# EscapeManager

EscapeManager connects ESP32-based escape-room components to a browser manager. Every component
(a board running this library inside your own program) serves the manager UI itself, announces
itself over UDP, and answers authenticated requests. There is **no central server**: the browser
opens `http://escapemanager.local/` (every device answers for that name), discovers all other
devices through the one it reached, and talks to each of them directly. If the device it started
from goes away, the page keeps working through the others.

```
 browser ── http://escapemanager.local ──► any device (serves UI, /peers.json, /status.json, ...)
    │                                         ▲ UDP discovery (broadcast, authenticated)
    └──► polls every discovered device ───────┘ plan skeletons are replicated between devices
```

* **Wire protocol:** [PROTOCOL.md](PROTOCOL.md) (normative; proto 2).
* **Hardware to-do list / what still needs checking on real boards:** [HARDWARE_TODO.md](HARDWARE_TODO.md).

## Repository layout

| Path | Content |
|---|---|
| `src/EscapeManager.h` | The header a sketch includes. Everything below `src/` is the library (the Arduino IDE compiles all of it). |
| `src/protocol/` | Portable core: JSON, protocol handlers, secure transport, skeleton store, peer table, HTTP parser, mDNS codec. No Arduino, no sockets. |
| `src/net/` | Portable network layer on BSD sockets: non-blocking HTTP server/client, UDP, and `Device` (ties everything together). Runs on lwIP and on POSIX. |
| `src/esp/` | ESP32 platform layer: Wi-Fi (with the setup network), NVS, serial provisioning, mbedTLS backend, the `EscapeComponent` facade. |
| `src/manager/` | `manager.html` (the UI, one file) and its generated embedding (`ui_data.cpp`, `manager.html.gz`). |
| `extras/sim/` | PC simulator and serial host (same core as the firmware). Not part of the Arduino/PlatformIO library. |
| `extras/python/` | Python implementation of a device (for Raspberry Pi etc.). |
| `examples/` | Sketches in Arduino IDE layout: `Minimal`, `EspDummy`, `HostManagedWifi`, `Diagnostics`. |
| `scripts/` | Tools: UI build, test vectors, reference client, hardware tests, maintenance over serial (`scripts/pio_shims/` lets PlatformIO build the example sketches). |
| `library.properties`, `library.json`, `keywords.txt` | Metadata for the Arduino Library Manager and the PlatformIO registry. |
| `tools/setup/` | `setup.html`: configure Wi-Fi and tokens of a board over USB from the browser (Web Serial, no PlatformIO). |
| `graphify-out/` | Knowledge graph of the code base (see "Browsing the code" below). |
| `test/` | `test_core` (PC **and** ESP32), `test_net` (PC), `python/`, `serial_host/`, `manager/` (headless browser), `tools/`, `fixtures/`. |

## Installation

Works on every **ESP32 with Wi-Fi**: ESP32, ESP32-S2, ESP32-S3, ESP32-C3 and ESP32-C6 (the H2 and P4 have no Wi-Fi radio),
with Arduino-ESP32 **2.0.17 and 3.x** (the C6 needs 3.x). All of them are compile-tested with both cores in CI; so far the library has run
on a classic ESP32. Nothing has to be configured except your secrets - and even those are optional.

### Arduino IDE (no PlatformIO needed)

1. **Board support:** *Boards Manager* → "esp32 by Espressif Systems" (2.0.17 or any 3.x).
2. **Library:** *Sketch → Include Library → Add .ZIP Library…* with the ZIP of this repository (GitHub → *Code → Download
   ZIP*). Once the library is registered, *Library Manager* → "EscapeManager" does the same.
3. **Sketch:** *File → Examples → EscapeManager → Minimal*. Choose your ESP32 board under *Tools → Board*; the default
   *Partition Scheme* is fine (the firmware needs about 1.1 MB of the 1.25 MB app slot with core 3.x on a classic ESP32,
   0.95 MB with 2.0.17; RISC-V chips such as the C3 and C6 need about 1.2 MB with core 3.x).
4. **Secrets (optional):** open the `arduino_secrets.h` tab and fill in what you have, e.g.
   ```cpp
   #define ESCAPE_WIFI_SSID     "MyNetwork"
   #define ESCAPE_WIFI_PASSWORD "my wifi password"
   #define ESCAPE_AUTH_TOKEN    "a-long-random-token-of-your-own"
   ```
   Leave everything empty and the board opens its own Wi-Fi `EscapeSetup-<id>` after start-up: join it with a phone, a form
   opens, enter Wi-Fi and tokens there (see "Configuring Wi-Fi and tokens without reflashing").
5. **Upload**, then open `http://escapemanager.local/` (or the board's IP address) in a browser on the same Wi-Fi.

The sketch, the three ways to give secrets and their order are the same for PlatformIO. What the Arduino IDE cannot do, and what
replaces it:

| PlatformIO | Arduino IDE |
|---|---|
| `-DESCAPE_*` build flags / `secrets.ini` | `#define`s before `#include <EscapeManager.h>` (usually `arduino_secrets.h`), or `component.setWifi()` / `setAuthToken()` / `setEditToken()` / `setSetupApPassword()` before `begin()` |
| `pio run -e set-wifi`, `update-auth-token`, ... | the setup network, the manager's *Geräte-Setup*, or `tools/setup/setup.html` (USB, Chrome/Edge) |
| custom `partitions.csv` in `platformio.ini` | put a `partitions.csv` next to the sketch (verified with both cores); optional, see "Plan storage" |

### PlatformIO

```ini
[env:firmware]
platform = espressif32@6.12.0         ; Arduino-ESP32 2.0.17. For 3.x use the pioarduino platform (see platformio.ini)
board = esp32dev                      ; or esp32-s3-devkitc-1, esp32-c3-devkitm-1, ...
framework = arduino
lib_deps = https://github.com/bnnt29/EscapeManager.git      ; bnnt29/EscapeManager once registered
; build_flags = -DESCAPE_WIFI_SSID=\"MyNetwork\" -DESCAPE_WIFI_PASSWORD=\"secret\" -DESCAPE_AUTH_TOKEN=\"...\"
```

Put `examples/Minimal/Minimal.ino` into `src/main.ino` (or `main.cpp` with `#include <Arduino.h>`) and build. For secrets
keep a `secrets.ini` that is not committed:

```ini
; platformio.ini:   extra_configs = secrets.in[i]      (glob: no error when the file is missing)
; secrets.ini:      see secrets.ini.example in this repository
```

### Secrets: where they come from

Every secret is optional and is looked up in this order, **the first match wins**:

| # | Source | Set with |
|---|---|---|
| 1 | **Stored on the device** | the setup form, the manager's *Geräte-Setup*, serial commands (`set-wifi`, `update-auth-token`, ...) |
| 2 | **The sketch** | `#define ESCAPE_WIFI_SSID "..."` etc. before `#include <EscapeManager.h>` **or** the setters on `EscapeComponent` before `begin()` |
| 3 | **The build** (PlatformIO) | `-DESCAPE_WIFI_SSID=...` flags, e.g. from the untracked `secrets.ini` |
| 4 | Default | public token, no edit token, open setup Wi-Fi, no Wi-Fi credentials (= setup Wi-Fi) |

| Secret | `#define` / `-D` | Setter | Rule |
|---|---|---|---|
| Wi-Fi name, password | `ESCAPE_WIFI_SSID`, `ESCAPE_WIFI_PASSWORD` | `setWifi(ssid, password)` | name 1..32 bytes; password empty (open network) or 8..63 |
| Token of the installation | `ESCAPE_AUTH_TOKEN` | `setAuthToken()` | 8..128 printable characters, no spaces (>= 20 recommended) |
| Plan-edit token | `ESCAPE_EDIT_TOKEN` | `setEditToken()` | same |
| Setup Wi-Fi password | `ESCAPE_SETUP_AP_PASSWORD` | `setSetupApPassword()` | empty = open (default), else 8..63 |

A `#define` that is too long or too short is a **compile error** (`static_assert`); a setter returns `false` and prints the reason on
`Serial`. A secret that is given but unusable is never replaced by something weaker: an unusable token leaves the device
read-only, an unusable edit token locks plan sending, an unusable setup-Wi-Fi password means the setup Wi-Fi is not opened. Use only
letters, digits and `- _ .` in values that go through `-D` (the compiler command line); `#define`s and setters accept any text.
Other options (`component.setSetupButtonPin()`, `allowWifiSleep()`, `useHostManagedWifi()`) exist as setters and, for PlatformIO, as
`-D` flags (`ESCAPE_SETUP_BUTTON_PIN`, `ESCAPE_WIFI_ALLOW_SLEEP`, `ESCAPE_HOST_MANAGED_WIFI`).

### Boards that are not an ESP32

An Arduino Uno/Nano/Mega has no Wi-Fi and far too little RAM for the network stack. It can still take part through a PC: the PC
runs `extras/sim/escape_component_serial_host.cpp` (`./run_serial_host.sh`) and the Arduino only exchanges JSON lines over USB
(protocol in the header of that file).

## Quick start

```sh
./run_sim.sh --http-port 8080            # PC simulator (needs g++ and libssl-dev)
open http://127.0.0.1:8080/              # the manager UI

pio run -e esp-dummy -t upload           # demo firmware with two simulated components (real Wi-Fi)
pio device monitor                       # each shows a picture of its steps in the manager (next_step / solve / reset / toggle_error)
```

Nothing secret lives in the repository. For this repository's own PlatformIO environments, everything that must not be committed goes
into **one untracked file, `secrets.ini`** (copy `secrets.ini.example`): Wi-Fi name and password, the token, the plan-edit token and an
optional password for the setup network. The maintenance tools and hardware test scripts read the same `[secrets]` section as their
defaults. A board that cannot reach its Wi-Fi is configured without reflashing (next sections).

## Using the library in your own program

```cpp
#include "arduino_secrets.h"                  // optional: #define ESCAPE_WIFI_SSID "..." and the other secrets
#include <EscapeManager.h>                    // (older sketches: "esp/client.hpp" or "arduino/client.hpp" still work)

EscapeComponent component;

void setup() {
  uint8_t id = component.addComponent("Laser", "Room A", "laser-puzzle-v1");
  component.onActions(id, [](String out[], size_t max) { out[0] = "reset"; return (size_t)1; });
  component.onAction(id, [](const String &a) { return a == "reset"; });
  component.onPuzzle(id, [](uint16_t &step, uint16_t &total, String &state, bool &isHtml) {
    step = 2; total = 5; state = "step 2 of 5"; isHtml = false;
  });
  component.onPlanAction(id, [](PlanAction a) { return true; });   // lets the flow plan reset/complete it
  component.begin();                          // ~250 ms once (key derivation), then returns; Wi-Fi comes up in the background
}

void loop() {
  component.loop();                           // cooperative and bounded; never delay()s
  // Whenever something a manager displays MAY have changed (puzzle step, error, ...):
  // component.markDirty();                   // cheap at ANY rate, even on every loop() iteration
}
```

The callbacks and their data are documented in `src/esp/client.hpp`. Names and rooms set by an operator
in the manager are stored on the board and override the defaults given in `addComponent`.

### Resource behaviour (the library lives inside another program)

* **CPU:** no extra FreeRTOS task, no `delay()`, non-blocking sockets. Measured on an ESP32 at 240 MHz:
  `loop()` averages 0.1–0.2 ms when idle; serving a request costs up to ~16 ms in one call (an authenticated
  status document is built and signed). Writing to flash is the exception: saving a plan skeleton or
  renaming a component stalls the calling `loop()` for 25 ms (small) to ~80 ms (6 KB) because flash erase
  suspends the core. That only happens when an operator presses *Save*. `begin()` blocks ~250 ms once (key
  derivation; ~500 ms when an edit token is set, which derives a second key set); sockets are opened when the
  network is up, not in `begin()`.
* **Callbacks** (`onPuzzle`, `onAction`, ...) always run inside the caller's `loop()`, so host code needs no locking.
* **`markDirty()` is a hint, not a counter:** it only sets a flag. At most every 500 ms the library compares a
  fingerprint of the component state with the last announced one and bumps the change counter (and announces)
  only if something really differs. A host that calls it on every loop iteration (as `jail_controller` does)
  therefore costs ~1.6% CPU and causes no extra network traffic; a host that never calls it is simply not
  noticed until a manager polls.
* **Memory:** the demo firmware (Arduino core 2.0.17 + Wi-Fi + this library) uses 49.1 KB static RAM and 986 KB flash
  (`scripts/size_budget.json` guards both in CI); ~245 KB heap stays free. Per request the library allocates
  briefly on the heap (a ~4 KB component snapshot at a time); plan skeletons (up to 6 KB) are read from NVS
  only when needed.
* **Plan storage:** with the `plan_nvs` partition from `partitions.csv` (64 KB) up to 4 rooms x 6 KB fit.
  Without it (the Arduino IDE's default partition schemes) everything shares the 20 KB default NVS, which holds only about **one**
  6 KB plan (or two of ~3 KB): further writes are answered with `500 storage_full` and nothing already stored is damaged. To get the
  room, copy `partitions.csv` into the sketch folder (Arduino IDE) or set `board_build.partitions` (PlatformIO); the library
  finds the partition by name.
* **Ports:** HTTP on 80, UDP discovery on 4210, shared mDNS on 5353. If the HTTP port is taken by another server
  the library says so on `Serial` and retries every 5 s. A host that runs its own ESPmDNS can turn the shared
  record off (`DeviceOptions::mdnsPort = 0`).
* **Wi-Fi:** the library owns the station: it connects in the background with the credentials stored on the
  device (setup form, push, `set-wifi`) or from the build (`secrets.ini`), retries with back-off and opens the
  setup network when it cannot connect (above; it costs ~6 KB of heap while it is up and never blocks
  `loop()`). A host that manages Wi-Fi itself opts out (`-DESCAPE_HOST_MANAGED_WIFI=1`). The library keeps the
  radio awake (no modem sleep): sparse requests then answer in ~40 ms instead of 50-250 ms. Battery-powered
  devices opt out with `-DESCAPE_WIFI_ALLOW_SLEEP`.
* **Serial:** while provisioning is enabled (default) the library reads every line from `Serial`. A host that
  reads `Serial` itself calls `component.setSerialProvisioning(false)`.
* **Battery:** `onBattery` returns percent; `0` or negative means "no battery / unknown" (mains powered). A
  device with an empty battery is switched off and cannot report it, so `0` is never displayed.

### Configuring Wi-Fi and tokens without reflashing

The Wi-Fi is guaranteed to exist, but a board may have no or wrong credentials, so there are four ways to set the
four settings (Wi-Fi name, Wi-Fi password, token, plan-edit token):

1. **Setup network (any phone, tablet or PC, no app).** A board that has no credentials, or cannot connect for
   30 s, opens its own Wi-Fi **`EscapeSetup-<device id>`** (e.g. `EscapeSetup-e05a1bd04a04`: unique per board,
   never derived from your router's name, so several failing boards open different networks) and keeps trying
   the real Wi-Fi in the background. Join it; the page `http://10.99.77.1/setup` opens by itself on most devices
   (DNS and the usual captive-portal probes point to it). It shows which device this is and has a form for the
   four settings (empty = unchanged). Wi-Fi is applied at once and the page shows the result; the setup network
   closes 15 s after the board connected. Only the setup page is reachable from it, nothing of the game.
   **The setup network is open by default**: anyone in range can change the settings while the board has no
   Wi-Fi. For a WPA2 network set `setup_ap_password` in `secrets.ini` (`-DESCAPE_SETUP_AP_PASSWORD`, 8-63
   characters). A board can also be forced into setup mode by holding its BOOT button for 1.5 s within 10 s
   after start (`-DESCAPE_SETUP_BUTTON_PIN=-1` disables it; do not hold it while resetting: that enters the
   flash bootloader).
2. **Network push from the manager.** *Geräte-Setup* in the manager changes the settings of the ticked boards one
   after another ("Alle auswählen" / "Keine auswählen" tick or untick the whole list; needs the edit token if a
   board has one). New Wi-Fi credentials are tried for 30 s; if the board does
   not connect it falls back to the previous ones, so a typo cannot cut off a fleet.
3. **USB from the browser:** open `tools/setup/setup.html` in Chrome or Edge (offline file, Web Serial).
4. **USB from PlatformIO** (`scripts/device_storage.py`, no flashing):

| Command | Effect |
|---|---|
| `ESCAPE_AUTH_TOKEN='long-random-value' pio run -e update-auth-token` | Store an own token (8–128 printable ASCII characters; tools warn below 20). Without the variable the `[secrets]` `auth_token` is used |
| `ESCAPE_EDIT_TOKEN='another-long-value' pio run -e update-edit-token` / `pio run -e clear-edit-token` | Store / remove the plan-edit token |
| `ESCAPE_WIFI_SSID=… ESCAPE_WIFI_PASSWORD=… pio run -e set-wifi` | Store Wi-Fi credentials (defaults from `secrets.ini`) |
| `pio run -e device-info` | Print device id, versions, token and edit-token state, IP, Wi-Fi state, heap |
| `ESCAPE_DEVICE_PORT=/dev/ttyACM0 pio run -e reset-persistent-storage` | Erase everything stored (port must be given explicitly) |

A host program that manages Wi-Fi itself opts out of all of this with `-DESCAPE_HOST_MANAGED_WIFI=1` (or
`component.useHostManagedWifi()` before `begin()`; see `examples/HostManagedWifi`): the library then never touches the
radio and opens no setup network.

## Security in one page

Details in PROTOCOL.md section 5.7.

| | **Standard** (default token) | **Own token** |
|---|---|---|
| For | a closed escape-room network | shared or less trusted networks |
| Setup | none | provision a token on every device (secrets.ini, setup form, push, serial) and enter it in the manager |
| Protects against | accidents, malformed or hostile input, replays | additionally: anyone who does not know the token |

Both levels use the same format: AES-256-GCM envelopes for writes (bound to device, path and time, with a
replay cache), HMAC frames for authenticated reads and UDP announcements. With the default token the key
is public (it is in this repository), so treat Standard as protection against mistakes, not against
people on your network. A device whose stored token is unreadable reports `token:"invalid"` and is read-only.
The manager shows a quiet badge while the default token is active.

**Plan-edit token.** A second token decides who may *send plans to devices* (and change Wi-Fi/tokens over the
network). Everything else (reading, actions, configuration) stays on the normal token. The manager can always
edit plans locally - create, change, import, export - but without the edit token the changes are never sent to a
device, so they are lost when the page is reloaded; the page says so. A device without an edit token behaves as
before (the normal token may send plans), which keeps mixed-version fleets working. Plans a device stores are
stamped with a MAC of the edit key, and devices with an edit token adopt plans from other devices only if the
stamp is valid, so nobody can plant a plan through a fake peer. It is its own key set (PROTOCOL.md 3.1): set it
in `secrets.ini` (`edit_token`), with `pio run -e update-edit-token`, the setup form or the manager.

## The flow plan ("Ablaufplan")

The manager can lay out a room's puzzles as layers, lanes and connections, with placeholders, plan variables
and reset/complete commands. The firmware does not interpret it:

* one **skeleton per room** (layers, lanes, placeholders, variables; ≤ 6 KB) is stored as an opaque JSON
  object with a revision and hash on every device that has a component in that room, and replicated between
  those devices. A save carries `baseRev`; if someone else saved in between the manager shows a conflict
  dialog ("Neu laden" / "Überschreiben");
* one small **slice per component** (≤ 512 B) holds its lane and connections;
* plan commands (`reset`, `complete`) are separate from free-form actions: a component announces them by
  registering `onPlanAction`. The manager marks placeholders completed automatically and activates connected
  components when their incoming steps are reached.

`riddleId` identifies the puzzle *type* (set in the sketch or by the operator), `uuid` the physical
board+component. To replace a broken board, give the replacement the same `riddleId` and put it in the same
room; the plan then matches it. The same `riddleId` twice in one room raises a conflict banner.

## Verified on hardware

Two ESP32-D0WD boards plus the real `jail_controller` program; the setup network, the edit token and the network
push were exercised on both boards (`scripts/hw_edit_test.mjs`, 38 checks, and a PC joining the setup networks). The
Arduino IDE route (ZIP library, `arduino-cli`, Arduino-ESP32 3.3.12, default partition table, secrets as `#define`s and
through the setters) ran on a board next to a PlatformIO/2.0.17 board as a mixed fleet, and both on-device test suites
pass with both cores;
details, numbers and what is still open in
[HARDWARE_TODO.md](HARDWARE_TODO.md). Highlights: `scripts/hw_smoke.mjs` passes 59/59 (discovery and skeleton
sync over Wi-Fi, hostile input without reboots), a 29-minute soak ran with no reboot and no failed read, the
32-bit millisecond clock wrap (49.7 days) was exercised in a minute on real boards, `escapemanager.local` fails over in ~5 s when the answering board
is switched off, skeletons survive 12 hard resets during writes without corruption, the boot counter persists,
provisioning (`set-wifi`, `update-auth-token`, `reset-persistent-storage`) works end to end, and the manager UI
self-upgrades across real boards in Chromium and Firefox.

## Mixed versions

Not every device is updated when the library is. The wire format changes only additively; every device
publishes `proto`, `pmin`, `fw`, `ui` and `uih`; unknown fields are ignored and preserved (PROTOCOL.md
section 1). The manager UI also upgrades itself: if any authenticated peer serves a newer UI, the page
downloads it, verifies its hash against the value the peer announced, caches it, and uses it from the next
load; a UI that fails to start is dropped and the served one is used (setting "Ausgelieferte Version
verwenden" turns this off).

## Development

```sh
pio test -e native                 # C++ core + network layer + mutation fuzzers on the PC with ASan/UBSan (125 tests)
pio test -e esp32-test             # the same core tests incl. fuzzers on a connected ESP32 (mbedTLS backend, 98 tests)
pio test -e esp32-test-esp         # on-device tests of the secrets precedence (stored > sketch > build > default, 8 tests)
python3 scripts/check_library.py   # Arduino + PlatformIO library layout, versions, examples (CI also runs arduino-lint and builds
                                   # every example with arduino-cli for core 2.0.17 and 3.x on ESP32, S2, S3, C3, C6)
python3 -m pytest test/python      # Python device (needs `pip install -r extras/python/requirements.txt pytest`)
python3 test/serial_host/test_serial_host.py
node --test test/manager/          # crypto vectors + headless-browser tests (npm ci in test/manager first)
node --test test/setup/            # the Web Serial setup page against a fake serial port
python3 test/tools/test_device_storage.py
node scripts/hw_smoke.mjs <deviceA> [<deviceB>]   # black-box check of real boards or simulators
node scripts/hw_wrap_test.mjs <ipA> <ipB>         # 32-bit clock wrap on two boards flashed with `-e esp-dummy-wrap`
node scripts/hw_edit_test.mjs <ipA> <ipB>         # edit token + network setup on two boards (restores them)
```

Generated files are committed and checked in CI: `python3 scripts/build_ui.py` (UI embedding),
`node scripts/gen_vectors.mjs` (test vectors, generated by an implementation independent of the C++/Python
code), `node scripts/build_manager_crypto.mjs` (crypto bundle inside `manager.html`; `npm ci --prefix
tools/manager-crypto` first). Do not edit `ui_data.cpp` or `manager.html.gz` by hand.

**Releasing:** bump `EscapeVersion::FW` **and** `version=` in `library.properties` **and** `"version"` in `library.json`
(`scripts/check_library.py` fails if they differ); if `manager.html` changed bump `UI_VERSION` in it **and**
`EscapeVersion::UI` together; run `python3 scripts/build_ui.py`. A new wire level adds
`test/fixtures/protoN/` (frozen) and keeps the previous two levels working.

**Publishing the library** (once, by the maintainer; nothing here has been done yet):

1. Merge `rework/proto2` into `main` and tag the release: `git tag -s v2.1.0 && git push origin v2.1.0` (the tag must equal `version=`).
2. **Arduino Library Manager:** the checks pass locally (`arduino-lint --library-manager submit --compliance strict <library folder>`).
   Add `https://github.com/bnnt29/EscapeManager` to `repositories.txt` of
   [arduino/library-registry](https://github.com/arduino/library-registry) with a pull request; later releases are picked up from
   new tags automatically.
3. **PlatformIO registry:** `pio pkg pack` shows what would be uploaded (about 440 KB; `export.exclude` in `library.json`), then
   `pio pkg publish` (needs a PlatformIO account; the owner is the account that publishes).
4. Check the licence entry: `library.properties`/`library.json` say `LGPL-2.1-only`, taken from the `LICENSE` file.

Simulators and the Python device run on a PC: `./run_sim.sh`, `./run_serial_host.sh` (an Arduino without
Wi-Fi taking part through a USB serial line), `python3 extras/sim/escape_component_sim.py`.

## Browsing the code (graphify)

`graphify-out/` holds a knowledge graph of the repository (`graph.json`, `GRAPH_REPORT.md`, `graph.html`) built
with [graphify](https://github.com/Graphify-Labs/graphify) from the source files (AST only, no LLM, no API key).
It lets an agent or a human ask structural questions without reading whole files:

```sh
pipx install graphifyy                    # once
graphify query "how does a POST become a command?"
graphify path "Device" "SecureTransport"
graphify explain "SkeletonStore"
graphify update .                         # after code changes (also done by the opencode plugin)
```

`AGENTS.md` tells coding agents to query the graph first; `.opencode/plugins/graphify.js` reminds opencode of it.
Caches and local state in `graphify-out/` are not committed.
