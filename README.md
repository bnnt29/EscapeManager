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
| `src/protocol/` | Portable core: JSON, protocol handlers, secure transport, skeleton store, peer table, HTTP parser, mDNS codec. No Arduino, no sockets. |
| `src/net/` | Portable network layer on BSD sockets: non-blocking HTTP server/client, UDP, and `Device` (ties everything together). Runs on lwIP and on POSIX. |
| `src/esp/` | ESP32 platform layer: Wi-Fi, NVS, serial provisioning, mbedTLS backend, the `EscapeComponent` facade. |
| `src/manager/` | `manager.html` (the UI, one file) and its generated embedding (`ui_data.cpp`, `manager.html.gz`). |
| `src/sim/` | PC simulator and serial host (same core as the firmware). |
| `src/python/` | Python implementation of a device (for Raspberry Pi etc.). |
| `scripts/` | Tools: UI build, test vectors, reference client, hardware smoke test, maintenance over serial. |
| `test/` | `test_core` (PC **and** ESP32), `test_net` (PC), `python/`, `serial_host/`, `manager/` (headless browser), `tools/`, `fixtures/`. |

## Quick start

```sh
./run_sim.sh --http-port 8080            # PC simulator (needs g++ and libssl-dev)
open http://127.0.0.1:8080/              # the manager UI

pio run -e esp-dummy -t upload           # demo firmware with two simulated components (real Wi-Fi)
pio device monitor
```

Wi-Fi credentials never live in the repository. Either store them on the board
(`ESCAPE_WIFI_SSID=MyNet ESCAPE_WIFI_PASSWORD=secret pio run -e set-wifi`), or put build flags into the
untracked `secrets.ini` (template: `secrets.ini.example`). A host program that already connected Wi-Fi
needs neither: the library then simply uses that connection.

## Using the library in your own program

```ini
[env:firmware]
platform = espressif32@6.12.0
board = esp32dev
framework = arduino
lib_deps = https://github.com/bnnt29/EscapeManager.git
board_build.partitions = partitions.csv      ; your table; needs an NVS partition (see partitions.csv)
```

```cpp
#include "esp/client.hpp"                     // or "EscapeManager/src/arduino/client.hpp"

EscapeComponent component;

void setup() {
  uint8_t id = component.addComponent("Laser", "Room A", "laser-puzzle-v1");
  component.onActions(id, [](String out[], size_t max) { out[0] = "reset"; return (size_t)1; });
  component.onAction(id, [](const String &a) { return a == "reset"; });
  component.onPuzzle(id, [](uint16_t &step, uint16_t &total, String &state, bool &isHtml) {
    step = 2; total = 5; state = "step 2 of 5"; isHtml = false;
  });
  component.onPlanAction(id, [](PlanAction a) { return true; });   // lets the flow plan reset/complete it
  component.begin();                          // does not block
}

void loop() {
  component.loop();                           // cooperative and bounded; never delay()s
  // Whenever something a manager displays changed (puzzle step, error, ...):
  // component.markDirty();
}
```

The callbacks and their data are documented in `src/esp/client.hpp`. Names and rooms set by an operator
in the manager are stored on the board and override the defaults given in `addComponent`.

### Resource behaviour (the library lives inside another program)

* **CPU:** no extra FreeRTOS task. `loop()` is a bounded slice (HTTP I/O budget 4 ms per call); sockets
  are non-blocking; nothing calls `delay()`. The one-time key derivation in `begin()` takes ~230 ms.
* **Callbacks** (`onPuzzle`, `onAction`, ...) always run inside the caller's `loop()`, so host code needs no locking.
* **Memory:** the demo firmware (Arduino core + Wi-Fi + this library) uses 48.5 KB static RAM and 944 KB flash
  (`scripts/size_budget.json` guards both in CI). Per request the library allocates briefly on the heap
  (a status document is built in ~4 KB steps); plan skeletons (up to 6 KB) are read from NVS only when needed.
* **Ports:** HTTP on 80, UDP discovery on 4210, shared mDNS on 5353. A host program that already runs its own
  web server on port 80 or its own ESPmDNS must be configured accordingly (see `EscapeConfig.hpp`).
* **Serial:** while provisioning is enabled (default) the library reads every line from `Serial`. A host that
  reads `Serial` itself calls `component.setSerialProvisioning(false)`.
* **Battery:** `onBattery` returns percent; `0` or negative means "no battery / unknown" (mains powered). A
  device with an empty battery is switched off and cannot report it, so `0` is never displayed.

### Provisioning over serial (`scripts/device_storage.py`, no flashing)

| Command | Effect |
|---|---|
| `ESCAPE_AUTH_TOKEN='long-random-value' pio run -e update-auth-token` | Store an own token (8–128 printable ASCII characters; tools warn below 20) |
| `ESCAPE_WIFI_SSID=… ESCAPE_WIFI_PASSWORD=… pio run -e set-wifi` | Store Wi-Fi credentials |
| `pio run -e device-info` | Print device id, versions, token state, IP, heap |
| `ESCAPE_DEVICE_PORT=/dev/ttyACM0 pio run -e reset-persistent-storage` | Erase everything stored (port must be given explicitly) |

## Security in one page

Details in PROTOCOL.md section 5.7.

| | **Standard** (default token) | **Own token** |
|---|---|---|
| For | a closed escape-room network | shared or less trusted networks |
| Setup | none | provision a token on every device and enter it in the manager |
| Protects against | accidents, malformed or hostile input, replays | additionally: anyone who does not know the token |

Both levels use the same format: AES-256-GCM envelopes for writes (bound to device, path and time, with a
replay cache), HMAC frames for authenticated reads and UDP announcements. With the default token the key
is public (it is in this repository), so treat Standard as protection against mistakes, not against
people on your network. A device whose stored token is unreadable reports `token:"invalid"` and is read-only.
The manager shows a quiet badge while the default token is active.

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

## Mixed versions

Not every device is updated when the library is. The wire format changes only additively; every device
publishes `proto`, `pmin`, `fw`, `ui` and `uih`; unknown fields are ignored and preserved (PROTOCOL.md
section 1). The manager UI also upgrades itself: if any authenticated peer serves a newer UI, the page
downloads it, verifies its hash against the value the peer announced, caches it, and uses it from the next
load; a UI that fails to start is dropped and the served one is used (setting "Ausgelieferte Version
verwenden" turns this off).

## Development

```sh
pio test -e native                 # C++ core + network layer on the PC with ASan/UBSan (87 tests)
pio test -e esp32-test             # the same core tests on a connected ESP32 (mbedTLS backend)
python3 -m pytest test/python      # Python device (needs `pip install -r src/python/requirements.txt pytest`)
python3 test/serial_host/test_serial_host.py
node --test test/manager/          # crypto vectors + headless-browser tests (npm ci in test/manager first)
python3 test/tools/test_device_storage.py
node scripts/hw_smoke.mjs <deviceA> [<deviceB>]   # black-box check of real boards or simulators
```

Generated files are committed and checked in CI: `python3 scripts/build_ui.py` (UI embedding),
`node scripts/gen_vectors.mjs` (test vectors, generated by an implementation independent of the C++/Python
code), `node scripts/build_manager_crypto.mjs` (crypto bundle inside `manager.html`; `npm ci --prefix
tools/manager-crypto` first). Do not edit `ui_data.cpp` or `manager.html.gz` by hand.

**Releasing:** bump `EscapeVersion::FW`; if `manager.html` changed bump `UI_VERSION` in it **and**
`EscapeVersion::UI` together; run `python3 scripts/build_ui.py`. A new wire level adds
`test/fixtures/protoN/` (frozen) and keeps the previous two levels working.

Simulators and the Python device run on a PC: `./run_sim.sh`, `./run_serial_host.sh` (an Arduino without
Wi-Fi taking part through a USB serial line), `python3 src/sim/escape_component_sim.py`.
