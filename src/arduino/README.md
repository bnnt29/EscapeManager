# Arduino integration (ESP32)

New code includes `<EscapeManager.h>` (one level up, `src/EscapeManager.h`); the headers in this folder are kept so older sketches
that include `EscapeManager/src/arduino/client.hpp` or `arduino/client.hpp` still compile. `client.hpp` pulls in the complete ESP32 library from `src/esp/client.hpp`: Wi-Fi (in the
background), HTTP server, UDP discovery, shared mDNS name, NVS persistence and the secure
transport. See the top-level README for the integration guide and resource behaviour.

```cpp
#include <EscapeManager.h>

EscapeComponent component;

void setup() {
  // 3rd parameter (optional): puzzle-type id. Identifies the KIND of puzzle (not the name shown
  // in the UI) and is the same on every device of that puzzle type, also across rooms and for
  // replacement boards. Empty = generated once and persisted.
  uint8_t id = component.addComponent("Camera-1", "Room-A", "camera-puzzle-v1");
  component.onActions(id, [](String out[], size_t) { out[0] = "reset"; return (size_t)1; });
  component.onAction(id, [](const String &action) { return action == "reset"; });
  component.begin();      // does not block; Wi-Fi connects in the background
}

void loop() {
  component.loop();       // cooperative, bounded; never calls delay()
  // call component.markDirty() whenever something a manager displays changed
}
```

Requires an ESP32 with the Arduino framework. Other boards use the serial host
(`extras/sim/escape_component_serial_host.cpp`, see `run_serial_host.sh`), which runs on a PC.
