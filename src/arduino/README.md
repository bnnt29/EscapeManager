# Arduino-Integration (ESP32)

`client.hpp` bindet die vollstaendige ESP32-Firmware aus `src/esp/client.hpp`
ein. Damit stehen WLAN, HTTP, UDP-Discovery, NVS und der sichere Transport
sofort bereit. `MbedTlsCryptoBackend` liefert P-256, HKDF, HMAC-SHA-256 und
AES-256-GCM fuer die geschuetzten Manager-POST-Endpunkte.

```cpp
#include "EscapeManager/src/arduino/client.hpp"

EscapeComponent component;

void setup() {
  // 3. Parameter (optional): Raetsel-ID - identifiziert die ART des Raetsels
  // (NICHT den in der UI angezeigten Namen), gleich fuer alle Geraete
  // desselben Raetseltyps (auch in verschiedenen Raeumen/als Ersatzgeraet).
  // Leer/weggelassen = einmalig zufaellig erzeugen (siehe client.hpp).
  uint8_t id = component.addComponent("Kamera-1", "Raum-A", "camera-puzzle-v1");
  component.onActions(id, [](String out[], size_t) { out[0] = "reset"; return 1; });
  component.onAction(id, [](const String &action) { return action == "reset"; });
  component.begin();
}

void loop() {
  component.loop();
}
```

Dieser Adapter setzt einen ESP32 mit Arduino-Framework voraus. Andere
Arduino-Boards brauchen ein eigenes WLAN-/HTTP-/UDP-Backend sowie P-256- und
AES-GCM-Kryptographie, damit sie den sicheren Transport korrekt anbieten koennen.
