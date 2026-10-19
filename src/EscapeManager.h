#pragma once

// EscapeManager - connects an ESP32 program to the EscapeManager browser UI (see README.md, PROTOCOL.md).
//
//   #include "arduino_secrets.h"      // optional: #define ESCAPE_WIFI_SSID "..." etc. (see below)
//   #include <EscapeManager.h>
//
//   EscapeComponent component;
//
//   void setup() {
//     uint8_t id = component.addComponent("Laser", "Room A");
//     component.onAction(id, [](const String &a) { return a == "reset"; });
//     component.begin();                // does not block; Wi-Fi connects in the background
//   }
//   void loop() { component.loop(); }   // cooperative, never delay()s
//
// Secrets (all optional - without any, the board opens its own setup Wi-Fi where you enter them):
//   Define them BEFORE this include (Arduino's usual arduino_secrets.h), or call the setters of EscapeComponent
//   before begin(), or - PlatformIO - pass -DESCAPE_... build flags (secrets.ini):
//     ESCAPE_WIFI_SSID, ESCAPE_WIFI_PASSWORD     Wi-Fi to join (password empty = open network)
//     ESCAPE_AUTH_TOKEN                          shared token of the installation (default: public token)
//     ESCAPE_EDIT_TOKEN                          only holders may send plans to devices
//     ESCAPE_SETUP_AP_PASSWORD                   WPA2 password of the setup Wi-Fi (default: open)
//     ESCAPE_HOST_MANAGED_WIFI 1                 the sketch manages Wi-Fi itself
//   Whatever is stored on the device (setup form, network push, serial command) wins over these.

#include "esp/client.hpp"

// A library is compiled WITHOUT the sketch's #defines (Arduino IDE: no build flags at all), so the sketch's
// translation unit hands them over here, at start-up, before setup() runs. The registry is a function-local
// static of the library (safe against static initialisation order); values that are not defined are empty and
// change nothing. Compile-time length checks for the same values are in protocol/EscapeConfig.hpp.
namespace EscapeManagerSketch {
__attribute__((unused)) static const bool kSketchConfigRegistered = Escape::registerSketchConfig(
    ESCAPE_WIFI_SSID, ESCAPE_WIFI_PASSWORD, ESCAPE_AUTH_TOKEN, ESCAPE_EDIT_TOKEN, ESCAPE_SETUP_AP_PASSWORD,
    ESCAPE_HOST_MANAGED_WIFI != 0);
} // namespace EscapeManagerSketch
