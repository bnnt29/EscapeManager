// HostManagedWifi - EscapeManager next to a sketch that OWNS the Wi-Fi connection itself (opt-in).
//
// By default the library owns the Wi-Fi station: it connects with the credentials stored on the board and opens
// a setup network when it cannot. A sketch that manages Wi-Fi ITSELF says so with component.useHostManagedWifi()
// (or `#define ESCAPE_HOST_MANAGED_WIFI 1` before the include) BEFORE component.begin(): the library then never calls
// WiFi.begin() or WiFi.mode() and opens no setup network; reconnecting stays the sketch's job. The order of the
// sketch's WiFi.begin() and component.begin() does not matter. Tokens remain configurable over the network.
//
// This sketch connects with ESCAPE_WIFI_SSID / ESCAPE_WIFI_PASSWORD from arduino_secrets.h.
//   PlatformIO:  pio run -e host-managed-wifi -t upload
#include "arduino_secrets.h"
#include <EscapeManager.h>
#include <WiFi.h>

EscapeComponent component;
static uint16_t g_step = 0;

static void hostConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(ESCAPE_WIFI_SSID, ESCAPE_WIFI_PASSWORD);
  Serial.println("[host] WiFi.begin() called by the sketch");
}

void setup() {
  Serial.begin(115200);
  uint8_t id = component.addComponent("Host-Wifi-Test", "Host-Raum", "host-wifi-test");
  component.onActions(id, [](String out[], size_t) -> size_t { out[0] = "next_step"; return 1; });
  component.onAction(id, [](const String &a) -> bool { if (a == "next_step") { g_step++; return true; } return false; });
  component.onPuzzle(id, [](uint16_t &step, uint16_t &total, String &state, bool &isHtml) {
    step = g_step; total = 9; state = "Schritt " + String(g_step); isHtml = false;
  });
  component.useHostManagedWifi(); // same as #define ESCAPE_HOST_MANAGED_WIFI 1
  hostConnect();
  component.begin();
}

void loop() {
  static uint32_t maxUs = 0, last = 0;
  const uint32_t t = micros();
  component.loop();
  const uint32_t d = micros() - t;
  if (d > maxUs) maxUs = d;
  if (millis() - last >= 10000) {
    last = millis();
    Serial.printf("[host] status=%d ip=%s heap=%u loop max=%luus\n", (int)WiFi.status(), WiFi.localIP().toString().c_str(),
                  (unsigned)ESP.getFreeHeap(), (unsigned long)maxUs);
    maxUs = 0;
  }
}
