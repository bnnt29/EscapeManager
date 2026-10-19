// A host program that OWNS the Wi-Fi connection and uses EscapeManager next to it (opt-in).
//
// By default the library owns the station: it connects with the credentials stored on the device and
// opens a setup network when it cannot. A host that manages Wi-Fi itself says so, either with the build
// flag -DESCAPE_HOST_MANAGED_WIFI=1 (as in this example's environment) or with
// component.useHostManagedWifi() BEFORE component.begin(). The library then never calls WiFi.begin(),
// WiFi.mode() or opens an access point; reconnect handling stays the host's job. The order of the host's
// WiFi.begin() and component.begin() does not matter.
//
//   pio run -e host-managed-wifi -t upload
//
// The host's credentials come from -DESCAPE_WIFI_SSID / -DESCAPE_WIFI_PASSWORD (secrets.ini): in this mode
// the library itself ignores them. Tokens (normal and edit token) are still configurable over the network.
#include "../../src/esp/client.hpp"
#include <WiFi.h>

EscapeComponent component;
static uint16_t g_step = 0;

static void hostConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(EscapeConfig::WIFI_SSID, EscapeConfig::WIFI_PASSWORD);
  Serial.println("[host] WiFi.begin() called by the host program");
}

void setup() {
  Serial.begin(115200);
  uint8_t id = component.addComponent("Host-Wifi-Test", "Host-Raum", "host-wifi-test");
  component.onActions(id, [](String out[], size_t) -> size_t { out[0] = "next_step"; return 1; });
  component.onAction(id, [](const String &a) -> bool { if (a == "next_step") { g_step++; return true; } return false; });
  component.onPuzzle(id, [](uint16_t &step, uint16_t &total, String &state, bool &isHtml) {
    step = g_step; total = 9; state = "Schritt " + String(g_step); isHtml = false;
  });
  component.useHostManagedWifi(); // same as -DESCAPE_HOST_MANAGED_WIFI=1
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
