// A host program that OWNS the Wi-Fi connection and uses EscapeManager next to it.
//
// The library never calls WiFi.begin()/WiFi.mode() when the station is already set up by
// the host, and it takes the host's connection as it is (reconnect handling stays the
// host's job). Two orders are possible and both are supported:
//
//   HOST_WIFI_ORDER 1  host connects first, then component.begin()   (library detects it)
//   HOST_WIFI_ORDER 2  component.begin() first (library has no credentials and waits),
//                      the host connects later
//
//   pio run -e host-wifi-first -t upload      pio run -e host-wifi-after -t upload
//
// Give credentials to only ONE of the two (host or library): with both, order 2 lets whichever
// calls WiFi.begin() last win.
//
// The credentials of THE HOST come from -DHOST_WIFI_SSID/-DHOST_WIFI_PASSWORD (secrets.ini);
// these environments deliberately remove the library's own build-time credentials so only
// the host's connection can work.
#include "../../src/esp/client.hpp"
#include <WiFi.h>

#ifndef HOST_WIFI_ORDER
#define HOST_WIFI_ORDER 1
#endif
#ifndef HOST_WIFI_SSID
#define HOST_WIFI_SSID ""
#endif
#ifndef HOST_WIFI_PASSWORD
#define HOST_WIFI_PASSWORD ""
#endif

EscapeComponent component;
static uint16_t g_step = 0;

static void hostConnect() {
  WiFi.mode(WIFI_STA);
  WiFi.begin(HOST_WIFI_SSID, HOST_WIFI_PASSWORD);
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
#if HOST_WIFI_ORDER == 1
  hostConnect();
  component.begin();
#else
  component.begin();
  hostConnect();
#endif
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
