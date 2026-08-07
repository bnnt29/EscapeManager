#pragma once

// Kapselt SAEMTLICHE ESP32-/Arduino-spezifische Hardware-Zugriffe: WLAN-
// Verbindung, UDP-Sockets, HTTP-Server, NVS-Persistenz (Preferences), mDNS.
//
// Kennt das EscapeManager-Protokoll selbst NICHT (kein JSON-Parsing, keine
// Validierung, keine Peer-Tabelle - siehe dazu Protocol.hpp) - bietet nur
// generische Bausteine (Broadcast senden/empfangen, HTTP-Routen registrieren,
// Key/Value-Strings persistieren), auf denen client.cpp aufbaut. Das ist die
// Kehrseite von Protocol.hpp: dort lebt die Logik OHNE jede Hardware-
// Abhaengigkeit, hier lebt die Hardware OHNE jede Protokoll-Kenntnis - beides
// trifft sich erst in client.cpp/EscapeComponent zusammen.
//
// Einziger Grund, warum diese Datei ueberhaupt Protocol.hpp inkludiert: die
// HttpRequest/HttpResult-Typen, damit onGet()/onPost() direkt die von
// Protocol.hpp erwarteten/gelieferten Typen verwenden koennen, statt sie an
// der Schnittstelle nochmal zu duplizieren.

#include "../protocol/Protocol.hpp"

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <Preferences.h>
#include <ESPmDNS.h>

#include <functional>
#include <string>

class HardwareEsp32 {
public:
  // WiFi.mode(WIFI_STA) - danach ist WiFi.macAddress() lesbar, OHNE dass
  // bereits eine tatsaechliche Verbindung besteht (wird fuer macBasedUuid()
  // VOR connectWifi() gebraucht, siehe EscapeComponent::begin()).
  void initWifiInterface();

  // Baut die tatsaechliche WLAN-Verbindung auf (blockierend, 15s Timeout) und
  // startet danach den UDP-Socket + berechnet den pro Geraet fixen
  // Broadcast-Jitter (siehe jitterOffsetMs()).
  void connectWifi();

  // NACH Registrierung aller Routen (onGet/onPost/serveManagerHtml) aufrufen.
  void beginHttpServer();
  void beginMdns();

  // ---- UDP-Broadcast ----------------------------------------------------------
  void sendBroadcast(const std::string &payload);
  // Ruft "onPacket(payload, senderIp)" fuer jedes eingegangene Paket auf,
  // hoechstens maxPackets pro Aufruf (Schutz vor Bursts - haelt loop() reaktionsfaehig).
  void pollIncoming(int maxPackets, const std::function<void(const std::string &, const std::string &)> &onPacket);

  // ---- HTTP-Server --------------------------------------------------------------
  // Registriert eine unauthentifizierte GET-Route, die JSON liefert (inkl.
  // Access-Control-Allow-Origin: * - fuer /status.json und /plan-skeleton.json).
  void onGet(const char *path, const std::function<EscapeProtocol::HttpResult()> &handler);
  // Registriert eine per X-Auth-Token authentifizierte POST-Route (inkl.
  // automatischer CORS-Preflight-Antwort auf OPTIONS) - handler bekommt
  // bereits ein fertiges HttpRequest{body, authOk}, die eigentliche
  // Token-Pruefung (constantTimeEquals gegen EscapeConfig::AUTH_TOKEN)
  // passiert VOR dem Aufruf.
  void onPost(const char *path, const std::function<EscapeProtocol::HttpResult(const EscapeProtocol::HttpRequest &)> &handler);
  // Registriert GET / -> liefert das per PlatformIO eingebettete manager.html.
  void serveManagerHtml();
  // In loop() aufrufen: bedient anstehende HTTP-Anfragen.
  void handleHttpClients();

  // ---- Persistenz (NVS via Preferences) ------------------------------------------
  std::string loadString(const char *key, const std::string &def);
  void saveString(const char *key, const std::string &value);

  // ---- Sonstiges -----------------------------------------------------------------
  std::string localIp() const;
  uint32_t nowMs() const; // = millis(), als duenner Wrapper (Konsistenz/Testbarkeit)
  uint32_t jitterOffsetMs() const { return _jitterOffsetMs; }
  // Stabile, von Name/Raum unabhaengige Board+Komponenten-Identitaet - siehe
  // Kommentar zu PeerInfo::uuid in Protocol.hpp. Faellt auf die eFuse-Chip-ID
  // zurueck, wenn WiFi.macAddress() keine brauchbare Adresse liefert (siehe .cpp).
  std::string macBasedUuid(uint8_t localComponentId) const;

private:
  WiFiUDP _udp;
  WebServer _server{EscapeConfig::HTTP_PORT};
  Preferences _prefs;
  uint32_t _jitterOffsetMs = 0;

  IPAddress broadcastAddress() const;
};
