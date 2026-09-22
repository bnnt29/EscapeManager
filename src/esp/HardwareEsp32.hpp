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
#include "../protocol/SecureTransport.hpp"
#include "MbedTlsCryptoBackend.hpp"

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiClient.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <Preferences.h>
#include <ESPmDNS.h>
#include <nvs_flash.h>

#include <functional>
#include <string>

class HardwareEsp32 {
public:
  HardwareEsp32();

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
  bool beginSecurity();
  bool securityReady() const { return _security.ready(); }
  bool secureWritesAvailable() const { return _security.secureWritesAvailable(); }
  std::string securityDocument() const { return _security.securityDocument(); }
  bool protectDocument(const std::string &context, const std::string &plaintext, std::string &out) const {
    return _security.protectDocument(context, plaintext, out);
  }
  bool unprotectDocument(const std::string &context, const std::string &document, std::string &out) const {
    return _security.unprotectDocument(context, document, out);
  }

  // ---- UDP-Broadcast ----------------------------------------------------------
  void sendBroadcast(const std::string &payload);
  // Ruft "onPacket(payload, senderIp)" fuer jedes eingegangene Paket auf,
  // hoechstens maxPackets pro Aufruf (Schutz vor Bursts - haelt loop() reaktionsfaehig).
  void pollIncoming(int maxPackets, const std::function<void(const std::string &, const std::string &)> &onPacket);

  // ---- HTTP-Server --------------------------------------------------------------
  // Registriert eine unauthentifizierte GET-Route fuer /security.json. CORS
  // wird nur fuer lokale Datei-, Loopback-, mDNS- und private IPv4-Urspruenge
  // freigegeben.
  void onGet(const char *path, const std::function<EscapeProtocol::HttpResult()> &handler);
  // Antwort wird an Pfad, HTTP-Status und eine vom Client gelieferte Nonce
  // gebunden. Ohne provisionierten Token bleibt der Endpunkt mit 503 gesperrt.
  void onAuthenticatedGet(const char *path, const std::function<EscapeProtocol::HttpResult()> &handler);
  // Registriert eine verschluesselte und authentifizierte POST-Route (inkl.
  // automatischer CORS-Preflight-Antwort auf OPTIONS). SecureTransport
  // entschluesselt die Huelle und prueft Token-HMAC + Replay-Schutz VOR dem
  // Aufruf; der handler bekommt nur HttpRequest{plaintext, true}.
  void onPost(const char *path, const std::function<EscapeProtocol::HttpResult(const EscapeProtocol::HttpRequest &)> &handler);
  // Registriert GET / -> liefert das per PlatformIO eingebettete manager.html.
  void serveManagerHtml();
  // In loop() aufrufen: bedient anstehende HTTP-Anfragen.
  void handleHttpClients();

  // ---- Persistenz (NVS via Preferences) ------------------------------------------
  std::string loadString(const char *key, const std::string &def);
  void saveString(const char *key, const std::string &value);
  std::string loadBlob(const char *key, const std::string &def);
  void saveBlob(const char *key, const std::string &value);

  // ---- Ausgehender HTTP-Client (Uptime-Abgleich mit Peers) -----------------------
  // Blockierendes GET auf http://ip:port/path (kurzer Timeout) - NUR fuer
  // den geraeteinternen Peer-/Skeleton-Abgleich gedacht (siehe
  // EscapeProtocol::findSkeletonSyncSource() und EscapeComponent::
  // reconcileWithPeers()), daher bewusst minimal (kein TLS/Redirects/
  // Chunked-Transfer-Encoding). "port" kommt vom jeweiligen Peer (siehe
  // PeerAddress::httpPort/PeerInfo::httpPort) statt fest EscapeConfig::
  // HTTP_PORT anzunehmen - echte ESP32-Geraete nutzen zwar immer Port 80,
  // aber der PC-Simulator erlaubt mehrere Instanzen mit unterschiedlichen
  // Ports auf derselben IP. Liefert false bei jedem Fehler (Verbindung/
  // Timeout/Statuscode != 200); "outBody" bleibt dann unveraendert.
  bool httpGet(const std::string &ip, uint16_t port, const char *path, std::string &outBody);

  // ---- Sonstiges -----------------------------------------------------------------
  std::string localIp() const;
  uint32_t nowMs() const; // = millis(), als duenner Wrapper (Konsistenz/Testbarkeit)
  uint32_t jitterOffsetMs() const { return _jitterOffsetMs; }
  // Stabile, von Name/Raum unabhaengige Board+Komponenten-Identitaet - siehe
  // Kommentar zu PeerInfo::uuid in Protocol.hpp. Faellt auf die eFuse-Chip-ID
  // zurueck, wenn WiFi.macAddress() keine brauchbare Adresse liefert (siehe .cpp).
  std::string macBasedUuid(uint8_t localComponentId) const;

  bool initNvsSafely();
  bool openPreferencesFixed();
private:
  WiFiUDP _udp;
  WebServer _server{EscapeConfig::HTTP_PORT};
  MbedTlsCryptoBackend _crypto;
  EscapeSecurity::SecureTransport _security;
  Preferences _prefs;
  uint32_t _jitterOffsetMs = 0;
  uint32_t _secureRequestWindowStartMs = 0;
  uint8_t _secureRequestCount = 0;
  bool _nvsReady = false;
  bool _mdnsStarted = false;

  // Empfaengt den vom PlatformIO-Target gesendeten Base64-Token, schreibt ihn
  // in den bestehenden "escfg"-NVS-Namespace und startet das Board neu.
  void pollSerialConfiguration();
  void processSerialConfigurationLine(const char *line);
  bool persistAuthToken(const std::string &authToken);
  bool clearPersistentStorage();
  bool allowSecureRequest();
  bool ensurePreferencesNamespace(bool readOnly);
  void ensureMdnsRunning();

  IPAddress broadcastAddress() const;
};
