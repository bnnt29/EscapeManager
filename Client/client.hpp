#pragma once

// EscapeComponent: wiederverwendbare Firmware-Bibliothek fuer eine einzelne
// Escape-Room-Komponente (ESP32, Arduino-Framework/PlatformIO).
//
// Ziel: Ein neues Geraet braucht i.d.R. NUR Aenderungen in diesem Header
// (WLAN-Zugangsdaten, Auth-Token, Timings) sowie die Registrierung eigener
// Callbacks im Hauptskript (Sensordaten, Aktions-Logik). Netzwerk, Broadcast,
// HTTP-Server und Persistenz stecken vollstaendig in client.cpp.
//
// Die verwendeten APIs (WiFi.h, WiFiUdp.h, WebServer.h, Preferences.h) sind
// Teil des ESP32-Arduino-Cores. Preferences (NVS) ist ESP32-spezifisch - fuer
// andere Plattformen (z.B. ESP8266) muesste dieser Teil gegen EEPROM/LittleFS
// getauscht werden, der Rest (JSON-Protokoll, UDP, HTTP-Routen) ist bewusst
// auf Standard-Arduino-APIs beschraenkt und portierbar.

#include <Arduino.h>
#include <WiFi.h>
#include <WiFiUdp.h>
#include <WebServer.h>
#include <Preferences.h>
#include <ESPmDNS.h>
#include <functional>

namespace EscapeConfig {

  // ---- WLAN ---------------------------------------------------------------
  constexpr const char *WIFI_SSID = "EscapeRoom";
  constexpr const char *WIFI_PASSWORD = "changeme123";

  // ---- Sicherheit ---------------------------------------------------------
  // Gemeinsames Geheimnis fuer die gesamte Venue/Installation. Wird von jedem
  // Manager als "X-Auth-Token" Header bei /config und /action mitgeschickt.
  // WICHTIG: Ohne TLS (ESP32-HTTP ist Klartext) kann jeder im selben WLAN das
  // Token mitlesen. Mitigation: eigenes/isoliertes Venue-WLAN (WPA2/3, kein
  // Gast-Zugriff), Token nur fuer die Dauer der Veranstaltung gueltig,
  // Token vor Verteilung der Anlage austauschen.
  constexpr const char *AUTH_TOKEN = "changeme-venue-token";

  // ---- Ports ---------------------------------------------------------------
  constexpr uint16_t UDP_PORT = 4210;
  constexpr uint16_t HTTP_PORT = 80;

  // ---- Hostname/Auto-Discovery ---------------------------------------------
  // Alle Komponenten einer Venue registrieren denselben mDNS-Hostnamen. Da
  // jede Komponente dieselbe manager.html + status.json (inkl. aller Raeume)
  // ausliefert, landet ein Manager beim Aufruf von http://<MDNS_HOSTNAME>.local/
  // automatisch auf irgendeiner (der zuerst antwortenden, also praktisch
  // zufaellig/naeheliegenden) erreichbaren Komponente - ohne feste IP/Gateway.
  // mDNS funktioniert nur innerhalb desselben L2-Netzsegments (wie UDP-Broadcast).
  constexpr const char *MDNS_HOSTNAME = "escapemanager";

  // ---- Broadcast-Timing (Schutz vor WLAN-Ueberlastung) ---------------------
  // Regulaeres Intervall pro Komponente. Ein zufaelliger, pro Geraet fixer
  // Jitter (0..HEARTBEAT_JITTER_MS) verhindert, dass alle Komponenten exakt
  // synchron senden (z.B. wenn alle gleichzeitig eingeschaltet werden).
  constexpr uint32_t HEARTBEAT_INTERVAL_MS = 4000;
  constexpr uint32_t HEARTBEAT_JITTER_MS = 750;
  // Bei Zustandsaenderungen (markDirty()) wird sofort broadcastet, aber
  // hoechstens alle CHANGE_MIN_GAP_MS - verhindert Flooding bei schnellen
  // aufeinanderfolgenden Aenderungen.
  constexpr uint32_t CHANGE_MIN_GAP_MS = 300;
  // Nach dieser Zeit ohne Broadcast gilt eine andere Komponente als offline
  // und wird aus der eigenen Peer-Tabelle (und damit /status.json) entfernt.
  constexpr uint32_t PEER_TIMEOUT_MS = 20000;

  // ---- Kapazitaeten ---------------------------------------------------------
  // ESP32 hat nur begrenzt RAM: feste Obergrenzen statt dynamischer
  // Allokation, damit Speicherverbrauch unabhaengig von Netzwerkinhalten und
  // der (variablen, nie garantiert vollstaendigen) Anzahl gleichzeitig
  // eingeschalteter Komponenten vorhersagbar bleibt.
  constexpr size_t MAX_PEERS = 24;
  constexpr size_t MAX_NAME_LEN = 32;
  constexpr size_t MAX_ROOM_LEN = 32;
  constexpr size_t MAX_ERRORS = 4;
  constexpr size_t MAX_ERROR_LEN = 32;
  constexpr size_t MAX_ACTIONS = 8;
  constexpr size_t MAX_ACTION_LEN = 24;
  constexpr size_t MAX_FEED_LEN = 96;
  constexpr size_t MAX_STATE_LEN = 512;

  // ---- Custom Konfiguration pro Komponente -----------------------------------
  // Jede Komponente kann eine kleine Liste eigener Konfigurationsfelder (z.B.
  // Helligkeit, Anzeige-Text, Schwierigkeitsgrad) per Broadcast/status.json
  // bekanntgeben. Der Manager rendert daraus die Raum-Konfiguration und schickt
  // neue Werte per POST /config zurueck - dort serverseitig gegen genau diese
  // Grenzen validiert, bevor sie uebernommen werden.
  constexpr size_t MAX_CUSTOM_CONFIGS = 4;
  constexpr size_t MAX_CONFIG_KEY_LEN = 20;
  constexpr size_t MAX_CONFIG_VALUE_LEN = 48;
  constexpr size_t MAX_CONFIG_OPTIONS = 6;
  constexpr size_t MAX_CONFIG_OPTION_LEN = 16;

  // ---- Default-Identitaet ---------------------------------------------------
  // Greift nur, solange noch keine Konfiguration im NVS gespeichert wurde.
  constexpr const char *DEFAULT_NAME = "Komponente";
  constexpr const char *DEFAULT_ROOM = "unzugeordnet";

} // namespace EscapeConfig

// Typ eines custom Konfigurationsfeldes einer Komponente (siehe CustomConfigDef).
enum class CustomConfigType : uint8_t { Range, Text, Select };

// Beschreibt ein einzelnes, komponentenspezifisches Konfigurationsfeld (Name/
// Schluessel, Typ, erlaubte Werte) inkl. aktuellem Wert. Wird per Broadcast/
// status.json bekanntgegeben; bei POST /config wird ein neuer Wert anhand
// dieser Grenzen serverseitig validiert (siehe validateCustomConfigValue in
// client.cpp), bevor er uebernommen wird.
struct CustomConfigDef {
  char key[EscapeConfig::MAX_CONFIG_KEY_LEN + 1] = {0};
  CustomConfigType type = CustomConfigType::Text;
  int32_t rangeMin = 0;                  // nur bei Range
  int32_t rangeMax = 0;                  // nur bei Range
  uint16_t textMaxLen = 0;                // nur bei Text
  char options[EscapeConfig::MAX_CONFIG_OPTIONS][EscapeConfig::MAX_CONFIG_OPTION_LEN + 1] = {{0}}; // nur bei Select
  uint8_t optionCount = 0;                // nur bei Select
  char value[EscapeConfig::MAX_CONFIG_VALUE_LEN + 1] = {0}; // aktueller Wert, immer als String
};

// Aggregierter, zuletzt bekannter Zustand einer (fremden oder eigenen)
// Komponente. Ausschliesslich feste Puffer, keine String/heap-Allokation
// pro Peer, um Heap-Fragmentierung bei vielen kurzlebigen Peers zu vermeiden.
struct PeerInfo {
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  IPAddress ip;
  int8_t battery = -1;
  char errors[EscapeConfig::MAX_ERRORS][EscapeConfig::MAX_ERROR_LEN + 1] = {{0}};
  uint8_t errorCount = 0;
  char actions[EscapeConfig::MAX_ACTIONS][EscapeConfig::MAX_ACTION_LEN + 1] = {{0}};
  uint8_t actionCount = 0;
  char feed[EscapeConfig::MAX_FEED_LEN + 1] = {0};
  uint16_t puzzleStep = 0;
  uint16_t puzzleTotalSteps = 0; // 0 == kein Raetsel/keine Angabe
  char puzzleState[EscapeConfig::MAX_STATE_LEN + 1] = {0};
  bool puzzleIsHtml = false;
  CustomConfigDef customConfig[EscapeConfig::MAX_CUSTOM_CONFIGS];
  uint8_t customConfigCount = 0;
  uint32_t lastSeenMs = 0;
};

// Callback-Typen, ueber die das geraetespezifische Hauptskript seine Sensorik
// und Spiellogik anbindet, ohne das Netzwerk-/Broadcast-Verhalten anzufassen.
using BatteryProvider = std::function<int8_t()>; // -1 = unbekannt/Netzbetrieb
using StringListProvider = std::function<size_t(String out[], size_t maxCount)>;
using FeedProvider = std::function<String()>;
using PuzzleProvider = std::function<void(uint16_t &step, uint16_t &totalSteps, String &state, bool &isHtml)>;
using ActionHandler = std::function<bool(const String &action)>; // true = ausgefuehrt/ok
// Liefert die aktuelle Liste eigener Custom-Konfigurationsfelder (Schema +
// aktueller Wert) fuer Broadcast/status.json.
using CustomConfigProvider = std::function<size_t(CustomConfigDef out[], size_t maxCount)>;
// Wird pro Schluessel aufgerufen, nachdem ein per POST /config eingegangener
// Wert bereits gegen das eigene Schema validiert wurde (siehe handleConfig).
using CustomConfigSetHandler = std::function<bool(const String &key, const String &value)>;

class EscapeComponent {
public:
  // WLAN verbinden, NVS-Identitaet laden, UDP + HTTP-Server starten.
  void begin();

  // Muss regelmaessig (jeden loop()-Durchlauf, nicht blockierend) aufgerufen
  // werden: bedient HTTP-Anfragen, verarbeitet eingehende Broadcasts, sendet
  // eigene Broadcasts nach Zeitplan/bei Aenderung, raeumt veraltete Peers auf.
  void loop();

  // Vom Hauptskript aufrufen, wenn sich ein sicherbarer Zustand geaendert hat
  // (z.B. Raetsel-Schritt, neuer Fehler). Loest einen zeitnahen, aber auf
  // CHANGE_MIN_GAP_MS begrenzten Broadcast aus statt auf den naechsten
  // regulaeren Heartbeat zu warten.
  void markDirty();

  void onBattery(BatteryProvider cb);
  void onErrors(StringListProvider cb);
  void onActions(StringListProvider cb);
  void onFeed(FeedProvider cb);
  void onPuzzle(PuzzleProvider cb);
  void onAction(ActionHandler cb);
  void onCustomConfig(CustomConfigProvider cb);
  void onCustomConfigSet(CustomConfigSetHandler cb);

  const char *name() const { return _name; }
  const char *room() const { return _room; }

private:
  WiFiUDP _udp;
  WebServer _server{EscapeConfig::HTTP_PORT};
  Preferences _prefs;

  char _name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char _room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};

  PeerInfo _peers[EscapeConfig::MAX_PEERS];
  size_t _peerCount = 0;

  BatteryProvider _batteryCb;
  StringListProvider _errorsCb;
  StringListProvider _actionsCb;
  FeedProvider _feedCb;
  PuzzleProvider _puzzleCb;
  ActionHandler _actionHandler;
  CustomConfigProvider _customConfigCb;
  CustomConfigSetHandler _customConfigSetCb;

  bool _dirty = false;
  uint32_t _jitterOffsetMs = 0;
  uint32_t _lastBroadcastMs = 0;
  uint32_t _lastExpireCheckMs = 0;

  void loadIdentity();
  void saveIdentity(const String &name, const String &room);

  IPAddress broadcastAddress() const;
  void sendBroadcast();
  void pollIncoming();
  void expireStalePeers();
  PeerInfo *findOrCreatePeer(const char *name, const char *room);
  void fillSelfPeer(PeerInfo &p) const;
  void writePeerJson(String &out, const PeerInfo &p) const;

  bool checkAuth();
  void sendCorsPreflight();
  void handleRoot();
  void handleStatus();
  void handleAction();
  void handleConfig();
};
