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
  // Wie viele eigene Raetsel-Komponenten EIN ESP32 gleichzeitig anmelden kann
  // (addComponent()), z.B. mehrere Sensoren/Aktoren, die an einem Board haengen.
  // Jede davon hat eigenen Namen/Raum/Zustand, teilt sich aber Netzwerk-Stack,
  // HTTP-Server und Batteriemessung mit den anderen Komponenten desselben Boards.
  constexpr size_t MAX_LOCAL_COMPONENTS = 4;
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

  // ---- Ablaufplan (Raum-weiter Prozessgraph aus Ebenen/Lanes/Verbindungen) --
  // Die eigentliche Graph-Logik (Ebenen, Lanes, Linien, Dummies, Variablen)
  // lebt bewusst NUR im Manager (manager.html) - die Firmware speichert/liefert
  // sie nur als rohe, fuer sie bedeutungslose JSON-Bloecke, aufgeteilt in zwei
  // Teile, um NVS/RAM klein zu halten (kein voller Plan pro Geraet noetig):
  //  - Pro Komponente EIN kleiner "Slice" (eigene Lane-Zuordnung + ausgehende
  //    Verbindungen dieser einen Komponente), analog zu name/room persistiert.
  //  - Ein EINZIGES, geraeteweites "Skeleton" (Ebenen/Lanes-Struktur, Dummy-
  //    Knoten, Variablen-Katalog) - inhaltlich identisch auf allen Geraeten
  //    eines Raums, vom Manager beim Speichern an alle verteilt.
  // "uuid" ist trotz des Feldnamens (Schema-Kompatibilitaet) keine echte
  // Zufalls-UUID, sondern von der WLAN-MAC-Adresse des Boards abgeleitet
  // ("aabbccddeeff-<id>") - deterministisch, kollisionsfrei pro Board+
  // Komponente und ohne Zufallsquelle/NVS-Race ueber Reboots hinweg stabil.
  // Ist die MAC nicht verfuegbar (WiFi.macAddress() liefert nur 0x00/0xFF,
  // z.B. bei WLAN-Treiberfehler), faellt macBasedUuid() auf die eFuse-
  // Chip-ID zurueck ("chip<hex>-<id>") - ebenfalls werkseitig eindeutig und
  // deterministisch, siehe Kommentar dort.
  // Wird trotzdem in NVS gespiegelt (siehe resolveUuid()), damit ein spaeter
  // manuell in NVS gesetzter Wert Vorrang haette. Format braucht deutlich
  // weniger Platz als eine UUIDv4 (36 Zeichen) - "aabbccddeeff-3" sind 14.
  constexpr size_t MAX_UUID_LEN = 20;
  // Bewusst klein gehalten: mit MAX_PEERS=24 kostet jedes zusaetzliche Byte
  // hier 24x RAM (fixe PeerInfo-Tabelle, siehe Kommentar dort). Ebenen-/Lane-
  // IDs im Plan-Slice sind daher kurze, vom Manager vergebene Tokens (z.B.
  // "L0"/"A"), keine UUIDs - nur Komponenten/Dummies selbst brauchen echte
  // UUIDs (stabile Identitaet ueber Reboots/Umbenennungen hinweg).
  constexpr size_t MAX_PLAN_LEN = 512; // Slice EINER Komponente
  constexpr size_t MAX_PLAN_SKELETON_LEN = 6144; // Ebenen/Lanes/Dummies/Variablen eines Raums

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
// Ein PeerInfo-Eintrag entspricht IMMER genau einer Komponente, nicht einem
// Geraet - ein einzelnes ESP32-Board mit mehreren addComponent()-Aufrufen
// erzeugt bei anderen Boards entsprechend mehrere PeerInfo-Eintraege mit
// derselben ip, aber unterschiedlichem id/name/room.
struct PeerInfo {
  uint8_t id = 0; // Komponenten-Index auf dem Sender-Board (siehe addComponent())
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0}; // stabile Identitaet fuer den Ablaufplan, ueberlebt Name-/Raumaenderungen
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
  // Roher JSON-Ablaufplan-Slice dieser Komponente (siehe LocalComponent::plan) -
  // fuer die Firmware ein bedeutungsloser Blob, nur zum Weiterreichen an den Manager.
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0};
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

// Zustand + Callbacks EINER lokalen Raetsel-Komponente auf diesem Board (siehe
// EscapeComponent::addComponent()). Ein Board mit mehreren Komponenten haelt
// mehrere Instanzen davon; Netzwerk/HTTP/Batterie bleiben geraeteweit geteilt.
struct LocalComponent {
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0};
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  // Roher JSON-Ablaufplan-Slice dieser Komponente (Lane-Zuordnung + eigene
  // Verbindungen), von Manager/manager.html verwaltet - leer = nicht zugeordnet.
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0};
  StringListProvider errorsCb;
  StringListProvider actionsCb;
  FeedProvider feedCb;
  PuzzleProvider puzzleCb;
  ActionHandler actionHandler;
  CustomConfigProvider customConfigCb;
  CustomConfigSetHandler customConfigSetCb;
};

class EscapeComponent {
public:
  // WLAN verbinden, UDP + HTTP-Server starten. addComponent() muss vorher
  // (in setup(), vor begin()) fuer jede Raetsel-Komponente des Boards
  // aufgerufen worden sein.
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

  // Registriert eine neue lokale Raetsel-Komponente (Default-Identitaet, aus
  // NVS ueberschrieben falls dort bereits gespeichert) und liefert deren
  // stabile Komponenten-ID (0-basiert, in Aufrufreihenfolge) fuer die
  // folgenden on*(id, ...)-Aufrufe zurueck. Muss vor begin() erfolgen. Ab dem
  // (MAX_LOCAL_COMPONENTS+1)-ten Aufruf wird die letzte gueltige ID erneut
  // zurueckgegeben (Kapazitaet ist zur Compile-/Bootzeit fest).
  uint8_t addComponent(const String &defaultName, const String &defaultRoom);

  // Batterie ist geraeteweit (ein physischer Akku pro Board), daher ohne
  // Komponenten-ID - gilt fuer alle per addComponent() angemeldeten Komponenten.
  void onBattery(BatteryProvider cb);

  // Alle uebrigen Callbacks sind pro Komponente - id kommt von addComponent().
  void onErrors(uint8_t id, StringListProvider cb);
  void onActions(uint8_t id, StringListProvider cb);
  void onFeed(uint8_t id, FeedProvider cb);
  void onPuzzle(uint8_t id, PuzzleProvider cb);
  void onAction(uint8_t id, ActionHandler cb);
  void onCustomConfig(uint8_t id, CustomConfigProvider cb);
  void onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb);

  const char *name(uint8_t id) const { return id < _componentCount ? _components[id].name : ""; }
  const char *room(uint8_t id) const { return id < _componentCount ? _components[id].room : ""; }
  const char *uuid(uint8_t id) const { return id < _componentCount ? _components[id].uuid : ""; }
  uint8_t componentCount() const { return _componentCount; }

private:
  WiFiUDP _udp;
  WebServer _server{EscapeConfig::HTTP_PORT};
  Preferences _prefs;

  LocalComponent _components[EscapeConfig::MAX_LOCAL_COMPONENTS];
  uint8_t _componentCount = 0;

  PeerInfo _peers[EscapeConfig::MAX_PEERS];
  size_t _peerCount = 0;

  BatteryProvider _batteryCb;

  // Roher, geraeteweiter Ablaufplan-"Skeleton" (Ebenen/Lanes/Dummies/
  // Variablen-Katalog eines Raums) - siehe EscapeConfig::MAX_PLAN_SKELETON_LEN.
  // std::vector statt Stack-Array: 6 KB waeren als lokale Variable riskant,
  // als Member ist die Groesse aber ohnehin fix im .bss/Heap.
  String _planSkeleton;

  bool _dirty = false;
  uint32_t _jitterOffsetMs = 0;
  uint32_t _lastBroadcastMs = 0;
  uint32_t _lastExpireCheckMs = 0;

  void loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom);
  void saveIdentity(uint8_t id, const String &name, const String &room);
  void loadPlanSkeleton();
  // Muss NACH WiFi.mode()/WiFi-Init aufgerufen werden (MAC-Adresse ist vorher
  // ggf. nicht verfuegbar) - siehe begin().
  void resolveUuid(uint8_t id);

  IPAddress broadcastAddress() const;
  void sendBroadcast();
  void pollIncoming();
  void expireStalePeers();
  PeerInfo *findOrCreatePeer(const char *name, const char *room);
  void fillComponentPeer(PeerInfo &p, uint8_t id) const;
  void writePeerJson(String &out, const PeerInfo &p) const;

  bool checkAuth();
  void sendCorsPreflight();
  void handleRoot();
  void handleStatus();
  void handleAction();
  void handleConfig();
  void handlePlan();
  void handlePlanSkeletonGet();
  void handlePlanSkeletonPost();
};
