#pragma once

// Plattformunabhaengige EscapeManager-Protokoll-Logik: Datenmodell, JSON-
// Wire-Format, Peer-Verwaltung, Validierung und die Anfrage-Behandlung fuer
// /action, /config, /plan und /plan-skeleton.
//
// Bewusst OHNE jede Hardware-/Netzwerk-API (kein Arduino.h, kein WiFi/WebServer,
// keine POSIX-Sockets) - genau das macht diese Datei fuer sowohl die
// ESP32-Firmware (Client/client.cpp, ueber HardwareEsp32.hpp) als auch den
// PC-Simulator (Sim/escape_component_sim.cpp) direkt wiederverwendbar: aendert
// sich das Protokoll (neues Feld, neue Validierungsregel, ...), muss das nur
// HIER angepasst werden, beide Verwendungsstellen profitieren automatisch.
//
// Nur C++11/14-Syntax (keine if-init-Statements/structured bindings), damit
// die Datei ohne Anpassung der PlatformIO-Toolchain-Flags kompiliert.
//
// ANMERKUNG fuer eine moegliche kuenftige Python-Anbindung: die hier
// exponierten Funktionen/Klassen arbeiten ausschliesslich mit std::string,
// std::vector und POD-artigen Structs (keine Templates/Exceptions in der
// Schnittstelle) - das haelt die Tuer offen fuer eine spaetere duenne
// extern "C"-Bruecke (z.B. per ctypes aus Python), falls das mal gebraucht wird.

#include "EscapeConfig.hpp"
#include "Json.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace EscapeProtocol {

// ---- Datenmodell ------------------------------------------------------------

enum class CustomConfigType : uint8_t { Range, Text, Select };

// Beschreibt ein einzelnes, komponentenspezifisches Konfigurationsfeld (Name/
// Schluessel, Typ, erlaubte Werte) inkl. aktuellem Wert. Wird per Broadcast/
// status.json bekanntgegeben; bei POST /config wird ein neuer Wert anhand
// dieser Grenzen validiert (siehe validateCustomConfigValue), bevor er
// uebernommen wird. Ausschliesslich feste Puffer (keine std::string-Felder),
// damit dieselbe Darstellung wie im PeerInfo unten auch auf dem RAM-knappen
// ESP32 ohne Heap-Allokation pro Peer auskommt.
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
// Komponente - Wire-Format-Entsprechung eines Eintrags in status.json/den
// Broadcast-Paketen. Ausschliesslich feste Puffer, keine String/Heap-
// Allokation pro Peer, um Heap-Fragmentierung bei vielen kurzlebigen Peers zu
// vermeiden (siehe PeerTable). Sowohl als dauerhafte Speicherung fremder Peers
// (siehe PeerTable) als auch als TRANSIENTE Momentaufnahme einer eigenen
// Komponente (siehe ComponentHost::snapshot()) verwendet.
struct PeerInfo {
  uint8_t id = 0; // Komponenten-Index auf dem Sender-Board (siehe ComponentHost)
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0}; // stabile Identitaet fuer den Ablaufplan, ueberlebt Name-/Raumaenderungen
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  char ip[EscapeConfig::MAX_IP_LEN + 1] = {0};
  uint16_t httpPort = EscapeConfig::HTTP_PORT;
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
  // Roher JSON-Ablaufplan-Slice dieser Komponente - fuer Client/Sim ein
  // bedeutungsloser Blob, nur zum Weiterreichen an den Manager.
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0};
  // Aktivitaets-Benachrichtigung dieser Komponente, siehe EscapeConfig::MAX_EVENT_MSG_LEN.
  uint32_t eventSeq = 0;
  char eventMsg[EscapeConfig::MAX_EVENT_MSG_LEN + 1] = {0};
  // Geraeteweite Felder (wie ip/battery pro Komponente dupliziert): Zeit seit
  // Boot/Prozessstart des SENDENDEN Geraets (millis()/monotonicMillis()) und
  // dessen "slave"-Rolle - siehe EscapeConfig::RECONCILE_INTERVAL_MS und
  // shouldAdoptFromPeer() weiter unten fuer die Verwendung.
  uint32_t upTimeMs = 0;
  bool slave = false;
  uint32_t lastSeenMs = 0;
};

// ---- Kleine Hilfsfunktionen (Wire-Format, Validierung) ----------------------

// Kopiert "src" (ggf. abgeschnitten) nach "dst", immer nullterminiert.
void copyBounded(char *dst, size_t dstSize, const char *src);

// Vergleicht zwei Strings ohne Frueh-Abbruch bei erstem Unterschied, um
// Timing-Angriffe auf den Auth-Token zu erschweren. Die Laenge selbst ist
// ueber die Schleifenzahl minimal beobachtbar, was fuer dieses Bedrohungsmodell
// (LAN-Zugriff, kein hochpraeziser Fernangreifer) akzeptabel ist.
bool constantTimeEquals(const std::string &a, const std::string &b);

const char *customConfigTypeName(CustomConfigType t);
const CustomConfigDef *findCustomConfigDef(const CustomConfigDef *defs, size_t count, const char *key);

// Prueft einen von aussen (POST /config) eingegangenen Wert gegen das vom
// Hauptskript deklarierte Schema (Grenzen/erlaubte Werte), bevor er
// uebernommen wird - der Client (Manager) ist eine nicht vertrauenswuerdige
// Eingabequelle.
bool validateCustomConfigValue(const CustomConfigDef &def, const std::string &value);

// Schreibt EINEN Komponenten-/Peer-Eintrag als JSON-Objekt. Mit
// includeDeviceFields=true (status.json / Peer-Tabelle) werden ip/battery/
// lastSeenMs mit ausgegeben, mit false (Broadcast-Payload, wo ip/battery
// bereits einmal auf oberster Ebene stehen) werden sie weggelassen.
void writeComponentJson(std::string &out, const PeerInfo &p, bool includeDeviceFields);

// Parst EIN Komponenten-Objekt aus dem "components"-Array eines Broadcasts
// (siehe buildBroadcastJson) in "out" - befuellt alles AUSSER ip/battery/
// lastSeenMs, die kommen vom Aufrufer (Absenderadresse bzw. oberste
// Broadcast-Ebene, siehe ingestBroadcast).
void parseComponentIntoPeer(const EscapeJson::Value &comp, PeerInfo &out);

// ---- Peer-Tabelle (aus fremden UDP-Broadcasts) ------------------------------

class PeerTable {
public:
  // Liefert den bestehenden Eintrag fuer (name,room) oder legt einen neuen an.
  // Ist die Tabelle voll (MAX_PEERS), wird der am laengsten nicht gesehene
  // Eintrag verdraengt statt einen neuen zu verwerfen.
  PeerInfo *findOrCreate(const char *name, const char *room);

  // Entfernt alle Eintraege, die seit mehr als timeoutMs nichts mehr gesendet haben.
  void expireStale(uint32_t nowMs, uint32_t timeoutMs = EscapeConfig::PEER_TIMEOUT_MS);

  size_t count() const { return count_; }
  const PeerInfo &at(size_t i) const { return peers_[i]; }

private:
  PeerInfo peers_[EscapeConfig::MAX_PEERS];
  size_t count_ = 0;
};

// ---- Anbindung an die (plattformabhaengige) Komponenten-Verwaltung ---------

// Schnittstelle, ueber die die Protokoll-Logik auf die tatsaechlichen lokalen
// Komponenten eines Geraets zugreift. ESP32 (client.cpp: LocalComponent[]
// + Callbacks) und der C++-Sim (ComponentState-Liste) implementieren dies
// jeweils gegen ihre eigene interne Darstellung.
class ComponentHost {
public:
  virtual ~ComponentHost() {}

  virtual uint8_t componentCount() const = 0;
  // Batterie ist geraeteweit (ein physischer Akku pro Board), daher ohne
  // Komponenten-Index - analog EscapeComponent::onBattery().
  virtual int8_t battery() const = 0;

  // Zeit seit Boot/Prozessstart dieses Geraets (millis() auf dem ESP32, seit
  // Prozessstart im Sim) - Grundlage fuer den Uptime-Abgleich, siehe
  // shouldAdoptFromPeer()/reconcileLocalComponentsFromPeers().
  virtual uint32_t upTimeMs() const = 0;

  // "Slave"-Geraete gelten NIE als Quelle der Wahrheit fuer andere (auch nicht
  // bei hoeherer Uptime) und uebernehmen umgekehrt IMMER von einem laenger
  // laufenden Nicht-Slave-Peer - z.B. fuer bewusst als Ersatz/Kopie markierte
  // Ersatz-Hardware. Geraeteweit, per POST /config setzbar (siehe
  // handleConfigRequest), daher mit Setter.
  virtual bool isSlave() const = 0;
  virtual void setSlave(bool slave) = 0;

  // Guenstiger Zugriff NUR auf Name/Raum, z.B. um beim Empfang eines
  // Broadcasts eigene Komponenten zu erkennen (siehe ingestBroadcast) - ruft
  // im Unterschied zu snapshot() keine teuren Callbacks (Fehler/Aktionen/...) auf.
  virtual void identity(uint8_t index, std::string &name, std::string &room) const = 0;

  // Vollstaendige Momentaufnahme der Komponente "index" (Fehler/Aktionen/
  // Feed/Raetsel/CustomConfig ueber die jeweiligen Callbacks/Felder abfragen).
  // Fuellt ALLES AUSSER id/ip/battery/lastSeenMs (die setzt der Aufrufer).
  virtual void snapshot(uint8_t index, PeerInfo &out) const = 0;

  // Wendet eine per POST /action eingegangene Aktion an; Rueckgabe = ob
  // ausgefuehrt/erfolgreich.
  virtual bool applyAction(uint8_t index, const std::string &action) = 0;

  virtual void setIdentity(uint8_t index, const std::string &name, const std::string &room) = 0;

  // Liefert das eigene CustomConfig-Schema (leer, falls die Komponente keins hat).
  virtual void customConfigDefs(uint8_t index, std::vector<CustomConfigDef> &out) const = 0;
  // Wird NUR fuer bereits (gegen customConfigDefs()) validierte Schluessel/Werte
  // aufgerufen (siehe handleConfigRequest) - alles-oder-nichts pro Anfrage.
  virtual bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) = 0;

  // Roher Ablaufplan-Slice (siehe PeerInfo::plan) - leerer String loescht ihn.
  virtual void setPlan(uint8_t index, const std::string &planJson) = 0;

  // Erhoeht den Aktivitaets-Zaehler + setzt die Klartext-Meldung (siehe
  // PeerInfo::eventSeq/eventMsg), damit sie im naechsten Broadcast/status.json
  // an alle Manager weitergereicht wird.
  virtual void pushEvent(uint8_t index, const std::string &msg) = 0;

  // Wird nach jeder moeglichen Zustandsaenderung aufgerufen, um einen
  // zeitnahen (aber gedrosselten) Broadcast auszuloesen - siehe isChangeBroadcastDue().
  virtual void markDirty() = 0;
};

// ---- Broadcast senden/empfangen, status.json --------------------------------

// Baut EIN Broadcast-Paket ("{ip,battery,components:[...]}") aus allen
// lokalen Komponenten von "host".
std::string buildBroadcastJson(const ComponentHost &host, const std::string &deviceIp,
                               uint16_t httpPort = EscapeConfig::HTTP_PORT);

// Baut die /status.json-Antwort (eigene Komponenten + bekannte Peers, in
// dieser Reihenfolge, als flaches JSON-Array).
std::string buildStatusJson(const ComponentHost &host, const PeerTable &peers, const std::string &deviceIp,
                             uint32_t nowMs, uint16_t httpPort = EscapeConfig::HTTP_PORT);

// Verarbeitet ein eingegangenes Broadcast-Paket (siehe buildBroadcastJson):
// traegt alle fremden Komponenten (die keiner eigenen von "self" entsprechen)
// in "peers" ein. Fehlerhafte/fremde Pakete werden stillschweigend verworfen.
void ingestBroadcast(const std::string &json, const std::string &senderIp, uint32_t nowMs, const ComponentHost &self,
                      PeerTable &peers);

// ---- HTTP-Anfragen (/action, /config, /plan, /plan-skeleton) ----------------

// "authOk" muss der Aufrufer VORHER bestimmen (Header-Zugriff ist
// plattformspezifisch) - siehe constantTimeEquals().
struct HttpRequest {
  std::string body;
  bool authOk = false;
};

struct HttpResult {
  int status = 200;
  std::string body;
};

HttpResult handleActionRequest(ComponentHost &host, const HttpRequest &req);
HttpResult handleConfigRequest(ComponentHost &host, const HttpRequest &req);
HttpResult handlePlanRequest(ComponentHost &host, const HttpRequest &req);
HttpResult handlePlanSkeletonGetRequest(const std::string &skeletonStorage);
// "skeletonStorage" ist die geraeteweite (nicht pro Komponente) Persistenz -
// deren tatsaechliche Speicherung (NVS vs. Datei vs. nur RAM) bleibt beim Aufrufer.
HttpResult handlePlanSkeletonPostRequest(ComponentHost &host, const HttpRequest &req, std::string &skeletonStorage);

// ---- Timing-Entscheidungen (Heartbeat/Jitter/Change-Broadcast) --------------
// Reine Funktionen auf Basis eines millis()-artigen, ueberlaufsicheren
// Zaehlers (unsigned-Subtraktion) - identisch zum Arduino-millis()-Idiom.

bool isHeartbeatDue(uint32_t nowMs, uint32_t lastBroadcastMs, uint32_t intervalMs);
bool isChangeBroadcastDue(uint32_t nowMs, uint32_t lastBroadcastMs, bool dirty);

// ---- Uptime-Abgleich mit laenger laufenden Peers ----------------------------
// Siehe EscapeConfig::RECONCILE_INTERVAL_MS fuer die Motivation: ein neu
// beigetretenes/frisch gebootetes Geraet soll seine eigene Persistenz von
// einem laenger laufenden Teil des Systems uebernehmen statt eigene,
// moeglicherweise veraltete Werte zu verteilen.

// Entscheidet, ob "peer" als Quelle fuer die EIGENE Persistenz gelten darf:
// - ein Peer, der sich selbst als "slave" meldet, ist NIE Quelle der Wahrheit
//   (auch nicht bei hoeherer Uptime - ein Slave hat selbst nur uebernommene,
//   keine eigenen autoritativen Werte).
// - ein eigenes "slave"-Geraet uebernimmt immer (Uptime-Vergleich entfaellt).
// - sonst (normaler Fall): nur uebernehmen, wenn der Peer LAENGER laeuft.
bool shouldAdoptFromPeer(bool ownSlave, uint32_t ownUpTimeMs, const PeerInfo &peer);

// Prueft fuer jede eigene Komponente, ob ein Peer mit IDENTISCHER uuid (z.B.
// bewusst gleich konfigurierte Ersatz-Hardware) existiert, der laut
// shouldAdoptFromPeer() als autoritativ gilt, und uebernimmt dessen bereits
// (aus dessen Broadcasts) gecachte CustomConfig-Werte (validiert gegen das
// EIGENE Schema) sowie dessen Ablaufplan-Slice - ausschliesslich ueber die
// bestehenden ComponentHost-Setter (setCustomConfigValue/setPlan), damit die
// Persistenz genau wie bei einem eingehenden POST /config bzw. /plan erfolgt.
// Braucht KEINE zusaetzliche Netzwerkanfrage: alle noetigen Daten stehen schon
// in "peers" (per Broadcast empfangen).
void reconcileLocalComponentsFromPeers(ComponentHost &host, const PeerTable &peers);

// Waehlt den besten Peer aus, von dem das geraeteweite Ablaufplan-Skeleton
// uebernommen werden sollte (Raum = Raum irgendeiner eigenen Komponente, laut
// shouldAdoptFromPeer() autoritativ, bei mehreren Kandidaten der mit der
// hoechsten Uptime) - oder nullptr, wenn kein solcher Peer existiert. Liefert
// nur die ENTSCHEIDUNG (welcher Peer/welche IP); das eigentliche Abholen
// (HTTP GET .../plan-skeleton.json) ist plattformabhaengig und NICHT Teil
// dieser Datei (siehe HardwareEsp32::httpGet() bzw. die Sim-Gegenstuecke).
const PeerInfo *findSkeletonSyncSource(const ComponentHost &host, const PeerTable &peers);

} // namespace EscapeProtocol
