#pragma once

// Plattformunabhaengige EscapeManager-Protokoll-Logik: Datenmodell, JSON-
// Wire-Format, Peer-Verwaltung, Validierung und die Anfrage-Behandlung fuer
// /action, /plan-action, /config, /plan und /plan-skeleton.
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
// EINSTIEG FUER NEUE PLATTFORMEN:
//   1. Eine Klasse von ProtocolAdapter ableiten und dessen drei kleine
//      Teil-Interfaces implementieren (Geraet lesen, Komponenten lesen,
//      eingehende Befehle anwenden). Nur diese Klasse muss die eigene
//      Anwendungs-/Persistenzstruktur kennen.
//   2. UDP-Empfang an ingestPeerAnnouncement() und UDP-Versand an
//      buildPeerAnnouncementJson() anbinden (reine Discovery: IP+Port, siehe
//      PeerAddressTable) - KEIN Geraetezustand mehr per Broadcast.
//   3. Die fuenf HTTP-POST-Pfade an handle*Request(), /status.json an
//      buildStatusJson() (nur EIGENE Komponenten) und /peers.json an
//      buildPeersJson() anbinden. JSON, Validierung und Peer-Logik bleiben
//      vollstaendig in Protocol.cpp.
//   4. Periodischer Abgleich (siehe RECONCILE_INTERVAL_MS): fuer eine per
//      PeerAddressTable bekannte Adresse /status.json per HTTP abrufen, mit
//      ingestStatusJson() in eine TRANSIENTE PeerTable einlesen und wie zuvor
//      an findSkeletonSyncSource() uebergeben.
// Konkrete Implementierungen: EscapeComponent::Host in esp/client.hpp und
// SimProtocolAdapter in sim/escape_component_sim.cpp.

#include "EscapeConfig.hpp"
#include "Json.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace EscapeProtocol {

// ---- Datenmodell ------------------------------------------------------------

enum class CustomConfigType : uint8_t { Range, Text, Select };

// Explizite Ablaufplan-Steuerung, getrennt von frei benannten Komponenten-
// Aktionen. Der Manager verwendet diese beiden Befehle fuer Raum-/Ebenen-
// Operationen und kann die Unterstuetzung ueber planActionMask erkennen.
enum class PlanAction : uint8_t { Reset = 0, Complete = 1 };

const char *planActionName(PlanAction action);
uint8_t planActionBit(PlanAction action);

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

// Aggregierter Zustand EINER Komponente - Wire-Format-Entsprechung eines
// Eintrags in status.json. Ausschliesslich feste Puffer, keine String/Heap-
// Allokation pro Peer, um Heap-Fragmentierung zu vermeiden. Zwei Verwendungen:
// als TRANSIENTE Momentaufnahme einer EIGENEN Komponente (siehe
// ComponentStateInterface::snapshot(), fuer buildStatusJson()) und als
// Eintrag einer NUR TRANSIENTEN PeerTable waehrend des periodischen Abgleichs
// mit EINEM per HTTP abgefragten Peer (siehe ingestStatusJson(),
// reconcile*()) - NICHT mehr dauerhaft fuer das gesamte Netz gehalten (das
// war vor der Umstellung auf browserseitige Aggregation die Ursache der
// alten Geraeteobergrenze, siehe PeerAddress/PeerAddressTable weiter unten).
struct PeerInfo {
  uint8_t id = 0; // Komponenten-Index auf dem Sender-Board
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0}; // stabile Identitaet DIESES PHYSISCHEN Boards (MAC-abgeleitet)
  // Identitaet DES RAETSELS, unabhaengig von der Hardware - siehe Kommentar zu
  // MAX_RIDDLE_ID_LEN. Grundlage von Ablaufplan-Zuordnung + Raum-Konflikterkennung.
  char riddleId[EscapeConfig::MAX_RIDDLE_ID_LEN + 1] = {0};
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  char ip[EscapeConfig::MAX_IP_LEN + 1] = {0};
  uint16_t httpPort = EscapeConfig::HTTP_PORT;
  int8_t battery = -1;
  char errors[EscapeConfig::MAX_ERRORS][EscapeConfig::MAX_ERROR_LEN + 1] = {{0}};
  uint8_t errorCount = 0;
  char actions[EscapeConfig::MAX_ACTIONS][EscapeConfig::MAX_ACTION_LEN + 1] = {{0}};
  uint8_t actionCount = 0;
  uint8_t planActionMask = 0;
  char feed[EscapeConfig::MAX_FEED_LEN + 1] = {0};
  char tip[EscapeConfig::MAX_TIP_LEN + 1] = {0};
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

// Schreibt EINEN Komponenten-/Peer-Eintrag als vollstaendiges JSON-Objekt
// (inkl. ip/httpPort/battery/upTimeMs/slave/lastSeenMs - jeder status.json-
// Eintrag ist seit der Umstellung auf browserseitige Aggregation
// selbststaendig, es gibt kein geraeteweites "aussenrum" mehr wie frueher im
// Broadcast).
void writeComponentJson(std::string &out, const PeerInfo &p);

// Parst EIN Komponenten-Objekt (z.B. aus einem /status.json-Array-Eintrag,
// siehe ingestStatusJson, oder aus der seriellen Bruecke, siehe
// escape_component_serial_host.cpp) in "out" - befuellt alles AUSSER ip/
// httpPort/battery/upTimeMs/slave/lastSeenMs, die je nach Aufrufer
// unterschiedlich herkommen (siehe dortige Kommentare).
void parseComponentIntoPeer(const EscapeJson::Value &comp, PeerInfo &out);

// ---- Peer-Tabelle (transient, aus EINEM per HTTP abgefragten Peer) --------

class PeerTable {
public:
  // Liefert den bestehenden Eintrag fuer (name,room) oder legt einen neuen an.
  // Ist die Tabelle voll (MAX_PEERS), wird der am laengsten nicht gesehene
  // Eintrag verdraengt statt einen neuen zu verwerfen.
  PeerInfo *findOrCreate(const char *name, const char *room);

  // Entfernt alle Eintraege, die seit mehr als timeoutMs nichts mehr gesendet haben.
  void expireStale(uint32_t nowMs, uint32_t timeoutMs = EscapeConfig::PEER_TIMEOUT_MS);

  // Leert die Tabelle (nur der Belegungszaehler wird zurueckgesetzt - die
  // dahinterliegenden PeerInfo-Slots werden beim naechsten findOrCreate()
  // ueber parseComponentIntoPeer()/ingestStatusJson() vollstaendig neu
  // befuellt, siehe dortige Kommentare). Ermoeglicht es Aufrufern, eine
  // "static"-Instanz gefahrlos wiederzuverwenden statt sizeof(PeerTable)
  // (mehrere KB) bei jedem Aufruf neu auf dem Stack anzulegen.
  void clear() { count_ = 0; }

  size_t count() const { return count_; }
  const PeerInfo &at(size_t i) const { return peers_[i]; }

private:
  PeerInfo peers_[EscapeConfig::MAX_PEERS];
  size_t count_ = 0;
};

// ---- Leichte Peer-Adresstabelle (reine Discovery, siehe /peers.json) -------
// Nur IP+Port+Sichtzeit, JE EINE Zeile pro erreichbarem GERAET (nicht pro
// Komponente) - kostet nur wenige Byte pro Eintrag, im Gegensatz zur
// vollstaendigen PeerInfo oben mit teils hundert(en) Byte grossen
// Zeichenpuffern PRO KOMPONENTE. Deshalb kann EscapeConfig::MAX_PEER_ADDRESSES
// um Groessenordnungen hoeher liegen als MAX_PEERS: die frueher harte
// Geraeteobergrenze verschiebt sich dadurch praktisch auf die Groesse des LAN.
struct PeerAddress {
  char ip[EscapeConfig::MAX_IP_LEN + 1] = {0};
  uint16_t httpPort = EscapeConfig::HTTP_PORT;
  uint32_t lastSeenMs = 0;
  // Siehe ChangeLock/buildPeerAnnouncementJson: welche ABRUFBARE RESSOURCE
  // dieses Peers eine per POST geaenderte, noch von NIEMANDEM abgerufene
  // Aenderung traegt - getrennt nach Ressource (nicht ein einzelnes Flag),
  // damit ein Beobachter NUR das tatsaechlich Betroffene neu abruft (siehe
  // manager.html mergePeersList()/refetchPeerStatus()/refetchPeerPlanSkeleton()).
  // statusChanged: sichtbar ueber GET /status.json (Action/PlanAction/Config/Plan).
  // planSkeletonChanged: sichtbar ueber GET /plan-skeleton.json (nur PlanSkeleton).
  bool statusChanged = false;
  bool planSkeletonChanged = false;
};

class PeerAddressTable {
public:
  // Liefert den bestehenden Eintrag fuer (ip,httpPort) oder legt einen neuen
  // an - NICHT nur nach ip, damit mehrere Instanzen mit derselben IP (z.B.
  // mehrere PC-Simulatoren auf einem Rechner, je eigener --http-port) sich
  // gegenseitig als unterschiedliche Peers erkennen. Ist die Tabelle voll
  // (MAX_PEER_ADDRESSES), wird die am laengsten nicht gesehene Adresse
  // verdraengt statt eine neue zu verwerfen.
  PeerAddress *findOrCreate(const char *ip, uint16_t httpPort);

  // Entfernt alle Adressen, die seit mehr als timeoutMs nichts mehr gesendet haben.
  void expireStale(uint32_t nowMs, uint32_t timeoutMs = EscapeConfig::PEER_TIMEOUT_MS);

  size_t count() const { return count_; }
  const PeerAddress &at(size_t i) const { return addrs_[i]; }

private:
  PeerAddress addrs_[EscapeConfig::MAX_PEER_ADDRESSES];
  size_t count_ = 0;
};

// ---- Bearbeitungssperre nach Aenderung ("Optimistic Lock") ------------------
// Nach einer erfolgreich angewendeten schreibenden Anfrage gilt ihr Typ als
// "geaendert, aber noch nicht abgerufen" - solange lehnt die Komponente
// WEITERE Anfragen DESSELBEN Typs mit 409 ab (siehe EscapeConfig::
// LOCK_UNTIL_FETCHED_*), bis die Anfrage bestaetigt, die genau DIESEN Typ
// tatsaechlich sichtbar macht: GET /status.json fuer Action/PlanAction/
// Config/Plan (noteStatusFetched()), GET /plan-skeleton.json NUR fuer
// PlanSkeleton (notePlanSkeletonFetched()) - ein Plan-Slice ("plan") ist Teil
// von status.json, das raumweite Skeleton dagegen NICHT, daher getrennte
// Bestaetigung statt eines einzelnen "alles gesehen"-Schalters. Gilt
// GERAETEWEIT, nicht pro Komponente. Der jeweilige Host (ESP/Sim/Serial-Host)
// haelt EINE ChangeLock-Instanz und verdrahtet sie um die bestehenden
// handle*Request()-Aufrufe bzw. die beiden GET-Routen (siehe esp/client.cpp,
// sim/escape_component_sim.cpp).
enum class MutationType : uint8_t { Action = 0, PlanAction = 1, Config = 2, Plan = 3, PlanSkeleton = 4 };
constexpr size_t kMutationTypeCount = 5;

// Ob "type" ueberhaupt der Sperre unterliegt, siehe EscapeConfig::
// LOCK_UNTIL_FETCHED_* (pro Anfrage-Typ einzeln konfigurierbar).
bool mutationLockEnabled(MutationType type);

class ChangeLock {
public:
  // true, wenn "type" aktuell gesperrt ist (siehe mutationLockEnabled()) UND
  // eine vorherige Aenderung dieses Typs noch nicht abgerufen wurde.
  bool isLocked(MutationType type) const;
  // Nach erfolgreicher Anwendung einer schreibenden Anfrage aufzurufen.
  void markChanged(MutationType type);
  // Von der GET /status.json-Behandlung aufzurufen: hebt NUR die dort
  // sichtbaren Typen auf (Action/PlanAction/Config/Plan) - NICHT PlanSkeleton,
  // das status.json gar nicht enthaelt.
  void noteStatusFetched();
  // Von der GET /plan-skeleton.json-Behandlung aufzurufen: hebt NUR PlanSkeleton auf.
  void notePlanSkeletonFetched();
  // Fuer den Discovery-Broadcast (siehe buildPeerAnnouncementJson()): ob
  // Action/PlanAction/Config/Plan aktuell eine unbestaetigte Aenderung tragen
  // (=> /status.json lohnt einen Refetch) bzw. ob PlanSkeleton das tut
  // (=> /plan-skeleton.json lohnt einen Refetch).
  bool hasUnseenStatusChange() const;
  bool hasUnseenPlanSkeletonChange() const;

private:
  bool pending_[kMutationTypeCount] = {false, false, false, false, false};
};

// ---- Zu implementierende Plattform-Interfaces ------------------------------

// Geraeteweiter Zustand. Implementiert Batterie/Uptime sowie die persistente
// Slave-Rolle und die Benachrichtigung ueber lokale Zustandsaenderungen.
class DeviceStateInterface {
public:
  virtual ~DeviceStateInterface() {}
  virtual int8_t battery() const = 0;
  virtual uint32_t upTimeMs() const = 0;
  virtual bool isSlave() const = 0;
  virtual void setSlave(bool slave) = 0;
  // Zeitnahen Broadcast vormerken; die konkrete Drosselung bleibt beim Host.
  virtual void markDirty() = 0;
};

// Nur lesender Zugriff auf alle lokalen Komponenten. snapshot() fuellt alle
// komponentenspezifischen PeerInfo-Felder; id/ip/httpPort/battery/Uptime setzt
// das Protokoll selbst. customConfigDefs() liefert das Schema samt Ist-Werten.
class ComponentStateInterface {
public:
  virtual ~ComponentStateInterface() {}
  virtual uint8_t componentCount() const = 0;
  virtual void identity(uint8_t index, std::string &name, std::string &room) const = 0;
  virtual void snapshot(uint8_t index, PeerInfo &out) const = 0;
  virtual void customConfigDefs(uint8_t index, std::vector<CustomConfigDef> &out) const = 0;
};

// Schreibender Zugriff fuer bereits vom Protokoll authentifizierte und
// validierte Aenderungen. Persistenz (NVS/Datei/...) gehoert in diese Setter.
class ComponentCommandInterface {
public:
  virtual ~ComponentCommandInterface() {}
  virtual bool applyAction(uint8_t index, const std::string &action) = 0;
  virtual bool applyPlanAction(uint8_t index, PlanAction action) = 0;
  virtual void setIdentity(uint8_t index, const std::string &name, const std::string &room) = 0;
  // Aendert NUR die Raetsel-Identitaet (siehe PeerInfo::riddleId), unabhaengig
  // von Name/Raum - z.B. um ein Ersatzgeraet manuell auf dieselbe riddleId wie
  // das ausgetauschte Original zu setzen.
  virtual void setRiddleId(uint8_t index, const std::string &riddleId) = 0;
  virtual bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) = 0;
  virtual void setPlan(uint8_t index, const std::string &planJson) = 0;
  virtual void pushEvent(uint8_t index, const std::string &msg) = 0;
};

// EINZIGER Basistyp, den eine neue Integration implementiert. Die Aufteilung
// in drei Basisklassen dient nur dazu, die Verantwortlichkeiten schnell zu
// erfassen; Protocol-Funktionen erwarten immer diesen kombinierten Adapter.
class ProtocolAdapter : public DeviceStateInterface,
                        public ComponentStateInterface,
                        public ComponentCommandInterface {
public:
  virtual ~ProtocolAdapter() {}
};

// Rueckwaertskompatibilitaet fuer bestehende Integrationen.
using ComponentHost = ProtocolAdapter;

// ---- Discovery-Broadcast (nur IP+Port), /peers.json, /status.json ----------

// Baut die minimale UDP-Discovery-Ankuendigung ("ich bin unter httpPort
// erreichbar") - KEIN Geraete-/Komponentenzustand mehr, siehe Kopfkommentar
// dieser Datei und EscapeConfig::MAX_PEER_ADDRESSES. "statusChanged"/
// "planSkeletonChanged" spiegeln ChangeLock::hasUnseenStatusChange()/
// hasUnseenPlanSkeletonChange() dieses Geraets (siehe dort).
std::string buildPeerAnnouncementJson(uint16_t httpPort = EscapeConfig::HTTP_PORT,
                                      bool statusChanged = false, bool planSkeletonChanged = false);

// Verarbeitet eine eingegangene Discovery-Ankuendigung: traegt den Absender
// (senderIp, NICHT ein evtl. im Payload enthaltenes Feld - die Quelladresse
// des UDP-Pakets ist die vertrauenswuerdigere Angabe) in "peers" ein, ausser
// er ist das Geraet selbst (Vergleich von senderIp+Port aus dem Payload mit
// ownIp+ownHttpPort - NICHT nur ip, damit mehrere Instanzen mit derselben IP,
// z.B. PC-Simulatoren auf einem Rechner, sich gegenseitig als Peers sehen).
// Fehlerhafte/eigene Pakete werden stillschweigend verworfen.
void ingestPeerAnnouncement(const std::string &json, const std::string &senderIp, const std::string &ownIp,
                            uint32_t nowMs, PeerAddressTable &peers,
                            uint16_t ownHttpPort = EscapeConfig::HTTP_PORT);

// Baut /peers.json: bekannte Peer-Adressen (inkl. "statusChanged"/
// "planSkeletonChanged", siehe PeerAddress) als schlankes JSON-Array - DAS
// ist die Grundlage, auf der der Browser (siehe manager.html) das Netz
// selbst entdeckt, aggregiert und gezielt (nur die betroffene Ressource)
// nachlaedt.
std::string buildPeersJson(const PeerAddressTable &peers);

// Baut die /status.json-Antwort NUR aus den eigenen Komponenten von "host"
// (KEINE Peers mehr - die aggregiert seit dieser Umstellung ausschliesslich
// der Browser, siehe manager.html poll()/ingest()).
std::string buildStatusJson(const ProtocolAdapter &host, const std::string &deviceIp,
                             uint32_t nowMs, uint16_t httpPort = EscapeConfig::HTTP_PORT);

// Parst eine per HTTP von GENAU EINEM Peer geholte /status.json-Antwort (siehe
// buildStatusJson) in eine TRANSIENTE PeerTable - jeder Array-Eintrag ist
// SELBSTSTAENDIG (ip/httpPort/battery/upTimeMs/slave/lastSeenMs stehen anders
// als frueher im Broadcast direkt am Eintrag, nicht einmal geraeteweit auf
// oberster Ebene). Grundlage von reconcileWithPeers() auf ESP-/Sim-Seite:
// ersetzt die vormalige kontinuierliche Befuellung aus Broadcasts.
void ingestStatusJson(const std::string &json, uint32_t nowMs, PeerTable &peers);

// ---- HTTP-Anfragen (/action, /plan-action, /config, /plan, /plan-skeleton) --

// "authOk" muss der Aufrufer VORHER bestimmen (Header-Zugriff ist
// plattformspezifisch) - siehe constantTimeEquals().
struct HttpRequest {
  HttpRequest() {}
  HttpRequest(const std::string &requestBody, bool authenticated)
      : body(requestBody), authOk(authenticated) {}

  std::string body;
  bool authOk = false;
};

struct HttpResult {
  HttpResult() {}
  HttpResult(int statusCode, const std::string &responseBody)
      : status(statusCode), body(responseBody) {}

  int status = 200;
  std::string body;
};

HttpResult handleActionRequest(ProtocolAdapter &host, const HttpRequest &req);
HttpResult handlePlanActionRequest(ProtocolAdapter &host, const HttpRequest &req);
HttpResult handleConfigRequest(ProtocolAdapter &host, const HttpRequest &req);
HttpResult handlePlanRequest(ProtocolAdapter &host, const HttpRequest &req);
HttpResult handlePlanSkeletonGetRequest(const std::string &skeletonStorage);
// Fuehrt direkte Legacy-Skeletons und neue {"plans":[...]}-Sammlungen nach
// Raum zusammen. Plaene aus incomingStorage ersetzen nur denselben Raum und
// lassen alle anderen Raeume in currentStorage unveraendert.
bool mergePlanSkeletonStorage(const std::string &currentStorage,
                              const std::string &incomingStorage,
                              std::string &mergedStorage);
// "skeletonStorage" ist die geraeteweite Sammlung aller Raum-Skeletons - deren
// tatsaechliche Speicherung (NVS vs. Datei vs. nur RAM) bleibt beim Aufrufer.
HttpResult handlePlanSkeletonPostRequest(ProtocolAdapter &host, const HttpRequest &req, std::string &skeletonStorage);

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

// Waehlt den besten Peer aus, von dem das geraeteweite Ablaufplan-Skeleton
// uebernommen werden sollte (Raum = Raum irgendeiner eigenen Komponente, laut
// shouldAdoptFromPeer() autoritativ, bei mehreren Kandidaten der mit der
// hoechsten Uptime) - oder nullptr, wenn kein solcher Peer existiert. Liefert
// nur die ENTSCHEIDUNG (welcher Peer/welche IP); das eigentliche Abholen
// (HTTP GET .../plan-skeleton.json) ist plattformabhaengig und NICHT Teil
// dieser Datei (siehe HardwareEsp32::httpGet() bzw. die Sim-Gegenstuecke).
const PeerInfo *findSkeletonSyncSource(const ProtocolAdapter &host, const PeerTable &peers);

} // namespace EscapeProtocol
