// Implementierung von Protocol.hpp (siehe dort fuer Design-Rationale).

#include "Protocol.hpp"

#include <cstdlib>

namespace EscapeProtocol {

namespace {

void appendJsonEscaped(std::string &out, const char *s) {
  if (!s) return;
  EscapeJson::appendEscaped(out, std::string(s));
}

// Liest ein Feld als String aus einem geparsten JSON-Objekt, "" falls fehlend.
std::string fieldString(const EscapeJson::Value &obj, const char *key) {
  const EscapeJson::Value *v = obj.find(key);
  return v ? v->asString() : std::string();
}

double fieldNumber(const EscapeJson::Value &obj, const char *key, double def) {
  const EscapeJson::Value *v = obj.find(key);
  return v ? v->asNumber(def) : def;
}

} // namespace

// ---- Kleine Hilfsfunktionen --------------------------------------------------

void copyBounded(char *dst, size_t dstSize, const char *src) {
  // dstSize==0 wuerde "dstSize - 1" (unsigned) zu SIZE_MAX unterlaufen lassen
  // und damit strncpy/dst[dstSize-1] weit ueber den Puffer hinausschreiben.
  // Aktuell ruft niemand mit dstSize==0 auf (immer sizeof(fixed_array) mit
  // N>=1), aber die Funktion nimmt einen rohen Zeiger+Groesse entgegen und
  // sollte daher auch bei einer zukuenftigen dstSize==0-Aufrufstelle sicher
  // bleiben statt sich auf diese Annahme zu verlassen.
  if (dstSize == 0) return;
  strncpy(dst, src ? src : "", dstSize - 1);
  dst[dstSize - 1] = '\0';
}

bool constantTimeEquals(const std::string &a, const std::string &b) {
  uint8_t diff = (uint8_t)(a.size() != b.size());
  size_t n = a.size() < b.size() ? a.size() : b.size();
  for (size_t i = 0; i < n; i++) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  return diff == 0;
}

const char *customConfigTypeName(CustomConfigType t) {
  switch (t) {
    case CustomConfigType::Range: return "range";
    case CustomConfigType::Select: return "select";
    case CustomConfigType::Text:
    default: return "text";
  }
}

const char *planActionName(PlanAction action) {
  switch (action) {
    case PlanAction::Complete: return "complete";
    case PlanAction::Reset:
    default: return "reset";
  }
}

uint8_t planActionBit(PlanAction action) {
  return (uint8_t)(1u << (uint8_t)action);
}

const CustomConfigDef *findCustomConfigDef(const CustomConfigDef *defs, size_t count, const char *key) {
  for (size_t i = 0; i < count; i++) {
    if (strncmp(defs[i].key, key, sizeof(defs[i].key)) == 0) return &defs[i];
  }
  return nullptr;
}

bool validateCustomConfigValue(const CustomConfigDef &def, const std::string &value) {
  switch (def.type) {
    case CustomConfigType::Range: {
      if (value.empty()) return false;
      char *end = nullptr;
      long v = strtol(value.c_str(), &end, 10);
      if (end == value.c_str() || *end != '\0') return false; // kein sauberer Ganzzahl-String
      return v >= def.rangeMin && v <= def.rangeMax;
    }
    case CustomConfigType::Text:
      return value.size() <= def.textMaxLen;
    case CustomConfigType::Select:
      for (uint8_t i = 0; i < def.optionCount; i++) {
        if (value == def.options[i]) return true;
      }
      return false;
  }
  return false;
}

// ---- JSON-Wire-Format --------------------------------------------------------

namespace {

void writeCustomConfigDefJson(std::string &out, const CustomConfigDef &d) {
  out += '{';
  out += "\"key\":\""; appendJsonEscaped(out, d.key); out += "\",";
  out += "\"type\":\""; out += customConfigTypeName(d.type); out += "\",";
  switch (d.type) {
    case CustomConfigType::Range:
      out += "\"min\":"; out += std::to_string(d.rangeMin); out += ',';
      out += "\"max\":"; out += std::to_string(d.rangeMax); out += ',';
      break;
    case CustomConfigType::Text:
      out += "\"maxLength\":"; out += std::to_string(d.textMaxLen); out += ',';
      break;
    case CustomConfigType::Select:
      out += "\"options\":[";
      for (uint8_t i = 0; i < d.optionCount; i++) {
        if (i) out += ',';
        out += '"'; appendJsonEscaped(out, d.options[i]); out += '"';
      }
      out += "],";
      break;
  }
  out += "\"value\":\""; appendJsonEscaped(out, d.value); out += "\"";
  out += '}';
}

} // namespace

void writeComponentJson(std::string &out, const PeerInfo &p) {
  out += '{';
  out += "\"id\":"; out += std::to_string(p.id); out += ',';
  out += "\"uuid\":\""; appendJsonEscaped(out, p.uuid); out += "\",";
  out += "\"riddleId\":\""; appendJsonEscaped(out, p.riddleId); out += "\",";
  out += "\"name\":\""; appendJsonEscaped(out, p.name); out += "\",";
  out += "\"room\":\""; appendJsonEscaped(out, p.room); out += "\",";

  out += "\"ip\":\""; appendJsonEscaped(out, p.ip); out += "\",";
  out += "\"httpPort\":"; out += std::to_string(p.httpPort); out += ',';
  out += "\"battery\":"; out += std::to_string(p.battery); out += ',';
  out += "\"upTimeMs\":"; out += std::to_string(p.upTimeMs); out += ',';
  out += "\"slave\":"; out += (p.slave ? "true" : "false"); out += ',';

  out += "\"errors\":[";
  for (uint8_t i = 0; i < p.errorCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.errors[i]); out += '"';
  }
  out += "],";

  out += "\"actions\":[";
  for (uint8_t i = 0; i < p.actionCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.actions[i]); out += '"';
  }
  out += "],";

  out += "\"planActions\":[";
  bool firstPlanAction = true;
  const PlanAction planActions[] = {PlanAction::Reset, PlanAction::Complete};
  for (size_t i = 0; i < sizeof(planActions) / sizeof(planActions[0]); i++) {
    if (!(p.planActionMask & planActionBit(planActions[i]))) continue;
    if (!firstPlanAction) out += ',';
    firstPlanAction = false;
    out += '"'; out += planActionName(planActions[i]); out += '"';
  }
  out += "],";

  if (p.feed[0]) {
    out += "\"feed\":\""; appendJsonEscaped(out, p.feed); out += "\",";
  }

  if (p.tip[0]) {
    out += "\"tip\":\""; appendJsonEscaped(out, p.tip); out += "\",";
  }

  if (p.puzzleTotalSteps > 0) {
    out += "\"puzzle\":{";
    out += "\"step\":"; out += std::to_string(p.puzzleStep); out += ',';
    out += "\"totalSteps\":"; out += std::to_string(p.puzzleTotalSteps); out += ',';
    out += "\"state\":\""; appendJsonEscaped(out, p.puzzleState); out += "\",";
    out += "\"isHtml\":"; out += (p.puzzleIsHtml ? "true" : "false");
    out += "},";
  }

  if (p.customConfigCount) {
    out += "\"customConfig\":[";
    for (uint8_t i = 0; i < p.customConfigCount; i++) {
      if (i) out += ',';
      writeCustomConfigDefJson(out, p.customConfig[i]);
    }
    out += "],";
  }

  if (p.plan[0]) {
    out += "\"plan\":"; out += p.plan; out += ',';
  }

  if (p.eventSeq) {
    out += "\"evtSeq\":"; out += std::to_string(p.eventSeq); out += ',';
    out += "\"evtMsg\":\""; appendJsonEscaped(out, p.eventMsg); out += "\",";
  }

  out += "\"lastSeenMs\":"; out += std::to_string(p.lastSeenMs);
  out += '}';
}

void parseComponentIntoPeer(const EscapeJson::Value &comp, PeerInfo &p) {
  p.id = (uint8_t)fieldNumber(comp, "id", 0);
  copyBounded(p.uuid, sizeof(p.uuid), fieldString(comp, "uuid").c_str());
  copyBounded(p.riddleId, sizeof(p.riddleId), fieldString(comp, "riddleId").c_str());
  copyBounded(p.name, sizeof(p.name), fieldString(comp, "name").c_str());
  copyBounded(p.room, sizeof(p.room), fieldString(comp, "room").c_str());

  p.errorCount = 0;
  const EscapeJson::Value *errs = comp.find("errors");
  if (errs && errs->type == EscapeJson::Type::Array) {
    for (size_t i = 0; i < errs->arrayValue.size(); i++) {
      if (p.errorCount >= EscapeConfig::MAX_ERRORS) break;
      copyBounded(p.errors[p.errorCount], sizeof(p.errors[0]), errs->arrayValue[i].asString().c_str());
      p.errorCount++;
    }
  }

  p.actionCount = 0;
  const EscapeJson::Value *acts = comp.find("actions");
  if (acts && acts->type == EscapeJson::Type::Array) {
    for (size_t i = 0; i < acts->arrayValue.size(); i++) {
      if (p.actionCount >= EscapeConfig::MAX_ACTIONS) break;
      copyBounded(p.actions[p.actionCount], sizeof(p.actions[0]), acts->arrayValue[i].asString().c_str());
      p.actionCount++;
    }
  }

  p.planActionMask = 0;
  const EscapeJson::Value *planActs = comp.find("planActions");
  if (planActs && planActs->type == EscapeJson::Type::Array) {
    for (size_t i = 0; i < planActs->arrayValue.size(); i++) {
      const std::string action = planActs->arrayValue[i].asString();
      if (action == planActionName(PlanAction::Reset)) p.planActionMask |= planActionBit(PlanAction::Reset);
      if (action == planActionName(PlanAction::Complete)) p.planActionMask |= planActionBit(PlanAction::Complete);
    }
  }

  copyBounded(p.feed, sizeof(p.feed), fieldString(comp, "feed").c_str());
  copyBounded(p.tip, sizeof(p.tip), fieldString(comp, "tip").c_str());

  const EscapeJson::Value *puzzle = comp.find("puzzle");
  if (puzzle && puzzle->type == EscapeJson::Type::Object) {
    p.puzzleStep = (uint16_t)fieldNumber(*puzzle, "step", 0);
    p.puzzleTotalSteps = (uint16_t)fieldNumber(*puzzle, "totalSteps", 0);
    copyBounded(p.puzzleState, sizeof(p.puzzleState), fieldString(*puzzle, "state").c_str());
    const EscapeJson::Value *isHtml = puzzle->find("isHtml");
    p.puzzleIsHtml = isHtml ? isHtml->asBool(false) : false;
  } else {
    p.puzzleTotalSteps = 0;
  }

  p.customConfigCount = 0;
  const EscapeJson::Value *cc = comp.find("customConfig");
  if (cc && cc->type == EscapeJson::Type::Array) {
    for (size_t i = 0; i < cc->arrayValue.size(); i++) {
      const EscapeJson::Value &item = cc->arrayValue[i];
      if (item.type != EscapeJson::Type::Object) continue;
      if (p.customConfigCount >= EscapeConfig::MAX_CUSTOM_CONFIGS) break;
      CustomConfigDef &d = p.customConfig[p.customConfigCount];
      d = CustomConfigDef();
      copyBounded(d.key, sizeof(d.key), fieldString(item, "key").c_str());
      std::string type = fieldString(item, "type");
      if (type.empty()) type = "text";
      if (type == "range") {
        d.type = CustomConfigType::Range;
        d.rangeMin = (int32_t)fieldNumber(item, "min", 0);
        d.rangeMax = (int32_t)fieldNumber(item, "max", 0);
      } else if (type == "select") {
        d.type = CustomConfigType::Select;
        const EscapeJson::Value *opts = item.find("options");
        if (opts && opts->type == EscapeJson::Type::Array) {
          for (size_t j = 0; j < opts->arrayValue.size(); j++) {
            if (d.optionCount >= EscapeConfig::MAX_CONFIG_OPTIONS) break;
            copyBounded(d.options[d.optionCount], sizeof(d.options[0]), opts->arrayValue[j].asString().c_str());
            d.optionCount++;
          }
        }
      } else {
        d.type = CustomConfigType::Text;
        d.textMaxLen = (uint16_t)fieldNumber(item, "maxLength", 0);
      }
      const EscapeJson::Value *value = item.find("value");
      copyBounded(d.value, sizeof(d.value), value ? value->asStringLoose().c_str() : "");
      p.customConfigCount++;
    }
  }

  const EscapeJson::Value *plan = comp.find("plan");
  if (plan && plan->type != EscapeJson::Type::Null) {
    std::string planStr;
    EscapeJson::stringify(*plan, planStr);
    copyBounded(p.plan, sizeof(p.plan), planStr.c_str());
  } else {
    p.plan[0] = '\0';
  }

  p.eventSeq = (uint32_t)fieldNumber(comp, "evtSeq", 0);
  copyBounded(p.eventMsg, sizeof(p.eventMsg), fieldString(comp, "evtMsg").c_str());
}

// ---- Peer-Tabelle -------------------------------------------------------------

PeerInfo *PeerTable::findOrCreate(const char *name, const char *room) {
  for (size_t i = 0; i < count_; i++) {
    if (strncmp(peers_[i].name, name, sizeof(peers_[i].name)) == 0 &&
        strncmp(peers_[i].room, room, sizeof(peers_[i].room)) == 0) {
      return &peers_[i];
    }
  }
  if (count_ < EscapeConfig::MAX_PEERS) {
    return &peers_[count_++];
  }
  // Tabelle voll (z.B. viele kurzlebige/testweise Komponenten im Netz):
  // am laengsten nicht gesehenen Eintrag verdraengen statt neue zu verwerfen.
  size_t oldest = 0;
  for (size_t i = 1; i < count_; i++) {
    if (peers_[i].lastSeenMs < peers_[oldest].lastSeenMs) oldest = i;
  }
  return &peers_[oldest];
}

void PeerTable::expireStale(uint32_t nowMs, uint32_t timeoutMs) {
  size_t w = 0;
  for (size_t i = 0; i < count_; i++) {
    if (nowMs - peers_[i].lastSeenMs <= timeoutMs) {
      if (w != i) peers_[w] = peers_[i];
      w++;
    }
  }
  count_ = w;
}

// ---- Leichte Peer-Adresstabelle ------------------------------------------------

PeerAddress *PeerAddressTable::findOrCreate(const char *ip, uint16_t httpPort) {
  for (size_t i = 0; i < count_; i++) {
    if (addrs_[i].httpPort == httpPort && strncmp(addrs_[i].ip, ip, sizeof(addrs_[i].ip)) == 0) return &addrs_[i];
  }
  // Neuer Eintrag: ip/httpPort SOFORT setzen, da genau diese beiden Felder
  // den Vergleich oben treiben - sonst findet ein direkt anschliessender
  // findOrCreate() mit denselben Argumenten diesen Slot nicht wieder.
  if (count_ < EscapeConfig::MAX_PEER_ADDRESSES) {
    PeerAddress *created = &addrs_[count_++];
    copyBounded(created->ip, sizeof(created->ip), ip);
    created->httpPort = httpPort;
    return created;
  }
  // Tabelle voll: am laengsten nicht gesehene Adresse verdraengen statt eine
  // neue zu verwerfen (analog PeerTable::findOrCreate()).
  size_t oldest = 0;
  for (size_t i = 1; i < count_; i++) {
    if (addrs_[i].lastSeenMs < addrs_[oldest].lastSeenMs) oldest = i;
  }
  PeerAddress *evicted = &addrs_[oldest];
  copyBounded(evicted->ip, sizeof(evicted->ip), ip);
  evicted->httpPort = httpPort;
  return evicted;
}

void PeerAddressTable::expireStale(uint32_t nowMs, uint32_t timeoutMs) {
  size_t w = 0;
  for (size_t i = 0; i < count_; i++) {
    if (nowMs - addrs_[i].lastSeenMs <= timeoutMs) {
      if (w != i) addrs_[w] = addrs_[i];
      w++;
    }
  }
  count_ = w;
}

// ---- Bearbeitungssperre nach Aenderung ("Optimistic Lock") ------------------

bool mutationLockEnabled(MutationType type) {
  switch (type) {
    case MutationType::Action: return EscapeConfig::LOCK_UNTIL_FETCHED_ACTION;
    case MutationType::PlanAction: return EscapeConfig::LOCK_UNTIL_FETCHED_PLAN_ACTION;
    case MutationType::Config: return EscapeConfig::LOCK_UNTIL_FETCHED_CONFIG;
    case MutationType::Plan: return EscapeConfig::LOCK_UNTIL_FETCHED_PLAN;
    case MutationType::PlanSkeleton: return EscapeConfig::LOCK_UNTIL_FETCHED_PLAN_SKELETON;
  }
  return false;
}

bool ChangeLock::isLocked(MutationType type) const {
  return mutationLockEnabled(type) && pending_[(size_t)type];
}

void ChangeLock::markChanged(MutationType type) {
  pending_[(size_t)type] = true;
}

void ChangeLock::noteStatusFetched() {
  // NUR die in status.json sichtbaren Typen - PlanSkeleton bleibt unberuehrt,
  // das raumweite Skeleton wird dort gar nicht mit ausgegeben.
  pending_[(size_t)MutationType::Action] = false;
  pending_[(size_t)MutationType::PlanAction] = false;
  pending_[(size_t)MutationType::Config] = false;
  pending_[(size_t)MutationType::Plan] = false;
}

void ChangeLock::notePlanSkeletonFetched() {
  pending_[(size_t)MutationType::PlanSkeleton] = false;
}

bool ChangeLock::hasUnseenStatusChange() const {
  return pending_[(size_t)MutationType::Action] || pending_[(size_t)MutationType::PlanAction] ||
         pending_[(size_t)MutationType::Config] || pending_[(size_t)MutationType::Plan];
}

bool ChangeLock::hasUnseenPlanSkeletonChange() const {
  return pending_[(size_t)MutationType::PlanSkeleton];
}

// ---- Discovery-Broadcast (nur IP+Port), /peers.json, /status.json ----------

std::string buildPeerAnnouncementJson(uint16_t httpPort, bool statusChanged, bool planSkeletonChanged) {
  std::string out;
  out += "{\"httpPort\":"; out += std::to_string(httpPort); out += ',';
  out += "\"statusChanged\":"; out += (statusChanged ? "true" : "false"); out += ',';
  out += "\"planSkeletonChanged\":"; out += (planSkeletonChanged ? "true" : "false");
  out += '}';
  return out;
}

void ingestPeerAnnouncement(const std::string &json, const std::string &senderIp, const std::string &ownIp,
                            uint32_t nowMs, PeerAddressTable &peers, uint16_t ownHttpPort) {
  if (senderIp.empty()) return;
  EscapeJson::Value doc;
  if (!EscapeJson::parse(json, doc) || doc.type != EscapeJson::Type::Object) return;

  double httpPortValue = fieldNumber(doc, "httpPort", EscapeConfig::HTTP_PORT);
  uint16_t httpPort = httpPortValue >= 1 && httpPortValue <= 65535
      ? (uint16_t)httpPortValue
      : EscapeConfig::HTTP_PORT;

  // Nicht nur nach IP filtern: mehrere Instanzen auf demselben Rechner (z.B.
  // PC-Simulatoren, siehe Kopfkommentar der jeweiligen Sim-Datei) teilen sich
  // dieselbe IP und unterscheiden sich nur durch httpPort.
  if (senderIp == ownIp && httpPort == ownHttpPort) return; // eigene (Loopback-)Broadcasts ignorieren

  PeerAddress *p = peers.findOrCreate(senderIp.c_str(), httpPort);
  if (!p) return;
  copyBounded(p->ip, sizeof(p->ip), senderIp.c_str());
  p->httpPort = httpPort;
  p->lastSeenMs = nowMs;
  const EscapeJson::Value *statusChangedVal = doc.find("statusChanged");
  p->statusChanged = statusChangedVal ? statusChangedVal->asBool(false) : false;
  const EscapeJson::Value *planSkeletonChangedVal = doc.find("planSkeletonChanged");
  p->planSkeletonChanged = planSkeletonChangedVal ? planSkeletonChangedVal->asBool(false) : false;
}

std::string buildPeersJson(const PeerAddressTable &peers) {
  std::string out;
  out += '[';
  for (size_t i = 0; i < peers.count(); i++) {
    if (i) out += ',';
    const PeerAddress &p = peers.at(i);
    out += "{\"ip\":\""; appendJsonEscaped(out, p.ip); out += "\",";
    out += "\"httpPort\":"; out += std::to_string(p.httpPort); out += ',';
    out += "\"statusChanged\":"; out += (p.statusChanged ? "true" : "false"); out += ',';
    out += "\"planSkeletonChanged\":"; out += (p.planSkeletonChanged ? "true" : "false"); out += ',';
    out += "\"lastSeenMs\":"; out += std::to_string(p.lastSeenMs);
    out += '}';
  }
  out += ']';
  return out;
}

std::string buildStatusJson(const ProtocolAdapter &host, const std::string &deviceIp,
                             uint32_t nowMs, uint16_t httpPort) {
  std::string out;
  out.reserve(256 + host.componentCount() * (700 + EscapeConfig::MAX_PLAN_LEN));
  out += '[';
  uint8_t n = host.componentCount();
  for (uint8_t i = 0; i < n; i++) {
    if (i) out += ',';
    // "static" statt Stack-lokal: sizeof(PeerInfo) ~4 KB ist eine grosse
    // Teilmenge des 8 KB loopTask-Stacks (ARDUINO_LOOP_STACK_SIZE) - diese
    // Funktion wird ausserdem aus einem HTTP-Handler heraus aufgerufen, der
    // selbst schon Stack-Tiefe (WebServer/Lambda) mitbringt. host.snapshot()
    // (-> fillSnapshot) ueberschreibt inzwischen JEDES Feld unconditional
    // (siehe dortigen Kommentar zu feed/tip/puzzle), plus die device-weiten
    // Felder werden unten immer gesetzt - ein wiederverwendeter Slot ist
    // also gefahrlos.
    static PeerInfo p;
    host.snapshot(i, p);
    p.id = i;
    copyBounded(p.ip, sizeof(p.ip), deviceIp.c_str());
    p.httpPort = httpPort;
    p.battery = host.battery();
    p.upTimeMs = host.upTimeMs();
    p.slave = host.isSlave();
    p.lastSeenMs = nowMs;
    writeComponentJson(out, p);
  }
  out += ']';
  return out;
}

void ingestStatusJson(const std::string &json, uint32_t nowMs, PeerTable &peers) {
  EscapeJson::Value doc;
  if (!EscapeJson::parse(json, doc) || doc.type != EscapeJson::Type::Array) return;

  for (size_t i = 0; i < doc.arrayValue.size(); i++) {
    const EscapeJson::Value &comp = doc.arrayValue[i];
    if (comp.type != EscapeJson::Type::Object) continue;
    std::string name = fieldString(comp, "name");
    std::string room = fieldString(comp, "room");
    if (name.empty() || room.empty()) continue;

    PeerInfo *p = peers.findOrCreate(name.c_str(), room.c_str());
    if (!p) continue;
    parseComponentIntoPeer(comp, *p);

    copyBounded(p->ip, sizeof(p->ip), fieldString(comp, "ip").c_str());
    double httpPortValue = fieldNumber(comp, "httpPort", EscapeConfig::HTTP_PORT);
    p->httpPort = httpPortValue >= 1 && httpPortValue <= 65535 ? (uint16_t)httpPortValue : EscapeConfig::HTTP_PORT;
    p->battery = (int8_t)fieldNumber(comp, "battery", -1);
    p->upTimeMs = (uint32_t)fieldNumber(comp, "upTimeMs", 0);
    const EscapeJson::Value *slaveVal = comp.find("slave");
    p->slave = slaveVal ? slaveVal->asBool(false) : false;
    p->lastSeenMs = nowMs; // lokale Empfangszeit statt des (potenziell leicht versetzten) Peer-Zeitstempels
  }
}

// ---- HTTP-Anfragen ------------------------------------------------------------

HttpResult handleActionRequest(ProtocolAdapter &host, const HttpRequest &req) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};

  EscapeJson::Value doc;
  if (!EscapeJson::parse(req.body, doc) || doc.type != EscapeJson::Type::Object) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }
  // "id" waehlt die Ziel-Komponente auf diesem Board aus; fehlt es, wird
  // Komponente 0 angenommen (rueckwaertskompatibel zu Boards mit nur einer
  // Komponente).
  uint8_t id = (uint8_t)fieldNumber(doc, "id", 0);
  if (id >= host.componentCount()) return HttpResult{400, "{\"error\":\"invalid id\"}"};

  std::string action = fieldString(doc, "action");
  if (action.empty() || action.size() > EscapeConfig::MAX_ACTION_LEN) {
    return HttpResult{400, "{\"error\":\"invalid action\"}"};
  }

  bool ok = host.applyAction(id, action);
  if (ok) host.pushEvent(id, "Aktion \"" + action + "\" ausgefuehrt");
  host.markDirty(); // Zustand hat sich moeglicherweise geaendert -> zeitnah neu broadcasten
  return HttpResult{ok ? 200 : 422, ok ? "{\"ok\":true}" : "{\"ok\":false}"};
}

HttpResult handlePlanActionRequest(ProtocolAdapter &host, const HttpRequest &req) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};

  EscapeJson::Value doc;
  if (!EscapeJson::parse(req.body, doc) || doc.type != EscapeJson::Type::Object) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }
  uint8_t id = (uint8_t)fieldNumber(doc, "id", 0);
  if (id >= host.componentCount()) return HttpResult{400, "{\"error\":\"invalid id\"}"};

  const std::string actionText = fieldString(doc, "action");
  PlanAction action;
  if (actionText == planActionName(PlanAction::Reset)) {
    action = PlanAction::Reset;
  } else if (actionText == planActionName(PlanAction::Complete)) {
    action = PlanAction::Complete;
  } else {
    return HttpResult{400, "{\"error\":\"invalid plan action\"}"};
  }

  PeerInfo component;
  host.snapshot(id, component);
  if (!(component.planActionMask & planActionBit(action))) {
    return HttpResult{422, "{\"error\":\"plan action unsupported\"}"};
  }

  const bool ok = host.applyPlanAction(id, action);
  if (ok) {
    host.pushEvent(id, action == PlanAction::Reset
        ? "Ablaufplan-Fortschritt zurueckgesetzt"
        : "Ablaufplan-Komponente abgeschlossen");
  }
  host.markDirty();
  return HttpResult{ok ? 200 : 422, ok ? "{\"ok\":true}" : "{\"ok\":false}"};
}

HttpResult handleConfigRequest(ProtocolAdapter &host, const HttpRequest &req) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};

  EscapeJson::Value doc;
  if (!EscapeJson::parse(req.body, doc) || doc.type != EscapeJson::Type::Object) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }
  uint8_t id = (uint8_t)fieldNumber(doc, "id", 0);
  if (id >= host.componentCount()) return HttpResult{400, "{\"error\":\"invalid id\"}"};

  std::string name = fieldString(doc, "name");
  std::string room = fieldString(doc, "room");
  bool identityGiven = !name.empty() || !room.empty();
  if (identityGiven && (name.empty() || room.empty() || name.size() > EscapeConfig::MAX_NAME_LEN ||
                        room.size() > EscapeConfig::MAX_ROOM_LEN)) {
    return HttpResult{400, "{\"error\":\"invalid name/room\"}"};
  }

  const EscapeJson::Value *customCfg = doc.find("config");
  bool customCfgApplied = false;
  if (customCfg && customCfg->type == EscapeJson::Type::Object) {
    std::vector<CustomConfigDef> defs;
    host.customConfigDefs(id, defs);
    if (defs.empty()) {
      return HttpResult{400, "{\"error\":\"component has no custom config\"}"};
    }

    // Erst alle Werte gegen das deklarierte Schema validieren, dann erst
    // anwenden - vermeidet Teilanwendung bei einer ungueltigen Anfrage.
    for (std::map<std::string, EscapeJson::Value>::const_iterator it = customCfg->objectValue.begin();
         it != customCfg->objectValue.end(); ++it) {
      const CustomConfigDef *def = findCustomConfigDef(defs.data(), defs.size(), it->first.c_str());
      std::string value = it->second.asStringLoose();
      if (!def || !validateCustomConfigValue(*def, value)) {
        return HttpResult{400, "{\"error\":\"invalid config value\"}"};
      }
    }
    for (std::map<std::string, EscapeJson::Value>::const_iterator it = customCfg->objectValue.begin();
         it != customCfg->objectValue.end(); ++it) {
      host.setCustomConfigValue(id, it->first, it->second.asStringLoose());
    }
    customCfgApplied = true;
  }

  if (identityGiven) host.setIdentity(id, name, room);

  // Geraeteweit unabhaengig von Name/Raum, siehe PeerInfo::riddleId - erlaubt
  // z.B. ein Ersatzgeraet manuell auf dieselbe riddleId des ausgetauschten
  // Originals zu setzen.
  std::string riddleId = fieldString(doc, "riddleId");
  bool riddleIdGiven = !riddleId.empty();
  if (riddleIdGiven && riddleId.size() > EscapeConfig::MAX_RIDDLE_ID_LEN) {
    return HttpResult{400, "{\"error\":\"invalid riddleId\"}"};
  }
  if (riddleIdGiven) host.setRiddleId(id, riddleId);

  // Geraeteweit (nicht pro Komponente, "id" bleibt trotzdem erforderlich, um
  // ein gueltiges Ziel-Board zu adressieren) - siehe ProtocolAdapter::setSlave().
  const EscapeJson::Value *slaveVal = doc.find("slave");
  bool slaveGiven = slaveVal != nullptr;
  if (slaveGiven) host.setSlave(slaveVal->asBool(false));

  std::string eventMsg;
  if (customCfgApplied) eventMsg += "Konfiguration geaendert";
  if (identityGiven) {
    if (!eventMsg.empty()) eventMsg += ", ";
    eventMsg += "Name/Raum geaendert";
  }
  if (riddleIdGiven) {
    if (!eventMsg.empty()) eventMsg += ", ";
    eventMsg += "Raetsel-ID geaendert";
  }
  if (slaveGiven) {
    if (!eventMsg.empty()) eventMsg += ", ";
    eventMsg += slaveVal->asBool(false) ? "als Slave markiert" : "Slave-Markierung entfernt";
  }
  if (!eventMsg.empty()) host.pushEvent(id, eventMsg);

  host.markDirty();
  return HttpResult{200, "{\"ok\":true}"};
}

HttpResult handlePlanRequest(ProtocolAdapter &host, const HttpRequest &req) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};
  if (req.body.size() > EscapeConfig::MAX_PLAN_LEN + 256) {
    return HttpResult{413, "{\"error\":\"plan too large\"}"};
  }

  EscapeJson::Value doc;
  if (!EscapeJson::parse(req.body, doc) || doc.type != EscapeJson::Type::Object) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }
  uint8_t id = (uint8_t)fieldNumber(doc, "id", 0);
  if (id >= host.componentCount()) return HttpResult{400, "{\"error\":\"invalid id\"}"};

  const EscapeJson::Value *planVal = doc.find("plan");
  bool cleared = !planVal || planVal->type == EscapeJson::Type::Null;
  std::string planText;
  if (!cleared) {
    EscapeJson::stringify(*planVal, planText);
    if (planText.size() > EscapeConfig::MAX_PLAN_LEN) {
      return HttpResult{413, "{\"error\":\"plan too large\"}"};
    }
  }

  host.setPlan(id, planText); // "plan":null (oder fehlend) loescht die Zuordnung wieder
  host.pushEvent(id, cleared ? "Ablaufplan-Zuordnung entfernt" : "Ablaufplan aktualisiert");
  host.markDirty(); // Slice ist Teil des naechsten Broadcasts
  return HttpResult{200, "{\"ok\":true}"};
}

HttpResult handlePlanSkeletonGetRequest(const std::string &skeletonStorage) {
  return HttpResult{200, skeletonStorage.empty() ? std::string("{\"plans\":[]}") : skeletonStorage};
}

namespace {

bool collectPlanSkeletons(const EscapeJson::Value &root,
                          std::map<std::string, EscapeJson::Value> &plans) {
  if (root.type != EscapeJson::Type::Object) return false;

  const EscapeJson::Value *collection = root.find("plans");
  if (collection) {
    if (collection->type != EscapeJson::Type::Array) return false;
    for (size_t i = 0; i < collection->arrayValue.size(); i++) {
      const EscapeJson::Value &plan = collection->arrayValue[i];
      const EscapeJson::Value *room = plan.find("room");
      if (!room || room->type != EscapeJson::Type::String || room->stringValue.empty()) return false;
      plans[room->stringValue] = plan;
    }
    return true;
  }

  const EscapeJson::Value *room = root.find("room");
  if (!room || room->type != EscapeJson::Type::String || room->stringValue.empty()) return false;
  plans[room->stringValue] = root;
  return true;
}

} // namespace

bool mergePlanSkeletonStorage(const std::string &currentStorage,
                              const std::string &incomingStorage,
                              std::string &mergedStorage) {
  EscapeJson::Value incoming;
  if (!EscapeJson::parse(incomingStorage, incoming)) return false;

  std::map<std::string, EscapeJson::Value> plans;
  if (!currentStorage.empty() && currentStorage != "{}") {
    EscapeJson::Value current;
    if (EscapeJson::parse(currentStorage, current)) {
      // Eine beschaedigte/alte Speicherung darf einen neuen gueltigen Plan
      // nicht blockieren; nur gueltige bestehende Raeume werden uebernommen.
      collectPlanSkeletons(current, plans);
    }
  }
  if (!collectPlanSkeletons(incoming, plans)) return false;
  if (plans.size() > EscapeConfig::MAX_LOCAL_COMPONENTS) return false;

  std::string result = "{\"plans\":[";
  bool first = true;
  for (std::map<std::string, EscapeJson::Value>::const_iterator it = plans.begin();
       it != plans.end(); ++it) {
    if (!first) result += ',';
    first = false;
    EscapeJson::stringify(it->second, result);
  }
  result += "]}";
  if (result.size() > EscapeConfig::MAX_PLAN_SKELETON_STORAGE_LEN) return false;
  mergedStorage.swap(result);
  return true;
}

HttpResult handlePlanSkeletonPostRequest(ProtocolAdapter &host, const HttpRequest &req, std::string &skeletonStorage) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};
  if (req.body.size() > EscapeConfig::MAX_PLAN_SKELETON_LEN) {
    return HttpResult{413, "{\"error\":\"skeleton too large\"}"};
  }
  EscapeJson::Value postedSkeleton;
  if (!EscapeJson::parse(req.body, postedSkeleton)) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }
  const EscapeJson::Value *postedRoom = postedSkeleton.find("room");
  if (!postedRoom || postedRoom->type != EscapeJson::Type::String || postedRoom->stringValue.empty()) {
    return HttpResult{400, "{\"error\":\"missing plan room\"}"};
  }
  std::string mergedStorage;
  if (!mergePlanSkeletonStorage(skeletonStorage, req.body, mergedStorage)) {
    return HttpResult{400, "{\"error\":\"invalid plan skeleton storage\"}"};
  }
  skeletonStorage.swap(mergedStorage);

  // Nur lokale Komponenten des gespeicherten Raums benachrichtigen. Ein Board
  // kann Komponenten mehrerer Raeume tragen, deren Plaene unabhaengig sind.
  uint8_t n = host.componentCount();
  for (uint8_t i = 0; i < n; i++) {
    std::string name, room;
    host.identity(i, name, room);
    if (room == postedRoom->stringValue) host.pushEvent(i, "Raum-Ablaufplan aktualisiert");
  }

  return HttpResult{200, "{\"ok\":true}"};
}

// ---- Timing-Entscheidungen ----------------------------------------------------

bool isHeartbeatDue(uint32_t nowMs, uint32_t lastBroadcastMs, uint32_t intervalMs) {
  return (nowMs - lastBroadcastMs) >= intervalMs;
}

bool isChangeBroadcastDue(uint32_t nowMs, uint32_t lastBroadcastMs, bool dirty) {
  return dirty && (nowMs - lastBroadcastMs) >= EscapeConfig::CHANGE_MIN_GAP_MS;
}

// ---- Uptime-Abgleich mit laenger laufenden Peers -----------------------------

bool shouldAdoptFromPeer(bool ownSlave, uint32_t ownUpTimeMs, const PeerInfo &peer) {
  if (peer.slave) return false; // Slaves sind selbst nie Quelle der Wahrheit
  if (ownSlave) return true;    // Ein eigener Slave uebernimmt immer, Uptime irrelevant
  return peer.upTimeMs > ownUpTimeMs;
}

const PeerInfo *findSkeletonSyncSource(const ProtocolAdapter &host, const PeerTable &peers) {
  bool ownSlave = host.isSlave();
  uint32_t ownUp = host.upTimeMs();
  uint8_t n = host.componentCount();

  const PeerInfo *best = nullptr;
  for (size_t j = 0; j < peers.count(); j++) {
    const PeerInfo &cand = peers.at(j);
    if (!shouldAdoptFromPeer(ownSlave, ownUp, cand)) continue;

    bool roomMatches = false;
    for (uint8_t i = 0; i < n && !roomMatches; i++) {
      std::string name, room;
      host.identity(i, name, room);
      if (room == cand.room) roomMatches = true;
    }
    if (!roomMatches) continue;

    if (!best || cand.upTimeMs > best->upTimeMs) best = &cand;
  }
  return best;
}

} // namespace EscapeProtocol
