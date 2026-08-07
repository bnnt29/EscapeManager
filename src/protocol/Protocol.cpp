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

void writeComponentJson(std::string &out, const PeerInfo &p, bool includeDeviceFields) {
  out += '{';
  out += "\"id\":"; out += std::to_string(p.id); out += ',';
  out += "\"uuid\":\""; appendJsonEscaped(out, p.uuid); out += "\",";
  out += "\"name\":\""; appendJsonEscaped(out, p.name); out += "\",";
  out += "\"room\":\""; appendJsonEscaped(out, p.room); out += "\",";

  if (includeDeviceFields) {
    out += "\"ip\":\""; appendJsonEscaped(out, p.ip); out += "\",";
    out += "\"battery\":"; out += std::to_string(p.battery); out += ',';
  }

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

  if (p.feed[0]) {
    out += "\"feed\":\""; appendJsonEscaped(out, p.feed); out += "\",";
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

  if (includeDeviceFields) {
    out += "\"lastSeenMs\":"; out += std::to_string(p.lastSeenMs);
  } else {
    // Kein unbedingtes Feld mehr uebrig (lastSeenMs wird hier nicht
    // ausgegeben) - ueberzaehliges Komma vom letzten Feld entfernen.
    if (!out.empty() && out.back() == ',') out.pop_back();
  }
  out += '}';
}

void parseComponentIntoPeer(const EscapeJson::Value &comp, PeerInfo &p) {
  p.id = (uint8_t)fieldNumber(comp, "id", 0);
  copyBounded(p.uuid, sizeof(p.uuid), fieldString(comp, "uuid").c_str());
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

  copyBounded(p.feed, sizeof(p.feed), fieldString(comp, "feed").c_str());

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

// ---- Broadcast senden/empfangen, status.json ---------------------------------

std::string buildBroadcastJson(const ComponentHost &host, const std::string &deviceIp) {
  std::string out;
  out += "{\"ip\":\""; appendJsonEscaped(out, deviceIp.c_str()); out += "\",";
  out += "\"battery\":"; out += std::to_string(host.battery()); out += ',';
  out += "\"components\":[";
  uint8_t n = host.componentCount();
  for (uint8_t i = 0; i < n; i++) {
    if (i) out += ',';
    PeerInfo p;
    host.snapshot(i, p);
    p.id = i;
    writeComponentJson(out, p, /*includeDeviceFields=*/false);
  }
  out += "]}";
  return out;
}

std::string buildStatusJson(const ComponentHost &host, const PeerTable &peers, const std::string &deviceIp,
                             uint32_t nowMs) {
  std::string out;
  out.reserve(256 + (peers.count() + host.componentCount()) * (700 + EscapeConfig::MAX_PLAN_LEN));
  out += '[';
  uint8_t n = host.componentCount();
  bool first = true;
  for (uint8_t i = 0; i < n; i++) {
    if (!first) out += ',';
    first = false;
    PeerInfo p;
    host.snapshot(i, p);
    p.id = i;
    copyBounded(p.ip, sizeof(p.ip), deviceIp.c_str());
    p.battery = host.battery();
    p.lastSeenMs = nowMs;
    writeComponentJson(out, p, true);
  }
  for (size_t i = 0; i < peers.count(); i++) {
    if (!first) out += ',';
    first = false;
    writeComponentJson(out, peers.at(i), true);
  }
  out += ']';
  return out;
}

void ingestBroadcast(const std::string &json, const std::string &senderIp, uint32_t nowMs, const ComponentHost &self,
                      PeerTable &peers) {
  EscapeJson::Value doc;
  if (!EscapeJson::parse(json, doc) || doc.type != EscapeJson::Type::Object) return;

  const EscapeJson::Value *comps = doc.find("components");
  if (!comps || comps->type != EscapeJson::Type::Array) return;
  int8_t senderBattery = (int8_t)fieldNumber(doc, "battery", -1);

  uint8_t selfCount = self.componentCount();
  for (size_t i = 0; i < comps->arrayValue.size(); i++) {
    const EscapeJson::Value &comp = comps->arrayValue[i];
    if (comp.type != EscapeJson::Type::Object) continue;
    std::string name = fieldString(comp, "name");
    std::string room = fieldString(comp, "room");
    if (name.empty() || room.empty()) continue;

    // Eigene Komponenten ignorieren (Identitaet, nicht IP - ein Board kann
    // seine IP per DHCP wechseln, ohne dass sich name/room aendern).
    bool isSelf = false;
    for (uint8_t j = 0; j < selfCount; j++) {
      std::string ownName, ownRoom;
      self.identity(j, ownName, ownRoom);
      if (ownName == name && ownRoom == room) {
        isSelf = true;
        break;
      }
    }
    if (isSelf) continue;

    PeerInfo *p = peers.findOrCreate(name.c_str(), room.c_str());
    if (!p) continue;
    parseComponentIntoPeer(comp, *p);
    copyBounded(p->ip, sizeof(p->ip), senderIp.c_str());
    p->battery = senderBattery;
    p->lastSeenMs = nowMs;
  }
}

// ---- HTTP-Anfragen ------------------------------------------------------------

HttpResult handleActionRequest(ComponentHost &host, const HttpRequest &req) {
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

HttpResult handleConfigRequest(ComponentHost &host, const HttpRequest &req) {
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

  std::string eventMsg;
  if (customCfgApplied) eventMsg += "Konfiguration geaendert";
  if (identityGiven) {
    if (!eventMsg.empty()) eventMsg += ", ";
    eventMsg += "Name/Raum geaendert";
  }
  if (!eventMsg.empty()) host.pushEvent(id, eventMsg);

  host.markDirty();
  return HttpResult{200, "{\"ok\":true}"};
}

HttpResult handlePlanRequest(ComponentHost &host, const HttpRequest &req) {
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
  return HttpResult{200, skeletonStorage.empty() ? std::string("{}") : skeletonStorage};
}

HttpResult handlePlanSkeletonPostRequest(ComponentHost &host, const HttpRequest &req, std::string &skeletonStorage) {
  if (!req.authOk) return HttpResult{401, "{\"error\":\"unauthorized\"}"};
  if (req.body.empty()) return HttpResult{400, "{\"error\":\"missing body\"}"};
  if (req.body.size() > EscapeConfig::MAX_PLAN_SKELETON_LEN) {
    return HttpResult{413, "{\"error\":\"skeleton too large\"}"};
  }
  // Nur auf gueltiges JSON pruefen - der Inhalt (Ebenen/Lanes/...) ist fuer
  // Client/Sim bedeutungslos, er wird nur unveraendert gespeichert/geliefert.
  EscapeJson::Value doc;
  if (!EscapeJson::parse(req.body, doc)) {
    return HttpResult{400, "{\"error\":\"invalid json\"}"};
  }

  skeletonStorage = req.body;

  // Betrifft den ganzen Raum (alle lokalen Komponenten dieses Boards) - jede
  // von ihnen bekommt daher eine eigene Aktivitaets-Meldung, damit Manager,
  // die eine andere Komponente desselben Raums beobachten, es ebenfalls sehen.
  uint8_t n = host.componentCount();
  for (uint8_t i = 0; i < n; i++) host.pushEvent(i, "Raum-Ablaufplan aktualisiert");

  return HttpResult{200, "{\"ok\":true}"};
}

// ---- Timing-Entscheidungen ----------------------------------------------------

bool isHeartbeatDue(uint32_t nowMs, uint32_t lastBroadcastMs, uint32_t intervalMs) {
  return (nowMs - lastBroadcastMs) >= intervalMs;
}

bool isChangeBroadcastDue(uint32_t nowMs, uint32_t lastBroadcastMs, bool dirty) {
  return dirty && (nowMs - lastBroadcastMs) >= EscapeConfig::CHANGE_MIN_GAP_MS;
}

} // namespace EscapeProtocol
