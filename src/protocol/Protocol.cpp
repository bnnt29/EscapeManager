// Implementation of Protocol.hpp (see there and PROTOCOL.md).

#include "Protocol.hpp"

#include "Base64Url.hpp"
#include "Compat.hpp"
#include "EscapeVersion.hpp"

#include <cstdlib>
#include <memory>

namespace EscapeProtocol {

using EscapeJson::appendEscaped;
using EscapeJson::appendUInt;

// ---- Small helpers --------------------------------------------------------------------

void copyBounded(char *dst, size_t dstSize, const char *src) {
  if (dstSize == 0) return;
  strncpy(dst, src ? src : "", dstSize - 1);
  dst[dstSize - 1] = '\0';
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

uint8_t planActionBit(PlanAction action) { return (uint8_t)(1u << (uint8_t)action); }

const CustomConfigDef *findCustomConfigDef(const CustomConfigDef *defs, size_t count, const char *key) {
  for (size_t i = 0; i < count; i++) {
    if (strncmp(defs[i].key, key, sizeof(defs[i].key)) == 0) return &defs[i];
  }
  return nullptr;
}

bool validateCustomConfigValue(const CustomConfigDef &def, const std::string &value) {
  switch (def.type) {
    case CustomConfigType::Range: {
      if (value.empty() || value.size() > 12) return false;
      size_t i = 0;
      if (value[0] == '-') i = 1;
      if (i >= value.size()) return false;
      long long v = 0;
      for (; i < value.size(); i++) {
        if (value[i] < '0' || value[i] > '9') return false; // strict integer text
        v = v * 10 + (value[i] - '0');
      }
      if (value[0] == '-') v = -v;
      return v >= def.rangeMin && v <= def.rangeMax;
    }
    case CustomConfigType::Text:
      return value.size() <= def.textMaxLen && value.size() <= EscapeConfig::MAX_CONFIG_VALUE_LEN;
    case CustomConfigType::Select:
      for (uint8_t i = 0; i < def.optionCount && i < EscapeConfig::MAX_CONFIG_OPTIONS; i++) {
        if (value == def.options[i]) return true;
      }
      return false;
  }
  return false;
}

std::vector<std::string> hostedRooms(const ProtocolAdapter &host) {
  std::vector<std::string> rooms;
  for (uint8_t i = 0; i < host.componentCount(); i++) {
    std::string name, room;
    host.identity(i, name, room);
    if (room.empty()) continue;
    bool seen = false;
    for (size_t k = 0; k < rooms.size(); k++) seen = seen || rooms[k] == room;
    if (!seen) rooms.push_back(room);
  }
  return rooms;
}

// ---- Documents ---------------------------------------------------------------------------------

namespace {

void appendStr(std::string &out, const char *key, const char *value) {
  out += '"';
  out += key;
  out += "\":\"";
  appendEscaped(out, value);
  out += '"';
}

void writeConfigDef(std::string &out, const CustomConfigDef &d) {
  out += '{';
  appendStr(out, "key", d.key);
  out += ",\"type\":\"";
  out += customConfigTypeName(d.type);
  out += "\",";
  switch (d.type) {
    case CustomConfigType::Range:
      out += "\"min\":";
      EscapeJson::appendInt(out, d.rangeMin);
      out += ",\"max\":";
      EscapeJson::appendInt(out, d.rangeMax);
      out += ',';
      break;
    case CustomConfigType::Text:
      out += "\"maxLength\":";
      appendUInt(out, d.textMaxLen);
      out += ',';
      break;
    case CustomConfigType::Select:
      out += "\"options\":[";
      for (uint8_t i = 0; i < d.optionCount && i < EscapeConfig::MAX_CONFIG_OPTIONS; i++) {
        if (i) out += ',';
        out += '"';
        appendEscaped(out, d.options[i]);
        out += '"';
      }
      out += "],";
      break;
  }
  appendStr(out, "value", d.value);
  out += '}';
}

bool isHttpUrl(const char *s) {
  return strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0;
}

void writeComponent(std::string &out, uint8_t id, const ComponentSnapshot &c) {
  out += "{\"id\":";
  appendUInt(out, id);
  out += ',';
  appendStr(out, "uuid", c.uuid);
  out += ',';
  appendStr(out, "riddleId", c.riddleId);
  out += ',';
  appendStr(out, "name", c.name);
  out += ',';
  appendStr(out, "room", c.room);

  out += ",\"errors\":[";
  for (uint8_t i = 0; i < c.errorCount && i < EscapeConfig::MAX_ERRORS; i++) {
    if (i) out += ',';
    out += '"';
    appendEscaped(out, c.errors[i]);
    out += '"';
  }
  out += "],\"actions\":[";
  for (uint8_t i = 0; i < c.actionCount && i < EscapeConfig::MAX_ACTIONS; i++) {
    if (i) out += ',';
    out += '"';
    appendEscaped(out, c.actions[i]);
    out += '"';
  }
  out += "],\"planActions\":[";
  bool first = true;
  const PlanAction all[2] = {PlanAction::Reset, PlanAction::Complete};
  for (int i = 0; i < 2; i++) {
    if (!(c.planActionMask & planActionBit(all[i]))) continue;
    if (!first) out += ',';
    first = false;
    out += '"';
    out += planActionName(all[i]);
    out += '"';
  }
  out += ']';

  if (c.feed[0] && isHttpUrl(c.feed)) {
    out += ',';
    appendStr(out, "feed", c.feed);
  }
  if (c.tip[0]) {
    out += ',';
    appendStr(out, "tip", c.tip);
  }
  if (c.puzzleTotalSteps > 0) {
    out += ",\"puzzle\":{\"step\":";
    appendUInt(out, c.puzzleStep);
    out += ",\"totalSteps\":";
    appendUInt(out, c.puzzleTotalSteps);
    out += ',';
    appendStr(out, "state", c.puzzleState);
    out += ",\"isHtml\":";
    out += c.puzzleIsHtml ? "true" : "false";
    out += '}';
  }
  if (c.customConfigCount) {
    out += ",\"customConfig\":[";
    for (uint8_t i = 0; i < c.customConfigCount && i < EscapeConfig::MAX_CUSTOM_CONFIGS; i++) {
      if (i) out += ',';
      writeConfigDef(out, c.customConfig[i]);
    }
    out += ']';
  }
  if (c.plan[0] && EscapeJson::validate(c.plan, strlen(c.plan), 16)) {
    out += ",\"plan\":";
    out += c.plan;
  }
  if (c.eventSeq) {
    out += ",\"evtSeq\":";
    appendUInt(out, c.eventSeq);
    out += ',';
    appendStr(out, "evtMsg", c.eventMsg);
  }
  out += '}';
}

void appendCommonDeviceFields(std::string &out, const DeviceInfo &info) {
  out += "\"proto\":";
  appendUInt(out, EscapeVersion::PROTO);
  out += ",\"pmin\":";
  appendUInt(out, EscapeVersion::PROTO_MIN);
  out += ",\"fw\":\"";
  out += EscapeVersion::FW;
  out += "\",\"ui\":\"";
  out += EscapeVersion::UI;
  out += "\",\"uih\":\"";
  out += EscapeVersion::UI_HASH;
  out += "\",\"did\":\"" + info.did + "\"";
}

} // namespace

std::string buildSecurityDoc(const DeviceInfo &info) {
  std::string out;
  out.reserve(512);
  out += '{';
  appendCommonDeviceFields(out, info);
  out += ",\"time\":";
  appendUInt(out, info.nowMs);
  out += ",\"token\":\"";
  out += Escape::tokenStateName(info.token);
  out += "\",\"writable\":";
  out += info.writable ? "true" : "false";
  out += ",\"strictGet\":";
  out += EscapeConfig::STRICT_GET ? "true" : "false";
  out += ",\"allowTokenInUrl\":";
  out += EscapeConfig::ALLOW_AUTH_TOKEN_IN_URL ? "true" : "false";
  out += ",\"kdf\":{\"alg\":\"pbkdf2-sha256\",\"iter\":";
  appendUInt(out, EscapeConfig::KDF_ITERATIONS);
  out += "},\"caps\":[\"plan\",\"cfg\"],\"limits\":{\"body\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_BODY_BYTES);
  out += ",\"skeleton\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_PLAN_SKELETON_LEN);
  out += ",\"plan\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_PLAN_LEN);
  out += ",\"name\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_NAME_LEN);
  out += ",\"room\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_ROOM_LEN);
  out += ",\"riddle\":";
  appendUInt(out, (uint32_t)EscapeConfig::MAX_RIDDLE_ID_LEN);
  out += "}}";
  return out;
}

std::string buildStatusDoc(const ProtocolAdapter &host, const DeviceInfo &info) {
  return Escape::guardAlloc([&]() -> std::string {
    std::string out;
    out.reserve(512 + (size_t)host.componentCount() * 1200);
    out += '{';
    appendCommonDeviceFields(out, info);
    out += ",\"ip\":\"";
    appendEscaped(out, info.ip);
    out += "\",\"port\":";
    appendUInt(out, info.port);
    out += ",\"boot\":";
    appendUInt(out, info.boot);
    out += ",\"seq\":";
    appendUInt(out, info.seq);
    out += ",\"up\":";
    appendUInt(out, info.nowMs);
    if (info.battery > 0) { // <= 0 means no battery / unknown and is not reported
      out += ",\"battery\":";
      appendUInt(out, (uint32_t)(info.battery > 100 ? 100 : info.battery));
    }
    out += ",\"token\":\"";
    out += Escape::tokenStateName(info.token);
    out += "\",\"components\":[";
    // One heap snapshot, reused for every component (about 4 KB, freed right after).
    std::unique_ptr<ComponentSnapshot> snap(new ComponentSnapshot());
    const uint8_t n = host.componentCount();
    for (uint8_t i = 0; i < n; i++) {
      *snap = ComponentSnapshot();
      host.snapshot(i, *snap);
      if (i) out += ',';
      writeComponent(out, i, *snap);
    }
    out += "]}";
    return out;
  }, std::string());
}

std::string buildPeersDoc(const Escape::PeerTable &peers, const DeviceInfo &self, uint32_t selfSkeletonSummaryHash) {
  return Escape::guardAlloc([&]() -> std::string {
    std::string out;
    out.reserve(160 + (peers.count() + 1) * 140);
    out += "{\"proto\":";
    appendUInt(out, EscapeVersion::PROTO);
    out += ",\"self\":{\"did\":\"" + self.did + "\",\"ip\":\"";
    appendEscaped(out, self.ip);
    out += "\",\"port\":";
    appendUInt(out, self.port);
    out += ",\"proto\":";
    appendUInt(out, EscapeVersion::PROTO);
    out += ",\"seq\":";
    appendUInt(out, self.seq);
    out += ",\"uih\":\"";
    out += EscapeVersion::UI_HASH;
    out += "\",\"skh\":\"" + Escape::hex8(selfSkeletonSummaryHash) + "\",\"age\":0},\"peers\":[";
    for (size_t i = 0; i < peers.count(); i++) {
      const Escape::PeerEntry &p = peers.at(i);
      char ip[16];
      Escape::u32ToIpv4Text(p.ip, ip);
      if (i) out += ',';
      out += "{\"did\":\"" + Escape::didToText(p.did) + "\",\"ip\":\"";
      out += ip;
      out += "\",\"port\":";
      appendUInt(out, p.port);
      out += ",\"proto\":";
      appendUInt(out, p.proto);
      out += ",\"seq\":";
      appendUInt(out, p.seq);
      out += ",\"uih\":\"" + Escape::hex8(p.uih) + "\",\"skh\":\"" + Escape::hex8(p.skh) + "\",\"age\":";
      appendUInt(out, self.nowMs - p.lastSeenMs);
      out += '}';
    }
    out += "]}";
    return out;
  }, std::string());
}

std::string buildSkeletonIndexDoc(const Escape::SkeletonStore &store) {
  return Escape::guardAlloc([&]() -> std::string {
    std::string out = "{\"proto\":";
    appendUInt(out, EscapeVersion::PROTO);
    out += ",\"rooms\":[";
    for (size_t i = 0; i < store.count(); i++) {
      const Escape::SkeletonInfo &s = store.at(i);
      if (i) out += ',';
      out += "{\"room\":\"";
      appendEscaped(out, s.room);
      out += "\",\"rev\":";
      appendUInt(out, s.rev);
      out += ",\"hash\":\"" + Escape::hex8(s.hash) + "\"}";
    }
    out += "]}";
    return out;
  }, std::string());
}

// ---- Handlers --------------------------------------------------------------------------------------

std::string errorBody(const char *code, const char *text, const std::string &extraMembers) {
  std::string out = "{\"ok\":false,\"code\":\"";
  out += code;
  out += "\",\"error\":\"";
  appendEscaped(out, text);
  out += '"';
  if (!extraMembers.empty()) {
    out += ',';
    out += extraMembers;
  }
  out += '}';
  return out;
}

HttpResult errorResult(int status, const char *code, const char *text, const std::string &extraMembers) {
  return HttpResult(status, errorBody(code, text, extraMembers));
}

namespace {

const size_t kMaxSmallBody = 2048;

HttpResult okResult() { return HttpResult(200, "{\"ok\":true}"); }

// Parses a small command body into a DOM object (bounded by the DOM limits).
bool parseCommand(const std::string &body, EscapeJson::Value &doc, HttpResult &error) {
  if (body.empty()) { error = errorResult(400, "bad_request", "missing body"); return false; }
  if (body.size() > kMaxSmallBody) { error = errorResult(413, "too_large", "body too large"); return false; }
  if (!EscapeJson::parse(body, doc) || doc.type != EscapeJson::Type::Object) {
    error = errorResult(400, "bad_request", "invalid json");
    return false;
  }
  return true;
}

// "id" selects the component; a missing id means component 0.
bool readComponentId(const EscapeJson::Value &doc, const ProtocolAdapter &host, uint8_t &id) {
  long long v = 0;
  const EscapeJson::Value *f = doc.find("id");
  if (f && !f->asInt(0, 255, v)) return false;
  if (v >= host.componentCount()) return false;
  id = (uint8_t)v;
  return true;
}

} // namespace

HttpResult handleAction(ProtocolAdapter &host, const std::string &body) {
  EscapeJson::Value doc;
  HttpResult err;
  if (!parseCommand(body, doc, err)) return err;
  uint8_t id = 0;
  if (!readComponentId(doc, host, id)) return errorResult(400, "bad_id", "invalid component id");
  const std::string action = doc.find("action") ? doc.find("action")->asString() : std::string();
  if (action.empty() || action.size() > EscapeConfig::MAX_ACTION_LEN) return errorResult(400, "bad_action", "invalid action");

  const bool ok = host.applyAction(id, action);
  if (ok) host.pushEvent(id, "Aktion \"" + action + "\" ausgefuehrt");
  host.markDirty();
  return ok ? okResult() : errorResult(422, "rejected", "action rejected");
}

HttpResult handlePlanAction(ProtocolAdapter &host, const std::string &body) {
  EscapeJson::Value doc;
  HttpResult err;
  if (!parseCommand(body, doc, err)) return err;
  uint8_t id = 0;
  if (!readComponentId(doc, host, id)) return errorResult(400, "bad_id", "invalid component id");
  const std::string text = doc.find("action") ? doc.find("action")->asString() : std::string();
  PlanAction action;
  if (text == planActionName(PlanAction::Reset)) action = PlanAction::Reset;
  else if (text == planActionName(PlanAction::Complete)) action = PlanAction::Complete;
  else return errorResult(400, "bad_action", "invalid plan action");

  bool supported = false;
  {
    std::unique_ptr<ComponentSnapshot> snap(new ComponentSnapshot());
    host.snapshot(id, *snap);
    supported = (snap->planActionMask & planActionBit(action)) != 0;
  }
  if (!supported) return errorResult(422, "unsupported", "plan action unsupported");
  const bool ok = host.applyPlanAction(id, action);
  if (ok) {
    host.pushEvent(id, action == PlanAction::Reset ? "Ablaufplan-Fortschritt zurueckgesetzt"
                                                   : "Ablaufplan-Komponente abgeschlossen");
  }
  host.markDirty();
  return ok ? okResult() : errorResult(422, "rejected", "plan action rejected");
}

HttpResult handleConfig(ProtocolAdapter &host, const std::string &body) {
  EscapeJson::Value doc;
  HttpResult err;
  if (!parseCommand(body, doc, err)) return err;
  uint8_t id = 0;
  if (!readComponentId(doc, host, id)) return errorResult(400, "bad_id", "invalid component id");

  // 1. Validate EVERYTHING before applying anything.
  const EscapeJson::Value *nameV = doc.find("name"), *roomV = doc.find("room");
  const EscapeJson::Value *riddleV = doc.find("riddleId"), *cfgV = doc.find("config");
  const bool identityGiven = nameV || roomV;
  std::string name, room, riddleId;
  if (identityGiven) {
    if (!nameV || !roomV || nameV->type != EscapeJson::Type::String || roomV->type != EscapeJson::Type::String) {
      return errorResult(400, "bad_request", "name and room must be given together");
    }
    name = nameV->stringValue;
    room = roomV->stringValue;
    if (name.empty() || room.empty() || name.size() > EscapeConfig::MAX_NAME_LEN || room.size() > EscapeConfig::MAX_ROOM_LEN) {
      return errorResult(400, "bad_request", "invalid name/room");
    }
  }
  if (riddleV) {
    if (riddleV->type != EscapeJson::Type::String || riddleV->stringValue.empty() ||
        riddleV->stringValue.size() > EscapeConfig::MAX_RIDDLE_ID_LEN) {
      return errorResult(400, "bad_request", "invalid riddleId");
    }
    riddleId = riddleV->stringValue;
  }
  std::vector<CustomConfigDef> defs;
  if (cfgV) {
    if (cfgV->type != EscapeJson::Type::Object) return errorResult(400, "bad_request", "config must be an object");
    host.customConfigDefs(id, defs);
    if (defs.empty() && !cfgV->objectValue.empty()) return errorResult(400, "bad_request", "component has no custom config");
    for (std::map<std::string, EscapeJson::Value>::const_iterator it = cfgV->objectValue.begin();
         it != cfgV->objectValue.end(); ++it) {
      const CustomConfigDef *def = findCustomConfigDef(defs.data(), defs.size(), it->first.c_str());
      if (!def || !validateCustomConfigValue(*def, it->second.asStringLoose())) {
        return errorResult(400, "bad_request", "invalid config value");
      }
    }
  }

  // 2. Apply.
  bool cfgApplied = false;
  if (cfgV) {
    for (std::map<std::string, EscapeJson::Value>::const_iterator it = cfgV->objectValue.begin();
         it != cfgV->objectValue.end(); ++it) {
      if (host.setCustomConfigValue(id, it->first, it->second.asStringLoose())) cfgApplied = true;
    }
  }
  if (identityGiven) host.setIdentity(id, name, room);
  if (riddleV) host.setRiddleId(id, riddleId);

  std::string message;
  if (cfgApplied) message += "Konfiguration geaendert";
  if (identityGiven) message += std::string(message.empty() ? "" : ", ") + "Name/Raum geaendert";
  if (riddleV) message += std::string(message.empty() ? "" : ", ") + "Raetsel-ID geaendert";
  if (!message.empty()) host.pushEvent(id, message);
  host.markDirty();
  return okResult();
}

HttpResult handlePlan(ProtocolAdapter &host, const std::string &body) {
  if (body.empty()) return errorResult(400, "bad_request", "missing body");
  if (body.size() > EscapeConfig::MAX_PLAN_LEN + 128) return errorResult(413, "too_large", "plan too large");
  EscapeJson::Slice sid, splan;
  const EscapeJson::Scan idScan = EscapeJson::findField(body.data(), body.size(), "id", sid);
  if (idScan == EscapeJson::Scan::Invalid) return errorResult(400, "bad_request", "invalid json");
  uint32_t id = 0;
  if (idScan == EscapeJson::Scan::Found && !EscapeJson::sliceToUInt(sid, 255, id)) return errorResult(400, "bad_id", "invalid component id");
  if (id >= host.componentCount()) return errorResult(400, "bad_id", "invalid component id");
  const EscapeJson::Scan planScan = EscapeJson::findField(body.data(), body.size(), "plan", splan);
  if (planScan == EscapeJson::Scan::Invalid) return errorResult(400, "bad_request", "invalid json");

  std::string planText;
  const bool cleared = planScan == EscapeJson::Scan::Missing || EscapeJson::sliceIsNull(splan);
  if (!cleared) {
    if (EscapeJson::sliceKind(splan) != 'o') return errorResult(400, "bad_request", "plan must be an object");
    if (splan.n > EscapeConfig::MAX_PLAN_LEN) return errorResult(413, "too_large", "plan too large");
    planText = splan.str();
  }
  host.setPlan((uint8_t)id, planText);
  host.pushEvent((uint8_t)id, cleared ? "Ablaufplan-Zuordnung entfernt" : "Ablaufplan aktualisiert");
  host.markDirty();
  return okResult();
}

HttpResult handlePlanSkeleton(ProtocolAdapter &host, Escape::SkeletonStore &store, const std::string &body) {
  if (body.empty()) return errorResult(400, "bad_request", "missing body");
  if (body.size() > EscapeConfig::MAX_PLAN_SKELETON_LEN + 512) return errorResult(413, "too_large", "skeleton too large");
  EscapeJson::Slice sroom, sbase, ssk;
  if (EscapeJson::findField(body.data(), body.size(), "room", sroom) != EscapeJson::Scan::Found ||
      EscapeJson::findField(body.data(), body.size(), "baseRev", sbase) != EscapeJson::Scan::Found ||
      EscapeJson::findField(body.data(), body.size(), "sk", ssk) != EscapeJson::Scan::Found) {
    return errorResult(400, "bad_request", "room, baseRev and sk are required");
  }
  std::string room;
  uint32_t baseRev = 0;
  if (!EscapeJson::sliceToString(sroom, room) || room.empty() || room.size() > EscapeConfig::MAX_ROOM_LEN ||
      !EscapeJson::sliceToUInt(sbase, 0xFFFFFFFFu, baseRev)) {
    return errorResult(400, "bad_request", "invalid room or baseRev");
  }
  if (ssk.n > EscapeConfig::MAX_PLAN_SKELETON_LEN) return errorResult(413, "too_large", "skeleton too large");
  bool hosted = false;
  const std::vector<std::string> rooms = hostedRooms(host);
  for (size_t i = 0; i < rooms.size(); i++) hosted = hosted || rooms[i] == room;
  if (!hosted) return errorResult(422, "room_not_hosted", "no local component in this room");

  uint32_t rev = 0, hash = 0;
  const Escape::SkeletonStore::Result r = store.put(room, baseRev, ssk.p, ssk.n, rev, hash);
  const std::string revMembers = "\"rev\":" + std::to_string(rev) + ",\"hash\":\"" + Escape::hex8(hash) + "\"";
  switch (r) {
    case Escape::SkeletonStore::Result::Stored:
      for (uint8_t i = 0; i < host.componentCount(); i++) {
        std::string n, rm;
        host.identity(i, n, rm);
        if (rm == room) host.pushEvent(i, "Raum-Ablaufplan aktualisiert");
      }
      host.markDirty();
      return HttpResult(200, "{\"ok\":true," + revMembers + "}");
    case Escape::SkeletonStore::Result::Unchanged:
      return HttpResult(200, "{\"ok\":true," + revMembers + "}");
    case Escape::SkeletonStore::Result::Conflict:
      return errorResult(409, "rev_conflict", "skeleton was changed by someone else", revMembers);
    case Escape::SkeletonStore::Result::TooLarge: return errorResult(413, "too_large", "skeleton too large");
    case Escape::SkeletonStore::Result::Invalid: return errorResult(400, "bad_request", "sk must be a JSON object");
    case Escape::SkeletonStore::Result::RoomLimit: return errorResult(422, "room_limit", "too many rooms stored");
    case Escape::SkeletonStore::Result::KeyCollision: return errorResult(422, "room_limit", "room key collision");
    default: return errorResult(500, "storage_full", "could not store skeleton");
  }
}

// ---- Timing -------------------------------------------------------------------------------------------

bool isHeartbeatDue(uint32_t nowMs, uint32_t lastBroadcastMs, uint32_t intervalMs) {
  return (nowMs - lastBroadcastMs) >= intervalMs;
}

bool isChangeBroadcastDue(uint32_t nowMs, uint32_t lastBroadcastMs, bool dirty) {
  return dirty && (nowMs - lastBroadcastMs) >= EscapeConfig::CHANGE_MIN_GAP_MS;
}

} // namespace EscapeProtocol
