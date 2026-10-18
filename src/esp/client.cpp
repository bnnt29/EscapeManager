// Implementation of EscapeComponent (see client.hpp): wires the host program's components
// to the portable device core.

#include "client.hpp"

#include "../manager/UiData.hpp"
#include "../net/Clock.hpp"
#include "../protocol/EscapeVersion.hpp"

namespace {
const uint8_t kInvalidId = 255;
} // namespace

EscapeComponent::EscapeComponent() : _host(*this), _componentCount(0), _begun(false), _dirtyBeforeBegin(false), _beginMs(0), _portWarned(false) {}

void EscapeComponent::begin() {
  if (_begun) return;
  _begun = true;
  _hw.beginStorage();
  _hw.startWifi(); // non-blocking; also makes the Wi-Fi RNG source true-random before any key is derived

  const std::string did = _hw.deviceId();
  for (uint8_t i = 0; i < _componentCount; i++) {
    const std::string uuid = did + "-" + std::to_string(i);
    EscapeProtocol::copyBounded(_components[i].uuid, sizeof(_components[i].uuid), uuid.c_str());
  }

  std::string token;
  Escape::TokenState tokenState;
  _hw.loadToken(token, tokenState);

  Escape::DeviceOptions options;
  options.did = did;
  options.bootCounter = _hw.nextBootCounter();
  options.uiData = EscapeUi::data;
  options.uiLength = EscapeUi::length;

  _device.reset(new Escape::Device(_host, _hw.crypto(), _hw.skeletonStorage(), _hw));
  const uint32_t beginStartMs = millis();
  const bool started = _device->begin(options, token, tokenState);
  _beginMs = millis() - beginStartMs; // dominated by the one-time key derivation (PBKDF2)
  (void)started; // sockets open once the network is up, see Device::begin()
  if (_dirtyBeforeBegin) _device->hostChanged();
  printBanner();
}

void EscapeComponent::printBanner() const {
  Serial.printf("EscapeManager %s (proto %u) did=%s token=%s components=%u (begin() blocked %lu ms)\n", EscapeVersion::FW,
                (unsigned)EscapeVersion::PROTO, _device ? _device->did().c_str() : "-",
                Escape::tokenStateName(_device ? _device->transport().tokenState() : Escape::TokenState::Invalid),
                (unsigned)_componentCount, (unsigned long)_beginMs);
  if (_device && _device->transport().tokenState() == Escape::TokenState::Default) {
    Serial.println("EscapeManager: default token active (fine for a closed escape-room network; set your own with ESCAPE_AUTH_TOKEN)");
  } else if (_device && _device->transport().tokenState() == Escape::TokenState::Invalid) {
    Serial.println("EscapeManager: stored token unusable - read-only until a valid token is provisioned");
  }
}

void EscapeComponent::loop() {
  if (!_begun) return;
  const uint32_t now = Escape::nowMillis();
  _hw.service(now);
  if (!_device) return;
  _device->loop(now);
  if (_device->httpPortFailed() != _portWarned) { // report once per state change, not every retry
    _portWarned = _device->httpPortFailed();
    Serial.println(_portWarned ? "EscapeManager: cannot open the HTTP port (is another server using port 80?); retrying every 5 s"
                               : "EscapeManager: HTTP server started");
  }
}

// Host-facing hint: cheap at any call rate (see Device::hostChanged()).
void EscapeComponent::markDirty() {
  if (_device) _device->hostChanged();
  else _dirtyBeforeBegin = true;
}

void EscapeComponent::pushEvent(uint8_t id, const String &msg) {
  if (id >= _componentCount) return;
  LocalComponent &c = _components[id];
  c.eventSeq++;
  EscapeProtocol::copyBounded(c.eventMsg, sizeof(c.eventMsg), msg.c_str());
  markDirty();
}

uint8_t EscapeComponent::addComponent(const String &defaultName, const String &defaultRoom, const String &defaultRiddleId) {
  if (_componentCount >= EscapeConfig::MAX_LOCAL_COMPONENTS) return kInvalidId; // callbacks for this id are ignored
  const uint8_t id = _componentCount++;
  loadIdentity(id, defaultName, defaultRoom);
  resolveRiddleId(id, defaultRiddleId);
  return id;
}

void EscapeComponent::onBattery(BatteryProvider cb) { _batteryCb = cb; }
void EscapeComponent::onErrors(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].errorsCb = cb; }
void EscapeComponent::onActions(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].actionsCb = cb; }
void EscapeComponent::onFeed(uint8_t id, FeedProvider cb) { if (id < _componentCount) _components[id].feedCb = cb; }
void EscapeComponent::onTip(uint8_t id, TipProvider cb) { if (id < _componentCount) _components[id].tipCb = cb; }
void EscapeComponent::onPuzzle(uint8_t id, PuzzleProvider cb) { if (id < _componentCount) _components[id].puzzleCb = cb; }
void EscapeComponent::onAction(uint8_t id, ActionHandler cb) { if (id < _componentCount) _components[id].actionHandler = cb; }
void EscapeComponent::onPlanAction(uint8_t id, PlanActionHandler cb) { if (id < _componentCount) _components[id].planActionHandler = cb; }
void EscapeComponent::onCustomConfig(uint8_t id, CustomConfigProvider cb) { if (id < _componentCount) _components[id].customConfigCb = cb; }
void EscapeComponent::onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb) { if (id < _componentCount) _components[id].customConfigSetCb = cb; }

// ---- Identity (NVS keys name<i>/room<i>/riddle<i>/plan<i>) --------------------------------------

void EscapeComponent::loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom) {
  LocalComponent &c = _components[id];
  const std::string n = _hw.loadString(("name" + std::to_string(id)).c_str(), std::string(defaultName.c_str()));
  const std::string r = _hw.loadString(("room" + std::to_string(id)).c_str(), std::string(defaultRoom.c_str()));
  const std::string p = _hw.loadString(("plan" + std::to_string(id)).c_str(), "");
  EscapeProtocol::copyBounded(c.name, sizeof(c.name), n.c_str());
  EscapeProtocol::copyBounded(c.room, sizeof(c.room), r.c_str());
  EscapeProtocol::copyBounded(c.plan, sizeof(c.plan), p.c_str());
}

void EscapeComponent::resolveRiddleId(uint8_t id, const String &defaultRiddleId) {
  const std::string key = "riddle" + std::to_string(id);
  std::string value = _hw.loadString(key.c_str(), "");
  if (value.empty()) {
    // First start: take the sketch's puzzle-type id (all devices of one puzzle type share
    // it), otherwise a random one that an operator can overwrite later. Deliberately NOT
    // derived from the MAC so a replacement board can be given the original's id.
    if (defaultRiddleId.length()) {
      value = std::string(defaultRiddleId.c_str());
    } else {
      uint8_t r[8];
      esp_fill_random(r, sizeof(r));
      char text[EscapeConfig::MAX_RIDDLE_ID_LEN + 1];
      snprintf(text, sizeof(text), "riddle-%02x%02x%02x%02x%02x%02x%02x%02x", r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7]);
      value = text;
    }
    _hw.saveString(key.c_str(), value);
  }
  EscapeProtocol::copyBounded(_components[id].riddleId, sizeof(_components[id].riddleId), value.c_str());
}

// ---- Snapshot ------------------------------------------------------------------------------------

void EscapeComponent::fillSnapshot(uint8_t id, EscapeProtocol::ComponentSnapshot &out) const {
  const LocalComponent &c = _components[id];
  EscapeProtocol::copyBounded(out.uuid, sizeof(out.uuid), c.uuid);
  EscapeProtocol::copyBounded(out.riddleId, sizeof(out.riddleId), c.riddleId);
  EscapeProtocol::copyBounded(out.name, sizeof(out.name), c.name);
  EscapeProtocol::copyBounded(out.room, sizeof(out.room), c.room);
  EscapeProtocol::copyBounded(out.plan, sizeof(out.plan), c.plan);
  out.eventSeq = c.eventSeq;
  EscapeProtocol::copyBounded(out.eventMsg, sizeof(out.eventMsg), c.eventMsg);

  out.errorCount = 0;
  if (c.errorsCb) {
    String buf[EscapeConfig::MAX_ERRORS];
    const size_t n = c.errorsCb(buf, EscapeConfig::MAX_ERRORS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ERRORS; i++) {
      EscapeProtocol::copyBounded(out.errors[i], sizeof(out.errors[0]), buf[i].c_str());
      out.errorCount++;
    }
  }
  out.actionCount = 0;
  if (c.actionsCb) {
    String buf[EscapeConfig::MAX_ACTIONS];
    const size_t n = c.actionsCb(buf, EscapeConfig::MAX_ACTIONS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ACTIONS; i++) {
      EscapeProtocol::copyBounded(out.actions[i], sizeof(out.actions[0]), buf[i].c_str());
      out.actionCount++;
    }
  }
  out.planActionMask = c.planActionHandler
      ? (EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Reset) | EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Complete))
      : 0;
  if (c.feedCb) {
    const String feed = c.feedCb();
    EscapeProtocol::copyBounded(out.feed, sizeof(out.feed), feed.c_str());
  }
  if (c.tipCb) {
    const String tip = c.tipCb();
    EscapeProtocol::copyBounded(out.tip, sizeof(out.tip), tip.c_str());
  }
  out.puzzleTotalSteps = 0;
  if (c.puzzleCb) {
    uint16_t step = 0, total = 0;
    String state;
    bool isHtml = false;
    c.puzzleCb(step, total, state, isHtml);
    out.puzzleStep = step;
    out.puzzleTotalSteps = total;
    EscapeProtocol::copyBounded(out.puzzleState, sizeof(out.puzzleState), state.c_str());
    out.puzzleIsHtml = isHtml;
  }
  out.customConfigCount = 0;
  if (c.customConfigCb) {
    const size_t n = c.customConfigCb(out.customConfig, EscapeConfig::MAX_CUSTOM_CONFIGS); // straight into the snapshot
    out.customConfigCount = (uint8_t)(n < EscapeConfig::MAX_CUSTOM_CONFIGS ? n : EscapeConfig::MAX_CUSTOM_CONFIGS);
  }
}

// ---- ProtocolAdapter -------------------------------------------------------------------------------

void EscapeComponent::Host::identity(uint8_t i, std::string &name, std::string &room) const {
  if (i >= owner_._componentCount) return;
  name = owner_._components[i].name;
  room = owner_._components[i].room;
}

void EscapeComponent::Host::snapshot(uint8_t i, EscapeProtocol::ComponentSnapshot &out) const {
  if (i < owner_._componentCount) owner_.fillSnapshot(i, out);
}

void EscapeComponent::Host::customConfigDefs(uint8_t i, std::vector<EscapeProtocol::CustomConfigDef> &out) const {
  out.clear();
  if (i >= owner_._componentCount || !owner_._components[i].customConfigCb) return;
  out.resize(EscapeConfig::MAX_CUSTOM_CONFIGS);
  const size_t n = owner_._components[i].customConfigCb(out.data(), EscapeConfig::MAX_CUSTOM_CONFIGS);
  out.resize(n < EscapeConfig::MAX_CUSTOM_CONFIGS ? n : EscapeConfig::MAX_CUSTOM_CONFIGS);
}

bool EscapeComponent::Host::applyAction(uint8_t i, const std::string &action) {
  if (i >= owner_._componentCount || !owner_._components[i].actionHandler) return false;
  return owner_._components[i].actionHandler(String(action.c_str()));
}

bool EscapeComponent::Host::applyPlanAction(uint8_t i, EscapeProtocol::PlanAction action) {
  if (i >= owner_._componentCount || !owner_._components[i].planActionHandler) return false;
  return owner_._components[i].planActionHandler(action);
}

void EscapeComponent::Host::setIdentity(uint8_t i, const std::string &name, const std::string &room) {
  if (i >= owner_._componentCount) return;
  LocalComponent &c = owner_._components[i];
  owner_._hw.saveString(("name" + std::to_string(i)).c_str(), name);
  owner_._hw.saveString(("room" + std::to_string(i)).c_str(), room);
  EscapeProtocol::copyBounded(c.name, sizeof(c.name), name.c_str());
  EscapeProtocol::copyBounded(c.room, sizeof(c.room), room.c_str());
}

void EscapeComponent::Host::setRiddleId(uint8_t i, const std::string &riddleId) {
  if (i >= owner_._componentCount) return;
  owner_._hw.saveString(("riddle" + std::to_string(i)).c_str(), riddleId);
  EscapeProtocol::copyBounded(owner_._components[i].riddleId, sizeof(owner_._components[i].riddleId), riddleId.c_str());
}

bool EscapeComponent::Host::setCustomConfigValue(uint8_t i, const std::string &key, const std::string &value) {
  if (i >= owner_._componentCount || !owner_._components[i].customConfigSetCb) return false;
  return owner_._components[i].customConfigSetCb(String(key.c_str()), String(value.c_str()));
}

void EscapeComponent::Host::setPlan(uint8_t i, const std::string &planJson) {
  if (i >= owner_._componentCount) return;
  LocalComponent &c = owner_._components[i];
  EscapeProtocol::copyBounded(c.plan, sizeof(c.plan), planJson.c_str());
  owner_._hw.saveString(("plan" + std::to_string(i)).c_str(), std::string(c.plan));
}

void EscapeComponent::Host::pushEvent(uint8_t i, const std::string &message) {
  owner_.pushEvent(i, String(message.c_str()));
}
