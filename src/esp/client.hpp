#pragma once

// EscapeComponent: the EscapeManager library for ONE ESP32 program, source-compatible
// with the previous API. It is a thin facade over
//   * HardwareEsp32 (Wi-Fi, NVS, serial provisioning, crypto backend),
//   * Escape::Device (src/net: HTTP server, discovery, shared mDNS record, sync), and
//   * the protocol layer (src/protocol), which the PC simulator uses unchanged.
//
// Resource behaviour (the library runs inside another program):
//   * begin() does not block: Wi-Fi connects in the background (only the one-time key
//     derivation, ~230 ms, runs inside begin()).
//   * loop() is cooperative and bounded; it never calls delay() or a blocking socket.
//   * No extra FreeRTOS task; all callbacks run in the context of the caller's loop().

#include "../net/Device.hpp"
#include "../protocol/EscapeConfig.hpp"
#include "../protocol/Protocol.hpp"
#include "HardwareEsp32.hpp"

#include <Arduino.h>
#include <functional>
#include <memory>

// Protocol data types remain reachable under their old, unqualified names so existing
// onCustomConfig()/onPlanAction() callbacks keep compiling.
using CustomConfigDef = EscapeProtocol::CustomConfigDef;
using CustomConfigType = EscapeProtocol::CustomConfigType;
using PlanAction = EscapeProtocol::PlanAction;

// Callbacks through which the host program connects its sensors and game logic.
using BatteryProvider = std::function<int8_t()>; // percent; <= 0 = no battery / unknown (mains powered)
using StringListProvider = std::function<size_t(String out[], size_t maxCount)>;
using FeedProvider = std::function<String()>;
using TipProvider = std::function<String()>;
using PuzzleProvider = std::function<void(uint16_t &step, uint16_t &totalSteps, String &state, bool &isHtml)>;
using ActionHandler = std::function<bool(const String &action)>; // true = executed
using PlanActionHandler = std::function<bool(PlanAction action)>;
using CustomConfigProvider = std::function<size_t(CustomConfigDef out[], size_t maxCount)>;
// Called per key after the value was validated against the component's own schema.
using CustomConfigSetHandler = std::function<bool(const String &key, const String &value)>;

// State and callbacks of one local puzzle component. Fixed buffers for everything that
// lives permanently (no String members: avoids heap fragmentation over long runtimes).
struct LocalComponent {
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0};
  char riddleId[EscapeConfig::MAX_RIDDLE_ID_LEN + 1] = {0};
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0};
  uint32_t eventSeq = 0;
  char eventMsg[EscapeConfig::MAX_EVENT_MSG_LEN + 1] = {0};
  StringListProvider errorsCb;
  StringListProvider actionsCb;
  FeedProvider feedCb;
  TipProvider tipCb;
  PuzzleProvider puzzleCb;
  ActionHandler actionHandler;
  PlanActionHandler planActionHandler;
  CustomConfigProvider customConfigCb;
  CustomConfigSetHandler customConfigSetCb;
};

class EscapeComponent {
public:
  EscapeComponent();

  // Starts storage, Wi-Fi (in the background), the HTTP server, discovery and the shared
  // mDNS name. Register all components (addComponent) before calling it.
  void begin();

  // Call from every loop() iteration. Cooperative and bounded (no blocking calls).
  void loop();

  // Call when observable state changed (puzzle step, new error, ...): triggers a prompt
  // announcement so managers refresh quickly. Cheap; safe to call every loop().
  void markDirty();

  // Records an activity message for a component (shown in the manager's log).
  void pushEvent(uint8_t id, const String &msg);

  // Registers a local component and returns its id (0-based, in call order). Names and
  // rooms saved by an operator in NVS override the defaults. defaultRiddleId identifies
  // the puzzle TYPE (see PROTOCOL.md); empty = generate once and persist. Beyond
  // MAX_LOCAL_COMPONENTS the call is ignored and 255 is returned; the on*() calls ignore
  // that id, so unchecked callers cannot corrupt another component.
  uint8_t addComponent(const String &defaultName, const String &defaultRoom, const String &defaultRiddleId = "");

  // Battery is per device (one pack per board).
  void onBattery(BatteryProvider cb);

  // The other callbacks are per component; `id` comes from addComponent().
  void onErrors(uint8_t id, StringListProvider cb);
  void onActions(uint8_t id, StringListProvider cb);
  void onFeed(uint8_t id, FeedProvider cb);
  void onTip(uint8_t id, TipProvider cb);
  void onPuzzle(uint8_t id, PuzzleProvider cb);
  void onAction(uint8_t id, ActionHandler cb);
  // Registering a handler announces reset+complete as planActions.
  void onPlanAction(uint8_t id, PlanActionHandler cb);
  void onCustomConfig(uint8_t id, CustomConfigProvider cb);
  void onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb);

  const char *name(uint8_t id) const { return id < _componentCount ? _components[id].name : ""; }
  const char *room(uint8_t id) const { return id < _componentCount ? _components[id].room : ""; }
  const char *uuid(uint8_t id) const { return id < _componentCount ? _components[id].uuid : ""; }
  uint8_t componentCount() const { return _componentCount; }

  // Serial provisioning (ESCAPE_* commands, see README) consumes ALL serial input while
  // enabled (the default). Disable it if the host program reads Serial itself.
  void setSerialProvisioning(bool enabled) { _hw.setSerialProvisioning(enabled); }

private:
  class Host : public EscapeProtocol::ProtocolAdapter {
  public:
    explicit Host(EscapeComponent &owner) : owner_(owner) {}
    int8_t battery() const override { return owner_._batteryCb ? owner_._batteryCb() : -1; }
    void markDirty() override { owner_.markDirty(); }
    uint8_t componentCount() const override { return owner_._componentCount; }
    void identity(uint8_t index, std::string &name, std::string &room) const override;
    void snapshot(uint8_t index, EscapeProtocol::ComponentSnapshot &out) const override;
    void customConfigDefs(uint8_t index, std::vector<EscapeProtocol::CustomConfigDef> &out) const override;
    bool applyAction(uint8_t index, const std::string &action) override;
    bool applyPlanAction(uint8_t index, EscapeProtocol::PlanAction action) override;
    void setIdentity(uint8_t index, const std::string &name, const std::string &room) override;
    void setRiddleId(uint8_t index, const std::string &riddleId) override;
    bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) override;
    void setPlan(uint8_t index, const std::string &planJson) override;
    void pushEvent(uint8_t index, const std::string &message) override;

  private:
    EscapeComponent &owner_;
  };

  void loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom);
  void resolveRiddleId(uint8_t id, const String &defaultRiddleId);
  void fillSnapshot(uint8_t id, EscapeProtocol::ComponentSnapshot &out) const;
  void printBanner() const;

  HardwareEsp32 _hw;
  Host _host;
  LocalComponent _components[EscapeConfig::MAX_LOCAL_COMPONENTS];
  uint8_t _componentCount;
  BatteryProvider _batteryCb;
  std::unique_ptr<Escape::Device> _device;
  bool _begun;
  bool _dirtyBeforeBegin;
};
