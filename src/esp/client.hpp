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
#include "SketchConfig.hpp"

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

  // Tell the library that something a manager displays MAY have changed (puzzle step, new
  // error, ...). Cheap and safe at any rate, also on every loop() iteration: it only sets a flag.
  // At most every 500 ms the library compares the state with the last announced one and, only
  // if it differs, bumps the change counter and announces so managers refresh quickly.
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

  // ---- Secrets without build flags (Arduino IDE) -----------------------------------------------------------------
  // Call these BEFORE begin() (they return false and print the reason if the value is unusable or begin() was
  // already called). The same values can be given as `#define ESCAPE_WIFI_SSID "..."`, ESCAPE_WIFI_PASSWORD,
  // ESCAPE_AUTH_TOKEN, ESCAPE_EDIT_TOKEN, ESCAPE_SETUP_AP_PASSWORD before `#include <EscapeManager.h>` (usually from
  // an arduino_secrets.h). Whatever is stored on the device (setup form, network push, serial command) wins over
  // these; they win over build flags (-D..., secrets.ini); everything is optional. An unusable token is NOT replaced
  // by the public default: the device stays read-only for it (edit token: plan sending locked).
  bool setWifi(const char *ssid, const char *password = "") { return Escape::SketchConfig::get().setWifi(ssid, password); }
  bool setAuthToken(const char *token) { return Escape::SketchConfig::get().setAuthToken(token); }
  bool setEditToken(const char *token) { return Escape::SketchConfig::get().setEditToken(token); }
  // "" = open setup network (default), otherwise WPA2 with this password (8..63 characters).
  bool setSetupApPassword(const char *password) { return Escape::SketchConfig::get().setSetupApPassword(password); }
  // GPIO of the BOOT-style button that opens the setup network when held 1.5 s within 10 s after start (-1 = none).
  void setSetupButtonPin(int pin) { Escape::SketchConfig::get().setSetupButtonPin(pin); }
  // Let the Wi-Fi radio sleep between beacons (saves power, adds 50-200 ms to the first request after a quiet moment).
  void allowWifiSleep(bool allow = true) { Escape::SketchConfig::get().setAllowWifiSleep(allow); }

  // The library owns the Wi-Fi station: it connects with the credentials stored on the device (setup
  // network form, network push, serial command) or from the build (secrets.ini) and opens a setup network
  // when it cannot connect. A host program that manages Wi-Fi ITSELF opts out - build with
  // -DESCAPE_HOST_MANAGED_WIFI=1 or call this BEFORE begin(): the library then never touches the radio.
  void useHostManagedWifi(bool hostManaged = true) { _hw.setHostManagedWifi(hostManaged); Escape::SketchConfig::get().setHostManagedWifi(hostManaged); }
  // True while the setup network is up.
  bool setupNetworkActive() const { return _hw.setupNetworkActive(); }

private:
  class Host : public EscapeProtocol::ProtocolAdapter {
  public:
    explicit Host(EscapeComponent &owner) : owner_(owner) {}
    int8_t battery() const override { return owner_._batteryCb ? owner_._batteryCb() : -1; }
    // After a command handled by the protocol layer: announce immediately (not a host hint).
    void markDirty() override { if (owner_._device) owner_._device->markDirty(); }
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
  uint32_t _beginMs;
  bool _portWarned;
};
