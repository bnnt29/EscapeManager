#pragma once

// Platform-independent EscapeManager protocol logic (proto 2, see PROTOCOL.md): data
// model, document builders (status, peers, security, skeleton index) and the handlers
// of the five mutating endpoints. No hardware, sockets or Arduino headers, so the
// ESP32 firmware, the simulators and the native tests all run exactly this code.
//
// A platform integrates by implementing ProtocolAdapter (read components, apply
// commands) and wiring documents/handlers to its HTTP server and UDP socket
// (see esp/client.cpp and sim/escape_component_sim.cpp).
//
// C++11 only (no structured bindings, no if-init), so it builds with the stock
// Arduino-ESP32 toolchain flags.

#include "EscapeConfig.hpp"
#include "Json.hpp"
#include "Peers.hpp"
#include "SecureTransport.hpp"
#include "Setup.hpp"
#include "SkeletonStore.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace EscapeProtocol {

// ---- Data model --------------------------------------------------------------------

enum class CustomConfigType : uint8_t { Range, Text, Select };

// Explicit plan commands, separate from free-form component actions. A component
// announces support through planActionMask.
enum class PlanAction : uint8_t { Reset = 0, Complete = 1 };

const char *planActionName(PlanAction action);
uint8_t planActionBit(PlanAction action);

// One configurable field of a component (type, limits, current value). Fixed buffers
// only: no heap allocation per field.
struct CustomConfigDef {
  char key[EscapeConfig::MAX_CONFIG_KEY_LEN + 1] = {0};
  CustomConfigType type = CustomConfigType::Text;
  int32_t rangeMin = 0;
  int32_t rangeMax = 0;
  uint16_t textMaxLen = 0;
  char options[EscapeConfig::MAX_CONFIG_OPTIONS][EscapeConfig::MAX_CONFIG_OPTION_LEN + 1] = {{0}};
  uint8_t optionCount = 0;
  char value[EscapeConfig::MAX_CONFIG_VALUE_LEN + 1] = {0};
};

// Snapshot of ONE local component as it appears in status.json. ~4 KB, so it is only
// ever allocated on the heap, briefly, while a document is built.
struct ComponentSnapshot {
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0};
  char riddleId[EscapeConfig::MAX_RIDDLE_ID_LEN + 1] = {0};
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  char errors[EscapeConfig::MAX_ERRORS][EscapeConfig::MAX_ERROR_LEN + 1] = {{0}};
  uint8_t errorCount = 0;
  char actions[EscapeConfig::MAX_ACTIONS][EscapeConfig::MAX_ACTION_LEN + 1] = {{0}};
  uint8_t actionCount = 0;
  uint8_t planActionMask = 0;
  char feed[EscapeConfig::MAX_FEED_LEN + 1] = {0};
  char tip[EscapeConfig::MAX_TIP_LEN + 1] = {0};
  uint16_t puzzleStep = 0;
  uint16_t puzzleTotalSteps = 0; // 0 == no puzzle information
  char puzzleState[EscapeConfig::MAX_STATE_LEN + 1] = {0};
  bool puzzleIsHtml = false;
  CustomConfigDef customConfig[EscapeConfig::MAX_CUSTOM_CONFIGS];
  uint8_t customConfigCount = 0;
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0}; // opaque plan slice (JSON object)
  uint32_t eventSeq = 0;
  char eventMsg[EscapeConfig::MAX_EVENT_MSG_LEN + 1] = {0};

  // Resets every field IN PLACE. (`*p = ComponentSnapshot()` would build a ~4 KB
  // temporary on the stack - a quarter of an ESP32 loop-task stack.)
  void clear() { memset(static_cast<void *>(this), 0, sizeof(*this)); }
};

// Device-wide values for the documents (the platform fills it per request).
struct DeviceInfo {
  std::string did;       // 12 hex chars
  std::string uiHash;    // hash of the UI this device serves (8 hex chars)
  std::string ip;
  uint16_t port;
  uint32_t boot;
  uint32_t seq;
  uint32_t nowMs;        // device clock
  int battery;           // percent; <= 0 means "no battery / unknown"
  Escape::TokenState token;
  Escape::EditState edit;
  bool writable;
  bool setupCap;         // POST /setup is available (a SetupSink is attached)
  const char *setupAp;   // "open" | "wpa2" | "none": the setup network this device can open
  DeviceInfo() : port(EscapeConfig::HTTP_PORT), boot(0), seq(0), nowMs(0), battery(-1),
                 token(Escape::TokenState::Default), edit(Escape::EditState::Unset), writable(true), setupCap(false),
                 setupAp("none") {}
};

// ---- Small helpers -------------------------------------------------------------------

// Copies src into dst, truncated and always NUL-terminated.
void copyBounded(char *dst, size_t dstSize, const char *src);

const char *customConfigTypeName(CustomConfigType t);
const CustomConfigDef *findCustomConfigDef(const CustomConfigDef *defs, size_t count, const char *key);
// Checks a value arriving from outside against the schema the component declared.
bool validateCustomConfigValue(const CustomConfigDef &def, const std::string &value);

// ---- Platform interface ----------------------------------------------------------------
// The single type a new integration implements.

class ProtocolAdapter {
public:
  virtual ~ProtocolAdapter() {}

  // Device
  virtual int8_t battery() const = 0; // <= 0: no battery / unknown
  // Observable state changed: bump `seq` and announce soon.
  virtual void markDirty() = 0;

  // Components (read)
  virtual uint8_t componentCount() const = 0;
  virtual void identity(uint8_t index, std::string &name, std::string &room) const = 0;
  virtual void snapshot(uint8_t index, ComponentSnapshot &out) const = 0;
  virtual void customConfigDefs(uint8_t index, std::vector<CustomConfigDef> &out) const = 0;

  // Commands (already authenticated and validated by the protocol layer)
  virtual bool applyAction(uint8_t index, const std::string &action) = 0;
  virtual bool applyPlanAction(uint8_t index, PlanAction action) = 0;
  virtual void setIdentity(uint8_t index, const std::string &name, const std::string &room) = 0;
  virtual void setRiddleId(uint8_t index, const std::string &riddleId) = 0;
  virtual bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) = 0;
  virtual void setPlan(uint8_t index, const std::string &planJson) = 0;
  virtual void pushEvent(uint8_t index, const std::string &message) = 0;
};

// Distinct rooms of the local components (for skeleton hosting and cleanup).
std::vector<std::string> hostedRooms(const ProtocolAdapter &host);

// ---- Documents ------------------------------------------------------------------------------

std::string buildSecurityDoc(const DeviceInfo &info);
std::string buildStatusDoc(const ProtocolAdapter &host, const DeviceInfo &info);
// Only the `components` array of the status document (also the basis of change detection).
std::string buildComponentsDoc(const ProtocolAdapter &host);
// `selfSkeletonSummaryHash` is SkeletonStore::summaryHash().
std::string buildPeersDoc(const Escape::PeerTable &peers, const DeviceInfo &self, uint32_t selfSkeletonSummaryHash);
std::string buildSkeletonIndexDoc(const Escape::SkeletonStore &store);

// ---- Mutating endpoints -------------------------------------------------------------------------

struct HttpResult {
  int status;
  std::string body;
  HttpResult() : status(200) {}
  HttpResult(int code, const std::string &text) : status(code), body(text) {}
};

// `{"ok":false,"code":"..","error":".."}` plus optional raw JSON members ("rev":3,...).
std::string errorBody(const char *code, const char *text, const std::string &extraMembers = std::string());
HttpResult errorResult(int status, const char *code, const char *text, const std::string &extraMembers = std::string());

// `body` is the decrypted POST plaintext.
HttpResult handleAction(ProtocolAdapter &host, const std::string &body);
HttpResult handlePlanAction(ProtocolAdapter &host, const std::string &body);
HttpResult handleConfig(ProtocolAdapter &host, const std::string &body);
HttpResult handlePlan(ProtocolAdapter &host, const std::string &body);
HttpResult handlePlanSkeleton(ProtocolAdapter &host, Escape::SkeletonStore &store, const std::string &body);
// POST /setup (plaintext {"ssid","pass","token","editToken"}). `tokensChanged` is set when a token
// was changed: the caller re-derives the keys AFTER sealing the response.
HttpResult handleSetup(Escape::SetupSink &sink, const std::string &body, bool &tokensChanged);

// ---- Timing helpers (overflow-safe millis() arithmetic) ------------------------------------------

bool isHeartbeatDue(uint32_t nowMs, uint32_t lastBroadcastMs, uint32_t intervalMs);
bool isChangeBroadcastDue(uint32_t nowMs, uint32_t lastBroadcastMs, bool dirty);

} // namespace EscapeProtocol
