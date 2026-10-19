#pragma once
// A configurable stand-in for the host program's components that records every call (shared by
// the protocol tests and the fuzz tests).
#include "../../src/protocol/Protocol.hpp"

#include <string>
#include <vector>

namespace EscapeProtocol {}
using namespace EscapeProtocol;

// A configurable stand-in for the host program's components that records every call.
class FakeHost : public ProtocolAdapter {
public:
  FakeHost() : count(2), battery_(-1), actionResult(true), planActionResult(true), dirty(0), setCalls(0) {
    names[0] = "Laser"; rooms[0] = "Raum A"; riddle[0] = "laser-v1";
    names[1] = "Kamera"; rooms[1] = "Raum B"; riddle[1] = "cam-v1";
    mask[0] = 3; mask[1] = 0;
    CustomConfigDef d;
    copyBounded(d.key, sizeof(d.key), "brightness");
    d.type = CustomConfigType::Range; d.rangeMin = 0; d.rangeMax = 100;
    copyBounded(d.value, sizeof(d.value), "50");
    cfg.push_back(d);
    CustomConfigDef t;
    copyBounded(t.key, sizeof(t.key), "label");
    t.type = CustomConfigType::Text; t.textMaxLen = 8;
    cfg.push_back(t);
  }
  uint8_t count;
  int8_t battery_;
  std::string names[4], rooms[4], riddle[4], plans[4];
  uint8_t mask[4] = {0, 0, 0, 0};
  std::string tip, feed, stateText;
  std::vector<CustomConfigDef> cfg;
  bool actionResult, planActionResult;
  int dirty, setCalls;
  std::vector<std::string> events, actionsApplied;
  std::string lastCfgKey, lastCfgValue;

  int8_t battery() const override { return battery_; }
  void markDirty() override { dirty++; }
  uint8_t componentCount() const override { return count; }
  void identity(uint8_t i, std::string &n, std::string &r) const override { n = names[i]; r = rooms[i]; }
  void snapshot(uint8_t i, ComponentSnapshot &o) const override {
    copyBounded(o.uuid, sizeof(o.uuid), ("aabbccddeeff-" + std::to_string(i)).c_str());
    copyBounded(o.riddleId, sizeof(o.riddleId), riddle[i].c_str());
    copyBounded(o.name, sizeof(o.name), names[i].c_str());
    copyBounded(o.room, sizeof(o.room), rooms[i].c_str());
    o.planActionMask = mask[i];
    copyBounded(o.tip, sizeof(o.tip), tip.c_str());
    copyBounded(o.feed, sizeof(o.feed), feed.c_str());
    copyBounded(o.plan, sizeof(o.plan), plans[i].c_str());
    if (i == 0) {
      copyBounded(o.errors[0], sizeof(o.errors[0]), "sensor_timeout");
      o.errorCount = 1;
      copyBounded(o.actions[0], sizeof(o.actions[0]), "open");
      o.actionCount = 1;
      o.puzzleStep = 2; o.puzzleTotalSteps = 5;
      copyBounded(o.puzzleState, sizeof(o.puzzleState), stateText.c_str());
      o.puzzleIsHtml = false;
      o.customConfigCount = (uint8_t)cfg.size();
      for (size_t k = 0; k < cfg.size(); k++) o.customConfig[k] = cfg[k];
      o.eventSeq = 3;
      copyBounded(o.eventMsg, sizeof(o.eventMsg), "Aktion \"open\" ausgefuehrt");
    }
  }
  void customConfigDefs(uint8_t i, std::vector<CustomConfigDef> &out) const override { out.clear(); if (i == 0) out = cfg; }
  bool applyAction(uint8_t, const std::string &a) override { actionsApplied.push_back(a); return actionResult; }
  bool applyPlanAction(uint8_t, PlanAction) override { return planActionResult; }
  void setIdentity(uint8_t i, const std::string &n, const std::string &r) override { names[i] = n; rooms[i] = r; setCalls++; }
  void setRiddleId(uint8_t i, const std::string &r) override { riddle[i] = r; setCalls++; }
  bool setCustomConfigValue(uint8_t, const std::string &k, const std::string &v) override { lastCfgKey = k; lastCfgValue = v; setCalls++; return true; }
  void setPlan(uint8_t i, const std::string &p) override { plans[i] = p; setCalls++; }
  void pushEvent(uint8_t, const std::string &m) override { events.push_back(m); }
};

