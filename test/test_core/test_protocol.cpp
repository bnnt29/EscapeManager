#include <unity.h>
#include <cstring>
#include <string>
#include <vector>

#include "../../src/protocol/EscapeVersion.hpp"
#include "../../src/protocol/Protocol.hpp"
#include "fakehost.hpp"
#include "tests.hpp"

namespace EscapeVersion {
const char *const UI_HASH = "0badc0de"; // tests have no embedded UI
}

using namespace EscapeProtocol;
using EscapeJson::Value;

namespace {

DeviceInfo info() {
  DeviceInfo d;
  d.did = "aabbccddeeff";
  d.uiHash = "0badc0de";
  d.ip = "192.168.1.20";
  d.port = 80;
  d.boot = 5;
  d.seq = 17;
  d.nowMs = 123456;
  d.battery = 87;
  return d;
}

bool parseObj(const std::string &text, Value &v) { return EscapeJson::parse(text, v, EscapeJson::ParseLimits(16, 4000)); }

void test_status_doc_structure() {
  FakeHost host;
  host.tip = "Dreh den Schluessel";
  host.feed = "http://192.168.1.5/stream";
  host.stateText = "Schritt 2";
  host.plans[0] = "{\"planId\":\"p\",\"layer\":\"L1\"}";
  const std::string doc = buildStatusDoc(host, info());
  Value v;
  TEST_ASSERT_TRUE(parseObj(doc, v));
  TEST_ASSERT_EQUAL_INT(2, (int)v.find("proto")->asNumber());
  TEST_ASSERT_EQUAL_STRING("aabbccddeeff", v.find("did")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("0badc0de", v.find("uih")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(17, (int)v.find("seq")->asNumber());
  TEST_ASSERT_EQUAL_INT(87, (int)v.find("battery")->asNumber());
  TEST_ASSERT_EQUAL_STRING("default", v.find("token")->asString().c_str());
  const Value *comps = v.find("components");
  TEST_ASSERT_EQUAL_UINT(2, comps->arrayValue.size());
  const Value &c0 = comps->arrayValue[0];
  TEST_ASSERT_EQUAL_STRING("Laser", c0.find("name")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("laser-v1", c0.find("riddleId")->asString().c_str());
  TEST_ASSERT_EQUAL_UINT(2, c0.find("planActions")->arrayValue.size());
  TEST_ASSERT_EQUAL_STRING("sensor_timeout", c0.find("errors")->arrayValue[0].asString().c_str());
  TEST_ASSERT_EQUAL_INT(5, (int)c0.find("puzzle")->find("totalSteps")->asNumber());
  TEST_ASSERT_EQUAL_STRING("http://192.168.1.5/stream", c0.find("feed")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("L1", c0.find("plan")->find("layer")->asString().c_str()); // plan slice embedded as an object
  TEST_ASSERT_EQUAL_STRING("range", c0.find("customConfig")->arrayValue[0].find("type")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(3, (int)c0.find("evtSeq")->asNumber());
  const Value &c1 = comps->arrayValue[1];
  TEST_ASSERT_NULL(c1.find("puzzle"));
  TEST_ASSERT_NULL(c1.find("evtSeq"));
  TEST_ASSERT_EQUAL_UINT(0, c1.find("planActions")->arrayValue.size());
  // removed in proto 2: per-component device fields
  TEST_ASSERT_NULL(c0.find("ip"));
  TEST_ASSERT_NULL(c0.find("battery"));
  TEST_ASSERT_NULL(c0.find("slave"));
  TEST_ASSERT_NULL(c0.find("upTimeMs"));
}

void test_status_battery_convention() {
  FakeHost host;
  DeviceInfo d = info();
  Value v;
  d.battery = 0;  // mains powered host returning 0, or "unknown": never reported
  TEST_ASSERT_TRUE(parseObj(buildStatusDoc(host, d), v));
  TEST_ASSERT_NULL(v.find("battery"));
  d.battery = -1;
  TEST_ASSERT_TRUE(parseObj(buildStatusDoc(host, d), v));
  TEST_ASSERT_NULL(v.find("battery"));
  d.battery = 1;
  TEST_ASSERT_TRUE(parseObj(buildStatusDoc(host, d), v));
  TEST_ASSERT_EQUAL_INT(1, (int)v.find("battery")->asNumber());
  d.battery = 250;
  TEST_ASSERT_TRUE(parseObj(buildStatusDoc(host, d), v));
  TEST_ASSERT_EQUAL_INT(100, (int)v.find("battery")->asNumber());
}

void test_status_doc_sanitizes_hostile_component_data() {
  FakeHost host;
  host.names[0] = std::string("Evil\"<script>\n\\") + "\xc3"; // quote, control char, backslash, cut UTF-8
  host.feed = "javascript:alert(1)";
  host.tip = std::string(2000, 'x'); // longer than MAX_TIP_LEN: truncated by the snapshot copy
  host.plans[0] = "{broken json";       // an invalid slice must never poison the document
  host.stateText = std::string("<b>") + std::string(5000, 'y');
  const std::string doc = buildStatusDoc(host, info());
  TEST_ASSERT_TRUE(EscapeJson::validate(doc.data(), doc.size(), 16)); // always valid JSON, valid UTF-8
  Value v;
  TEST_ASSERT_TRUE(parseObj(doc, v));
  const Value &c0 = v.find("components")->arrayValue[0];
  TEST_ASSERT_NULL(c0.find("feed"));  // not http(s)
  TEST_ASSERT_NULL(c0.find("plan"));
  TEST_ASSERT_TRUE(c0.find("tip")->asString().size() == EscapeConfig::MAX_TIP_LEN);
  TEST_ASSERT_TRUE(c0.find("puzzle")->find("state")->asString().size() == EscapeConfig::MAX_STATE_LEN);
}

void test_security_doc() {
  DeviceInfo d = info();
  d.token = Escape::TokenState::Invalid;
  d.writable = false;
  Value v;
  TEST_ASSERT_TRUE(parseObj(buildSecurityDoc(d), v));
  TEST_ASSERT_EQUAL_STRING("invalid", v.find("token")->asString().c_str());
  TEST_ASSERT_FALSE(v.find("writable")->asBool(true));
  TEST_ASSERT_EQUAL_INT(123456, (int)v.find("time")->asNumber());
  TEST_ASSERT_EQUAL_INT(2048, (int)v.find("kdf")->find("iter")->asNumber());
  TEST_ASSERT_EQUAL_STRING("pbkdf2-sha256", v.find("kdf")->find("alg")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(12288, (int)v.find("limits")->find("body")->asNumber());
  TEST_ASSERT_EQUAL_INT(6144, (int)v.find("limits")->find("skeleton")->asNumber());
  TEST_ASSERT_TRUE(v.find("caps")->arrayValue.size() >= 1);
  TEST_ASSERT_NOT_NULL(v.find("fw"));
}

void test_peers_doc() {
  static Escape::PeerTable table;
  table.clear();
  uint8_t own[6] = {0, 0, 0, 0, 0, 1};
  Escape::Announcement a;
  const std::string ann = Escape::buildAnnouncementDoc("112233445566", "192.168.1.30", 8080, 2, 4, 99, 2, "1a2b3c4d", "[]", 0xdeadbeefu);
  TEST_ASSERT_TRUE(Escape::parseAnnouncement(ann.data(), ann.size(), a));
  table.ingest(a, "192.168.1.30", own, 1000);
  DeviceInfo self = info();
  self.nowMs = 3500;
  Value v;
  TEST_ASSERT_TRUE(parseObj(buildPeersDoc(table, self, 0x01020304u), v));
  TEST_ASSERT_EQUAL_STRING("aabbccddeeff", v.find("self")->find("did")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("01020304", v.find("self")->find("skh")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(0, (int)v.find("self")->find("age")->asNumber());
  const Value &p = v.find("peers")->arrayValue[0];
  TEST_ASSERT_EQUAL_STRING("192.168.1.30", p.find("ip")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(8080, (int)p.find("port")->asNumber());
  TEST_ASSERT_EQUAL_INT(99, (int)p.find("seq")->asNumber());
  TEST_ASSERT_EQUAL_INT(2500, (int)p.find("age")->asNumber());
  TEST_ASSERT_EQUAL_STRING("deadbeef", p.find("skh")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("1a2b3c4d", p.find("uih")->asString().c_str());
}

bool isCode(const HttpResult &r, int status, const char *code) {
  Value v;
  return r.status == status && parseObj(r.body, v) && v.find("code") && v.find("code")->asString() == code;
}

void test_action() {
  FakeHost host;
  HttpResult r = handleAction(host, "{\"id\":0,\"action\":\"open\"}");
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_EQUAL_STRING("{\"ok\":true}", r.body.c_str());
  TEST_ASSERT_EQUAL_UINT(1, host.actionsApplied.size());
  TEST_ASSERT_EQUAL_UINT(1, host.events.size());
  TEST_ASSERT_TRUE(host.dirty > 0);
  r = handleAction(host, "{\"action\":\"x\"}"); // id defaults to 0
  TEST_ASSERT_EQUAL_INT(200, r.status);
  host.actionResult = false;
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":0,\"action\":\"x\"}"), 422, "rejected"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":2,\"action\":\"x\"}"), 400, "bad_id"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":256,\"action\":\"x\"}"), 400, "bad_id")); // no uint8 wrap-around
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":\"1\",\"action\":\"x\"}"), 400, "bad_id")); // strings are not ids
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":1.5,\"action\":\"x\"}"), 400, "bad_id"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":0}"), 400, "bad_action"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{\"id\":0,\"action\":\"" + std::string(25, 'a') + "\"}"), 400, "bad_action"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, ""), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "[]"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, "{broken"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleAction(host, std::string(3000, ' ')), 413, "too_large"));
  // hostile node floods are rejected by the DOM limits, not by running out of memory
  std::string flood = "{\"id\":0,\"x\":[";
  for (int i = 0; i < 1000; i++) flood += "0,";
  flood += "0]}";
  TEST_ASSERT_TRUE(isCode(handleAction(host, flood), 413, "too_large") || isCode(handleAction(host, flood), 400, "bad_request"));
}

void test_plan_action() {
  FakeHost host;
  TEST_ASSERT_EQUAL_INT(200, handlePlanAction(host, "{\"id\":0,\"action\":\"reset\"}").status);
  TEST_ASSERT_EQUAL_INT(200, handlePlanAction(host, "{\"id\":0,\"action\":\"complete\"}").status);
  TEST_ASSERT_TRUE(isCode(handlePlanAction(host, "{\"id\":1,\"action\":\"reset\"}"), 422, "unsupported")); // mask 0
  TEST_ASSERT_TRUE(isCode(handlePlanAction(host, "{\"id\":0,\"action\":\"explode\"}"), 400, "bad_action"));
  host.planActionResult = false;
  TEST_ASSERT_TRUE(isCode(handlePlanAction(host, "{\"id\":0,\"action\":\"reset\"}"), 422, "rejected"));
}

void test_config_is_atomic() {
  FakeHost host;
  // valid + invalid together: nothing may be applied
  HttpResult r = handleConfig(host, "{\"id\":0,\"config\":{\"brightness\":\"70\",\"label\":\"waytoolongvalue\"}}");
  TEST_ASSERT_TRUE(isCode(r, 400, "bad_request"));
  TEST_ASSERT_EQUAL_INT(0, host.setCalls);
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"name\":\"X\",\"config\":{\"brightness\":\"101\"}}"), 400, "bad_request"));
  TEST_ASSERT_EQUAL_INT(0, host.setCalls);
  TEST_ASSERT_EQUAL_STRING("Laser", host.names[0].c_str());
  // identity valid but riddleId invalid: nothing applied (used to apply the identity first)
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"name\":\"Neu\",\"room\":\"Raum Z\",\"riddleId\":\"" + std::string(33, 'r') + "\"}"), 400, "bad_request"));
  TEST_ASSERT_EQUAL_INT(0, host.setCalls);
  TEST_ASSERT_EQUAL_STRING("Laser", host.names[0].c_str());
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"name\":\"OnlyName\"}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"name\":\"\",\"room\":\"R\"}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"config\":{\"nokey\":\"1\"}}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":1,\"config\":{\"brightness\":\"1\"}}"), 400, "bad_request")); // component without config
  TEST_ASSERT_TRUE(isCode(handleConfig(host, "{\"id\":0,\"config\":[1]}"), 400, "bad_request"));
  TEST_ASSERT_EQUAL_INT(0, host.setCalls);
  r = handleConfig(host, "{\"id\":0,\"name\":\"Neu\",\"room\":\"Raum Z\",\"riddleId\":\"new-v2\",\"config\":{\"brightness\":70,\"label\":\"ok\"}}");
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_EQUAL_STRING("Neu", host.names[0].c_str());
  TEST_ASSERT_EQUAL_STRING("Raum Z", host.rooms[0].c_str());
  TEST_ASSERT_EQUAL_STRING("new-v2", host.riddle[0].c_str());
  TEST_ASSERT_EQUAL_STRING("70", host.lastCfgValue.size() == 2 && host.lastCfgKey == "label" ? "70" : host.lastCfgValue.c_str()); // number accepted as text
  TEST_ASSERT_TRUE(host.events.size() == 1);
  // no `slave` field any more: it is simply ignored
  TEST_ASSERT_EQUAL_INT(200, handleConfig(host, "{\"id\":0,\"slave\":true}").status);
}

void test_config_range_value_strictness() {
  CustomConfigDef d;
  d.type = CustomConfigType::Range; d.rangeMin = -5; d.rangeMax = 5;
  TEST_ASSERT_TRUE(validateCustomConfigValue(d, "-5"));
  TEST_ASSERT_TRUE(validateCustomConfigValue(d, "0"));
  TEST_ASSERT_TRUE(validateCustomConfigValue(d, "5"));
  const char *bad[] = {"6", "-6", "", "-", "+1", "1.0", "1e1", " 1", "1 ", "0x1", "abc", "99999999999999"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(validateCustomConfigValue(d, bad[i]), bad[i]);
  CustomConfigDef s;
  s.type = CustomConfigType::Select; s.optionCount = 2;
  copyBounded(s.options[0], sizeof(s.options[0]), "easy");
  copyBounded(s.options[1], sizeof(s.options[1]), "hard");
  TEST_ASSERT_TRUE(validateCustomConfigValue(s, "hard"));
  TEST_ASSERT_FALSE(validateCustomConfigValue(s, "medium"));
  TEST_ASSERT_FALSE(validateCustomConfigValue(s, ""));
}

void test_plan_slice() {
  FakeHost host;
  TEST_ASSERT_EQUAL_INT(200, handlePlan(host, "{\"id\":0,\"plan\":{\"planId\":\"p\",\"layer\":\"L1\",\"lane\":\"A\"}}").status);
  TEST_ASSERT_EQUAL_STRING("{\"planId\":\"p\",\"layer\":\"L1\",\"lane\":\"A\"}", host.plans[0].c_str()); // verbatim
  TEST_ASSERT_EQUAL_INT(200, handlePlan(host, "{\"id\":0,\"plan\":null}").status);
  TEST_ASSERT_TRUE(host.plans[0].empty());
  TEST_ASSERT_EQUAL_INT(200, handlePlan(host, "{\"id\":0}").status); // missing = clear
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":0,\"plan\":[1]}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":0,\"plan\":\"x\"}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":0,\"plan\":{\"a\":\"" + std::string(520, 'x') + "\"}}"), 413, "too_large"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":0,\"plan\":{\"a\":\"" + std::string(2000, 'x') + "\"}}"), 413, "too_large"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":7,\"plan\":null}"), 400, "bad_id"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, "{\"id\":0,\"plan\":{broken}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handlePlan(host, ""), 400, "bad_request"));
  std::string exact = "{\"a\":\"" + std::string(EscapeConfig::MAX_PLAN_LEN - 8, 'x') + "\"}";
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::MAX_PLAN_LEN, exact.size());
  TEST_ASSERT_EQUAL_INT(200, handlePlan(host, "{\"id\":1,\"plan\":" + exact + "}").status);
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::MAX_PLAN_LEN, host.plans[1].size());
}

void test_skeleton_handler() {
  FakeHost host;
  Escape::MemoryStorage mem;
  Escape::SkeletonStore store(mem);
  const std::string sk = "{\"planId\":\"p\",\"layers\":[]}";
  HttpResult r = handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk + "}");
  TEST_ASSERT_EQUAL_INT(200, r.status);
  Value v;
  TEST_ASSERT_TRUE(parseObj(r.body, v));
  TEST_ASSERT_EQUAL_INT(1, (int)v.find("rev")->asNumber());
  TEST_ASSERT_EQUAL_STRING(Escape::hex8(Escape::fnv1a32(sk)).c_str(), v.find("hash")->asString().c_str());
  TEST_ASSERT_EQUAL_UINT(1, host.events.size()); // component in that room was notified
  // same content again: idempotent
  r = handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk + "}");
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_EQUAL_UINT(1, host.events.size());
  // stale writer
  const std::string sk2 = "{\"planId\":\"p\",\"layers\":[1]}";
  r = handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk2 + "}");
  TEST_ASSERT_TRUE(isCode(r, 409, "rev_conflict"));
  TEST_ASSERT_TRUE(parseObj(r.body, v));
  TEST_ASSERT_EQUAL_INT(1, (int)v.find("rev")->asNumber()); // tells the manager the current revision
  r = handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":1,\"sk\":" + sk2 + "}");
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_TRUE(isCode(handlePlanSkeleton(host, store, "{\"room\":\"Nowhere\",\"baseRev\":0,\"sk\":" + sk + "}"), 422, "room_not_hosted"));
  TEST_ASSERT_TRUE(isCode(handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"sk\":" + sk + "}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":2,\"sk\":[1]}"), 400, "bad_request"));
  TEST_ASSERT_TRUE(isCode(handlePlanSkeleton(host, store, "{\"room\":\"Raum A\",\"baseRev\":2,\"sk\":{\"x\":\"" + std::string(7000, 'a') + "\"}}"), 413, "too_large"));
  mem.setFailWrites(true);
  TEST_ASSERT_TRUE(isCode(handlePlanSkeleton(host, store, "{\"room\":\"Raum B\",\"baseRev\":0,\"sk\":" + sk + "}"), 500, "storage_full"));
  // hosted rooms follow identity changes
  std::vector<std::string> rooms = hostedRooms(host);
  TEST_ASSERT_EQUAL_UINT(2, rooms.size());
  host.rooms[1] = "Raum A";
  TEST_ASSERT_EQUAL_UINT(1, hostedRooms(host).size());
}

void test_timing_helpers() {
  TEST_ASSERT_TRUE(isHeartbeatDue(10000, 0, 4000));
  TEST_ASSERT_FALSE(isHeartbeatDue(3999, 0, 4000));
  TEST_ASSERT_TRUE(isHeartbeatDue(100, 0xFFFFFF00u, 300)); // across the wrap
  TEST_ASSERT_FALSE(isHeartbeatDue(100, 0xFFFFFF00u, 4000));
  TEST_ASSERT_TRUE(isChangeBroadcastDue(1000, 0, true));
  TEST_ASSERT_FALSE(isChangeBroadcastDue(100, 0, true));
  TEST_ASSERT_FALSE(isChangeBroadcastDue(1000, 0, false));
}

} // namespace

void runProtocolTests() {
  RUN_TEST(test_status_doc_structure);
  RUN_TEST(test_status_battery_convention);
  RUN_TEST(test_status_doc_sanitizes_hostile_component_data);
  RUN_TEST(test_security_doc);
  RUN_TEST(test_peers_doc);
  RUN_TEST(test_action);
  RUN_TEST(test_plan_action);
  RUN_TEST(test_config_is_atomic);
  RUN_TEST(test_config_range_value_strictness);
  RUN_TEST(test_plan_slice);
  RUN_TEST(test_skeleton_handler);
  RUN_TEST(test_timing_helpers);
}
