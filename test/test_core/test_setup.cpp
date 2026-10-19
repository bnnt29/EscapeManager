#include <unity.h>
#include <cstring>
#include <string>

#include "../../src/protocol/Protocol.hpp"
#include "../../src/protocol/Setup.hpp"
#include "tests.hpp"

using namespace Escape;

namespace {

// Records what the portal / push would persist.
class FakeSink : public SetupSink {
public:
  SetupChange last;
  int applied;
  bool viaNetwork;
  SetupResult result;
  bool open;
  WifiPhase phase;
  std::string ssid;
  FakeSink() : applied(0), viaNetwork(false), result(SetupResult::Ok), open(true), phase(WifiPhase::Idle) {}
  SetupResult applySetup(const SetupChange &c, bool net) override {
    last = c;
    viaNetwork = net;
    applied++;
    return result;
  }
  void currentTokens(SetupTokens &out) override { out = SetupTokens(); }
  std::string setupNetworkName() const override { return "EscapeSetup-aabbccddeeff"; }
  bool setupNetworkOpen() const override { return open; }
  std::string configuredSsid() const override { return ssid; }
  WifiPhase wifiPhase() const override { return phase; }
  std::string wifiAddress() const override { return "192.168.1.77"; }
  const char *wifiFailReason() const override { return "Passwort falsch?"; }
};

HttpRequest request(Method m, const std::string &path, const std::string &body = std::string()) {
  HttpRequest r;
  r.method = m;
  r.path = path;
  r.body = body;
  return r;
}

void test_setup_network_name_is_unique_and_never_the_router_name() {
  TEST_ASSERT_EQUAL_STRING("EscapeSetup-e05a1bd04a04", setupNetworkName("e05a1bd04a04", "Heimnetz").c_str());
  TEST_ASSERT_EQUAL_STRING("EscapeSetup-0cb81501c400", setupNetworkName("0cb81501c400", "Heimnetz").c_str());
  TEST_ASSERT_TRUE(setupNetworkName("e05a1bd04a04", "") != setupNetworkName("0cb81501c400", "")); // two failing devices
  TEST_ASSERT_EQUAL_UINT(24, setupNetworkName("e05a1bd04a04", "").size());                          // within the 32-byte limit
  // A router that happens to carry exactly this name must not make the device join itself.
  TEST_ASSERT_EQUAL_STRING("EscapeSetup-e05a1bd04a04-S", setupNetworkName("e05a1bd04a04", "EscapeSetup-e05a1bd04a04").c_str());
  TEST_ASSERT_TRUE(isSetupNetworkName("EscapeSetup-0cb81501c400"));
  TEST_ASSERT_TRUE(isSetupNetworkName("EscapeSetup-anything"));
  TEST_ASSERT_FALSE(isSetupNetworkName("Heimnetz"));
  TEST_ASSERT_FALSE(isSetupNetworkName("escapesetup-x"));
}

void test_setup_validation() {
  TEST_ASSERT_TRUE(validWifiSsid("Heimnetz"));
  TEST_ASSERT_TRUE(validWifiSsid(std::string(32, 'x')));
  TEST_ASSERT_FALSE(validWifiSsid(""));
  TEST_ASSERT_FALSE(validWifiSsid(std::string(33, 'x')));
  TEST_ASSERT_FALSE(validWifiSsid("a\nb"));
  TEST_ASSERT_TRUE(validWifiPassword(""));                    // open network
  TEST_ASSERT_TRUE(validWifiPassword("12345678"));
  TEST_ASSERT_TRUE(validWifiPassword(std::string(63, 'p')));
  TEST_ASSERT_FALSE(validWifiPassword("1234567"));            // WPA needs 8..63
  TEST_ASSERT_FALSE(validWifiPassword(std::string(64, 'p')));
  TEST_ASSERT_TRUE(validSetupToken("12345678"));
  TEST_ASSERT_FALSE(validSetupToken("1234567"));
  TEST_ASSERT_FALSE(validSetupToken("has space in it"));
  TEST_ASSERT_FALSE(validSetupToken(std::string(129, 'x')));

  SetupChange c;
  std::string error;
  c.hasWifi = true;
  c.ssid = "EscapeSetup-0cb81501c400"; // never join (another device's) setup network
  TEST_ASSERT_FALSE(validateSetupChange(c, error));
  c.ssid = "Heimnetz";
  c.pass = "short";
  TEST_ASSERT_FALSE(validateSetupChange(c, error));
  c.pass = "longenough";
  TEST_ASSERT_TRUE(validateSetupChange(c, error));
}

void test_setup_json() {
  SetupChange c;
  std::string error;
  TEST_ASSERT_TRUE(parseSetupJson("{\"ssid\":\"Heimnetz\",\"pass\":\"geheimgeheim\",\"token\":\"a-new-token-123\",\"editToken\":\"another-token-456\"}", c, error));
  TEST_ASSERT_TRUE(c.hasWifi && c.hasToken && c.hasEditToken);
  TEST_ASSERT_EQUAL_STRING("Heimnetz", c.ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("geheimgeheim", c.pass.c_str());
  // Fields are independent; "" removes a token.
  TEST_ASSERT_TRUE(parseSetupJson("{\"editToken\":\"\"}", c, error));
  TEST_ASSERT_TRUE(c.hasEditToken && c.editToken.empty() && !c.hasWifi && !c.hasToken);
  const char *bad[] = {"", "[]", "{}", "{\"ssid\":\"x\"}", "{\"pass\":\"12345678\"}", "{\"ssid\":1,\"pass\":\"\"}",
                       "{\"token\":5}", "{\"token\":\"short\"}", "{\"ssid\":\"EscapeSetup-aabbccddeeff\",\"pass\":\"\"}",
                       "{\"editToken\":null}"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(parseSetupJson(bad[i], c, error), bad[i]);
  // An open network is a valid choice.
  TEST_ASSERT_TRUE(parseSetupJson("{\"ssid\":\"Cafe\",\"pass\":\"\"}", c, error));
  TEST_ASSERT_TRUE(c.hasWifi && c.pass.empty());
}

void test_setup_handler() {
  FakeSink sink;
  bool changed = true;
  EscapeProtocol::HttpResult r = EscapeProtocol::handleSetup(sink, "{\"token\":\"a-new-token-123\"}", changed);
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_TRUE(changed);
  TEST_ASSERT_TRUE(sink.viaNetwork); // network pushes keep the old Wi-Fi as fallback
  r = EscapeProtocol::handleSetup(sink, "{\"ssid\":\"Heimnetz\",\"pass\":\"geheimgeheim\"}", changed);
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_FALSE(changed); // Wi-Fi alone does not touch the keys
  r = EscapeProtocol::handleSetup(sink, "{\"ssid\":\"x\"}", changed);
  TEST_ASSERT_EQUAL_INT(400, r.status);
  TEST_ASSERT_EQUAL_INT(2, sink.applied); // a rejected change is never applied
  sink.result = SetupResult::Storage;
  r = EscapeProtocol::handleSetup(sink, "{\"token\":\"a-new-token-123\"}", changed);
  TEST_ASSERT_EQUAL_INT(500, r.status);
  TEST_ASSERT_FALSE(changed);
}

void test_dns_answers_everything_with_the_portal_address() {
  // Query for "connectivitycheck.gstatic.com" type A.
  const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x11, 'c', 'o', 'n', 'n', 'e', 'c', 't', 'i', 'v', 'i', 't', 'y', 'c', 'h', 'e', 'c', 'k',
                           0x07, 'g', 's', 't', 'a', 't', 'i', 'c', 0x03, 'c', 'o', 'm', 0x00, 0x00, 0x01, 0x00, 0x01};
  uint8_t out[128];
  const size_t n = buildDnsAnswer(query, sizeof(query), EscapeConfig::SETUP_AP_IP, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(sizeof(query) + 16, n);
  TEST_ASSERT_EQUAL_HEX8(0x12, out[0]);
  TEST_ASSERT_EQUAL_HEX8(0x34, out[1]);
  TEST_ASSERT_EQUAL_HEX8(0x81, out[2]);
  TEST_ASSERT_EQUAL_HEX8(0x80, out[3]);
  TEST_ASSERT_EQUAL_HEX8(1, out[7]);                                   // one answer
  TEST_ASSERT_EQUAL_MEMORY(query + 12, out + 12, sizeof(query) - 12);  // question echoed
  const uint8_t *a = out + sizeof(query);
  TEST_ASSERT_EQUAL_HEX8(0xC0, a[0]);
  TEST_ASSERT_EQUAL_HEX8(1, a[3]);                                     // type A
  TEST_ASSERT_EQUAL_HEX8(4, a[11]);
  TEST_ASSERT_EQUAL_HEX8(10, a[12]);
  TEST_ASSERT_EQUAL_HEX8(99, a[13]);
  TEST_ASSERT_EQUAL_HEX8(77, a[14]);
  TEST_ASSERT_EQUAL_HEX8(1, a[15]);

  // AAAA: NOERROR without an answer, so clients fall back to A quickly.
  uint8_t aaaa[sizeof(query)];
  memcpy(aaaa, query, sizeof(query));
  aaaa[sizeof(aaaa) - 3] = 0x1c;
  const size_t m = buildDnsAnswer(aaaa, sizeof(aaaa), EscapeConfig::SETUP_AP_IP, out, sizeof(out));
  TEST_ASSERT_EQUAL_UINT(sizeof(query), m);
  TEST_ASSERT_EQUAL_HEX8(0, out[7]);
}

void test_dns_ignores_garbage() {
  uint8_t out[600];
  const uint8_t shortQuery[] = {1, 2, 3};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(shortQuery, sizeof(shortQuery), 1, out, sizeof(out)));
  uint8_t response[40] = {0x12, 0x34, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(response, 19, 1, out, sizeof(out)));   // a response, not a query
  uint8_t twoQuestions[40] = {0x12, 0x34, 0x01, 0x00, 0, 2, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(twoQuestions, 19, 1, out, sizeof(out)));
  uint8_t compressed[40] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 0x0C, 0, 0, 1, 0, 1};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(compressed, 19, 1, out, sizeof(out)));
  uint8_t truncated[40] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 20, 'a', 'b'};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(truncated, 15, 1, out, sizeof(out)));
  const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 1, 'a', 0, 0, 1, 0, 1};
  TEST_ASSERT_EQUAL_UINT(0, buildDnsAnswer(query, sizeof(query), 1, out, 20)); // answer does not fit
  // mutation sweep: never read or write out of bounds (ASan)
  for (size_t i = 0; i < sizeof(query); i++) {
    for (int v = 0; v < 256; v += 51) {
      uint8_t m[sizeof(query)];
      memcpy(m, query, sizeof(query));
      m[i] = (uint8_t)v;
      buildDnsAnswer(m, sizeof(m), 1, out, sizeof(out));
      for (size_t cut = 0; cut < sizeof(query); cut++) buildDnsAnswer(m, cut, 1, out, sizeof(out));
    }
  }
}

void test_portal_pages() {
  FakeSink sink;
  sink.ssid = "Heimnetz";
  bool changed = false;
  HttpResponse res;
  handleSetupPortal(request(Method::Get, "/setup"), sink, "aabbccddeeff", "Tuer <b>1</b> (Raum A)", res, changed);
  TEST_ASSERT_EQUAL_INT(200, res.status);
  TEST_ASSERT_TRUE(res.contentType.find("text/html") == 0);
  TEST_ASSERT_TRUE(res.body.find("action=/setup/save") != std::string::npos);
  TEST_ASSERT_TRUE(res.body.find("EscapeSetup-aabbccddeeff") != std::string::npos);
  TEST_ASSERT_TRUE(res.body.find("Tuer &lt;b&gt;1&lt;/b&gt;") != std::string::npos); // device names are escaped
  TEST_ASSERT_TRUE(res.body.find("offen") != std::string::npos);
  TEST_ASSERT_TRUE(res.body.find("Jeder in Reichweite") != std::string::npos);        // open network warning
  TEST_ASSERT_TRUE(res.body.find("Heimnetz") != std::string::npos);
  TEST_ASSERT_TRUE(res.body.find("pass=") == std::string::npos);                      // the password is never shown
  TEST_ASSERT_FALSE(changed);

  sink.open = false; // WPA2 setup network: no warning about strangers
  HttpResponse wpa;
  handleSetupPortal(request(Method::Get, "/setup"), sink, "aabbccddeeff", "", wpa, changed);
  TEST_ASSERT_TRUE(wpa.body.find("Jeder in Reichweite") == std::string::npos);
  TEST_ASSERT_TRUE(wpa.body.find("WPA2") != std::string::npos);
}

void test_portal_redirects_captive_probes() {
  FakeSink sink;
  bool changed = false;
  const char *probes[] = {"/generate_204", "/gen_204", "/hotspot-detect.html", "/library/test/success.html", "/connecttest.txt",
                          "/ncsi.txt", "/canonical.html", "/success.txt", "/", "/anything/else"};
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    HttpResponse res;
    handleSetupPortal(request(Method::Get, probes[i]), sink, "aabbccddeeff", "", res, changed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(302, res.status, probes[i]);
    TEST_ASSERT_EQUAL_STRING_MESSAGE("http://10.99.77.1/setup", res.location.c_str(), probes[i]);
  }
  HttpResponse head = HttpResponse();
  head.status = 302;
  head.location = "http://10.99.77.1/setup";
  TEST_ASSERT_TRUE(formatResponseHead(head, "", false).find("Location: http://10.99.77.1/setup\r\n") != std::string::npos);
  HttpResponse res;
  handleSetupPortal(request(Method::Post, "/action", "{}"), sink, "aabbccddeeff", "", res, changed);
  TEST_ASSERT_EQUAL_INT(404, res.status); // nothing of the game's API is reachable from the setup network
  TEST_ASSERT_EQUAL_INT(0, sink.applied);
}

void test_portal_save() {
  FakeSink sink;
  bool changed = false;
  HttpResponse res;
  handleSetupPortal(request(Method::Post, "/setup/save",
                            "ssid=Mein+Netz%21&pass=p%40ss+word&token=&edit=edit-token-123"),
                    sink, "aabbccddeeff", "", res, changed);
  TEST_ASSERT_EQUAL_INT(200, res.status);
  TEST_ASSERT_EQUAL_INT(1, sink.applied);
  TEST_ASSERT_FALSE(sink.viaNetwork);                       // direct: no fallback network
  TEST_ASSERT_TRUE(sink.last.hasWifi);
  TEST_ASSERT_EQUAL_STRING("Mein Netz!", sink.last.ssid.c_str());   // '+' is a space, %21 is '!'
  TEST_ASSERT_EQUAL_STRING("p@ss word", sink.last.pass.c_str());
  TEST_ASSERT_FALSE(sink.last.hasToken);                    // empty field: unchanged
  TEST_ASSERT_TRUE(sink.last.hasEditToken);
  TEST_ASSERT_EQUAL_STRING("edit-token-123", sink.last.editToken.c_str());
  TEST_ASSERT_TRUE(changed);                                // a token changed: the caller re-derives the keys
  TEST_ASSERT_TRUE(res.body.find("Gespeichert") != std::string::npos);
  TEST_ASSERT_TRUE(res.body.find("refresh") != std::string::npos);

  // Wi-Fi only: the keys stay.
  HttpResponse wifiOnly;
  handleSetupPortal(request(Method::Post, "/setup/save", "ssid=Cafe&pass="), sink, "aabbccddeeff", "", wifiOnly, changed);
  TEST_ASSERT_EQUAL_INT(200, wifiOnly.status);
  TEST_ASSERT_FALSE(changed);
  TEST_ASSERT_TRUE(sink.last.pass.empty()); // open network

  // Rejections keep the form and apply nothing.
  const int before = sink.applied;
  const char *bad[] = {"", "ssid=&pass=&token=&edit=", "pass=12345678", "ssid=Netz&pass=short", "token=short",
                       "ssid=EscapeSetup-0cb81501c400&pass=", "edit=has%20space%20inside"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    HttpResponse r;
    handleSetupPortal(request(Method::Post, "/setup/save", bad[i]), sink, "aabbccddeeff", "", r, changed);
    TEST_ASSERT_EQUAL_INT_MESSAGE(400, r.status, bad[i]);
    TEST_ASSERT_TRUE_MESSAGE(r.body.find("class=e") != std::string::npos, bad[i]);
    TEST_ASSERT_FALSE(changed);
  }
  TEST_ASSERT_EQUAL_INT(before, sink.applied);
  sink.result = SetupResult::Storage;
  HttpResponse failed;
  handleSetupPortal(request(Method::Post, "/setup/save", "ssid=Cafe&pass="), sink, "aabbccddeeff", "", failed, changed);
  TEST_ASSERT_EQUAL_INT(500, failed.status);
  TEST_ASSERT_FALSE(changed);
}

void test_portal_status_page() {
  FakeSink sink;
  sink.ssid = "Heimnetz";
  bool changed = false;
  struct { WifiPhase phase; const char *expect; bool refresh; } cases[] = {
      {WifiPhase::Connecting, "verbindet", true}, {WifiPhase::Connected, "192.168.1.77", false},
      {WifiPhase::Failed, "Passwort falsch?", false}, {WifiPhase::Idle, "kein WLAN", true}};
  for (size_t i = 0; i < 4; i++) {
    sink.phase = cases[i].phase;
    HttpResponse res;
    handleSetupPortal(request(Method::Get, "/setup/status"), sink, "aabbccddeeff", "", res, changed);
    TEST_ASSERT_EQUAL_INT(200, res.status);
    TEST_ASSERT_TRUE_MESSAGE(res.body.find(cases[i].expect) != std::string::npos, cases[i].expect);
    TEST_ASSERT_EQUAL_INT((int)cases[i].refresh, (int)(res.body.find("http-equiv=refresh") != std::string::npos));
  }
}

} // namespace

void runSetupTests() {
  RUN_TEST(test_setup_network_name_is_unique_and_never_the_router_name);
  RUN_TEST(test_setup_validation);
  RUN_TEST(test_setup_json);
  RUN_TEST(test_setup_handler);
  RUN_TEST(test_dns_answers_everything_with_the_portal_address);
  RUN_TEST(test_dns_ignores_garbage);
  RUN_TEST(test_portal_pages);
  RUN_TEST(test_portal_redirects_captive_probes);
  RUN_TEST(test_portal_save);
  RUN_TEST(test_portal_status_page);
}
