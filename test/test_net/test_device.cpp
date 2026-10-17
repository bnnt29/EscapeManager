// Two complete Device instances in one process, talking over loopback: discovery,
// authenticated reads, secure writes, skeleton sync and the shared mDNS record.
#include <unity.h>

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/net/Clock.hpp"
#include "../../src/net/Device.hpp"
#include "../../src/protocol/Base64Url.hpp"
#include "../../src/protocol/Mdns.hpp"
#include "../../src/sim/OpenSslCryptoBackend.hpp"

using namespace Escape;
using EscapeJson::Value;

namespace {

class Host : public EscapeProtocol::ProtocolAdapter {
public:
  Host(const char *room, const char *name) : dev(nullptr), actions(0), room_(room), name_(name) {}
  Device *dev;
  int actions;
  std::string room_, name_, plan_;
  int8_t battery() const override { return 55; }
  void markDirty() override { if (dev) dev->markDirty(); }
  uint8_t componentCount() const override { return 1; }
  void identity(uint8_t, std::string &n, std::string &r) const override { n = name_; r = room_; }
  void snapshot(uint8_t, EscapeProtocol::ComponentSnapshot &o) const override {
    EscapeProtocol::copyBounded(o.name, sizeof(o.name), name_.c_str());
    EscapeProtocol::copyBounded(o.room, sizeof(o.room), room_.c_str());
    EscapeProtocol::copyBounded(o.uuid, sizeof(o.uuid), "x-0");
    EscapeProtocol::copyBounded(o.plan, sizeof(o.plan), plan_.c_str());
  }
  void customConfigDefs(uint8_t, std::vector<EscapeProtocol::CustomConfigDef> &o) const override { o.clear(); }
  bool applyAction(uint8_t, const std::string &) override { actions++; return true; }
  bool applyPlanAction(uint8_t, EscapeProtocol::PlanAction) override { return true; }
  void setIdentity(uint8_t, const std::string &n, const std::string &r) override { name_ = n; room_ = r; }
  void setRiddleId(uint8_t, const std::string &) override {}
  bool setCustomConfigValue(uint8_t, const std::string &, const std::string &) override { return true; }
  void setPlan(uint8_t, const std::string &p) override { plan_ = p; }
  void pushEvent(uint8_t, const std::string &) override {}
};

class Platform : public DevicePlatform {
public:
  uint32_t localIp() override { return 0x7F000001; }
  uint32_t broadcastIp() override { return 0x7FFFFFFF; }
};

struct Node {
  OpenSslCryptoBackend crypto;
  MemoryStorage storage;
  Platform platform;
  Host host;
  Device device;
  Node(const char *room, const char *name) : host(room, name), device(host, crypto, storage, platform) { host.dev = &device; }
};

DeviceOptions options(const char *did, uint16_t port, uint32_t boot = 1) {
  DeviceOptions o;
  o.did = did;
  o.httpPort = port;
  o.udpPort = 14310;
  o.mdnsPort = 0;
  o.bootCounter = boot;
  return o;
}

const char *kToken = "correct-horse-battery-staple";

void pump(Node &a, Node &b, uint32_t ms, uint32_t *clock) {
  const uint32_t end = *clock + ms;
  while ((int32_t)(*clock - end) < 0) {
    a.device.loop(*clock);
    b.device.loop(*clock);
    *clock += 5;
    usleep(1500);
  }
}

// Minimal blocking client for tests: pumps both devices while waiting.
std::string http(Node &a, Node &b, uint32_t *clock, uint16_t port, const std::string &request) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(0x7F000001);
  TEST_ASSERT_EQUAL_INT(0, connect(fd, (sockaddr *)&addr, sizeof(addr)));
  send(fd, request.data(), request.size(), MSG_NOSIGNAL);
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  std::string response;
  for (int i = 0; i < 400; i++) {
    a.device.loop(*clock);
    b.device.loop(*clock);
    *clock += 5;
    char buf[8192];
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n > 0) response.append(buf, (size_t)n);
    else if (n == 0) break;
    usleep(500);
  }
  close(fd);
  return response;
}

std::string bodyOf(const std::string &r) {
  const size_t p = r.find("\r\n\r\n");
  return p == std::string::npos ? std::string() : r.substr(p + 4);
}

int statusOf(const std::string &r) { return r.size() > 12 ? atoi(r.c_str() + 9) : 0; }

// A manager's view of one device: derives the same keys and talks the protocol.
struct Client {
  OpenSslCryptoBackend crypto;
  SecureTransport tr;
  std::string did;
  Client(const char *token, const char *deviceId) : tr(crypto), did(deviceId) { tr.begin(token, TokenState::Custom, deviceId); }

  std::string get(Node &a, Node &b, uint32_t *clock, uint16_t port, const std::string &path, const std::string &query, bool *verified = nullptr) {
    const std::string nonce = "0123456789abcdefghijklmnop";
    const std::string target = path + "?nonce=" + nonce + (query.empty() ? "" : "&" + query);
    const std::string r = http(a, b, clock, port, "GET " + target + " HTTP/1.1\r\nHost: x\r\n\r\n");
    const std::string body = bodyOf(r);
    EscapeJson::Slice doc;
    const bool ok = tr.openDocumentFrame(path, nonce, statusOf(r), body.data(), body.size(), doc);
    if (verified) *verified = ok;
    return ok ? doc.str() : std::string();
  }

  // POST with the device clock taken from /security.json, like the manager does.
  std::string post(Node &a, Node &b, uint32_t *clock, uint16_t port, const std::string &path, const std::string &plaintext, int *status,
                   uint32_t tOverride = 0, bool useOverride = false) {
    const std::string sec = bodyOf(http(a, b, clock, port, "GET /security.json HTTP/1.1\r\n\r\n"));
    Value v;
    TEST_ASSERT_TRUE(EscapeJson::parse(sec, v, EscapeJson::ParseLimits(8, 400)));
    const uint32_t t = useOverride ? tOverride : (uint32_t)v.find("time")->asNumber();
    uint8_t ivBytes[12];
    crypto.randomBytes(ivBytes, 12);
    std::string envelope;
    TEST_ASSERT_TRUE(tr.sealRequest(path, t, plaintext, ivBytes, envelope));
    const std::string r = http(a, b, clock, port, "POST " + path + " HTTP/1.1\r\nContent-Length: " + std::to_string(envelope.size()) + "\r\n\r\n" + envelope);
    *status = statusOf(r);
    const std::string body = bodyOf(r);
    std::string plain;
    if (tr.openResponse(path, base64UrlEncode(ivBytes, 12), *status, body.data(), body.size(), plain)) return plain;
    return std::string("UNAUTHENTICATED:") + body;
  }
};

void test_discovery_and_authenticated_reads() {
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18101), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18102), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  pump(a, b, 1500, &clock);
  TEST_ASSERT_EQUAL_UINT(1, a.device.peers().count());
  TEST_ASSERT_EQUAL_UINT(1, b.device.peers().count());
  Client ca(kToken, "aaaaaaaaaaaa");
  bool ok = false;
  const std::string peersDoc = ca.get(a, b, &clock, 18101, "/peers.json", "", &ok);
  TEST_ASSERT_TRUE(ok);
  Value v;
  TEST_ASSERT_TRUE(EscapeJson::parse(peersDoc, v, EscapeJson::ParseLimits(8, 400)));
  TEST_ASSERT_EQUAL_STRING("aaaaaaaaaaaa", v.find("self")->find("did")->asString().c_str());
  TEST_ASSERT_EQUAL_STRING("bbbbbbbbbbbb", v.find("peers")->arrayValue[0].find("did")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(18102, (int)v.find("peers")->arrayValue[0].find("port")->asNumber());
  const std::string statusDoc = ca.get(a, b, &clock, 18101, "/status.json", "", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(EscapeJson::parse(statusDoc, v, EscapeJson::ParseLimits(8, 400)));
  TEST_ASSERT_EQUAL_INT(55, (int)v.find("battery")->asNumber());
  // a client with the wrong token cannot verify the frame
  Client wrong("another-token-value", "aaaaaaaaaaaa");
  wrong.get(a, b, &clock, 18101, "/status.json", "", &ok);
  TEST_ASSERT_FALSE(ok);
  // viewer mode (no nonce) returns the bare document; a bad nonce is refused
  std::string r = http(a, b, &clock, 18101, "GET /status.json HTTP/1.1\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(200, statusOf(r));
  TEST_ASSERT_TRUE(bodyOf(r).find("\"components\"") != std::string::npos);
  r = http(a, b, &clock, 18101, "GET /status.json?nonce=short HTTP/1.1\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(400, statusOf(r));
  a.device.end();
  b.device.end();
}

void test_secure_writes() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18101), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18102), kToken, TokenState::Custom));
  uint32_t clock = 5000;
  Client c(kToken, "aaaaaaaaaaaa");
  int status = 0;
  std::string r = c.post(a, b, &clock, 18101, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING("{\"ok\":true}", r.c_str());
  TEST_ASSERT_EQUAL_INT(1, a.host.actions);
  const uint32_t seqBefore = a.device.seq();
  TEST_ASSERT_TRUE(seqBefore > 1);
  // stale clock: authenticated 409 with the device time so the client can resync
  r = c.post(a, b, &clock, 18101, "/action", "{\"id\":0,\"action\":\"open\"}", &status, 100000, true);
  TEST_ASSERT_EQUAL_INT(409, status);
  Value v;
  TEST_ASSERT_TRUE(EscapeJson::parse(r, v, EscapeJson::ParseLimits(8, 100)));
  TEST_ASSERT_EQUAL_STRING("stale_time", v.find("code")->asString().c_str());
  TEST_ASSERT_TRUE(v.find("time") != nullptr);
  TEST_ASSERT_EQUAL_INT(1, a.host.actions);
  // a client with the wrong token gets an unauthenticated 401 and changes nothing
  Client wrong("another-token-value", "aaaaaaaaaaaa");
  r = wrong.post(a, b, &clock, 18101, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(401, status);
  TEST_ASSERT_EQUAL_INT(1, a.host.actions);
  // device ids are bound: a request for A is useless against B
  Client forB(kToken, "bbbbbbbbbbbb");
  r = forB.post(a, b, &clock, 18101, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(401, status);
  // the rate limiter has been exercised by the requests above; let the budget refill
  clock += 20000;
  // unknown token state: read-only device refuses writes but still serves reads
  a.device.end();
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18101), "", TokenState::Invalid));
  r = c.post(a, b, &clock, 18101, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(503, status);
  TEST_ASSERT_TRUE(r.find("read_only") != std::string::npos);
  const std::string sec = bodyOf(http(a, b, &clock, 18101, "GET /security.json HTTP/1.1\r\n\r\n"));
  TEST_ASSERT_TRUE(sec.find("\"token\":\"invalid\"") != std::string::npos);
  TEST_ASSERT_TRUE(sec.find("\"writable\":false") != std::string::npos);
  a.device.end();
  b.device.end();
}

void test_skeleton_write_and_sync() {
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18101), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18102), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  Client ca(kToken, "aaaaaaaaaaaa"), cb(kToken, "bbbbbbbbbbbb");
  pump(a, b, 1200, &clock);
  int status = 0;
  const std::string sk = "{\"planId\":\"p1\",\"layers\":[{\"id\":\"L1\",\"lanes\":[]}]}";
  std::string r = ca.post(a, b, &clock, 18101, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk + "}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_TRUE(r.find("\"rev\":1") != std::string::npos);
  TEST_ASSERT_NULL(b.device.store().find("Raum A"));
  pump(a, b, 8000, &clock); // A announces its skeleton summary; B fetches and adopts it
  TEST_ASSERT_NOT_NULL(b.device.store().find("Raum A"));
  TEST_ASSERT_EQUAL_UINT32(1, b.device.store().find("Raum A")->rev);
  TEST_ASSERT_EQUAL_UINT32(a.device.store().find("Raum A")->hash, b.device.store().find("Raum A")->hash);
  // B updates the plan on top of revision 1; A catches up through the same path
  const std::string sk2 = "{\"planId\":\"p1\",\"layers\":[{\"id\":\"L1\",\"lanes\":[{\"id\":\"A\"}]}]}";
  r = cb.post(a, b, &clock, 18102, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":1,\"sk\":" + sk2 + "}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  pump(a, b, 8000, &clock);
  TEST_ASSERT_EQUAL_UINT32(2, a.device.store().find("Raum A")->rev);
  // a stale writer (still on rev 1) is told about the conflict instead of overwriting
  r = ca.post(a, b, &clock, 18101, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":1,\"sk\":{\"planId\":\"other\"}}", &status);
  TEST_ASSERT_EQUAL_INT(409, status);
  TEST_ASSERT_TRUE(r.find("rev_conflict") != std::string::npos);
  // authenticated skeleton reads: index and single room, 404 for a room without a plan
  bool ok = false;
  const std::string idx = ca.get(a, b, &clock, 18101, "/plan-skeleton.json", "", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(idx.find("\"rev\":2") != std::string::npos);
  const std::string blob = ca.get(a, b, &clock, 18101, "/plan-skeleton.json", "room=Raum%20A", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(blob.find(sk2) != std::string::npos);
  const std::string none = ca.get(a, b, &clock, 18101, "/plan-skeleton.json", "room=Nowhere", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(none.find("no_plan") != std::string::npos);
  a.device.end();
  b.device.end();
}

void test_peer_with_other_token_is_ignored() {
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18101), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18102), "a-different-venue-token", TokenState::Custom));
  uint32_t clock = 1000;
  pump(a, b, 1500, &clock);
  TEST_ASSERT_EQUAL_UINT(0, a.device.peers().count()); // its announcements fail the MAC check
  TEST_ASSERT_EQUAL_UINT(0, b.device.peers().count());
  TEST_ASSERT_TRUE(a.device.announcementsSent() > 0);
  a.device.end();
  b.device.end();
}

void test_mdns_shared_record() {
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  DeviceOptions oa = options("aaaaaaaaaaaa", 18101), ob = options("bbbbbbbbbbbb", 18102);
  oa.mdnsPort = ob.mdnsPort = 15353;
  TEST_ASSERT_TRUE(a.device.begin(oa, kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(ob, kToken, TokenState::Custom));
  uint32_t clock = 1000;
  pump(a, b, 100, &clock);
  // Ask over unicast (QU bit) so the test does not depend on multicast routing on the CI host.
  const uint8_t query[] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 13, 'e', 's', 'c', 'a', 'p', 'e', 'm', 'a', 'n', 'a', 'g', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 1, 0x80, 1};
  UdpSocket asker;
  TEST_ASSERT_TRUE(asker.openBroadcast(0));
  int answers = 0;
  uint8_t buf[256];
  asker.send(0x7F000001, 15353, query, sizeof(query));
  for (int i = 0; i < 200 && answers < 2; i++) {
    pump(a, b, 10, &clock);
    uint32_t ip;
    uint16_t port;
    const int n = asker.receive(buf, sizeof(buf), ip, port);
    if (n > 0) {
      TEST_ASSERT_TRUE(n > 12);
      TEST_ASSERT_EQUAL_UINT8(0x84, buf[2]);
      answers++;
    }
  }
  TEST_ASSERT_TRUE(answers >= 1); // devices answer for the shared name (both when both received it)
  a.device.end();
  b.device.end();
}

} // namespace

void runDeviceTests() {
  RUN_TEST(test_discovery_and_authenticated_reads);
  RUN_TEST(test_secure_writes);
  RUN_TEST(test_skeleton_write_and_sync);
  RUN_TEST(test_peer_with_other_token_is_ignored);
  RUN_TEST(test_mdns_shared_record);
}
