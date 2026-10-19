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
#include "../../extras/sim/OpenSslCryptoBackend.hpp"

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
  Platform() : up(true), setup(false), setupClient(0) {}
  bool up;                                   // lets a test take the "network" down
  bool setup;                                // the setup network (access point) is up
  uint32_t setupClient;                      // the one address that counts as a client of the setup network
  uint32_t localIp() override { return up ? 0x7F000001 : 0; }
  uint32_t broadcastIp() override { return 0x7FFFFFFF; }
  bool setupNetworkUp() override { return setup; }
  bool isSetupClient(uint32_t ip) override { return setup && ip == setupClient; }
};

// Persists nothing; remembers what a network push or the portal asked for.
class Sink : public SetupSink {
public:
  SetupChange last;
  int applied;
  bool viaNetwork;
  SetupTokens tokens;
  Sink() : applied(0), viaNetwork(false) {}
  SetupResult applySetup(const SetupChange &c, bool net) override {
    last = c;
    viaNetwork = net;
    applied++;
    if (c.hasToken) { tokens.token = c.token; tokens.tokenState = c.token.empty() ? TokenState::Default : TokenState::Custom; }
    if (c.hasEditToken) { tokens.editToken = c.editToken; tokens.editState = c.editToken.empty() ? EditState::Unset : EditState::Custom; }
    return SetupResult::Ok;
  }
  void currentTokens(SetupTokens &out) override { out = tokens; }
  std::string setupNetworkName() const override { return "EscapeSetup-aaaaaaaaaaaa"; }
  const char *setupApMode() const override { return "open"; }
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
  KeyRole lastRole = KeyRole::Normal; // key set the last answer was sealed with
  Client(const char *token, const char *deviceId, const char *editToken = nullptr) : tr(crypto), did(deviceId) {
    tr.begin(token, TokenState::Custom, deviceId, editToken ? editToken : "", editToken ? EditState::Custom : EditState::Unset);
  }

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
                   uint32_t tOverride = 0, bool useOverride = false, KeyRole role = KeyRole::Normal) {
    const std::string sec = bodyOf(http(a, b, clock, port, "GET /security.json HTTP/1.1\r\n\r\n"));
    Value v;
    TEST_ASSERT_TRUE(EscapeJson::parse(sec, v, EscapeJson::ParseLimits(8, 400)));
    const uint32_t t = useOverride ? tOverride : (uint32_t)v.find("time")->asNumber();
    uint8_t ivBytes[12];
    crypto.randomBytes(ivBytes, 12);
    std::string envelope;
    TEST_ASSERT_TRUE(tr.sealRequest(path, t, plaintext, ivBytes, envelope, role));
    const std::string r = http(a, b, clock, port, "POST " + path + " HTTP/1.1\r\nContent-Length: " + std::to_string(envelope.size()) + "\r\n\r\n" + envelope);
    *status = statusOf(r);
    const std::string body = bodyOf(r);
    std::string plain;
    // Success is sealed with the key set that authenticated the request, errors before that with the normal one.
    if (tr.openResponse(path, base64UrlEncode(ivBytes, 12), *status, body.data(), body.size(), plain, role)) { lastRole = role; return plain; }
    if (role == KeyRole::Edit && tr.openResponse(path, base64UrlEncode(ivBytes, 12), *status, body.data(), body.size(), plain, KeyRole::Normal)) {
      lastRole = KeyRole::Normal;
      return plain;
    }
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

void test_sockets_wait_for_the_network_and_retry_when_the_port_is_taken() {
  // Network down at begin(): no sockets are opened (on the ESP32 the first socket() call blocks for
  // ~350 ms while the Wi-Fi stack is starting), begin() still succeeds.
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  a.platform.up = false;
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18121), kToken, TokenState::Custom));
  TEST_ASSERT_FALSE(a.device.socketsOpen());
  uint32_t clock = 1000;
  for (int i = 0; i < 20; i++) { a.device.loop(clock); clock += 50; }
  TEST_ASSERT_FALSE(a.device.socketsOpen());
  TEST_ASSERT_FALSE(a.device.httpPortFailed());
  {
    const int refused = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(18121);
    addr.sin_addr.s_addr = htonl(0x7F000001);
    TEST_ASSERT_TRUE(connect(refused, (sockaddr *)&addr, sizeof(addr)) != 0); // nobody listens yet
    close(refused);
  }
  // Link comes up: the first loop() opens the sockets and the device serves requests.
  a.platform.up = true;
  a.device.loop(clock);
  TEST_ASSERT_TRUE(a.device.socketsOpen());
  TEST_ASSERT_EQUAL_INT(200, statusOf(http(a, b, &clock, 18121, "GET /security.json HTTP/1.1\r\n\r\n")));
  a.device.end();

  // Port taken by someone else: flagged, retried every 5 s, and recovers when the port is freed.
  const int blocker = socket(AF_INET, SOCK_STREAM, 0);
  const int on = 1;
  setsockopt(blocker, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(18122);
  addr.sin_addr.s_addr = htonl(0x7F000001);
  TEST_ASSERT_EQUAL_INT(0, bind(blocker, (sockaddr *)&addr, sizeof(addr)));
  listen(blocker, 1);
  Node c("Raum A", "Tuer");
  c.platform.up = false;
  TEST_ASSERT_TRUE(c.device.begin(options("cccccccccccc", 18122), kToken, TokenState::Custom));
  c.platform.up = true;
  c.device.loop(clock);
  TEST_ASSERT_TRUE(c.device.httpPortFailed());
  TEST_ASSERT_FALSE(c.device.socketsOpen());
  clock += 1000;
  c.device.loop(clock);                      // inside the back-off window: no new attempt
  TEST_ASSERT_TRUE(c.device.httpPortFailed());
  close(blocker);                            // the other server goes away
  clock += 6000;
  c.device.loop(clock);
  TEST_ASSERT_FALSE(c.device.httpPortFailed());
  TEST_ASSERT_TRUE(c.device.socketsOpen());
  c.device.end();
  // With the network up at begin() and the port taken, begin() itself reports the failure.
  const int blocker2 = socket(AF_INET, SOCK_STREAM, 0);
  setsockopt(blocker2, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  TEST_ASSERT_EQUAL_INT(0, bind(blocker2, (sockaddr *)&addr, sizeof(addr)));
  listen(blocker2, 1);
  Node d("Raum A", "Tuer2");
  TEST_ASSERT_FALSE(d.device.begin(options("dddddddddddd", 18122), kToken, TokenState::Custom));
  close(blocker2);
}

void test_host_hints_are_coalesced_and_verified() {
  // Some host programs call markDirty() on EVERY loop iteration. That must not make `seq` climb
  // or the device announce at the loop rate; only a real change counts.
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18131), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18132), kToken, TokenState::Custom));
  uint32_t clock = 10000;
  for (int i = 0; i < 300; i++) { a.device.hostChanged(); a.device.loop(clock); clock += 5; } // 1.5 s, warm-up
  const uint32_t seq0 = a.device.seq();
  const uint32_t sent0 = a.device.announcementsSent();
  for (int i = 0; i < 2000; i++) { a.device.hostChanged(); a.device.loop(clock); clock += 5; usleep(100); } // 10 s of constant hints
  TEST_ASSERT_EQUAL_UINT32(seq0, a.device.seq());                       // nothing changed -> no new revision
  TEST_ASSERT_TRUE(a.device.announcementsSent() - sent0 <= 4);          // heartbeat pace (4-5 s), not every 300 ms

  // A real change behind a hint is picked up within the check interval - exactly once.
  a.host.plan_ = "{\"planId\":\"changed\"}";
  a.device.hostChanged();
  for (int i = 0; i < 200; i++) { a.device.hostChanged(); a.device.loop(clock); clock += 5; }  // 1 s
  TEST_ASSERT_EQUAL_UINT32(seq0 + 1, a.device.seq());
  for (int i = 0; i < 600; i++) { a.device.hostChanged(); a.device.loop(clock); clock += 5; }  // 3 s more of hints
  TEST_ASSERT_EQUAL_UINT32(seq0 + 1, a.device.seq());

  // Several changes between two checks collapse into one bump; a change WITHOUT a hint is not looked for.
  a.host.name_ = "Laser-2";
  a.host.room_ = "Raum A";
  a.device.hostChanged();
  a.device.loop(clock);
  clock += 700;
  a.device.loop(clock);
  TEST_ASSERT_EQUAL_UINT32(seq0 + 2, a.device.seq());
  a.host.plan_ = "{\"planId\":\"silent\"}";                          // no hint
  for (int i = 0; i < 400; i++) { a.device.loop(clock); clock += 5; }
  TEST_ASSERT_EQUAL_UINT32(seq0 + 2, a.device.seq());

  // Changes made through the protocol (a manager's write) stay immediate.
  Client c(kToken, "aaaaaaaaaaaa");
  int status = 0;
  c.post(a, b, &clock, 18131, "/action", "{\"id\":0,\"action\":\"go\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_TRUE(a.device.seq() > seq0 + 2);
  a.device.end();
  b.device.end();
}

void test_everything_works_with_the_clock_just_before_the_32_bit_wrap() {
  // The device clock is a uint32 millisecond counter that wraps after 49.7 days. Deadlines must never
  // depend on the clock being "small" (a deadline initialised to 0 and compared as a signed difference
  // stalls the whole feature while the clock is in the upper half: found on real hardware).
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  a.platform.up = false;                                     // late network: sockets are opened from loop()
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18141), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18142), kToken, TokenState::Custom));
  uint32_t clock = 0xFFFFF800u;                              // 2.05 s before the wrap
  for (int i = 0; i < 20; i++) { a.device.loop(clock); b.device.loop(clock); clock += 5; }
  TEST_ASSERT_FALSE(a.device.socketsOpen());
  a.platform.up = true;
  a.device.loop(clock);
  TEST_ASSERT_TRUE(a.device.socketsOpen());                  // opened although (int32_t)clock < 0
  // host hints work in the upper half of the range too
  a.host.plan_ = "{\"planId\":\"before\"}";
  a.device.hostChanged();
  const uint32_t seq0 = a.device.seq();
  for (int i = 0; i < 200; i++) { a.device.loop(clock); b.device.loop(clock); clock += 5; usleep(300); }
  TEST_ASSERT_TRUE(a.device.seq() > seq0);
  // discovery and secure writes before the wrap ...
  Client ca(kToken, "aaaaaaaaaaaa");
  int status = 0;
  ca.post(a, b, &clock, 18141, "/action", "{\"id\":0,\"action\":\"x\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_TRUE((int32_t)clock < 0 && clock > 0xFFFF0000u);   // still before the wrap
  // ... run across the wrap ...
  while (clock > 0x10000000u) { a.device.loop(clock); b.device.loop(clock); clock += 5; usleep(200); }
  TEST_ASSERT_TRUE(clock < 0x10000000u);                     // the clock wrapped
  for (int i = 0; i < 1500; i++) { a.device.loop(clock); b.device.loop(clock); clock += 5; usleep(200); }
  TEST_ASSERT_EQUAL_UINT(1, a.device.peers().count());       // discovery never stopped ...
  TEST_ASSERT_EQUAL_UINT(1, b.device.peers().count());
  ca.post(a, b, &clock, 18141, "/action", "{\"id\":0,\"action\":\"x\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);                        // ... and neither did secure writes
  a.device.end();
  b.device.end();
}


const char *kEditToken = "edit-token-for-the-tests";

void test_edit_token_guards_sending_plans() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18151), kToken, TokenState::Custom, kEditToken, EditState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18152), kToken, TokenState::Custom)); // no edit token: as before
  uint32_t clock = 5000;
  Client normal(kToken, "aaaaaaaaaaaa");
  Client editor(kToken, "aaaaaaaaaaaa", kEditToken);
  int status = 0;
  const std::string sk = "{\"planId\":\"p1\",\"layers\":[]}";
  const std::string skBody = "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk + "}";

  // Game operation needs only the normal token.
  std::string r = normal.post(a, b, &clock, 18151, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, a.host.actions);
  // Sending a plan with the normal token alone is refused - but the refusal is authenticated.
  r = normal.post(a, b, &clock, 18151, "/plan-skeleton", skBody, &status);
  TEST_ASSERT_EQUAL_INT(403, status);
  TEST_ASSERT_TRUE(r.find("edit_required") != std::string::npos);
  r = normal.post(a, b, &clock, 18151, "/plan", "{\"id\":0,\"plan\":{\"x\":1}}", &status);
  TEST_ASSERT_EQUAL_INT(403, status);
  TEST_ASSERT_NULL(a.device.store().find("Raum A"));
  TEST_ASSERT_TRUE(a.host.plan_.empty());
  // With the edit token it works, and the answer is sealed with the edit keys.
  r = editor.post(a, b, &clock, 18151, "/plan-skeleton", skBody, &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_TRUE(editor.lastRole == KeyRole::Edit);
  TEST_ASSERT_TRUE(r.find("\"rev\":1") != std::string::npos);
  r = editor.post(a, b, &clock, 18151, "/plan", "{\"id\":0,\"plan\":{\"x\":1}}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING("{\"x\":1}", a.host.plan_.c_str());
  // The stored skeleton is stamped (emac) so peers with the edit token accept it.
  bool ok = false;
  const std::string blob = normal.get(a, b, &clock, 18151, "/plan-skeleton.json", "room=Raum%20A", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(blob.find("\"emac\":\"") != std::string::npos);
  // A wrong edit token is refused like any other bad authentication.
  Client wrongEdit(kToken, "aaaaaaaaaaaa", "not-the-edit-token-0000");
  r = wrongEdit.post(a, b, &clock, 18151, "/plan", "{\"id\":0,\"plan\":null}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(401, status);
  TEST_ASSERT_EQUAL_STRING("{\"x\":1}", a.host.plan_.c_str());
  // The edit keys never authorise normal operation.
  r = editor.post(a, b, &clock, 18151, "/action", "{\"id\":0,\"action\":\"open\"}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(400, status);
  TEST_ASSERT_EQUAL_INT(1, a.host.actions);

  // A device WITHOUT an edit token behaves exactly as before (mixed fleets): the normal token sends plans.
  Client forB(kToken, "bbbbbbbbbbbb");
  r = forB.post(a, b, &clock, 18152, "/plan", "{\"id\":0,\"plan\":{\"y\":2}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  // ... and an edit-keyed request cannot even be verified there.
  Client editForB(kToken, "bbbbbbbbbbbb", kEditToken);
  r = editForB.post(a, b, &clock, 18152, "/plan", "{\"id\":0,\"plan\":null}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(401, status);

  // Published states (security.json is public; status.json is framed).
  const std::string secA = bodyOf(http(a, b, &clock, 18151, "GET /security.json HTTP/1.1\r\n\r\n"));
  TEST_ASSERT_TRUE(secA.find("\"edit\":\"custom\"") != std::string::npos);
  TEST_ASSERT_TRUE(secA.find("\"edit\"") != std::string::npos && secA.find("\"caps\":[\"plan\",\"cfg\",\"edit\"]") != std::string::npos);
  const std::string secB = bodyOf(http(a, b, &clock, 18152, "GET /security.json HTTP/1.1\r\n\r\n"));
  TEST_ASSERT_TRUE(secB.find("\"edit\":\"unset\"") != std::string::npos);
  const std::string status1 = normal.get(a, b, &clock, 18151, "/status.json", "", &ok);
  TEST_ASSERT_TRUE(ok);
  TEST_ASSERT_TRUE(status1.find("\"edit\":\"custom\"") != std::string::npos);
  a.device.end();
  b.device.end();
}

void test_edit_proof_endpoint() {
  Node a("Raum A", "Laser"), b("Raum A", "Kamera");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18151), kToken, TokenState::Custom, kEditToken, EditState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18152), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  Client editor(kToken, "aaaaaaaaaaaa", kEditToken);
  const std::string nonce = "0123456789abcdefghijklmnop";
  const std::string r = http(a, b, &clock, 18151, "GET /edit.json?nonce=" + nonce + " HTTP/1.1\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(200, statusOf(r));
  const std::string body = bodyOf(r);
  EscapeJson::Slice doc;
  TEST_ASSERT_TRUE(editor.tr.openEditDocumentFrame("/edit.json", nonce, 200, body.data(), body.size(), doc));
  TEST_ASSERT_TRUE(doc.str().find("\"edit\":\"custom\"") != std::string::npos);
  // Only a holder of the SAME edit token can verify it; the normal token cannot.
  Client normalOnly(kToken, "aaaaaaaaaaaa");
  TEST_ASSERT_FALSE(normalOnly.tr.openEditDocumentFrame("/edit.json", nonce, 200, body.data(), body.size(), doc));
  Client other(kToken, "aaaaaaaaaaaa", "some-other-edit-token-1");
  TEST_ASSERT_FALSE(other.tr.openEditDocumentFrame("/edit.json", nonce, 200, body.data(), body.size(), doc));
  // A nonce is mandatory (no unauthenticated variant), and a device without an edit token says so.
  TEST_ASSERT_EQUAL_INT(400, statusOf(http(a, b, &clock, 18151, "GET /edit.json HTTP/1.1\r\n\r\n")));
  const std::string none = http(a, b, &clock, 18152, "GET /edit.json?nonce=" + nonce + " HTTP/1.1\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(404, statusOf(none));
  TEST_ASSERT_TRUE(bodyOf(none).find("edit_unset") != std::string::npos);
  a.device.end();
  b.device.end();
}

void test_skeleton_sync_with_edit_token_rejects_planted_plans() {
  // A and B share both tokens. C only knows the normal token (an attacker, or a device that was never
  // given the edit token) and tries to push a newer plan to them through discovery.
  Node a("Raum A", "Laser"), b("Raum A", "Kamera"), c("Raum A", "Rogue");
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18161), kToken, TokenState::Custom, kEditToken, EditState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18162), kToken, TokenState::Custom, kEditToken, EditState::Custom));
  uint32_t clock = 1000;
  Client editA(kToken, "aaaaaaaaaaaa", kEditToken);
  pump(a, b, 1500, &clock);
  int status = 0;
  const std::string sk1 = "{\"planId\":\"legit\"}";
  editA.post(a, b, &clock, 18161, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + sk1 + "}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  pump(a, b, 8000, &clock);
  TEST_ASSERT_NOT_NULL(b.device.store().find("Raum A")); // signed skeleton propagates between edit-token devices
  TEST_ASSERT_EQUAL_UINT32(1, b.device.store().find("Raum A")->rev);

  // The rogue device stores a much newer skeleton and announces it.
  TEST_ASSERT_TRUE(c.device.begin(options("cccccccccccc", 18163), kToken, TokenState::Custom));
  Client plantC(kToken, "cccccccccccc");
  const std::string evil = "{\"planId\":\"planted\"}";
  plantC.post(c, a, &clock, 18163, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":0,\"sk\":" + evil + "}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  plantC.post(c, a, &clock, 18163, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":1,\"sk\":{\"planId\":\"planted2\"}}", &status);
  plantC.post(c, a, &clock, 18163, "/plan-skeleton", "{\"room\":\"Raum A\",\"baseRev\":2,\"sk\":{\"planId\":\"planted3\"}}", &status);
  TEST_ASSERT_EQUAL_UINT32(3, c.device.store().find("Raum A")->rev);
  const uint32_t hashA = a.device.store().find("Raum A")->hash;
  for (int i = 0; i < 2400; i++) { a.device.loop(clock); b.device.loop(clock); c.device.loop(clock); clock += 5; usleep(300); } // ~12 s
  TEST_ASSERT_EQUAL_UINT32(1, a.device.store().find("Raum A")->rev);   // never adopted
  TEST_ASSERT_EQUAL_UINT32(hashA, a.device.store().find("Raum A")->hash);
  TEST_ASSERT_EQUAL_UINT32(1, b.device.store().find("Raum A")->rev);
  a.device.end();
  b.device.end();
  c.device.end();
}

void test_setup_push_over_the_network() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  Sink sink;
  sink.tokens.token = kToken;
  sink.tokens.tokenState = TokenState::Custom;
  a.device.setSetupSink(&sink);
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18171), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18172), kToken, TokenState::Custom));
  uint32_t clock = 5000;
  Client c(kToken, "aaaaaaaaaaaa");
  const std::string sec = bodyOf(http(a, b, &clock, 18171, "GET /security.json HTTP/1.1\r\n\r\n"));
  TEST_ASSERT_TRUE(sec.find("\"setup\"") != std::string::npos);                  // advertised only with a sink
  TEST_ASSERT_TRUE(sec.find("\"setupAp\":\"open\"") != std::string::npos);
  TEST_ASSERT_TRUE(bodyOf(http(a, b, &clock, 18172, "GET /security.json HTTP/1.1\r\n\r\n")).find("\"setup\"") == std::string::npos);

  int status = 0;
  std::string r = c.post(a, b, &clock, 18171, "/setup", "{\"ssid\":\"Heimnetz\",\"pass\":\"geheimgeheim\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, sink.applied);
  TEST_ASSERT_TRUE(sink.viaNetwork);                                              // the old Wi-Fi stays as fallback
  TEST_ASSERT_EQUAL_STRING("Heimnetz", sink.last.ssid.c_str());
  // Invalid requests change nothing.
  r = c.post(a, b, &clock, 18171, "/setup", "{\"ssid\":\"x\"}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  r = c.post(a, b, &clock, 18171, "/setup", "{\"token\":\"short\"}", &status);
  TEST_ASSERT_EQUAL_INT(400, status);
  TEST_ASSERT_EQUAL_INT(1, sink.applied);
  // A token change is answered with the OLD keys, then the device runs with the new ones.
  clock += 20000; // refill the rate limit budget used above
  r = c.post(a, b, &clock, 18171, "/setup", "{\"token\":\"a-brand-new-token-1\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_STRING("{\"ok\":true}", r.c_str());
  r = c.post(a, b, &clock, 18171, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(401, status);                                             // old token is gone
  Client renewed("a-brand-new-token-1", "aaaaaaaaaaaa");
  r = renewed.post(a, b, &clock, 18171, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  // Devices without a sink do not know the path at all (older firmware / simulators).
  Client forB(kToken, "bbbbbbbbbbbb");
  forB.post(a, b, &clock, 18172, "/setup", "{\"token\":\"a-brand-new-token-1\"}", &status);
  TEST_ASSERT_EQUAL_INT(404, status);
  a.device.end();
  b.device.end();
}

void test_setup_push_needs_the_edit_token_when_there_is_one() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  Sink sink;
  sink.tokens.token = kToken;
  sink.tokens.tokenState = TokenState::Custom;
  sink.tokens.editToken = kEditToken;
  sink.tokens.editState = EditState::Custom;
  a.device.setSetupSink(&sink);
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18171), kToken, TokenState::Custom, kEditToken, EditState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18172), kToken, TokenState::Custom));
  uint32_t clock = 5000;
  Client normal(kToken, "aaaaaaaaaaaa"), editor(kToken, "aaaaaaaaaaaa", kEditToken);
  int status = 0;
  normal.post(a, b, &clock, 18171, "/setup", "{\"ssid\":\"Heimnetz\",\"pass\":\"geheimgeheim\"}", &status);
  TEST_ASSERT_EQUAL_INT(403, status);
  TEST_ASSERT_EQUAL_INT(0, sink.applied);
  editor.post(a, b, &clock, 18171, "/setup", "{\"editToken\":\"a-second-edit-token-2\"}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  TEST_ASSERT_EQUAL_INT(1, sink.applied);
  // The edit token changed: the old edit keys are dead, the new ones work.
  editor.post(a, b, &clock, 18171, "/plan", "{\"id\":0,\"plan\":null}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(401, status);
  Client renewed(kToken, "aaaaaaaaaaaa", "a-second-edit-token-2");
  renewed.post(a, b, &clock, 18171, "/plan", "{\"id\":0,\"plan\":null}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  // Removing the edit token ("") hands plan sending back to the normal token.
  renewed.post(a, b, &clock, 18171, "/setup", "{\"editToken\":\"\"}", &status, 0, false, KeyRole::Edit);
  TEST_ASSERT_EQUAL_INT(200, status);
  clock += 20000;
  normal.post(a, b, &clock, 18171, "/plan", "{\"id\":0,\"plan\":{\"z\":3}}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  a.device.end();
  b.device.end();
}

void test_setup_network_serves_only_the_portal() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  Sink sink;
  sink.tokens.token = kToken;
  sink.tokens.tokenState = TokenState::Custom;
  a.device.setSetupSink(&sink);
  a.platform.up = false;                      // no Wi-Fi: only the setup network exists
  a.platform.setup = true;
  a.platform.setupClient = 0x7F000001;        // the test plays the phone
  DeviceOptions oa = options("aaaaaaaaaaaa", 18181);
  oa.dnsPort = 18183;
  TEST_ASSERT_TRUE(a.device.begin(oa, kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18182), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  a.device.loop(clock);
  TEST_ASSERT_TRUE(a.device.socketsOpen());   // the HTTP server runs although the station has no address

  // Portal pages
  std::string r = http(a, b, &clock, 18181, "GET /setup HTTP/1.1\r\nHost: 10.99.77.1\r\n\r\n");
  TEST_ASSERT_EQUAL_INT(200, statusOf(r));
  TEST_ASSERT_TRUE(r.find("EscapeSetup-aaaaaaaaaaaa") != std::string::npos);
  TEST_ASSERT_TRUE(r.find("Laser (Raum A)") != std::string::npos);                // names the device
  // Captive-portal probes and the UI path are redirected, the game's data is not reachable.
  const char *probes[] = {"/generate_204", "/hotspot-detect.html", "/connecttest.txt", "/", "/status.json", "/peers.json", "/security.json"};
  for (size_t i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
    r = http(a, b, &clock, 18181, std::string("GET ") + probes[i] + " HTTP/1.1\r\n\r\n");
    TEST_ASSERT_EQUAL_INT_MESSAGE(302, statusOf(r), probes[i]);
    TEST_ASSERT_TRUE_MESSAGE(r.find("Location: http://10.99.77.1/setup\r\n") != std::string::npos, probes[i]);
  }
  Client c(kToken, "aaaaaaaaaaaa");
  int status = 0;
  const std::string poster = "POST /action HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}";
  TEST_ASSERT_EQUAL_INT(404, statusOf(http(a, b, &clock, 18181, poster)));
  TEST_ASSERT_EQUAL_INT(0, a.host.actions);

  // Saving through the form
  const std::string form = "ssid=Heimnetz&pass=geheimgeheim&token=a-brand-new-token-1&edit=";
  r = http(a, b, &clock, 18181, "POST /setup/save HTTP/1.1\r\nContent-Length: " + std::to_string(form.size()) + "\r\n\r\n" + form);
  TEST_ASSERT_EQUAL_INT(200, statusOf(r));
  TEST_ASSERT_EQUAL_INT(1, sink.applied);
  TEST_ASSERT_FALSE(sink.viaNetwork);
  TEST_ASSERT_EQUAL_STRING("Heimnetz", sink.last.ssid.c_str());
  TEST_ASSERT_TRUE(sink.last.hasToken && !sink.last.hasEditToken);
  // The token change took effect without a restart: the next secure request with the new token works,
  // but not from the setup network - it is a LAN request now.
  a.platform.setup = false;
  a.platform.up = true;
  Client renewed("a-brand-new-token-1", "aaaaaaaaaaaa");
  renewed.post(a, b, &clock, 18181, "/action", "{\"id\":0,\"action\":\"open\"}", &status);
  TEST_ASSERT_EQUAL_INT(200, status);
  a.device.end();
  b.device.end();
}

void test_lan_clients_never_reach_the_portal() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  Sink sink;
  a.device.setSetupSink(&sink);
  a.platform.setup = true;                    // the setup network is up AND the station is connected (linger phase)
  a.platform.setupClient = 0x0A000063;        // ... but this test's client (127.0.0.1) is on the LAN
  TEST_ASSERT_TRUE(a.device.begin(options("aaaaaaaaaaaa", 18181), kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18182), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  TEST_ASSERT_EQUAL_INT(200, statusOf(http(a, b, &clock, 18181, "GET /status.json HTTP/1.1\r\n\r\n")));
  TEST_ASSERT_EQUAL_INT(404, statusOf(http(a, b, &clock, 18181, "GET /setup HTTP/1.1\r\n\r\n")));
  TEST_ASSERT_EQUAL_INT(404, statusOf(http(a, b, &clock, 18181, "GET /generate_204 HTTP/1.1\r\n\r\n")));
  const std::string form = "ssid=Evil&pass=";
  TEST_ASSERT_EQUAL_INT(404, statusOf(http(a, b, &clock, 18181, "POST /setup/save HTTP/1.1\r\nContent-Length: " + std::to_string(form.size()) + "\r\n\r\n" + form)));
  TEST_ASSERT_EQUAL_INT(0, sink.applied);
  a.device.end();
  b.device.end();
}

void test_setup_network_dns() {
  Node a("Raum A", "Laser"), b("Raum B", "Kamera");
  Sink sink;
  a.device.setSetupSink(&sink);
  a.platform.up = false;
  a.platform.setup = true;
  a.platform.setupClient = 0x7F000001;
  DeviceOptions oa = options("aaaaaaaaaaaa", 18181);
  oa.dnsPort = 18185;
  TEST_ASSERT_TRUE(a.device.begin(oa, kToken, TokenState::Custom));
  TEST_ASSERT_TRUE(b.device.begin(options("bbbbbbbbbbbb", 18182), kToken, TokenState::Custom));
  uint32_t clock = 1000;
  a.device.loop(clock);
  const uint8_t query[] = {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, 0, 1, 0, 1};
  UdpSocket phone;
  TEST_ASSERT_TRUE(phone.openBroadcast(0));
  uint8_t buf[256];
  int n = 0;
  phone.send(0x7F000001, 18185, query, sizeof(query));
  for (int i = 0; i < 200 && n <= 0; i++) {
    pump(a, b, 10, &clock);
    uint32_t ip;
    uint16_t port;
    n = phone.receive(buf, sizeof(buf), ip, port);
  }
  TEST_ASSERT_EQUAL_INT((int)sizeof(query) + 16, n);
  TEST_ASSERT_EQUAL_UINT8(10, buf[n - 4]);
  TEST_ASSERT_EQUAL_UINT8(99, buf[n - 3]);
  TEST_ASSERT_EQUAL_UINT8(77, buf[n - 2]);
  TEST_ASSERT_EQUAL_UINT8(1, buf[n - 1]);
  // Queries from outside the setup network get no answer; once the network is down the socket is closed.
  a.platform.setupClient = 0x0A000063;
  phone.send(0x7F000001, 18185, query, sizeof(query));
  n = 0;
  for (int i = 0; i < 30 && n <= 0; i++) {
    pump(a, b, 10, &clock);
    uint32_t ip;
    uint16_t port;
    n = phone.receive(buf, sizeof(buf), ip, port);
  }
  TEST_ASSERT_TRUE(n <= 0);
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
  RUN_TEST(test_sockets_wait_for_the_network_and_retry_when_the_port_is_taken);
  RUN_TEST(test_host_hints_are_coalesced_and_verified);
  RUN_TEST(test_everything_works_with_the_clock_just_before_the_32_bit_wrap);
  RUN_TEST(test_edit_token_guards_sending_plans);
  RUN_TEST(test_edit_proof_endpoint);
  RUN_TEST(test_skeleton_sync_with_edit_token_rejects_planted_plans);
  RUN_TEST(test_setup_push_over_the_network);
  RUN_TEST(test_setup_push_needs_the_edit_token_when_there_is_one);
  RUN_TEST(test_setup_network_serves_only_the_portal);
  RUN_TEST(test_lan_clients_never_reach_the_portal);
  RUN_TEST(test_setup_network_dns);
}
