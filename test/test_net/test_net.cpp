// Loopback tests of the socket layer (src/net): HTTP server limits and timeouts, the
// non-blocking client, and UDP. PC only: the same code runs on the ESP32 through lwIP and
// is exercised there by the esp-dummy integration tests.
#include <unity.h>

#include <arpa/inet.h>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <unistd.h>

#include "../../src/net/Clock.hpp"
#include "../../src/net/Net.hpp"
#include "../../src/protocol/EscapeVersion.hpp"

namespace EscapeVersion {
const char *const UI_HASH = "0badc0de"; // no embedded UI in this test
}

using namespace Escape;

void setUp() {}
void tearDown() {}

namespace {

const uint16_t kPort = 18080;

class TestHandler : public HttpHandler {
public:
  TestHandler() : handled(0) { big.assign(200000, 'x'); for (size_t i = 0; i < big.size(); i++) big[i] = (char)('a' + i % 26); }
  RouteInfo route(Method m, const std::string &path) override {
    if (path == "/get" && m == Method::Get) return RouteInfo{true, 0};
    if (path == "/big" && m == Method::Get) return RouteInfo{true, 0};
    if (path == "/post" && m == Method::Post) return RouteInfo{true, 100};
    return RouteInfo{false, 0};
  }
  void handle(const HttpRequest &req, uint32_t, HttpResponse &r) override {
    handled++;
    lastBody = req.body;
    lastOrigin = req.origin;
    r.status = 200;
    r.contentType = "application/json";
    if (req.path == "/big") r.body = big;
    else r.body = "{\"path\":\"" + req.path + "\",\"len\":" + std::to_string(req.body.size()) + "}";
  }
  int handled;
  std::string big, lastBody, lastOrigin;
};

int connectTo(uint16_t port) {
  const int fd = socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(port);
  a.sin_addr.s_addr = htonl(0x7F000001);
  TEST_ASSERT_EQUAL_INT(0, connect(fd, (sockaddr *)&a, sizeof(a)));
  fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
  return fd;
}

// Sends `request` and pumps the server until the peer closes or `maxMs` of real time pass.
std::string exchange(HttpServer &server, const std::string &request, uint32_t maxMs = 3000, size_t chunk = 0) {
  const int fd = connectTo(kPort);
  std::string response;
  size_t sent = 0;
  const uint32_t start = nowMillis();
  while (nowMillis() - start < maxMs) {
    if (sent < request.size()) {
      const size_t want = chunk ? (request.size() - sent < chunk ? request.size() - sent : chunk) : request.size() - sent;
      const ssize_t n = send(fd, request.data() + sent, want, MSG_NOSIGNAL);
      if (n > 0) sent += (size_t)n;
    }
    server.poll(nowMillis(), 5000);
    char buf[4096];
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n > 0) response.append(buf, (size_t)n);
    else if (n == 0) break;
  }
  close(fd);
  return response;
}

std::string body(const std::string &response) {
  const size_t p = response.find("\r\n\r\n");
  return p == std::string::npos ? std::string() : response.substr(p + 4);
}

void test_get_and_post() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  std::string r = exchange(s, "GET /get HTTP/1.1\r\nHost: x\r\nOrigin: http://192.168.1.5\r\n\r\n");
  TEST_ASSERT_TRUE(r.find("HTTP/1.1 200 OK") == 0);
  TEST_ASSERT_EQUAL_STRING("{\"path\":\"/get\",\"len\":0}", body(r).c_str());
  TEST_ASSERT_TRUE(r.find("Access-Control-Allow-Origin: http://192.168.1.5") != std::string::npos);
  TEST_ASSERT_EQUAL_STRING("http://192.168.1.5", h.lastOrigin.c_str());
  r = exchange(s, "POST /post HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello", 3000, 3); // dribbled in 3-byte pieces
  TEST_ASSERT_EQUAL_STRING("{\"path\":\"/post\",\"len\":5}", body(r).c_str());
  TEST_ASSERT_EQUAL_STRING("hello", h.lastBody.c_str());
  r = exchange(s, "HEAD /get HTTP/1.1\r\n\r\n");
  TEST_ASSERT_TRUE(r.find("200 OK") != std::string::npos);
  TEST_ASSERT_TRUE(body(r).empty());
  s.end();
}

void test_rejections() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  TEST_ASSERT_TRUE(exchange(s, "GET /nope HTTP/1.1\r\n\r\n").find("404") != std::string::npos);
  TEST_ASSERT_TRUE(exchange(s, "POST /get HTTP/1.1\r\nContent-Length: 1\r\n\r\nx").find("404") != std::string::npos); // wrong method
  const int before = h.handled;
  // The body limit of the route (100) is enforced from the header alone: no body byte is needed.
  std::string r = exchange(s, "POST /post HTTP/1.1\r\nContent-Length: 101\r\n\r\n");
  TEST_ASSERT_TRUE(r.find("413") != std::string::npos);
  TEST_ASSERT_TRUE(body(r).find("too_large") != std::string::npos);
  TEST_ASSERT_TRUE(exchange(s, "BREW /get HTTP/1.1\r\n\r\n").find("405") != std::string::npos);
  TEST_ASSERT_TRUE(exchange(s, "GET /get HTTP/9.9\r\n\r\n").find("505") != std::string::npos);
  TEST_ASSERT_TRUE(exchange(s, "garbage\r\n\r\n").find("400") != std::string::npos);
  TEST_ASSERT_TRUE(exchange(s, "GET /" + std::string(2000, 'a') + " HTTP/1.1\r\n\r\n").find("431") != std::string::npos);
  TEST_ASSERT_EQUAL_INT(before, h.handled); // none of these reached the handler
  s.end();
}

void test_early_rejection_is_delivered_even_with_unsent_body() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  // The client announces a large body to an unknown route and keeps sending it while the
  // server already answered 404. The answer must arrive intact (no reset in between).
  const int fd = connectTo(kPort);
  const std::string head = "POST /nope HTTP/1.1\r\nContent-Length: 60000\r\n\r\n";
  send(fd, head.data(), head.size(), MSG_NOSIGNAL);
  std::string response;
  size_t sent = 0;
  const std::string chunk(1000, 'x');
  const uint32_t start = nowMillis();
  while (nowMillis() - start < 3000) {
    if (sent < 60000) { const ssize_t n = send(fd, chunk.data(), chunk.size(), MSG_NOSIGNAL); if (n > 0) sent += (size_t)n; }
    s.poll(nowMillis(), 5000);
    char buf[1024];
    const ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n > 0) response.append(buf, (size_t)n);
    else if (n == 0) break;
  }
  close(fd);
  TEST_ASSERT_TRUE(response.find("HTTP/1.1 404") == 0);
  TEST_ASSERT_TRUE(response.find("not_found") != std::string::npos);
  for (int i = 0; i < 5; i++) s.poll(nowMillis() + 3000 * (uint32_t)(i + 1), 5000); // drained connections are released
  TEST_ASSERT_EQUAL_UINT(0, s.activeConnections());
  s.end();
}

void test_back_to_back_rejections_never_get_503() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  // Requests that are rejected before their body arrives leave the connection draining for a
  // moment. A client that fires the next request immediately must still be served.
  for (int round = 0; round < 12; round++) {
    const int fd = connectTo(kPort);
    const std::string head = "POST /nope HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n";
    send(fd, head.data(), head.size(), MSG_NOSIGNAL);
    std::string first;
    for (int i = 0; i < 100 && first.find("404") == std::string::npos; i++) {
      s.poll(nowMillis(), 5000);
      char buf[512];
      const ssize_t n = recv(fd, buf, sizeof(buf), 0);
      if (n > 0) first.append(buf, (size_t)n);
    }
    close(fd); // the client hangs up at once; the server has not noticed yet
    TEST_ASSERT_TRUE(first.find("404") != std::string::npos);
  }
  const std::string r = exchange(s, "GET /get HTTP/1.1\r\n\r\n");
  TEST_ASSERT_TRUE_MESSAGE(r.find("HTTP/1.1 200 OK") == 0, r.c_str());
  s.end();
}

void test_preflight_and_expect_continue() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  std::string r = exchange(s, "OPTIONS /post HTTP/1.1\r\nOrigin: http://escapemanager.local\r\n\r\n");
  TEST_ASSERT_TRUE(r.find("HTTP/1.1 204") == 0);
  TEST_ASSERT_TRUE(r.find("Access-Control-Allow-Methods: GET, POST, OPTIONS") != std::string::npos);
  r = exchange(s, "OPTIONS /post HTTP/1.1\r\nOrigin: http://evil.example\r\n\r\n");
  TEST_ASSERT_TRUE(r.find("Access-Control-Allow-Origin") == std::string::npos);
  r = exchange(s, "POST /post HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nok");
  TEST_ASSERT_TRUE(r.find("HTTP/1.1 100 Continue") == 0);
  TEST_ASSERT_TRUE(r.find("HTTP/1.1 200 OK") != std::string::npos);
  s.end();
}

void test_large_body_arrives_intact() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  const std::string r = exchange(s, "GET /big HTTP/1.1\r\n\r\n", 8000);
  TEST_ASSERT_TRUE(body(r) == h.big);
  s.end();
}

void test_idle_and_slow_connections_are_dropped() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  const int a = connectTo(kPort), b = connectTo(kPort);
  uint32_t fake = nowMillis();
  s.poll(fake, 5000);
  s.poll(fake, 5000);
  TEST_ASSERT_EQUAL_UINT(2, s.activeConnections()); // both slots held by silent (speculative) clients
  // A FRESH silent connection is never evicted: it may just be about to send its request.
  const int fresh = connectTo(kPort);
  const std::string quick = "GET /get HTTP/1.1\r\n\r\n";
  send(fresh, quick.data(), quick.size(), MSG_NOSIGNAL);
  std::string early0;
  for (int i = 0; i < 20; i++) { s.poll(fake, 5000); char b0[256]; const ssize_t n0 = recv(fresh, b0, sizeof(b0), 0); if (n0 > 0) early0.append(b0, (size_t)n0); usleep(1000); }
  TEST_ASSERT_TRUE(early0.empty());          // waits in the backlog, still no reset or error
  TEST_ASSERT_EQUAL_UINT(2, s.activeConnections());
  close(fresh);
  // Once the silent ones have been idle for the grace period, a real request evicts the oldest of them.
  fake += EscapeConfig::HTTP_EVICT_SILENT_AFTER_MS + 100;
  const int c = connectTo(kPort);
  const std::string request = "GET /get HTTP/1.1\r\n\r\n";
  send(c, request.data(), request.size(), MSG_NOSIGNAL);
  std::string answer;
  for (int i = 0; i < 100 && answer.find("200 OK") == std::string::npos; i++) {
    s.poll(fake, 5000);
    char buf[512];
    const ssize_t n = recv(c, buf, sizeof(buf), 0);
    if (n > 0) answer.append(buf, (size_t)n);
    usleep(1000);
  }
  TEST_ASSERT_TRUE(answer.find("200 OK") != std::string::npos);
  // ... but connections that DID send something are never evicted: with both slots busy with real
  // (partial) requests the newcomer is NOT answered with an error; it waits in the listen backlog.
  close(a); close(b); close(c);
  for (int i = 0; i < 5; i++) s.poll(fake, 5000);
  const int d1 = connectTo(kPort), d2 = connectTo(kPort);
  send(d1, "GET /ge", 7, MSG_NOSIGNAL);
  send(d2, "GET /ge", 7, MSG_NOSIGNAL);
  for (int i = 0; i < 10; i++) { s.poll(fake, 5000); usleep(1000); }
  const int e = connectTo(kPort);
  send(e, request.data(), request.size(), MSG_NOSIGNAL);
  std::string early;
  for (int i = 0; i < 40; i++) {
    s.poll(fake, 5000);
    char buf[256];
    const ssize_t n = recv(e, buf, sizeof(buf), 0);
    if (n > 0) early.append(buf, (size_t)n);
    usleep(1000);
  }
  TEST_ASSERT_TRUE(early.empty());                      // no 503, no reset: it is simply waiting
  TEST_ASSERT_EQUAL_UINT(2, s.activeConnections());
  // The partial requests finish (the clients hang up): the waiting request is served.
  close(d1); close(d2);
  std::string served;
  for (int i = 0; i < 200 && served.find("200 OK") == std::string::npos; i++) {
    s.poll(fake, 5000);
    char buf[512];
    const ssize_t n = recv(e, buf, sizeof(buf), 0);
    if (n > 0) served.append(buf, (size_t)n);
    usleep(1000);
  }
  TEST_ASSERT_TRUE(served.find("200 OK") != std::string::npos);
  close(e);
  fake += EscapeConfig::HTTP_IDLE_TIMEOUT_MS + 100; // time passes without a byte: slots are freed
  s.poll(fake, 5000);
  s.poll(fake, 5000);
  TEST_ASSERT_EQUAL_UINT(0, s.activeConnections());
  // slowloris: one byte per interval never completes within the request timeout
  const int d = connectTo(kPort);
  fake = nowMillis();
  s.poll(fake, 5000);
  for (int i = 0; i < 12; i++) {
    send(d, "G", 1, MSG_NOSIGNAL);
    fake += 1500;
    s.poll(fake, 5000);
  }
  s.poll(fake, 5000);
  TEST_ASSERT_EQUAL_UINT(0, s.activeConnections());
  close(d);
  s.end();
}

void test_poll_respects_budget_and_survives_resets() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  for (int i = 0; i < 20; i++) { // clients that connect and vanish
    const int fd = connectTo(kPort);
    send(fd, "GET /ge", 7, MSG_NOSIGNAL);
    close(fd);
    s.poll(nowMillis(), 5000);
    s.poll(nowMillis(), 5000);
  }
  TEST_ASSERT_EQUAL_UINT(0, s.activeConnections());
  const uint32_t t0 = nowMicros();
  for (int i = 0; i < 200; i++) s.poll(nowMillis(), 2000);
  TEST_ASSERT_TRUE(nowMicros() - t0 < 200000); // an idle server costs almost nothing per call
  s.end();
}

void test_client_get() {
  TestHandler h;
  HttpServer s;
  TEST_ASSERT_TRUE(s.begin(kPort, &h));
  HttpClient c;
  TEST_ASSERT_TRUE(c.begin(0x7F000001, kPort, "/get?x=1", nowMillis(), 3000, 1000));
  for (int i = 0; i < 2000 && !c.finished(); i++) { s.poll(nowMillis(), 5000); c.poll(nowMillis()); usleep(500); }
  TEST_ASSERT_TRUE(c.state() == HttpClient::State::Done);
  TEST_ASSERT_EQUAL_INT(200, c.status());
  TEST_ASSERT_EQUAL_STRING("{\"path\":\"/get\",\"len\":0}", c.body().c_str());
  // body larger than the caller's limit is refused, not buffered
  TEST_ASSERT_TRUE(c.begin(0x7F000001, kPort, "/big", nowMillis(), 3000, 1000));
  for (int i = 0; i < 2000 && !c.finished(); i++) { s.poll(nowMillis(), 5000); c.poll(nowMillis()); usleep(500); }
  TEST_ASSERT_TRUE(c.state() == HttpClient::State::Failed);
  TEST_ASSERT_TRUE(c.body().size() <= 1000 + 1024);
  TEST_ASSERT_TRUE(c.begin(0x7F000001, kPort, "/big", nowMillis(), 3000, 300000));
  for (int i = 0; i < 4000 && !c.finished(); i++) { s.poll(nowMillis(), 5000); c.poll(nowMillis()); usleep(500); }
  TEST_ASSERT_TRUE(c.state() == HttpClient::State::Done);
  TEST_ASSERT_TRUE(c.body() == h.big);
  s.end();
  // nobody listening: fails instead of hanging
  TEST_ASSERT_TRUE(c.begin(0x7F000001, kPort, "/get", nowMillis(), 500, 1000) || c.state() == HttpClient::State::Failed);
  for (int i = 0; i < 100 && !c.finished(); i++) { c.poll(nowMillis()); usleep(1000); }
  TEST_ASSERT_TRUE(c.state() == HttpClient::State::Failed);
}

void test_client_deadline_on_silent_server() {
  const int lfd = socket(AF_INET, SOCK_STREAM, 0); // accepts but never answers
  const int on = 1;
  setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_port = htons(kPort);
  a.sin_addr.s_addr = htonl(0x7F000001);
  TEST_ASSERT_EQUAL_INT(0, bind(lfd, (sockaddr *)&a, sizeof(a)));
  listen(lfd, 1);
  HttpClient c;
  uint32_t fake = nowMillis();
  TEST_ASSERT_TRUE(c.begin(0x7F000001, kPort, "/get", fake, 2000, 1000));
  for (int i = 0; i < 20; i++) { c.poll(fake); usleep(1000); }
  TEST_ASSERT_TRUE(c.busy());
  fake += 2500; // deadline passes
  c.poll(fake);
  TEST_ASSERT_TRUE(c.state() == HttpClient::State::Failed);
  close(lfd);
}

void test_udp_unicast_and_broadcast() {
  UdpSocket a, b;
  TEST_ASSERT_TRUE(a.openBroadcast(14210));
  TEST_ASSERT_TRUE(b.openBroadcast(14210));
  uint8_t buf[64];
  uint32_t ip = 0;
  uint16_t port = 0;
  TEST_ASSERT_EQUAL_INT(0, a.receive(buf, sizeof(buf), ip, port)); // nothing pending, non-blocking
  const uint8_t msg[] = "hello";
  TEST_ASSERT_TRUE(a.send(0x7F000001, 14210, msg, sizeof(msg)));
  int got = 0;
  for (int i = 0; i < 50 && got == 0; i++) {
    got = a.receive(buf, sizeof(buf), ip, port);
    if (got == 0) got = b.receive(buf, sizeof(buf), ip, port);
    usleep(1000);
  }
  TEST_ASSERT_EQUAL_INT((int)sizeof(msg), got);
  TEST_ASSERT_EQUAL_UINT32(0x7F000001u, ip);
  TEST_ASSERT_TRUE(a.send(0x7FFFFFFF, 14210, msg, sizeof(msg))); // loopback broadcast address
  int receivers = 0;
  for (int i = 0; i < 50 && receivers < 2; i++) {
    if (a.receive(buf, sizeof(buf), ip, port) > 0) receivers++;
    if (b.receive(buf, sizeof(buf), ip, port) > 0) receivers++;
    usleep(1000);
  }
  TEST_ASSERT_EQUAL_INT(2, receivers); // every listener on the port hears a broadcast
  a.close();
  TEST_ASSERT_FALSE(a.isOpen());
  TEST_ASSERT_EQUAL_INT(-1, a.receive(buf, sizeof(buf), ip, port));
}

} // namespace

void runDeviceTests();

int main(int, char **) {
  UNITY_BEGIN();
  RUN_TEST(test_get_and_post);
  RUN_TEST(test_rejections);
  RUN_TEST(test_early_rejection_is_delivered_even_with_unsent_body);
  RUN_TEST(test_back_to_back_rejections_never_get_503);
  RUN_TEST(test_preflight_and_expect_continue);
  RUN_TEST(test_large_body_arrives_intact);
  RUN_TEST(test_idle_and_slow_connections_are_dropped);
  RUN_TEST(test_poll_respects_budget_and_survives_resets);
  RUN_TEST(test_client_get);
  RUN_TEST(test_client_deadline_on_silent_server);
  RUN_TEST(test_udp_unicast_and_broadcast);
  runDeviceTests();
  return UNITY_END();
}
