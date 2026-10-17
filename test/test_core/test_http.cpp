#include <unity.h>
#include <cstring>
#include <string>
#include <vector>

#include "../../src/protocol/Http.hpp"
#include "../../src/protocol/Mdns.hpp"
#include "../../src/protocol/RateLimiter.hpp"
#include "tests.hpp"

using namespace Escape;

namespace {

// Feeds `text` in chunks of `chunk` bytes and drives the parser like a server would.
HttpRequestParser::State drive(HttpRequestParser &p, const std::string &text, size_t chunk, size_t maxBody) {
  size_t pos = 0;
  while (pos < text.size()) {
    const size_t n = (text.size() - pos < chunk) ? text.size() - pos : chunk;
    size_t used = p.feed((const uint8_t *)text.data() + pos, n);
    size_t offset = pos + used;
    // After a stop the remaining bytes of this chunk are offered again.
    if (p.state() == HttpRequestParser::State::HeadersComplete) {
      p.beginBody(maxBody);
      used += p.feed((const uint8_t *)text.data() + offset, n - used);
    }
    if (p.state() == HttpRequestParser::State::Error || p.state() == HttpRequestParser::State::Done) return p.state();
    pos += used == 0 ? n : used;
  }
  return p.state();
}

void test_parse_get() {
  HttpRequestParser p;
  const std::string req = "GET /status.json?nonce=abc&x=1 HTTP/1.1\r\nHost: escapemanager.local\r\nOrigin: http://escapemanager.local\r\nIf-None-Match: \"abc\"\r\n\r\n";
  TEST_ASSERT_TRUE(drive(p, req, req.size(), 0) == HttpRequestParser::State::Done);
  TEST_ASSERT_TRUE(p.request().method == Method::Get);
  TEST_ASSERT_EQUAL_STRING("/status.json", p.request().path.c_str());
  TEST_ASSERT_EQUAL_STRING("nonce=abc&x=1", p.request().query.c_str());
  TEST_ASSERT_EQUAL_STRING("http://escapemanager.local", p.request().origin.c_str());
  TEST_ASSERT_EQUAL_STRING("\"abc\"", p.request().ifNoneMatch.c_str());
}

void test_parse_post_byte_by_byte() {
  const std::string body = "{\"v\":2}";
  const std::string req = "POST /action HTTP/1.1\r\ncontent-length: " + std::to_string(body.size()) + "\r\nContent-Type: text/plain\r\n\r\n" + body;
  for (size_t chunk = 1; chunk <= 7; chunk += 3) {
    HttpRequestParser p;
    TEST_ASSERT_TRUE(drive(p, req, chunk, 100) == HttpRequestParser::State::Done);
    TEST_ASSERT_EQUAL_STRING(body.c_str(), p.request().body.c_str());
    TEST_ASSERT_TRUE(p.request().method == Method::Post);
  }
}

void test_pipelined_bytes_are_not_consumed() {
  HttpRequestParser p;
  const std::string req = "GET / HTTP/1.1\r\n\r\nGET /second HTTP/1.1\r\n\r\n";
  size_t used = p.feed((const uint8_t *)req.data(), req.size());
  TEST_ASSERT_TRUE(p.state() == HttpRequestParser::State::HeadersComplete);
  TEST_ASSERT_EQUAL_UINT(strlen("GET / HTTP/1.1\r\n\r\n"), used);
}

void expectError(const std::string &req, int status, size_t maxBody = 100) {
  HttpRequestParser p;
  TEST_ASSERT_TRUE_MESSAGE(drive(p, req, req.size(), maxBody) == HttpRequestParser::State::Error, req.c_str());
  TEST_ASSERT_EQUAL_INT_MESSAGE(status, p.errorStatus(), req.c_str());
}

void test_parse_errors() {
  expectError("BREW / HTTP/1.1\r\n\r\n", 405);
  expectError("GET / HTTP/2.0\r\n\r\n", 505);
  expectError("GET /\r\n\r\n", 400);
  expectError("GET noslash HTTP/1.1\r\n\r\n", 400);
  expectError("GET /a b HTTP/1.1\r\n\r\n", 400);
  expectError("GET / HTTP/1.1\r\nBadHeader\r\n\r\n", 400);
  expectError("GET / HTTP/1.1\r\n folded: x\r\n\r\n", 400);
  expectError("POST / HTTP/1.1\r\nContent-Length: abc\r\n\r\n", 400);
  expectError("POST / HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n", 400);
  expectError("POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n", 501);
  expectError("POST /x HTTP/1.1\r\nContent-Length: 101\r\n\r\n", 413, 100);       // over the route's limit, before buffering
  expectError("POST /x HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n", 400);   // absurd length text
  expectError("GET /x HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd", 400);          // GET with a body
  expectError("GET /" + std::string(600, 'a') + " HTTP/1.1\r\n\r\n", 414);
  expectError("GET / HTTP/1.1\r\nX: " + std::string(EscapeConfig::MAX_HEADER_BYTES, 'a') + "\r\n\r\n", 431);
}

void test_expect_continue() {
  HttpRequestParser p;
  const std::string req = "POST /plan HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n";
  p.feed((const uint8_t *)req.data(), req.size());
  TEST_ASSERT_TRUE(p.state() == HttpRequestParser::State::HeadersComplete);
  TEST_ASSERT_TRUE(p.request().expectContinue);
}

void test_hostile_input_never_grows_unbounded() {
  uint32_t seed = 12345;
  for (int round = 0; round < 300; round++) {
    HttpRequestParser p;
    std::string junk;
    const size_t n = 200 + (size_t)(seed % 3000);
    for (size_t i = 0; i < n; i++) {
      seed = seed * 1664525u + 1013904223u;
      junk.push_back((char)(seed >> 24));
    }
    if (round % 3 == 0) junk = "GET /" + junk;
    if (round % 3 == 1) junk = "POST / HTTP/1.1\r\nContent-Length: 50\r\n\r\n" + junk;
    size_t pos = 0;
    while (pos < junk.size()) {
      const size_t used = p.feed((const uint8_t *)junk.data() + pos, junk.size() - pos);
      pos += used;
      if (p.state() == HttpRequestParser::State::HeadersComplete) p.beginBody(100);
      if (p.state() == HttpRequestParser::State::Error || p.state() == HttpRequestParser::State::Done) break;
      if (used == 0) break;
    }
    TEST_ASSERT_TRUE(p.request().body.size() <= 50);
  }
}

void test_query_and_percent_decoding() {
  std::string v;
  TEST_ASSERT_TRUE(queryParam("room=Raum%20A&nonce=x", "room", v));
  TEST_ASSERT_EQUAL_STRING("Raum A", v.c_str());
  TEST_ASSERT_TRUE(queryParam("room=K%C3%A4fig%2FX", "room", v));
  TEST_ASSERT_EQUAL_STRING("K\xc3\xa4" "fig/X", v.c_str());
  TEST_ASSERT_TRUE(queryParam("a=1&room=a+b", "room", v));
  TEST_ASSERT_EQUAL_STRING("a+b", v.c_str()); // '+' stays literal
  TEST_ASSERT_TRUE(queryParam("flag", "flag", v));
  TEST_ASSERT_TRUE(v.empty());
  TEST_ASSERT_FALSE(queryParam("a=1", "room", v));
  TEST_ASSERT_FALSE(queryParam("room=%zz", "room", v));
  TEST_ASSERT_FALSE(queryParam("room=%4", "room", v));
  TEST_ASSERT_FALSE(queryParam("", "room", v));
}

void test_cors_policy() {
  const char *allowed[] = {"null", "http://localhost", "http://localhost:8080", "http://127.0.0.1:8080", "http://escapemanager.local",
                           "https://x.local:81", "http://192.168.1.20", "http://10.1.2.3", "http://172.16.0.1", "http://172.31.255.255",
                           "http://169.254.1.1", "http://[::1]:80"};
  for (size_t i = 0; i < sizeof(allowed) / sizeof(allowed[0]); i++) TEST_ASSERT_TRUE_MESSAGE(originAllowed(allowed[i]), allowed[i]);
  const char *denied[] = {"", "http://evil.example", "https://github.com", "http://172.32.0.1", "http://172.15.0.1", "http://192.169.1.1",
                          "http://8.8.8.8", "http://localhost.evil.com", "http://evil.local.com", "ftp://192.168.1.1", "http://192.168.1.1.evil.com",
                          "http://", "http://192.168.1", "javascript:alert(1)", "http://[fe80::1]", "http://a b.local"};
  for (size_t i = 0; i < sizeof(denied) / sizeof(denied[0]); i++) TEST_ASSERT_FALSE_MESSAGE(originAllowed(denied[i]), denied[i]);
}

void test_response_head() {
  HttpResponse r;
  r.status = 200;
  r.contentType = "application/json";
  r.body = "{\"a\":1}";
  std::string h = formatResponseHead(r, "http://192.168.1.5", false);
  TEST_ASSERT_TRUE(h.find("HTTP/1.1 200 OK\r\n") == 0);
  TEST_ASSERT_TRUE(h.find("Content-Length: 7\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("Connection: close\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("Access-Control-Allow-Origin: http://192.168.1.5\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("Cache-Control: no-store") != std::string::npos);
  TEST_ASSERT_TRUE(h.size() >= 4 && h.substr(h.size() - 4) == "\r\n\r\n");
  h = formatResponseHead(r, "http://evil.example", false);
  TEST_ASSERT_TRUE(h.find("Access-Control-Allow-Origin") == std::string::npos);
  h = formatResponseHead(r, "", false);
  TEST_ASSERT_TRUE(h.find("Access-Control-Allow-Origin") == std::string::npos);
  HttpResponse ui;
  ui.contentType = "text/html; charset=utf-8";
  static const uint8_t blob[3] = {1, 2, 3};
  ui.staticBody = blob;
  ui.staticLength = 3;
  ui.gzip = true;
  ui.etag = "1a2b3c4d";
  h = formatResponseHead(ui, "", false);
  TEST_ASSERT_TRUE(h.find("Content-Encoding: gzip\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("ETag: \"1a2b3c4d\"\r\n") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("Cache-Control: no-cache") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("Content-Length: 3\r\n") != std::string::npos);
  HttpResponse pre;
  pre.status = 204;
  h = formatResponseHead(pre, "null", true);
  TEST_ASSERT_TRUE(h.find("Access-Control-Allow-Methods: GET, POST, OPTIONS") != std::string::npos);
  TEST_ASSERT_TRUE(h.find("HTTP/1.1 204 No Content") == 0);
}

// ---- mDNS -----------------------------------------------------------------------------

std::vector<uint8_t> makeQuery(const char *name, uint16_t qtype, uint16_t qclass, bool withKnownAnswer, const uint8_t *knownIp, uint32_t knownTtl) {
  std::vector<uint8_t> p = {0, 0, 0, 0, 0, 1, 0, (uint8_t)(withKnownAnswer ? 1 : 0), 0, 0, 0, 0};
  std::vector<uint8_t> enc;
  const char *l = name;
  while (*l) {
    const char *dot = strchr(l, '.');
    size_t len = dot ? (size_t)(dot - l) : strlen(l);
    enc.push_back((uint8_t)len);
    enc.insert(enc.end(), l, l + len);
    l += len;
    if (*l == '.') l++;
  }
  enc.push_back(0);
  p.insert(p.end(), enc.begin(), enc.end());
  p.push_back(qtype >> 8); p.push_back(qtype & 0xFF); p.push_back(qclass >> 8); p.push_back(qclass & 0xFF);
  if (withKnownAnswer) {
    p.push_back(0xC0); p.push_back(12); // compression pointer to the question name
    p.push_back(0); p.push_back(1); p.push_back(0); p.push_back(1);
    p.push_back(knownTtl >> 24); p.push_back(knownTtl >> 16); p.push_back(knownTtl >> 8); p.push_back(knownTtl);
    p.push_back(0); p.push_back(4);
    p.insert(p.end(), knownIp, knownIp + 4);
  }
  return p;
}

void test_mdns_answer_bytes() {
  const uint8_t ip[4] = {192, 168, 1, 7};
  uint8_t out[128];
  const size_t n = buildMdnsAnswer(out, sizeof(out), "escapemanager.local", ip, 15);
  const uint8_t expected[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0,
                              13, 'e', 's', 'c', 'a', 'p', 'e', 'm', 'a', 'n', 'a', 'g', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0,
                              0, 1, 0, 1,        // A, IN - cache-flush bit NOT set
                              0, 0, 0, 15, 0, 4, 192, 168, 1, 7};
  TEST_ASSERT_EQUAL_UINT(sizeof(expected), n);
  TEST_ASSERT_EQUAL_MEMORY(expected, out, sizeof(expected));
  TEST_ASSERT_EQUAL_UINT(0, buildMdnsAnswer(out, 20, "escapemanager.local", ip, 15)); // too small
}

void test_mdns_query_matching() {
  const uint8_t ip[4] = {192, 168, 1, 7}, other[4] = {192, 168, 1, 8};
  const char *host = "escapemanager.local";
  MdnsQuery q = parseMdnsQuery(makeQuery("escapemanager.local", 1, 1, false, nullptr, 0).data(), makeQuery("escapemanager.local", 1, 1, false, nullptr, 0).size(), host, ip, 15);
  TEST_ASSERT_TRUE(q.matches);
  TEST_ASSERT_FALSE(q.unicast);
  TEST_ASSERT_FALSE(q.suppressed);
  std::vector<uint8_t> p = makeQuery("EscapeManager.LOCAL", 255, 0x8001, false, nullptr, 0); // case-insensitive, ANY, QU bit
  q = parseMdnsQuery(p.data(), p.size(), host, ip, 15);
  TEST_ASSERT_TRUE(q.matches);
  TEST_ASSERT_TRUE(q.unicast);
  p = makeQuery("other.local", 1, 1, false, nullptr, 0);
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).matches);
  p = makeQuery("escapemanager.local", 28, 1, false, nullptr, 0); // AAAA is not answered
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).matches);
  p = makeQuery("escapemanager.localx", 1, 1, false, nullptr, 0);
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).matches);
  p = makeQuery("manager.local", 1, 1, false, nullptr, 0);
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).matches);
  p = makeQuery("escapemanager.local", 1, 1, true, ip, 15); // known answer with our address and fresh TTL
  q = parseMdnsQuery(p.data(), p.size(), host, ip, 15);
  TEST_ASSERT_TRUE(q.matches);
  TEST_ASSERT_TRUE(q.suppressed);
  p = makeQuery("escapemanager.local", 1, 1, true, ip, 5);   // TTL below half: still answer
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).suppressed);
  p = makeQuery("escapemanager.local", 1, 1, true, other, 15); // another device's address: still answer
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).suppressed);
}

void test_mdns_rejects_garbage() {
  const uint8_t ip[4] = {1, 2, 3, 4};
  const char *host = "escapemanager.local";
  std::vector<uint8_t> p = makeQuery("escapemanager.local", 1, 1, false, nullptr, 0);
  p[2] |= 0x80; // a response, not a query
  TEST_ASSERT_FALSE(parseMdnsQuery(p.data(), p.size(), host, ip, 15).matches);
  p = makeQuery("escapemanager.local", 1, 1, false, nullptr, 0);
  for (size_t cut = 0; cut < p.size(); cut++) parseMdnsQuery(p.data(), cut, host, ip, 15); // truncations never crash
  std::vector<uint8_t> loop = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0xC0, 12, 0, 1, 0, 1}; // pointer to itself
  TEST_ASSERT_FALSE(parseMdnsQuery(loop.data(), loop.size(), host, ip, 15).matches);
  std::vector<uint8_t> huge(1600, 0);
  TEST_ASSERT_FALSE(parseMdnsQuery(huge.data(), huge.size(), host, ip, 15).matches);
  uint32_t seed = 7;
  for (int round = 0; round < 2000; round++) {
    std::vector<uint8_t> junk(12 + (size_t)(seed % 120));
    for (size_t i = 0; i < junk.size(); i++) { seed = seed * 1664525u + 1013904223u; junk[i] = (uint8_t)(seed >> 24); }
    junk[2] &= 0x7F;
    parseMdnsQuery(junk.data(), junk.size(), host, ip, 15);
  }
  TEST_ASSERT_TRUE(mdnsResponseDelayMs(0) == 20);
  TEST_ASSERT_TRUE(mdnsResponseDelayMs(0xFFFFFFFFu) >= 20 && mdnsResponseDelayMs(0xFFFFFFFFu) <= 120);
}

// ---- Rate limiter ----------------------------------------------------------------------

void test_rate_limiter() {
  RateLimiter rl;
  uint32_t now = 1000;
  int allowed = 0;
  for (int i = 0; i < 50; i++) allowed += rl.allowSource(0x0A000001u, now) ? 1 : 0;
  TEST_ASSERT_EQUAL_INT(EscapeConfig::RATE_BURST, allowed); // burst, then blocked
  TEST_ASSERT_TRUE(rl.allowSource(0x0A000002u, now));        // another source is unaffected
  now += EscapeConfig::RATE_REFILL_MS * 3;
  allowed = 0;
  for (int i = 0; i < 10; i++) allowed += rl.allowSource(0x0A000001u, now) ? 1 : 0;
  TEST_ASSERT_EQUAL_INT(3, allowed);                          // refilled slowly
  RateLimiter many;
  for (uint32_t s = 0; s < 100; s++) many.allowSource(s + 1, 5000); // more sources than slots: no crash, LRU reuse
  TEST_ASSERT_TRUE(many.allowSource(1000, 5000));
  RateLimiter g;
  int ok = 0;
  for (int i = 0; i < 100; i++) ok += g.allowGlobal(10000) ? 1 : 0;
  TEST_ASSERT_EQUAL_INT(EscapeConfig::GLOBAL_POSTS_PER_SECOND, ok);
  TEST_ASSERT_TRUE(g.allowGlobal(11001)); // next second
  RateLimiter w;
  for (int i = 0; i < 10; i++) w.allowSource(1, 0xFFFFFFF0u);
  TEST_ASSERT_TRUE(w.allowSource(1, 0xFFFFFFF0u + 100 * EscapeConfig::RATE_REFILL_MS)); // across the clock wrap
}

} // namespace

void runHttpTests() {
  RUN_TEST(test_parse_get);
  RUN_TEST(test_parse_post_byte_by_byte);
  RUN_TEST(test_pipelined_bytes_are_not_consumed);
  RUN_TEST(test_parse_errors);
  RUN_TEST(test_expect_continue);
  RUN_TEST(test_hostile_input_never_grows_unbounded);
  RUN_TEST(test_query_and_percent_decoding);
  RUN_TEST(test_cors_policy);
  RUN_TEST(test_response_head);
  RUN_TEST(test_mdns_answer_bytes);
  RUN_TEST(test_mdns_query_matching);
  RUN_TEST(test_mdns_rejects_garbage);
  RUN_TEST(test_rate_limiter);
}
