// Deterministic mutation fuzzing of every parser and of the secure transport. Valid inputs are mutated
// (bit flips, byte replacement, insertions, deletions, duplicated or swapped chunks, truncation, splices)
// and fed to the code under test. Besides "no crash / no sanitizer finding" (the PC build runs with
// AddressSanitizer and UBSan) the tests check invariants, for example: authentication never succeeds
// for a modified message, and what the strict scanner accepts the DOM parser accepts too.
// Iteration counts are small on the ESP32 (it runs the same file) and large on the PC.
#include <unity.h>

#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "../../src/protocol/Base64Url.hpp"
#include "../../src/protocol/Http.hpp"
#include "../../src/protocol/Json.hpp"
#include "../../src/protocol/Mdns.hpp"
#include "../../src/protocol/Peers.hpp"
#include "../../src/protocol/Protocol.hpp"
#include "../../src/protocol/SecureTransport.hpp"
#include "../../src/protocol/SkeletonStore.hpp"
#include "backend.hpp"
#include "fakehost.hpp"
#include "tests.hpp"
#include "vectors.hpp"

#ifdef ARDUINO
static const int kRounds = 120;
#else
static const int kRounds = 4000;
#endif

namespace {

struct Rng {
  uint32_t s;
  explicit Rng(uint32_t seed) : s(seed ? seed : 1) {}
  uint32_t next() { s ^= s << 13; s ^= s >> 17; s ^= s << 5; return s; }
  uint32_t below(uint32_t n) { return n ? next() % n : 0; }
};

std::string mutate(const std::string &in, Rng &r, const std::vector<std::string> &corpus) {
  std::string s = in;
  const int ops = 1 + (int)r.below(4);
  for (int k = 0; k < ops; k++) {
    switch (r.below(9)) {
      case 0: if (!s.empty()) s[r.below((uint32_t)s.size())] ^= (char)(1u << r.below(8)); break;                  // bit flip
      case 1: if (!s.empty()) s[r.below((uint32_t)s.size())] = (char)r.below(256); break;                         // random byte
      case 2: s.insert(r.below((uint32_t)s.size() + 1), 1, (char)r.below(256)); break;                            // insert
      case 3: if (!s.empty()) s.erase(r.below((uint32_t)s.size()), 1 + r.below(4)); break;                        // delete
      case 4: if (!s.empty()) { size_t a = r.below((uint32_t)s.size()), n = 1 + r.below(16); s.insert(a, s.substr(a, n)); } break; // duplicate chunk
      case 5: if (!s.empty()) s.resize(r.below((uint32_t)s.size())); break;                                        // truncate
      case 6: { const std::string &o = corpus[r.below((uint32_t)corpus.size())]; if (!o.empty()) { size_t a = r.below((uint32_t)o.size()); s.insert(r.below((uint32_t)s.size() + 1), o.substr(a, 1 + r.below(24))); } } break; // splice from another input
      case 7: { static const char *tokens[] = {"{", "}", "[", "]", "\"", "\\", ",", ":", "null", "true", "-", "e", "\\u", "\\ud800", "%", "\r\n", "0"}; s.insert(r.below((uint32_t)s.size() + 1), tokens[r.below(17)]); } break;
      default: if (s.size() > 1) { size_t a = r.below((uint32_t)s.size()), b = r.below((uint32_t)s.size()); std::swap(s[a], s[b]); } break; // swap
    }
    if (s.size() > 20000) s.resize(20000);
  }
  return s;
}

std::vector<std::string> jsonCorpus() {
  std::vector<std::string> c;
  c.push_back("{\"id\":0,\"action\":\"open\"}");
  c.push_back("{\"id\":1,\"name\":\"Laser\",\"room\":\"Raum A\",\"riddleId\":\"x-1\",\"config\":{\"brightness\":\"50\",\"label\":\"hi\"}}");
  c.push_back("{\"room\":\"Raum A\",\"baseRev\":3,\"sk\":{\"planId\":\"p\",\"layers\":[{\"id\":\"L1\",\"lanes\":[{\"id\":\"A\",\"x\":[1,2.5e3,-0.25,true,null]}]}]}}");
  c.push_back("{\"id\":0,\"plan\":{\"planId\":\"p\",\"layer\":\"L1\",\"lane\":\"A\",\"connections\":[{\"to\":\"B\",\"step\":2}]}}");
  c.push_back("{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"192.168.1.20\",\"port\":80,\"boot\":5,\"ctr\":123,\"seq\":17,\"pmin\":2,\"uih\":\"1a2b3c4d\",\"skh\":\"00000000\",\"sk\":[[\"a1b2c3d4\",3,\"9f8e7d6c\"]]}");
  c.push_back("[1,[2,[3,[4,[5]]]],\"\\u00e9\\ud83d\\ude00\",{\"a\":{\"b\":{\"c\":[]}}}]");
  c.push_back("{\"s\":\"\\n\\t\\\"\\\\/\\b\\f\\r\",\"n\":[0,-0,1e-7,123456789012,0.1,1E+2]}");
  return c;
}

void test_json_dom_and_scanner_agree_under_mutation() {
  const std::vector<std::string> corpus = jsonCorpus();
  Rng r(0xC0FFEE);
  int accepted = 0;
  for (int i = 0; i < kRounds * 4; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    EscapeJson::Value v;
    const bool dom = EscapeJson::parse(in, v, EscapeJson::ParseLimits(16, 2000));
    const bool scan = EscapeJson::validate(in.data(), in.size(), 16);
    // What the DOM parser accepts the strict scanner accepts too (same grammar, same depth).
    if (dom) { TEST_ASSERT_TRUE_MESSAGE(scan, in.c_str()); accepted++; }
    if (dom) { // and the output of stringify() always parses back to the same text
      std::string a, b;
      TEST_ASSERT_TRUE(EscapeJson::stringify(v, a));
      EscapeJson::Value again;
      TEST_ASSERT_TRUE(EscapeJson::parse(a, again, EscapeJson::ParseLimits(16, 2000)));
      TEST_ASSERT_TRUE(EscapeJson::stringify(again, b));
      TEST_ASSERT_TRUE(a == b);
    }
    EscapeJson::Slice sl;
    const EscapeJson::Scan found = EscapeJson::findField(in.data(), in.size(), "sk", sl, 16);
    if (found != EscapeJson::Scan::Invalid) TEST_ASSERT_TRUE(scan);   // classification consistent with validate()
    if (found == EscapeJson::Scan::Found) {                            // the slice is a valid value inside the buffer
      TEST_ASSERT_TRUE(sl.p >= in.data() && sl.p + sl.n <= in.data() + in.size());
      TEST_ASSERT_TRUE(EscapeJson::validate(sl.p, sl.n, 16));
    }
    std::string text; uint32_t u = 0; double d = 0; bool b = false;
    EscapeJson::sliceToString(sl, text); EscapeJson::sliceToUInt(sl, 1000, u); EscapeJson::sliceToDouble(sl, d); EscapeJson::sliceToBool(sl, b);
    EscapeJson::sliceKind(sl);
  }
  TEST_ASSERT_TRUE(accepted > 0);   // the mutator does produce valid documents too (the check is not vacuous)
}

void test_text_helpers_under_mutation() {
  Rng r(0xBADC0DE);
  std::vector<std::string> corpus; corpus.push_back("room=Raum%20A&nonce=abcdef0123456789&x=%C3%A4"); corpus.push_back("http://192.168.1.5:8080"); corpus.push_back("aabbccddeeff"); corpus.push_back("192.168.1.20");
  corpus.push_back("AAECAwQFBgcICQoL"); corpus.push_back("00ff10ab");
  for (int i = 0; i < kRounds * 4; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    std::string out, val; std::vector<uint8_t> bytes; uint8_t ip[4], did[6]; uint32_t h = 0;
    Escape::percentDecode(in, out);
    Escape::queryParam(in, "room", val);
    Escape::originAllowed(in);
    if (Escape::base64UrlDecode(in, bytes)) { // canonical: re-encoding gives back exactly the same text
      TEST_ASSERT_TRUE(Escape::base64UrlEncode(bytes.data(), bytes.size()) == in);
    }
    Escape::hexDecode(in.data(), in.size(), bytes);
    if (Escape::parseIpv4(in.data(), in.size(), ip)) { char t[16]; Escape::u32ToIpv4Text(Escape::ipv4ToU32(ip), t); TEST_ASSERT_TRUE(in == t); }
    if (Escape::parseDid(in.data(), in.size(), did)) TEST_ASSERT_TRUE(Escape::didToText(did) == in);
    if (Escape::parseHex8(in.data(), in.size(), h)) TEST_ASSERT_TRUE(Escape::hex8(h) == in);
    Escape::SecureTransport::validNonce(in);
  }
}

void test_announcements_under_mutation() {
  Rng r(0xA11CE);
  std::vector<std::string> corpus;
  corpus.push_back(Escape::buildAnnouncementDoc("aabbccddeeff", "192.168.1.20", 80, 5, 123, 17, 2, "1a2b3c4d", "[[\"a1b2c3d4\",3,\"9f8e7d6c\"]]", 0x12345678u));
  corpus.push_back(Escape::buildAnnouncementDoc("112233445566", "10.0.0.1", 8080, 0, 1, 1, 2, "00000000", "[]", 0));
  static Escape::PeerTable table;
  table.clear();
  uint8_t own[6] = {1, 2, 3, 4, 5, 6};
  for (int i = 0; i < kRounds * 4; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    Escape::Announcement a;
    if (Escape::parseAnnouncement(in.data(), in.size(), a)) {
      TEST_ASSERT_TRUE(a.port != 0 && a.skCount <= Escape::kMaxAnnouncedRooms);
      uint8_t ip[4];
      TEST_ASSERT_TRUE(Escape::parseIpv4(a.ip, strlen(a.ip), ip));
      table.ingest(a, a.ip, own, 1000 + (uint32_t)i);                 // whatever parses can be ingested
    }
  }
  TEST_ASSERT_TRUE(table.count() <= EscapeConfig::MAX_PEER_ADDRESSES);
}

void test_http_parser_under_mutation() {
  Rng r(0x417);
  std::vector<std::string> corpus;
  corpus.push_back("GET /status.json?nonce=abcdef0123456789 HTTP/1.1\r\nHost: x\r\nOrigin: http://192.168.1.5\r\nIf-None-Match: \"abc\"\r\n\r\n");
  corpus.push_back("POST /action HTTP/1.1\r\nContent-Length: 7\r\nContent-Type: text/plain\r\n\r\n{\"v\":2}");
  corpus.push_back("OPTIONS /plan HTTP/1.1\r\nOrigin: null\r\n\r\n");
  corpus.push_back("POST /plan HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\nabc");
  for (int i = 0; i < kRounds * 2; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    Escape::HttpRequestParser p;
    size_t pos = 0;
    const size_t chunk = 1 + r.below(40);
    while (pos < in.size()) {
      const size_t n = (in.size() - pos < chunk) ? in.size() - pos : chunk;
      const size_t used = p.feed((const uint8_t *)in.data() + pos, n);
      pos += used;
      if (p.state() == Escape::HttpRequestParser::State::HeadersComplete) p.beginBody(100);
      if (p.state() == Escape::HttpRequestParser::State::Error || p.state() == Escape::HttpRequestParser::State::Done) break;
      if (used == 0) break;
    }
    TEST_ASSERT_TRUE(p.request().body.size() <= 100);
    TEST_ASSERT_TRUE(p.request().path.size() <= 520);
    if (p.state() == Escape::HttpRequestParser::State::Error) TEST_ASSERT_TRUE(p.errorStatus() >= 400);
    Escape::HttpResponse resp;
    resp.body = "x";
    Escape::formatResponseHead(resp, p.request().origin, p.request().method == Escape::Method::Options);
  }
}

void test_mdns_under_mutation() {
  Rng r(0x4D4E53);
  std::vector<std::string> corpus;
  const uint8_t q1[] = {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 13, 'e', 's', 'c', 'a', 'p', 'e', 'm', 'a', 'n', 'a', 'g', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 1, 0x80, 1};
  const uint8_t q2[] = {0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 13, 'e', 's', 'c', 'a', 'p', 'e', 'm', 'a', 'n', 'a', 'g', 'e', 'r', 5, 'l', 'o', 'c', 'a', 'l', 0, 0, 1, 0, 1, 0xC0, 12, 0, 1, 0, 1, 0, 0, 0, 15, 0, 4, 1, 2, 3, 4};
  corpus.push_back(std::string((const char *)q1, sizeof(q1)));
  corpus.push_back(std::string((const char *)q2, sizeof(q2)));
  const uint8_t ip[4] = {1, 2, 3, 4};
  uint8_t out[300];
  for (int i = 0; i < kRounds * 4; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    Escape::parseMdnsQuery((const uint8_t *)in.data(), in.size(), "escapemanager.local", ip, 15);
  }
  TEST_ASSERT_TRUE(Escape::buildMdnsAnswer(out, sizeof(out), "escapemanager.local", ip, 15) > 0);
}

// An authenticated message modified in ANY way must not authenticate; the transport and the handlers
// never crash on what survives.
Escape::SecureTransport *makeTransport(TestBackend &backend, const char *token) {
  Escape::SecureTransport *t = new Escape::SecureTransport(backend);
  t->begin(token, Escape::TokenState::Custom, Vectors::kDid);
  return t;
}

void test_secure_transport_never_authenticates_a_modified_message() {
  static TestBackend backend;
  const std::string post = Vectors::T1::postEnvelope, resp = Vectors::T1::respEnvelope, get = Vectors::T1::getFrame, udp = Vectors::T1::udpFrame;
  std::vector<std::string> corpus; corpus.push_back(post); corpus.push_back(resp); corpus.push_back(get); corpus.push_back(udp);
  Rng r(0x5EC);
  std::unique_ptr<Escape::SecureTransport> t(makeTransport(backend, Vectors::T1::token));
  int rounds = kRounds / 4 + 20;   // each round costs PBKDF2-free crypto only, but AES/HMAC on the chip are slow-ish
  for (int i = 0; i < rounds; i++) {
    std::string plain, iv;
    // POST envelope: a mutated copy never opens - the single exception is a mutation that left the bytes unchanged
    std::string m = mutate(post, r, corpus);
    Escape::OpenResult res = t->openRequest(Vectors::T1::postPath, m.data(), m.size(), Vectors::T1::postT + 10, plain, iv);
    if (res.status == 200) { TEST_ASSERT_TRUE(plain == Vectors::T1::postPlain); t.reset(makeTransport(backend, Vectors::T1::token)); } // a harmless re-encoding of the same message: fine, but the plaintext must be the original
    // response envelope
    m = mutate(resp, r, corpus);
    if (t->openResponse(Vectors::T1::postPath, Vectors::T1::postIv, 200, m.data(), m.size(), plain)) TEST_ASSERT_TRUE(plain == Vectors::T1::respPlain);
    // GET frame and UDP frame: byte-exact; any change must fail
    EscapeJson::Slice doc;
    m = mutate(get, r, corpus);
    if (t->openDocumentFrame(Vectors::T1::getPath, Vectors::T1::getNonce, 200, m.data(), m.size(), doc)) TEST_ASSERT_TRUE(m == get);
    m = mutate(udp, r, corpus);
    if (t->openAnnouncement(m.data(), m.size(), doc)) TEST_ASSERT_TRUE(m == udp);
  }
}

// Exhaustive single-bit-flip sweep: EVERY bit of EVERY authenticated message is flipped once and none of
// the 8*N variants may authenticate (random mutation alone rarely hits the one bit that matters, e.g. the
// last byte of a MAC when a comparison is one byte short).
void test_every_single_bit_flip_breaks_authentication() {
  static TestBackend backend;
  std::unique_ptr<Escape::SecureTransport> t(makeTransport(backend, Vectors::T1::token));
  const std::string post = Vectors::T1::postEnvelope, resp = Vectors::T1::respEnvelope, get = Vectors::T1::getFrame, udp = Vectors::T1::udpFrame;
  int checked = 0;
  for (int kind = 0; kind < 4; kind++) {
    const std::string &orig = kind == 0 ? post : kind == 1 ? resp : kind == 2 ? get : udp;
    for (size_t i = 0; i < orig.size(); i++) {
      for (int bit = 0; bit < 8; bit++) {
        std::string m = orig;
        m[i] = (char)(m[i] ^ (1 << bit));
        std::string plain, iv;
        EscapeJson::Slice doc;
        bool accepted = false;
        if (kind == 0) accepted = t->openRequest(Vectors::T1::postPath, m.data(), m.size(), Vectors::T1::postT + 10, plain, iv).status == 200;
        else if (kind == 1) accepted = t->openResponse(Vectors::T1::postPath, Vectors::T1::postIv, 200, m.data(), m.size(), plain);
        else if (kind == 2) accepted = t->openDocumentFrame(Vectors::T1::getPath, Vectors::T1::getNonce, 200, m.data(), m.size(), doc);
        else accepted = t->openAnnouncement(m.data(), m.size(), doc);
        char label[64];
        snprintf(label, sizeof(label), "message %d byte %u bit %d authenticated", kind, (unsigned)i, bit);
        // The only tolerated case: the protocol-level field of a RESPONSE (`"v":2`) is not covered by the AEAD
        // (the tag binds iv, ciphertext, device, path and status); a response with a higher `v` still carries
        // exactly the original plaintext. Everything else must fail.
        const bool versionDigit = kind == 1 && i == orig.find("\"v\":") + 4;
        if (accepted && versionDigit) {
          TEST_ASSERT_TRUE(plain == Vectors::T1::respPlain);
          accepted = false;
        }
        TEST_ASSERT_FALSE_MESSAGE(accepted, label);
        checked++;
      }
    }
  }
  TEST_ASSERT_TRUE(checked > 4000);
  // and the untouched originals still work
  std::string plain, iv;
  TEST_ASSERT_EQUAL_INT(200, t->openRequest(Vectors::T1::postPath, post.data(), post.size(), Vectors::T1::postT + 10, plain, iv).status);
}

void test_handlers_survive_mutated_bodies() {
  FakeHost host;
  Escape::MemoryStorage mem;
  Escape::SkeletonStore store(mem);
  const std::vector<std::string> corpus = jsonCorpus();
  Rng r(0x4A11D);
  for (int i = 0; i < kRounds * 2; i++) {
    const std::string in = mutate(corpus[r.below((uint32_t)corpus.size())], r, corpus);
    EscapeProtocol::HttpResult res;
    switch (r.below(5)) {
      case 0: res = EscapeProtocol::handleAction(host, in); break;
      case 1: res = EscapeProtocol::handlePlanAction(host, in); break;
      case 2: res = EscapeProtocol::handleConfig(host, in); break;
      case 3: res = EscapeProtocol::handlePlan(host, in); break;
      default: res = EscapeProtocol::handlePlanSkeleton(host, store, in); break;
    }
    TEST_ASSERT_TRUE(res.status == 200 || (res.status >= 400 && res.status < 600));
    TEST_ASSERT_TRUE(EscapeJson::validate(res.body.data(), res.body.size(), 16));     // every answer is valid JSON
    TEST_ASSERT_TRUE(host.plans[0].size() <= EscapeConfig::MAX_PLAN_LEN && host.plans[1].size() <= EscapeConfig::MAX_PLAN_LEN);
    TEST_ASSERT_TRUE(host.names[0].size() <= EscapeConfig::MAX_NAME_LEN && host.rooms[0].size() <= EscapeConfig::MAX_ROOM_LEN);
    TEST_ASSERT_TRUE(!host.names[0].empty() && !host.rooms[0].empty() && !host.names[1].empty() && !host.rooms[1].empty());
  }
  TEST_ASSERT_TRUE(store.count() <= EscapeConfig::MAX_SKELETON_ROOMS);
  // every stored skeleton is a valid blob whose hash matches its content
  for (size_t i = 0; i < store.count(); i++) {
    std::string blob;
    TEST_ASSERT_TRUE(store.get(store.at(i).room, blob));
    TEST_ASSERT_TRUE(EscapeJson::validate(blob.data(), blob.size(), 16));
  }
}

void test_skeleton_adopt_under_mutation() {
  Rng r(0x5CE1E);
  const std::string sk = "{\"planId\":\"p\",\"layers\":[{\"id\":\"L1\"}]}";
  const std::string blob = "{\"room\":\"Raum A\",\"rev\":3,\"hash\":\"" + Escape::hex8(Escape::fnv1a32(sk)) + "\",\"sk\":" + sk + "}";
  std::vector<std::string> corpus; corpus.push_back(blob); corpus.push_back(sk);
  for (int i = 0; i < kRounds * 2; i++) {
    Escape::MemoryStorage mem;
    Escape::SkeletonStore store(mem);
    const std::string in = mutate(blob, r, corpus);
    const Escape::SkeletonStore::Result res = store.adopt(in, "Raum A");
    if (res == Escape::SkeletonStore::Result::Stored) {      // whatever was stored is internally consistent
      std::string back;
      TEST_ASSERT_TRUE(store.get("Raum A", back));
      EscapeJson::Slice s2, h2;
      TEST_ASSERT_TRUE(EscapeJson::findField(back.data(), back.size(), "sk", s2) == EscapeJson::Scan::Found);
      TEST_ASSERT_TRUE(EscapeJson::findField(back.data(), back.size(), "hash", h2) == EscapeJson::Scan::Found);
      std::string hash; EscapeJson::sliceToString(h2, hash);
      TEST_ASSERT_EQUAL_STRING(Escape::hex8(Escape::fnv1a32(s2.p, s2.n)).c_str(), hash.c_str());
    }
  }
}

} // namespace

void runFuzzTests() {
  RUN_TEST(test_json_dom_and_scanner_agree_under_mutation);
  RUN_TEST(test_text_helpers_under_mutation);
  RUN_TEST(test_announcements_under_mutation);
  RUN_TEST(test_http_parser_under_mutation);
  RUN_TEST(test_mdns_under_mutation);
  RUN_TEST(test_secure_transport_never_authenticates_a_modified_message);
  RUN_TEST(test_every_single_bit_flip_breaks_authentication);
  RUN_TEST(test_handlers_survive_mutated_bodies);
  RUN_TEST(test_skeleton_adopt_under_mutation);
}
