#include <unity.h>
#include <cstring>
#include <string>
#include <vector>

#include "../../src/protocol/Base64Url.hpp"
#include "../../src/protocol/SecureTransport.hpp"
#include "backend.hpp"
#include "tests.hpp"
#include "vectors.hpp"

using namespace Escape;

namespace {

TestBackend g_backend;

struct Vec {
  const char *token, *master, *kReq, *kResp, *kMac, *postPath, *postIv, *postPlain, *postEnvelope, *respIv,
      *respPlain, *respEnvelope, *getPath, *getNonce, *getDoc, *getFrame, *udpDoc, *udpFrame;
  unsigned postT;
};

#define VEC_FROM(ns)                                                                                            \
  { ns::token, ns::master, ns::kReq, ns::kResp, ns::kMac, ns::postPath, ns::postIv, ns::postPlain,             \
    ns::postEnvelope, ns::respIv, ns::respPlain, ns::respEnvelope, ns::getPath, ns::getNonce, ns::getDoc,       \
    ns::getFrame, ns::udpDoc, ns::udpFrame, ns::postT }

const Vec kVectors[2] = {VEC_FROM(Vectors::T0), VEC_FROM(Vectors::T1)};

std::string hexOf(const uint8_t *p, size_t n) {
  std::string s;
  hexEncode(p, n, s);
  return s;
}

void beginWith(SecureTransport &t, const Vec &v, const char *did = Vectors::kDid) {
  TEST_ASSERT_TRUE(t.begin(v.token, TokenState::Custom, did));
  TEST_ASSERT_TRUE(t.writable());
}

void test_hkdf_rfc5869() {
  std::vector<uint8_t> ikm, salt, info, okm;
  hexDecode(Vectors::kHkdfIkm, strlen(Vectors::kHkdfIkm), ikm);
  hexDecode(Vectors::kHkdfSalt, strlen(Vectors::kHkdfSalt), salt);
  hexDecode(Vectors::kHkdfInfo, strlen(Vectors::kHkdfInfo), info);
  uint8_t out[42];
  TEST_ASSERT_TRUE(hkdfSha256(g_backend, ikm.data(), ikm.size(), salt.data(), salt.size(), info.data(), info.size(), out, 42));
  TEST_ASSERT_EQUAL_STRING(Vectors::kHkdfOkm, hexOf(out, 42).c_str());
  TEST_ASSERT_FALSE(hkdfSha256(g_backend, ikm.data(), ikm.size(), nullptr, 0, nullptr, 0, out, 255 * 32 + 1));
}

void test_key_schedule_matches_vectors() {
  for (int i = 0; i < 2; i++) {
    DerivedKeys k;
    TEST_ASSERT_TRUE(SecureTransport::deriveKeys(g_backend, kVectors[i].token, k));
    TEST_ASSERT_EQUAL_STRING(kVectors[i].master, hexOf(k.master, 32).c_str());
    TEST_ASSERT_EQUAL_STRING(kVectors[i].kReq, hexOf(k.req, 32).c_str());
    TEST_ASSERT_EQUAL_STRING(kVectors[i].kResp, hexOf(k.resp, 32).c_str());
    TEST_ASSERT_EQUAL_STRING(kVectors[i].kMac, hexOf(k.mac, 32).c_str());
  }
}

void test_hmac_parts_equal_one_shot() {
  const uint8_t key[3] = {1, 2, 3};
  const char *msg = "hello world";
  uint8_t a[32], b[32];
  ByteRange whole[1] = {{(const uint8_t *)msg, 11}};
  ByteRange split[3] = {{(const uint8_t *)msg, 3}, {(const uint8_t *)msg + 3, 0}, {(const uint8_t *)msg + 3, 8}};
  TEST_ASSERT_TRUE(g_backend.hmacSha256(key, 3, whole, 1, a));
  TEST_ASSERT_TRUE(g_backend.hmacSha256(key, 3, split, 3, b));
  TEST_ASSERT_EQUAL_MEMORY(a, b, 32);
}

void test_gcm_roundtrip_and_tamper() {
  uint8_t key[32], iv[12], tag[16];
  for (int i = 0; i < 32; i++) key[i] = (uint8_t)i;
  for (int i = 0; i < 12; i++) iv[i] = (uint8_t)(100 + i);
  const char *aad = "context";
  std::vector<uint8_t> buf(5000);
  for (size_t i = 0; i < buf.size(); i++) buf[i] = (uint8_t)(i * 7);
  const std::vector<uint8_t> plain = buf;
  TEST_ASSERT_TRUE(g_backend.aes256GcmEncrypt(key, iv, (const uint8_t *)aad, 7, buf.data(), buf.size(), buf.data(), tag)); // in place
  TEST_ASSERT_TRUE(buf != plain);
  std::vector<uint8_t> dec(buf.size());
  TEST_ASSERT_TRUE(g_backend.aes256GcmDecrypt(key, iv, (const uint8_t *)aad, 7, buf.data(), buf.size(), tag, dec.data()));
  TEST_ASSERT_TRUE(dec == plain);
  uint8_t badTag[16];
  memcpy(badTag, tag, 16);
  badTag[0] ^= 1;
  TEST_ASSERT_FALSE(g_backend.aes256GcmDecrypt(key, iv, (const uint8_t *)aad, 7, buf.data(), buf.size(), badTag, dec.data()));
  for (size_t i = 0; i < dec.size(); i++) TEST_ASSERT_EQUAL_UINT8(0, dec[i]); // no unverified plaintext released
  TEST_ASSERT_FALSE(g_backend.aes256GcmDecrypt(key, iv, (const uint8_t *)"other", 5, buf.data(), buf.size(), tag, dec.data()));
}

void test_open_request_vector() {
  for (int i = 0; i < 2; i++) {
    const Vec &v = kVectors[i];
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::string plain, iv;
    const std::string env = v.postEnvelope;
    OpenResult r = t.openRequest(v.postPath, env.data(), env.size(), v.postT + 1000, plain, iv);
    TEST_ASSERT_EQUAL_INT(200, r.status);
    TEST_ASSERT_NULL(r.code);
    TEST_ASSERT_EQUAL_STRING(v.postPlain, plain.c_str());
    TEST_ASSERT_EQUAL_STRING(v.postIv, iv.c_str());
    // The very same envelope again is a replay.
    r = t.openRequest(v.postPath, env.data(), env.size(), v.postT + 1500, plain, iv);
    TEST_ASSERT_EQUAL_INT(409, r.status);
    TEST_ASSERT_EQUAL_STRING("replay", r.code);
    TEST_ASSERT_TRUE(plain.empty());
  }
}

void test_seal_request_matches_vector() {
  for (int i = 0; i < 2; i++) {
    const Vec &v = kVectors[i];
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::vector<uint8_t> iv;
    hexDecode("000102030405060708090a0b", 24, iv);
    std::string env;
    TEST_ASSERT_TRUE(t.sealRequest(v.postPath, v.postT, v.postPlain, iv.data(), env));
    TEST_ASSERT_EQUAL_STRING(v.postEnvelope, env.c_str()); // byte-identical to the Node reference
  }
}

void test_request_rejections() {
  const Vec &v = kVectors[0];
  const std::string env = v.postEnvelope;
  std::string plain, iv;
  {
    SecureTransport t(g_backend);
    beginWith(t, v);
    OpenResult r = t.openRequest(v.postPath, env.data(), env.size(), v.postT + 15001, plain, iv);
    TEST_ASSERT_EQUAL_INT(409, r.status);
    TEST_ASSERT_EQUAL_STRING("stale_time", r.code);
    TEST_ASSERT_EQUAL_STRING(v.postIv, iv.c_str()); // readable, so the error can be answered authenticated
    r = t.openRequest(v.postPath, env.data(), env.size(), v.postT - 15001, plain, iv);
    TEST_ASSERT_EQUAL_STRING("stale_time", r.code);
    r = t.openRequest(v.postPath, env.data(), env.size(), v.postT + 15000, plain, iv);
    TEST_ASSERT_EQUAL_INT(200, r.status); // exactly at the edge is still accepted
  }
  {
    SecureTransport t(g_backend);
    beginWith(t, v);
    OpenResult r = t.openRequest("/config", env.data(), env.size(), v.postT, plain, iv); // path is bound
    TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
    TEST_ASSERT_EQUAL_INT(401, r.status);
    TEST_ASSERT_EQUAL_UINT(0, t.replayEntries(v.postT)); // failures never enter the cache
  }
  {
    SecureTransport t(g_backend);
    beginWith(t, v, "112233445566"); // device id is bound
    OpenResult r = t.openRequest(v.postPath, env.data(), env.size(), v.postT, plain, iv);
    TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
  }
  {
    SecureTransport t(g_backend);
    beginWith(t, kVectors[1]); // other token
    OpenResult r = t.openRequest(v.postPath, env.data(), env.size(), v.postT, plain, iv);
    TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
  }
  {
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::string tampered = env;
    const size_t pos = tampered.find("\"ct\":\"") + 8;
    tampered[pos] = tampered[pos] == 'A' ? 'B' : 'A';
    OpenResult r = t.openRequest(v.postPath, tampered.data(), tampered.size(), v.postT, plain, iv);
    TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
    std::string moved = env;
    moved.replace(moved.find("\"t\":123456"), 10, "\"t\":123457"); // t is authenticated too
    r = t.openRequest(v.postPath, moved.data(), moved.size(), v.postT, plain, iv);
    TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
  }
  {
    SecureTransport t(g_backend);
    beginWith(t, v);
    const char *bad[] = {"", "{}", "[]", "garbage", "{\"v\":2}", "{\"v\":1,\"t\":1,\"iv\":\"AAECAwQFBgcICQoL\",\"ct\":\"AAAAAAAAAAAAAAAAAAAAAA\"}",
                         "{\"v\":3,\"t\":1,\"iv\":\"AAECAwQFBgcICQoL\",\"ct\":\"AAAAAAAAAAAAAAAAAAAAAA\"}",
                         "{\"v\":2,\"t\":-1,\"iv\":\"AAECAwQFBgcICQoL\",\"ct\":\"AAAAAAAAAAAAAAAAAAAAAA\"}",
                         "{\"v\":2,\"t\":1,\"iv\":\"AAEC\",\"ct\":\"AAAAAAAAAAAAAAAAAAAAAA\"}",
                         "{\"v\":2,\"t\":0,\"iv\":\"AAECAwQFBgcICQoL\",\"ct\":\"AAAA\"}"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
      OpenResult r = t.openRequest("/action", bad[i], strlen(bad[i]), 0, plain, iv);
      TEST_ASSERT_EQUAL_INT_MESSAGE(400, r.status, bad[i]);
      TEST_ASSERT_EQUAL_STRING_MESSAGE("bad_envelope", r.code, bad[i]);
    }
    std::string huge(EscapeConfig::MAX_BODY_BYTES + 1, 'x');
    OpenResult r = t.openRequest("/action", huge.data(), huge.size(), 0, plain, iv);
    TEST_ASSERT_EQUAL_INT(413, r.status);
  }
}

void test_read_only_states() {
  SecureTransport t(g_backend);
  TEST_ASSERT_TRUE(t.begin("", TokenState::Invalid, Vectors::kDid));
  TEST_ASSERT_FALSE(t.writable());
  TEST_ASSERT_TRUE(t.tokenState() == TokenState::Invalid);
  std::string plain, iv;
  const std::string env = kVectors[0].postEnvelope;
  OpenResult r = t.openRequest("/action", env.data(), env.size(), kVectors[0].postT, plain, iv);
  TEST_ASSERT_EQUAL_INT(503, r.status);
  TEST_ASSERT_EQUAL_STRING("read_only", r.code);
  TEST_ASSERT_TRUE(iv.empty());
  std::string out;
  TEST_ASSERT_FALSE(t.frameDocument("/status.json", "0123456789abcdef", 200, "{}", out));
  SecureTransport shortToken(g_backend);
  TEST_ASSERT_FALSE(shortToken.begin("short", TokenState::Custom, Vectors::kDid)); // < 8 chars
  TEST_ASSERT_FALSE(shortToken.writable());
}

void test_response_envelopes() {
  for (int i = 0; i < 2; i++) {
    const Vec &v = kVectors[i];
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::string plain;
    const std::string env = v.respEnvelope;
    TEST_ASSERT_TRUE(t.openResponse(v.postPath, v.postIv, 200, env.data(), env.size(), plain));
    TEST_ASSERT_EQUAL_STRING(v.respPlain, plain.c_str());
    TEST_ASSERT_FALSE(t.openResponse(v.postPath, v.postIv, 409, env.data(), env.size(), plain));   // status bound
    TEST_ASSERT_FALSE(t.openResponse("/config", v.postIv, 200, env.data(), env.size(), plain));    // path bound
    TEST_ASSERT_FALSE(t.openResponse(v.postPath, "AAAAAAAAAAAAAAAA", 200, env.data(), env.size(), plain)); // request bound
    std::string sealed;
    TEST_ASSERT_TRUE(t.sealResponse("/plan", "AAECAwQFBgcICQoL", 409, "{\"ok\":false,\"code\":\"rev_conflict\"}", sealed));
    TEST_ASSERT_TRUE(t.openResponse("/plan", "AAECAwQFBgcICQoL", 409, sealed.data(), sealed.size(), plain));
    TEST_ASSERT_EQUAL_STRING("{\"ok\":false,\"code\":\"rev_conflict\"}", plain.c_str());
    std::string sealed2;
    t.sealResponse("/plan", "AAECAwQFBgcICQoL", 409, "{\"ok\":false,\"code\":\"rev_conflict\"}", sealed2);
    TEST_ASSERT_TRUE(sealed != sealed2); // fresh random IV every time
  }
}

void test_document_frames() {
  for (int i = 0; i < 2; i++) {
    const Vec &v = kVectors[i];
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::string frame;
    TEST_ASSERT_TRUE(t.frameDocument(v.getPath, v.getNonce, 200, v.getDoc, frame));
    TEST_ASSERT_EQUAL_STRING(v.getFrame, frame.c_str()); // byte-identical to the Node reference
    EscapeJson::Slice doc;
    TEST_ASSERT_TRUE(t.openDocumentFrame(v.getPath, v.getNonce, 200, frame.data(), frame.size(), doc));
    TEST_ASSERT_EQUAL_STRING(v.getDoc, doc.str().c_str());
    TEST_ASSERT_TRUE(doc.p >= frame.data() && doc.p + doc.n <= frame.data() + frame.size()); // zero-copy slice
    TEST_ASSERT_FALSE(t.openDocumentFrame(v.getPath, "0123456789abcdefXYZ", 200, frame.data(), frame.size(), doc));
    TEST_ASSERT_FALSE(t.openDocumentFrame(v.getPath, v.getNonce, 404, frame.data(), frame.size(), doc));
    TEST_ASSERT_FALSE(t.openDocumentFrame("/peers.json", v.getNonce, 200, frame.data(), frame.size(), doc));
    std::string tampered = frame;
    tampered[tampered.find("\"seq\":17") + 7] = '8';
    TEST_ASSERT_FALSE(t.openDocumentFrame(v.getPath, v.getNonce, 200, tampered.data(), tampered.size(), doc));
    std::string truncated = frame.substr(0, frame.size() - 3);
    TEST_ASSERT_FALSE(t.openDocumentFrame(v.getPath, v.getNonce, 200, truncated.data(), truncated.size(), doc));
    TEST_ASSERT_FALSE(t.openDocumentFrame(v.getPath, v.getNonce, 200, "{}", 2, doc));
    SecureTransport other(g_backend);
    beginWith(other, v, "112233445566"); // frames are bound to the device id
    TEST_ASSERT_FALSE(other.openDocumentFrame(v.getPath, v.getNonce, 200, frame.data(), frame.size(), doc));
    TEST_ASSERT_FALSE(t.frameDocument(v.getPath, "short", 200, v.getDoc, frame));   // nonce rules
    TEST_ASSERT_FALSE(t.frameDocument(v.getPath, "0123456789abcdef!", 200, v.getDoc, frame));
  }
}

void test_announcement_frames() {
  for (int i = 0; i < 2; i++) {
    const Vec &v = kVectors[i];
    SecureTransport t(g_backend);
    beginWith(t, v);
    std::string frame;
    TEST_ASSERT_TRUE(t.frameAnnouncement(v.udpDoc, frame));
    TEST_ASSERT_EQUAL_STRING(v.udpFrame, frame.c_str());
    EscapeJson::Slice doc;
    TEST_ASSERT_TRUE(t.openAnnouncement(frame.data(), frame.size(), doc));
    TEST_ASSERT_EQUAL_STRING(v.udpDoc, doc.str().c_str());
    std::string tampered = frame;
    tampered[tampered.find("\"ctr\":123") + 8] = '4';
    TEST_ASSERT_FALSE(t.openAnnouncement(tampered.data(), tampered.size(), doc));
    // A GET frame must not be accepted as an announcement (different MAC domain).
    std::string get;
    t.frameDocument("/status.json", "0123456789abcdef", 200, v.udpDoc, get);
    TEST_ASSERT_FALSE(t.openAnnouncement(get.data(), get.size(), doc));
  }
}

void test_replay_cache_is_bounded_and_fails_closed() {
  const Vec &v = kVectors[0];
  SecureTransport t(g_backend);
  beginWith(t, v);
  const uint32_t now = 1000000;
  std::string plain, iv;
  for (size_t i = 0; i < EscapeConfig::REPLAY_CACHE_SIZE; i++) {
    uint8_t ivBytes[12];
    for (int k = 0; k < 12; k++) ivBytes[k] = (uint8_t)(i * 3 + k + 1);
    std::string env;
    TEST_ASSERT_TRUE(t.sealRequest("/action", now, "{\"id\":0,\"action\":\"x\"}", ivBytes, env));
    OpenResult r = t.openRequest("/action", env.data(), env.size(), now, plain, iv);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, r.status, "fill");
  }
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::REPLAY_CACHE_SIZE, t.replayEntries(now));
  uint8_t extra[12] = {99, 98, 97, 96, 95, 94, 93, 92, 91, 90, 89, 88};
  std::string env;
  t.sealRequest("/action", now, "{}", extra, env);
  OpenResult r = t.openRequest("/action", env.data(), env.size(), now, plain, iv);
  TEST_ASSERT_EQUAL_INT(429, r.status);
  TEST_ASSERT_EQUAL_STRING("rate_limited", r.code);
  // Once the time window of the oldest requests has passed, capacity returns - and
  // old IVs still cannot be replayed because their `t` is now outside the window.
  const uint32_t later = now + EscapeConfig::TIME_WINDOW_MS + 1;
  t.sealRequest("/action", later, "{}", extra, env);
  r = t.openRequest("/action", env.data(), env.size(), later, plain, iv);
  TEST_ASSERT_EQUAL_INT(200, r.status);
  uint8_t first[12];
  for (int k = 0; k < 12; k++) first[k] = (uint8_t)(0 * 3 + k + 1);
  t.sealRequest("/action", now, "{\"id\":0,\"action\":\"x\"}", first, env);
  r = t.openRequest("/action", env.data(), env.size(), later, plain, iv);
  TEST_ASSERT_EQUAL_STRING("stale_time", r.code);
}

void test_clock_wraparound() {
  // Device clock is a uint32 millisecond counter that wraps after 49.7 days.
  const Vec &v = kVectors[0];
  SecureTransport t(g_backend);
  beginWith(t, v);
  uint8_t ivBytes[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  std::string env, plain, iv;
  const uint32_t tSent = 0xFFFFFF00u; // just before the wrap
  t.sealRequest("/action", tSent, "{}", ivBytes, env);
  OpenResult r = t.openRequest("/action", env.data(), env.size(), 5000u, plain, iv); // clock already wrapped
  TEST_ASSERT_EQUAL_INT(200, r.status);
  uint8_t iv2[12] = {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
  t.sealRequest("/action", 4000u, "{}", iv2, env);
  r = t.openRequest("/action", env.data(), env.size(), 0xFFFFFF00u, plain, iv);
  TEST_ASSERT_EQUAL_INT(200, r.status);
}

// ---- Plan-edit token (PROTOCOL.md 3.1) ---------------------------------------------------------------

void beginWithEdit(SecureTransport &t) {
  TEST_ASSERT_TRUE(t.begin(Vectors::Edit::normalToken, TokenState::Custom, Vectors::kDid, Vectors::Edit::editToken, EditState::Custom));
  TEST_ASSERT_TRUE(t.writable());
  TEST_ASSERT_TRUE(t.editReady());
}

void test_edit_key_schedule_matches_vectors() {
  DerivedKeys k;
  TEST_ASSERT_TRUE(SecureTransport::deriveKeys(g_backend, Vectors::Edit::editToken, k, true));
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::master, hexOf(k.master, 32).c_str());
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::kReq, hexOf(k.req, 32).c_str());
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::kResp, hexOf(k.resp, 32).c_str());
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::kMac, hexOf(k.mac, 32).c_str());
  // The salt separates the two key sets: the same text as normal token gives other keys.
  DerivedKeys same;
  TEST_ASSERT_TRUE(SecureTransport::deriveKeys(g_backend, Vectors::Edit::editToken, same, false));
  TEST_ASSERT_TRUE(memcmp(same.master, k.master, 32) != 0);
}

void test_edit_envelope_vectors() {
  SecureTransport t(g_backend);
  beginWithEdit(t);
  std::string plain, iv;
  const std::string env = Vectors::Edit::postEnvelope;
  OpenResult r = t.openRequest(Vectors::Edit::postPath, env.data(), env.size(), Vectors::Edit::postT + 1000, plain, iv);
  TEST_ASSERT_EQUAL_INT(200, r.status);
  TEST_ASSERT_TRUE(r.role == KeyRole::Edit);
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::postPlain, plain.c_str());
  r = t.openRequest(Vectors::Edit::postPath, env.data(), env.size(), Vectors::Edit::postT + 1500, plain, iv);
  TEST_ASSERT_EQUAL_STRING("replay", r.code);

  // The client side produces exactly the reference bytes.
  std::vector<uint8_t> ivBytes;
  hexDecode("000102030405060708090a0b", 24, ivBytes);
  std::string sealed;
  TEST_ASSERT_TRUE(t.sealRequest(Vectors::Edit::postPath, Vectors::Edit::postT, Vectors::Edit::postPlain, ivBytes.data(), sealed, KeyRole::Edit));
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::postEnvelope, sealed.c_str());

  std::string answer;
  const std::string resp = Vectors::Edit::respEnvelope;
  TEST_ASSERT_TRUE(t.openResponse(Vectors::Edit::postPath, Vectors::Edit::postIv, 200, resp.data(), resp.size(), answer, KeyRole::Edit));
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::respPlain, answer.c_str());
  TEST_ASSERT_FALSE(t.openResponse(Vectors::Edit::postPath, Vectors::Edit::postIv, 200, resp.data(), resp.size(), answer, KeyRole::Normal));
  std::string mine;
  TEST_ASSERT_TRUE(t.sealResponse("/plan", Vectors::Edit::postIv, 200, "{\"ok\":true}", mine, KeyRole::Edit));
  TEST_ASSERT_TRUE(t.openResponse("/plan", Vectors::Edit::postIv, 200, mine.data(), mine.size(), answer, KeyRole::Edit));
  TEST_ASSERT_FALSE(t.openResponse("/plan", Vectors::Edit::postIv, 200, mine.data(), mine.size(), answer, KeyRole::Normal));
}

void test_edit_required_after_authentication() {
  SecureTransport t(g_backend);
  beginWithEdit(t);
  std::string plain, iv;
  const std::string normal = Vectors::Edit::postNormalEnvelope; // valid, but with the NORMAL keys
  OpenResult r = t.openRequest(Vectors::Edit::postPath, normal.data(), normal.size(), Vectors::Edit::postT, plain, iv);
  TEST_ASSERT_EQUAL_INT(403, r.status);
  TEST_ASSERT_EQUAL_STRING("edit_required", r.code);
  TEST_ASSERT_TRUE(r.role == KeyRole::Normal); // sealed with the normal keys: the sender proved the normal token
  TEST_ASSERT_TRUE(plain.empty());
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::postIv, iv.c_str());
  // Every edit path, with normal keys, is refused; other paths are unaffected.
  const char *paths[] = {"/plan", "/plan-skeleton", "/setup"};
  for (size_t i = 0; i < 3; i++) {
    std::vector<uint8_t> ivBytes(12, (uint8_t)(20 + i));
    std::string env;
    TEST_ASSERT_TRUE(t.sealRequest(paths[i], Vectors::Edit::postT, "{}", ivBytes.data(), env));
    r = t.openRequest(paths[i], env.data(), env.size(), Vectors::Edit::postT, plain, iv);
    TEST_ASSERT_EQUAL_INT_MESSAGE(403, r.status, paths[i]);
  }
  const char *open[] = {"/action", "/plan-action", "/config"};
  for (size_t i = 0; i < 3; i++) {
    std::vector<uint8_t> ivBytes(12, (uint8_t)(40 + i));
    std::string env;
    TEST_ASSERT_TRUE(t.sealRequest(open[i], Vectors::Edit::postT, "{}", ivBytes.data(), env));
    r = t.openRequest(open[i], env.data(), env.size(), Vectors::Edit::postT, plain, iv);
    TEST_ASSERT_EQUAL_INT_MESSAGE(200, r.status, open[i]);
  }
  // The edit key set does not authorise normal operation.
  std::vector<uint8_t> ivBytes(12, 77);
  std::string env;
  TEST_ASSERT_TRUE(t.sealRequest("/action", Vectors::Edit::postT, "{}", ivBytes.data(), env, KeyRole::Edit));
  r = t.openRequest("/action", env.data(), env.size(), Vectors::Edit::postT, plain, iv);
  TEST_ASSERT_EQUAL_INT(400, r.status);
}

void test_edit_unset_keeps_old_behaviour() {
  SecureTransport t(g_backend);
  TEST_ASSERT_TRUE(t.begin(Vectors::Edit::normalToken, TokenState::Custom, Vectors::kDid));
  TEST_ASSERT_TRUE(t.editState() == EditState::Unset);
  TEST_ASSERT_FALSE(t.editReady());
  std::string plain, iv;
  const std::string normal = Vectors::Edit::postNormalEnvelope;
  OpenResult r = t.openRequest(Vectors::Edit::postPath, normal.data(), normal.size(), Vectors::Edit::postT, plain, iv);
  TEST_ASSERT_EQUAL_INT(200, r.status); // the normal token may still send plans
  const std::string edit = Vectors::Edit::postEnvelope;
  SecureTransport t2(g_backend);
  TEST_ASSERT_TRUE(t2.begin(Vectors::Edit::normalToken, TokenState::Custom, Vectors::kDid));
  r = t2.openRequest(Vectors::Edit::postPath, edit.data(), edit.size(), Vectors::Edit::postT, plain, iv);
  TEST_ASSERT_EQUAL_INT(401, r.status); // an edit envelope cannot be verified without an edit token
  TEST_ASSERT_EQUAL_STRING("auth_failed", r.code);
  std::string frame;
  TEST_ASSERT_FALSE(t2.frameEditDocument("/edit.json", Vectors::Edit::proofNonce, 200, "{}", frame));
  TEST_ASSERT_FALSE(t2.signingEnabled());
}

void test_unusable_edit_token_never_opens_editing() {
  std::string plain, iv;
  {
    SecureTransport t(g_backend);
    TEST_ASSERT_FALSE(t.begin(Vectors::Edit::normalToken, TokenState::Custom, Vectors::kDid, "short", EditState::Custom));
    TEST_ASSERT_TRUE(t.editState() == EditState::Invalid);
    const std::string normal = Vectors::Edit::postNormalEnvelope;
    OpenResult r = t.openRequest(Vectors::Edit::postPath, normal.data(), normal.size(), Vectors::Edit::postT, plain, iv);
    TEST_ASSERT_EQUAL_INT(503, r.status);
    TEST_ASSERT_EQUAL_STRING("read_only", r.code);
    std::vector<uint8_t> ivBytes(12, 5);
    std::string env;
    TEST_ASSERT_TRUE(t.sealRequest("/action", Vectors::Edit::postT, "{}", ivBytes.data(), env));
    r = t.openRequest("/action", env.data(), env.size(), Vectors::Edit::postT, plain, iv);
    TEST_ASSERT_EQUAL_INT(200, r.status); // game operation stays available
  }
  {
    SecureTransport t(g_backend); // stored but unreadable
    TEST_ASSERT_TRUE(t.begin(Vectors::Edit::normalToken, TokenState::Custom, Vectors::kDid, "", EditState::Invalid));
    const std::string normal = Vectors::Edit::postNormalEnvelope;
    OpenResult r = t.openRequest(Vectors::Edit::postPath, normal.data(), normal.size(), Vectors::Edit::postT, plain, iv);
    TEST_ASSERT_EQUAL_INT(503, r.status);
  }
}

void test_edit_proof_frame_and_skeleton_mac() {
  SecureTransport t(g_backend);
  beginWithEdit(t);
  std::string frame;
  TEST_ASSERT_TRUE(t.frameEditDocument(Vectors::Edit::proofPath, Vectors::Edit::proofNonce, 200, Vectors::Edit::proofDoc, frame));
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::proofFrame, frame.c_str());
  EscapeJson::Slice doc;
  TEST_ASSERT_TRUE(t.openEditDocumentFrame(Vectors::Edit::proofPath, Vectors::Edit::proofNonce, 200, frame.data(), frame.size(), doc));
  // A frame MACed with the NORMAL key never passes as edit proof and vice versa.
  std::string normalFrame;
  TEST_ASSERT_TRUE(t.frameDocument(Vectors::Edit::proofPath, Vectors::Edit::proofNonce, 200, Vectors::Edit::proofDoc, normalFrame));
  TEST_ASSERT_FALSE(t.openEditDocumentFrame(Vectors::Edit::proofPath, Vectors::Edit::proofNonce, 200, normalFrame.data(), normalFrame.size(), doc));
  TEST_ASSERT_FALSE(t.openDocumentFrame(Vectors::Edit::proofPath, Vectors::Edit::proofNonce, 200, frame.data(), frame.size(), doc));

  std::string emac;
  TEST_ASSERT_TRUE(t.signSkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev, 0x9f8e7d6cu, emac));
  TEST_ASSERT_EQUAL_STRING(Vectors::Edit::skEmac, emac.c_str());
  TEST_ASSERT_TRUE(t.verifySkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev, 0x9f8e7d6cu, emac));
  TEST_ASSERT_FALSE(t.verifySkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev + 1, 0x9f8e7d6cu, emac));
  TEST_ASSERT_FALSE(t.verifySkeleton("Raum-B", Vectors::Edit::skRev, 0x9f8e7d6cu, emac));
  TEST_ASSERT_FALSE(t.verifySkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev, 0x9f8e7d6du, emac));
  TEST_ASSERT_FALSE(t.verifySkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev, 0x9f8e7d6cu, emac.substr(1)));
  TEST_ASSERT_FALSE(t.verifySkeleton(Vectors::Edit::skRoom, Vectors::Edit::skRev, 0x9f8e7d6cu, std::string(43, 'A')));
}

} // namespace

void runCryptoTests() {
  RUN_TEST(test_hkdf_rfc5869);
  RUN_TEST(test_key_schedule_matches_vectors);
  RUN_TEST(test_hmac_parts_equal_one_shot);
  RUN_TEST(test_gcm_roundtrip_and_tamper);
  RUN_TEST(test_open_request_vector);
  RUN_TEST(test_seal_request_matches_vector);
  RUN_TEST(test_request_rejections);
  RUN_TEST(test_read_only_states);
  RUN_TEST(test_response_envelopes);
  RUN_TEST(test_document_frames);
  RUN_TEST(test_announcement_frames);
  RUN_TEST(test_replay_cache_is_bounded_and_fails_closed);
  RUN_TEST(test_clock_wraparound);
  RUN_TEST(test_edit_key_schedule_matches_vectors);
  RUN_TEST(test_edit_envelope_vectors);
  RUN_TEST(test_edit_required_after_authentication);
  RUN_TEST(test_edit_unset_keeps_old_behaviour);
  RUN_TEST(test_unusable_edit_token_never_opens_editing);
  RUN_TEST(test_edit_proof_frame_and_skeleton_mac);
}
