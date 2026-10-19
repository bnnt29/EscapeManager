#include <unity.h>
#include <cstring>
#include <string>

#include "../../src/protocol/Peers.hpp"
#include "../../src/protocol/SkeletonStore.hpp"
#include "tests.hpp"

using namespace Escape;

namespace {

void test_ipv4_and_did() {
  uint8_t ip[4];
  TEST_ASSERT_TRUE(parseIpv4("192.168.1.20", 12, ip));
  TEST_ASSERT_EQUAL_UINT32(0xC0A80114u, ipv4ToU32(ip));
  char text[16];
  u32ToIpv4Text(0xC0A80114u, text);
  TEST_ASSERT_EQUAL_STRING("192.168.1.20", text);
  u32ToIpv4Text(0x0A000001u, text);
  TEST_ASSERT_EQUAL_STRING("10.0.0.1", text);
  u32ToIpv4Text(0xFFFFFFFFu, text);
  TEST_ASSERT_EQUAL_STRING("255.255.255.255", text);
  const char *bad[] = {"", "1.2.3", "1.2.3.4.5", "256.1.1.1", "01.2.3.4", "1.2.3.", "a.b.c.d", " 1.2.3.4", "1.2.3.4 ", "1..2.3"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(parseIpv4(bad[i], strlen(bad[i]), ip), bad[i]);
  uint8_t did[6];
  TEST_ASSERT_TRUE(parseDid("aabbccddeeff", 12, did));
  TEST_ASSERT_EQUAL_STRING("aabbccddeeff", didToText(did).c_str());
  TEST_ASSERT_FALSE(parseDid("AABBCCDDEEFF", 12, did));
  TEST_ASSERT_FALSE(parseDid("aabbccddee", 10, did));
  TEST_ASSERT_FALSE(parseDid("aabbccddeegg", 12, did));
}

std::string doc(const char *did = "aabbccddeeff", const char *ip = "192.168.1.20", unsigned boot = 5, unsigned ctr = 10) {
  return buildAnnouncementDoc(did, ip, 80, boot, ctr, 17, 2, "1a2b3c4d", "[[\"a1b2c3d4\",3,\"9f8e7d6c\"]]", 0x12345678u);
}

void test_announcement_roundtrip() {
  const std::string d = doc();
  Announcement a;
  TEST_ASSERT_TRUE(parseAnnouncement(d.data(), d.size(), a));
  TEST_ASSERT_EQUAL_STRING("aabbccddeeff", didToText(a.did).c_str());
  TEST_ASSERT_EQUAL_STRING("192.168.1.20", a.ip);
  TEST_ASSERT_EQUAL_UINT16(80, a.port);
  TEST_ASSERT_EQUAL_UINT32(5, a.boot);
  TEST_ASSERT_EQUAL_UINT32(10, a.ctr);
  TEST_ASSERT_EQUAL_UINT32(17, a.seq);
  TEST_ASSERT_EQUAL_UINT32(0x1a2b3c4du, a.uih);
  TEST_ASSERT_EQUAL_UINT32(0x12345678u, a.skh);
  TEST_ASSERT_EQUAL_UINT8(1, a.skCount);
  TEST_ASSERT_EQUAL_UINT32(0xa1b2c3d4u, a.sk[0].roomKey);
  TEST_ASSERT_EQUAL_UINT32(3, a.sk[0].rev);
  TEST_ASSERT_EQUAL_UINT32(0x9f8e7d6cu, a.sk[0].hash);
}

void test_announcement_rejects_malformed() {
  Announcement a;
  const char *bad[] = {
      "", "{}", "[]", "garbage",
      "{\"v\":2,\"did\":\"aabbccddeeff\"}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":0,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":[]}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3\",\"port\":80,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":[]}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":80,\"boot\":-1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":[]}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":80,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"XYZ\",\"skh\":\"00000000\",\"sk\":[]}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":80,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":[[\"a\",1]]}",
      "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":80,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":\"x\"}",
  };
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(parseAnnouncement(bad[i], strlen(bad[i]), a), bad[i]);
  std::string many = "{\"v\":2,\"did\":\"aabbccddeeff\",\"ip\":\"1.2.3.4\",\"port\":80,\"boot\":1,\"ctr\":1,\"seq\":1,\"pmin\":2,\"uih\":\"00000000\",\"skh\":\"00000000\",\"sk\":[";
  for (int i = 0; i < 9; i++) many += std::string(i ? "," : "") + "[\"a1b2c3d4\",1,\"9f8e7d6c\"]";
  many += "]}";
  TEST_ASSERT_FALSE(parseAnnouncement(many.data(), many.size(), a)); // more rooms than allowed
}

void test_peer_table_freshness_rules() {
  static PeerTable table;
  table.clear();
  uint8_t own[6];
  parseDid("112233445566", 12, own);
  Announcement a;
  std::string d = doc("aabbccddeeff", "192.168.1.20", 5, 10);
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.20", own, 1000) == PeerTable::Result::Accepted);
  TEST_ASSERT_EQUAL_UINT(1, table.count());
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.20", own, 1100) == PeerTable::Result::Replay);  // same (boot, ctr)
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.99", own, 1100) == PeerTable::Result::BadSource); // ip must match the source
  d = doc("aabbccddeeff", "192.168.1.20", 5, 9);
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.20", own, 1200) == PeerTable::Result::Replay);  // older counter
  d = doc("aabbccddeeff", "192.168.1.20", 4, 99);
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.20", own, 1200) == PeerTable::Result::Replay);  // older boot
  d = doc("aabbccddeeff", "192.168.1.20", 5, 11);
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.20", own, 1300) == PeerTable::Result::Accepted);
  d = doc("aabbccddeeff", "192.168.1.21", 6, 1); // new boot restarts the counter; address change follows the source
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.21", own, 1400) == PeerTable::Result::Accepted);
  TEST_ASSERT_EQUAL_UINT(1, table.count());
  char ip[16];
  u32ToIpv4Text(table.at(0).ip, ip);
  TEST_ASSERT_EQUAL_STRING("192.168.1.21", ip);
  d = doc("112233445566", "192.168.1.5", 1, 1); // our own announcement
  parseAnnouncement(d.data(), d.size(), a);
  TEST_ASSERT_TRUE(table.ingest(a, "192.168.1.5", own, 1500) == PeerTable::Result::Own);
  TEST_ASSERT_EQUAL_UINT(1, table.count());
}

void test_peer_expiry_and_eviction() {
  static PeerTable table;
  table.clear();
  uint8_t own[6] = {0, 0, 0, 0, 0, 1};
  Announcement a;
  for (size_t i = 0; i < EscapeConfig::MAX_PEER_ADDRESSES + 5; i++) {
    char did[13], ip[20];
    snprintf(did, sizeof(did), "%012x", (unsigned)(0x100 + i));
    snprintf(ip, sizeof(ip), "10.0.%u.%u", (unsigned)(i / 200), (unsigned)(i % 200 + 1));
    const std::string d = buildAnnouncementDoc(did, ip, 80, 1, 1, 1, 2, "00000000", "[]", 0);
    TEST_ASSERT_TRUE(parseAnnouncement(d.data(), d.size(), a));
    TEST_ASSERT_TRUE(table.ingest(a, ip, own, 1000 + (uint32_t)i) == PeerTable::Result::Accepted);
  }
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::MAX_PEER_ADDRESSES, table.count()); // bounded; oldest evicted
  uint8_t first[6];
  parseDid("000000000100", 12, first);
  TEST_ASSERT_NULL(table.findByDid(first));
  uint8_t last[6];
  char lastDid[13];
  snprintf(lastDid, sizeof(lastDid), "%012x", (unsigned)(0x100 + EscapeConfig::MAX_PEER_ADDRESSES + 4));
  parseDid(lastDid, 12, last);
  TEST_ASSERT_NOT_NULL(table.findByDid(last));
  table.expireStale(1000 + 5000 + EscapeConfig::PEER_TIMEOUT_MS);
  TEST_ASSERT_EQUAL_UINT(0, table.count());
}

void test_expiry_across_clock_wrap() {
  static PeerTable table;
  table.clear();
  uint8_t own[6] = {0, 0, 0, 0, 0, 1};
  Announcement a;
  const std::string d = doc();
  parseAnnouncement(d.data(), d.size(), a);
  table.ingest(a, "192.168.1.20", own, 0xFFFFFF00u);
  table.expireStale(0x00000100u, 20000); // 512 ms later, across the wrap: still alive
  TEST_ASSERT_EQUAL_UINT(1, table.count());
  table.expireStale(0x00005000u, 20000);
  TEST_ASSERT_EQUAL_UINT(0, table.count());
}

} // namespace

void runPeerTests() {
  RUN_TEST(test_ipv4_and_did);
  RUN_TEST(test_announcement_roundtrip);
  RUN_TEST(test_announcement_rejects_malformed);
  RUN_TEST(test_peer_table_freshness_rules);
  RUN_TEST(test_peer_expiry_and_eviction);
  RUN_TEST(test_expiry_across_clock_wrap);
}
