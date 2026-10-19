#include <unity.h>
#include <cstring>
#include <string>

#include "../../src/protocol/Json.hpp"
#include "../../src/protocol/SkeletonStore.hpp"
#include "tests.hpp"
#include "vectors.hpp"

using namespace Escape;

namespace {

const char *kSkA = "{\"planId\":\"p1\",\"layers\":[{\"id\":\"L1\",\"lanes\":[]}]}";
const char *kSkB = "{\"planId\":\"p1\",\"layers\":[{\"id\":\"L1\",\"lanes\":[{\"id\":\"A\"}]}]}";

void test_fnv_vectors() {
  for (size_t i = 0; i < sizeof(Vectors::kFnv) / sizeof(Vectors::kFnv[0]); i++) {
    TEST_ASSERT_EQUAL_STRING(Vectors::kFnv[i].hash, hex8(fnv1a32(std::string(Vectors::kFnv[i].text))).c_str());
  }
  uint32_t v = 0;
  TEST_ASSERT_TRUE(parseHex8("00ff10ab", 8, v));
  TEST_ASSERT_EQUAL_UINT32(0x00ff10abu, v);
  TEST_ASSERT_FALSE(parseHex8("00FF10AB", 8, v)); // one canonical (lowercase) text
  TEST_ASSERT_FALSE(parseHex8("00ff10a", 7, v));
}

void test_put_get_and_blob_format() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  TEST_ASSERT_TRUE(store.load());
  uint32_t rev = 0, hash = 0;
  TEST_ASSERT_TRUE(store.put("Raum-A", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT32(1, rev);
  TEST_ASSERT_EQUAL_UINT32(fnv1a32(std::string(kSkA)), hash);
  std::string blob;
  TEST_ASSERT_TRUE(store.get("Raum-A", blob));
  EscapeJson::Slice s;
  TEST_ASSERT_TRUE(EscapeJson::findField(blob.data(), blob.size(), "sk", s) == EscapeJson::Scan::Found);
  TEST_ASSERT_EQUAL_STRING(kSkA, s.str().c_str()); // byte-for-byte
  TEST_ASSERT_TRUE(EscapeJson::validate(blob.data(), blob.size()));
  TEST_ASSERT_FALSE(store.get("Other", blob));
}

void test_revision_rules() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  uint32_t rev = 0, hash = 0;
  store.put("R", 0, kSkA, strlen(kSkA), rev, hash);
  const size_t writes = mem.writeCount();
  // identical content: no write, no revision bump, works with any baseRev (retry-safe)
  TEST_ASSERT_TRUE(store.put("R", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Unchanged);
  TEST_ASSERT_TRUE(store.put("R", 7, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Unchanged);
  TEST_ASSERT_EQUAL_UINT32(1, rev);
  TEST_ASSERT_EQUAL_UINT(writes, mem.writeCount());
  // changed content with a stale baseRev
  TEST_ASSERT_TRUE(store.put("R", 0, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::Conflict);
  TEST_ASSERT_EQUAL_UINT32(1, rev); // reports the current revision
  TEST_ASSERT_EQUAL_UINT32(fnv1a32(std::string(kSkA)), hash);
  TEST_ASSERT_TRUE(store.put("R", 1, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT32(2, rev);
  TEST_ASSERT_EQUAL_UINT32(2, store.find("R")->rev);
}

void test_validation_and_limits() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  uint32_t rev = 0, hash = 0;
  const char *bad[] = {"", "[]", "\"x\"", "{", "{\"a\":01}", "null"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
    TEST_ASSERT_TRUE_MESSAGE(store.put("R", 0, bad[i], strlen(bad[i]), rev, hash) == SkeletonStore::Result::Invalid, bad[i]);
  }
  TEST_ASSERT_TRUE(store.put("", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Invalid);
  TEST_ASSERT_TRUE(store.put(std::string(33, 'x'), 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Invalid);
  std::string big = "{\"x\":\"" + std::string(EscapeConfig::MAX_PLAN_SKELETON_LEN, 'a') + "\"}";
  TEST_ASSERT_TRUE(store.put("R", 0, big.data(), big.size(), rev, hash) == SkeletonStore::Result::TooLarge);
  std::string maxSize = "{\"x\":\"" + std::string(EscapeConfig::MAX_PLAN_SKELETON_LEN - 8, 'a') + "\"}";
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::MAX_PLAN_SKELETON_LEN, maxSize.size());
  TEST_ASSERT_TRUE(store.put("R", 0, maxSize.data(), maxSize.size(), rev, hash) == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT(1, store.count());
}

void test_persistence_and_room_limit() {
  MemoryStorage mem;
  {
    SkeletonStore store(mem);
    uint32_t rev = 0, hash = 0;
    for (size_t i = 0; i < EscapeConfig::MAX_SKELETON_ROOMS; i++) {
      const std::string room = "Raum" + std::to_string(i);
      TEST_ASSERT_TRUE(store.put(room, 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Stored);
    }
    TEST_ASSERT_TRUE(store.put("one-too-many", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::RoomLimit);
    store.put("Raum0", 1, kSkB, strlen(kSkB), rev, hash);
  }
  SkeletonStore reloaded(mem);
  TEST_ASSERT_TRUE(reloaded.load());
  TEST_ASSERT_EQUAL_UINT(EscapeConfig::MAX_SKELETON_ROOMS, reloaded.count());
  TEST_ASSERT_EQUAL_UINT32(2, reloaded.find("Raum0")->rev);
  std::string blob;
  TEST_ASSERT_TRUE(reloaded.get("Raum0", blob));
}

void test_storage_failures_keep_state_consistent() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  uint32_t rev = 0, hash = 0;
  store.put("R", 0, kSkA, strlen(kSkA), rev, hash);
  mem.setFailWrites(true);
  TEST_ASSERT_TRUE(store.put("R", 1, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::StorageError);
  TEST_ASSERT_EQUAL_UINT32(1, store.find("R")->rev); // RAM index unchanged
  TEST_ASSERT_TRUE(store.put("New", 0, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::StorageError);
  TEST_ASSERT_NULL(store.find("New"));
  mem.setFailWrites(false);
  mem.setCapacity(60); // smaller than any skeleton blob
  TEST_ASSERT_TRUE(store.put("R", 1, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::StorageError);
  std::string blob;
  mem.setCapacity(0);
  TEST_ASSERT_TRUE(store.get("R", blob)); // old blob still intact
  EscapeJson::Slice s;
  EscapeJson::findField(blob.data(), blob.size(), "sk", s);
  TEST_ASSERT_EQUAL_STRING(kSkA, s.str().c_str());
}

std::string makeBlob(const std::string &room, uint32_t rev, const std::string &sk, const std::string &hashOverride = "") {
  return "{\"room\":\"" + room + "\",\"rev\":" + std::to_string(rev) + ",\"hash\":\"" +
         (hashOverride.empty() ? hex8(fnv1a32(sk)) : hashOverride) + "\",\"sk\":" + sk + "}";
}

void test_adopt_rules() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 3, kSkA), "R") == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT32(3, store.find("R")->rev);
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 2, kSkB), "R") == SkeletonStore::Result::NotNewer);
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 3, kSkA), "R") == SkeletonStore::Result::NotNewer); // equal
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 4, kSkB), "R") == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT32(4, store.find("R")->rev);
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 5, kSkA, "00000000"), "R") == SkeletonStore::Result::Invalid); // hash lies
  TEST_ASSERT_TRUE(store.adopt(makeBlob("Other", 9, kSkA), "R") == SkeletonStore::Result::Invalid);          // wrong room
  TEST_ASSERT_TRUE(store.adopt("{\"room\":\"R\"}", "R") == SkeletonStore::Result::Invalid);
  TEST_ASSERT_TRUE(store.adopt("garbage", "R") == SkeletonStore::Result::Invalid);
  TEST_ASSERT_TRUE(store.adopt(makeBlob("R", 0, kSkA), "R") == SkeletonStore::Result::Invalid);               // rev 0
  TEST_ASSERT_EQUAL_UINT32(4, store.find("R")->rev);
}

void test_adopt_equal_rev_tiebreak_converges() {
  // Two devices wrote different content at the same revision: the larger hash wins on both.
  const std::string a = kSkA, b = kSkB;
  const bool aWins = fnv1a32(a) > fnv1a32(b);
  MemoryStorage m1, m2;
  SkeletonStore s1(m1), s2(m2);
  s1.adopt(makeBlob("R", 2, a), "R");
  s2.adopt(makeBlob("R", 2, b), "R");
  s1.adopt(makeBlob("R", 2, b), "R");
  s2.adopt(makeBlob("R", 2, a), "R");
  TEST_ASSERT_EQUAL_UINT32(s1.find("R")->hash, s2.find("R")->hash);
  TEST_ASSERT_EQUAL_UINT32(aWins ? fnv1a32(a) : fnv1a32(b), s1.find("R")->hash);
}

void test_keep_only_and_summary() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  uint32_t rev = 0, hash = 0;
  store.put("A", 0, kSkA, strlen(kSkA), rev, hash);
  store.put("B", 0, kSkB, strlen(kSkB), rev, hash);
  const std::string before = store.summaryJson();
  TEST_ASSERT_TRUE(EscapeJson::validate(before.data(), before.size()));
  std::vector<std::string> keep;
  keep.push_back("B");
  store.keepOnly(keep);
  TEST_ASSERT_EQUAL_UINT(1, store.count());
  TEST_ASSERT_NULL(store.find("A"));
  TEST_ASSERT_FALSE(mem.has(("sk_" + roomKey("A")).c_str())); // blob erased
  TEST_ASSERT_TRUE(before != store.summaryJson());
  SkeletonStore again(mem);
  again.load();
  TEST_ASSERT_EQUAL_UINT(1, again.count());
  TEST_ASSERT_EQUAL_UINT32(store.summaryHash(), again.summaryHash());
  MemoryStorage emptyMem;
  SkeletonStore empty(emptyMem);
  TEST_ASSERT_EQUAL_STRING("[]", empty.summaryJson().c_str());
}

void test_damaged_index_is_survivable() {
  MemoryStorage mem;
  mem.write("skidx", "[{\"r\":\"Good\",\"v\":2,\"h\":\"0000abcd\"},{\"r\":\"\",\"v\":1,\"h\":\"0000abcd\"},{\"r\":\"X\",\"v\":-1,\"h\":\"zz\"},5]");
  SkeletonStore store(mem);
  TEST_ASSERT_TRUE(store.load());
  TEST_ASSERT_EQUAL_UINT(1, store.count());
  TEST_ASSERT_EQUAL_UINT32(2, store.find("Good")->rev);
  mem.write("skidx", "not json");
  SkeletonStore broken(mem);
  TEST_ASSERT_FALSE(broken.load());
  TEST_ASSERT_EQUAL_UINT(0, broken.count());
}

// A signer with a trivial, deterministic "MAC": enough to test the store's rules (the real MAC is
// SecureTransport, tested in test_crypto.cpp).
class FakeSigner : public SkeletonSigner {
public:
  bool enabled;
  FakeSigner() : enabled(true) {}
  bool signingEnabled() const override { return enabled; }
  bool signSkeleton(const std::string &room, uint32_t rev, uint32_t hash, std::string &emac) const override {
    // 43 base64url characters like a real MAC, but deterministic and cheap
    const std::string h = hex8(fnv1a32(room + "|" + std::to_string(rev) + "|" + hex8(hash)));
    emac = h + h + h + h + h + "AAA";
    return true;
  }
  bool verifySkeleton(const std::string &room, uint32_t rev, uint32_t hash, const std::string &emac) const override {
    std::string expected;
    signSkeleton(room, rev, hash, expected);
    return emac == expected;
  }
};

std::string emacOf(SkeletonStore &store, const std::string &room) {
  std::string blob, emac;
  EscapeJson::Slice s;
  if (!store.get(room, blob)) return "<none>";
  if (EscapeJson::findField(blob.data(), blob.size(), "emac", s) != EscapeJson::Scan::Found) return "";
  EscapeJson::sliceToString(s, emac);
  return emac;
}

void test_signed_writes_and_restamp() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  FakeSigner signer;
  uint32_t rev = 0, hash = 0;
  // Before the edit token exists: no MAC.
  TEST_ASSERT_TRUE(store.put("R", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_STRING("", emacOf(store, "R").c_str());
  store.setSigner(&signer);
  // An authorised re-send of the SAME content stamps it without a new revision.
  TEST_ASSERT_TRUE(store.put("R", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_UINT32(1, rev);
  {
    std::string expected;
    signer.signSkeleton("R", 1, fnv1a32(std::string(kSkA)), expected);
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), emacOf(store, "R").c_str());
  }
  const size_t writes = mem.writeCount();
  TEST_ASSERT_TRUE(store.put("R", 0, kSkA, strlen(kSkA), rev, hash) == SkeletonStore::Result::Unchanged); // stamped: nothing to do
  TEST_ASSERT_EQUAL_UINT(writes, mem.writeCount());
  // A new revision carries a fresh MAC; the blob stays valid JSON with the skeleton byte-for-byte.
  TEST_ASSERT_TRUE(store.put("R", 1, kSkB, strlen(kSkB), rev, hash) == SkeletonStore::Result::Stored);
  {
    std::string expected;
    signer.signSkeleton("R", 2, fnv1a32(std::string(kSkB)), expected);
    TEST_ASSERT_EQUAL_STRING(expected.c_str(), emacOf(store, "R").c_str());
  }
  std::string blob;
  store.get("R", blob);
  TEST_ASSERT_TRUE(EscapeJson::validate(blob.data(), blob.size()));
  EscapeJson::Slice sk;
  EscapeJson::findField(blob.data(), blob.size(), "sk", sk);
  TEST_ASSERT_EQUAL_STRING(kSkB, sk.str().c_str());
}

void test_adopt_needs_valid_mac_with_edit_token() {
  MemoryStorage mem;
  SkeletonStore store(mem);
  FakeSigner signer;
  store.setSigner(&signer);
  const std::string plain = makeBlob("R", 3, kSkA);
  TEST_ASSERT_TRUE(store.adopt(plain, "R") == SkeletonStore::Result::Unauthorized); // no MAC: planted through a fake peer
  std::string forged = plain;
  forged.insert(forged.find(",\"sk\""), ",\"emac\":\"" + std::string(43, 'A') + "\"");
  TEST_ASSERT_TRUE(store.adopt(forged, "R") == SkeletonStore::Result::Unauthorized);
  // Malformed MACs are rejected before anything is stored (they would end up inside the stored blob).
  const char *badMacs[] = {"forged", "", "AAAA\\\"x", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\\\"", "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA+"};
  for (size_t i = 0; i < sizeof(badMacs) / sizeof(badMacs[0]); i++) {
    MemoryStorage m;
    SkeletonStore open(m); // no edit token: the format is still enforced
    std::string blob = plain;
    blob.insert(blob.find(",\"sk\""), std::string(",\"emac\":\"") + badMacs[i] + "\"");
    TEST_ASSERT_TRUE_MESSAGE(open.adopt(blob, "R") == SkeletonStore::Result::Invalid, badMacs[i]);
    TEST_ASSERT_EQUAL_UINT(0, open.count());
  }
  std::string good = plain;
  std::string emac;
  signer.signSkeleton("R", 3, fnv1a32(std::string(kSkA)), emac);
  good.insert(good.find(",\"sk\""), ",\"emac\":\"" + emac + "\"");
  TEST_ASSERT_TRUE(store.adopt(good, "R") == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_STRING(emac.c_str(), emacOf(store, "R").c_str()); // kept, so this device can pass it on
  // A MAC of another revision does not carry over to a newer one.
  std::string replayed = makeBlob("R", 4, kSkB);
  replayed.insert(replayed.find(",\"sk\""), ",\"emac\":\"" + emac + "\"");
  TEST_ASSERT_TRUE(store.adopt(replayed, "R") == SkeletonStore::Result::Unauthorized);

  // Without an edit token the device accepts as before and keeps the MAC it was given.
  MemoryStorage mem2;
  SkeletonStore open(mem2);
  TEST_ASSERT_TRUE(open.adopt(good, "R") == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_STRING(emac.c_str(), emacOf(open, "R").c_str());
  MemoryStorage mem3;
  SkeletonStore open2(mem3);
  TEST_ASSERT_TRUE(open2.adopt(plain, "R") == SkeletonStore::Result::Stored);
  TEST_ASSERT_EQUAL_STRING("", emacOf(open2, "R").c_str());
}

} // namespace

void runStoreTests() {
  RUN_TEST(test_signed_writes_and_restamp);
  RUN_TEST(test_adopt_needs_valid_mac_with_edit_token);
  RUN_TEST(test_fnv_vectors);
  RUN_TEST(test_put_get_and_blob_format);
  RUN_TEST(test_revision_rules);
  RUN_TEST(test_validation_and_limits);
  RUN_TEST(test_persistence_and_room_limit);
  RUN_TEST(test_storage_failures_keep_state_consistent);
  RUN_TEST(test_adopt_rules);
  RUN_TEST(test_adopt_equal_rev_tiebreak_converges);
  RUN_TEST(test_keep_only_and_summary);
  RUN_TEST(test_damaged_index_is_survivable);
}
