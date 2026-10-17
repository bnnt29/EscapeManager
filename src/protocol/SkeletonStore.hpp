#pragma once

// Per-room plan skeletons (PROTOCOL.md 5.4). The firmware does not interpret a
// skeleton; it stores it opaque per room together with a revision and a content hash
// so devices converge on the newest plan without relying on uptime or wall clocks:
// (rev, hash) is compared lexicographically.
//
// Only a small index (room, rev, hash) stays in RAM; skeleton bodies (up to 6 KB) are
// read from storage when a request needs them.

#include "EscapeConfig.hpp"
#include "Storage.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Escape {

uint32_t fnv1a32(const char *data, size_t length);
inline uint32_t fnv1a32(const std::string &s) { return fnv1a32(s.data(), s.size()); }
std::string hex8(uint32_t value);
bool parseHex8(const char *text, size_t length, uint32_t &out);

// Storage key suffix of a room ("a1b2c3d4").
inline std::string roomKey(const std::string &room) { return hex8(fnv1a32(room)); }

struct SkeletonInfo {
  std::string room;
  uint32_t rev;
  uint32_t hash;
};

class SkeletonStore {
public:
  enum class Result {
    Stored,       // new revision written
    Unchanged,    // identical content already stored (idempotent)
    Conflict,     // baseRev does not match the stored revision
    TooLarge,
    Invalid,      // not a JSON object / bad room / bad blob
    RoomLimit,    // more rooms than MAX_SKELETON_ROOMS
    KeyCollision, // two different rooms share a storage key
    StorageError,
    NotNewer      // adopt(): offered blob is not newer
  };

  explicit SkeletonStore(BlobStorage &storage) : storage_(storage) {}

  // Reads the index. A missing index is an empty store; a damaged one is dropped.
  bool load();

  size_t count() const { return index_.size(); }
  const SkeletonInfo &at(size_t i) const { return index_[i]; }
  const SkeletonInfo *find(const std::string &room) const;

  // The stored blob `{"room":..,"rev":..,"hash":..,"sk":{...}}`.
  bool get(const std::string &room, std::string &blob);

  // Manager write: stores `sk` (raw JSON object) as revision baseRev+1 if the stored
  // revision equals baseRev (0 for a room without skeleton).
  Result put(const std::string &room, uint32_t baseRev, const char *sk, size_t skLength, uint32_t &rev,
             uint32_t &hash);

  // Sync write: takes a complete blob from a peer, re-validates it (room, hash over
  // `sk`) and stores it if it is newer than what we have.
  Result adopt(const std::string &blob, const std::string &expectedRoom);

  // Drops skeletons of rooms that have no local component any more.
  void keepOnly(const std::vector<std::string> &rooms);

  // True if (rev, hash) beats (curRev, curHash).
  static bool isNewer(uint32_t rev, uint32_t hash, uint32_t curRev, uint32_t curHash) {
    return rev > curRev || (rev == curRev && hash > curHash);
  }

  // Fingerprint of the index for announcements and /peers.json ("skh").
  std::string summaryJson() const;     // [["room8",rev,"hash8"],...]
  uint32_t summaryHash() const;

private:
  Result store(const std::string &room, uint32_t rev, uint32_t hash, const char *sk, size_t skLength);
  bool saveIndex();
  static std::string blobKey(const std::string &room) { return "sk_" + roomKey(room); }
  bool keyCollides(const std::string &room) const;

  BlobStorage &storage_;
  std::vector<SkeletonInfo> index_;
};

} // namespace Escape
