#include "SkeletonStore.hpp"

#include "Compat.hpp"
#include "Json.hpp"

#include <cstring>

namespace Escape {

namespace {
const char kIndexKey[] = "skidx";
bool validRoomName(const std::string &room) {
  return !room.empty() && room.size() <= EscapeConfig::MAX_ROOM_LEN;
}
} // namespace

uint32_t fnv1a32(const char *data, size_t length) {
  uint32_t h = 0x811c9dc5u;
  for (size_t i = 0; i < length; i++) {
    h ^= (uint8_t)data[i];
    h *= 0x01000193u;
  }
  return h;
}

std::string hex8(uint32_t value) {
  static const char kHex[] = "0123456789abcdef";
  std::string s(8, '0');
  for (int i = 7; i >= 0; i--) {
    s[(size_t)i] = kHex[value & 0xF];
    value >>= 4;
  }
  return s;
}

bool parseHex8(const char *text, size_t length, uint32_t &out) {
  if (length != 8) return false;
  uint32_t v = 0;
  for (size_t i = 0; i < 8; i++) {
    const char c = text[i];
    v <<= 4;
    if (c >= '0' && c <= '9') v |= (uint32_t)(c - '0');
    else if (c >= 'a' && c <= 'f') v |= (uint32_t)(c - 'a' + 10);
    else return false; // lowercase only: one canonical text per value
  }
  out = v;
  return true;
}

const SkeletonInfo *SkeletonStore::find(const std::string &room) const {
  for (size_t i = 0; i < index_.size(); i++) {
    if (index_[i].room == room) return &index_[i];
  }
  return nullptr;
}

bool SkeletonStore::load() {
  index_.clear();
  std::string text;
  if (!storage_.read(kIndexKey, text)) return true; // nothing stored yet
  return Escape::guardAlloc([&]() -> bool {
    EscapeJson::Value doc;
    if (!EscapeJson::parse(text, doc) || doc.type != EscapeJson::Type::Array) return false;
    for (size_t i = 0; i < doc.arrayValue.size() && index_.size() < EscapeConfig::MAX_SKELETON_ROOMS; i++) {
      const EscapeJson::Value &e = doc.arrayValue[i];
      const EscapeJson::Value *r = e.find("r"), *v = e.find("v"), *h = e.find("h");
      long long rev = 0;
      uint32_t hash = 0;
      if (!r || r->type != EscapeJson::Type::String || !validRoomName(r->stringValue) || !v ||
          !v->asInt(0, 0xFFFFFFFFLL, rev) || !h || h->type != EscapeJson::Type::String ||
          !parseHex8(h->stringValue.data(), h->stringValue.size(), hash)) {
        continue; // damaged entry: drop it, keep the rest
      }
      SkeletonInfo info;
      info.room = r->stringValue;
      info.rev = (uint32_t)rev;
      info.hash = hash;
      index_.push_back(info);
    }
    return true;
  }, false);
}

bool SkeletonStore::saveIndex() {
  return Escape::guardAlloc([&]() -> bool {
    std::string text = "[";
    for (size_t i = 0; i < index_.size(); i++) {
      if (i) text += ',';
      text += "{\"r\":\"";
      EscapeJson::appendEscaped(text, index_[i].room);
      text += "\",\"v\":";
      EscapeJson::appendUInt(text, index_[i].rev);
      text += ",\"h\":\"" + hex8(index_[i].hash) + "\"}";
    }
    text += ']';
    return storage_.write(kIndexKey, text);
  }, false);
}

bool SkeletonStore::keyCollides(const std::string &room) const {
  const uint32_t k = fnv1a32(room);
  for (size_t i = 0; i < index_.size(); i++) {
    if (index_[i].room != room && fnv1a32(index_[i].room) == k) return true;
  }
  return false;
}

bool SkeletonStore::get(const std::string &room, std::string &blob) {
  if (!find(room)) return false;
  return storage_.read(blobKey(room).c_str(), blob);
}

SkeletonStore::Result SkeletonStore::store(const std::string &room, uint32_t rev, uint32_t hash, const char *sk,
                                           size_t skLength, const std::string &emac) {
  return Escape::guardAlloc([&]() -> Result {
    std::string blob;
    blob.reserve(skLength + 160 + room.size());
    blob += "{\"room\":\"";
    EscapeJson::appendEscaped(blob, room);
    blob += "\",\"rev\":";
    EscapeJson::appendUInt(blob, rev);
    blob += ",\"hash\":\"" + hex8(hash) + "\"";
    if (!emac.empty()) blob += ",\"emac\":\"" + emac + "\"";
    blob += ",\"sk\":";
    blob.append(sk, skLength);
    blob += '}';
    if (!storage_.write(blobKey(room).c_str(), blob)) return Result::StorageError;
    SkeletonInfo *entry = nullptr;
    for (size_t i = 0; i < index_.size(); i++) {
      if (index_[i].room == room) entry = &index_[i];
    }
    const SkeletonInfo previous = entry ? *entry : SkeletonInfo();
    const bool existed = entry != nullptr;
    if (!entry) {
      index_.push_back(SkeletonInfo());
      entry = &index_.back();
      entry->room = room;
    }
    entry->rev = rev;
    entry->hash = hash;
    if (!saveIndex()) {
      // Keep RAM and storage consistent: roll the index back; the orphaned blob is harmless.
      if (existed) { *entry = previous; } else { index_.pop_back(); }
      return Result::StorageError;
    }
    return Result::Stored;
  }, Result::StorageError);
}

SkeletonStore::Result SkeletonStore::put(const std::string &room, uint32_t baseRev, const char *sk,
                                         size_t skLength, uint32_t &rev, uint32_t &hash) {
  if (!validRoomName(room)) return Result::Invalid;
  if (skLength > EscapeConfig::MAX_PLAN_SKELETON_LEN) return Result::TooLarge;
  if (!sk || skLength < 2 || sk[0] != '{' || !EscapeJson::validate(sk, skLength, 16)) return Result::Invalid;
  const uint32_t newHash = fnv1a32(sk, skLength);
  const SkeletonInfo *existing = find(room);
  const uint32_t curRev = existing ? existing->rev : 0;
  const bool signing = signer_ && signer_->signingEnabled();
  if (existing && existing->hash == newHash) {
    rev = existing->rev; // identical content: nothing to write, retries are harmless
    hash = existing->hash;
    if (signing) {
      // A skeleton stored before the edit token was set carries no MAC yet: an authorised re-send
      // of the same content stamps it (same revision) so peers with an edit token accept it.
      std::string blob, emac;
      EscapeJson::Slice se;
      bool stamped = false;
      if (storage_.read(blobKey(room).c_str(), blob) &&
          EscapeJson::findField(blob.data(), blob.size(), "emac", se) == EscapeJson::Scan::Found &&
          EscapeJson::sliceToString(se, emac)) {
        stamped = signer_->verifySkeleton(room, existing->rev, existing->hash, emac);
      }
      if (!stamped) {
        std::string fresh;
        if (!signer_->signSkeleton(room, existing->rev, existing->hash, fresh)) return Result::StorageError;
        return store(room, existing->rev, existing->hash, sk, skLength, fresh) == Result::Stored ? Result::Stored : Result::StorageError;
      }
    }
    return Result::Unchanged;
  }
  if (baseRev != curRev) {
    rev = curRev;
    hash = existing ? existing->hash : 0;
    return Result::Conflict;
  }
  if (!existing && index_.size() >= EscapeConfig::MAX_SKELETON_ROOMS) return Result::RoomLimit;
  if (!existing && keyCollides(room)) return Result::KeyCollision;
  if (curRev == 0xFFFFFFFFu) return Result::Invalid;
  std::string emac;
  if (signing && !signer_->signSkeleton(room, curRev + 1, newHash, emac)) return Result::StorageError;
  const Result r = store(room, curRev + 1, newHash, sk, skLength, emac);
  if (r == Result::Stored) {
    rev = curRev + 1;
    hash = newHash;
  }
  return r;
}

SkeletonStore::Result SkeletonStore::adopt(const std::string &blob, const std::string &expectedRoom) {
  if (blob.size() > EscapeConfig::MAX_PLAN_SKELETON_LEN + 160) return Result::TooLarge;
  EscapeJson::Slice sroom, srev, shash, ssk, semac;
  const char *p = blob.data();
  const size_t n = blob.size();
  if (EscapeJson::findField(p, n, "room", sroom) != EscapeJson::Scan::Found ||
      EscapeJson::findField(p, n, "rev", srev) != EscapeJson::Scan::Found ||
      EscapeJson::findField(p, n, "hash", shash) != EscapeJson::Scan::Found ||
      EscapeJson::findField(p, n, "sk", ssk) != EscapeJson::Scan::Found) {
    return Result::Invalid;
  }
  std::string room, hashText;
  uint32_t rev = 0, hash = 0;
  if (!EscapeJson::sliceToString(sroom, room) || room != expectedRoom || !validRoomName(room) ||
      !EscapeJson::sliceToUInt(srev, 0xFFFFFFFFu, rev) || rev == 0 ||
      !EscapeJson::sliceToString(shash, hashText) || !parseHex8(hashText.data(), hashText.size(), hash)) {
    return Result::Invalid;
  }
  if (ssk.n > EscapeConfig::MAX_PLAN_SKELETON_LEN) return Result::TooLarge;
  if (ssk.n < 2 || ssk.p[0] != '{' || !EscapeJson::validate(ssk.p, ssk.n, 16)) return Result::Invalid;
  if (fnv1a32(ssk.p, ssk.n) != hash) return Result::Invalid; // content does not match its claimed hash
  // The MAC travels with the skeleton. A device with an edit token insists on a valid one; a device
  // without keeps it unchanged so it can pass it on.
  std::string emac;
  if (EscapeJson::findField(p, n, "emac", semac) == EscapeJson::Scan::Found) {
    // A MAC is exactly 43 base64url characters; anything else could carry quotes into the stored blob.
    if (!EscapeJson::sliceToString(semac, emac) || emac.size() != 43) return Result::Invalid;
    for (size_t i = 0; i < emac.size(); i++) {
      const char c = emac[i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return Result::Invalid;
    }
  }
  if (signer_ && signer_->signingEnabled()) {
    if (emac.empty() || !signer_->verifySkeleton(room, rev, hash, emac)) return Result::Unauthorized;
  }
  const SkeletonInfo *existing = find(room);
  if (existing && !isNewer(rev, hash, existing->rev, existing->hash)) return Result::NotNewer;
  if (!existing && index_.size() >= EscapeConfig::MAX_SKELETON_ROOMS) return Result::RoomLimit;
  if (!existing && keyCollides(room)) return Result::KeyCollision;
  return store(room, rev, hash, ssk.p, ssk.n, emac);
}

void SkeletonStore::keepOnly(const std::vector<std::string> &rooms) {
  bool changed = false;
  for (size_t i = index_.size(); i-- > 0;) {
    bool keep = false;
    for (size_t k = 0; k < rooms.size(); k++) keep = keep || rooms[k] == index_[i].room;
    if (!keep) {
      storage_.erase(blobKey(index_[i].room).c_str());
      index_.erase(index_.begin() + (long)i);
      changed = true;
    }
  }
  if (changed) saveIndex();
}

std::string SkeletonStore::summaryJson() const {
  std::string s = "[";
  for (size_t i = 0; i < index_.size(); i++) {
    if (i) s += ',';
    s += "[\"" + roomKey(index_[i].room) + "\",";
    EscapeJson::appendUInt(s, index_[i].rev);
    s += ",\"" + hex8(index_[i].hash) + "\"]";
  }
  s += ']';
  return s;
}

uint32_t SkeletonStore::summaryHash() const {
  const std::string s = summaryJson();
  return fnv1a32(s.data(), s.size());
}

} // namespace Escape
