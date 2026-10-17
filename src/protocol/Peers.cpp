#include "Peers.hpp"

#include "Json.hpp"
#include "SkeletonStore.hpp"

#include <cstring>

namespace Escape {

bool parseIpv4(const char *text, size_t length, uint8_t out[4]) {
  size_t i = 0;
  for (int part = 0; part < 4; part++) {
    if (i >= length) return false;
    const size_t start = i;
    unsigned v = 0;
    while (i < length && text[i] >= '0' && text[i] <= '9') {
      v = v * 10 + (unsigned)(text[i] - '0');
      if (v > 255) return false;
      i++;
    }
    const size_t digits = i - start;
    if (digits == 0 || digits > 3 || (digits > 1 && text[start] == '0')) return false;
    out[part] = (uint8_t)v;
    if (part < 3) {
      if (i >= length || text[i] != '.') return false;
      i++;
    }
  }
  return i == length;
}

uint32_t ipv4ToU32(const uint8_t ip[4]) {
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
}

void u32ToIpv4Text(uint32_t ip, char out[16]) {
  size_t o = 0;
  for (int part = 0; part < 4; part++) {
    const unsigned v = (ip >> (24 - 8 * part)) & 0xFF;
    if (v >= 100) out[o++] = (char)('0' + v / 100);
    if (v >= 10) out[o++] = (char)('0' + (v / 10) % 10);
    out[o++] = (char)('0' + v % 10);
    if (part < 3) out[o++] = '.';
  }
  out[o] = '\0';
}

bool parseDid(const char *text, size_t length, uint8_t out[6]) {
  if (length != 12) return false;
  for (size_t i = 0; i < 6; i++) {
    unsigned v = 0;
    for (size_t k = 0; k < 2; k++) {
      const char c = text[i * 2 + k];
      v <<= 4;
      if (c >= '0' && c <= '9') v |= (unsigned)(c - '0');
      else if (c >= 'a' && c <= 'f') v |= (unsigned)(c - 'a' + 10);
      else return false;
    }
    out[i] = (uint8_t)v;
  }
  return true;
}

std::string didToText(const uint8_t did[6]) {
  static const char kHex[] = "0123456789abcdef";
  std::string s(12, '0');
  for (size_t i = 0; i < 6; i++) {
    s[i * 2] = kHex[did[i] >> 4];
    s[i * 2 + 1] = kHex[did[i] & 15];
  }
  return s;
}

std::string buildAnnouncementDoc(const std::string &did, const std::string &ip, uint16_t port, uint32_t boot,
                                 uint32_t ctr, uint32_t seq, uint8_t pmin, const std::string &uiHash,
                                 const std::string &skeletonSummaryJson, uint32_t skeletonSummaryHash) {
  std::string s;
  s.reserve(200 + skeletonSummaryJson.size());
  s += "{\"v\":2,\"did\":\"" + did + "\",\"ip\":\"" + ip + "\",\"port\":";
  EscapeJson::appendUInt(s, port);
  s += ",\"boot\":";
  EscapeJson::appendUInt(s, boot);
  s += ",\"ctr\":";
  EscapeJson::appendUInt(s, ctr);
  s += ",\"seq\":";
  EscapeJson::appendUInt(s, seq);
  s += ",\"pmin\":";
  EscapeJson::appendUInt(s, pmin);
  s += ",\"uih\":\"" + uiHash + "\",\"skh\":\"" + hex8(skeletonSummaryHash) + "\",\"sk\":" + skeletonSummaryJson + "}";
  return s;
}

namespace {

bool fieldUInt(const char *json, size_t n, const char *key, uint32_t maxValue, uint32_t &out) {
  EscapeJson::Slice s;
  return EscapeJson::findField(json, n, key, s, 8) == EscapeJson::Scan::Found && EscapeJson::sliceToUInt(s, maxValue, out);
}

bool fieldText(const char *json, size_t n, const char *key, std::string &out) {
  EscapeJson::Slice s;
  return EscapeJson::findField(json, n, key, s, 8) == EscapeJson::Scan::Found && EscapeJson::sliceToString(s, out);
}

bool fieldHex8(const char *json, size_t n, const char *key, uint32_t &out) {
  std::string t;
  return fieldText(json, n, key, t) && parseHex8(t.data(), t.size(), out);
}

} // namespace

bool parseAnnouncement(const char *json, size_t length, Announcement &out) {
  memset(&out, 0, sizeof(out));
  uint32_t v = 0, port = 0, pmin = 0;
  std::string did, ip;
  if (!fieldUInt(json, length, "v", 255, v) || !fieldUInt(json, length, "port", 65535, port) || port == 0 ||
      !fieldUInt(json, length, "pmin", 255, pmin) || !fieldUInt(json, length, "boot", 0xFFFFFFFFu, out.boot) ||
      !fieldUInt(json, length, "ctr", 0xFFFFFFFFu, out.ctr) || !fieldUInt(json, length, "seq", 0xFFFFFFFFu, out.seq) ||
      !fieldText(json, length, "did", did) || !parseDid(did.data(), did.size(), out.did) ||
      !fieldText(json, length, "ip", ip) || ip.size() > 15 || !fieldHex8(json, length, "uih", out.uih) ||
      !fieldHex8(json, length, "skh", out.skh)) {
    return false;
  }
  uint8_t ipBytes[4];
  if (!parseIpv4(ip.data(), ip.size(), ipBytes)) return false;
  memcpy(out.ip, ip.c_str(), ip.size() + 1);
  out.version = (uint8_t)v;
  out.port = (uint16_t)port;
  out.pmin = (uint8_t)pmin;

  EscapeJson::Slice sk;
  if (EscapeJson::findField(json, length, "sk", sk, 8) != EscapeJson::Scan::Found || EscapeJson::sliceKind(sk) != 'a') return false;
  EscapeJson::Value arr;
  if (!EscapeJson::parse(sk.p, sk.n, arr, EscapeJson::ParseLimits(3, 1 + kMaxAnnouncedRooms * 4))) return false;
  if (arr.arrayValue.size() > kMaxAnnouncedRooms) return false;
  for (size_t i = 0; i < arr.arrayValue.size(); i++) {
    const EscapeJson::Value &e = arr.arrayValue[i];
    long long rev = 0;
    if (e.type != EscapeJson::Type::Array || e.arrayValue.size() != 3 ||
        e.arrayValue[0].type != EscapeJson::Type::String || e.arrayValue[2].type != EscapeJson::Type::String ||
        !e.arrayValue[1].asInt(0, 0xFFFFFFFFLL, rev)) {
      return false;
    }
    AnnouncedSkeleton &a = out.sk[out.skCount];
    if (!parseHex8(e.arrayValue[0].stringValue.data(), e.arrayValue[0].stringValue.size(), a.roomKey) ||
        !parseHex8(e.arrayValue[2].stringValue.data(), e.arrayValue[2].stringValue.size(), a.hash)) {
      return false;
    }
    a.rev = (uint32_t)rev;
    out.skCount++;
  }
  return true;
}

PeerTable::Result PeerTable::ingest(const Announcement &a, const char *sourceIp, const uint8_t ownDid[6],
                                    uint32_t nowMs) {
  if (memcmp(a.did, ownDid, 6) == 0) return Result::Own;
  if (!sourceIp || strcmp(sourceIp, a.ip) != 0) return Result::BadSource;
  uint8_t ipBytes[4];
  if (!parseIpv4(a.ip, strlen(a.ip), ipBytes)) return Result::BadSource;

  PeerEntry *entry = nullptr;
  for (size_t i = 0; i < count_; i++) {
    if (memcmp(peers_[i].did, a.did, 6) == 0) entry = &peers_[i];
  }
  if (entry) {
    if (!(a.boot > entry->boot || (a.boot == entry->boot && a.ctr > entry->ctr))) return Result::Replay;
  } else if (count_ < EscapeConfig::MAX_PEER_ADDRESSES) {
    entry = &peers_[count_++];
  } else {
    size_t oldest = 0; // table full: evict the peer heard longest ago
    for (size_t i = 1; i < count_; i++) {
      if ((int32_t)(peers_[oldest].lastSeenMs - peers_[i].lastSeenMs) > 0) oldest = i;
    }
    entry = &peers_[oldest];
  }
  memcpy(entry->did, a.did, 6);
  entry->proto = a.version;
  entry->pmin = a.pmin;
  entry->port = a.port;
  entry->ip = ipv4ToU32(ipBytes);
  entry->boot = a.boot;
  entry->ctr = a.ctr;
  entry->seq = a.seq;
  entry->uih = a.uih;
  entry->skh = a.skh;
  entry->lastSeenMs = nowMs;
  return Result::Accepted;
}

void PeerTable::expireStale(uint32_t nowMs, uint32_t timeoutMs) {
  size_t w = 0;
  for (size_t i = 0; i < count_; i++) {
    if (nowMs - peers_[i].lastSeenMs <= timeoutMs) {
      if (w != i) peers_[w] = peers_[i];
      w++;
    }
  }
  count_ = w;
}

const PeerEntry *PeerTable::findByDid(const uint8_t did[6]) const {
  for (size_t i = 0; i < count_; i++) {
    if (memcmp(peers_[i].did, did, 6) == 0) return &peers_[i];
  }
  return nullptr;
}

} // namespace Escape
