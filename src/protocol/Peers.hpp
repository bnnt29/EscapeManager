#pragma once

// Peer discovery data (PROTOCOL.md 4.3): the announcement document and a compact,
// fixed-size table of the devices heard on the network. Entries only hold what
// discovery needs (address, counters, change fingerprints); full state is fetched on
// demand from the device itself, so the table stays small enough for a host program
// with little RAM (about 40 bytes per entry).

#include "EscapeConfig.hpp"

#include <cstdint>
#include <string>

namespace Escape {

constexpr size_t kMaxAnnouncedRooms = 8;

struct AnnouncedSkeleton {
  uint32_t roomKey;
  uint32_t rev;
  uint32_t hash;
};

struct Announcement {
  uint8_t did[6];
  char ip[16];
  uint16_t port;
  uint8_t version;   // `v`: protocol level used by the sender
  uint8_t pmin;
  uint32_t boot, ctr, seq, uih, skh;
  AnnouncedSkeleton sk[kMaxAnnouncedRooms];
  uint8_t skCount;
};

// "a.b.c.d" -> 4 bytes; strict (no leading zeros, no spaces).
bool parseIpv4(const char *text, size_t length, uint8_t out[4]);
uint32_t ipv4ToU32(const uint8_t ip[4]);
void u32ToIpv4Text(uint32_t ip, char out[16]);

// Device ids are 12 lowercase hex characters.
bool parseDid(const char *text, size_t length, uint8_t out[6]);
std::string didToText(const uint8_t did[6]);

// Builds the announcement DOC (before MAC framing).
std::string buildAnnouncementDoc(const std::string &did, const std::string &ip, uint16_t port, uint32_t boot,
                                 uint32_t ctr, uint32_t seq, uint8_t pmin, const std::string &uiHash,
                                 const std::string &skeletonSummaryJson, uint32_t skeletonSummaryHash);

// Strict parser of an announcement DOC; false for anything malformed or out of range.
bool parseAnnouncement(const char *json, size_t length, Announcement &out);

struct PeerEntry {
  uint8_t did[6];
  uint8_t proto;
  uint8_t pmin;
  uint16_t port;
  uint32_t ip;
  uint32_t boot, ctr, seq, uih, skh;
  uint32_t lastSeenMs;
};

class PeerTable {
public:
  enum class Result { Accepted, Own, BadSource, Replay };

  PeerTable() : count_(0) {}

  // Applies the freshness rules of PROTOCOL.md 4.3: the announced `ip` must equal the
  // datagram source, and (boot, ctr) must be strictly larger than the last accepted
  // pair of that device. The device's own announcements are ignored.
  Result ingest(const Announcement &a, const char *sourceIp, const uint8_t ownDid[6], uint32_t nowMs);

  // Drops peers silent for longer than timeoutMs.
  void expireStale(uint32_t nowMs, uint32_t timeoutMs = EscapeConfig::PEER_TIMEOUT_MS);

  size_t count() const { return count_; }
  const PeerEntry &at(size_t i) const { return peers_[i]; }
  const PeerEntry *findByDid(const uint8_t did[6]) const;
  void clear() { count_ = 0; }

private:
  PeerEntry peers_[EscapeConfig::MAX_PEER_ADDRESSES];
  size_t count_;
};

} // namespace Escape
