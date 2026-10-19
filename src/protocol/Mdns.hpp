#pragma once

// Minimal mDNS responder logic (RFC 6762) for ONE shared A record, e.g.
// "escapemanager.local". Every device answers for the same name with its own address
// and without the cache-flush bit, so resolvers keep all addresses and can fail over
// when one device disappears (PROTOCOL.md section 7). Pure packet code: the socket
// handling lives in src/net.

#include <cstddef>
#include <cstdint>

namespace Escape {

struct MdnsQuery {
  bool matches;     // a question for our name (A or ANY, class IN)
  bool unicast;     // the question has the QU bit: answer the sender directly
  bool suppressed;  // known-answer suppression: the asker already has our address
};

// Parses a received datagram. `hostname` is the full name ("escapemanager.local").
// Responses (QR bit set) and anything malformed or oversized yield matches == false.
MdnsQuery parseMdnsQuery(const uint8_t *packet, size_t length, const char *hostname, const uint8_t ip[4],
                         uint32_t ttlSeconds);

// Writes an answer packet; returns its length (0 if `capacity` is too small).
size_t buildMdnsAnswer(uint8_t *out, size_t capacity, const char *hostname, const uint8_t ip[4],
                       uint32_t ttlSeconds);

// Random delay in [20, 120] ms for multicast answers (RFC 6762 section 6.3), derived
// from any 32-bit random value.
inline uint32_t mdnsResponseDelayMs(uint32_t random) { return 20 + random % 101; }

} // namespace Escape
