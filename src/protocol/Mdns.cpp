#include "Mdns.hpp"

#include <cstring>

namespace Escape {

namespace {

inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
inline uint32_t rd32(const uint8_t *p) { return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
inline char lower(char c) { return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c; }

// Walks a (possibly compressed) name starting at `offset`. Compares it
// case-insensitively with `target` ("a.b.local") without allocating, and sets
// `next` to the offset just after the name in the original position.
// Returns false on malformed data.
bool readName(const uint8_t *p, size_t len, size_t offset, const char *target, bool &equal, size_t &next) {
  size_t pos = offset;
  size_t targetPos = 0;
  const size_t targetLen = strlen(target);
  bool jumped = false;
  size_t hops = 0;
  size_t total = 0;
  equal = true;
  next = offset;
  for (;;) {
    if (pos >= len) return false;
    const uint8_t l = p[pos];
    if (l == 0) {
      if (!jumped) next = pos + 1;
      if (targetPos != targetLen) equal = false;
      return true;
    }
    if ((l & 0xC0) == 0xC0) {
      if (pos + 1 >= len || ++hops > 6) return false;
      const size_t ptr = ((size_t)(l & 0x3F) << 8) | p[pos + 1];
      if (ptr >= len) return false;
      if (!jumped) next = pos + 2;
      jumped = true;
      pos = ptr;
      continue;
    }
    if ((l & 0xC0) != 0 || l > 63 || pos + 1 + l > len) return false;
    total += (size_t)l + 1;
    if (total > 255) return false;
    if (targetPos != 0) { // label separator in the target
      if (targetPos < targetLen && target[targetPos] == '.') targetPos++;
      else equal = false;
    }
    for (size_t i = 0; i < l; i++) {
      if (targetPos >= targetLen || lower(target[targetPos]) != lower((char)p[pos + 1 + i])) equal = false;
      else targetPos++;
    }
    pos += 1 + (size_t)l;
  }
}

} // namespace

MdnsQuery parseMdnsQuery(const uint8_t *p, size_t len, const char *hostname, const uint8_t ip[4],
                         uint32_t ttlSeconds) {
  MdnsQuery result = {false, false, false};
  if (len < 12 || len > 1500) return result;
  const uint16_t flags = rd16(p + 2);
  if (flags & 0x8000) return result;        // a response
  if ((flags >> 11) & 0x0F) return result;  // opcode != QUERY
  const uint16_t qd = rd16(p + 4), an = rd16(p + 6);
  if (qd == 0 || qd > 16 || an > 32) return result;
  size_t offset = 12;
  bool match = false, unicast = false;
  for (uint16_t i = 0; i < qd; i++) {
    bool equal = false;
    size_t next = 0;
    if (!readName(p, len, offset, hostname, equal, next) || next + 4 > len) return MdnsQuery{false, false, false};
    const uint16_t qtype = rd16(p + next), qclass = rd16(p + next + 2);
    offset = next + 4;
    if (equal && (qtype == 1 || qtype == 255) && (qclass & 0x7FFF) == 1) {
      match = true;
      unicast = unicast || (qclass & 0x8000) != 0;
    }
  }
  if (!match) return result;
  bool suppressed = false;
  for (uint16_t i = 0; i < an; i++) { // known answers
    bool equal = false;
    size_t next = 0;
    if (!readName(p, len, offset, hostname, equal, next) || next + 10 > len) break;
    const uint16_t type = rd16(p + next), cls = rd16(p + next + 2);
    const uint32_t ttl = rd32(p + next + 4);
    const uint16_t rdlen = rd16(p + next + 8);
    offset = next + 10;
    if (offset + rdlen > len) break;
    if (equal && type == 1 && (cls & 0x7FFF) == 1 && rdlen == 4 && memcmp(p + offset, ip, 4) == 0 &&
        ttl >= ttlSeconds / 2) {
      suppressed = true;
    }
    offset += rdlen;
  }
  result.matches = true;
  result.unicast = unicast;
  result.suppressed = suppressed;
  return result;
}

size_t buildMdnsAnswer(uint8_t *out, size_t capacity, const char *hostname, const uint8_t ip[4],
                       uint32_t ttlSeconds) {
  const size_t nameLen = strlen(hostname);
  if (nameLen == 0 || nameLen > 253) return 0;
  const size_t need = 12 + nameLen + 2 + 10 + 4;
  if (capacity < need) return 0;
  size_t o = 0;
  const uint8_t header[12] = {0, 0, 0x84, 0x00, 0, 0, 0, 1, 0, 0, 0, 0}; // QR, AA; one answer
  memcpy(out, header, 12);
  o = 12;
  const char *label = hostname;
  while (*label) { // encode labels
    const char *dot = strchr(label, '.');
    const size_t l = dot ? (size_t)(dot - label) : strlen(label);
    if (l == 0 || l > 63) return 0;
    out[o++] = (uint8_t)l;
    memcpy(out + o, label, l);
    o += l;
    label += l;
    if (*label == '.') label++;
  }
  out[o++] = 0;
  out[o++] = 0; out[o++] = 1;       // TYPE A
  out[o++] = 0; out[o++] = 1;       // CLASS IN, cache-flush bit NOT set (shared record)
  out[o++] = (uint8_t)(ttlSeconds >> 24); out[o++] = (uint8_t)(ttlSeconds >> 16);
  out[o++] = (uint8_t)(ttlSeconds >> 8);  out[o++] = (uint8_t)ttlSeconds;
  out[o++] = 0; out[o++] = 4;       // RDLENGTH
  memcpy(out + o, ip, 4);
  o += 4;
  return o;
}

} // namespace Escape
