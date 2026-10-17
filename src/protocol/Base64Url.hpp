#pragma once

// base64url without padding (RFC 4648 section 5). Decoding is strict and canonical:
// only the url-safe alphabet, no padding, and unused trailing bits must be zero, so
// every byte string has exactly one accepted text form (important for replay
// caches keyed by IV text).

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Escape {

void base64UrlEncode(const uint8_t *data, size_t length, std::string &out);
inline std::string base64UrlEncode(const uint8_t *data, size_t length) {
  std::string s;
  base64UrlEncode(data, length, s);
  return s;
}
bool base64UrlDecode(const char *text, size_t length, std::vector<uint8_t> &out);
inline bool base64UrlDecode(const std::string &text, std::vector<uint8_t> &out) {
  return base64UrlDecode(text.data(), text.size(), out);
}
// Decoded length of a valid text of the given length (0 if the length is impossible).
size_t base64UrlDecodedLength(size_t textLength);

// Lowercase hex helpers (used for hashes and tests).
void hexEncode(const uint8_t *data, size_t length, std::string &out);
bool hexDecode(const char *text, size_t length, std::vector<uint8_t> &out);

} // namespace Escape
