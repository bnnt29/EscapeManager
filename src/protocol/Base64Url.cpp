#include "Base64Url.hpp"

namespace Escape {

namespace {
const char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int decodeChar(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}
} // namespace

void base64UrlEncode(const uint8_t *data, size_t length, std::string &out) {
  out.clear();
  out.reserve((length * 4 + 2) / 3);
  size_t i = 0;
  for (; i + 3 <= length; i += 3) {
    const uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8) | data[i + 2];
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
    out.push_back(kAlphabet[v & 63]);
  }
  if (length - i == 1) {
    const uint32_t v = (uint32_t)data[i] << 16;
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
  } else if (length - i == 2) {
    const uint32_t v = ((uint32_t)data[i] << 16) | ((uint32_t)data[i + 1] << 8);
    out.push_back(kAlphabet[(v >> 18) & 63]);
    out.push_back(kAlphabet[(v >> 12) & 63]);
    out.push_back(kAlphabet[(v >> 6) & 63]);
  }
}

size_t base64UrlDecodedLength(size_t textLength) {
  const size_t rem = textLength % 4;
  if (rem == 1) return 0;
  return textLength / 4 * 3 + (rem == 0 ? 0 : rem - 1);
}

bool base64UrlDecode(const char *text, size_t length, std::vector<uint8_t> &out) {
  out.clear();
  if (length % 4 == 1) return false;
  out.reserve(base64UrlDecodedLength(length));
  size_t i = 0;
  for (; i + 4 <= length; i += 4) {
    int a = decodeChar(text[i]), b = decodeChar(text[i + 1]), c = decodeChar(text[i + 2]), d = decodeChar(text[i + 3]);
    if (a < 0 || b < 0 || c < 0 || d < 0) { out.clear(); return false; }
    const uint32_t v = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
    out.push_back((uint8_t)(v >> 16));
    out.push_back((uint8_t)(v >> 8));
    out.push_back((uint8_t)v);
  }
  const size_t rem = length - i;
  if (rem == 2) {
    int a = decodeChar(text[i]), b = decodeChar(text[i + 1]);
    if (a < 0 || b < 0 || (b & 0x0F) != 0) { out.clear(); return false; }
    out.push_back((uint8_t)((a << 2) | (b >> 4)));
  } else if (rem == 3) {
    int a = decodeChar(text[i]), b = decodeChar(text[i + 1]), c = decodeChar(text[i + 2]);
    if (a < 0 || b < 0 || c < 0 || (c & 0x03) != 0) { out.clear(); return false; }
    out.push_back((uint8_t)((a << 2) | (b >> 4)));
    out.push_back((uint8_t)(((b & 0x0F) << 4) | (c >> 2)));
  }
  return true;
}

void hexEncode(const uint8_t *data, size_t length, std::string &out) {
  static const char kHex[] = "0123456789abcdef";
  out.clear();
  out.reserve(length * 2);
  for (size_t i = 0; i < length; i++) {
    out.push_back(kHex[data[i] >> 4]);
    out.push_back(kHex[data[i] & 15]);
  }
}

bool hexDecode(const char *text, size_t length, std::vector<uint8_t> &out) {
  out.clear();
  if (length % 2) return false;
  for (size_t i = 0; i < length; i += 2) {
    int v[2];
    for (int k = 0; k < 2; k++) {
      const char c = text[i + k];
      if (c >= '0' && c <= '9') v[k] = c - '0';
      else if (c >= 'a' && c <= 'f') v[k] = c - 'a' + 10;
      else if (c >= 'A' && c <= 'F') v[k] = c - 'A' + 10;
      else { out.clear(); return false; }
    }
    out.push_back((uint8_t)(v[0] << 4 | v[1]));
  }
  return true;
}

} // namespace Escape
