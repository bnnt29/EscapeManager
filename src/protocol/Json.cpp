// Implementation of Json.hpp (see there for the design rationale).

#include "Json.hpp"

#include "Compat.hpp"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace EscapeJson {

namespace {

inline bool isWs(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }
inline bool isDigit(char c) { return c >= '0' && c <= '9'; }

// Length (1..4) of the valid UTF-8 sequence starting at s[0], or 0 if invalid
// (overlong forms, surrogates and code points above U+10FFFF are rejected).
size_t utf8SeqLen(const unsigned char *s, size_t n) {
  const unsigned char c = s[0];
  if (c < 0x80) return 1;
  if (c >= 0xC2 && c <= 0xDF) return (n >= 2 && (s[1] & 0xC0) == 0x80) ? 2 : 0;
  if (c >= 0xE0 && c <= 0xEF) {
    if (n < 3 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80) return 0;
    if (c == 0xE0 && s[1] < 0xA0) return 0;
    if (c == 0xED && s[1] >= 0xA0) return 0;
    return 3;
  }
  if (c >= 0xF0 && c <= 0xF4) {
    if (n < 4 || (s[1] & 0xC0) != 0x80 || (s[2] & 0xC0) != 0x80 || (s[3] & 0xC0) != 0x80) return 0;
    if (c == 0xF0 && s[1] < 0x90) return 0;
    if (c == 0xF4 && s[1] >= 0x90) return 0;
    return 4;
  }
  return 0;
}

void appendUtf8(std::string &out, uint32_t cp) {
  if (cp < 0x80) {
    out.push_back((char)cp);
  } else if (cp < 0x800) {
    out.push_back((char)(0xC0 | (cp >> 6)));
    out.push_back((char)(0x80 | (cp & 0x3F)));
  } else if (cp < 0x10000) {
    out.push_back((char)(0xE0 | (cp >> 12)));
    out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back((char)(0x80 | (cp & 0x3F)));
  } else {
    out.push_back((char)(0xF0 | (cp >> 18)));
    out.push_back((char)(0x80 | ((cp >> 12) & 0x3F)));
    out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
    out.push_back((char)(0x80 | (cp & 0x3F)));
  }
}

struct Cursor {
  const char *s;
  size_t n;
  size_t i;
  Cursor(const char *text, size_t length) : s(text), n(length), i(0) {}
  bool eof() const { return i >= n; }
  void skipWs() { while (i < n && isWs(s[i])) i++; }
};

bool readHex4(Cursor &c, uint32_t &out) {
  if (c.n - c.i < 4) return false;
  uint32_t v = 0;
  for (int k = 0; k < 4; k++) {
    const char h = c.s[c.i + k];
    v <<= 4;
    if (h >= '0' && h <= '9') v |= (uint32_t)(h - '0');
    else if (h >= 'a' && h <= 'f') v |= (uint32_t)(h - 'a' + 10);
    else if (h >= 'A' && h <= 'F') v |= (uint32_t)(h - 'A' + 10);
    else return false;
  }
  c.i += 4;
  out = v;
  return true;
}

// Scans a string starting at the opening quote; appends the decoded text to *out
// when out is not null.
bool scanString(Cursor &c, std::string *out) {
  if (c.eof() || c.s[c.i] != '"') return false;
  c.i++;
  for (;;) {
    if (c.eof()) return false;
    const unsigned char ch = (unsigned char)c.s[c.i];
    if (ch == '"') {
      c.i++;
      return true;
    }
    if (ch < 0x20) return false;
    if (ch == '\\') {
      c.i++;
      if (c.eof()) return false;
      const char e = c.s[c.i++];
      switch (e) {
        case '"': case '\\': case '/': if (out) out->push_back(e); break;
        case 'b': if (out) out->push_back('\b'); break;
        case 'f': if (out) out->push_back('\f'); break;
        case 'n': if (out) out->push_back('\n'); break;
        case 'r': if (out) out->push_back('\r'); break;
        case 't': if (out) out->push_back('\t'); break;
        case 'u': {
          uint32_t cp = 0;
          if (!readHex4(c, cp)) return false;
          if (cp >= 0xD800 && cp <= 0xDBFF) {
            uint32_t low = 0;
            if (c.n - c.i < 2 || c.s[c.i] != '\\' || c.s[c.i + 1] != 'u') return false;
            c.i += 2;
            if (!readHex4(c, low) || low < 0xDC00 || low > 0xDFFF) return false;
            cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
          } else if (cp >= 0xDC00 && cp <= 0xDFFF) {
            return false; // lone low surrogate
          }
          if (cp == 0) return false; // embedded NUL
          if (out) appendUtf8(*out, cp);
          break;
        }
        default: return false;
      }
      continue;
    }
    if (ch >= 0x80) {
      const size_t len = utf8SeqLen((const unsigned char *)c.s + c.i, c.n - c.i);
      if (!len) return false;
      if (out) out->append(c.s + c.i, len);
      c.i += len;
      continue;
    }
    if (out) out->push_back((char)ch);
    c.i++;
  }
}

// Strict JSON number grammar. Optionally converts; non-finite results are rejected.
bool scanNumber(Cursor &c, double *out) {
  const size_t start = c.i;
  if (c.i < c.n && c.s[c.i] == '-') c.i++;
  if (c.eof()) return false;
  if (c.s[c.i] == '0') {
    c.i++;
  } else if (c.s[c.i] >= '1' && c.s[c.i] <= '9') {
    while (c.i < c.n && isDigit(c.s[c.i])) c.i++;
  } else {
    return false;
  }
  if (c.i < c.n && c.s[c.i] == '.') {
    c.i++;
    if (c.eof() || !isDigit(c.s[c.i])) return false;
    while (c.i < c.n && isDigit(c.s[c.i])) c.i++;
  }
  if (c.i < c.n && (c.s[c.i] == 'e' || c.s[c.i] == 'E')) {
    c.i++;
    if (c.i < c.n && (c.s[c.i] == '+' || c.s[c.i] == '-')) c.i++;
    if (c.eof() || !isDigit(c.s[c.i])) return false;
    while (c.i < c.n && isDigit(c.s[c.i])) c.i++;
  }
  const size_t len = c.i - start;
  if (len > 63) return false;
  if (out) {
    char buf[64];
    memcpy(buf, c.s + start, len);
    buf[len] = '\0';
    const double v = strtod(buf, nullptr);
    if (!std::isfinite(v)) return false;
    *out = v;
  }
  return true;
}

bool scanLiteral(Cursor &c, const char *word) {
  const size_t len = strlen(word);
  if (c.n - c.i < len || memcmp(c.s + c.i, word, len) != 0) return false;
  c.i += len;
  return true;
}

// Validating skip of one value (no allocation, small frame).
bool skipValue(Cursor &c, size_t depth, size_t maxDepth) {
  c.skipWs();
  if (c.eof()) return false;
  const char ch = c.s[c.i];
  if (ch == '{') {
    if (depth + 1 > maxDepth) return false;
    c.i++;
    c.skipWs();
    if (!c.eof() && c.s[c.i] == '}') { c.i++; return true; }
    for (;;) {
      c.skipWs();
      if (!scanString(c, nullptr)) return false;
      c.skipWs();
      if (c.eof() || c.s[c.i] != ':') return false;
      c.i++;
      if (!skipValue(c, depth + 1, maxDepth)) return false;
      c.skipWs();
      if (c.eof()) return false;
      if (c.s[c.i] == ',') { c.i++; continue; }
      if (c.s[c.i] == '}') { c.i++; return true; }
      return false;
    }
  }
  if (ch == '[') {
    if (depth + 1 > maxDepth) return false;
    c.i++;
    c.skipWs();
    if (!c.eof() && c.s[c.i] == ']') { c.i++; return true; }
    for (;;) {
      if (!skipValue(c, depth + 1, maxDepth)) return false;
      c.skipWs();
      if (c.eof()) return false;
      if (c.s[c.i] == ',') { c.i++; continue; }
      if (c.s[c.i] == ']') { c.i++; return true; }
      return false;
    }
  }
  if (ch == '"') return scanString(c, nullptr);
  if (ch == 't') return scanLiteral(c, "true");
  if (ch == 'f') return scanLiteral(c, "false");
  if (ch == 'n') return scanLiteral(c, "null");
  return scanNumber(c, nullptr);
}

// ---- DOM parser ---------------------------------------------------------------------

class DomParser {
public:
  DomParser(const char *s, size_t n, const ParseLimits &limits) : c_(s, n), limits_(limits), nodes_(0) {}

  bool parseDocument(Value &out) {
    if (!parseValue(out, 0)) return false;
    c_.skipWs();
    return c_.eof();
  }

private:
  Cursor c_;
  ParseLimits limits_;
  size_t nodes_;

  bool parseValue(Value &out, size_t depth) {
    if (++nodes_ > limits_.maxNodes) return false;
    c_.skipWs();
    if (c_.eof()) return false;
    const char ch = c_.s[c_.i];
    switch (ch) {
      case '{': return parseObject(out, depth + 1);
      case '[': return parseArray(out, depth + 1);
      case '"':
        out.type = Type::String;
        return scanString(c_, &out.stringValue);
      case 't':
        out.type = Type::Bool;
        out.boolValue = true;
        return scanLiteral(c_, "true");
      case 'f':
        out.type = Type::Bool;
        out.boolValue = false;
        return scanLiteral(c_, "false");
      case 'n':
        out.type = Type::Null;
        return scanLiteral(c_, "null");
      default:
        out.type = Type::Number;
        return scanNumber(c_, &out.numberValue);
    }
  }

  bool parseObject(Value &out, size_t depth) {
    if (depth > limits_.maxDepth) return false;
    out.type = Type::Object;
    c_.i++; // '{'
    c_.skipWs();
    if (!c_.eof() && c_.s[c_.i] == '}') { c_.i++; return true; }
    for (;;) {
      c_.skipWs();
      std::string key;
      if (!scanString(c_, &key)) return false;
      c_.skipWs();
      if (c_.eof() || c_.s[c_.i] != ':') return false;
      c_.i++;
      Value val;
      if (!parseValue(val, depth)) return false;
      // First occurrence wins, matching findField().
      if (out.objectValue.find(key) == out.objectValue.end()) out.objectValue.insert(std::make_pair(std::move(key), std::move(val)));
      c_.skipWs();
      if (c_.eof()) return false;
      if (c_.s[c_.i] == ',') { c_.i++; continue; }
      if (c_.s[c_.i] == '}') { c_.i++; return true; }
      return false;
    }
  }

  bool parseArray(Value &out, size_t depth) {
    if (depth > limits_.maxDepth) return false;
    out.type = Type::Array;
    c_.i++; // '['
    c_.skipWs();
    if (!c_.eof() && c_.s[c_.i] == ']') { c_.i++; return true; }
    for (;;) {
      Value val;
      if (!parseValue(val, depth)) return false;
      out.arrayValue.push_back(std::move(val));
      c_.skipWs();
      if (c_.eof()) return false;
      if (c_.s[c_.i] == ',') { c_.i++; continue; }
      if (c_.s[c_.i] == ']') { c_.i++; return true; }
      return false;
    }
  }
};

void appendInt64(std::string &out, long long v) {
  char buf[24];
  char *p = buf + sizeof(buf);
  const bool neg = v < 0;
  unsigned long long u = neg ? 0ULL - (unsigned long long)v : (unsigned long long)v;
  do { *--p = (char)('0' + (u % 10)); u /= 10; } while (u);
  if (neg) *--p = '-';
  out.append(p, (size_t)(buf + sizeof(buf) - p));
}

bool stringifyInto(const Value &v, std::string &out, size_t maxBytes) {
  if (maxBytes && out.size() > maxBytes) return false;
  switch (v.type) {
    case Type::Null: out += "null"; break;
    case Type::Bool: out += v.boolValue ? "true" : "false"; break;
    case Type::Number: appendNumber(out, v.numberValue); break;
    case Type::String:
      out += '"';
      appendEscaped(out, v.stringValue);
      out += '"';
      break;
    case Type::Array:
      out += '[';
      for (size_t i = 0; i < v.arrayValue.size(); i++) {
        if (i) out += ',';
        if (!stringifyInto(v.arrayValue[i], out, maxBytes)) return false;
      }
      out += ']';
      break;
    case Type::Object: {
      out += '{';
      bool first = true;
      for (std::map<std::string, Value>::const_iterator it = v.objectValue.begin(); it != v.objectValue.end(); ++it) {
        if (!first) out += ',';
        first = false;
        out += '"';
        appendEscaped(out, it->first);
        out += "\":";
        if (!stringifyInto(it->second, out, maxBytes)) return false;
      }
      out += '}';
      break;
    }
  }
  return !(maxBytes && out.size() > maxBytes);
}

} // namespace

// ---- Value ---------------------------------------------------------------------------

std::string Value::asStringLoose() const {
  switch (type) {
    case Type::String: return stringValue;
    case Type::Number: {
      std::string s;
      appendNumber(s, numberValue);
      return s;
    }
    case Type::Bool: return boolValue ? "true" : "false";
    default: return "";
  }
}

bool Value::asInt(long long lo, long long hi, long long &out) const {
  if (type != Type::Number || !std::isfinite(numberValue)) return false;
  if (numberValue < (double)lo || numberValue > (double)hi) return false;
  if (numberValue != std::floor(numberValue)) return false;
  out = (long long)numberValue;
  return true;
}

// ---- Public API ---------------------------------------------------------------------------

bool parse(const char *text, size_t length, Value &out, const ParseLimits &limits) {
  return Escape::guardAlloc([&]() -> bool {
    out = Value();
    DomParser parser(text, length, limits);
    if (parser.parseDocument(out)) return true;
    out = Value();
    return false;
  }, false);
}

bool parse(const std::string &text, Value &out, const ParseLimits &limits) {
  return parse(text.data(), text.size(), out, limits);
}

void appendEscaped(std::string &out, const char *s, size_t length) {
  static const char kHex[] = "0123456789abcdef";
  size_t i = 0;
  while (i < length) {
    const unsigned char c = (unsigned char)s[i];
    if (c >= 0x20 && c != '"' && c != '\\' && c < 0x80) {
      out.push_back((char)c);
      i++;
      continue;
    }
    if (c >= 0x80) {
      const size_t len = utf8SeqLen((const unsigned char *)s + i, length - i);
      if (len) {
        out.append(s + i, len);
        i += len;
      } else {
        out += "\\ufffd"; // invalid byte (e.g. a multi-byte character cut by a size limit)
        i++;
      }
      continue;
    }
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        out += "\\u00";
        out.push_back(kHex[c >> 4]);
        out.push_back(kHex[c & 0xF]);
    }
    i++;
  }
}

void appendEscaped(std::string &out, const std::string &s) { appendEscaped(out, s.data(), s.size()); }

void appendUInt(std::string &out, uint32_t value) { appendInt64(out, (long long)value); }
void appendInt(std::string &out, int32_t value) { appendInt64(out, (long long)value); }

void appendNumber(std::string &out, double value) {
  if (!std::isfinite(value)) {
    out += "null";
    return;
  }
  if (value == std::floor(value) && std::fabs(value) < 1e15) {
    appendInt64(out, (long long)value);
    return;
  }
  char buf[40];
  snprintf(buf, sizeof(buf), "%.15g", value);
  if (strtod(buf, nullptr) != value) snprintf(buf, sizeof(buf), "%.17g", value);
  out += buf;
}

bool stringify(const Value &v, std::string &out, size_t maxBytes) {
  return Escape::guardAlloc([&]() -> bool { return stringifyInto(v, out, maxBytes); }, false);
}

bool validate(const char *s, size_t n, size_t maxDepth) {
  Cursor c(s, n);
  if (!skipValue(c, 0, maxDepth)) return false;
  c.skipWs();
  return c.eof();
}

Scan findField(const char *s, size_t n, const char *key, Slice &out, size_t maxDepth) {
  out = Slice();
  Cursor c(s, n);
  c.skipWs();
  if (c.eof() || c.s[c.i] != '{') return Scan::Invalid;
  c.i++;
  c.skipWs();
  bool found = false;
  if (!c.eof() && c.s[c.i] == '}') {
    c.i++;
  } else {
    for (;;) {
      c.skipWs();
      const size_t keyStart = c.i;
      // Compare the raw key first (common case: no escapes) without allocating.
      std::string decoded;
      Cursor kc = c;
      if (!scanString(kc, nullptr)) return Scan::Invalid;
      bool equal = false;
      if (!found) {
        const size_t rawLen = kc.i - keyStart - 2;
        const char *raw = c.s + keyStart + 1;
        if (memchr(raw, '\\', rawLen) == nullptr) {
          equal = rawLen == strlen(key) && memcmp(raw, key, rawLen) == 0;
        } else {
          Cursor dc = c;
          if (!Escape::guardAlloc([&]() -> bool { return scanString(dc, &decoded); }, false)) return Scan::Invalid;
          equal = decoded == key;
        }
      }
      c.i = kc.i;
      c.skipWs();
      if (c.eof() || c.s[c.i] != ':') return Scan::Invalid;
      c.i++;
      c.skipWs();
      const size_t valueStart = c.i;
      if (!skipValue(c, 1, maxDepth)) return Scan::Invalid;
      if (equal && !found) {
        found = true;
        out.p = c.s + valueStart;
        out.n = c.i - valueStart;
      }
      c.skipWs();
      if (c.eof()) return Scan::Invalid;
      if (c.s[c.i] == ',') { c.i++; continue; }
      if (c.s[c.i] == '}') { c.i++; break; }
      return Scan::Invalid;
    }
  }
  c.skipWs();
  if (!c.eof()) return Scan::Invalid;
  return found ? Scan::Found : Scan::Missing;
}

bool sliceToString(const Slice &s, std::string &out) {
  if (!s.p || s.n < 2) return false;
  Cursor c(s.p, s.n);
  std::string tmp;
  if (!Escape::guardAlloc([&]() -> bool { return scanString(c, &tmp); }, false) || c.i != s.n) return false;
  out.swap(tmp);
  return true;
}

bool sliceToUInt(const Slice &s, uint32_t maxValue, uint32_t &out) {
  if (!s.p || s.n == 0 || s.n > 10) return false;
  if (s.n > 1 && s.p[0] == '0') return false;
  unsigned long long v = 0;
  for (size_t i = 0; i < s.n; i++) {
    if (!isDigit(s.p[i])) return false;
    v = v * 10 + (unsigned)(s.p[i] - '0');
  }
  if (v > maxValue) return false;
  out = (uint32_t)v;
  return true;
}

bool sliceToDouble(const Slice &s, double &out) {
  if (!s.p || !s.n) return false;
  Cursor c(s.p, s.n);
  double v = 0;
  if (!scanNumber(c, &v) || c.i != s.n) return false;
  out = v;
  return true;
}

bool sliceToBool(const Slice &s, bool &out) {
  if (s.n == 4 && memcmp(s.p, "true", 4) == 0) { out = true; return true; }
  if (s.n == 5 && memcmp(s.p, "false", 5) == 0) { out = false; return true; }
  return false;
}

bool sliceIsNull(const Slice &s) { return s.n == 4 && memcmp(s.p, "null", 4) == 0; }

char sliceKind(const Slice &s) {
  if (!s.p || !s.n) return 0;
  switch (s.p[0]) {
    case '{': return 'o';
    case '[': return 'a';
    case '"': return 's';
    case 't': case 'f': return 'b';
    case 'n': return 'z';
    case '-': case '0': case '1': case '2': case '3': case '4':
    case '5': case '6': case '7': case '8': case '9': return 'n';
    default: return 0;
  }
}

} // namespace EscapeJson
