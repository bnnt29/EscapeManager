#pragma once

// Minimal, dependency-free JSON for the EscapeManager protocol (C++11, no Arduino
// headers, shared by the ESP32 firmware, the simulators and the native tests).
//
// Two ways to read JSON, chosen by how much memory the caller can afford:
//  * DOM (`Value` + `parse`): builds a tree. Only for SMALL bodies; hard limits on
//    nesting depth and node count bound the memory an input can cost.
//  * Scanner (`validate`, `findField`, `Slice`): no allocation at all. Used for
//    envelopes, plan slices and skeletons, which are passed through verbatim.
//
// Both implement strict RFC 8259 grammar: no leading zeros or '+', no control
// characters in strings, valid UTF-8, \u escapes with proper surrogate pairs, no
// embedded NUL, whitespace limited to space/tab/CR/LF, non-finite numbers rejected.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace EscapeJson {

enum class Type { Null, Bool, Number, String, Array, Object };

struct ParseLimits {
  size_t maxDepth;   // nesting levels of containers (root container = 1)
  size_t maxNodes;   // total number of values in the tree
  ParseLimits(size_t depth = 8, size_t nodes = 160) : maxDepth(depth), maxNodes(nodes) {}
};

class Value {
public:
  Type type = Type::Null;
  bool boolValue = false;
  double numberValue = 0;
  std::string stringValue;
  std::vector<Value> arrayValue;
  std::map<std::string, Value> objectValue;

  std::string asString(const std::string &def = "") const { return type == Type::String ? stringValue : def; }
  double asNumber(double def = 0) const { return type == Type::Number ? numberValue : def; }
  bool asBool(bool def = false) const { return type == Type::Bool ? boolValue : def; }

  const Value *find(const std::string &key) const {
    if (type != Type::Object) return nullptr;
    std::map<std::string, Value>::const_iterator it = objectValue.find(key);
    return it == objectValue.end() ? nullptr : &it->second;
  }

  // Strings as they are; numbers and bools converted to text (config values may
  // arrive as either).
  std::string asStringLoose() const;

  // Integer in [lo, hi] without fraction; false for anything else.
  bool asInt(long long lo, long long hi, long long &out) const;
};

// Parses "text" as exactly one JSON value. False on syntax errors, trailing
// characters, or when a limit is exceeded. Never throws.
bool parse(const std::string &text, Value &out, const ParseLimits &limits = ParseLimits());
bool parse(const char *text, size_t length, Value &out, const ParseLimits &limits = ParseLimits());

// Appends the JSON-escaped CONTENT of "s" (no surrounding quotes). Control
// characters become \u00XX so output always round-trips.
void appendEscaped(std::string &out, const char *s, size_t length);
void appendEscaped(std::string &out, const std::string &s);
inline void appendEscaped(std::string &out, const char *s) { if (s) appendEscaped(out, s, std::char_traits<char>::length(s)); }

// Number formatting without locale or printf-float pitfalls.
void appendUInt(std::string &out, uint32_t value);
void appendInt(std::string &out, int32_t value);
// Shortest round-trip-safe form; integers print without fraction; NaN/Inf -> null.
void appendNumber(std::string &out, double value);

// Re-serialises a parsed value compactly. Stops (returns false) if the output
// would exceed maxBytes (0 = unlimited).
bool stringify(const Value &v, std::string &out, size_t maxBytes = 0);

// ---- Allocation-free scanner ------------------------------------------------------

struct Slice {
  const char *p = nullptr;
  size_t n = 0;
  bool empty() const { return n == 0; }
  std::string str() const { return std::string(p ? p : "", n); }
};

enum class Scan { Found, Missing, Invalid };

// True iff [s, s+n) is exactly one valid JSON value within the depth limit.
bool validate(const char *s, size_t n, size_t maxDepth = 16);

// Finds a TOP-LEVEL member of a JSON object and returns the raw bytes of its value
// (strings include their quotes). Duplicate keys: the first wins. The whole
// document is validated; Invalid is returned for malformed input or non-objects.
Scan findField(const char *s, size_t n, const char *key, Slice &out, size_t maxDepth = 16);

// Decodes a slice that holds a JSON string (with quotes) into UTF-8 text.
bool sliceToString(const Slice &s, std::string &out);
// Integer without sign/fraction/exponent in [0, maxValue].
bool sliceToUInt(const Slice &s, uint32_t maxValue, uint32_t &out);
bool sliceToDouble(const Slice &s, double &out);
bool sliceToBool(const Slice &s, bool &out);
bool sliceIsNull(const Slice &s);
// Kind of the value: 'o'bject, 'a'rray, 's'tring, 'n'umber, 'b'ool, 'z' (null), 0 if empty.
char sliceKind(const Slice &s);

} // namespace EscapeJson
