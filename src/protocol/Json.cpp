// Implementierung von Json.hpp (siehe dort fuer Design-Rationale).

#include "Json.hpp"

#include <cctype>
#include <cstdlib>

namespace EscapeJson {

namespace {

const size_t kMaxJsonDepth = 24;

// Haengt einen Unicode-Codepoint UTF-8-kodiert an - fuer \uXXXX-Escapes
// (inkl. UTF-16-Surrogatpaaren fuer Codepoints > 0xFFFF). Im Unterschied zu
// einer frueheren, vereinfachten Sim-only-Fassung (die nur bis 0xFF direkt
// uebernahm) hier vollstaendig, weil dieser Parser jetzt auch von der
// ESP32-Firmware genutzt wird und Namen/Texte beliebige Unicode-Zeichen
// enthalten koennen.
void appendUtf8(std::string &out, uint32_t cp) {
  if (cp <= 0x7F) {
    out += (char)cp;
  } else if (cp <= 0x7FF) {
    out += (char)(0xC0 | (cp >> 6));
    out += (char)(0x80 | (cp & 0x3F));
  } else if (cp <= 0xFFFF) {
    out += (char)(0xE0 | (cp >> 12));
    out += (char)(0x80 | ((cp >> 6) & 0x3F));
    out += (char)(0x80 | (cp & 0x3F));
  } else {
    out += (char)(0xF0 | (cp >> 18));
    out += (char)(0x80 | ((cp >> 12) & 0x3F));
    out += (char)(0x80 | ((cp >> 6) & 0x3F));
    out += (char)(0x80 | (cp & 0x3F));
  }
}

class Parser {
public:
  // Nimmt den String per Wert (statt per Referenz), damit auch temporaere
  // Strings sicher sind - eine gespeicherte Referenz auf ein Temporary waere
  // nach dem Konstruktoraufruf dangling (undefined behavior).
  explicit Parser(std::string s) : s_(std::move(s)), i_(0) {}

  bool parseDocument(Value &out) {
    skipWs();
    if (!parseValue(out, 0)) return false;
    skipWs();
    return eof(); // keine ueberschuessigen Zeichen nach dem Wert erlaubt
  }

private:
  std::string s_;
  size_t i_;

  void skipWs() { while (i_ < s_.size() && std::isspace((unsigned char)s_[i_])) i_++; }
  bool eof() const { return i_ >= s_.size(); }
  char peek() const { return s_[i_]; }

  bool parseValue(Value &out, size_t depth) {
    skipWs();
    if (eof() || depth > kMaxJsonDepth) return false;
    switch (peek()) {
      case '{': return parseObject(out, depth);
      case '[': return parseArray(out, depth);
      case '"': return parseString(out);
      case 't':
      case 'f': return parseBool(out);
      case 'n': return parseNull(out);
      default: return parseNumber(out);
    }
  }

  bool parseObject(Value &out, size_t depth) {
    out = Value();
    out.type = Type::Object;
    i_++;
    skipWs();
    if (!eof() && peek() == '}') { i_++; return true; }
    while (true) {
      skipWs();
      Value keyVal;
      if (eof() || peek() != '"' || !parseString(keyVal)) return false;
      skipWs();
      if (eof() || peek() != ':') return false;
      i_++;
      Value val;
      if (!parseValue(val, depth + 1)) return false;
      out.objectValue[keyVal.stringValue] = std::move(val);
      skipWs();
      if (eof()) return false;
      if (peek() == ',') { i_++; continue; }
      if (peek() == '}') { i_++; break; }
      return false;
    }
    return true;
  }

  bool parseArray(Value &out, size_t depth) {
    out = Value();
    out.type = Type::Array;
    i_++;
    skipWs();
    if (!eof() && peek() == ']') { i_++; return true; }
    while (true) {
      Value val;
      if (!parseValue(val, depth + 1)) return false;
      out.arrayValue.push_back(std::move(val));
      skipWs();
      if (eof()) return false;
      if (peek() == ',') { i_++; continue; }
      if (peek() == ']') { i_++; break; }
      return false;
    }
    return true;
  }

  // Liest genau 4 Hex-Ziffern ab der aktuellen Position (fuer \uXXXX).
  bool readHex4(unsigned &out) {
    if (i_ + 4 > s_.size()) return false;
    for (int k = 0; k < 4; k++) {
      if (!std::isxdigit((unsigned char)s_[i_ + k])) return false;
    }
    out = (unsigned)std::stoul(s_.substr(i_, 4), nullptr, 16);
    i_ += 4;
    return true;
  }

  bool parseString(Value &out) {
    out = Value();
    out.type = Type::String;
    if (eof() || peek() != '"') return false;
    i_++;
    std::string result;
    while (true) {
      if (eof()) return false;
      char c = s_[i_++];
      if (c == '"') break;
      if ((uint8_t)c < 0x20) return false; // unescaped control character: ungueltiges JSON
      if (c == '\\') {
        if (eof()) return false;
        char e = s_[i_++];
        switch (e) {
          case '"': result += '"'; break;
          case '\\': result += '\\'; break;
          case '/': result += '/'; break;
          case 'n': result += '\n'; break;
          case 'r': result += '\r'; break;
          case 't': result += '\t'; break;
          case 'b': result += '\b'; break;
          case 'f': result += '\f'; break;
          case 'u': {
            unsigned code;
            if (!readHex4(code)) return false;
            // UTF-16-Surrogatpaar (Codepoints > 0xFFFF werden als zwei
            // \uXXXX-Escapes kodiert) zu einem echten Codepoint zusammenfassen.
            if (code >= 0xD800 && code <= 0xDBFF) {
              if (i_ + 2 > s_.size() || s_[i_] != '\\' || s_[i_ + 1] != 'u') return false;
              i_ += 2;
              unsigned low;
              if (!readHex4(low)) return false;
              if (low < 0xDC00 || low > 0xDFFF) return false;
              uint32_t combined = 0x10000 + (((uint32_t)code - 0xD800) << 10) + (low - 0xDC00);
              appendUtf8(result, combined);
            } else {
              appendUtf8(result, code);
            }
            break;
          }
          default: return false;
        }
      } else {
        result += c;
      }
    }
    out.stringValue = std::move(result);
    return true;
  }

  bool parseBool(Value &out) {
    if (s_.compare(i_, 4, "true") == 0) {
      out = Value(); out.type = Type::Bool; out.boolValue = true; i_ += 4; return true;
    }
    if (s_.compare(i_, 5, "false") == 0) {
      out = Value(); out.type = Type::Bool; out.boolValue = false; i_ += 5; return true;
    }
    return false;
  }

  bool parseNull(Value &out) {
    if (s_.compare(i_, 4, "null") == 0) { out = Value(); out.type = Type::Null; i_ += 4; return true; }
    return false;
  }

  bool parseNumber(Value &out) {
    size_t start = i_;
    if (!eof() && peek() == '-') i_++;
    while (!eof() && (std::isdigit((unsigned char)peek()) || peek() == '.' || peek() == 'e' || peek() == 'E' ||
                      peek() == '-' || peek() == '+')) {
      i_++;
    }
    if (i_ == start) return false;
    try {
      out = Value();
      out.type = Type::Number;
      out.numberValue = std::stod(s_.substr(start, i_ - start));
    } catch (...) {
      return false;
    }
    return true;
  }
};

} // namespace

bool parse(const std::string &text, Value &out) {
  Parser parser(text);
  return parser.parseDocument(out);
}

void appendEscaped(std::string &out, const std::string &s) {
  for (unsigned char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if (c >= 0x20) out += (char)c; // sonstige Steuerzeichen verwerfen
    }
  }
}

void stringify(const Value &v, std::string &out) {
  switch (v.type) {
    case Type::Null:
      out += "null";
      break;
    case Type::Bool:
      out += v.boolValue ? "true" : "false";
      break;
    case Type::Number: {
      double d = v.numberValue;
      if (d == (long long)d) out += std::to_string((long long)d);
      else out += std::to_string(d);
      break;
    }
    case Type::String:
      out += '"';
      appendEscaped(out, v.stringValue);
      out += '"';
      break;
    case Type::Array: {
      out += '[';
      for (size_t i = 0; i < v.arrayValue.size(); i++) {
        if (i) out += ',';
        stringify(v.arrayValue[i], out);
      }
      out += ']';
      break;
    }
    case Type::Object: {
      out += '{';
      bool first = true;
      for (auto &kv : v.objectValue) {
        if (!first) out += ',';
        first = false;
        out += '"'; appendEscaped(out, kv.first); out += "\":";
        stringify(kv.second, out);
      }
      out += '}';
      break;
    }
  }
}

} // namespace EscapeJson
