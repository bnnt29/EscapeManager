#pragma once

// Minimaler, abhaengigkeitsfreier JSON-Wert/Parser/Serialisierer fuer das
// EscapeManager-Protokoll. Reines std::string/std::vector-basiertes C++17 -
// bewusst OHNE Arduino.h/ArduinoJson, damit dieselbe Implementierung sowohl
// von der ESP32-Firmware (Client/client.cpp, ueber die Arduino-Toolchain,
// die std::string/std::vector unterstuetzt) als auch vom PC-Simulator
// (Sim/escape_component_sim.cpp, per plain g++) verwendet werden kann. Genau
// dieser Baustein war zuvor 1:1 dupliziert (einmal als ArduinoJson-Nutzung
// in client.cpp, einmal als eigener Parser in escape_component_sim.cpp).
//
// Deckt nur ab, was das Protokoll braucht: Objekte, Arrays, Strings, Zahlen,
// Bools, null - kein Anspruch auf einen vollstaendigen JSON-Standard
// (z.B. keine bewusste Unterstuetzung fuer sehr grosse Zahlen/BigInt).

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace EscapeJson {

enum class Type { Null, Bool, Number, String, Array, Object };

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
    auto it = objectValue.find(key);
    return it == objectValue.end() ? nullptr : &it->second;
  }

  // Wie ArduinoJson's JsonVariant::as<String>(): liefert auch Zahlen/Bools als
  // String statt nur echte JSON-Strings zu akzeptieren (wird beim Anwenden
  // von POST /config-Werten gebraucht, deren Typ vom Aufrufer variieren kann).
  std::string asStringLoose() const {
    switch (type) {
      case Type::String: return stringValue;
      case Type::Number: {
        if (numberValue == (long long)numberValue) return std::to_string((long long)numberValue);
        return std::to_string(numberValue);
      }
      case Type::Bool: return boolValue ? "true" : "false";
      default: return "";
    }
  }
};

// Parst "text" komplett als einen einzelnen JSON-Wert. Liefert false bei
// Syntaxfehlern oder ueberschuessigen Zeichen nach dem Wert.
bool parse(const std::string &text, Value &out);

// Haengt "s" JSON-escaped (Anfuehrungszeichen bereits inbegriffen NICHT
// gesetzt - nur der Inhalt zwischen den Quotes) an "out" an.
void appendEscaped(std::string &out, const std::string &s);

// Re-serialisiert einen (Teil-)Wert wieder in kompakten JSON-Text - fuer
// opake Bloecke wie den Ablaufplan-Slice, dessen Inhalt fuer Client/Sim
// bedeutungslos ist, der aber unveraendert weitergereicht werden muss.
void stringify(const Value &v, std::string &out);

} // namespace EscapeJson
