// Simuliert eine Escape-Room-Komponente auf dem PC (Gegenstueck zu
// escape_component_sim.py). Implementiert exakt dasselbe Protokoll wie die
// ESP32-Firmware (Client/client.hpp + client.cpp) und Manager/manager.html:
//   - UDP-Broadcast (Heartbeat + Jitter + Change-getriebene Broadcasts)
//   - UDP-Empfang fremder Broadcasts -> eigene Peer-Tabelle
//   - HTTP GET  /             (liefert Manager/manager.html, wie die ESP32-Firmware)
//   - HTTP GET  /status.json  (eigener Zustand + bekannte Peers, unauthentifiziert)
//   - HTTP POST /action       (X-Auth-Token erforderlich)
//   - HTTP POST /config       (X-Auth-Token erforderlich, setzt Name/Raum)
//
// Nutzt nur POSIX-Sockets (Linux/macOS), keine externen Abhaengigkeiten.
//
// Bauen:   g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp
// Starten: ./escape_component_sim --name Laser-1 --room Raum-A --http-port 8080
//
// Hinweis Portwahl: manager.html und die ESP32-Firmware gehen von Port 80 fuer
// /action und /config aus (keine Port-Angabe in der URL). Auf einem PC laufen
// mehrere Simulator-Instanzen mit derselben IP - jede braucht daher einen
// eigenen --http-port, wenn mehrere gleichzeitig laufen sollen. Aktionen ueber
// die Manager-Oberflaeche funktionieren dann nur fuer die Instanz auf Port 80
// (ggf. root/CAP_NET_BIND_SERVICE noetig). Fuer volle Mehrkomponenten-Tests mit
// funktionierenden Aktions-Buttons empfiehlt sich je Instanz eine eigene IP
// (z.B. per Docker-Container/Netzwerk-Namespace).

/*
cd Sim
g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp


sudo ./escape_component_sim --name Laser-1 --room Raum-A
# oder ohne sudo:
./escape_component_sim --name Laser-1 --room Raum-A --http-port 8080
*/

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <unistd.h>
#ifdef __linux__
#include <net/if.h>
#endif

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

namespace SimConfig {
// Muessen zu Client/client.hpp (EscapeConfig) passen, damit das Verhalten
// (Broadcast-Timing, Kapazitaeten) identisch zur echten ESP32-Firmware ist.
constexpr size_t MAX_PEERS = 24;
constexpr int PEER_TIMEOUT_S = 20;
constexpr double HEARTBEAT_INTERVAL_S = 4.0;
constexpr double HEARTBEAT_JITTER_S = 0.75;
constexpr double CHANGE_MIN_GAP_S = 0.3;
constexpr size_t MAX_NAME_LEN = 32;
constexpr size_t MAX_ROOM_LEN = 32;
constexpr size_t MAX_ERRORS = 4;
constexpr size_t MAX_ERROR_LEN = 32;
constexpr size_t MAX_ACTIONS = 8;
constexpr size_t MAX_ACTION_LEN = 24;
constexpr size_t MAX_FEED_LEN = 96;
constexpr size_t MAX_STATE_LEN = 512;
constexpr size_t MAX_CUSTOM_CONFIGS = 4;
constexpr size_t MAX_CONFIG_OPTIONS = 6;
} // namespace SimConfig

namespace {

std::string toLower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
  return r;
}

std::string clip(const std::string &s, size_t maxLen) {
  return s.size() > maxLen ? s.substr(0, maxLen) : s;
}

void appendJsonEscaped(std::string &out, const std::string &s) {
  for (char c : s) {
    switch (c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if ((unsigned char)c >= 0x20) out += c; // sonstige Steuerzeichen verwerfen
    }
  }
}

// Wie EscapeConfig::AUTH_TOKEN-Vergleich in client.cpp: kein Frueh-Abbruch,
// um Timing-Angriffe auf den Auth-Token zu erschweren.
bool constantTimeEquals(const std::string &a, const std::string &b) {
  uint8_t diff = (uint8_t)(a.size() != b.size());
  size_t n = std::min(a.size(), b.size());
  for (size_t i = 0; i < n; i++) diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  return diff == 0;
}

// ---- Minimaler JSON-Parser/-Wert (kein externes JSON-Lib noetig) -----------
// Deckt genau ab, was das Protokoll braucht: Objekte, Arrays, Strings,
// Zahlen, Bools, null.
struct JsonValue {
  enum class Type { Null, Bool, Number, String, Array, Object } type = Type::Null;
  bool boolValue = false;
  double numberValue = 0;
  std::string stringValue;
  std::vector<JsonValue> arrayValue;
  std::map<std::string, JsonValue> objectValue;

  std::string asString(const std::string &def = "") const { return type == Type::String ? stringValue : def; }
  double asNumber(double def = 0) const { return type == Type::Number ? numberValue : def; }
  bool asBool(bool def = false) const { return type == Type::Bool ? boolValue : def; }

  const JsonValue *find(const std::string &key) const {
    if (type != Type::Object) return nullptr;
    auto it = objectValue.find(key);
    return it == objectValue.end() ? nullptr : &it->second;
  }

  // Wie ArduinoJson's JsonVariant::as<String>(): liefert auch Zahlen/Bools als
  // String, statt nur echte JSON-Strings zu akzeptieren (wird u.a. beim
  // Anwenden von POST /config-Werten gebraucht).
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

class JsonParser {
public:
  // Nimmt den String per Wert (statt per Referenz), damit auch temporaere
  // Strings (z.B. JsonParser(std::string(buf, n))) sicher sind - eine
  // gespeicherte Referenz auf ein Temporary waere nach dem Konstruktoraufruf
  // dangling (undefined behavior).
  explicit JsonParser(std::string s) : s_(std::move(s)), i_(0) {}

  bool parse(JsonValue &out) {
    skipWs();
    return parseValue(out);
  }

private:
  std::string s_;
  size_t i_;

  void skipWs() { while (i_ < s_.size() && std::isspace((unsigned char)s_[i_])) i_++; }
  bool eof() const { return i_ >= s_.size(); }
  char peek() const { return s_[i_]; }

  bool parseValue(JsonValue &out) {
    skipWs();
    if (eof()) return false;
    switch (peek()) {
      case '{': return parseObject(out);
      case '[': return parseArray(out);
      case '"': return parseString(out);
      case 't':
      case 'f': return parseBool(out);
      case 'n': return parseNull(out);
      default: return parseNumber(out);
    }
  }

  bool parseObject(JsonValue &out) {
    out = JsonValue();
    out.type = JsonValue::Type::Object;
    i_++;
    skipWs();
    if (!eof() && peek() == '}') { i_++; return true; }
    while (true) {
      skipWs();
      JsonValue keyVal;
      if (eof() || peek() != '"' || !parseString(keyVal)) return false;
      skipWs();
      if (eof() || peek() != ':') return false;
      i_++;
      JsonValue val;
      if (!parseValue(val)) return false;
      out.objectValue[keyVal.stringValue] = std::move(val);
      skipWs();
      if (eof()) return false;
      if (peek() == ',') { i_++; continue; }
      if (peek() == '}') { i_++; break; }
      return false;
    }
    return true;
  }

  bool parseArray(JsonValue &out) {
    out = JsonValue();
    out.type = JsonValue::Type::Array;
    i_++;
    skipWs();
    if (!eof() && peek() == ']') { i_++; return true; }
    while (true) {
      JsonValue val;
      if (!parseValue(val)) return false;
      out.arrayValue.push_back(std::move(val));
      skipWs();
      if (eof()) return false;
      if (peek() == ',') { i_++; continue; }
      if (peek() == ']') { i_++; break; }
      return false;
    }
    return true;
  }

  bool parseString(JsonValue &out) {
    out = JsonValue();
    out.type = JsonValue::Type::String;
    if (eof() || peek() != '"') return false;
    i_++;
    std::string result;
    while (true) {
      if (eof()) return false;
      char c = s_[i_++];
      if (c == '"') break;
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
            if (i_ + 4 > s_.size()) return false;
            // Vereinfachtes \uXXXX: nur bis 0xFF direkt uebernehmen, hoehere
            // Codepoints werden als '?' dargestellt (fuer dieses Testwerkzeug ausreichend).
            unsigned code = (unsigned)std::stoul(s_.substr(i_, 4), nullptr, 16);
            i_ += 4;
            result += (code <= 0xFF) ? (char)code : '?';
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

  bool parseBool(JsonValue &out) {
    if (s_.compare(i_, 4, "true") == 0) {
      out = JsonValue(); out.type = JsonValue::Type::Bool; out.boolValue = true; i_ += 4; return true;
    }
    if (s_.compare(i_, 5, "false") == 0) {
      out = JsonValue(); out.type = JsonValue::Type::Bool; out.boolValue = false; i_ += 5; return true;
    }
    return false;
  }

  bool parseNull(JsonValue &out) {
    if (s_.compare(i_, 4, "null") == 0) { out = JsonValue(); out.type = JsonValue::Type::Null; i_ += 4; return true; }
    return false;
  }

  bool parseNumber(JsonValue &out) {
    size_t start = i_;
    if (!eof() && (peek() == '-' || peek() == '+')) i_++;
    while (!eof() && (std::isdigit((unsigned char)peek()) || peek() == '.' || peek() == 'e' || peek() == 'E' ||
                      peek() == '-' || peek() == '+')) {
      i_++;
    }
    if (i_ == start) return false;
    try {
      out = JsonValue();
      out.type = JsonValue::Type::Number;
      out.numberValue = std::stod(s_.substr(start, i_ - start));
    } catch (...) {
      return false;
    }
    return true;
  }
};

// Re-serialisiert einen bereits geparsten JsonValue-(Teil-)Baum zurueck in
// kompakten JSON-Text - fuer den Ablaufplan-Slice (siehe ComponentState::plan_
// / Peer::plan): der Sim versteht dessen Inhalt nicht, muss ihn aber aus einem
// eingehenden Broadcast/POST-Body wieder als roher JSON-Text weiterreichen
// koennen (analog serializeJson(comp["plan"], ...) in Client/client.cpp).
void stringifyJsonValue(const JsonValue &v, std::string &out) {
  switch (v.type) {
    case JsonValue::Type::Null:
      out += "null";
      break;
    case JsonValue::Type::Bool:
      out += v.boolValue ? "true" : "false";
      break;
    case JsonValue::Type::Number: {
      double d = v.numberValue;
      if (d == (long long)d) out += std::to_string((long long)d);
      else out += std::to_string(d);
      break;
    }
    case JsonValue::Type::String:
      out += '"';
      appendJsonEscaped(out, v.stringValue);
      out += '"';
      break;
    case JsonValue::Type::Array: {
      out += '[';
      for (size_t i = 0; i < v.arrayValue.size(); i++) {
        if (i) out += ',';
        stringifyJsonValue(v.arrayValue[i], out);
      }
      out += ']';
      break;
    }
    case JsonValue::Type::Object: {
      out += '{';
      bool first = true;
      for (auto &kv : v.objectValue) {
        if (!first) out += ',';
        first = false;
        out += '"'; appendJsonEscaped(out, kv.first); out += "\":";
        stringifyJsonValue(kv.second, out);
      }
      out += '}';
      break;
    }
  }
}

// Beschreibt ein einzelnes, komponentenspezifisches Konfigurationsfeld (Name/
// Schluessel, Typ, erlaubte Werte) inkl. aktuellem Wert - analog zu
// CustomConfigDef in Client/client.hpp. "value" wird immer als String
// transportiert, unabhaengig vom Typ (vereinfacht das Protokoll).
struct CustomConfigDef {
  std::string key;
  std::string type; // "range" | "text" | "select"
  int rangeMin = 0, rangeMax = 0;     // nur bei "range"
  int textMaxLen = 0;                  // nur bei "text"
  std::vector<std::string> options;    // nur bei "select"
  std::string value;
};

void writeCustomConfigDefJson(std::string &out, const CustomConfigDef &d) {
  out += '{';
  out += "\"key\":\""; appendJsonEscaped(out, d.key); out += "\",";
  out += "\"type\":\""; appendJsonEscaped(out, d.type); out += "\",";
  if (d.type == "range") {
    out += "\"min\":" + std::to_string(d.rangeMin) + ",";
    out += "\"max\":" + std::to_string(d.rangeMax) + ",";
  } else if (d.type == "text") {
    out += "\"maxLength\":" + std::to_string(d.textMaxLen) + ",";
  } else if (d.type == "select") {
    out += "\"options\":[";
    for (size_t i = 0; i < d.options.size(); i++) {
      if (i) out += ',';
      out += '"'; appendJsonEscaped(out, d.options[i]); out += '"';
    }
    out += "],";
  }
  out += "\"value\":\""; appendJsonEscaped(out, d.value); out += "\"";
  out += '}';
}

void writeCustomConfigListJson(std::string &out, const std::vector<CustomConfigDef> &defs) {
  out += "\"customConfig\":[";
  for (size_t i = 0; i < defs.size(); i++) {
    if (i) out += ',';
    writeCustomConfigDefJson(out, defs[i]);
  }
  out += "],";
}

// Server-seitige Validierung eines von aussen (POST /config) eingegangenen
// Werts gegen das deklarierte Schema - der Manager ist eine nicht
// vertrauenswuerdige Eingabequelle (analog validateCustomConfigValue in
// Client/client.cpp).
bool validateCustomConfigValue(const CustomConfigDef &def, const std::string &value) {
  if (def.type == "range") {
    if (value.empty()) return false;
    char *end = nullptr;
    long v = std::strtol(value.c_str(), &end, 10);
    if (end == value.c_str() || *end != '\0') return false;
    return v >= def.rangeMin && v <= def.rangeMax;
  }
  if (def.type == "text") {
    return (int)value.size() <= def.textMaxLen;
  }
  if (def.type == "select") {
    return std::find(def.options.begin(), def.options.end(), value) != def.options.end();
  }
  return false;
}

const CustomConfigDef *findCustomConfigDef(const std::vector<CustomConfigDef> &defs, const std::string &key) {
  for (auto &d : defs) {
    if (d.key == key) return &d;
  }
  return nullptr;
}

// ---- Geraeteweiter Zustand (analog EscapeComponent::onBattery in
// Client/client.hpp: EINE physische Batterie pro Board, geteilt von allen
// lokalen Komponenten) -------------------------------------------------------

class DeviceState {
public:
  void drainBattery() {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      battery_ = std::max(0, battery_ - 10);
    }
    dirty.store(true);
  }

  int battery() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return battery_;
  }

  // Roher, geraeteweiter Ablaufplan-"Skeleton" (Ebenen/Lanes/Dummies/
  // Variablen-Katalog eines Raums) - analog EscapeComponent::_planSkeleton in
  // Client/client.hpp, fuer den Sim bedeutungslos, nur Speicher+Weiterleitung.
  std::string planSkeleton() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return planSkeleton_.empty() ? "{}" : planSkeleton_;
  }

  void setPlanSkeleton(std::string raw) {
    std::lock_guard<std::mutex> lock(mutex_);
    planSkeleton_ = std::move(raw);
  }

  std::atomic<bool> dirty{false};

private:
  mutable std::mutex mutex_;
  int battery_ = 100;
  std::string planSkeleton_;
};

// ---- Eigener Zustand EINER lokalen Raetsel-Komponente (analog LocalComponent
// in Client/client.hpp) -------------------------------------------------------

class ComponentState {
public:
  ComponentState(int id, std::string name, std::string room, int totalSteps, DeviceState &device, std::string uuid)
      : id_(id), uuid_(std::move(uuid)), name_(std::move(name)), room_(std::move(room)), device_(device),
        totalSteps_(totalSteps) {
    // Beispielhafte Custom-Konfiguration, um das Protokoll end-to-end testen
    // zu koennen (Manager-Oberflaeche <-> /status.json <-> POST /config).
    customConfig_.push_back({"brightness", "range", 0, 100, 0, {}, "50"});
    customConfig_.push_back({"label", "text", 0, 0, 32, {}, ""});
    customConfig_.push_back({"difficulty", "select", 0, 0, 0, {"easy", "medium", "hard"}, "medium"});
  }

  int id() const { return id_; }

  bool applyAction(const std::string &action) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      if (action == "reset") {
        step_ = 0;
        errors_.clear();
      } else if (action == "next_step") {
        step_ = std::min(totalSteps_, step_ + 1);
      } else if (action == "solve") {
        step_ = totalSteps_;
      } else if (action == "toggle_error") {
        auto it = std::find(errors_.begin(), errors_.end(), "sensor_timeout");
        if (it != errors_.end()) errors_.erase(it);
        else errors_.push_back("sensor_timeout");
      } else if (action == "drain_battery") {
        device_.drainBattery(); // setzt bereits device_.dirty
        return true;
      } else {
        return false;
      }
    }
    device_.dirty.store(true);
    return true;
  }

  void setIdentity(const std::string &name, const std::string &room) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      name_ = name;
      room_ = room;
    }
    device_.dirty.store(true);
  }

  // Prueft alle Werte in "values" gegen das eigene Schema und wendet sie erst
  // dann alles-oder-nichts an (kein Teilanwenden bei einer ungueltigen
  // Anfrage) - analog handleConfig() in Client/client.cpp.
  bool applyCustomConfig(const std::map<std::string, std::string> &values) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &kv : values) {
      const CustomConfigDef *def = findCustomConfigDef(customConfig_, kv.first);
      if (!def || !validateCustomConfigValue(*def, kv.second)) return false;
    }
    for (auto &kv : values) {
      for (auto &def : customConfig_) {
        if (def.key == kv.first) def.value = kv.second;
      }
    }
    device_.dirty.store(true);
    return true;
  }

  std::vector<CustomConfigDef> customConfigSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return customConfig_;
  }

  // planValue: "" loescht die Zuordnung wieder, sonst roher JSON-Text (schon
  // serialisiertes Objekt) - analog EscapeComponent::handlePlan() in client.cpp.
  void setPlan(std::string planValue) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      plan_ = std::move(planValue);
    }
    device_.dirty.store(true);
  }

  std::pair<std::string, std::string> identity() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {name_, room_};
  }

  std::string snapshotJson() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::string out;
    out += '{';
    out += "\"id\":" + std::to_string(id_) + ",";
    out += "\"uuid\":\""; appendJsonEscaped(out, uuid_); out += "\",";
    out += "\"name\":\""; appendJsonEscaped(out, name_); out += "\",";
    out += "\"room\":\""; appendJsonEscaped(out, room_); out += "\",";

    out += "\"errors\":[";
    for (size_t i = 0; i < errors_.size(); i++) {
      if (i) out += ',';
      out += '"'; appendJsonEscaped(out, errors_[i]); out += '"';
    }
    out += "],";

    out += "\"actions\":[";
    for (size_t i = 0; i < actions_.size(); i++) {
      if (i) out += ',';
      out += '"'; appendJsonEscaped(out, actions_[i]); out += '"';
    }
    out += "],";

    out += "\"puzzle\":{";
    out += "\"step\":" + std::to_string(step_) + ",";
    out += "\"totalSteps\":" + std::to_string(totalSteps_) + ",";
    out += "\"state\":\""; appendJsonEscaped(out, puzzleStateHtml()); out += "\",";
    out += "\"isHtml\":true";
    out += "},";

    writeCustomConfigListJson(out, customConfig_);
    if (!plan_.empty()) {
      out += "\"plan\":"; out += plan_; out += ',';
    }
    out.pop_back(); // ueberzaehliges Komma nach dem letzten Feld entfernen
    out += '}';
    return out;
  }

private:
  std::string puzzleStateHtml() const {
    return "<div style=\"font-family:sans-serif\">Schritt " + std::to_string(step_) + "/" +
           std::to_string(totalSteps_) + "</div>";
  }

  int id_;
  std::string uuid_;
  mutable std::mutex mutex_;
  std::string name_, room_;
  // Roher Ablaufplan-Slice dieser Komponente (Lane-Zuordnung + eigene
  // Verbindungen), von Manager/manager.html verwaltet - leer = nicht zugeordnet.
  std::string plan_;
  DeviceState &device_;
  std::vector<std::string> errors_;
  std::vector<std::string> actions_{"reset", "next_step", "solve", "toggle_error", "drain_battery"};
  int step_ = 0;
  int totalSteps_ = 5;
  std::vector<CustomConfigDef> customConfig_;
};

// ---- Peer-Tabelle (aus fremden UDP-Broadcasts) ------------------------------

struct Peer {
  int id = 0; // Komponenten-Index auf dem Sender-Board (siehe ComponentState::id())
  std::string uuid, name, room, ip, feed, puzzleState;
  int battery = -1;
  std::vector<std::string> errors, actions;
  int puzzleStep = 0, puzzleTotalSteps = 0;
  bool puzzleIsHtml = false;
  std::vector<CustomConfigDef> customConfig;
  std::string plan; // roher Ablaufplan-Slice dieser Komponente, opak weitergereicht
  std::chrono::steady_clock::time_point lastSeen;
};

std::string writePeerJson(const Peer &p) {
  std::string out;
  out += '{';
  out += "\"id\":" + std::to_string(p.id) + ",";
  out += "\"uuid\":\""; appendJsonEscaped(out, p.uuid); out += "\",";
  out += "\"name\":\""; appendJsonEscaped(out, p.name); out += "\",";
  out += "\"room\":\""; appendJsonEscaped(out, p.room); out += "\",";
  out += "\"ip\":\""; appendJsonEscaped(out, p.ip); out += "\",";
  out += "\"battery\":" + std::to_string(p.battery) + ",";

  out += "\"errors\":[";
  for (size_t i = 0; i < p.errors.size(); i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.errors[i]); out += '"';
  }
  out += "],";

  out += "\"actions\":[";
  for (size_t i = 0; i < p.actions.size(); i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.actions[i]); out += '"';
  }
  out += "],";

  if (!p.feed.empty()) {
    out += "\"feed\":\""; appendJsonEscaped(out, p.feed); out += "\",";
  }

  if (p.puzzleTotalSteps > 0) {
    out += "\"puzzle\":{";
    out += "\"step\":" + std::to_string(p.puzzleStep) + ",";
    out += "\"totalSteps\":" + std::to_string(p.puzzleTotalSteps) + ",";
    out += "\"state\":\""; appendJsonEscaped(out, p.puzzleState); out += "\",";
    out += std::string("\"isHtml\":") + (p.puzzleIsHtml ? "true" : "false");
    out += "},";
  }

  if (!p.customConfig.empty()) writeCustomConfigListJson(out, p.customConfig);

  if (!p.plan.empty()) {
    out += "\"plan\":"; out += p.plan; out += ',';
  }

  out += "\"lastSeenMs\":0"; // manager.html wertet dieses Feld ohnehin nicht aus
  out += '}';
  return out;
}

class PeerTable {
public:
  // "msg" ist hier bereits das EINZELNE Komponenten-Objekt aus dem
  // "components"-Array eines Broadcasts, nicht die gesamte Nachricht - id und
  // battery kommen vom Aufrufer (top-level im Broadcast, siehe listenLoop).
  void ingest(const JsonValue &msg, int id, const std::string &name, const std::string &room, int battery,
              const std::string &sourceIp, std::chrono::steady_clock::time_point now) {
    Peer p;
    p.id = id;
    if (const JsonValue *v = msg.find("uuid")) p.uuid = v->asString();
    p.name = clip(name, SimConfig::MAX_NAME_LEN);
    p.room = clip(room, SimConfig::MAX_ROOM_LEN);
    p.ip = sourceIp;
    p.battery = battery;

    if (const JsonValue *v = msg.find("errors"); v && v->type == JsonValue::Type::Array) {
      for (auto &e : v->arrayValue) {
        if (p.errors.size() >= SimConfig::MAX_ERRORS) break;
        p.errors.push_back(clip(e.asString(), SimConfig::MAX_ERROR_LEN));
      }
    }
    if (const JsonValue *v = msg.find("actions"); v && v->type == JsonValue::Type::Array) {
      for (auto &a : v->arrayValue) {
        if (p.actions.size() >= SimConfig::MAX_ACTIONS) break;
        p.actions.push_back(clip(a.asString(), SimConfig::MAX_ACTION_LEN));
      }
    }
    if (const JsonValue *v = msg.find("feed")) p.feed = clip(v->asString(), SimConfig::MAX_FEED_LEN);

    if (const JsonValue *puzzle = msg.find("puzzle"); puzzle && puzzle->type == JsonValue::Type::Object) {
      const JsonValue *step = puzzle->find("step");
      const JsonValue *total = puzzle->find("totalSteps");
      const JsonValue *state = puzzle->find("state");
      const JsonValue *isHtml = puzzle->find("isHtml");
      p.puzzleStep = step ? (int)step->asNumber(0) : 0;
      p.puzzleTotalSteps = total ? (int)total->asNumber(0) : 0;
      p.puzzleState = clip(state ? state->asString() : "", SimConfig::MAX_STATE_LEN);
      p.puzzleIsHtml = isHtml ? isHtml->asBool(false) : false;
    }

    if (const JsonValue *v = msg.find("customConfig"); v && v->type == JsonValue::Type::Array) {
      for (auto &cc : v->arrayValue) {
        if (cc.type != JsonValue::Type::Object) continue;
        if (p.customConfig.size() >= SimConfig::MAX_CUSTOM_CONFIGS) break;
        CustomConfigDef d;
        const JsonValue *key = cc.find("key");
        d.key = key ? key->asString() : "";
        const JsonValue *type = cc.find("type");
        d.type = type ? type->asString("text") : "text";
        if (d.type == "range") {
          const JsonValue *min = cc.find("min");
          const JsonValue *max = cc.find("max");
          d.rangeMin = min ? (int)min->asNumber(0) : 0;
          d.rangeMax = max ? (int)max->asNumber(0) : 0;
        } else if (d.type == "select") {
          if (const JsonValue *opts = cc.find("options"); opts && opts->type == JsonValue::Type::Array) {
            for (auto &o : opts->arrayValue) {
              if (d.options.size() >= SimConfig::MAX_CONFIG_OPTIONS) break;
              d.options.push_back(o.asString());
            }
          }
        } else {
          const JsonValue *maxLen = cc.find("maxLength");
          d.textMaxLen = maxLen ? (int)maxLen->asNumber(0) : 0;
        }
        const JsonValue *value = cc.find("value");
        d.value = value ? value->asStringLoose() : "";
        p.customConfig.push_back(std::move(d));
      }
    }
    if (const JsonValue *v = msg.find("plan"); v && v->type != JsonValue::Type::Null) {
      stringifyJsonValue(*v, p.plan);
    }
    p.lastSeen = now;

    std::lock_guard<std::mutex> lock(mutex_);
    auto it = std::find_if(entries_.begin(), entries_.end(),
                            [&](const Peer &e) { return e.name == p.name && e.room == p.room; });
    if (it != entries_.end()) {
      *it = std::move(p);
      return;
    }
    if (entries_.size() >= SimConfig::MAX_PEERS) {
      auto oldest = std::min_element(entries_.begin(), entries_.end(),
                                      [](const Peer &a, const Peer &b) { return a.lastSeen < b.lastSeen; });
      *oldest = std::move(p);
      return;
    }
    entries_.push_back(std::move(p));
  }

  void expire(std::chrono::steady_clock::time_point now) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(std::remove_if(entries_.begin(), entries_.end(),
                                   [&](const Peer &e) {
                                     return std::chrono::duration_cast<std::chrono::seconds>(now - e.lastSeen)
                                                .count() > SimConfig::PEER_TIMEOUT_S;
                                   }),
                    entries_.end());
  }

  std::vector<std::string> snapshotJsonList() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> out;
    out.reserve(entries_.size());
    for (auto &e : entries_) out.push_back(writePeerJson(e));
    return out;
  }

private:
  std::mutex mutex_;
  std::vector<Peer> entries_;
};

// ---- Minimaler HTTP-Server --------------------------------------------------

struct HttpRequest {
  std::string method;
  std::string path;
  std::map<std::string, std::string> headers; // Schluessel klein geschrieben
  std::string body;
};

bool readHttpRequest(int fd, HttpRequest &req) {
  std::string buffer;
  char chunk[4096];
  size_t headerEnd = std::string::npos;
  while (headerEnd == std::string::npos) {
    ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
    if (n <= 0) return false;
    buffer.append(chunk, (size_t)n);
    headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos && buffer.size() > 16384) return false; // Schutz vor endlosem Header
  }
  std::string headerPart = buffer.substr(0, headerEnd);
  std::string rest = buffer.substr(headerEnd + 4);

  std::istringstream headerStream(headerPart);
  std::string line;
  if (!std::getline(headerStream, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream requestLine(line);
  std::string httpVersion;
  if (!(requestLine >> req.method >> req.path >> httpVersion)) return false;

  while (std::getline(headerStream, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    if (line.empty()) continue;
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    std::string key = toLower(line.substr(0, colon));
    size_t valueStart = line.find_first_not_of(' ', colon + 1);
    req.headers[key] = valueStart == std::string::npos ? "" : line.substr(valueStart);
  }

  size_t contentLength = 0;
  auto it = req.headers.find("content-length");
  if (it != req.headers.end()) {
    try { contentLength = std::stoul(it->second); } catch (...) { contentLength = 0; }
  }
  contentLength = std::min<size_t>(contentLength, 65536); // Schutz vor ueberdimensionierten Bodies

  while (rest.size() < contentLength) {
    ssize_t n = recv(fd, chunk, sizeof(chunk), 0);
    if (n <= 0) break;
    rest.append(chunk, (size_t)n);
  }
  req.body = rest.substr(0, std::min(rest.size(), contentLength));
  return true;
}

bool fileReadable(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  return f.good();
}

std::string readFileToString(const std::string &path) {
  std::ifstream f(path, std::ios::binary);
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// Sucht Manager/manager.html analog zum PlatformIO-Embed der ESP32-Firmware,
// damit der Sim unter "/" dieselbe Manager-Oberflaeche ausliefert.
std::string findManagerHtml(const std::string &override) {
  if (!override.empty()) {
    if (fileReadable(override)) return override;
    std::cerr << "[sim] --manager-html Pfad nicht lesbar: " << override << "\n";
  }
  std::vector<std::string> candidates;
#ifdef __linux__
  char exePath[4096];
  ssize_t len = readlink("/proc/self/exe", exePath, sizeof(exePath) - 1);
  if (len > 0) {
    exePath[len] = '\0';
    std::string dir(exePath);
    size_t slash = dir.find_last_of('/');
    if (slash != std::string::npos) candidates.push_back(dir.substr(0, slash) + "/../Manager/manager.html");
  }
#endif
  candidates.push_back("../Manager/manager.html");
  candidates.push_back("Manager/manager.html");
  for (auto &c : candidates) {
    if (fileReadable(c)) return c;
  }
  return "";
}

void sendResponse(int fd, int code, const std::string &contentType, const std::string &body,
                   const std::vector<std::string> &extraHeaders = {}) {
  const char *reason = code == 200   ? "OK"
                       : code == 204 ? "No Content"
                       : code == 400 ? "Bad Request"
                       : code == 401 ? "Unauthorized"
                       : code == 404 ? "Not Found"
                       : code == 422 ? "Unprocessable Entity"
                                     : "Error";
  std::ostringstream os;
  os << "HTTP/1.1 " << code << " " << reason << "\r\n";
  os << "Content-Type: " << contentType << "\r\n";
  os << "Content-Length: " << body.size() << "\r\n";
  os << "Access-Control-Allow-Origin: *\r\n";
  os << "Connection: close\r\n";
  for (auto &h : extraHeaders) os << h << "\r\n";
  os << "\r\n" << body;
  std::string full = os.str();
  send(fd, full.data(), full.size(), 0);
}

// Fuegt ip/battery (geraeteweit, siehe DeviceState) in ein von
// ComponentState::snapshotJson() geliefertes Objekt ein - fuer /status.json
// braucht jeder Komponenten-Eintrag eine FLACHE Kopie mit ip/battery inline,
// waehrend der Broadcast selbst sie nur einmal auf oberster Ebene traegt.
std::string appendIpBattery(std::string compJson, const std::string &ip, int battery) {
  if (!compJson.empty() && compJson.back() == '}') compJson.pop_back();
  compJson += ",\"ip\":\"";
  appendJsonEscaped(compJson, ip);
  compJson += "\",\"battery\":" + std::to_string(battery) + "}";
  return compJson;
}

void handleClient(int fd, std::list<ComponentState> &components, DeviceState &device, PeerTable &peers,
                   const std::string &token, const std::string &ip, const std::string &managerHtml) {
  HttpRequest req;
  if (!readHttpRequest(fd, req)) {
    close(fd);
    return;
  }

  auto checkAuth = [&]() {
    auto it = req.headers.find("x-auth-token");
    return it != req.headers.end() && constantTimeEquals(it->second, token);
  };
  // "id" waehlt die Ziel-Komponente auf diesem Board aus (siehe
  // ComponentState::id()); fehlt es, wird Komponente 0 angenommen
  // (rueckwaertskompatibel zu Boards mit nur einer Komponente).
  auto findComponent = [&](int id) -> ComponentState * {
    for (auto &c : components) {
      if (c.id() == id) return &c;
    }
    return nullptr;
  };

  if (req.method == "OPTIONS" && (req.path == "/action" || req.path == "/config" || req.path == "/plan" ||
                                   req.path == "/plan-skeleton")) {
    sendResponse(fd, 204, "text/plain", "",
                 {"Access-Control-Allow-Methods: GET, POST, OPTIONS",
                  "Access-Control-Allow-Headers: Content-Type, X-Auth-Token"});
  } else if (req.method == "GET" && req.path == "/plan-skeleton.json") {
    sendResponse(fd, 200, "application/json", device.planSkeleton());
  } else if (req.method == "GET" && req.path == "/status.json") {
    peers.expire(std::chrono::steady_clock::now());
    int battery = device.battery();
    std::string json = "[";
    bool first = true;
    for (auto &c : components) {
      if (!first) json += ",";
      first = false;
      json += appendIpBattery(c.snapshotJson(), ip, battery);
    }
    for (auto &p : peers.snapshotJsonList()) {
      if (!first) json += ",";
      first = false;
      json += p;
    }
    json += "]";
    sendResponse(fd, 200, "application/json", json);
  } else if (req.method == "GET" && req.path == "/") {
    if (!managerHtml.empty()) {
      sendResponse(fd, 200, "text/html; charset=utf-8", managerHtml);
    } else {
      std::string names;
      for (auto &c : components) {
        auto [name, room] = c.identity();
        if (!names.empty()) names += ", ";
        names += name + " (" + room + ")";
      }
      sendResponse(fd, 200, "text/plain; charset=utf-8",
                   "EscapeComponentSim: " + names + " auf " + ip + "\n");
    }
  } else if (req.method == "POST" && req.path == "/action") {
    if (!checkAuth()) {
      sendResponse(fd, 401, "application/json", "{\"error\":\"unauthorized\"}");
    } else {
      JsonValue doc;
      JsonParser parser(req.body);
      if (!parser.parse(doc) || doc.type != JsonValue::Type::Object) {
        sendResponse(fd, 400, "application/json", "{\"error\":\"invalid json\"}");
      } else {
        const JsonValue *idVal = doc.find("id");
        ComponentState *state = findComponent(idVal ? (int)idVal->asNumber(0) : 0);
        if (!state) {
          sendResponse(fd, 400, "application/json", "{\"error\":\"invalid id\"}");
        } else {
          const JsonValue *actionVal = doc.find("action");
          std::string action = actionVal ? actionVal->asString() : "";
          bool ok = !action.empty() && state->applyAction(action);
          sendResponse(fd, ok ? 200 : 422, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
        }
      }
    }
  } else if (req.method == "POST" && req.path == "/config") {
    if (!checkAuth()) {
      sendResponse(fd, 401, "application/json", "{\"error\":\"unauthorized\"}");
    } else {
      JsonValue doc;
      JsonParser parser(req.body);
      if (!parser.parse(doc) || doc.type != JsonValue::Type::Object) {
        sendResponse(fd, 400, "application/json", "{\"error\":\"invalid json\"}");
      } else {
        const JsonValue *idVal = doc.find("id");
        ComponentState *state = findComponent(idVal ? (int)idVal->asNumber(0) : 0);
        if (!state) {
          sendResponse(fd, 400, "application/json", "{\"error\":\"invalid id\"}");
        } else {
          const JsonValue *nameVal = doc.find("name");
          const JsonValue *roomVal = doc.find("room");
          std::string name = nameVal ? nameVal->asString() : "";
          std::string room = roomVal ? roomVal->asString() : "";
          bool identityGiven = !name.empty() || !room.empty();
          if (identityGiven && (name.empty() || room.empty())) {
            sendResponse(fd, 400, "application/json", "{\"error\":\"invalid name/room\"}");
          } else {
            bool ok = true;
            if (const JsonValue *cfg = doc.find("config"); cfg && cfg->type == JsonValue::Type::Object) {
              std::map<std::string, std::string> values;
              for (auto &kv : cfg->objectValue) values[kv.first] = kv.second.asStringLoose();
              ok = state->applyCustomConfig(values);
            }
            if (!ok) {
              sendResponse(fd, 400, "application/json", "{\"error\":\"invalid config value\"}");
            } else {
              if (identityGiven) state->setIdentity(name, room);
              sendResponse(fd, 200, "application/json", "{\"ok\":true}");
            }
          }
        }
      }
    }
  } else if (req.method == "POST" && req.path == "/plan") {
    if (!checkAuth()) {
      sendResponse(fd, 401, "application/json", "{\"error\":\"unauthorized\"}");
    } else {
      JsonValue doc;
      JsonParser parser(req.body);
      if (!parser.parse(doc) || doc.type != JsonValue::Type::Object) {
        sendResponse(fd, 400, "application/json", "{\"error\":\"invalid json\"}");
      } else {
        const JsonValue *idVal = doc.find("id");
        ComponentState *state = findComponent(idVal ? (int)idVal->asNumber(0) : 0);
        if (!state) {
          sendResponse(fd, 400, "application/json", "{\"error\":\"invalid id\"}");
        } else {
          const JsonValue *planVal = doc.find("plan");
          if (!planVal || planVal->type == JsonValue::Type::Null) {
            state->setPlan(""); // "plan":null (oder fehlend) loescht die Zuordnung wieder
          } else {
            std::string planText;
            stringifyJsonValue(*planVal, planText);
            state->setPlan(planText);
          }
          sendResponse(fd, 200, "application/json", "{\"ok\":true}");
        }
      }
    }
  } else if (req.method == "POST" && req.path == "/plan-skeleton") {
    if (!checkAuth()) {
      sendResponse(fd, 401, "application/json", "{\"error\":\"unauthorized\"}");
    } else {
      // Inhalt (Ebenen/Lanes/Dummies/Variablen) ist fuer den Sim bedeutungslos -
      // nur als JSON validieren und roh weiterreichen, analog
      // EscapeComponent::handlePlanSkeletonPost() in Client/client.cpp.
      JsonValue doc;
      JsonParser parser(req.body);
      if (!parser.parse(doc) || doc.type != JsonValue::Type::Object) {
        sendResponse(fd, 400, "application/json", "{\"error\":\"invalid json\"}");
      } else {
        device.setPlanSkeleton(req.body);
        sendResponse(fd, 200, "application/json", "{\"ok\":true}");
      }
    }
  } else {
    sendResponse(fd, 404, "application/json", "{\"error\":\"not found\"}");
  }
  close(fd);
}

void httpServerLoop(int port, std::list<ComponentState> &components, DeviceState &device, PeerTable &peers,
                     const std::string &token,
                     const std::string &ip, const std::string &managerHtml, std::atomic<bool> &stop) {
  int listenFd = socket(AF_INET, SOCK_STREAM, 0);
  int opt = 1;
  setsockopt(listenFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons((uint16_t)port);
  if (bind(listenFd, (sockaddr *)&addr, sizeof(addr)) != 0) {
    std::cerr << "[sim] Kann HTTP-Port " << port << " nicht binden: " << std::strerror(errno) << "\n";
    std::cerr << "[sim] Port < 1024 benoetigt meist Root-Rechte (sudo) oder CAP_NET_BIND_SERVICE.\n";
    close(listenFd);
    return;
  }
  listen(listenFd, 16);

  while (!stop.load()) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(listenFd, &readSet);
    timeval tv{1, 0};
    int r = select(listenFd + 1, &readSet, nullptr, nullptr, &tv);
    if (r <= 0) continue;
    sockaddr_in clientAddr{};
    socklen_t clientLen = sizeof(clientAddr);
    int clientFd = accept(listenFd, (sockaddr *)&clientAddr, &clientLen);
    if (clientFd < 0) continue;
    handleClient(clientFd, components, device, peers, token, ip, managerHtml);
  }
  close(listenFd);
}

// ---- Broadcast senden / empfangen -------------------------------------------

void broadcastLoop(int sock, int udpPort, std::list<ComponentState> &components, DeviceState &device,
                    const std::string &ip, const std::string &broadcastIp, double jitterS, std::atomic<bool> &stop) {
  auto lastSend = std::chrono::steady_clock::now() - std::chrono::hours(1);
  sockaddr_in bcastAddr{};
  bcastAddr.sin_family = AF_INET;
  bcastAddr.sin_port = htons((uint16_t)udpPort);
  inet_pton(AF_INET, broadcastIp.c_str(), &bcastAddr.sin_addr);

  while (!stop.load()) {
    auto now = std::chrono::steady_clock::now();
    double sinceLast = std::chrono::duration<double>(now - lastSend).count();
    bool dueHeartbeat = sinceLast >= (SimConfig::HEARTBEAT_INTERVAL_S + jitterS);
    bool dueChange = device.dirty.load() && sinceLast >= SimConfig::CHANGE_MIN_GAP_S;
    if (dueHeartbeat || dueChange) {
      // Ein Paket pro Geraet: gemeinsames ip/battery, plus "components"-Array
      // mit je einem Eintrag pro ComponentState - analog zu
      // EscapeComponent::sendBroadcast() in Client/client.cpp.
      std::string payload = "{\"ip\":\"";
      appendJsonEscaped(payload, ip);
      payload += "\",\"battery\":" + std::to_string(device.battery()) + ",\"components\":[";
      bool first = true;
      for (auto &c : components) {
        if (!first) payload += ',';
        first = false;
        payload += c.snapshotJson();
      }
      payload += "]}";
      sendto(sock, payload.data(), payload.size(), 0, (sockaddr *)&bcastAddr, sizeof(bcastAddr));
      lastSend = now;
      device.dirty.store(false);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

void listenLoop(int udpPort, std::list<ComponentState> &components, PeerTable &peers, std::atomic<bool> &stop) {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  int opt = 1;
  setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
  setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons((uint16_t)udpPort);
  if (bind(sock, (sockaddr *)&addr, sizeof(addr)) != 0) {
    std::cerr << "[sim] Kann UDP-Port " << udpPort << " nicht binden: " << std::strerror(errno) << "\n";
    close(sock);
    return;
  }

  char buf[4096];
  while (!stop.load()) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(sock, &readSet);
    timeval tv{1, 0};
    int r = select(sock + 1, &readSet, nullptr, nullptr, &tv);
    if (r <= 0) continue;

    sockaddr_in srcAddr{};
    socklen_t srcLen = sizeof(srcAddr);
    ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0, (sockaddr *)&srcAddr, &srcLen);
    if (n <= 0) continue;
    buf[n] = '\0';

    JsonValue doc;
    JsonParser parser(std::string(buf, (size_t)n));
    bool parseOk = parser.parse(doc);
    if (!parseOk || doc.type != JsonValue::Type::Object) continue;

    const JsonValue *componentsVal = doc.find("components");
    if (!componentsVal || componentsVal->type != JsonValue::Type::Array) continue;
    int senderBattery = -1;
    if (const JsonValue *batteryVal = doc.find("battery")) senderBattery = (int)batteryVal->asNumber(-1);
    std::string senderIp;
    if (const JsonValue *ipVal = doc.find("ip")) senderIp = ipVal->asString();

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcAddr.sin_addr, ipStr, sizeof(ipStr));
    if (senderIp.empty()) senderIp = ipStr;

    for (auto &comp : componentsVal->arrayValue) {
      if (comp.type != JsonValue::Type::Object) continue;
      const JsonValue *nameVal = comp.find("name");
      const JsonValue *roomVal = comp.find("room");
      if (!nameVal || !roomVal) continue;
      std::string name = nameVal->asString();
      std::string room = roomVal->asString();
      if (name.empty() || room.empty()) continue;

      bool isSelf = false;
      for (auto &c : components) {
        auto [ownName, ownRoom] = c.identity();
        if (name == ownName && room == ownRoom) {
          isSelf = true;
          break;
        }
      }
      if (isSelf) continue; // eigene Komponente ignorieren

      int id = 0;
      if (const JsonValue *idVal = comp.find("id")) id = (int)idVal->asNumber(0);
      peers.ingest(comp, id, name, room, senderBattery, senderIp, std::chrono::steady_clock::now());
    }
  }
  close(sock);
}

std::string getLocalIp() {
  int sock = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0) return "127.0.0.1";
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(80);
  inet_pton(AF_INET, "8.8.8.8", &addr.sin_addr);

  std::string ip = "127.0.0.1";
  // UDP-"connect" sendet keine Pakete, ermittelt nur die ausgehende Interface-IP.
  if (connect(sock, (sockaddr *)&addr, sizeof(addr)) == 0) {
    sockaddr_in local{};
    socklen_t len = sizeof(local);
    if (getsockname(sock, (sockaddr *)&local, &len) == 0) {
      char buf[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &local.sin_addr, buf, sizeof(buf));
      ip = buf;
    }
  }
  close(sock);
  return ip;
}

// Subnetz-Broadcast-Adresse (ip | ~mask) des Interfaces mit localIp - analog zu
// EscapeComponent::broadcastAddress() in client.cpp. Auf Rechnern mit mehreren
// Interfaces/VPNs ist die pauschale Adresse 255.255.255.255 mehrdeutig
// geroutet; die gerichtete Subnetz-Broadcast-Adresse erzwingt den Versand
// ueber das richtige Interface.
std::string computeBroadcastAddress(const std::string &localIp) {
  ifaddrs *ifaddr = nullptr;
  std::string broadcast = "255.255.255.255"; // Fallback
  if (getifaddrs(&ifaddr) != 0) return broadcast;

  for (ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
    auto *sin = (sockaddr_in *)ifa->ifa_addr;
    char ipBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
    if (localIp != ipBuf || !ifa->ifa_netmask) continue;

    auto *maskSin = (sockaddr_in *)ifa->ifa_netmask;
    uint32_t bcastN = sin->sin_addr.s_addr | ~maskSin->sin_addr.s_addr;
    in_addr bcastAddr{};
    bcastAddr.s_addr = bcastN;
    char bcastBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &bcastAddr, bcastBuf, sizeof(bcastBuf));
    broadcast = bcastBuf;
    break;
  }
  freeifaddrs(ifaddr);
  return broadcast;
}

// MAC-Adresse des Interfaces mit localIp - Grundlage der Komponenten-
// Identitaet (siehe resolveComponentUuid()), analog WiFi.macAddress() in
// Client/client.cpp bzw. get_local_mac() in escape_component_sim.py. Nur unter
// Linux implementiert (SIOCGIFHWADDR ist linux-spezifisch); leerer String
// (Zufalls-Fallback in resolveComponentUuid()) auf anderen Plattformen oder
// falls keine Hardware-Adresse ermittelbar ist.
std::string getLocalMac(const std::string &localIp) {
#ifdef __linux__
  ifaddrs *ifaddr = nullptr;
  if (getifaddrs(&ifaddr) != 0) return "";
  std::string mac;
  for (ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
    auto *sin = (sockaddr_in *)ifa->ifa_addr;
    char ipBuf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
    if (localIp != ipBuf) continue;

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
      ifreq ifr{};
      strncpy(ifr.ifr_name, ifa->ifa_name, IFNAMSIZ - 1);
      if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
        auto *hw = (unsigned char *)ifr.ifr_hwaddr.sa_data;
        bool nonzero = false;
        for (int i = 0; i < 6; i++) {
          if (hw[i]) nonzero = true;
        }
        if (nonzero) {
          char buf[13];
          snprintf(buf, sizeof(buf), "%02x%02x%02x%02x%02x%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5]);
          mac = buf;
        }
      }
      close(sock);
    }
    break;
  }
  freeifaddrs(ifaddr);
  return mac;
#else
  (void)localIp;
  return "";
#endif
}

std::string uuidStatePath(int port) {
  return "/tmp/escape_sim_uuid_" + std::to_string(port) + ".json";
}

std::map<int, std::string> loadUuidState(const std::string &path) {
  std::map<int, std::string> result;
  std::ifstream f(path, std::ios::binary);
  if (!f.good()) return result;
  std::ostringstream ss;
  ss << f.rdbuf();
  JsonValue doc;
  JsonParser parser(ss.str());
  if (!parser.parse(doc) || doc.type != JsonValue::Type::Object) return result;
  for (auto &kv : doc.objectValue) {
    try {
      result[std::stoi(kv.first)] = kv.second.asString();
    } catch (...) {
      // ungueltiger Schluessel: ueberspringen statt abzubrechen
    }
  }
  return result;
}

void saveUuidState(const std::string &path, const std::map<int, std::string> &state) {
  std::string out = "{";
  bool first = true;
  for (auto &kv : state) {
    if (!first) out += ',';
    first = false;
    out += "\"" + std::to_string(kv.first) + "\":\"";
    appendJsonEscaped(out, kv.second);
    out += "\"";
  }
  out += "}";
  std::ofstream f(path, std::ios::trunc | std::ios::binary);
  if (f.good()) f << out;
}

// Analog EscapeComponent::resolveUuid() in Client/client.cpp: liefert eine
// ueber Prozess-Neustarts (gleicher --http-port) stabile Komponenten-
// Identitaet, von der Host-MAC-Adresse abgeleitet (deterministisch, wie auf
// dem ESP32) und in einer kleinen JSON-Datei im Temp-Verzeichnis persistiert
// (der Sim hat kein NVS-Aequivalent). Zufalls-Fallback, falls keine MAC
// ermittelbar ist (z.B. macOS/manche Container-Netzwerke).
std::string resolveComponentUuid(int port, int compId, const std::string &mac) {
  std::string path = uuidStatePath(port);
  auto state = loadUuidState(path);
  auto it = state.find(compId);
  if (it != state.end() && !it->second.empty()) return it->second;

  std::string value;
  if (!mac.empty()) {
    value = mac + "-" + std::to_string(compId);
  } else {
    std::mt19937_64 rng(std::random_device{}());
    std::uniform_int_distribution<uint64_t> dist;
    char buf[24];
    snprintf(buf, sizeof(buf), "%016llx", (unsigned long long)dist(rng));
    value = std::string(buf) + "-" + std::to_string(compId);
  }
  state[compId] = value;
  saveUuidState(path, state);
  return value;
}

// ---- Minimaler mDNS-Responder ------------------------------------------------
// Beantwortet A-Record-Anfragen fuer <hostname>.local per Multicast, analog zu
// MDNS.begin() + addService() in client.cpp: alle Komponenten/Simulatoren
// registrieren denselben Hostnamen, sodass http://<hostname>.local/ auf eine
// beliebige erreichbare Instanz zeigt. Kein externes mDNS-Lib noetig - nur
// so viel DNS-Paketbau/-Parsing wie fuer diesen einen Zweck noetig.

constexpr const char *MDNS_ADDR = "224.0.0.251";
constexpr uint16_t MDNS_PORT = 5353;

std::vector<uint8_t> encodeDnsName(const std::string &name) {
  std::vector<uint8_t> out;
  size_t start = 0;
  while (start <= name.size()) {
    size_t dot = name.find('.', start);
    std::string label = (dot == std::string::npos) ? name.substr(start) : name.substr(start, dot - start);
    out.push_back((uint8_t)label.size());
    for (char c : label) out.push_back((uint8_t)c);
    if (dot == std::string::npos) break;
    start = dot + 1;
  }
  out.push_back(0);
  return out;
}

std::vector<uint8_t> buildMdnsAAnswer(const std::string &name, const std::string &ip) {
  std::vector<uint8_t> out;
  auto push16 = [&](uint16_t v) {
    uint16_t n = htons(v);
    out.push_back(((uint8_t *)&n)[0]);
    out.push_back(((uint8_t *)&n)[1]);
  };
  auto push32 = [&](uint32_t v) {
    uint32_t n = htonl(v);
    for (int i = 0; i < 4; i++) out.push_back(((uint8_t *)&n)[i]);
  };
  push16(0);       // ID
  push16(0x8400);  // FLAGS: QR=1 (Antwort), AA=1 (authoritative)
  push16(0);       // QDCOUNT
  push16(1);       // ANCOUNT
  push16(0);       // NSCOUNT
  push16(0);       // ARCOUNT
  auto nameBytes = encodeDnsName(name);
  out.insert(out.end(), nameBytes.begin(), nameBytes.end());
  push16(1);       // TYPE A
  push16(0x8001);  // CLASS IN, Cache-Flush-Bit gesetzt (mDNS-Konvention fuer eindeutige Records)
  push32(120);     // TTL (Sekunden)
  in_addr addr{};
  inet_pton(AF_INET, ip.c_str(), &addr);
  push16(4);       // RDLENGTH
  auto *b = (uint8_t *)&addr.s_addr;
  for (int i = 0; i < 4; i++) out.push_back(b[i]);
  return out;
}

std::string decodeDnsName(const uint8_t *data, size_t len, size_t &offset) {
  std::vector<std::string> labels;
  while (offset < len) {
    uint8_t l = data[offset];
    if (l == 0) { offset++; break; }
    if ((l & 0xC0) == 0xC0) { offset += 2; break; } // Kompressionszeiger: in Fragen nicht erwartet
    offset++;
    if (offset + l > len) break;
    labels.emplace_back((const char *)&data[offset], l);
    offset += l;
  }
  std::string result;
  for (size_t i = 0; i < labels.size(); i++) {
    if (i) result += '.';
    result += labels[i];
  }
  return result;
}

bool mdnsQueryMatches(const uint8_t *data, size_t len, const std::string &targetName) {
  if (len < 12) return false;
  uint16_t flags = ((uint16_t)data[2] << 8) | data[3];
  if (flags & 0x8000) return false; // Antwort, keine Anfrage
  uint16_t qdcount = ((uint16_t)data[4] << 8) | data[5];
  size_t offset = 12;
  for (uint16_t i = 0; i < qdcount; i++) {
    std::string name = decodeDnsName(data, len, offset);
    if (offset + 4 > len) return false;
    uint16_t qtype = ((uint16_t)data[offset] << 8) | data[offset + 1];
    uint16_t qclass = ((uint16_t)data[offset + 2] << 8) | data[offset + 3];
    offset += 4;
    if (toLower(name) == targetName && (qtype == 1 || qtype == 255) && (qclass & 0x7FFF) == 1) return true;
  }
  return false;
}

void mdnsLoop(const std::string &hostname, const std::string &ip, std::atomic<bool> &stop) {
  std::string targetName = toLower(hostname + ".local");

  int recvSock = socket(AF_INET, SOCK_DGRAM, 0);
  int opt = 1;
  setsockopt(recvSock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#ifdef SO_REUSEPORT
  setsockopt(recvSock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif
  sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(MDNS_PORT);
  if (bind(recvSock, (sockaddr *)&addr, sizeof(addr)) != 0) {
    std::cerr << "[sim] mDNS deaktiviert (Port " << MDNS_PORT << " nicht verfuegbar: " << std::strerror(errno)
              << ")\n";
    close(recvSock);
    return;
  }

  ip_mreq mreq{};
  inet_pton(AF_INET, MDNS_ADDR, &mreq.imr_multiaddr);
  inet_pton(AF_INET, ip.c_str(), &mreq.imr_interface);
  if (setsockopt(recvSock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) != 0) {
    std::cerr << "[sim] mDNS deaktiviert (Multicast-Beitritt fehlgeschlagen: " << std::strerror(errno) << ")\n";
    close(recvSock);
    return;
  }

  uint8_t ttl = 255;
  setsockopt(recvSock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  in_addr ifaceAddr{};
  inet_pton(AF_INET, ip.c_str(), &ifaceAddr);
  setsockopt(recvSock, IPPROTO_IP, IP_MULTICAST_IF, &ifaceAddr, sizeof(ifaceAddr));

  std::vector<uint8_t> answer = buildMdnsAAnswer(targetName, ip);
  sockaddr_in mdnsAddr{};
  mdnsAddr.sin_family = AF_INET;
  mdnsAddr.sin_port = htons(MDNS_PORT);
  inet_pton(AF_INET, MDNS_ADDR, &mdnsAddr.sin_addr);

  // Antworten muessen laut RFC 6762 vom UDP-Quellport 5353 gesendet werden,
  // sonst verwerfen strikte mDNS-Resolver (z.B. nss-mdns/Avahi) sie
  // stillschweigend - daher denselben Socket wie zum Empfangen nutzen statt
  // einen separaten Sende-Socket mit zufaelligem Quellport.
  uint8_t buf[2048];
  while (!stop.load()) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(recvSock, &readSet);
    timeval tv{1, 0};
    int r = select(recvSock + 1, &readSet, nullptr, nullptr, &tv);
    if (r <= 0) continue;
    ssize_t n = recv(recvSock, buf, sizeof(buf), 0);
    if (n <= 0) continue;
    if (mdnsQueryMatches(buf, (size_t)n, targetName)) {
      sendto(recvSock, answer.data(), answer.size(), 0, (sockaddr *)&mdnsAddr, sizeof(mdnsAddr));
    }
  }
  close(recvSock);
}

// ---- CLI --------------------------------------------------------------------

struct Options {
  std::string name = "Sim-1";
  std::string room = "Sim-Room";
  bool nameGiven = false;
  bool roomGiven = false;
  // Repeatable: registriert eine weitere Raetsel-Komponente auf diesem
  // simulierten Geraet (analog mehreren addComponent()-Aufrufen auf einem
  // ESP32, siehe Client/client.hpp). Ohne --component wird genau eine
  // Komponente aus name/room angelegt.
  std::vector<std::pair<std::string, std::string>> components;
  int udpPort = 4210;
  int httpPort = 80;
  std::string token = "changeme-venue-token";
  int totalSteps = 5;
  std::string mdnsHostname = "escapemanager";
  bool mdnsEnabled = true;
  std::string managerHtmlPath;
};

// Ohne --name/--room/--component werden diese Beispielkomponenten angelegt
// (statt nur einer) - so laesst sich die Mehrkomponenten-/Mehrraum-Ansicht in
// Manager/manager.html ohne manuelle CLI-Angaben durchtesten, analog
// DEFAULT_DEMO_COMPONENTS in escape_component_sim.py.
const std::vector<std::pair<std::string, std::string>> kDefaultDemoComponents = {
    {"Laser-1", "Raum-A"},
    {"Kartenleser-1", "Raum-A"},
    {"Kamera-1", "Raum-B"},
    {"Drucksensor-1", "Raum-B"},
};

Options parseArgs(int argc, char **argv) {
  Options opts;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    auto nextVal = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
    if (arg == "--name") { opts.name = nextVal(); opts.nameGiven = true; }
    else if (arg == "--room") { opts.room = nextVal(); opts.roomGiven = true; }
    else if (arg == "--component") {
      std::string spec = nextVal();
      size_t colon = spec.find(':');
      if (colon == std::string::npos || colon == 0 || colon + 1 >= spec.size()) {
        std::cerr << "--component erwartet NAME:ROOM, bekommen: \"" << spec << "\"\n";
        std::exit(1);
      }
      opts.components.emplace_back(spec.substr(0, colon), spec.substr(colon + 1));
    }
    else if (arg == "--udp-port") opts.udpPort = std::atoi(nextVal().c_str());
    else if (arg == "--http-port") opts.httpPort = std::atoi(nextVal().c_str());
    else if (arg == "--token") opts.token = nextVal();
    else if (arg == "--total-steps") opts.totalSteps = std::atoi(nextVal().c_str());
    else if (arg == "--mdns-hostname") opts.mdnsHostname = nextVal();
    else if (arg == "--no-mdns") opts.mdnsEnabled = false;
    else if (arg == "--manager-html") opts.managerHtmlPath = nextVal();
    else if (arg == "--help" || arg == "-h") {
      std::cout << "Optionen: --name --room --component NAME:ROOM (mehrfach) --udp-port --http-port "
                   "--token --total-steps --mdns-hostname --no-mdns --manager-html\n";
      std::exit(0);
    }
  }
  if (opts.components.empty()) {
    if (opts.nameGiven || opts.roomGiven) opts.components.emplace_back(opts.name, opts.room);
    else opts.components = kDefaultDemoComponents;
  }
  return opts;
}

std::atomic<bool> g_stop{false};
void handleSignal(int) { g_stop.store(true); }

} // namespace

int main(int argc, char **argv) {
  Options opts = parseArgs(argc, argv);
  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);

  std::string ip = getLocalIp();
  std::string broadcastIp = computeBroadcastAddress(ip);
  std::string mac = getLocalMac(ip);
  DeviceState device;
  // std::list statt std::vector: ComponentState enthaelt einen std::mutex und
  // eine Referenz auf DeviceState, ist also weder kopier- noch verschiebbar -
  // std::list::emplace_back() konstruiert in-place und muss beim Wachsen nie
  // vorhandene Elemente verschieben (im Gegensatz zu std::vector bei Realloc).
  std::list<ComponentState> components;
  int nextId = 0;
  for (auto &[name, room] : opts.components) {
    int id = nextId++;
    components.emplace_back(id, name, room, opts.totalSteps, device, resolveComponentUuid(opts.httpPort, id, mac));
  }
  PeerTable peers;

  int sendSock = socket(AF_INET, SOCK_DGRAM, 0);
  int broadcastEnable = 1;
  setsockopt(sendSock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

  std::mt19937 rng(std::random_device{}());
  std::uniform_real_distribution<double> jitterDist(0.0, SimConfig::HEARTBEAT_JITTER_S);
  double jitterS = jitterDist(rng);

  std::thread broadcastThread(broadcastLoop, sendSock, opts.udpPort, std::ref(components), std::ref(device),
                               std::cref(ip), std::cref(broadcastIp), jitterS, std::ref(g_stop));
  std::thread listenThread(listenLoop, opts.udpPort, std::ref(components), std::ref(peers), std::ref(g_stop));
  std::thread mdnsThread;
  if (opts.mdnsEnabled) {
    mdnsThread = std::thread(mdnsLoop, std::cref(opts.mdnsHostname), std::cref(ip), std::ref(g_stop));
  }

  std::string managerHtmlPath = findManagerHtml(opts.managerHtmlPath);
  std::string managerHtml = managerHtmlPath.empty() ? std::string() : readFileToString(managerHtmlPath);

  std::string compDesc;
  for (auto &c : components) {
    auto [name, room] = c.identity();
    if (!compDesc.empty()) compDesc += ", ";
    compDesc += name + " (" + room + ") [id=" + std::to_string(c.id()) + "]";
  }
  std::cout << "[sim] " << compDesc << " auf " << ip << ":" << opts.httpPort
            << ", UDP-Broadcast Port " << opts.udpPort << " -> " << broadcastIp << "\n";
  std::cout << "[sim] Manager-Einstellungen: Quelle = http://" << ip << ":" << opts.httpPort << "\n";
  if (opts.mdnsEnabled) {
    std::cout << "[sim] mDNS: http://" << opts.mdnsHostname << ".local:" << opts.httpPort << "/ (falls vom Betriebssystem unterstuetzt)\n";
  }
  if (!managerHtml.empty()) {
    std::cout << "[sim] manager.html geladen von " << managerHtmlPath << "\n";
  } else {
    std::cerr << "[sim] Warnung: manager.html nicht gefunden - \"/\" liefert nur Klartext (siehe --manager-html).\n";
  }

  httpServerLoop(opts.httpPort, components, device, peers, opts.token, ip, managerHtml, g_stop);

  g_stop.store(true);
  broadcastThread.join();
  listenThread.join();
  if (mdnsThread.joinable()) mdnsThread.join();
  close(sendSock);
  return 0;
}
