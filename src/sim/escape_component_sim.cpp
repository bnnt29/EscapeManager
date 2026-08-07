// Simuliert eine Escape-Room-Komponente auf dem PC (Gegenstueck zu
// escape_component_sim.py). Verhaelt sich nach aussen identisch zur
// ESP32-Firmware (Client/client.hpp + client.cpp) und manager/manager.html:
//   - UDP-Broadcast (Heartbeat + Jitter + Change-getriebene Broadcasts)
//   - UDP-Empfang fremder Broadcasts -> eigene Peer-Tabelle
//   - HTTP GET  /             (liefert manager/manager.html, wie die ESP32-Firmware)
//   - HTTP GET  /status.json  (eigener Zustand + bekannte Peers, unauthentifiziert)
//   - HTTP POST /action       (X-Auth-Token erforderlich)
//   - HTTP POST /config       (X-Auth-Token erforderlich, setzt Name/Raum + CustomConfig)
//   - HTTP POST /plan, GET /plan-skeleton.json, POST /plan-skeleton
//
// WICHTIG: Die eigentliche Protokoll-Logik (JSON-Wire-Format, Validierung,
// Peer-Tabelle, /action|/config|/plan-Anfragebehandlung) lebt NICHT mehr in
// dieser Datei, sondern im plattformunabhaengigen Client/Protocol.hpp+cpp
// (gemeinsam mit Client/Json.hpp+cpp), das auch von der ESP32-Firmware
// verwendet wird. Diese Datei ist bewusst nur noch ein duenner Wrapper, der
// - die "Hardware" simuliert (POSIX-Sockets statt WiFiUDP/WebServer,
//   Dateien im Temp-Verzeichnis statt NVS/Preferences), und
// - die Komponenten-IMPLEMENTIERUNG bereitstellt (ComponentState: Raetsel-
//   Schritte, Aktionen, Beispiel-CustomConfig - das Gegenstueck zu einem
//   echten Geraete-main.cpp, das EscapeComponent::on*()-Callbacks registriert).
// Aendert sich das Protokoll, muss das nur in Client/Protocol.* angepasst
// werden - diese Datei profitiert automatisch davon.
//
// Nutzt sonst nur POSIX-Sockets (Linux/macOS), keine externen Abhaengigkeiten.
//
// Bauen (mehrere Uebersetzungseinheiten - Protocol.cpp/Json.cpp liegen in Client/):
//   g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp ../protocol/Protocol.cpp ../protocol/Json.cpp
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
cd src/sim
g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp ../protocol/Protocol.cpp ../protocol/Json.cpp

sudo ./escape_component_sim --name Laser-1 --room Raum-A
# oder ohne sudo:
./escape_component_sim --name Laser-1 --room Raum-A --http-port 8080


cd src/sim && g++ -std=c++17 -pthread -O2 -o escape_component_sim escape_component_sim.cpp ../protocol/Protocol.cpp ../protocol/Json.cpp && ./escape_component_sim --name Laser-1 --room Raum-A --http-port 8080
*/

#include <arpa/inet.h>
#if defined(__has_include)
#if __has_include(<ifaddrs.h>)
#include <ifaddrs.h>
#define ESCAPE_SIM_HAVE_IFADDRS 1
#endif
#endif
#ifndef ESCAPE_SIM_HAVE_IFADDRS
#define ESCAPE_SIM_HAVE_IFADDRS 0
#endif
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

#include "../protocol/Protocol.hpp"

using EscapeProtocol::CustomConfigDef;
using EscapeProtocol::CustomConfigType;
using EscapeProtocol::PeerInfo;
using EscapeProtocol::PeerTable;

namespace {

// Aus EscapeConfig::HEARTBEAT_INTERVAL_MS/... (Millisekunden, siehe
// Client/EscapeConfig.hpp) abgeleitete Sekunden-Werte fuer die
// chrono::duration<double>-basierten Zeitschleifen dieser Datei - so bleibt
// EscapeConfig die EINZIGE Quelle fuer die eigentlichen Zahlenwerte.
constexpr double kHeartbeatIntervalS = EscapeConfig::HEARTBEAT_INTERVAL_MS / 1000.0;
constexpr double kHeartbeatJitterS = EscapeConfig::HEARTBEAT_JITTER_MS / 1000.0;
constexpr double kChangeMinGapS = EscapeConfig::CHANGE_MIN_GAP_MS / 1000.0;

std::string toLower(const std::string &s) {
  std::string r = s;
  std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return (char)std::tolower(c); });
  return r;
}

// Monotone Millisekunden seit Prozessstart - dient als "millis()"-Ersatz fuer
// PeerTable/Protocol-Funktionen, die einen ueberlaufsicheren uint32_t-Zaehler
// erwarten (analog Arduino millis() auf dem ESP32). Function-lokales static
// ist seit C++11 garantiert threadsicher initialisiert (kein Data-Race trotz
// mehrerer Threads in diesem Sim).
uint32_t monotonicMillis() {
  static const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();
  return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start)
      .count();
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
// in Client/client.hpp) - das Gegenstueck zu den on*()-Callbacks, die ein
// echtes Geraete-main.cpp bei EscapeComponent registrieren wuerde. -----------

class ComponentState {
public:
  ComponentState(int id, std::string name, std::string room, int totalSteps, DeviceState &device, std::string uuid)
      : id_(id), uuid_(std::move(uuid)), name_(std::move(name)), room_(std::move(room)), device_(device),
        totalSteps_(totalSteps) {
    // Beispielhafte Custom-Konfiguration, um das Protokoll end-to-end testen
    // zu koennen (Manager-Oberflaeche <-> /status.json <-> POST /config).
    CustomConfigDef brightness{};
    EscapeProtocol::copyBounded(brightness.key, sizeof(brightness.key), "brightness");
    brightness.type = CustomConfigType::Range;
    brightness.rangeMin = 0;
    brightness.rangeMax = 100;
    EscapeProtocol::copyBounded(brightness.value, sizeof(brightness.value), "50");
    customConfig_.push_back(brightness);

    CustomConfigDef label{};
    EscapeProtocol::copyBounded(label.key, sizeof(label.key), "label");
    label.type = CustomConfigType::Text;
    label.textMaxLen = 32;
    customConfig_.push_back(label);

    CustomConfigDef difficulty{};
    EscapeProtocol::copyBounded(difficulty.key, sizeof(difficulty.key), "difficulty");
    difficulty.type = CustomConfigType::Select;
    for (const char *opt : {"easy", "medium", "hard"}) {
      EscapeProtocol::copyBounded(difficulty.options[difficulty.optionCount], sizeof(difficulty.options[0]), opt);
      difficulty.optionCount++;
    }
    EscapeProtocol::copyBounded(difficulty.value, sizeof(difficulty.value), "medium");
    customConfig_.push_back(difficulty);
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

  std::vector<CustomConfigDef> customConfigSnapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return customConfig_;
  }

  // Wird nur fuer bereits (gegen customConfigSnapshot()) validierte
  // Schluessel/Werte aufgerufen - siehe EscapeProtocol::handleConfigRequest().
  bool setCustomConfigValue(const std::string &key, const std::string &value) {
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto &d : customConfig_) {
      if (key == d.key) {
        EscapeProtocol::copyBounded(d.value, sizeof(d.value), value.c_str());
        device_.dirty.store(true);
        return true;
      }
    }
    return false;
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

  // Analog EscapeComponent::pushEvent() in Client/client.hpp+cpp: erhoeht den
  // Aktivitaets-Zaehler + setzt die Klartext-Meldung, damit sie beim naechsten
  // Broadcast an alle Manager (auch andere als die anfragende Instanz)
  // weitergereicht wird.
  void pushEvent(const std::string &msg) {
    {
      std::lock_guard<std::mutex> lock(mutex_);
      eventSeq_++;
      eventMsg_ = msg.substr(0, 64);
    }
    device_.dirty.store(true);
  }

  std::pair<std::string, std::string> identity() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return {name_, room_};
  }

  // Fuellt eine PeerInfo-Momentaufnahme dieser EINEN Komponente (alles AUSSER
  // id/ip/battery/lastSeenMs, die kommen geraeteweit von aussen dazu) - siehe
  // SimComponentHost::snapshot() weiter unten und EscapeProtocol::ComponentHost.
  void fillSnapshot(PeerInfo &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    EscapeProtocol::copyBounded(out.uuid, sizeof(out.uuid), uuid_.c_str());
    EscapeProtocol::copyBounded(out.name, sizeof(out.name), name_.c_str());
    EscapeProtocol::copyBounded(out.room, sizeof(out.room), room_.c_str());

    out.errorCount = 0;
    for (size_t i = 0; i < errors_.size() && out.errorCount < EscapeConfig::MAX_ERRORS; i++) {
      EscapeProtocol::copyBounded(out.errors[out.errorCount], sizeof(out.errors[0]), errors_[i].c_str());
      out.errorCount++;
    }

    out.actionCount = 0;
    for (size_t i = 0; i < actions_.size() && out.actionCount < EscapeConfig::MAX_ACTIONS; i++) {
      EscapeProtocol::copyBounded(out.actions[out.actionCount], sizeof(out.actions[0]), actions_[i].c_str());
      out.actionCount++;
    }

    out.puzzleStep = (uint16_t)step_;
    out.puzzleTotalSteps = (uint16_t)totalSteps_;
    EscapeProtocol::copyBounded(out.puzzleState, sizeof(out.puzzleState), puzzleStateHtml().c_str());
    out.puzzleIsHtml = true;

    out.customConfigCount = 0;
    for (size_t i = 0; i < customConfig_.size() && out.customConfigCount < EscapeConfig::MAX_CUSTOM_CONFIGS; i++) {
      out.customConfig[out.customConfigCount++] = customConfig_[i];
    }

    if (!plan_.empty()) {
      EscapeProtocol::copyBounded(out.plan, sizeof(out.plan), plan_.c_str());
    } else {
      out.plan[0] = '\0';
    }

    out.eventSeq = eventSeq_;
    EscapeProtocol::copyBounded(out.eventMsg, sizeof(out.eventMsg), eventMsg_.c_str());
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
  std::string plan_;
  int eventSeq_ = 0;
  std::string eventMsg_;
  DeviceState &device_;
  std::vector<std::string> errors_;
  std::vector<std::string> actions_{"reset", "next_step", "solve", "toggle_error", "drain_battery"};
  int step_ = 0;
  int totalSteps_ = 5;
  std::vector<CustomConfigDef> customConfig_;
};

// Bindet die simulierten Komponenten (siehe ComponentState oben) an die
// plattformunabhaengige Protokoll-Logik in Client/Protocol.* an - das
// Gegenstueck zur EscapeComponent-Klasse selbst auf der ESP32-Seite.
class SimComponentHost : public EscapeProtocol::ComponentHost {
public:
  SimComponentHost(std::list<ComponentState> &components, DeviceState &device)
      : components_(components), device_(device) {}

  uint8_t componentCount() const override { return (uint8_t)components_.size(); }
  int8_t battery() const override { return (int8_t)device_.battery(); }

  void identity(uint8_t index, std::string &name, std::string &room) const override {
    const ComponentState *c = find(index);
    if (!c) return;
    auto id = c->identity();
    name = id.first;
    room = id.second;
  }

  void snapshot(uint8_t index, PeerInfo &out) const override {
    const ComponentState *c = find(index);
    if (c) c->fillSnapshot(out);
  }

  bool applyAction(uint8_t index, const std::string &action) override {
    ComponentState *c = find(index);
    return c ? c->applyAction(action) : false;
  }

  void setIdentity(uint8_t index, const std::string &name, const std::string &room) override {
    ComponentState *c = find(index);
    if (c) c->setIdentity(name, room);
  }

  void customConfigDefs(uint8_t index, std::vector<CustomConfigDef> &out) const override {
    const ComponentState *c = find(index);
    out = c ? c->customConfigSnapshot() : std::vector<CustomConfigDef>();
  }

  bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) override {
    ComponentState *c = find(index);
    return c ? c->setCustomConfigValue(key, value) : false;
  }

  void setPlan(uint8_t index, const std::string &planJson) override {
    ComponentState *c = find(index);
    if (c) c->setPlan(planJson);
  }

  void pushEvent(uint8_t index, const std::string &msg) override {
    ComponentState *c = find(index);
    if (c) c->pushEvent(msg);
  }

  void markDirty() override { device_.dirty.store(true); }

private:
  ComponentState *find(uint8_t index) {
    for (auto &c : components_) {
      if (c.id() == index) return &c;
    }
    return nullptr;
  }
  const ComponentState *find(uint8_t index) const {
    for (auto &c : components_) {
      if (c.id() == index) return &c;
    }
    return nullptr;
  }

  std::list<ComponentState> &components_;
  DeviceState &device_;
};

// ---- Minimaler HTTP-Server (simulierte "Hardware": POSIX-Sockets statt
// WiFiUDP/WebServer) ----------------------------------------------------------

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

// Sucht manager/manager.html analog zum PlatformIO-Embed der ESP32-Firmware,
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
    if (slash != std::string::npos) candidates.push_back(dir.substr(0, slash) + "/../manager/manager.html");
  }
#endif
  candidates.push_back("../manager/manager.html");
  candidates.push_back("manager/manager.html");
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
                       : code == 413 ? "Payload Too Large"
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

void handleClient(int fd, SimComponentHost &host, PeerTable &peers, DeviceState &device, const std::string &token,
                   const std::string &ip, const std::string &managerHtml) {
  HttpRequest req;
  if (!readHttpRequest(fd, req)) {
    close(fd);
    return;
  }

  auto checkAuth = [&]() {
    auto it = req.headers.find("x-auth-token");
    return it != req.headers.end() && EscapeProtocol::constantTimeEquals(it->second, token);
  };
  auto respond = [&](const EscapeProtocol::HttpResult &r) { sendResponse(fd, r.status, "application/json", r.body); };

  if (req.method == "OPTIONS" && (req.path == "/action" || req.path == "/config" || req.path == "/plan" ||
                                   req.path == "/plan-skeleton")) {
    sendResponse(fd, 204, "text/plain", "",
                 {"Access-Control-Allow-Methods: GET, POST, OPTIONS",
                  "Access-Control-Allow-Headers: Content-Type, X-Auth-Token"});
  } else if (req.method == "GET" && req.path == "/plan-skeleton.json") {
    respond(EscapeProtocol::handlePlanSkeletonGetRequest(device.planSkeleton()));
  } else if (req.method == "GET" && req.path == "/status.json") {
    uint32_t now = monotonicMillis();
    peers.expireStale(now);
    sendResponse(fd, 200, "application/json", EscapeProtocol::buildStatusJson(host, peers, ip, now));
  } else if (req.method == "GET" && req.path == "/") {
    if (!managerHtml.empty()) {
      sendResponse(fd, 200, "text/html; charset=utf-8", managerHtml);
    } else {
      std::string names;
      for (uint8_t i = 0; i < host.componentCount(); i++) {
        std::string name, room;
        host.identity(i, name, room);
        if (!names.empty()) names += ", ";
        names += name + " (" + room + ")";
      }
      sendResponse(fd, 200, "text/plain; charset=utf-8", "EscapeComponentSim: " + names + " auf " + ip + "\n");
    }
  } else if (req.method == "POST" && req.path == "/action") {
    respond(EscapeProtocol::handleActionRequest(host, {req.body, checkAuth()}));
  } else if (req.method == "POST" && req.path == "/config") {
    respond(EscapeProtocol::handleConfigRequest(host, {req.body, checkAuth()}));
  } else if (req.method == "POST" && req.path == "/plan") {
    respond(EscapeProtocol::handlePlanRequest(host, {req.body, checkAuth()}));
  } else if (req.method == "POST" && req.path == "/plan-skeleton") {
    std::string storage = device.planSkeleton();
    EscapeProtocol::HttpResult r = EscapeProtocol::handlePlanSkeletonPostRequest(host, {req.body, checkAuth()}, storage);
    if (r.status == 200) device.setPlanSkeleton(storage);
    respond(r);
  } else {
    sendResponse(fd, 404, "application/json", "{\"error\":\"not found\"}");
  }
  close(fd);
}

void httpServerLoop(int port, SimComponentHost &host, PeerTable &peers, DeviceState &device, const std::string &token,
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
    handleClient(clientFd, host, peers, device, token, ip, managerHtml);
  }
  close(listenFd);
}

// ---- Broadcast senden / empfangen -------------------------------------------

void broadcastLoop(int sock, int udpPort, SimComponentHost &host, DeviceState &device, const std::string &ip,
                    const std::string &broadcastIp, double jitterS, std::atomic<bool> &stop) {
  auto lastSend = std::chrono::steady_clock::now() - std::chrono::hours(1);
  sockaddr_in bcastAddr{};
  bcastAddr.sin_family = AF_INET;
  bcastAddr.sin_port = htons((uint16_t)udpPort);
  inet_pton(AF_INET, broadcastIp.c_str(), &bcastAddr.sin_addr);

  while (!stop.load()) {
    auto now = std::chrono::steady_clock::now();
    double sinceLast = std::chrono::duration<double>(now - lastSend).count();
    bool dueHeartbeat = sinceLast >= (kHeartbeatIntervalS + jitterS);
    bool dueChange = device.dirty.load() && sinceLast >= kChangeMinGapS;
    if (dueHeartbeat || dueChange) {
      // Ein Paket pro Geraet: gemeinsames ip/battery, plus "components"-Array
      // mit je einem Eintrag pro ComponentState - siehe buildBroadcastJson().
      std::string payload = EscapeProtocol::buildBroadcastJson(host, ip);
      sendto(sock, payload.data(), payload.size(), 0, (sockaddr *)&bcastAddr, sizeof(bcastAddr));
      lastSend = now;
      device.dirty.store(false);
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

void listenLoop(int udpPort, SimComponentHost &host, PeerTable &peers, std::atomic<bool> &stop) {
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

    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &srcAddr.sin_addr, ipStr, sizeof(ipStr));
    EscapeProtocol::ingestBroadcast(std::string(buf, (size_t)n), ipStr, monotonicMillis(), host, peers);
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
#if ESCAPE_SIM_HAVE_IFADDRS
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
#else
  (void)localIp;
  return "255.255.255.255";
#endif
}

// MAC-Adresse des Interfaces mit localIp - Grundlage der Komponenten-
// Identitaet (siehe resolveComponentUuid()), analog WiFi.macAddress() in
// Client/client.cpp bzw. get_local_mac() in escape_component_sim.py. Nur unter
// Linux implementiert (SIOCGIFHWADDR ist linux-spezifisch); leerer String
// (Zufalls-Fallback in resolveComponentUuid()) auf anderen Plattformen oder
// falls keine Hardware-Adresse ermittelbar ist.
std::string getLocalMac(const std::string &localIp) {
#if defined(__linux__) && ESCAPE_SIM_HAVE_IFADDRS
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
  EscapeJson::Value doc;
  if (!EscapeJson::parse(ss.str(), doc) || doc.type != EscapeJson::Type::Object) return result;
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
  EscapeJson::Value doc;
  doc.type = EscapeJson::Type::Object;
  for (auto &kv : state) {
    EscapeJson::Value v;
    v.type = EscapeJson::Type::String;
    v.stringValue = kv.second;
    doc.objectValue[std::to_string(kv.first)] = std::move(v);
  }
  std::string out;
  EscapeJson::stringify(doc, out);
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
// so viel DNS-Paketbau/-Parsing wie fuer diesen einen Zweck noetig. Dies ist
// bewusst NICHT Teil von Client/Protocol.* - ESPmDNS auf dem ESP32 loest das
// bereits fertig, hier wird nur dessen Aussenwirkung fuer den Sim nachgebildet.

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
  int udpPort = EscapeConfig::UDP_PORT;
  int httpPort = EscapeConfig::HTTP_PORT;
  std::string token = EscapeConfig::AUTH_TOKEN;
  int totalSteps = 5;
  std::string mdnsHostname = EscapeConfig::MDNS_HOSTNAME;
  bool mdnsEnabled = true;
  std::string managerHtmlPath;
};

// Ohne --name/--room/--component werden diese Beispielkomponenten angelegt
// (statt nur einer) - so laesst sich die Mehrkomponenten-/Mehrraum-Ansicht in
// manager/manager.html ohne manuelle CLI-Angaben durchtesten, analog
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
  SimComponentHost host(components, device);
  PeerTable peers;

  int sendSock = socket(AF_INET, SOCK_DGRAM, 0);
  int broadcastEnable = 1;
  setsockopt(sendSock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));

  std::mt19937 rng(std::random_device{}());
  std::uniform_real_distribution<double> jitterDist(0.0, kHeartbeatJitterS);
  double jitterS = jitterDist(rng);

  std::thread broadcastThread(broadcastLoop, sendSock, opts.udpPort, std::ref(host), std::ref(device), std::cref(ip),
                               std::cref(broadcastIp), jitterS, std::ref(g_stop));
  std::thread listenThread(listenLoop, opts.udpPort, std::ref(host), std::ref(peers), std::ref(g_stop));
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

  httpServerLoop(opts.httpPort, host, peers, device, opts.token, ip, managerHtml, g_stop);

  g_stop.store(true);
  broadcastThread.join();
  listenThread.join();
  if (mdnsThread.joinable()) mdnsThread.join();
  close(sendSock);
  return 0;
}
