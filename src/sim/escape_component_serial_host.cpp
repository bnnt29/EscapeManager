// EscapeManager-PC-Host fuer Komponenten an einer USB-Serial-Verbindung.
//
// Der PC uebernimmt Netzwerk, Manager-UI und sicheren Transport. Ein Arduino
// muss nur zeilenbegrenztes JSON ueber Serial senden/empfangen. Jede Nachricht
// endet mit '\n'; Diagnoseausgaben, die kein JSON-Objekt sind, werden ignoriert.
//
// Arduino -> PC (vollstaendiger Zustand, beliebig oft sendbar):
//   {"type":"state","battery":87,"components":[
//     {"id":0,"uuid":"door-1","riddleId":"riddle-abc123","name":"Tuer","room":"Raum-A",
//      "errors":[],"actions":["open"],"planActions":["reset","complete"],
//      "puzzle":{"step":1,"totalSteps":3,"state":"bereit","isHtml":false}}
//   ]}
// Optional auf oberster Ebene: "slave":false und "planSkeleton":{...}.
// "riddleId" ist optional (leer, falls der Arduino-Sketch es nicht kennt) -
// siehe PeerInfo::riddleId in protocol/Protocol.hpp.
// Komponentenfelder entsprechen direkt dem components-Eintrag des
// EscapeManager-Broadcastformats (siehe protocol/Protocol.hpp).
//
// PC -> Arduino:
//   {"type":"getState"}
//   {"type":"action","id":0,"action":"open"}
//   {"type":"planAction","id":0,"action":"reset"}
//   {"type":"setIdentity","id":0,"name":"Tuer","room":"Raum-A"}
//   {"type":"setRiddleId","id":0,"value":"riddle-abc123"}
//   {"type":"setConfig","id":0,"key":"brightness","value":"50"}
//   {"type":"setPlan","id":0,"plan":{...}}
//   {"type":"setPlanSkeleton","value":{...}}
//   {"type":"setSlave","value":true}
//   {"type":"event","id":0,"message":"..."}
// Nach einem Befehl sollte der Arduino einen neuen state-Snapshot senden.
//
// Bauen (Linux/macOS, aus src/sim):
//   g++ -std=c++17 -pthread -O2 -o escape_component_serial_host
//     escape_component_serial_host.cpp OpenSslCryptoBackend.cpp
//     ../protocol/Protocol.cpp ../protocol/Json.cpp
//     ../protocol/SecureTransport.cpp -lcrypto
// Starten:
//   ./escape_component_serial_host --serial /dev/ttyACM0 --http-port 8080

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cctype>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <fstream>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "../protocol/Protocol.hpp"
#include "../protocol/SecureTransport.hpp"
#include "OpenSslCryptoBackend.hpp"

namespace {

using EscapeProtocol::PeerInfo;
using EscapeProtocol::PeerTable;
using EscapeProtocol::PeerAddress;
using EscapeProtocol::PeerAddressTable;

constexpr size_t kMaxSerialLine = 32 * 1024;

uint32_t monotonicMillis() {
  static const auto start = std::chrono::steady_clock::now();
  return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(
      std::chrono::steady_clock::now() - start).count();
}

std::string toLower(std::string value) {
  std::transform(value.begin(), value.end(), value.begin(),
                 [](unsigned char c) { return (char)std::tolower(c); });
  return value;
}

std::string jsonString(const std::string &value) {
  std::string out = "\"";
  EscapeJson::appendEscaped(out, value);
  out += '"';
  return out;
}

const EscapeJson::Value *field(const EscapeJson::Value &object, const char *name) {
  return object.type == EscapeJson::Type::Object ? object.find(name) : nullptr;
}

bool jsonBool(const EscapeJson::Value &object, const char *name, bool fallback) {
  const EscapeJson::Value *value = field(object, name);
  return value ? value->asBool(fallback) : fallback;
}

int jsonInt(const EscapeJson::Value &object, const char *name, int fallback) {
  const EscapeJson::Value *value = field(object, name);
  return value ? (int)value->asNumber(fallback) : fallback;
}

std::string rawJson(const EscapeJson::Value &value) {
  std::string out;
  EscapeJson::stringify(value, out);
  return out;
}

speed_t baudConstant(int baud) {
  switch (baud) {
    case 9600: return B9600;
    case 19200: return B19200;
    case 38400: return B38400;
    case 57600: return B57600;
    case 115200: return B115200;
#ifdef B230400
    case 230400: return B230400;
#endif
    default: return 0;
  }
}

class SerialPort {
public:
  SerialPort(std::string path, int baud) : path_(std::move(path)), baud_(baud) {}

  void run(const std::function<void(const std::string &)> &onLine,
           std::atomic<bool> &stop) {
    while (!stop.load()) {
      int fd = openConfigured();
      if (fd < 0) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        continue;
      }
      {
        std::lock_guard<std::mutex> lock(mutex_);
        fd_ = fd;
      }
      std::cout << "[serial] Verbunden: " << path_ << " @ " << baud_ << " Baud\n";
      sendJson("{\"type\":\"getState\"}");
      readLines(fd, onLine, stop);
      {
        std::lock_guard<std::mutex> lock(mutex_);
        if (fd_ == fd) fd_ = -1;
      }
      close(fd);
      if (!stop.load()) {
        std::cerr << "[serial] Verbindung verloren; neuer Versuch in 1 s\n";
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
  }

  bool sendJson(const std::string &json) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (fd_ < 0) return false;
    std::string line = json + "\n";
    size_t offset = 0;
    while (offset < line.size()) {
      ssize_t written = write(fd_, line.data() + offset, line.size() - offset);
      if (written > 0) {
        offset += (size_t)written;
        continue;
      }
      if (written < 0 && errno == EINTR) continue;
      if (written < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        fd_set writeSet;
        FD_ZERO(&writeSet);
        FD_SET(fd_, &writeSet);
        timeval timeout{0, 250000};
        if (select(fd_ + 1, nullptr, &writeSet, nullptr, &timeout) > 0) continue;
      }
      return false;
    }
    return true;
  }

private:
  int openConfigured() const {
    speed_t speed = baudConstant(baud_);
    if (!speed) {
      std::cerr << "[serial] Nicht unterstuetzte Baudrate: " << baud_ << "\n";
      return -1;
    }
    int fd = open(path_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0) {
      std::cerr << "[serial] " << path_ << " nicht verfuegbar: "
                << std::strerror(errno) << "\n";
      return -1;
    }
    termios options{};
    if (tcgetattr(fd, &options) != 0) {
      close(fd);
      return -1;
    }
    cfmakeraw(&options);
    cfsetispeed(&options, speed);
    cfsetospeed(&options, speed);
    options.c_cflag |= CLOCAL | CREAD;
#ifdef CRTSCTS
    options.c_cflag &= ~CRTSCTS;
#endif
    options.c_cc[VMIN] = 0;
    options.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &options) != 0) {
      close(fd);
      return -1;
    }
    tcflush(fd, TCIOFLUSH);
    return fd;
  }

  void readLines(int fd, const std::function<void(const std::string &)> &onLine,
                 std::atomic<bool> &stop) {
    std::string pending;
    char buffer[1024];
    while (!stop.load()) {
      fd_set readSet;
      FD_ZERO(&readSet);
      FD_SET(fd, &readSet);
      timeval timeout{0, 500000};
      int selected = select(fd + 1, &readSet, nullptr, nullptr, &timeout);
      if (selected < 0 && errno == EINTR) continue;
      if (selected < 0) return;
      if (selected == 0) continue;
      ssize_t count = read(fd, buffer, sizeof(buffer));
      if (count == 0) continue;
      if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
      if (count < 0) return;
      pending.append(buffer, (size_t)count);
      if (pending.size() > kMaxSerialLine && pending.find('\n') == std::string::npos) {
        pending.clear();
        std::cerr << "[serial] Uebergrosse Zeile verworfen\n";
      }
      size_t newline = 0;
      while ((newline = pending.find('\n')) != std::string::npos) {
        std::string line = pending.substr(0, newline);
        pending.erase(0, newline + 1);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) onLine(line);
      }
    }
  }

  std::string path_;
  int baud_;
  std::mutex mutex_;
  int fd_ = -1;
};

struct ComponentRecord {
  uint8_t serialId = 0;
  PeerInfo state;
};

class BridgeState {
public:
  bool applySerialLine(const std::string &line) {
    if (line.empty() || line.front() != '{') return false;
    EscapeJson::Value document;
    if (!EscapeJson::parse(line, document) || document.type != EscapeJson::Type::Object) {
      std::cerr << "[serial] Ungueltiges JSON verworfen\n";
      return false;
    }
    const EscapeJson::Value *type = document.find("type");
    if (!type || type->asString() != "state") return false;
    const EscapeJson::Value *components = document.find("components");
    if (!components || components->type != EscapeJson::Type::Array ||
        components->arrayValue.size() > EscapeConfig::MAX_LOCAL_COMPONENTS) {
      std::cerr << "[serial] state ohne gueltiges components-Array verworfen\n";
      return false;
    }

    std::vector<ComponentRecord> next;
    for (size_t index = 0; index < components->arrayValue.size(); index++) {
      const EscapeJson::Value &component = components->arrayValue[index];
      if (component.type != EscapeJson::Type::Object) return false;
      ComponentRecord record;
      int serialId = jsonInt(component, "id", (int)index);
      if (serialId < 0 || serialId > 255) return false;
      record.serialId = (uint8_t)serialId;
      EscapeProtocol::parseComponentIntoPeer(component, record.state);
      if (!record.state.name[0] || !record.state.room[0]) {
        std::cerr << "[serial] Komponente ohne name/room verworfen\n";
        return false;
      }
      next.push_back(record);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    components_ = std::move(next);
    battery_ = std::max(-1, std::min(100, jsonInt(document, "battery", battery_)));
    slave_ = jsonBool(document, "slave", slave_);
    const EscapeJson::Value *skeleton = document.find("planSkeleton");
    if (skeleton) planSkeleton_ = rawJson(*skeleton);
    dirty_.store(true);
    std::cout << "[serial] Zustand aktualisiert: " << components_.size()
              << " Komponente(n), Batterie " << battery_ << "\n";
    return true;
  }

  uint8_t componentCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return (uint8_t)components_.size();
  }

  bool identity(uint8_t index, std::string &name, std::string &room) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return false;
    name = components_[index].state.name;
    room = components_[index].state.room;
    return true;
  }

  bool snapshot(uint8_t index, PeerInfo &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return false;
    out = components_[index].state;
    return true;
  }

  bool customConfig(uint8_t index, std::vector<EscapeProtocol::CustomConfigDef> &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return false;
    const PeerInfo &component = components_[index].state;
    out.assign(component.customConfig, component.customConfig + component.customConfigCount);
    return true;
  }

  bool serialId(uint8_t index, uint8_t &out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return false;
    out = components_[index].serialId;
    return true;
  }

  void updateIdentity(uint8_t index, const std::string &name, const std::string &room) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return;
    EscapeProtocol::copyBounded(components_[index].state.name,
                                sizeof(components_[index].state.name), name.c_str());
    EscapeProtocol::copyBounded(components_[index].state.room,
                                sizeof(components_[index].state.room), room.c_str());
    dirty_.store(true);
  }

  void updateRiddleId(uint8_t index, const std::string &riddleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (index >= components_.size()) return;
    EscapeProtocol::copyBounded(components_[index].state.riddleId,
                                sizeof(components_[index].state.riddleId), riddleId.c_str());
    dirty_.store(true);
  }

  int8_t battery() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return (int8_t)battery_;
  }

  bool slave() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return slave_;
  }

  void setSlave(bool value) {
    std::lock_guard<std::mutex> lock(mutex_);
    slave_ = value;
    dirty_.store(true);
  }

  std::string planSkeleton() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return planSkeleton_.empty() ? "{}" : planSkeleton_;
  }

  void setPlanSkeleton(const std::string &value) {
    std::lock_guard<std::mutex> lock(mutex_);
    planSkeleton_ = value;
    dirty_.store(true);
  }

  std::atomic<bool> &dirty() { return dirty_; }

private:
  mutable std::mutex mutex_;
  std::vector<ComponentRecord> components_;
  int battery_ = -1;
  bool slave_ = false;
  std::string planSkeleton_ = "{}";
  std::atomic<bool> dirty_{true};
};

class SerialProtocolAdapter : public EscapeProtocol::ProtocolAdapter {
public:
  SerialProtocolAdapter(BridgeState &state, SerialPort &serial)
      : state_(state), serial_(serial) {}

  uint8_t componentCount() const override { return state_.componentCount(); }
  int8_t battery() const override { return state_.battery(); }
  uint32_t upTimeMs() const override { return monotonicMillis(); }
  bool isSlave() const override { return state_.slave(); }

  void setSlave(bool slave) override {
    if (serial_.sendJson("{\"type\":\"setSlave\",\"value\":" +
                         std::string(slave ? "true" : "false") + "}")) {
      state_.setSlave(slave);
    }
  }

  void markDirty() override { state_.dirty().store(true); }

  void identity(uint8_t index, std::string &name, std::string &room) const override {
    state_.identity(index, name, room);
  }

  void snapshot(uint8_t index, PeerInfo &out) const override {
    state_.snapshot(index, out);
  }

  void customConfigDefs(uint8_t index,
                        std::vector<EscapeProtocol::CustomConfigDef> &out) const override {
    out.clear();
    state_.customConfig(index, out);
  }

  bool applyAction(uint8_t index, const std::string &action) override {
    return sendIndexed(index, "{\"type\":\"action\",\"id\":", 
                       ",\"action\":" + jsonString(action) + "}");
  }

  bool applyPlanAction(uint8_t index, EscapeProtocol::PlanAction action) override {
    return sendIndexed(index, "{\"type\":\"planAction\",\"id\":",
                       ",\"action\":" + jsonString(EscapeProtocol::planActionName(action)) + "}");
  }

  void setIdentity(uint8_t index, const std::string &name,
                   const std::string &room) override {
    uint8_t id = 0;
    if (!state_.serialId(index, id)) return;
    std::string message = "{\"type\":\"setIdentity\",\"id\":" + std::to_string(id) +
                          ",\"name\":" + jsonString(name) +
                          ",\"room\":" + jsonString(room) + "}";
    if (serial_.sendJson(message)) state_.updateIdentity(index, name, room);
  }

  void setRiddleId(uint8_t index, const std::string &riddleId) override {
    uint8_t id = 0;
    if (!state_.serialId(index, id)) return;
    std::string message = "{\"type\":\"setRiddleId\",\"id\":" + std::to_string(id) +
                          ",\"value\":" + jsonString(riddleId) + "}";
    if (serial_.sendJson(message)) state_.updateRiddleId(index, riddleId);
  }

  bool setCustomConfigValue(uint8_t index, const std::string &key,
                            const std::string &value) override {
    return sendIndexed(index, "{\"type\":\"setConfig\",\"id\":",
                       ",\"key\":" + jsonString(key) +
                       ",\"value\":" + jsonString(value) + "}");
  }

  void setPlan(uint8_t index, const std::string &planJson) override {
    sendIndexed(index, "{\"type\":\"setPlan\",\"id\":",
                ",\"plan\":" + (planJson.empty() ? std::string("null") : planJson) + "}");
  }

  void pushEvent(uint8_t index, const std::string &message) override {
    sendIndexed(index, "{\"type\":\"event\",\"id\":",
                ",\"message\":" + jsonString(message) + "}");
  }

private:
  bool sendIndexed(uint8_t index, const std::string &prefix,
                   const std::string &suffix) {
    uint8_t id = 0;
    if (!state_.serialId(index, id)) return false;
    return serial_.sendJson(prefix + std::to_string(id) + suffix);
  }

  BridgeState &state_;
  SerialPort &serial_;
};

struct HttpRequest {
  std::string method;
  std::string path;
  std::string query;
  std::map<std::string, std::string> headers;
  std::string body;
  bool bodyTooLarge = false;
};

bool readHttpRequest(int fd, HttpRequest &request) {
  std::string buffer;
  char chunk[4096];
  size_t headerEnd = std::string::npos;
  while (headerEnd == std::string::npos) {
    ssize_t count = recv(fd, chunk, sizeof(chunk), 0);
    if (count <= 0) return false;
    buffer.append(chunk, (size_t)count);
    headerEnd = buffer.find("\r\n\r\n");
    if (headerEnd == std::string::npos && buffer.size() > 16384) return false;
  }
  std::istringstream stream(buffer.substr(0, headerEnd));
  std::string line;
  if (!std::getline(stream, line)) return false;
  if (!line.empty() && line.back() == '\r') line.pop_back();
  std::istringstream firstLine(line);
  std::string target;
  std::string version;
  if (!(firstLine >> request.method >> target >> version)) return false;
  size_t queryStart = target.find('?');
  request.path = target.substr(0, queryStart);
  if (queryStart != std::string::npos) request.query = target.substr(queryStart + 1);
  while (std::getline(stream, line)) {
    if (!line.empty() && line.back() == '\r') line.pop_back();
    size_t colon = line.find(':');
    if (colon == std::string::npos) continue;
    size_t valueStart = line.find_first_not_of(' ', colon + 1);
    request.headers[toLower(line.substr(0, colon))] =
        valueStart == std::string::npos ? "" : line.substr(valueStart);
  }
  size_t contentLength = 0;
  auto length = request.headers.find("content-length");
  if (length != request.headers.end()) {
    try { contentLength = std::stoul(length->second); } catch (...) { return false; }
  }
  if (contentLength > 12 * 1024) {
    request.bodyTooLarge = true;
    return true;
  }
  std::string body = buffer.substr(headerEnd + 4);
  while (body.size() < contentLength) {
    ssize_t count = recv(fd, chunk, sizeof(chunk), 0);
    if (count <= 0) return false;
    body.append(chunk, (size_t)count);
  }
  request.body = body.substr(0, contentLength);
  return true;
}

void sendResponse(int fd, int status, const std::string &contentType,
                  const std::string &body,
                  const std::vector<std::string> &headers = {}) {
  const char *reason = status == 200 ? "OK" : status == 204 ? "No Content" :
                       status == 400 ? "Bad Request" : status == 404 ? "Not Found" :
                       status == 413 ? "Payload Too Large" :
                       status == 429 ? "Too Many Requests" :
                       status == 503 ? "Service Unavailable" : "Error";
  std::ostringstream response;
  response << "HTTP/1.1 " << status << ' ' << reason << "\r\n"
           << "Content-Type: " << contentType << "\r\n"
           << "Content-Length: " << body.size() << "\r\n"
           << "Access-Control-Allow-Origin: *\r\n"
           << "Connection: close\r\n";
  for (const std::string &header : headers) response << header << "\r\n";
  response << "\r\n" << body;
  std::string data = response.str();
  size_t offset = 0;
  while (offset < data.size()) {
    ssize_t count = send(fd, data.data() + offset, data.size() - offset, 0);
    if (count <= 0) break;
    offset += (size_t)count;
  }
}

bool fileReadable(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  return file.good();
}

std::string findManagerHtml(const std::string &overridePath) {
  if (!overridePath.empty() && fileReadable(overridePath)) return overridePath;
  std::vector<std::string> candidates;
#ifdef __linux__
  char executable[4096];
  ssize_t size = readlink("/proc/self/exe", executable, sizeof(executable) - 1);
  if (size > 0) {
    executable[size] = '\0';
    std::string path(executable);
    size_t slash = path.find_last_of('/');
    if (slash != std::string::npos)
      candidates.push_back(path.substr(0, slash) + "/../manager/manager.html");
  }
#endif
  candidates.push_back("../manager/manager.html");
  candidates.push_back("src/manager/manager.html");
  for (const std::string &candidate : candidates) {
    if (fileReadable(candidate)) return candidate;
  }
  return "";
}

std::string readFile(const std::string &path) {
  std::ifstream file(path, std::ios::binary);
  std::ostringstream contents;
  contents << file.rdbuf();
  return contents.str();
}

bool validNonce(const std::string &query, std::string &nonce) {
  const std::string prefix = "nonce=";
  if (query.compare(0, prefix.size(), prefix) != 0) return false;
  nonce = query.substr(prefix.size());
  if (nonce.size() < 16 || nonce.size() > 64) return false;
  for (char value : nonce) {
    bool valid = (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') ||
                 (value >= '0' && value <= '9') || value == '-' || value == '_';
    if (!valid) return false;
  }
  return true;
}

void handleHttpClient(int fd, SerialProtocolAdapter &host, BridgeState &state,
                      SerialPort &serial, PeerAddressTable &peers, std::mutex &peersMutex,
                      EscapeProtocol::ChangeLock &changeLock,
                      EscapeSecurity::SecureTransport &security,
                      const std::string &ip, int httpPort,
                      const std::string &managerHtml, bool managerHtmlIsGzip) {
  HttpRequest request;
  if (!readHttpRequest(fd, request)) return;
  if (request.bodyTooLarge) {
    sendResponse(fd, 413, "application/json", "{\"error\":\"secure envelope too large\"}");
    return;
  }

  auto authenticatedGet = [&](const EscapeProtocol::HttpResult &result) {
    std::string nonce;
    if (!validNonce(request.query, nonce)) {
      sendResponse(fd, 400, "application/json", "{\"error\":\"invalid nonce\"}");
      return;
    }
    std::string context = "http-get-v1\n" + request.path + "\n" + nonce + "\n" +
                          std::to_string(result.status);
    std::string protectedBody;
    if (!security.protectDocument(context, result.body, protectedBody)) {
      sendResponse(fd, 503, "application/json", "{\"error\":\"secure reads unavailable\"}");
      return;
    }
    sendResponse(fd, result.status, "application/json", protectedBody);
  };
  auto handleSecurePost = [&](EscapeProtocol::MutationType type,
                              const std::function<EscapeProtocol::HttpResult(const std::string &)> &handler) {
    int status = 400;
    std::string error;
    std::string body;
    std::string requestId;
    if (!security.decryptRequest(request.path, request.body, body, status, error, &requestId)) {
      sendResponse(fd, status, "application/json", "{\"error\":" + jsonString(error) + "}");
      return;
    }
    EscapeProtocol::HttpResult result = changeLock.isLocked(type)
        ? EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"}
        : handler(body);
    if (result.status == 200) changeLock.markChanged(type);
    std::string context = "http-post-response-v1\n" + request.path + "\n" + requestId + "\n" +
                          std::to_string(result.status);
    std::string protectedBody;
    if (!security.protectDocument(context, result.body, protectedBody)) {
      sendResponse(fd, 503, "application/json", "{\"error\":\"secure response unavailable\"}");
      return;
    }
    sendResponse(fd, result.status, "application/json", protectedBody);
  };

  const bool commandPath = request.path == "/action" || request.path == "/plan-action" ||
                           request.path == "/config" || request.path == "/plan" ||
                           request.path == "/plan-skeleton";
  if (request.method == "OPTIONS" && commandPath) {
    sendResponse(fd, 204, "text/plain", "", {"Access-Control-Allow-Methods: GET, POST, OPTIONS",
                 "Access-Control-Allow-Headers: Content-Type"});
  } else if (request.method == "GET" && request.path == "/security.json") {
    sendResponse(fd, security.ready() ? 200 : 503, "application/json", security.securityDocument());
  } else if (request.method == "GET" && request.path == "/status.json") {
    changeLock.noteStatusFetched();
    std::string statusBody = EscapeProtocol::buildStatusJson(host, ip, monotonicMillis(), (uint16_t)httpPort);
    EscapeProtocol::HttpResult result{200, statusBody};
    if (EscapeConfig::AUTHENTICATE_GET_REQUESTS) authenticatedGet(result);
    else sendResponse(fd, 200, "application/json", statusBody);
  } else if (request.method == "GET" && request.path == "/peers.json") {
    std::string peersBody;
    {
      std::lock_guard<std::mutex> lock(peersMutex);
      peers.expireStale(monotonicMillis());
      peersBody = EscapeProtocol::buildPeersJson(peers);
    }
    EscapeProtocol::HttpResult result{200, peersBody};
    if (EscapeConfig::AUTHENTICATE_GET_REQUESTS) authenticatedGet(result);
    else sendResponse(fd, 200, "application/json", peersBody);
  } else if (request.method == "GET" && request.path == "/plan-skeleton.json") {
    changeLock.notePlanSkeletonFetched();
    EscapeProtocol::HttpResult result =
        EscapeProtocol::handlePlanSkeletonGetRequest(state.planSkeleton());
    if (EscapeConfig::AUTHENTICATE_GET_REQUESTS) authenticatedGet(result);
    else sendResponse(fd, result.status, "application/json", result.body);
  } else if (request.method == "GET" && request.path == "/") {
    if (managerHtml.empty())
      sendResponse(fd, 503, "text/plain; charset=utf-8", "manager.html nicht gefunden\n");
    else if (managerHtmlIsGzip)
      // Opt-in-Testpfad (siehe --manager-html mit .gz-Endung): der ECHTE
      // ESP32 liefert manager.html seit scripts/compress_manager_html.py
      // IMMER gzip-komprimiert aus (siehe HardwareEsp32.cpp).
      sendResponse(fd, 200, "text/html; charset=utf-8", managerHtml, {"Content-Encoding: gzip"});
    else
      sendResponse(fd, 200, "text/html; charset=utf-8", managerHtml);
  } else if (request.method == "POST" && request.path == "/action") {
    handleSecurePost(EscapeProtocol::MutationType::Action, [&](const std::string &body) {
      return EscapeProtocol::handleActionRequest(host, {body, true});
    });
  } else if (request.method == "POST" && request.path == "/plan-action") {
    handleSecurePost(EscapeProtocol::MutationType::PlanAction, [&](const std::string &body) {
      return EscapeProtocol::handlePlanActionRequest(host, {body, true});
    });
  } else if (request.method == "POST" && request.path == "/config") {
    handleSecurePost(EscapeProtocol::MutationType::Config, [&](const std::string &body) {
      return EscapeProtocol::handleConfigRequest(host, {body, true});
    });
  } else if (request.method == "POST" && request.path == "/plan") {
    handleSecurePost(EscapeProtocol::MutationType::Plan, [&](const std::string &body) {
      return EscapeProtocol::handlePlanRequest(host, {body, true});
    });
  } else if (request.method == "POST" && request.path == "/plan-skeleton") {
    handleSecurePost(EscapeProtocol::MutationType::PlanSkeleton, [&](const std::string &body) {
      std::string storage = state.planSkeleton();
      EscapeProtocol::HttpResult result = EscapeProtocol::handlePlanSkeletonPostRequest(
          host, {body, true}, storage);
      if (result.status == 200) {
        state.setPlanSkeleton(storage);
        serial.sendJson("{\"type\":\"setPlanSkeleton\",\"value\":" + storage + "}");
      }
      return result;
    });
  } else {
    sendResponse(fd, 404, "application/json", "{\"error\":\"not found\"}");
  }
}

void httpLoop(int port, SerialProtocolAdapter &host, BridgeState &state,
              SerialPort &serial, PeerAddressTable &peers, std::mutex &peersMutex,
              EscapeProtocol::ChangeLock &changeLock,
              EscapeSecurity::SecureTransport &security, const std::string &ip,
              const std::string &managerHtml, bool managerHtmlIsGzip, std::atomic<bool> &stop) {
  int server = socket(AF_INET, SOCK_STREAM, 0);
  int enabled = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons((uint16_t)port);
  if (server < 0 || bind(server, (sockaddr *)&address, sizeof(address)) != 0 ||
      listen(server, 16) != 0) {
    std::cerr << "[host] HTTP-Port " << port << " kann nicht gebunden werden: "
              << std::strerror(errno) << "\n";
    if (server >= 0) close(server);
    stop.store(true);
    return;
  }
  while (!stop.load()) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(server, &readSet);
    timeval timeout{1, 0};
    if (select(server + 1, &readSet, nullptr, nullptr, &timeout) <= 0) continue;
    int client = accept(server, nullptr, nullptr);
    if (client < 0) continue;
    handleHttpClient(client, host, state, serial, peers, peersMutex, changeLock, security,
                     ip, port, managerHtml, managerHtmlIsGzip);
    close(client);
  }
  close(server);
}

std::string localIp() {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd < 0) return "127.0.0.1";
  sockaddr_in destination{};
  destination.sin_family = AF_INET;
  destination.sin_port = htons(80);
  inet_pton(AF_INET, "8.8.8.8", &destination.sin_addr);
  std::string result = "127.0.0.1";
  if (connect(fd, (sockaddr *)&destination, sizeof(destination)) == 0) {
    sockaddr_in source{};
    socklen_t length = sizeof(source);
    if (getsockname(fd, (sockaddr *)&source, &length) == 0) {
      char text[INET_ADDRSTRLEN];
      if (inet_ntop(AF_INET, &source.sin_addr, text, sizeof(text))) result = text;
    }
  }
  close(fd);
  return result;
}

std::string broadcastAddress(const std::string &ip) {
  ifaddrs *interfaces = nullptr;
  if (getifaddrs(&interfaces) != 0) return "255.255.255.255";
  std::string result = "255.255.255.255";
  for (ifaddrs *item = interfaces; item; item = item->ifa_next) {
    if (!item->ifa_addr || !item->ifa_netmask || item->ifa_addr->sa_family != AF_INET) continue;
    sockaddr_in *address = (sockaddr_in *)item->ifa_addr;
    char text[INET_ADDRSTRLEN];
    if (!inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text)) || ip != text) continue;
    sockaddr_in *mask = (sockaddr_in *)item->ifa_netmask;
    in_addr broadcast{};
    broadcast.s_addr = address->sin_addr.s_addr | ~mask->sin_addr.s_addr;
    if (inet_ntop(AF_INET, &broadcast, text, sizeof(text))) result = text;
    break;
  }
  freeifaddrs(interfaces);
  return result;
}

void broadcastLoop(int fd, int udpPort, int httpPort, SerialProtocolAdapter &host,
                   BridgeState &state, const EscapeProtocol::ChangeLock &changeLock,
                   EscapeSecurity::SecureTransport &security,
                   const std::string &broadcastIp,
                   std::atomic<bool> &stop) {
  sockaddr_in destination{};
  destination.sin_family = AF_INET;
  destination.sin_port = htons((uint16_t)udpPort);
  inet_pton(AF_INET, broadcastIp.c_str(), &destination.sin_addr);
  std::mt19937 random(std::random_device{}());
  std::uniform_int_distribution<uint32_t> jitter(0, EscapeConfig::HEARTBEAT_JITTER_MS);
  const uint32_t heartbeat = EscapeConfig::HEARTBEAT_INTERVAL_MS + jitter(random);
  uint32_t lastBroadcast = monotonicMillis() - heartbeat;
  while (!stop.load()) {
    uint32_t now = monotonicMillis();
    bool due = EscapeProtocol::isHeartbeatDue(now, lastBroadcast, heartbeat) ||
               EscapeProtocol::isChangeBroadcastDue(now, lastBroadcast, state.dirty().load());
    if (due && host.componentCount() > 0) {
      std::string document = EscapeProtocol::buildPeerAnnouncementJson((uint16_t)httpPort,
          changeLock.hasUnseenStatusChange(), changeLock.hasUnseenPlanSkeletonChange());
      std::string protectedDocument;
      if (security.protectDocument("udp-broadcast-v1", document, protectedDocument)) {
        sendto(fd, protectedDocument.data(), protectedDocument.size(), 0,
               (sockaddr *)&destination, sizeof(destination));
      }
      state.dirty().store(false);
      lastBroadcast = now;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
  }
}

void listenLoop(int udpPort, PeerAddressTable &peers, const std::string &ownIp, uint16_t ownHttpPort,
                std::mutex &peersMutex, EscapeSecurity::SecureTransport &security,
                std::atomic<bool> &stop) {
  int fd = socket(AF_INET, SOCK_DGRAM, 0);
  int enabled = 1;
  setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &enabled, sizeof(enabled));
#ifdef SO_REUSEPORT
  setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &enabled, sizeof(enabled));
#endif
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons((uint16_t)udpPort);
  if (fd < 0 || bind(fd, (sockaddr *)&address, sizeof(address)) != 0) {
    std::cerr << "[host] UDP-Port " << udpPort << " kann nicht gebunden werden\n";
    if (fd >= 0) close(fd);
    return;
  }
  char buffer[16 * 1024];
  while (!stop.load()) {
    fd_set readSet;
    FD_ZERO(&readSet);
    FD_SET(fd, &readSet);
    timeval timeout{1, 0};
    if (select(fd + 1, &readSet, nullptr, nullptr, &timeout) <= 0) continue;
    sockaddr_in source{};
    socklen_t sourceSize = sizeof(source);
    ssize_t size = recvfrom(fd, buffer, sizeof(buffer), 0,
                            (sockaddr *)&source, &sourceSize);
    if (size <= 0) continue;
    char sourceIp[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &source.sin_addr, sourceIp, sizeof(sourceIp));
    std::string plaintext;
    if (security.unprotectDocument("udp-broadcast-v1",
                                   std::string(buffer, (size_t)size), plaintext)) {
      std::lock_guard<std::mutex> lock(peersMutex);
      EscapeProtocol::ingestPeerAnnouncement(plaintext, sourceIp, ownIp, monotonicMillis(), peers, ownHttpPort);
    }
  }
  close(fd);
}

struct Options {
  std::string serialPath;
  int baud = 115200;
  int udpPort = EscapeConfig::UDP_PORT;
  int httpPort = 8080;
  std::string token = EscapeConfig::AUTH_TOKEN;
  std::string managerHtml;
  std::string ip;
};

Options parseArguments(int argc, char **argv) {
  Options options;
  bool tokenGiven = false;
  for (int index = 1; index < argc; index++) {
    std::string argument = argv[index];
    auto value = [&]() -> std::string {
      if (index + 1 >= argc) {
        std::cerr << "Wert fuer " << argument << " fehlt\n";
        std::exit(2);
      }
      return argv[++index];
    };
    if (argument == "--serial") options.serialPath = value();
    else if (argument == "--baud") options.baud = std::atoi(value().c_str());
    else if (argument == "--udp-port") options.udpPort = std::atoi(value().c_str());
    else if (argument == "--http-port") options.httpPort = std::atoi(value().c_str());
    else if (argument == "--token") { options.token = value(); tokenGiven = true; }
    else if (argument == "--manager-html") options.managerHtml = value();
    else if (argument == "--ip") options.ip = value();
    else if (argument == "--help" || argument == "-h") {
      std::cout << "Verwendung: " << argv[0]
                << " --serial /dev/ttyACM0 [--baud 115200] [--http-port 8080]"
                   " [--udp-port 4210] [--token TOKEN] [--ip ADRESSE]"
                   " [--manager-html PFAD]\n";
      std::exit(0);
    } else {
      std::cerr << "Unbekannte Option: " << argument << "\n";
      std::exit(2);
    }
  }
  if (!tokenGiven) {
    const char *environment = std::getenv("ESCAPE_AUTH_TOKEN");
    if (environment && *environment) options.token = environment;
  }
  if (options.serialPath.empty()) {
    std::cerr << "--serial ist erforderlich (z.B. /dev/ttyACM0)\n";
    std::exit(2);
  }
  if (options.httpPort < 1 || options.httpPort > 65535 ||
      options.udpPort < 1 || options.udpPort > 65535) {
    std::cerr << "Port muss zwischen 1 und 65535 liegen\n";
    std::exit(2);
  }
  return options;
}

std::atomic<bool> stopRequested{false};
void handleSignal(int) { stopRequested.store(true); }

} // namespace

int main(int argc, char **argv) {
  Options options = parseArguments(argc, argv);
  std::signal(SIGINT, handleSignal);
  std::signal(SIGTERM, handleSignal);
  std::signal(SIGPIPE, SIG_IGN);

  const std::string ip = options.ip.empty() ? localIp() : options.ip;
  const std::string broadcastIp = broadcastAddress(ip);
  const std::string managerPath = findManagerHtml(options.managerHtml);
  const std::string managerHtml = managerPath.empty() ? "" : readFile(managerPath);
  // Opt-in-Testpfad fuer die gzip-komprimierte Auslieferung (siehe
  // scripts/compress_manager_html.py): --manager-html auf eine .gz-Datei
  // zeigen lassen, um denselben Content-Encoding-Codepfad wie den echten
  // ESP32 zu testen.
  const bool managerHtmlIsGzip = managerPath.size() >= 3 &&
      managerPath.compare(managerPath.size() - 3, 3, ".gz") == 0;

  OpenSslCryptoBackend crypto;
  EscapeSecurity::SecureTransport security(options.token, crypto);
  if (!security.begin()) {
    std::cerr << "[host] Sicherer Transport konnte nicht initialisiert werden\n";
    return 1;
  }

  BridgeState state;
  SerialPort serial(options.serialPath, options.baud);
  SerialProtocolAdapter host(state, serial);
  PeerAddressTable peers;
  std::mutex peersMutex;
  EscapeProtocol::ChangeLock changeLock;

  int sendSocket = socket(AF_INET, SOCK_DGRAM, 0);
  int broadcastEnabled = 1;
  setsockopt(sendSocket, SOL_SOCKET, SO_BROADCAST, &broadcastEnabled,
             sizeof(broadcastEnabled));

  std::thread serialThread([&]() {
    serial.run([&](const std::string &line) { state.applySerialLine(line); },
               stopRequested);
  });
  std::thread senderThread(broadcastLoop, sendSocket, options.udpPort,
                           options.httpPort, std::ref(host), std::ref(state),
                           std::cref(changeLock),
                           std::ref(security),
                           std::cref(broadcastIp), std::ref(stopRequested));
  std::thread receiverThread(listenLoop, options.udpPort, std::ref(peers),
                             std::cref(ip), (uint16_t)options.httpPort, std::ref(peersMutex),
                             std::ref(security), std::ref(stopRequested));

  std::cout << "[host] Serial-Bridge auf " << ip << ':' << options.httpPort
            << ", UDP " << options.udpPort << " -> " << broadcastIp << "\n";
  std::cout << "[host] Manager: http://" << ip << ':' << options.httpPort << "/\n";
  if (managerPath.empty())
    std::cerr << "[host] Warnung: manager.html nicht gefunden\n";
  else
    std::cout << "[host] manager.html: " << managerPath << "\n";

  httpLoop(options.httpPort, host, state, serial, peers, peersMutex, changeLock, security,
           ip, managerHtml, managerHtmlIsGzip, stopRequested);
  stopRequested.store(true);
  serialThread.join();
  senderThread.join();
  receiverThread.join();
  close(sendSocket);
  return 0;
}
