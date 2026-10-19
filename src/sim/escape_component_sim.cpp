// PC simulator of an EscapeManager device: the SAME portable core as the ESP32 firmware
// (src/net/Device + src/protocol), with simulated puzzle components instead of sensors.
// Only the "hardware" is different: POSIX sockets instead of lwIP, files instead of NVS,
// OpenSSL instead of mbedTLS.
//
//   ./run_sim.sh --http-port 8080                      two demo components in "Raum-A"
//   ./run_sim.sh --http-port 8081 --did 111111111111 --component Tuer:Raum-B:door-v1
//   ./run_sim.sh --http-port 8082 --token MyNormalToken --edit-token MyPlanEditToken --setup
//
// Several simulators on one PC need different --http-port and --did values; they find
// each other through the shared UDP discovery port and the loopback/LAN broadcast.
//
// Options:
//   --http-port N  --udp-port N  --mdns-port N  --no-mdns  --mdns-hostname H
//   --did 12HEX    --ip A.B.C.D  --broadcast A.B.C.D        device id, announced address / broadcast
//   --component NAME:ROOM[:RIDDLE_ID]                       repeatable; default: two demo components
//   --battery N  --total-steps N  --html-state
//   --manager-html FILE  --state-dir DIR
//   --token T        normal token (8..128 printable ASCII, no spaces); default: environment ESCAPE_AUTH_TOKEN,
//                    else the public default token
//   --edit-token T   plan-edit token (PROTOCOL.md 3.1, same rules); default: environment ESCAPE_EDIT_TOKEN,
//                    else none (edit "unset": the normal token may send plans). With one, POST /plan,
//                    /plan-skeleton and /setup need the edit keys and GET /edit.json proves the token.
//   --setup          accept token / Wi-Fi changes by POST /setup (PROTOCOL.md 5.8; cap "setup"). A change of
//                    the tokens takes effect at once but is kept in memory only (a restart starts with
//                    --token / --edit-token again); Wi-Fi credentials are only logged ("setup: wifi
//                    ssid=..", never the password) - the PC has no radio. Without --setup: 404 for /setup.
// Exit status: 2 for bad options, 1 if the HTTP port cannot be opened.

#include "../net/Clock.hpp"
#include "../net/Device.hpp"
#include "HostNetwork.hpp"
#include "OpenSslCryptoBackend.hpp"
#include "SimSetupSink.hpp"

#include <arpa/inet.h>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <openssl/evp.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

using namespace Escape;
using EscapeProtocol::ComponentSnapshot;
using EscapeProtocol::CustomConfigDef;
using EscapeProtocol::CustomConfigType;
using EscapeProtocol::PlanAction;

namespace {

volatile std::sig_atomic_t g_stop = 0;
void onSignal(int) { g_stop = 1; }

std::string readFile(const std::string &path, bool &ok) {
  std::ifstream f(path.c_str(), std::ios::binary);
  ok = f.good();
  std::ostringstream ss;
  ss << f.rdbuf();
  return ss.str();
}

// ---- Storage: skeleton blobs and component state as files (atomic rename) ----------------

class FileStorage : public BlobStorage {
public:
  explicit FileStorage(const std::string &dir) : dir_(dir) { mkdir(dir.c_str(), 0700); }
  bool read(const char *key, std::string &out) override {
    bool ok = false;
    std::string text = readFile(path(key), ok);
    if (!ok) return false;
    out.swap(text);
    return true;
  }
  bool write(const char *key, const std::string &data) override {
    const std::string tmp = path(key) + ".tmp";
    {
      std::ofstream f(tmp.c_str(), std::ios::binary | std::ios::trunc);
      f.write(data.data(), (std::streamsize)data.size());
      if (!f.good()) return false;
    }
    return std::rename(tmp.c_str(), path(key).c_str()) == 0;
  }
  bool erase(const char *key) override { return std::remove(path(key).c_str()) == 0; }

private:
  std::string path(const char *key) const { return dir_ + "/" + key; }
  std::string dir_;
};

// ---- Simulated components ------------------------------------------------------------------

struct SimComponent {
  std::string name, room, riddle, plan, tip;
  uint16_t step = 0, total = 5;
  bool errorActive = false;
  uint32_t eventSeq = 0;
  std::string eventMsg;
  std::string brightness = "50", label, difficulty = "medium";
};

class SimHost : public EscapeProtocol::ProtocolAdapter {
public:
  SimHost(FileStorage &state) : device(nullptr), battery_(100), htmlState(false), state_(state) {}
  Device *device;
  std::vector<SimComponent> comps;
  int battery_;
  bool htmlState;

  int8_t battery() const override { return (int8_t)battery_; }
  void markDirty() override { if (device) device->markDirty(); }
  uint8_t componentCount() const override { return (uint8_t)comps.size(); }
  void identity(uint8_t i, std::string &n, std::string &r) const override { n = comps[i].name; r = comps[i].room; }

  void snapshot(uint8_t i, ComponentSnapshot &o) const override {
    const SimComponent &c = comps[i];
    EscapeProtocol::copyBounded(o.name, sizeof(o.name), c.name.c_str());
    EscapeProtocol::copyBounded(o.room, sizeof(o.room), c.room.c_str());
    EscapeProtocol::copyBounded(o.riddleId, sizeof(o.riddleId), c.riddle.c_str());
    EscapeProtocol::copyBounded(o.uuid, sizeof(o.uuid), (didText + "-" + std::to_string(i)).c_str());
    EscapeProtocol::copyBounded(o.plan, sizeof(o.plan), c.plan.c_str());
    if (c.errorActive) { EscapeProtocol::copyBounded(o.errors[0], sizeof(o.errors[0]), "sensor_timeout"); o.errorCount = 1; }
    static const char *kActions[] = {"reset", "next_step", "solve", "toggle_error", "drain_battery"};
    for (const char *a : kActions) { EscapeProtocol::copyBounded(o.actions[o.actionCount++], sizeof(o.actions[0]), a); }
    o.planActionMask = EscapeProtocol::planActionBit(PlanAction::Reset) | EscapeProtocol::planActionBit(PlanAction::Complete);
    EscapeProtocol::copyBounded(o.tip, sizeof(o.tip), c.step < c.total ? "Naechste Aktion: next_step" : "");
    o.puzzleStep = c.step;
    o.puzzleTotalSteps = c.total;
    o.puzzleIsHtml = htmlState;
    const std::string state = htmlState ? "<svg width='160' height='40'><rect width='" + std::to_string(c.step * 160 / (c.total ? c.total : 1)) +
                                              "' height='40' fill='#4a90d9'/></svg>"
                                        : "Schritt " + std::to_string(c.step) + " von " + std::to_string(c.total);
    EscapeProtocol::copyBounded(o.puzzleState, sizeof(o.puzzleState), state.c_str());
    CustomConfigDef &b = o.customConfig[0];
    EscapeProtocol::copyBounded(b.key, sizeof(b.key), "brightness");
    b.type = CustomConfigType::Range; b.rangeMin = 0; b.rangeMax = 100;
    EscapeProtocol::copyBounded(b.value, sizeof(b.value), c.brightness.c_str());
    CustomConfigDef &l = o.customConfig[1];
    EscapeProtocol::copyBounded(l.key, sizeof(l.key), "label");
    l.type = CustomConfigType::Text; l.textMaxLen = 32;
    EscapeProtocol::copyBounded(l.value, sizeof(l.value), c.label.c_str());
    CustomConfigDef &d = o.customConfig[2];
    EscapeProtocol::copyBounded(d.key, sizeof(d.key), "difficulty");
    d.type = CustomConfigType::Select;
    for (const char *opt : {"easy", "medium", "hard"}) EscapeProtocol::copyBounded(d.options[d.optionCount++], sizeof(d.options[0]), opt);
    EscapeProtocol::copyBounded(d.value, sizeof(d.value), c.difficulty.c_str());
    o.customConfigCount = 3;
    o.eventSeq = c.eventSeq;
    EscapeProtocol::copyBounded(o.eventMsg, sizeof(o.eventMsg), c.eventMsg.c_str());
  }

  void customConfigDefs(uint8_t, std::vector<CustomConfigDef> &out) const override {
    ComponentSnapshot *s = new ComponentSnapshot();
    snapshot(0, *s);
    out.assign(s->customConfig, s->customConfig + s->customConfigCount);
    delete s;
  }

  bool applyAction(uint8_t i, const std::string &a) override {
    SimComponent &c = comps[i];
    if (a == "reset") { c.step = 0; c.errorActive = false; }
    else if (a == "next_step") c.step = c.step < c.total ? c.step + 1 : c.total;
    else if (a == "solve") c.step = c.total;
    else if (a == "toggle_error") c.errorActive = !c.errorActive;
    else if (a == "drain_battery") battery_ = battery_ > 10 ? battery_ - 10 : 0;
    else return false;
    return true;
  }
  bool applyPlanAction(uint8_t i, PlanAction a) override {
    if (a == PlanAction::Reset) { comps[i].step = 0; comps[i].errorActive = false; }
    else comps[i].step = comps[i].total;
    return true;
  }
  void setIdentity(uint8_t i, const std::string &n, const std::string &r) override { comps[i].name = n; comps[i].room = r; save(); }
  void setRiddleId(uint8_t i, const std::string &r) override { comps[i].riddle = r; save(); }
  bool setCustomConfigValue(uint8_t i, const std::string &k, const std::string &v) override {
    if (k == "brightness") comps[i].brightness = v;
    else if (k == "label") comps[i].label = v;
    else if (k == "difficulty") comps[i].difficulty = v;
    else return false;
    save();
    return true;
  }
  void setPlan(uint8_t i, const std::string &p) override { comps[i].plan = p; save(); }
  void pushEvent(uint8_t i, const std::string &m) override { comps[i].eventSeq++; comps[i].eventMsg = m; }

  // identity and settings survive restarts (the sim's stand-in for NVS)
  void save() {
    std::string s = "[";
    for (size_t i = 0; i < comps.size(); i++) {
      if (i) s += ',';
      s += "{\"name\":\"";  EscapeJson::appendEscaped(s, comps[i].name);
      s += "\",\"room\":\"";  EscapeJson::appendEscaped(s, comps[i].room);
      s += "\",\"riddle\":\""; EscapeJson::appendEscaped(s, comps[i].riddle);
      s += "\",\"plan\":\"";   EscapeJson::appendEscaped(s, comps[i].plan);
      s += "\",\"br\":\"" + comps[i].brightness + "\",\"label\":\""; EscapeJson::appendEscaped(s, comps[i].label);
      s += "\",\"diff\":\"" + comps[i].difficulty + "\"}";
    }
    s += "]";
    state_.write("components.json", s);
  }
  void load() {
    std::string text;
    EscapeJson::Value v;
    if (!state_.read("components.json", text) || !EscapeJson::parse(text, v, EscapeJson::ParseLimits(4, 200)) || v.type != EscapeJson::Type::Array) return;
    for (size_t i = 0; i < comps.size() && i < v.arrayValue.size(); i++) {
      const EscapeJson::Value &e = v.arrayValue[i];
      comps[i].name = e.find("name") ? e.find("name")->asString(comps[i].name) : comps[i].name;
      comps[i].room = e.find("room") ? e.find("room")->asString(comps[i].room) : comps[i].room;
      comps[i].riddle = e.find("riddle") ? e.find("riddle")->asString(comps[i].riddle) : comps[i].riddle;
      comps[i].plan = e.find("plan") ? e.find("plan")->asString() : "";
      comps[i].brightness = e.find("br") ? e.find("br")->asString("50") : "50";
      comps[i].label = e.find("label") ? e.find("label")->asString() : "";
      comps[i].difficulty = e.find("diff") ? e.find("diff")->asString("medium") : "medium";
    }
  }
  std::string didText;

private:
  FileStorage &state_;
};

class SimPlatform : public DevicePlatform {
public:
  SimPlatform(uint32_t ip, uint32_t broadcast) : ip_(ip), broadcast_(broadcast) {}
  uint32_t localIp() override { return ip_; }
  uint32_t broadcastIp() override { return broadcast_; }

private:
  uint32_t ip_, broadcast_;
};

std::string sha256Hex8(const std::string &data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
  char hex[9];
  snprintf(hex, sizeof(hex), "%02x%02x%02x%02x", md[0], md[1], md[2], md[3]);
  return hex;
}

void logSetup(const std::string &line) { std::cout << "[sim] " << line << std::endl; }

struct Options {
  std::vector<std::string> specs;
  uint16_t httpPort = 8080, udpPort = 4210, mdnsPort = 5353;
  std::string did, token, editToken, managerHtml, stateDir, mdnsHostname = std::string(EscapeConfig::MDNS_HOSTNAME) + ".local";
  std::string ip, broadcast;
  int battery = 100, totalSteps = 5;
  bool mdns = true, htmlState = false, setup = false;
};

std::string usageText(const char *program) {
  return std::string("usage: ") + program + " [--http-port N] [--udp-port N] [--did 12HEX] [--component NAME:ROOM[:RIDDLE_ID]]...\n"
         "       [--token T] [--edit-token T] [--setup] [--ip A.B.C.D] [--broadcast A.B.C.D] [--no-mdns] [--mdns-port N]\n"
         "       [--mdns-hostname H] [--manager-html FILE] [--state-dir DIR] [--battery N] [--total-steps N] [--html-state]\n"
         "  --token T       normal token, 8..128 printable ASCII characters (default: $ESCAPE_AUTH_TOKEN, else the public default)\n"
         "  --edit-token T  plan-edit token, same rules (default: $ESCAPE_EDIT_TOKEN, else none)\n"
         "  --setup         accept POST /setup (token / Wi-Fi changes; tokens in memory only, Wi-Fi only logged)\n";
}

bool parseArgs(int argc, char **argv, Options &o) {
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    auto val = [&]() -> std::string { return i + 1 < argc ? argv[++i] : std::string(); };
    if (a == "--component") o.specs.push_back(val());
    else if (a == "--http-port") o.httpPort = (uint16_t)atoi(val().c_str());
    else if (a == "--udp-port") o.udpPort = (uint16_t)atoi(val().c_str());
    else if (a == "--mdns-port") o.mdnsPort = (uint16_t)atoi(val().c_str());
    else if (a == "--did") o.did = val();
    else if (a == "--token") o.token = val();
    else if (a == "--edit-token") {
      if (i + 1 >= argc) { std::cerr << "missing value for --edit-token\n"; return false; }
      o.editToken = argv[++i];
    }
    else if (a == "--ip") o.ip = val();
    else if (a == "--broadcast") o.broadcast = val();
    else if (a == "--manager-html") o.managerHtml = val();
    else if (a == "--state-dir") o.stateDir = val();
    else if (a == "--mdns-hostname") o.mdnsHostname = val();
    else if (a == "--battery") o.battery = atoi(val().c_str());
    else if (a == "--total-steps") o.totalSteps = atoi(val().c_str());
    else if (a == "--no-mdns") o.mdns = false;
    else if (a == "--html-state") o.htmlState = true;
    else if (a == "--setup") o.setup = true;
    else if (a == "--help" || a == "-h") { std::cout << usageText(argv[0]); std::exit(0); }
    else { std::cerr << "unknown option " << a << "\nsee the header of escape_component_sim.cpp\n"; return false; }
  }
  return true;
}

} // namespace

// The simulator has no embedded firmware UI; it hashes whatever --manager-html it serves.
namespace EscapeVersion {
const char *const UI_HASH = "00000000";
}

int main(int argc, char **argv) {
  Options opt;
  if (!parseArgs(argc, argv, opt)) return 2;
  if (opt.token.empty() && getenv("ESCAPE_AUTH_TOKEN") && *getenv("ESCAPE_AUTH_TOKEN")) opt.token = getenv("ESCAPE_AUTH_TOKEN");
  if (opt.editToken.empty() && getenv("ESCAPE_EDIT_TOKEN") && *getenv("ESCAPE_EDIT_TOKEN")) opt.editToken = getenv("ESCAPE_EDIT_TOKEN");
  if (!opt.token.empty() && !tokenProblem(opt.token).empty()) {
    std::cerr << "the token " << tokenProblem(opt.token) << "\n";
    return 2;
  }
  if (!opt.editToken.empty() && !tokenProblem(opt.editToken).empty()) {
    std::cerr << "the edit token " << tokenProblem(opt.editToken) << "\n";
    return 2;
  }
  signal(SIGINT, onSignal);
  signal(SIGTERM, onSignal);
  signal(SIGPIPE, SIG_IGN);

  if (opt.did.empty()) { // stable per HTTP port so restarts keep their identity
    char d[13];
    snprintf(d, sizeof(d), "5e%02x%02x%02x%02x%02x", (unsigned)(opt.httpPort >> 8), (unsigned)(opt.httpPort & 0xFF), 0xab, 0xcd, 0xef);
    opt.did = d;
  }
  if (opt.stateDir.empty()) opt.stateDir = "/tmp/escape-sim-" + opt.did + "-" + std::to_string(opt.httpPort);
  if (opt.specs.empty()) { opt.specs.push_back("Laser-1:Raum-A"); opt.specs.push_back("Kamera-1:Raum-A"); }

  FileStorage state(opt.stateDir);
  FileStorage skeletons(opt.stateDir + "/plans");
  SimHost host(state);
  host.battery_ = opt.battery;
  host.htmlState = opt.htmlState;
  host.didText = opt.did;
  for (size_t i = 0; i < opt.specs.size() && i < EscapeConfig::MAX_LOCAL_COMPONENTS; i++) {
    std::vector<std::string> parts;
    std::stringstream ss(opt.specs[i]);
    for (std::string p; std::getline(ss, p, ':');) parts.push_back(p);
    if (parts.size() < 2) { std::cerr << "--component expects NAME:ROOM[:RIDDLE_ID]\n"; return 2; }
    SimComponent c;
    c.name = parts[0];
    c.room = parts[1];
    c.riddle = parts.size() > 2 ? parts[2] : "sim-" + parts[0];
    c.total = (uint16_t)opt.totalSteps;
    host.comps.push_back(c);
  }
  host.load();

  // The UI: any manager.html (raw or .gz); default is the repository's source file.
  std::string html;
  bool gz = false;
  {
    std::vector<std::string> candidates;
    if (!opt.managerHtml.empty()) candidates.push_back(opt.managerHtml);
    candidates.push_back("src/manager/manager.html");
    candidates.push_back("../manager/manager.html");
    for (size_t i = 0; i < candidates.size(); i++) {
      bool ok = false;
      html = readFile(candidates[i], ok);
      if (ok) { gz = candidates[i].size() > 3 && candidates[i].compare(candidates[i].size() - 3, 3, ".gz") == 0; break; }
      html.clear();
    }
    if (html.empty()) std::cerr << "[sim] no manager.html found (use --manager-html); GET / will return 404\n";
  }

  OpenSslCryptoBackend crypto;
  uint32_t ip = 0x7F000001, bc = 0xFFFFFFFFu;
  std::string ifaceName;
  if (!opt.ip.empty()) {
    uint8_t b[4];
    if (!parseIpv4(opt.ip.data(), opt.ip.size(), b)) { std::cerr << "--ip is not an IPv4 address\n"; return 2; }
    ip = ipv4ToU32(b);
    if ((ip >> 24) == 127) bc = 0x7FFFFFFFu; // loopback sims find each other through the loopback broadcast address
    else if (const uint32_t directed = broadcastForIp(ip)) bc = directed;
  } else {
    const HostInterface lan = detectLanInterface();
    ip = lan.ip;
    bc = lan.broadcast;
    ifaceName = lan.name;
  }
  if (!opt.broadcast.empty()) {
    uint8_t b[4];
    if (!parseIpv4(opt.broadcast.data(), opt.broadcast.size(), b)) { std::cerr << "--broadcast is not an IPv4 address\n"; return 2; }
    bc = ipv4ToU32(b);
  }
  SimPlatform platform(ip, bc);

  // Holds the tokens the device runs with; attached to the device only with --setup (POST /setup).
  SimSetupSink tokens(opt.token, opt.editToken, logSetup);
  Device device(host, crypto, skeletons, platform);
  host.device = &device;
  if (opt.setup) device.setSetupSink(&tokens);
  DeviceOptions o;
  o.did = opt.did;
  o.httpPort = opt.httpPort;
  o.udpPort = opt.udpPort;
  // A shared name without a port only reaches HTTP port 80; on another port the name would send
  // browsers to whatever else listens on port 80 of this PC (e.g. a local web server).
  const bool mdnsServesUi = opt.httpPort == 80;
  o.mdnsPort = opt.mdns && mdnsServesUi ? opt.mdnsPort : 0;
  o.mdnsHostname = opt.mdnsHostname;
  std::string bootText;
  uint32_t boot = 1;
  if (state.read("boot", bootText)) boot = (uint32_t)strtoul(bootText.c_str(), nullptr, 10) + 1;
  state.write("boot", std::to_string(boot));
  o.bootCounter = boot;
  o.uiData = html.empty() ? nullptr : (const uint8_t *)html.data();
  o.uiLength = html.size();
  o.uiGzip = gz;
  o.uiHash = html.empty() ? "00000000" : sha256Hex8(html);
  if (!device.begin(o, tokens.token(), tokens.tokenState(), tokens.editToken(), tokens.editState())) {
    std::cerr << "[sim] cannot listen on HTTP port " << opt.httpPort << "\n";
    return 1;
  }
  std::cout << "[sim] did=" << opt.did << " http=" << ipToString(ip) << ":" << opt.httpPort << " udp=" << opt.udpPort
            << " broadcast=" << ipToString(bc) << (ifaceName.empty() ? "" : " iface=" + ifaceName)
            << " token=" << tokenStateName(device.transport().tokenState())
            << " edit=" << editStateName(device.transport().editState()) << " setup=" << (opt.setup ? "on" : "off") << " ui=" << o.uiHash << " state=" << opt.stateDir << std::endl;
  if (opt.mdns && !mdnsServesUi) {
    std::cout << "[sim] mDNS off: " << opt.mdnsHostname << " can only point to HTTP port 80 (use --http-port 80 to act as a failover for it)" << std::endl;
  }
  if (ifaceName == "lo") std::cout << "[sim] no LAN interface found - only simulators on this PC will see this one (use --ip A.B.C.D)" << std::endl;
  for (size_t i = 0; i < host.comps.size(); i++) std::cout << "[sim]   component " << i << ": " << host.comps[i].name << " / " << host.comps[i].room << std::endl;

  const uint32_t start = nowMillis();
  while (!g_stop) {
    device.loop(nowMillis() - start, 4000);
    usleep(1000);
  }
  device.end();
  return 0;
}
