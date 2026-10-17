// EscapeManager PC host for components behind a USB-serial line (wire protocol proto 2).
//
// An ordinary Arduino (no Wi-Fi, no crypto) takes part in an EscapeManager network through this
// PC program. The PC owns the network side - HTTP server, UDP discovery, shared mDNS record, peer
// table, plan-skeleton store and the secure transport, i.e. the portable core `Escape::Device`
// that the ESP32 firmware and the simulator run too - and the Arduino only sends and receives
// newline-delimited JSON over its serial port. This file is the "hardware layer": a
// ProtocolAdapter that mirrors the Arduino's last `state` snapshot and turns adapter calls into
// command lines, plus a non-blocking serial driver.
//
//   ./run_serial_host.sh --serial /dev/ttyACM0 --http-port 8080
//   ./run_serial_host.sh --serial /dev/ttyUSB0 --baud 9600 --did 0a1b2c3d4e5f --token MySecretToken
//
// run_serial_host.sh builds this file with g++ -std=c++17 into .sim-build/ and starts it (needs
// libssl-dev like run_sim.sh). Several hosts on one PC need different --http-port values (and
// serial ports); they find each other and the simulators through the UDP discovery port.
//
// ---- Line protocol -------------------------------------------------------------------------------
// Every message is one JSON object on one line ('\n', a preceding '\r' is ignored). Lines that do not
// start with '{' (debug output, boot messages, line noise) are ignored, lines longer than 16 KB and
// lines that are not valid JSON are dropped, none of this disturbs the connection. Only messages with
// "type":"state" are used; JSON of any other type is ignored (so a sketch may log JSON of its own).
//
// Arduino -> PC: the complete state, as often as the sketch likes (on change, on getState, ...)
//   {"type":"state","battery":87,"components":[
//     {"id":0,"riddleId":"door-v1","name":"Tuer","room":"Raum-A",
//      "errors":[],"actions":["open"],"planActions":["reset","complete"],
//      "puzzle":{"step":1,"totalSteps":3,"state":"bereit","isHtml":false},
//      "tip":"..","feed":"http://..","evtSeq":3,"evtMsg":"..",
//      "customConfig":[{"key":"brightness","type":"range","min":0,"max":100,"value":"50"}],
//      "plan":{...}}
//   ]}
// The component fields are those of the component object of /status.json (PROTOCOL.md 5.2); all but
// `name`/`room` are optional. `id` is the number the PC uses to address the component in commands
// (default: its position in the array). `battery` <= 0 or missing means "no battery". At most
// EscapeConfig::MAX_LOCAL_COMPONENTS components are used; strings are cut to the protocol limits, lists
// are capped, `feed` is only kept when it is an http(s) URL. A snapshot is applied only as a whole.
//
// PC -> Arduino
//   {"type":"getState"}                                         on connect, every 5 s, after every command
//   {"type":"action","id":0,"action":"open"}
//   {"type":"planAction","id":0,"action":"reset"}               "reset" | "complete"
//   {"type":"setIdentity","id":0,"name":"Tuer","room":"Raum-A"}
//   {"type":"setRiddleId","id":0,"value":"door-v1"}
//   {"type":"setConfig","id":0,"key":"brightness","value":"50"}  (value is always a string)
//   {"type":"setPlan","id":0,"plan":{...}}                      plan is null when it was cleared
//   {"type":"event","id":0,"message":"..."}                     informational, sketches may ignore it
// After a command the Arduino should answer with a new `state`; the PC asks for one (getState) anyway.
//
// ---- Changes in proto 2 --------------------------------------------------------------------------
// The line protocol is wire compatible with the pre-proto-2 host: existing sketches keep working
// unchanged. Only the obsolete `setPlanSkeleton` and `setSlave` messages are gone - plan skeletons are
// stored per room by the Device core on the PC (<state-dir>/plans, synchronised with the other devices
// of the room), slave mode does not exist any more. The optional top-level `slave` and `planSkeleton`
// members of a state are ignored. The component `uuid` is no longer taken from the sketch: the PC
// publishes `<did>-<index>` as PROTOCOL.md prescribes. Missing name/room fall back to the defaults of the
// firmware instead of dropping the whole snapshot. An Arduino that stops answering (no valid state for
// 15 s, or the port is gone) stays listed with the error "serial_offline" and its actions are rejected
// (422) until it reports again; the port is reopened automatically with a back-off.
//
// ---- What the PC remembers (--state-dir) ---------------------------------------------------------
//   did, boot            device id (derived from hostname and serial port unless --did is given) and boot counter
//   state.json           name/room, riddle id and plan slice the operator set through the manager (these are
//                        applied over what the sketch reports and are re-sent with setIdentity/setRiddleId/setPlan
//                        after every reconnect when the Arduino reports something else) plus the last reported
//                        component list, so the rooms (and with them the stored plan skeletons) are known before
//                        the Arduino has answered
//   plans/               room plan skeletons of the Device core
// All files are replaced atomically (temporary file, fsync, rename). Default state dir:
// $XDG_STATE_HOME or ~/.local/state, subdirectory escape-serial-host/<serial port>.
//
// ---- Options -------------------------------------------------------------------------------------
//   --serial DEV          serial device (required)          --baud N           115200 (default)
//   --http-port N         8080 (default)                    --udp-port N       4210 (default)
//   --did 12HEX           device id                         --token T          own token (8..128 chars),
//   --ip A.B.C.D          address to announce                                  default ESCAPE_AUTH_TOKEN env/public
//   --broadcast A.B.C.D   discovery broadcast address       --no-mdns          no shared mDNS record
//                         (default: the LAN interface's)                       (only answered with --http-port 80)
//   --mdns-port N         5353                              --mdns-hostname H  escapemanager.local
//   --manager-html FILE   UI to serve at "/" (.gz allowed; default src/manager/manager.html, if found)
//   --state-dir DIR       see above
// SIGINT/SIGTERM stop the program cleanly; exit status 1 if the HTTP port cannot be opened, 2 for bad options.

#include "../net/Clock.hpp"
#include "../net/Device.hpp"
#include "HostNetwork.hpp"
#include "OpenSslCryptoBackend.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cerrno>
#include <csignal>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <ifaddrs.h>
#include <iostream>
#include <map>
#include <openssl/evp.h>
#include <poll.h>
#include <sstream>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

using namespace Escape;
using EscapeProtocol::ComponentSnapshot;
using EscapeProtocol::CustomConfigDef;
using EscapeProtocol::CustomConfigType;
using EscapeProtocol::PlanAction;
using EscapeJson::Type;
using EscapeJson::Value;

namespace {

volatile std::sig_atomic_t g_stop = 0;
void onSignal(int) { g_stop = 1; }

#if defined(__GNUC__)
#define EM_PRINTF(a, b) __attribute__((format(printf, a, b)))
#else
#define EM_PRINTF(a, b)
#endif

void logMsg(const char *fmt, ...) EM_PRINTF(1, 2);
void logMsg(const char *fmt, ...) {
  char text[600];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(text, sizeof(text), fmt, ap);
  va_end(ap);
  fprintf(stderr, "[serial-host] %s\n", text);
}

// ---- Files: atomic blob storage (state dir, plan skeletons) ---------------------------------------

bool mkdirs(const std::string &path) {
  std::string cur;
  for (size_t i = 0; i <= path.size(); i++) {
    if (i == path.size() || path[i] == '/') {
      if (!cur.empty() && mkdir(cur.c_str(), 0700) != 0 && errno != EEXIST) return false;
    }
    if (i < path.size()) cur += path[i];
  }
  struct stat st;
  return stat(path.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
}

bool readFile(const std::string &path, std::string &out, size_t maxBytes = 1u << 20) {
  std::ifstream f(path.c_str(), std::ios::binary);
  if (!f.good()) return false;
  std::ostringstream ss;
  ss << f.rdbuf();
  out = ss.str();
  return out.size() <= maxBytes;
}

class FileStorage : public BlobStorage {
public:
  explicit FileStorage(const std::string &dir) : dir_(dir), ready_(mkdirs(dir)) {}
  bool ready() const { return ready_; }
  bool read(const char *key, std::string &out) override {
    if (!validKey(key)) return false;
    return readFile(path(key), out);
  }
  // temporary file + fsync + rename: a crash leaves either the old or the new content
  bool write(const char *key, const std::string &data) override {
    if (!validKey(key)) return false;
    const std::string target = path(key), tmp = target + ".tmp";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    bool ok = true;
    for (size_t off = 0; ok && off < data.size();) {
      const ssize_t n = ::write(fd, data.data() + off, data.size() - off);
      if (n > 0) off += (size_t)n;
      else if (n < 0 && errno == EINTR) continue;
      else ok = false;
    }
    ok = ok && ::fsync(fd) == 0;
    ::close(fd);
    if (!ok || ::rename(tmp.c_str(), target.c_str()) != 0) {
      ::unlink(tmp.c_str());
      return false;
    }
    const int dirFd = ::open(dir_.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); // make the rename durable (best effort)
    if (dirFd >= 0) {
      ::fsync(dirFd);
      ::close(dirFd);
    }
    return true;
  }
  bool erase(const char *key) override { return validKey(key) && ::unlink(path(key).c_str()) == 0; }

private:
  static bool validKey(const char *key) {
    const size_t n = key ? strlen(key) : 0;
    if (n == 0 || n > 64 || key[0] == '.') return false;
    for (size_t i = 0; i < n; i++) {
      const char c = key[i];
      if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-' || c == '.')) return false;
    }
    return true;
  }
  std::string path(const char *key) const { return dir_ + "/" + key; }
  std::string dir_;
  bool ready_;
};

// ---- Serial line: framing --------------------------------------------------------------------------

// Cuts the byte stream into JSON lines with bounded memory: only lines that start with '{' are
// collected (everything else is debug output and skipped without being stored), and a line longer than
// kMaxLine is discarded up to its newline.
class LineFramer {
public:
  static constexpr size_t kMaxLine = 16 * 1024;

  void reset() {
    std::string().swap(buf_);
    mode_ = Mode::Start;
  }
  uint32_t takeOversize() {
    const uint32_t n = oversize_;
    oversize_ = 0;
    return n;
  }

  template <class Emit> void feed(const char *p, size_t n, Emit &&emit) {
    size_t i = 0;
    while (i < n) {
      if (mode_ == Mode::Start) {
        const unsigned char c = (unsigned char)p[i];
        if (c <= ' ') { i++; continue; } // blank lines, CR, NUL and other control noise between lines
        buf_.clear();
        mode_ = c == '{' ? Mode::Collect : Mode::Discard;
      }
      const char *nl = (const char *)memchr(p + i, '\n', n - i);
      const size_t seg = nl ? (size_t)(nl - (p + i)) : n - i;
      if (mode_ == Mode::Collect) {
        if (buf_.size() + seg > kMaxLine) {
          std::string().swap(buf_);
          mode_ = Mode::Discard;
          oversize_++;
        } else {
          buf_.append(p + i, seg);
        }
      }
      i += seg;
      if (nl) {
        i++;
        if (mode_ == Mode::Collect) {
          while (!buf_.empty() && (unsigned char)buf_.back() <= ' ') buf_.pop_back();
          emit(buf_);
        }
        buf_.clear();
        mode_ = Mode::Start;
      }
    }
  }

private:
  enum class Mode { Start, Collect, Discard };
  std::string buf_;
  Mode mode_ = Mode::Start;
  uint32_t oversize_ = 0;
};

// ---- Serial line: port ---------------------------------------------------------------------------------

speed_t baudConstant(int baud) {
  switch (baud) {
    case 1200: return B1200;
    case 2400: return B2400;
    case 4800: return B4800;
    case 9600: return B9600;
    case 19200: return B19200;
    case 38400: return B38400;
    case 57600: return B57600;
    case 115200: return B115200;
#ifdef B230400
    case 230400: return B230400;
#endif
#ifdef B460800
    case 460800: return B460800;
#endif
#ifdef B921600
    case 921600: return B921600;
#endif
    default: return 0;
  }
}

// Non-blocking serial port with automatic re-open. Nothing here waits: reads and writes take what the
// kernel offers, the rest of the output stays in a small bounded queue (and is dropped when the line
// makes no progress for kStallMs - a command that arrives minutes late would be worse than a lost one).
class SerialLink {
public:
  static constexpr size_t kMaxOut = 8192;
  static constexpr uint32_t kStallMs = 5000;
  static constexpr uint32_t kBackoffMinMs = 500, kBackoffMaxMs = 5000;
  static constexpr int kReadsPerPoll = 2; // at most 8 KB of input (and of parsing work) per loop iteration: a babbling Arduino cannot starve HTTP

  SerialLink(const std::string &path, int baud) : path_(path), baud_(baud), speed_(baudConstant(baud)) {}
  ~SerialLink() { shutdown(); }

  std::function<void()> onOpen, onClose, onDrop; // onDrop: queued output was thrown away (stalled line)
  std::function<void(const std::string &)> onLine;

  bool isOpen() const { return fd_ >= 0; }
  size_t pending() const { return out_.size(); }
  void noteHealthy() { fails_ = 0; }
  uint32_t takeOversize() { return framer_.takeOversize(); }

  // Queues one line (the newline is added). False if the port is closed or the queue is full.
  bool send(const std::string &line) {
    if (fd_ < 0 || out_.size() + line.size() + 1 > kMaxOut) return false;
    if (out_.empty()) progressMs_ = now_;
    out_ += line;
    out_ += '\n';
    return true;
  }

  // Waits up to `ms` for input (or just sleeps while the port is closed).
  void wait(int ms) {
    if (fd_ < 0) {
      usleep((useconds_t)ms * 1000);
      return;
    }
    pollfd p;
    p.fd = fd_;
    p.events = POLLIN;
    p.revents = 0;
    if (::poll(&p, 1, ms) > 0 && (p.revents & (POLLHUP | POLLERR | POLLNVAL))) hangup_ = true;
  }

  // Opens the port when due, reads what is available and hands complete lines to onLine.
  void pollInput(uint32_t now) {
    now_ = now;
    if (fd_ < 0) {
      if ((int32_t)(now - nextOpenMs_) < 0 || !open(now)) return;
    }
    char buf[4096];
    for (int round = 0; round < kReadsPerPoll && fd_ >= 0; round++) {
      const ssize_t n = ::read(fd_, buf, sizeof(buf));
      if (n > 0) {
        framer_.feed(buf, (size_t)n, [&](const std::string &line) {
          if (onLine) onLine(line);
        });
        continue;
      }
      if (n < 0 && errno == EINTR) continue;
      if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) { // EIO/ENODEV: unplugged, pty peer gone
        closeLink(now, strerror(errno));
        return;
      }
      if (hangup_) closeLink(now, "hang-up");
      return;
    }
  }

  void flush(uint32_t now) {
    now_ = now;
    if (fd_ < 0 || out_.empty()) return;
    const ssize_t n = ::write(fd_, out_.data(), out_.size());
    if (n > 0) {
      atLineStart_ = out_[(size_t)n - 1] == '\n';
      out_.erase(0, (size_t)n);
      progressMs_ = now;
    } else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
      closeLink(now, strerror(errno));
      return;
    }
    if (!out_.empty() && (int32_t)(now - progressMs_) > (int32_t)kStallMs) {
      logMsg("serial output made no progress for %u ms, dropping %zu queued bytes", (unsigned)kStallMs, out_.size());
      out_ = atLineStart_ ? std::string() : std::string("\n"); // terminate a half-written line for the Arduino
      progressMs_ = now;
      if (onDrop) onDrop();
    }
  }

  void shutdown() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
  }

private:
  uint32_t backoffMs() const { return std::min<uint32_t>(kBackoffMinMs << std::min<uint32_t>(fails_, 4), kBackoffMaxMs); }

  bool failOpen(uint32_t now, const char *why) {
    if (fails_ == 0 || lastError_ != why || (int32_t)(now - lastLogMs_) > 30000) {
      logMsg("cannot open %s: %s (retrying with back-off)", path_.c_str(), why);
      lastError_ = why;
      lastLogMs_ = now;
    }
    nextOpenMs_ = now + backoffMs();
    fails_++;
    return false;
  }

  bool open(uint32_t now) {
    if (!speed_) return failOpen(now, "unsupported baud rate");
    const int fd = ::open(path_.c_str(), O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return failOpen(now, strerror(errno));
    termios t;
    memset(&t, 0, sizeof(t));
    if (!isatty(fd) || tcgetattr(fd, &t) != 0) { // never write commands into a regular file or a socket
      ::close(fd);
      return failOpen(now, "not a terminal device");
    }
    cfmakeraw(&t);
    cfsetispeed(&t, speed_);
    cfsetospeed(&t, speed_);
    t.c_cflag |= CLOCAL | CREAD;
    t.c_cflag &= ~(tcflag_t)(CSTOPB | PARENB | HUPCL); // no HUPCL: closing the port (host restart) does not drop DTR and reset the board
#ifdef CRTSCTS
    t.c_cflag &= ~(tcflag_t)CRTSCTS;
#endif
    t.c_cc[VMIN] = 0;
    t.c_cc[VTIME] = 0;
    if (tcsetattr(fd, TCSANOW, &t) != 0) {
      const int err = errno;
      ::close(fd);
      return failOpen(now, strerror(err));
    }
    tcflush(fd, TCIOFLUSH);
#ifdef TIOCEXCL
    ioctl(fd, TIOCEXCL); // keep a second program from reading half of the Arduino's lines (best effort)
#endif
    fd_ = fd;
    hangup_ = false;
    atLineStart_ = true;
    out_.clear();
    framer_.reset();
    lastError_.clear();
    logMsg("connected to %s @ %d baud", path_.c_str(), baud_);
    if (onOpen) onOpen();
    return true;
  }

  void closeLink(uint32_t now, const char *why) {
    if (fd_ < 0) return;
    ::close(fd_);
    fd_ = -1;
    out_.clear();
    framer_.reset();
    const uint32_t delay = backoffMs();
    fails_++;
    nextOpenMs_ = now + delay;
    logMsg("lost %s (%s); reopening in %u ms", path_.c_str(), why, (unsigned)delay);
    if (onClose) onClose();
  }

  std::string path_;
  int baud_;
  speed_t speed_;
  int fd_ = -1;
  bool hangup_ = false;
  bool atLineStart_ = true;
  uint32_t now_ = 0, nextOpenMs_ = 0, progressMs_ = 0, lastLogMs_ = 0, fails_ = 0;
  std::string lastError_, out_;
  LineFramer framer_;
};

// ---- Text helpers ---------------------------------------------------------------------------------------

// Copies s into a fixed buffer, cutting at a UTF-8 character boundary (status.json must stay valid UTF-8).
void setText(char *dst, size_t capacity, const std::string &s) {
  size_t n = std::min(s.size(), capacity - 1);
  while (n > 0 && n < s.size() && ((unsigned char)s[n] & 0xC0) == 0x80) n--;
  memcpy(dst, s.data(), n);
  dst[n] = '\0';
}

std::string jsonString(const std::string &s) {
  std::string out = "\"";
  EscapeJson::appendEscaped(out, s);
  out += '"';
  return out;
}

std::string textField(const Value &o, const char *key) {
  const Value *v = o.find(key);
  return v ? v->asString() : std::string();
}

long long clampedInt(const Value *v, long long lo, long long hi, long long fallback) {
  if (!v || v->type != Type::Number) return fallback;
  if (!(v->numberValue >= (double)lo)) return lo;
  if (v->numberValue > (double)hi) return hi;
  return (long long)v->numberValue;
}

std::string sha256Hex8(const std::string &data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(data.data(), data.size(), md, &len, EVP_sha256(), nullptr);
  char hex[9];
  snprintf(hex, sizeof(hex), "%02x%02x%02x%02x", md[0], md[1], md[2], md[3]);
  return hex;
}

// ---- The adapter: the Arduino as a device ---------------------------------------------------------------

class SerialHost : public EscapeProtocol::ProtocolAdapter {
public:
  SerialHost(const std::string &serialPath, int baud, BlobStorage &state) : link_(serialPath, baud), state_(state) {
    link_.onOpen = [this]() { onOpen(); };
    link_.onClose = [this]() { onClose(); };
    link_.onDrop = [this]() { markOverridesDirty(); };
    link_.onLine = [this](const std::string &line) { onLine(line); };
  }

  void attach(Device *device, const std::string &did) {
    device_ = device;
    did_ = did;
  }

  // Restores operator settings and the last known component list (so rooms are known before the first state).
  void load() {
    std::string text;
    if (!state_.read("state.json", text)) return;
    Value doc;
    if (!EscapeJson::parse(text, doc, EscapeJson::ParseLimits(6, 1500)) || doc.type != Type::Object) {
      logMsg("state.json is unreadable, starting without stored settings");
      return;
    }
    const Value *ov = doc.find("ov");
    for (size_t i = 0; ov && ov->type == Type::Array && i < ov->arrayValue.size() && i < 32; i++) {
      const Value &e = ov->arrayValue[i];
      long long id = 0;
      if (e.type != Type::Object || !e.find("id") || !e.find("id")->asInt(0, 255, id)) continue;
      Override &o = overrides_[(uint8_t)id];
      const std::string name = textField(e, "name"), room = textField(e, "room"), riddle = textField(e, "riddleId");
      if (!name.empty() && !room.empty() && name.size() <= EscapeConfig::MAX_NAME_LEN && room.size() <= EscapeConfig::MAX_ROOM_LEN) {
        o.hasIdentity = true;
        o.name = name;
        o.room = room;
      }
      if (!riddle.empty() && riddle.size() <= EscapeConfig::MAX_RIDDLE_ID_LEN) {
        o.hasRiddle = true;
        o.riddle = riddle;
      }
      const Value *plan = e.find("plan");
      if (plan && plan->type == Type::String && plan->stringValue.size() <= EscapeConfig::MAX_PLAN_LEN &&
          (plan->stringValue.empty() || EscapeJson::validate(plan->stringValue.data(), plan->stringValue.size()))) {
        o.hasPlan = true;
        o.plan = plan->stringValue;
      }
    }
    const Value *known = doc.find("known");
    for (size_t i = 0; known && known->type == Type::Array && i < known->arrayValue.size() && known_.size() < EscapeConfig::MAX_LOCAL_COMPONENTS; i++) {
      const Value &e = known->arrayValue[i];
      long long id = 0;
      if (e.type != Type::Object || !e.find("id") || !e.find("id")->asInt(0, 255, id)) continue;
      Known k;
      k.id = (uint8_t)id;
      k.name = textField(e, "name");
      k.room = textField(e, "room");
      k.riddle = textField(e, "riddleId");
      known_.push_back(k);
    }
    std::vector<Slot> placeholders(known_.size());
    for (size_t i = 0; i < known_.size(); i++) {
      placeholders[i].serialId = known_[i].id;
      placeholders[i].snap.clear();
      setText(placeholders[i].snap.name, sizeof(placeholders[i].snap.name), known_[i].name);
      setText(placeholders[i].snap.room, sizeof(placeholders[i].snap.room), known_[i].room);
      setText(placeholders[i].snap.riddleId, sizeof(placeholders[i].snap.riddleId), known_[i].riddle);
    }
    slots_.swap(placeholders);
  }

  // Serial input, timers, overrides (the first half of a main-loop iteration; the second is pumpOutput()).
  void pollInput(uint32_t now) {
    now_ = now;
    link_.pollInput(now);
    if (const uint32_t n = link_.takeOversize()) warn(WarnOversize, "dropped %u line(s) longer than %u bytes", (unsigned)n, (unsigned)LineFramer::kMaxLine);
    if (online_ && (int32_t)(now - lastStateMs_) > (int32_t)kOfflineMs) {
      logMsg("no state from the Arduino for %u s - marking the component(s) offline", (unsigned)(kOfflineMs / 1000));
      online_ = false;
      markDirty();
    }
    if (link_.isOpen() && (int32_t)(now - lastGetStateMs_) >= (int32_t)(online_ ? kPollMs : kRetryMs)) wantGetState_ = true;
    pushOverrides();
    if (stateDirty_ && (int32_t)(now - lastSaveMs_) >= (int32_t)kSaveGapMs) saveState();
  }

  // Writes queued commands; asks for a fresh state once everything before it has gone out.
  void pumpOutput(uint32_t now) {
    now_ = now;
    link_.flush(now);
    if (wantGetState_ && link_.isOpen() && link_.pending() == 0 && (int32_t)(now - lastGetStateMs_) >= (int32_t)kMinGetStateGapMs) {
      wantGetState_ = false;
      lastGetStateMs_ = now;
      link_.send("{\"type\":\"getState\"}");
      link_.flush(now);
    }
  }

  void wait(int ms) { link_.wait(ms); }
  void shutdown() {
    if (stateDirty_) saveState();
    link_.shutdown();
  }

  // ---- ProtocolAdapter ----------------------------------------------------------------------------------
  int8_t battery() const override { return battery_; }
  void markDirty() override {
    if (device_) device_->markDirty();
  }
  uint8_t componentCount() const override { return (uint8_t)slots_.size(); }

  void identity(uint8_t i, std::string &name, std::string &room) const override {
    if (i >= slots_.size()) return;
    const Override *o = findOverride(slots_[i].serialId);
    if (o && o->hasIdentity) {
      name = o->name;
      room = o->room;
    } else {
      name = slots_[i].snap.name;
      room = slots_[i].snap.room;
    }
  }

  void snapshot(uint8_t i, ComponentSnapshot &out) const override {
    if (i >= slots_.size()) return;
    const Slot &s = slots_[i];
    out = s.snap;
    if (const Override *o = findOverride(s.serialId)) { // operator settings win over what the sketch reports
      if (o->hasIdentity) {
        setText(out.name, sizeof(out.name), o->name);
        setText(out.room, sizeof(out.room), o->room);
      }
      if (o->hasRiddle) setText(out.riddleId, sizeof(out.riddleId), o->riddle);
      if (o->hasPlan) setText(out.plan, sizeof(out.plan), o->plan);
    }
    setText(out.uuid, sizeof(out.uuid), did_ + "-" + std::to_string((unsigned)i));
    if (!online()) { // still listed, but visibly not answering
      const size_t at = out.errorCount < EscapeConfig::MAX_ERRORS ? out.errorCount++ : EscapeConfig::MAX_ERRORS - 1;
      setText(out.errors[at], sizeof(out.errors[at]), "serial_offline");
    }
  }

  void customConfigDefs(uint8_t i, std::vector<CustomConfigDef> &out) const override {
    out.clear();
    if (i < slots_.size()) out.assign(slots_[i].snap.customConfig, slots_[i].snap.customConfig + slots_[i].snap.customConfigCount);
  }

  bool applyAction(uint8_t i, const std::string &action) override { return command(i, "action", ",\"action\":" + jsonString(action)); }
  bool applyPlanAction(uint8_t i, PlanAction a) override {
    return command(i, "planAction", ",\"action\":" + jsonString(EscapeProtocol::planActionName(a)));
  }
  bool setCustomConfigValue(uint8_t i, const std::string &key, const std::string &value) override {
    return command(i, "setConfig", ",\"key\":" + jsonString(key) + ",\"value\":" + jsonString(value));
  }
  void pushEvent(uint8_t i, const std::string &message) override { command(i, "event", ",\"message\":" + jsonString(message)); }

  // Identity, riddle id and plan are kept on the PC and pushed to the Arduino by pushOverrides().
  void setIdentity(uint8_t i, const std::string &name, const std::string &room) override {
    if (i >= slots_.size()) return;
    Override &o = overrides_[slots_[i].serialId];
    o.hasIdentity = true;
    o.name = name;
    o.room = room;
    o.dirty = o.force = true;
    saveState();
  }
  void setRiddleId(uint8_t i, const std::string &riddleId) override {
    if (i >= slots_.size()) return;
    Override &o = overrides_[slots_[i].serialId];
    o.hasRiddle = true;
    o.riddle = riddleId;
    o.dirty = o.force = true;
    saveState();
  }
  void setPlan(uint8_t i, const std::string &planJson) override {
    if (i >= slots_.size()) return;
    Override &o = overrides_[slots_[i].serialId];
    o.hasPlan = true;
    o.plan = planJson;
    o.dirty = o.force = true;
    saveState();
  }

private:
  // One component as the Arduino reported it. Slots are never copied, only built in place and swapped:
  // snap is memset before it is filled, so two snapshots can be compared with memcmp.
  struct Slot {
    uint8_t serialId = 0;
    ComponentSnapshot snap;
  };
  struct Override { // settings of the operator, persisted
    bool hasIdentity = false, hasRiddle = false, hasPlan = false;
    bool dirty = false, force = false; // dirty: send to the Arduino; force: even if it already reports the value
    std::string name, room, riddle, plan; // plan "" = cleared on purpose
  };
  struct Known {
    uint8_t id = 0;
    std::string name, room, riddle;
    bool operator==(const Known &o) const { return id == o.id && name == o.name && room == o.room && riddle == o.riddle; }
  };
  enum Warn { WarnOversize, WarnBadJson, WarnBadState, WarnQueue, WarnSave, WarnCount };
  struct Throttle {
    bool used = false;
    uint32_t lastMs = 0, suppressed = 0;
  };

  static constexpr uint32_t kOfflineMs = 15000;     // no valid state for this long: offline
  static constexpr uint32_t kPollMs = 5000;         // getState interval while the Arduino answers
  static constexpr uint32_t kRetryMs = 1000;        // ... and while it does not (it may still be booting after the port opened)
  static constexpr uint32_t kMinGetStateGapMs = 50;
  static constexpr uint32_t kSaveGapMs = 5000;      // limit for rewrites caused by the sketch's own changes

  bool online() const { return online_ && link_.isOpen(); }

  const Override *findOverride(uint8_t id) const {
    const std::map<uint8_t, Override>::const_iterator it = overrides_.find(id);
    return it == overrides_.end() ? nullptr : &it->second;
  }

  EM_PRINTF(3, 4) void warn(Warn kind, const char *fmt, ...) {
    Throttle &t = throttle_[kind];
    if (t.used && (int32_t)(now_ - t.lastMs) < 2000) {
      t.suppressed++;
      return;
    }
    char text[300];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(text, sizeof(text), fmt, ap);
    va_end(ap);
    logMsg("%s%s", text, t.suppressed ? " (more of these were suppressed)" : "");
    t.used = true;
    t.lastMs = now_;
    t.suppressed = 0;
  }

  // Queues one command for the component at host index i (false: Arduino not reachable or queue full).
  bool command(uint8_t i, const char *type, const std::string &members) {
    if (i >= slots_.size() || !online()) return false;
    return sendLine(std::string("{\"type\":\"") + type + "\",\"id\":" + std::to_string((unsigned)slots_[i].serialId) + members + "}");
  }
  bool sendLine(const std::string &line) {
    if (!link_.send(line)) {
      warn(WarnQueue, "serial output queue full, command dropped");
      return false;
    }
    wantGetState_ = true; // the Arduino should report the effect
    return true;
  }

  // Sends operator settings the Arduino has not got yet (after a command through the manager or a reconnect).
  void pushOverrides() {
    if (!online()) return;
    for (std::map<uint8_t, Override>::iterator it = overrides_.begin(); it != overrides_.end(); ++it) {
      Override &o = it->second;
      if (!o.dirty) continue;
      const Slot *slot = nullptr;
      for (size_t k = 0; k < slots_.size(); k++) {
        if (slots_[k].serialId == it->first) slot = &slots_[k];
      }
      if (!slot) continue;
      const ComponentSnapshot &rep = slot->snap;
      const std::string id = std::to_string((unsigned)it->first);
      bool ok = true;
      if (o.hasIdentity && (o.force || o.name != rep.name || o.room != rep.room)) {
        ok = ok && sendLine("{\"type\":\"setIdentity\",\"id\":" + id + ",\"name\":" + jsonString(o.name) + ",\"room\":" + jsonString(o.room) + "}");
      }
      if (ok && o.hasRiddle && (o.force || o.riddle != rep.riddleId)) {
        ok = sendLine("{\"type\":\"setRiddleId\",\"id\":" + id + ",\"value\":" + jsonString(o.riddle) + "}");
      }
      if (ok && o.hasPlan && (o.force || o.plan != rep.plan)) {
        ok = sendLine("{\"type\":\"setPlan\",\"id\":" + id + ",\"plan\":" + (o.plan.empty() ? std::string("null") : o.plan) + "}");
      }
      if (ok) o.dirty = o.force = false; // otherwise (queue full) the next iteration retries
    }
  }

  // ---- Serial events -------------------------------------------------------------------------------------
  void onOpen() {
    wantGetState_ = true;
    lastGetStateMs_ = now_ - kMinGetStateGapMs;
    markOverridesDirty();
  }
  // Operator settings are re-checked against what the Arduino reports (after a reconnect or lost output).
  void markOverridesDirty() {
    for (std::map<uint8_t, Override>::iterator it = overrides_.begin(); it != overrides_.end(); ++it) it->second.dirty = true;
  }
  void onClose() {
    wantGetState_ = false;
    if (online_) {
      online_ = false;
      markDirty();
    }
  }

  void onLine(const std::string &line) {
    if (line.find("state") == std::string::npos) return; // debug output that happens to look like JSON: not worth a parse
    Value doc;
    if (!EscapeJson::parse(line, doc, EscapeJson::ParseLimits(20, 2048)) || doc.type != Type::Object) {
      warn(WarnBadJson, "ignored a line that is not valid JSON (%zu bytes)", line.size());
      return;
    }
    const Value *type = doc.find("type");
    if (!type || type->asString() != "state") return; // unknown message types are ignored
    applyState(doc);
  }

  // Reads one component object of a state; false if the snapshot as a whole must be dropped.
  static bool parseComponent(const Value &c, size_t index, Slot &out) {
    if (c.type != Type::Object) return false;
    long long id = (long long)index;
    if (const Value *v = c.find("id")) {
      if (!v->asInt(0, 255, id)) return false;
    }
    out.serialId = (uint8_t)id;
    ComponentSnapshot &s = out.snap;
    s.clear();
    std::string t = textField(c, "name");
    setText(s.name, sizeof(s.name), t.empty() ? EscapeConfig::DEFAULT_NAME : t);
    t = textField(c, "room");
    setText(s.room, sizeof(s.room), t.empty() ? EscapeConfig::DEFAULT_ROOM : t);
    setText(s.riddleId, sizeof(s.riddleId), textField(c, "riddleId"));

    const Value *list = c.find("errors");
    for (size_t k = 0; list && list->type == Type::Array && k < list->arrayValue.size() && s.errorCount < EscapeConfig::MAX_ERRORS; k++) {
      const std::string e = list->arrayValue[k].asString();
      if (!e.empty()) setText(s.errors[s.errorCount++], sizeof(s.errors[0]), e);
    }
    list = c.find("actions");
    for (size_t k = 0; list && list->type == Type::Array && k < list->arrayValue.size() && s.actionCount < EscapeConfig::MAX_ACTIONS; k++) {
      const std::string a = list->arrayValue[k].asString();
      if (!a.empty() && a.size() <= EscapeConfig::MAX_ACTION_LEN) setText(s.actions[s.actionCount++], sizeof(s.actions[0]), a);
    }
    list = c.find("planActions");
    for (size_t k = 0; list && list->type == Type::Array && k < list->arrayValue.size(); k++) {
      const std::string a = list->arrayValue[k].asString();
      if (a == EscapeProtocol::planActionName(PlanAction::Reset)) s.planActionMask |= EscapeProtocol::planActionBit(PlanAction::Reset);
      if (a == EscapeProtocol::planActionName(PlanAction::Complete)) s.planActionMask |= EscapeProtocol::planActionBit(PlanAction::Complete);
    }
    t = textField(c, "feed");
    if (t.size() <= EscapeConfig::MAX_FEED_LEN && (t.compare(0, 7, "http://") == 0 || t.compare(0, 8, "https://") == 0)) setText(s.feed, sizeof(s.feed), t);
    setText(s.tip, sizeof(s.tip), textField(c, "tip"));

    const Value *puzzle = c.find("puzzle");
    if (puzzle && puzzle->type == Type::Object) {
      s.puzzleStep = (uint16_t)clampedInt(puzzle->find("step"), 0, 65535, 0);
      s.puzzleTotalSteps = (uint16_t)clampedInt(puzzle->find("totalSteps"), 0, 65535, 0);
      setText(s.puzzleState, sizeof(s.puzzleState), textField(*puzzle, "state"));
      s.puzzleIsHtml = puzzle->find("isHtml") && puzzle->find("isHtml")->asBool(false);
    }

    list = c.find("customConfig");
    for (size_t k = 0; list && list->type == Type::Array && k < list->arrayValue.size() && s.customConfigCount < EscapeConfig::MAX_CUSTOM_CONFIGS; k++) {
      const Value &item = list->arrayValue[k];
      const std::string key = textField(item, "key");
      if (item.type != Type::Object || key.empty() || key.size() > EscapeConfig::MAX_CONFIG_KEY_LEN) continue;
      CustomConfigDef &d = s.customConfig[s.customConfigCount++]; // already all-zero (clear())
      setText(d.key, sizeof(d.key), key);
      const std::string type = textField(item, "type");
      if (type == "range") {
        d.type = CustomConfigType::Range;
        d.rangeMin = (int32_t)clampedInt(item.find("min"), INT32_MIN, INT32_MAX, 0);
        d.rangeMax = (int32_t)clampedInt(item.find("max"), INT32_MIN, INT32_MAX, 0);
      } else if (type == "select") {
        d.type = CustomConfigType::Select;
        const Value *opts = item.find("options");
        for (size_t j = 0; opts && opts->type == Type::Array && j < opts->arrayValue.size() && d.optionCount < EscapeConfig::MAX_CONFIG_OPTIONS; j++) {
          const std::string o = opts->arrayValue[j].asString();
          if (!o.empty() && o.size() <= EscapeConfig::MAX_CONFIG_OPTION_LEN) setText(d.options[d.optionCount++], sizeof(d.options[0]), o);
        }
      } else {
        d.type = CustomConfigType::Text;
        d.textMaxLen = (uint16_t)clampedInt(item.find("maxLength"), 0, 65535, EscapeConfig::MAX_CONFIG_VALUE_LEN);
      }
      if (const Value *v = item.find("value")) setText(d.value, sizeof(d.value), v->asStringLoose());
    }

    const Value *plan = c.find("plan"); // a sketch that echoes the plan returns it re-serialised (the PC keeps the exact copy)
    std::string planText;
    if (plan && plan->type == Type::Object && EscapeJson::stringify(*plan, planText, EscapeConfig::MAX_PLAN_LEN) && planText.size() <= EscapeConfig::MAX_PLAN_LEN) {
      setText(s.plan, sizeof(s.plan), planText);
    }
    s.eventSeq = (uint32_t)clampedInt(c.find("evtSeq"), 0, 0xFFFFFFFFll, 0);
    setText(s.eventMsg, sizeof(s.eventMsg), textField(c, "evtMsg"));
    return true;
  }

  void applyState(const Value &doc) {
    const Value *comps = doc.find("components");
    if (!comps || comps->type != Type::Array) {
      warn(WarnBadState, "state without a components array dropped");
      return;
    }
    size_t n = comps->arrayValue.size();
    if (n > EscapeConfig::MAX_LOCAL_COMPONENTS) {
      warn(WarnBadState, "state lists %zu components, only the first %u are used", n, (unsigned)EscapeConfig::MAX_LOCAL_COMPONENTS);
      n = EscapeConfig::MAX_LOCAL_COMPONENTS;
    }
    std::vector<Slot> next(n);
    for (size_t i = 0; i < n; i++) {
      if (!parseComponent(comps->arrayValue[i], i, next[i])) {
        warn(WarnBadState, "state dropped: component %zu is invalid", i);
        return;
      }
      bool duplicate = false;
      for (size_t k = 0; k < i; k++) duplicate = duplicate || next[k].serialId == next[i].serialId;
      if (duplicate) {
        warn(WarnBadState, "state dropped: duplicate component id %u", (unsigned)next[i].serialId);
        return;
      }
    }
    const Value *b = doc.find("battery");
    const int battery = b && b->type == Type::Number ? (int)clampedInt(b, -1, 100, -1) : -1;

    bool changed = !online_ || battery_ != (battery > 0 ? battery : -1) || next.size() != slots_.size();
    for (size_t i = 0; !changed && i < n; i++) {
      changed = next[i].serialId != slots_[i].serialId || memcmp((const void *)&next[i].snap, (const void *)&slots_[i].snap, sizeof(ComponentSnapshot)) != 0;
    }
    const std::vector<std::string> roomsBefore = EscapeProtocol::hostedRooms(*this);
    slots_.swap(next);
    battery_ = (int8_t)(battery > 0 ? battery : -1);
    if (!online_) logMsg("Arduino answers: %zu component(s), battery %s", slots_.size(), battery_ > 0 ? (std::to_string(battery_) + "%").c_str() : "none");
    online_ = true;
    lastStateMs_ = now_;
    link_.noteHealthy();

    std::vector<Known> known;
    for (size_t i = 0; i < slots_.size(); i++) {
      Known k;
      k.id = slots_[i].serialId;
      k.name = slots_[i].snap.name;
      k.room = slots_[i].snap.room;
      k.riddle = slots_[i].snap.riddleId;
      known.push_back(k);
    }
    if (known != known_) {
      known_.swap(known);
      stateDirty_ = true; // written at most every kSaveGapMs (a chattering sketch must not wear out the disk)
    }
    if (changed) markDirty();
    if (device_ && EscapeProtocol::hostedRooms(*this) != roomsBefore) device_->hostedRoomsChanged();
  }

  // ---- Persistence ---------------------------------------------------------------------------------------
  void saveState() {
    std::string s = "{\"v\":1,\"ov\":[";
    bool first = true;
    for (std::map<uint8_t, Override>::const_iterator it = overrides_.begin(); it != overrides_.end(); ++it) {
      const Override &o = it->second;
      if (!o.hasIdentity && !o.hasRiddle && !o.hasPlan) continue;
      s += first ? "{\"id\":" : ",{\"id\":";
      first = false;
      s += std::to_string((unsigned)it->first);
      if (o.hasIdentity) s += ",\"name\":" + jsonString(o.name) + ",\"room\":" + jsonString(o.room);
      if (o.hasRiddle) s += ",\"riddleId\":" + jsonString(o.riddle);
      if (o.hasPlan) s += ",\"plan\":" + jsonString(o.plan); // as text: exactly the bytes the manager sent
      s += '}';
    }
    s += "],\"known\":[";
    for (size_t i = 0; i < known_.size(); i++) {
      s += i ? ",{\"id\":" : "{\"id\":";
      s += std::to_string((unsigned)known_[i].id) + ",\"name\":" + jsonString(known_[i].name) + ",\"room\":" + jsonString(known_[i].room) +
           ",\"riddleId\":" + jsonString(known_[i].riddle) + "}";
    }
    s += "]}";
    lastSaveMs_ = now_;
    if (state_.write("state.json", s)) stateDirty_ = false;
    else warn(WarnSave, "cannot write state.json to the state directory - settings will not survive a restart");
  }

  SerialLink link_;
  BlobStorage &state_;
  Device *device_ = nullptr;
  std::string did_;
  std::vector<Slot> slots_;
  std::map<uint8_t, Override> overrides_;
  std::vector<Known> known_;
  int8_t battery_ = -1;
  bool online_ = false, wantGetState_ = false, stateDirty_ = false;
  uint32_t now_ = 0, lastStateMs_ = 0, lastGetStateMs_ = 0, lastSaveMs_ = 0;
  Throttle throttle_[WarnCount];
};

// ---- Platform ----------------------------------------------------------------------------------------------

class SerialPlatform : public DevicePlatform {
public:
  SerialPlatform(uint32_t ip, uint32_t broadcast) : ip_(ip), broadcast_(broadcast) {}
  uint32_t localIp() override { return ip_; }
  uint32_t broadcastIp() override { return broadcast_; }

private:
  uint32_t ip_, broadcast_;
};

// ---- Options -----------------------------------------------------------------------------------------------

struct Options {
  std::string serial, did, token, managerHtml, stateDir, ip, broadcast;
  std::string mdnsHostname = std::string(EscapeConfig::MDNS_HOSTNAME) + ".local";
  int baud = 115200;
  uint16_t httpPort = 8080, udpPort = EscapeConfig::UDP_PORT, mdnsPort = 5353;
  bool mdns = true;
};

int parseArgs(int argc, char **argv, Options &o) { // 0 ok, 1 --help, 2 error
  auto number = [&](const std::string &name, const std::string &text, long lo, long hi, long &out) {
    char *end = nullptr;
    errno = 0;
    out = strtol(text.c_str(), &end, 10);
    if (text.empty() || *end || errno || out < lo || out > hi) {
      std::cerr << name << " expects a number between " << lo << " and " << hi << "\n";
      return false;
    }
    return true;
  };
  for (int i = 1; i < argc; i++) {
    const std::string a = argv[i];
    if (a == "--help" || a == "-h") return 1;
    if (a == "--no-mdns") { o.mdns = false; continue; }
    if (i + 1 >= argc) { std::cerr << "missing value for " << a << "\n"; return 2; }
    const std::string v = argv[++i];
    long n = 0;
    if (a == "--serial") o.serial = v;
    else if (a == "--baud") { if (!number(a, v, 1, 4000000, n)) return 2; o.baud = (int)n; }
    else if (a == "--http-port") { if (!number(a, v, 1, 65535, n)) return 2; o.httpPort = (uint16_t)n; }
    else if (a == "--udp-port") { if (!number(a, v, 1, 65535, n)) return 2; o.udpPort = (uint16_t)n; }
    else if (a == "--mdns-port") { if (!number(a, v, 1, 65535, n)) return 2; o.mdnsPort = (uint16_t)n; }
    else if (a == "--did") o.did = v;
    else if (a == "--token") o.token = v;
    else if (a == "--ip") o.ip = v;
    else if (a == "--broadcast") o.broadcast = v;
    else if (a == "--manager-html") o.managerHtml = v;
    else if (a == "--state-dir") o.stateDir = v;
    else if (a == "--mdns-hostname") o.mdnsHostname = v;
    else { std::cerr << "unknown option " << a << "\nsee the header of escape_component_serial_host.cpp\n"; return 2; }
  }
  if (o.serial.empty()) { std::cerr << "--serial DEVICE is required (e.g. /dev/ttyACM0)\n"; return 2; }
  if (!baudConstant(o.baud)) { std::cerr << "unsupported --baud " << o.baud << "\n"; return 2; }
  return 0;
}

std::string defaultStateDir(const std::string &serial) {
  std::string base;
  if (const char *xdg = getenv("XDG_STATE_HOME")) base = xdg;
  if (base.empty() && getenv("HOME") && *getenv("HOME")) base = std::string(getenv("HOME")) + "/.local/state";
  if (base.empty()) base = "/tmp";
  std::string name;
  for (char c : serial) name += (isalnum((unsigned char)c) || c == '-' || c == '.') ? c : '_';
  while (!name.empty() && name[0] == '_') name.erase(0, 1);
  return base + "/escape-serial-host/" + (name.empty() ? "serial" : name);
}

// Stable per PC and serial port; the locally-administered bit keeps it apart from real MAC addresses.
std::string deriveDid(const std::string &serial) {
  char host[256] = {0};
  gethostname(host, sizeof(host) - 1);
  const std::string seed = std::string(host) + "|" + serial;
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  EVP_Digest(seed.data(), seed.size(), md, &len, EVP_sha256(), nullptr);
  md[0] = (unsigned char)((md[0] | 0x02) & 0xFE);
  char d[13];
  snprintf(d, sizeof(d), "%02x%02x%02x%02x%02x%02x", md[0], md[1], md[2], md[3], md[4], md[5]);
  return d;
}

std::string exeDir() {
  char buf[4096];
  const ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
  if (n <= 0) return std::string();
  buf[n] = '\0';
  const std::string p = buf;
  return p.substr(0, p.find_last_of('/') == std::string::npos ? 0 : p.find_last_of('/'));
}

} // namespace

// This program has no embedded firmware UI; it hashes whatever manager.html it serves.
namespace EscapeVersion {
const char *const UI_HASH = "00000000";
}

int main(int argc, char **argv) {
  Options opt;
  const int parsed = parseArgs(argc, argv, opt);
  if (parsed == 1) {
    std::cout << "usage: " << argv[0] << " --serial DEV [--baud N] [--http-port N] [--udp-port N] [--did 12HEX] [--token T]\n"
              << "       [--ip A.B.C.D] [--broadcast A.B.C.D] [--no-mdns] [--mdns-port N] [--mdns-hostname H]\n"
              << "       [--manager-html FILE] [--state-dir DIR]\n";
    return 0;
  }
  if (parsed) return 2;
  signal(SIGINT, onSignal);
  signal(SIGTERM, onSignal);
  signal(SIGPIPE, SIG_IGN);

  if (opt.token.empty() && getenv("ESCAPE_AUTH_TOKEN") && *getenv("ESCAPE_AUTH_TOKEN")) opt.token = getenv("ESCAPE_AUTH_TOKEN");
  if (!opt.token.empty() && (opt.token.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN || opt.token.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN)) {
    std::cerr << "the token must have " << EscapeConfig::MIN_AUTH_TOKEN_LEN << ".." << EscapeConfig::MAX_AUTH_TOKEN_LEN << " characters\n";
    return 2;
  }
  if (!opt.token.empty() && opt.token.size() < EscapeConfig::RECOMMENDED_AUTH_TOKEN_LEN) logMsg("warning: a token shorter than %u characters is easy to guess", (unsigned)EscapeConfig::RECOMMENDED_AUTH_TOKEN_LEN);

  uint32_t ip = 0x7F000001, bc = 0xFFFFFFFFu;
  std::string ifaceName;
  uint8_t b[4];
  if (!opt.ip.empty()) {
    if (!parseIpv4(opt.ip.data(), opt.ip.size(), b)) { std::cerr << "--ip is not an IPv4 address\n"; return 2; }
    ip = ipv4ToU32(b);
    if ((ip >> 24) == 127) bc = 0x7FFFFFFFu; // loopback hosts find each other through 127.255.255.255
    else if (const uint32_t directed = broadcastForIp(ip)) bc = directed;
  } else {
    const HostInterface lan = detectLanInterface();
    ip = lan.ip;
    bc = lan.broadcast;
    ifaceName = lan.name;
  }
  if (!opt.broadcast.empty()) {
    if (!parseIpv4(opt.broadcast.data(), opt.broadcast.size(), b)) { std::cerr << "--broadcast is not an IPv4 address\n"; return 2; }
    bc = ipv4ToU32(b);
  }

  if (opt.stateDir.empty()) opt.stateDir = defaultStateDir(opt.serial);
  FileStorage state(opt.stateDir);
  FileStorage skeletons(opt.stateDir + "/plans");
  if (!state.ready() || !skeletons.ready()) logMsg("warning: cannot create the state directory %s - nothing will be remembered", opt.stateDir.c_str());

  std::string did;
  for (char c : opt.did) did += (char)tolower((unsigned char)c);
  uint8_t didBytes[6];
  if (did.empty()) { // derived once, then kept in the state dir (stable even if hostname or port name change)
    std::string stored;
    if (state.read("did", stored)) did = stored.substr(0, stored.find_first_of("\r\n"));
    if (!parseDid(did.data(), did.size(), didBytes)) {
      did = deriveDid(opt.serial);
      state.write("did", did + "\n");
    }
  }
  if (did.size() != 12 || !parseDid(did.data(), did.size(), didBytes)) {
    std::cerr << "--did expects 12 hex characters\n";
    return 2;
  }

  SerialHost host(opt.serial, opt.baud, state);
  host.load(); // before Device::begin(): it drops skeletons of rooms without a component

  std::string html; // the UI: any manager.html (raw or .gz), by default the repository's source file
  bool gz = false;
  {
    std::vector<std::string> candidates;
    if (!opt.managerHtml.empty()) candidates.push_back(opt.managerHtml);
    candidates.push_back("src/manager/manager.html");
    candidates.push_back("../manager/manager.html");
    if (!exeDir().empty()) {
      candidates.push_back(exeDir() + "/../src/manager/manager.html");
      candidates.push_back(exeDir() + "/../manager/manager.html");
    }
    for (size_t i = 0; i < candidates.size(); i++) {
      if (readFile(candidates[i], html, 8u << 20) && !html.empty()) {
        gz = candidates[i].size() > 3 && candidates[i].compare(candidates[i].size() - 3, 3, ".gz") == 0;
        break;
      }
      html.clear();
    }
    if (html.empty()) logMsg("no manager.html found (use --manager-html); GET / will return 404");
  }

  OpenSslCryptoBackend crypto;
  SerialPlatform platform(ip, bc);
  Device device(host, crypto, skeletons, platform);
  host.attach(&device, did);

  DeviceOptions o;
  o.did = did;
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
  const bool custom = !opt.token.empty();
  if (!device.begin(o, custom ? opt.token : EscapeConfig::AUTH_TOKEN, custom ? TokenState::Custom : TokenState::Default)) {
    std::cerr << "[serial-host] cannot listen on HTTP port " << opt.httpPort << "\n";
    return 1;
  }
  std::cout << "[serial-host] did=" << did << " http=" << ipToString(ip) << ":" << opt.httpPort << " udp=" << opt.udpPort
            << " broadcast=" << ipToString(bc) << (ifaceName.empty() ? "" : " iface=" + ifaceName)
            << " serial=" << opt.serial << "@" << opt.baud << " token=" << tokenStateName(device.transport().tokenState())
            << " ui=" << o.uiHash << " state=" << opt.stateDir << std::endl;
  if (opt.mdns && !mdnsServesUi) {
    std::cout << "[serial-host] mDNS off: " << opt.mdnsHostname << " can only point to HTTP port 80 (use --http-port 80 to act as a failover for it)" << std::endl;
  }

  const uint32_t start = nowMillis();
  while (!g_stop) {
    const uint32_t now = nowMillis() - start;
    host.pollInput(now);   // serial first: the HTTP side then serves the freshest state
    device.loop(now, 4000);
    host.pumpOutput(now);  // commands queued by HTTP requests go out in the same iteration
    host.wait(2);
  }
  logMsg("shutting down");
  device.end();
  host.shutdown();
  return 0;
}
