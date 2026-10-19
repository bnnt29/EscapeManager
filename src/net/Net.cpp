// Implementation of Net.hpp. BSD socket API only, so it compiles for lwIP (ESP32) and POSIX.

#include "Net.hpp"

#include "../protocol/Compat.hpp"
#include "../protocol/Json.hpp"
#include "Clock.hpp"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(ARDUINO) && defined(ESCAPE_NET_TRACE)
#include <Arduino.h>
#define TRACE(...) Serial.printf(__VA_ARGS__)
#else
#define TRACE(...)
#endif
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

namespace Escape {

namespace {

bool setNonBlocking(int fd) {
  const int flags = fcntl(fd, F_GETFL, 0);
  return flags >= 0 && fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

bool wouldBlock(int e) { return e == EAGAIN || e == EWOULDBLOCK || e == EINTR; }

sockaddr_in makeAddress(uint32_t ip, uint16_t port) {
  sockaddr_in a;
  memset(&a, 0, sizeof(a));
  a.sin_family = AF_INET;
  a.sin_addr.s_addr = htonl(ip);
  a.sin_port = htons(port);
  return a;
}

const size_t kSendSlice = 2920;  // bytes written per connection per poll
const size_t kRecvSlice = 768;   // bytes read per connection per poll

bool headerValue(const std::string &head, const char *name, std::string &out) {
  // Case-insensitive search of "\r\n<name>:" in the header block.
  const size_t nameLen = strlen(name);
  size_t pos = 0;
  while ((pos = head.find("\r\n", pos)) != std::string::npos) {
    pos += 2;
    if (head.size() - pos < nameLen + 1) break;
    bool match = true;
    for (size_t i = 0; i < nameLen; i++) {
      char a = head[pos + i], b = name[i];
      if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
      if (b >= 'A' && b <= 'Z') b = (char)(b + 32);
      if (a != b) { match = false; break; }
    }
    if (!match || head[pos + nameLen] != ':') continue;
    size_t v = pos + nameLen + 1;
    while (v < head.size() && (head[v] == ' ' || head[v] == '\t')) v++;
    const size_t end = head.find("\r\n", v);
    out = head.substr(v, end == std::string::npos ? std::string::npos : end - v);
    return true;
  }
  return false;
}

} // namespace

std::string ipToString(uint32_t ip) {
  char text[16];
  size_t o = 0;
  for (int part = 0; part < 4; part++) {
    const unsigned v = (ip >> (24 - 8 * part)) & 0xFF;
    if (v >= 100) text[o++] = (char)('0' + v / 100);
    if (v >= 10) text[o++] = (char)('0' + (v / 10) % 10);
    text[o++] = (char)('0' + v % 10);
    if (part < 3) text[o++] = '.';
  }
  text[o] = '\0';
  return std::string(text);
}

// ---- UdpSocket ---------------------------------------------------------------------------

bool UdpSocket::openBroadcast(uint16_t port) {
  close();
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) return false;
  const int on = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
  setsockopt(fd_, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on));
  sockaddr_in a = makeAddress(0, port);
  if (bind(fd_, (sockaddr *)&a, sizeof(a)) != 0 || !setNonBlocking(fd_)) {
    close();
    return false;
  }
  return true;
}

bool UdpSocket::openPlain(uint16_t port) {
  close();
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) return false;
  const int on = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in a = makeAddress(0, port);
  if (bind(fd_, (sockaddr *)&a, sizeof(a)) != 0 || !setNonBlocking(fd_)) {
    close();
    return false;
  }
  return true;
}

bool UdpSocket::openMulticast(uint16_t port, uint32_t group, uint32_t interfaceIp) {
  close();
  fd_ = socket(AF_INET, SOCK_DGRAM, 0);
  if (fd_ < 0) return false;
  const int on = 1;
  setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
#ifdef SO_REUSEPORT
  setsockopt(fd_, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on));
#endif
  sockaddr_in a = makeAddress(0, port);
  if (bind(fd_, (sockaddr *)&a, sizeof(a)) != 0 || !setNonBlocking(fd_)) {
    close();
    return false;
  }
  if (!rejoin(group, interfaceIp)) {
    close();
    return false;
  }
  const int ttl = 255;
  setsockopt(fd_, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));
  if (interfaceIp) {
    in_addr iface;
    iface.s_addr = htonl(interfaceIp);
    setsockopt(fd_, IPPROTO_IP, IP_MULTICAST_IF, &iface, sizeof(iface));
  }
  return true;
}

bool UdpSocket::rejoin(uint32_t group, uint32_t interfaceIp) {
  if (fd_ < 0) return false;
  ip_mreq mreq;
  memset(&mreq, 0, sizeof(mreq));
  mreq.imr_multiaddr.s_addr = htonl(group);
  mreq.imr_interface.s_addr = htonl(interfaceIp);
  setsockopt(fd_, IPPROTO_IP, IP_DROP_MEMBERSHIP, &mreq, sizeof(mreq)); // ignore: may not be a member yet
  return setsockopt(fd_, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq)) == 0;
}

void UdpSocket::close() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
}

int UdpSocket::receive(uint8_t *buffer, size_t capacity, uint32_t &sourceIp, uint16_t &sourcePort) {
  if (fd_ < 0) return -1;
  sockaddr_in from;
  socklen_t len = sizeof(from);
  const ssize_t n = recvfrom(fd_, buffer, capacity, 0, (sockaddr *)&from, &len);
  if (n < 0) return wouldBlock(errno) ? 0 : -1;
  sourceIp = ntohl(from.sin_addr.s_addr);
  sourcePort = ntohs(from.sin_port);
  return (int)n;
}

bool UdpSocket::send(uint32_t destinationIp, uint16_t destinationPort, const uint8_t *data, size_t length) {
  if (fd_ < 0) return false;
  sockaddr_in to = makeAddress(destinationIp, destinationPort);
  return sendto(fd_, data, length, MSG_NOSIGNAL, (sockaddr *)&to, sizeof(to)) == (ssize_t)length;
}

// ---- HttpServer -------------------------------------------------------------------------------

struct HttpServer::Connection {
  enum class Phase { Free, Reading, Writing, Draining };
  int fd;
  Phase phase;
  uint32_t startMs, lastMs, remoteIp, drainStartMs;
  size_t drained;
  uint32_t tReq, tHandled, tSent;
  bool continueSent, headOnly, gotBytes;
  HttpRequestParser parser;
  std::string head, body;
  const uint8_t *staticBody;
  size_t staticLength, sentHead, sentBody;

  Connection() : fd(-1), phase(Phase::Free), startMs(0), lastMs(0), remoteIp(0), drainStartMs(0), drained(0), tReq(0), tHandled(0), tSent(0), continueSent(false), headOnly(false), gotBytes(false),
                 staticBody(nullptr), staticLength(0), sentHead(0), sentBody(0) {}
  void reset() {
    fd = -1;
    phase = Phase::Free;
    continueSent = headOnly = gotBytes = false;
    drained = 0;
    parser.reset();
    head.clear();
    std::string().swap(body); // release the memory of large bodies
    staticBody = nullptr;
    staticLength = sentHead = sentBody = 0;
  }
};

HttpServer::HttpServer() : listenFd_(-1), handler_(nullptr), connections_(nullptr) {}

HttpServer::~HttpServer() { end(); }

bool HttpServer::begin(uint16_t port, HttpHandler *handler) {
  end();
  handler_ = handler;
  listenFd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (listenFd_ < 0) return false;
  const int on = 1;
  setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));
  sockaddr_in a = makeAddress(0, port);
  if (bind(listenFd_, (sockaddr *)&a, sizeof(a)) != 0 || listen(listenFd_, EscapeConfig::HTTP_LISTEN_BACKLOG) != 0 || !setNonBlocking(listenFd_)) {
    ::close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  connections_ = Escape::guardAlloc([&]() -> Connection * { return new Connection[EscapeConfig::MAX_HTTP_CONNECTIONS]; }, (Connection *)nullptr);
  if (!connections_) {
    ::close(listenFd_);
    listenFd_ = -1;
    return false;
  }
  return true;
}

void HttpServer::end() {
  if (connections_) {
    for (size_t i = 0; i < EscapeConfig::MAX_HTTP_CONNECTIONS; i++) {
      if (connections_[i].fd >= 0) closeConnection(connections_[i]);
    }
    delete[] connections_;
    connections_ = nullptr;
  }
  if (listenFd_ >= 0) ::close(listenFd_);
  listenFd_ = -1;
}

size_t HttpServer::activeConnections() const {
  size_t n = 0;
  if (!connections_) return 0;
  for (size_t i = 0; i < EscapeConfig::MAX_HTTP_CONNECTIONS; i++) n += connections_[i].phase != Connection::Phase::Free ? 1 : 0;
  return n;
}

void HttpServer::closeConnection(Connection &c) {
  if (c.fd >= 0) ::close(c.fd);
  c.reset();
}

void HttpServer::accept(uint32_t nowMs) {
  // Pick a slot BEFORE accepting. A newcomer is only taken when there is room for it:
  //  * a free slot, or
  //  * a connection that no longer matters: a draining one (its response was already delivered, it only
  //    swallows the rest of a rejected body) or the oldest SILENT one (browsers open speculative
  //    connections that never send a byte). A fresh connection is silent for the few milliseconds before
  //    its request arrives, so only connections silent for HTTP_EVICT_SILENT_AFTER_MS qualify.
  // Connections that sent part of a request (or are still answering one) are never evicted. When every
  // slot is busy with real work the newcomer is NOT accepted: it waits in the listen backlog (a short
  // delay for the client) instead of being answered with an error - and closing an accepted connection
  // whose request bytes are unread would reset it, which can destroy even that error reply.
  Connection *slot = nullptr, *draining = nullptr, *silent = nullptr;
  for (size_t i = 0; i < EscapeConfig::MAX_HTTP_CONNECTIONS; i++) {
    Connection &c = connections_[i];
    if (c.phase == Connection::Phase::Free) { slot = &c; break; }
    if (c.phase == Connection::Phase::Draining && (!draining || (int32_t)(draining->drainStartMs - c.drainStartMs) > 0)) draining = &c;
    if (c.phase == Connection::Phase::Reading && !c.gotBytes && nowMs - c.startMs >= EscapeConfig::HTTP_EVICT_SILENT_AFTER_MS &&
        (!silent || (int32_t)(silent->startMs - c.startMs) > 0)) silent = &c;
  }
  Connection *evictable = draining ? draining : silent;
  if (!slot && !evictable) return;

  sockaddr_in from;
  socklen_t len = sizeof(from);
  const int fd = ::accept(listenFd_, (sockaddr *)&from, &len);
  if (fd < 0) return;
  setNonBlocking(fd);
  // The response goes out in several chunks; without TCP_NODELAY a small trailing segment waits for the
  // client's delayed ACK (measured on an ESP32: worst request 1389 ms -> 332 ms).
  const int one = 1;
  setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
  if (!slot) {
    slot = evictable;
    closeConnection(*slot);
  }
  slot->reset();
  slot->fd = fd;
  slot->phase = Connection::Phase::Reading;
  slot->startMs = slot->lastMs = nowMs;
  slot->remoteIp = ntohl(from.sin_addr.s_addr);
}

void HttpServer::respond(Connection &c, HttpResponse &r) {
  const HttpRequest &req = c.parser.request();
  c.headOnly = req.method == Method::Head;
  const bool preflight = req.method == Method::Options;
  c.head = formatResponseHead(r, req.origin, preflight);
  c.body.swap(r.body);
  c.staticBody = r.staticBody;
  c.staticLength = r.staticLength;
  c.sentHead = c.sentBody = 0;
  c.phase = Connection::Phase::Writing;
}

namespace {
const char *errorCodeFor(int status) {
  switch (status) {
    case 404: return "not_found";
    case 413: return "too_large";
    default: return "bad_request";
  }
}
} // namespace

bool HttpServer::step(Connection &c, uint32_t nowMs) {
  if (nowMs - c.startMs > EscapeConfig::HTTP_REQUEST_TIMEOUT_MS) return false;

  if (c.phase == Connection::Phase::Reading) {
    if (nowMs - c.lastMs > EscapeConfig::HTTP_IDLE_TIMEOUT_MS) return false;
    uint8_t buf[kRecvSlice];
    const ssize_t n = recv(c.fd, buf, sizeof(buf), 0);
    if (n == 0) return false;                  // peer closed before sending a full request
    if (n < 0) return wouldBlock(errno);
    c.lastMs = nowMs;
    c.gotBytes = true;
    size_t pos = 0;
    while (pos < (size_t)n && c.phase == Connection::Phase::Reading) {
      const size_t used = c.parser.feed(buf + pos, (size_t)n - pos);
      pos += used;
      HttpResponse response;
      if (c.parser.state() == HttpRequestParser::State::HeadersComplete) {
        const HttpRequest &req = c.parser.request();
        if (req.method == Method::Options) {
          response.status = 204;
          c.parser.beginBody(0);
          respond(c, response);
          break;
        }
        const RouteInfo route = handler_->route(req.method == Method::Head ? Method::Get : req.method, req.path);
        if (!route.found) {
          c.parser.fail(404);
        } else {
          c.parser.beginBody(route.maxBody);
          if (c.parser.state() == HttpRequestParser::State::Body && req.expectContinue && !c.continueSent) {
            static const char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";
            send(c.fd, cont, sizeof(cont) - 1, MSG_NOSIGNAL);
            c.continueSent = true;
          }
        }
      }
      if (c.parser.state() == HttpRequestParser::State::Done) {
        c.tReq = nowMs;
        response.contentType = "application/json";
        const uint32_t h0 = nowMicros();
        handler_->handle(c.parser.request(), c.remoteIp, response);
        c.tHandled = (nowMicros() - h0) / 1000;
        respond(c, response);
      } else if (c.parser.state() == HttpRequestParser::State::Error) {
        const int status = c.parser.errorStatus();
        response.status = status;
        response.contentType = "application/json";
        response.body = "{\"ok\":false,\"code\":\"" + std::string(errorCodeFor(status)) + "\",\"error\":\"" + statusText(status) + "\"}";
        respond(c, response);
      } else if (used == 0) {
        break;
      }
    }
  }

  if (c.phase == Connection::Phase::Writing) {
    size_t budget = kSendSlice;
    while (budget && c.sentHead < c.head.size()) {
      const size_t want = c.head.size() - c.sentHead < budget ? c.head.size() - c.sentHead : budget;
      const ssize_t n = send(c.fd, c.head.data() + c.sentHead, want, MSG_NOSIGNAL);
      if (n < 0) return wouldBlock(errno);
      c.sentHead += (size_t)n;
      budget -= (size_t)n;
    }
    if (c.sentHead < c.head.size()) return true;
    const uint8_t *data = c.staticBody ? c.staticBody : (const uint8_t *)c.body.data();
    const size_t total = c.headOnly ? 0 : (c.staticBody ? c.staticLength : c.body.size());
    while (budget && c.sentBody < total) {
      const size_t want = total - c.sentBody < budget ? total - c.sentBody : budget;
      const ssize_t n = send(c.fd, data + c.sentBody, want, MSG_NOSIGNAL);
      if (n < 0) return wouldBlock(errno);
      c.sentBody += (size_t)n;
      budget -= (size_t)n;
    }
    if (c.sentBody >= total) {
      TRACE("[http] %s total %lu ms | request read %lu ms | handler %lu ms | sending %lu ms | %lu B\n", c.parser.request().path.c_str(), (unsigned long)(nowMs - c.startMs), (unsigned long)(c.tReq - c.startMs), (unsigned long)c.tHandled, (unsigned long)(nowMs - c.tReq - c.tHandled), (unsigned long)total);
      if (c.parser.state() == HttpRequestParser::State::Done) return false; // everything was read: just close
      // The request was rejected before its body arrived. Closing now would reset the
      // connection while the client is still sending, and the reset can destroy the
      // response in flight. Half-close, then swallow the rest briefly.
      shutdown(c.fd, SHUT_WR);
      c.phase = Connection::Phase::Draining;
      c.drainStartMs = nowMs;
      return true;
    }
  }

  if (c.phase == Connection::Phase::Draining) {
    uint8_t sink[256];
    const ssize_t n = recv(c.fd, sink, sizeof(sink), 0);
    if (n == 0) return false;
    if (n > 0) c.drained += (size_t)n;
    else if (!wouldBlock(errno)) return false;
    return c.drained < EscapeConfig::MAX_BODY_BYTES * 4 && nowMs - c.drainStartMs < 1500;
  }
  return true;
}

size_t HttpServer::poll(uint32_t nowMs, uint32_t budgetMicros) {
  if (listenFd_ < 0 || !connections_) return 0;
  const uint32_t start = nowMicros();
  accept(nowMs);
  static size_t rotate = 0; // start each pass at a different connection so none starves
  rotate++;
  size_t active = 0;
  for (size_t k = 0; k < EscapeConfig::MAX_HTTP_CONNECTIONS; k++) {
    Connection &c = connections_[(k + rotate) % EscapeConfig::MAX_HTTP_CONNECTIONS];
    if (c.phase == Connection::Phase::Free) continue;
    if (!step(c, nowMs)) closeConnection(c);
    else active++;
    if (nowMicros() - start > budgetMicros) break;
  }
  return active;
}

// ---- HttpClient -------------------------------------------------------------------------------

bool HttpClient::begin(uint32_t ip, uint16_t port, const std::string &target, uint32_t nowMs, uint32_t timeoutMs,
                       size_t maxBody) {
  abort();
  body_.clear();
  head_.clear();
  status_ = 0;
  sent_ = 0;
  contentLength_ = 0;
  maxBody_ = maxBody;
  deadlineMs_ = nowMs + timeoutMs;
  fd_ = socket(AF_INET, SOCK_STREAM, 0);
  if (fd_ < 0 || fd_ >= FD_SETSIZE || !setNonBlocking(fd_)) {
    fail();
    return false;
  }
  sockaddr_in a = makeAddress(ip, port);
  const int rc = connect(fd_, (sockaddr *)&a, sizeof(a));
  if (rc != 0 && errno != EINPROGRESS && !wouldBlock(errno)) {
    fail();
    return false;
  }
  request_ = Escape::guardAlloc([&]() -> std::string {
    return "GET " + target + " HTTP/1.1\r\nHost: " + ipToString(ip) + "\r\nAccept: application/json\r\nConnection: close\r\n\r\n";
  }, std::string());
  if (request_.empty()) {
    fail();
    return false;
  }
  state_ = rc == 0 ? State::Sending : State::Connecting;
  return true;
}

void HttpClient::fail() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  state_ = State::Failed;
}

void HttpClient::abort() {
  if (fd_ >= 0) ::close(fd_);
  fd_ = -1;
  state_ = State::Idle;
}

void HttpClient::poll(uint32_t nowMs) {
  if (state_ == State::Idle || finished()) return;
  if ((int32_t)(nowMs - deadlineMs_) > 0) return fail();

  if (state_ == State::Connecting) {
    fd_set w;
    FD_ZERO(&w);
    FD_SET(fd_, &w);
    timeval tv = {0, 0};
    const int r = select(fd_ + 1, nullptr, &w, nullptr, &tv);
    if (r < 0) return fail();
    if (r == 0) return; // still connecting
    int err = 0;
    socklen_t len = sizeof(err);
    if (getsockopt(fd_, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) return fail();
    state_ = State::Sending;
  }
  if (state_ == State::Sending) {
    const ssize_t n = send(fd_, request_.data() + sent_, request_.size() - sent_, MSG_NOSIGNAL);
    if (n < 0) {
      if (!wouldBlock(errno)) fail();
      return;
    }
    sent_ += (size_t)n;
    if (sent_ < request_.size()) return;
    state_ = State::ReceivingHead;
  }
  uint8_t buf[1024];
  if (state_ == State::ReceivingHead || state_ == State::ReceivingBody) {
    const ssize_t n = recv(fd_, buf, sizeof(buf), 0);
    if (n < 0) {
      if (!wouldBlock(errno)) fail();
      return;
    }
    if (n == 0) { // peer closed: fine only if the body is complete
      if (state_ == State::ReceivingBody && body_.size() == contentLength_) { ::close(fd_); fd_ = -1; state_ = State::Done; }
      else fail();
      return;
    }
    const bool ok = Escape::guardAlloc([&]() -> bool {
      if (state_ == State::ReceivingHead) {
        head_.append((const char *)buf, (size_t)n);
        const size_t end = head_.find("\r\n\r\n");
        if (end == std::string::npos) return head_.size() <= EscapeConfig::MAX_HEADER_BYTES;
        body_ = head_.substr(end + 4);
        head_.resize(end + 2); // keep the final CRLF so header search works
        if (head_.compare(0, 9, "HTTP/1.1 ") != 0 && head_.compare(0, 9, "HTTP/1.0 ") != 0) return false;
        status_ = atoi(head_.c_str() + 9);
        std::string length;
        if (!headerValue(head_, "content-length", length) || length.empty() || length.size() > 9) return false;
        contentLength_ = 0;
        for (size_t i = 0; i < length.size(); i++) {
          if (length[i] < '0' || length[i] > '9') return false;
          contentLength_ = contentLength_ * 10 + (size_t)(length[i] - '0');
        }
        if (contentLength_ > maxBody_) return false;
        state_ = State::ReceivingBody;
      } else {
        body_.append((const char *)buf, (size_t)n);
      }
      return body_.size() <= contentLength_;
    }, false);
    if (!ok) return fail();
    if (state_ == State::ReceivingBody && body_.size() == contentLength_) {
      ::close(fd_);
      fd_ = -1;
      state_ = State::Done;
    }
  }
}

} // namespace Escape
