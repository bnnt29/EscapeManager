#pragma once

// Non-blocking network building blocks on BSD sockets. The same code runs on the
// ESP32 (lwIP via the IDF/Arduino socket API) and on the PC (POSIX), so the HTTP
// server, the peer client and the UDP/mDNS sockets are shared by the firmware and the
// simulators and can be tested on the PC.
//
// Nothing here blocks: every poll() does a bounded amount of work and returns, which
// keeps the host program's loop() responsive (the library's main design constraint).
// IPv4 addresses are `uint32_t` in HOST byte order (a<<24 | b<<16 | c<<8 | d).

#include "../protocol/Http.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace Escape {

// ---- UDP -----------------------------------------------------------------------------

class UdpSocket {
public:
  UdpSocket() : fd_(-1) {}
  ~UdpSocket() { close(); }
  UdpSocket(const UdpSocket &) = delete;
  UdpSocket &operator=(const UdpSocket &) = delete;

  // Listens on `port` (all interfaces) and may send broadcasts. Several processes
  // (e.g. simulators on one PC) can share the port.
  bool openBroadcast(uint16_t port);
  // Joins the multicast group on the interface with address `interfaceIp` (0 = default)
  // and listens on `port`; used for mDNS (224.0.0.251:5353).
  bool openMulticast(uint16_t port, uint32_t group, uint32_t interfaceIp);
  // Re-joins the group after a network change (Wi-Fi reconnect). No-op for other sockets.
  bool rejoin(uint32_t group, uint32_t interfaceIp);
  void close();
  bool isOpen() const { return fd_ >= 0; }

  // >0: bytes received, 0: nothing pending, <0: error.
  int receive(uint8_t *buffer, size_t capacity, uint32_t &sourceIp, uint16_t &sourcePort);
  bool send(uint32_t destinationIp, uint16_t destinationPort, const uint8_t *data, size_t length);

private:
  int fd_;
};

// ---- HTTP server -----------------------------------------------------------------------

struct RouteInfo {
  bool found;
  size_t maxBody; // bytes of body the route accepts (0 for GET routes)
};

class HttpHandler {
public:
  virtual ~HttpHandler() {}
  // Called as soon as the request headers are complete, before any body byte is
  // buffered, so oversized bodies are refused cheaply.
  virtual RouteInfo route(Method method, const std::string &path) = 0;
  // Called with the complete request. May take a few milliseconds (crypto) but must not block.
  virtual void handle(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response) = 0;
};

class HttpServer {
public:
  HttpServer();
  ~HttpServer();
  HttpServer(const HttpServer &) = delete;
  HttpServer &operator=(const HttpServer &) = delete;

  bool begin(uint16_t port, HttpHandler *handler);
  void end();
  bool running() const { return listenFd_ >= 0; }

  // One bounded pass: accept at most one connection, then give each active connection a
  // small slice of I/O. Stops early once `budgetMicros` is used up. Returns the number
  // of connections that are still active.
  size_t poll(uint32_t nowMs, uint32_t budgetMicros);

  size_t activeConnections() const;

private:
  struct Connection;
  void accept(uint32_t nowMs);
  bool step(Connection &c, uint32_t nowMs);
  void respond(Connection &c, HttpResponse &r);
  void closeConnection(Connection &c);

  int listenFd_;
  HttpHandler *handler_;
  Connection *connections_;
};

// ---- HTTP client (device-to-device sync) --------------------------------------------------

class HttpClient {
public:
  enum class State { Idle, Connecting, Sending, ReceivingHead, ReceivingBody, Done, Failed };

  HttpClient() : fd_(-1), state_(State::Idle), status_(0), deadlineMs_(0), maxBody_(0), sent_(0), contentLength_(0) {}
  ~HttpClient() { abort(); }
  HttpClient(const HttpClient &) = delete;
  HttpClient &operator=(const HttpClient &) = delete;

  // Starts `GET target` against ip:port. The whole exchange must finish within
  // timeoutMs and the body may not exceed maxBody (a Content-Length is required).
  bool begin(uint32_t ip, uint16_t port, const std::string &target, uint32_t nowMs, uint32_t timeoutMs, size_t maxBody);
  // Advances the exchange by a bounded amount of work.
  void poll(uint32_t nowMs);
  void abort();

  State state() const { return state_; }
  bool finished() const { return state_ == State::Done || state_ == State::Failed; }
  bool busy() const { return state_ != State::Idle && !finished(); }
  int status() const { return status_; }
  const std::string &body() const { return body_; }

private:
  void fail();

  int fd_;
  State state_;
  int status_;
  uint32_t deadlineMs_;
  size_t maxBody_;
  std::string request_;
  size_t sent_;
  std::string head_;
  std::string body_;
  size_t contentLength_;
};

// Formats ip as "a.b.c.d".
std::string ipToString(uint32_t ip);

} // namespace Escape
