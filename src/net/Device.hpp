#pragma once

// The portable device core. It owns the HTTP server, the UDP discovery socket, the
// shared mDNS record, the peer table, the skeleton store and the secure transport, and
// ties them to a ProtocolAdapter (the host program's components). The ESP32 firmware
// (esp/client.cpp) and the PC simulator run exactly this code; only the platform
// services below and the adapter differ.
//
// loop() is cooperative and bounded: it never blocks (no delay(), no blocking sockets)
// and stops after the time budget, so it can live inside another program's loop().

#include "../protocol/CryptoBackend.hpp"
#include "../protocol/Http.hpp"
#include "../protocol/Peers.hpp"
#include "../protocol/Protocol.hpp"
#include "../protocol/RateLimiter.hpp"
#include "../protocol/SecureTransport.hpp"
#include "../protocol/SkeletonStore.hpp"
#include "Net.hpp"

#include <string>

namespace Escape {

// What the platform has to tell the core about its network.
class DevicePlatform {
public:
  virtual ~DevicePlatform() {}
  // Address of this device in host byte order; 0 while the network is down.
  virtual uint32_t localIp() = 0;
  // Directed broadcast address of the local network (e.g. 192.168.1.255).
  virtual uint32_t broadcastIp() = 0;
};

struct DeviceOptions {
  std::string did;                 // 12 lowercase hex characters
  uint16_t httpPort;
  uint16_t udpPort;
  uint16_t mdnsPort;               // 0 disables the shared mDNS record
  std::string mdnsHostname;        // e.g. "escapemanager.local"
  uint32_t bootCounter;            // persistent boot counter (monotonic across boots)
  const uint8_t *uiData;           // gzipped manager.html in flash, may be null
  size_t uiLength;
  DeviceOptions() : httpPort(EscapeConfig::HTTP_PORT), udpPort(EscapeConfig::UDP_PORT), mdnsPort(5353),
                    mdnsHostname(std::string(EscapeConfig::MDNS_HOSTNAME) + ".local"), bootCounter(1),
                    uiData(nullptr), uiLength(0) {}
};

class Device : public HttpHandler {
public:
  Device(EscapeProtocol::ProtocolAdapter &host, CryptoBackend &crypto, BlobStorage &skeletonStorage,
         DevicePlatform &platform);

  // Derives the keys (once, ~230 ms on an ESP32), loads stored skeletons and opens the
  // sockets. Returns false if the HTTP port cannot be opened.
  bool begin(const DeviceOptions &options, const std::string &token, TokenState tokenState);
  void end();

  // Runs one bounded slice of work. `budgetMicros` limits the time spent in the HTTP
  // server; everything else is a handful of small operations.
  void loop(uint32_t nowMs, uint32_t budgetMicros = 4000);

  // Observable state changed: bump `seq` and announce soon.
  void markDirty();
  // Rooms may have changed: drop skeletons of rooms without a local component.
  void hostedRoomsChanged();

  uint32_t seq() const { return seq_; }
  const PeerTable &peers() const { return peers_; }
  SkeletonStore &store() { return store_; }
  SecureTransport &transport() { return transport_; }
  const std::string &did() const { return options_.did; }
  uint32_t announcementsSent() const { return announcementsSent_; }
  bool syncInFlight() const { return client_.busy(); }

  // HttpHandler
  RouteInfo route(Method method, const std::string &path) override;
  void handle(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response) override;

private:
  struct SyncRequest {
    bool pending;
    uint32_t ip;
    uint16_t port;
    uint32_t roomKey;
    std::string room;
    std::string did;
    SyncRequest() : pending(false), ip(0), port(0), roomKey(0) {}
  };

  EscapeProtocol::DeviceInfo deviceInfo() const;
  void handleGet(const HttpRequest &request, HttpResponse &response);
  void handlePost(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response);
  void sendDocument(const HttpRequest &request, const std::string &path, int status, const std::string &doc,
                    HttpResponse &response);
  void plainError(HttpResponse &response, int status, const char *code, const char *text);
  void serveUi(const HttpRequest &request, HttpResponse &response);

  void receiveAnnouncements(uint32_t nowMs);
  void maybeAnnounce(uint32_t nowMs);
  void considerSync(const Announcement &a, uint32_t nowMs);
  void pumpSync(uint32_t nowMs);
  void serviceMdns(uint32_t nowMs);

  EscapeProtocol::ProtocolAdapter &host_;
  CryptoBackend &crypto_;
  DevicePlatform &platform_;
  SecureTransport transport_;
  SkeletonStore store_;
  PeerTable peers_;
  RateLimiter limiter_;
  HttpServer server_;
  UdpSocket udp_;
  UdpSocket mdns_;
  HttpClient client_;
  DeviceOptions options_;
  uint8_t didBytes_[6];
  bool begun_;

  uint32_t nowMs_;
  uint32_t seq_;
  uint32_t ctr_;
  bool dirty_;
  uint32_t lastAnnounceMs_;
  uint32_t jitterMs_;
  uint32_t announcementsSent_;

  SyncRequest sync_;
  SyncRequest syncActive_;
  std::string syncNonce_;
  uint32_t syncFailMs_;
  uint32_t syncFailRoomKey_;
  uint32_t syncFailIp_;
  bool syncHasFailure_;

  uint32_t mdnsIp_;
  bool mdnsAnswerPending_;
  uint32_t mdnsAnswerAtMs_;
};

} // namespace Escape
