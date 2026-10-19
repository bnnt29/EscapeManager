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
#include "../protocol/EscapeVersion.hpp"
#include "../protocol/Http.hpp"
#include "../protocol/Peers.hpp"
#include "../protocol/Protocol.hpp"
#include "../protocol/RateLimiter.hpp"
#include "../protocol/SecureTransport.hpp"
#include "../protocol/Setup.hpp"
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
  // True while the device runs its own setup network (access point, ESP32 only): the HTTP server then
  // also has to run although the station has no address, and DNS answers for the portal.
  virtual bool setupNetworkUp() { return false; }
  // True if `ip` belongs to a client of the setup network. Those clients only ever see the setup portal.
  virtual bool isSetupClient(uint32_t ip) { (void)ip; return false; }
};

struct DeviceOptions {
  std::string did;                 // 12 lowercase hex characters
  uint16_t httpPort;
  uint16_t udpPort;
  uint16_t mdnsPort;               // 0 disables the shared mDNS record
  uint16_t dnsPort;                // captive-portal DNS while the setup network is up (0 disables)
  std::string mdnsHostname;        // e.g. "escapemanager.local"
  uint32_t bootCounter;            // persistent boot counter (monotonic across boots)
  const uint8_t *uiData;           // manager.html (gzipped by default), may be null
  size_t uiLength;
  bool uiGzip;                     // uiData is gzip-compressed
  std::string uiHash;              // 8 hex chars; defaults to the firmware's embedded UI hash
  const uint8_t *setupData;        // tools/setup/setup.html (gzipped), may be null
  size_t setupLength;
  std::string setupHash;           // etag for the setup page; defaults to the UI hash
  DeviceOptions() : httpPort(EscapeConfig::HTTP_PORT), udpPort(EscapeConfig::UDP_PORT), mdnsPort(5353),
                    dnsPort((uint16_t)EscapeConfig::SETUP_DNS_PORT),
                    mdnsHostname(std::string(EscapeConfig::MDNS_HOSTNAME) + ".local"), bootCounter(1),
                    uiData(nullptr), uiLength(0), uiGzip(true), uiHash(EscapeVersion::UI_HASH),
                    setupData(nullptr), setupLength(0), setupHash(EscapeVersion::UI_HASH) {}
};

class Device : public HttpHandler {
public:
  Device(EscapeProtocol::ProtocolAdapter &host, CryptoBackend &crypto, BlobStorage &skeletonStorage,
         DevicePlatform &platform);

  // Derives the keys (once, ~250 ms on an ESP32) and loads stored skeletons. The sockets are
  // opened right away if the network is already up; otherwise on the first loop() after it came
  // up (on the ESP32 the very first socket() call blocks for ~350 ms while the Wi-Fi/lwIP stack
  // is still starting, and 1 ms once the link is up). Returns false only if the network is up
  // and the HTTP port cannot be opened.
  // The edit token (PROTOCOL.md 3.1) is optional; with EditState::Custom a second key set is derived
  // (another ~250 ms on an ESP32).
  bool begin(const DeviceOptions &options, const std::string &token, TokenState tokenState,
             const std::string &editToken = std::string(), EditState editState = EditState::Unset);
  void end();

  // Platform services for POST /setup and the setup portal (persisting Wi-Fi and tokens). Optional:
  // without a sink the device does not advertise the "setup" capability. Call before begin().
  void setSetupSink(SetupSink *sink) { sink_ = sink; }

  // Runs one bounded slice of work. `budgetMicros` limits the time spent in the HTTP
  // server; everything else is a handful of small operations.
  void loop(uint32_t nowMs, uint32_t budgetMicros = 4000);

  // Observable state changed (called by the protocol handlers after a command): bump `seq` and
  // announce soon.
  void markDirty();
  // The host program says "something MAY have changed". Safe to call at any rate (a flag, nothing
  // else): at most every HOST_CHANGE_CHECK_MS the state is fingerprinted and `seq` is bumped only
  // if it really differs from the last announced state.
  void hostChanged() { hostDirty_ = true; }
  // Rooms may have changed: drop skeletons of rooms without a local component.
  void hostedRoomsChanged();

  uint32_t seq() const { return seq_; }
  const PeerTable &peers() const { return peers_; }
  SkeletonStore &store() { return store_; }
  SecureTransport &transport() { return transport_; }
  const std::string &did() const { return options_.did; }
  uint32_t announcementsSent() const { return announcementsSent_; }
  bool syncInFlight() const { return client_.busy(); }
  // True while the HTTP port could not be opened (another server on that port?); retried every 5 s.
  bool httpPortFailed() const { return socketsFailed_; }
  bool socketsOpen() const { return server_.running(); }

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
  void handleSetupClient(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response);
  void serveEditProof(const HttpRequest &request, HttpResponse &response);
  void reloadTokens();
  void serviceDns(uint32_t nowMs);
  std::string deviceLabel() const;
  void sendDocument(const HttpRequest &request, const std::string &path, int status, const std::string &doc,
                    HttpResponse &response);
  void plainError(HttpResponse &response, int status, const char *code, const char *text);
  void serveUi(const HttpRequest &request, HttpResponse &response);
  void serveSetupPage(const HttpRequest &request, HttpResponse &response);

  void receiveAnnouncements(uint32_t nowMs);
  void maybeAnnounce(uint32_t nowMs);
  void considerSync(const Announcement &a, uint32_t nowMs);
  void pumpSync(uint32_t nowMs);
  void serviceMdns(uint32_t nowMs);
  bool openSockets();
  void checkHostChange(uint32_t nowMs);

  EscapeProtocol::ProtocolAdapter &host_;
  CryptoBackend &crypto_;
  DevicePlatform &platform_;
  SecureTransport transport_;
  SkeletonStore store_;
  PeerTable peers_;
  RateLimiter limiter_;     // POSTs
  RateLimiter udpLimiter_;  // discovery datagrams: a spoofed flood must not use up a manager's POST budget
  HttpServer server_;
  UdpSocket udp_;
  UdpSocket mdns_;
  UdpSocket dns_;
  HttpClient client_;
  SetupSink *sink_;
  bool dnsTried_;
  DeviceOptions options_;
  uint8_t didBytes_[6];
  bool begun_;
  bool socketsFailed_;
  // Deadlines are only valid while their `armed` flag is set. A magic initial value such as 0 breaks
  // the signed comparison whenever the 32-bit clock is in its upper half (found on hardware).
  bool socketBackoff_;
  uint32_t nextSocketAttemptMs_;

  bool hostDirty_;
  bool haveFingerprint_;
  uint32_t fingerprint_;
  bool hostCheckArmed_;
  uint32_t nextHostCheckMs_;

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
