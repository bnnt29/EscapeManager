#include "Device.hpp"

#include "../protocol/Base64Url.hpp"
#include "../protocol/Compat.hpp"
#include "../protocol/EscapeVersion.hpp"
#include "../protocol/Mdns.hpp"
#include "Clock.hpp"

#include <cstring>

namespace Escape {

namespace {

const uint32_t kMdnsGroup = 0xE00000FBu; // 224.0.0.251

bool eqPath(const std::string &a, const char *b) { return a == b; }

std::string urlEncode(const std::string &s) {
  static const char kHex[] = "0123456789ABCDEF";
  std::string out;
  for (size_t i = 0; i < s.size(); i++) {
    const unsigned char c = (unsigned char)s[i];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~') {
      out.push_back((char)c);
    } else {
      out.push_back('%');
      out.push_back(kHex[c >> 4]);
      out.push_back(kHex[c & 15]);
    }
  }
  return out;
}

} // namespace

Device::Device(EscapeProtocol::ProtocolAdapter &host, CryptoBackend &crypto, BlobStorage &skeletonStorage,
               DevicePlatform &platform)
    : host_(host), crypto_(crypto), platform_(platform), transport_(crypto), store_(skeletonStorage), begun_(false),
      nowMs_(0), seq_(1), ctr_(0), dirty_(true), lastAnnounceMs_(0), jitterMs_(0), announcementsSent_(0),
      syncFailMs_(0), syncFailRoomKey_(0), syncFailIp_(0), syncHasFailure_(false), mdnsIp_(0),
      mdnsAnswerPending_(false), mdnsAnswerAtMs_(0) {
  memset(didBytes_, 0, sizeof(didBytes_));
}

bool Device::begin(const DeviceOptions &options, const std::string &token, TokenState tokenState) {
  end();
  options_ = options;
  if (!parseDid(options_.did.data(), options_.did.size(), didBytes_)) return false;
  transport_.begin(token, tokenState, options_.did);
  store_.load();
  store_.keepOnly(EscapeProtocol::hostedRooms(host_));
  uint8_t r[4];
  crypto_.randomBytes(r, sizeof(r));
  jitterMs_ = (((uint32_t)r[0] << 24 | (uint32_t)r[1] << 16 | (uint32_t)r[2] << 8 | r[3]) % (EscapeConfig::HEARTBEAT_JITTER_MS + 1));
  ctr_ = 0;
  seq_ = 1;
  dirty_ = true;
  if (!server_.begin(options_.httpPort, this)) return false;
  udp_.openBroadcast(options_.udpPort); // discovery is best effort: the HTTP side works without it
  begun_ = true;
  return true;
}

void Device::end() {
  server_.end();
  udp_.close();
  mdns_.close();
  client_.abort();
  begun_ = false;
}

void Device::markDirty() {
  seq_++;
  dirty_ = true;
}

void Device::hostedRoomsChanged() { store_.keepOnly(EscapeProtocol::hostedRooms(host_)); }

EscapeProtocol::DeviceInfo Device::deviceInfo() const {
  EscapeProtocol::DeviceInfo d;
  d.did = options_.did;
  d.uiHash = options_.uiHash;
  d.ip = ipToString(platform_.localIp());
  d.port = options_.httpPort;
  d.boot = options_.bootCounter;
  d.seq = seq_;
  d.nowMs = nowMs_;
  d.battery = host_.battery();
  d.token = transport_.tokenState();
  d.writable = transport_.writable();
  return d;
}

// ---- HTTP ------------------------------------------------------------------------------------

RouteInfo Device::route(Method method, const std::string &path) {
  if (method == Method::Get) {
    if (eqPath(path, "/") || eqPath(path, "/security.json") || eqPath(path, "/status.json") || eqPath(path, "/peers.json") ||
        eqPath(path, "/plan-skeleton.json") || eqPath(path, "/favicon.ico")) {
      return RouteInfo{true, 0};
    }
  } else if (method == Method::Post) {
    if (eqPath(path, "/action") || eqPath(path, "/plan-action") || eqPath(path, "/config") || eqPath(path, "/plan") ||
        eqPath(path, "/plan-skeleton")) {
      return RouteInfo{true, EscapeConfig::MAX_BODY_BYTES};
    }
  }
  return RouteInfo{false, 0};
}

void Device::plainError(HttpResponse &r, int status, const char *code, const char *text) {
  r.status = status;
  r.contentType = "application/json";
  r.body = EscapeProtocol::errorBody(code, text);
}

void Device::handle(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response) {
  response.contentType = "application/json";
  if (request.method == Method::Post) return handlePost(request, remoteIp, response);
  handleGet(request, response);
}

void Device::serveUi(const HttpRequest &request, HttpResponse &response) {
  if (!options_.uiData || !options_.uiLength) return plainError(response, 404, "not_found", "no embedded UI");
  response.contentType = "text/html; charset=utf-8";
  response.gzip = options_.uiGzip;
  response.etag = options_.uiHash;
  std::string inm = request.ifNoneMatch;
  if (inm.compare(0, 2, "W/") == 0) inm = inm.substr(2);
  if (inm == "\"" + response.etag + "\"") { // browser already has this build
    response.status = 304;
    response.gzip = false;
    return;
  }
  response.staticBody = options_.uiData;
  response.staticLength = options_.uiLength;
}

// Answers a GET with `doc`: authenticated frame when a nonce was sent, bare document
// otherwise (viewer mode, unless strict mode forbids it).
void Device::sendDocument(const HttpRequest &request, const std::string &path, int status, const std::string &doc,
                          HttpResponse &response) {
  if (doc.empty()) return plainError(response, 503, "busy", "out of memory, try again");
  std::string nonce;
  const bool hasNonce = queryParam(request.query, "nonce", nonce);
  if (!hasNonce) {
    if (EscapeConfig::STRICT_GET) return plainError(response, 401, "auth_required", "authenticated read required");
    response.status = status;
    response.body = doc;
    return;
  }
  std::string frame;
  if (!SecureTransport::validNonce(nonce)) return plainError(response, 400, "bad_request", "invalid nonce");
  if (!transport_.frameDocument(path, nonce, status, doc, frame)) {
    return plainError(response, 503, "read_only", "authenticated reads unavailable");
  }
  response.status = status;
  response.body.swap(frame);
}

void Device::handleGet(const HttpRequest &request, HttpResponse &response) {
  const std::string &path = request.path;
  if (path == "/") return serveUi(request, response);
  if (path == "/favicon.ico") { response.status = 204; return; }
  if (path == "/security.json") {
    response.body = EscapeProtocol::buildSecurityDoc(deviceInfo());
    if (response.body.empty()) plainError(response, 503, "busy", "out of memory, try again");
    return;
  }
  if (path == "/status.json") return sendDocument(request, path, 200, EscapeProtocol::buildStatusDoc(host_, deviceInfo()), response);
  if (path == "/peers.json") {
    return sendDocument(request, path, 200, EscapeProtocol::buildPeersDoc(peers_, deviceInfo(), store_.summaryHash()), response);
  }
  if (path == "/plan-skeleton.json") {
    std::string room;
    if (!queryParam(request.query, "room", room)) {
      return sendDocument(request, path, 200, EscapeProtocol::buildSkeletonIndexDoc(store_), response);
    }
    std::string blob;
    if (room.empty() || !store_.get(room, blob)) {
      return sendDocument(request, path, 404, EscapeProtocol::errorBody("no_plan", "no skeleton stored for this room"), response);
    }
    return sendDocument(request, path, 200, blob, response);
  }
  plainError(response, 404, "not_found", "unknown path");
}

void Device::handlePost(const HttpRequest &request, uint32_t remoteIp, HttpResponse &response) {
  if (!limiter_.allowGlobal(nowMs_) || !limiter_.allowSource(remoteIp, nowMs_)) {
    return plainError(response, 429, "rate_limited", "too many requests");
  }
  std::string plaintext, requestIv;
  const OpenResult opened = transport_.openRequest(request.path, request.body.data(), request.body.size(), nowMs_, plaintext, requestIv);

  EscapeProtocol::HttpResult result;
  if (opened.status != 200) {
    if (opened.status == 401) limiter_.allowSource(remoteIp, nowMs_, 3); // failed authentication costs extra
    std::string extra;
    if (std::string(opened.code) == "stale_time") extra = "\"time\":" + std::to_string(nowMs_);
    result = EscapeProtocol::errorResult(opened.status, opened.code, opened.code, extra);
    if (requestIv.empty() || !transport_.writable()) { // cannot be authenticated: plain
      response.status = result.status;
      response.body = result.body;
      return;
    }
  } else if (request.path == "/action") {
    result = EscapeProtocol::handleAction(host_, plaintext);
  } else if (request.path == "/plan-action") {
    result = EscapeProtocol::handlePlanAction(host_, plaintext);
  } else if (request.path == "/config") {
    result = EscapeProtocol::handleConfig(host_, plaintext);
    if (result.status == 200) hostedRoomsChanged();
  } else if (request.path == "/plan") {
    result = EscapeProtocol::handlePlan(host_, plaintext);
  } else {
    result = EscapeProtocol::handlePlanSkeleton(host_, store_, plaintext);
  }

  std::string sealed;
  if (!transport_.sealResponse(request.path, requestIv, result.status, result.body, sealed)) {
    return plainError(response, 503, "busy", "could not seal response");
  }
  response.status = result.status;
  response.body.swap(sealed);
}

// ---- UDP discovery ----------------------------------------------------------------------------

void Device::receiveAnnouncements(uint32_t nowMs) {
  uint8_t buf[EscapeConfig::MAX_ANNOUNCEMENT_BYTES + 16];
  for (int i = 0; i < 4; i++) {
    uint32_t src = 0;
    uint16_t srcPort = 0;
    const int n = udp_.receive(buf, sizeof(buf), src, srcPort);
    if (n <= 0) break;
    // Cheap rejections before any crypto: size, shape, per-source budget.
    if ((size_t)n > EscapeConfig::MAX_ANNOUNCEMENT_BYTES || n < 20 || memcmp(buf, "{\"doc\":", 7) != 0) continue;
    if (!udpLimiter_.allowSource(src, nowMs)) continue;
    EscapeJson::Slice doc;
    if (!transport_.openAnnouncement((const char *)buf, (size_t)n, doc)) continue;
    Announcement a;
    if (!parseAnnouncement(doc.p, doc.n, a)) continue;
    if (a.pmin > EscapeVersion::PROTO) continue; // peer needs a newer protocol than we speak: not usable
    const std::string srcText = ipToString(src);
    if (peers_.ingest(a, srcText.c_str(), didBytes_, nowMs) == PeerTable::Result::Accepted) considerSync(a, nowMs);
  }
}

void Device::maybeAnnounce(uint32_t nowMs) {
  const uint32_t ip = platform_.localIp();
  if (!ip || !udp_.isOpen()) return;
  const uint32_t interval = EscapeConfig::HEARTBEAT_INTERVAL_MS + jitterMs_;
  if (!(EscapeProtocol::isHeartbeatDue(nowMs, lastAnnounceMs_, interval) ||
        EscapeProtocol::isChangeBroadcastDue(nowMs, lastAnnounceMs_, dirty_))) {
    return;
  }
  lastAnnounceMs_ = nowMs;
  dirty_ = false;
  std::string frame;
  const bool ok = Escape::guardAlloc([&]() -> bool {
    const std::string doc = buildAnnouncementDoc(options_.did, ipToString(ip), options_.httpPort, options_.bootCounter, ++ctr_, seq_,
                                                 EscapeVersion::PROTO_MIN, options_.uiHash, store_.summaryJson(),
                                                 store_.summaryHash());
    return transport_.frameAnnouncement(doc, frame) && frame.size() <= EscapeConfig::MAX_ANNOUNCEMENT_BYTES;
  }, false);
  if (!ok) return;
  if (udp_.send(platform_.broadcastIp(), options_.udpPort, (const uint8_t *)frame.data(), frame.size())) announcementsSent_++;
}

// ---- Skeleton sync ----------------------------------------------------------------------------------

void Device::considerSync(const Announcement &a, uint32_t nowMs) {
  if (sync_.pending || client_.busy()) return; // one at a time; the next announcement retries
  uint8_t ipBytes[4];
  if (!parseIpv4(a.ip, strlen(a.ip), ipBytes)) return;
  const uint32_t ip = ipv4ToU32(ipBytes);
  const std::vector<std::string> rooms = EscapeProtocol::hostedRooms(host_);
  for (size_t k = 0; k < a.skCount; k++) {
    for (size_t r = 0; r < rooms.size(); r++) {
      if (roomKey(rooms[r]) != hex8(a.sk[k].roomKey)) continue;
      const SkeletonInfo *own = store_.find(rooms[r]);
      if (own && !SkeletonStore::isNewer(a.sk[k].rev, a.sk[k].hash, own->rev, own->hash)) continue;
      if (syncHasFailure_ && syncFailIp_ == ip && syncFailRoomKey_ == a.sk[k].roomKey &&
          nowMs - syncFailMs_ < EscapeConfig::SKELETON_SYNC_BACKOFF_MS) {
        continue;
      }
      sync_.pending = true;
      sync_.ip = ip;
      sync_.port = a.port;
      sync_.roomKey = a.sk[k].roomKey;
      sync_.room = rooms[r];
      sync_.did = didToText(a.did);
      return;
    }
  }
}

void Device::pumpSync(uint32_t nowMs) {
  if (client_.busy()) {
    client_.poll(nowMs);
  } else if (sync_.pending) {
    uint8_t n[16];
    crypto_.randomBytes(n, sizeof(n));
    syncNonce_ = base64UrlEncode(n, sizeof(n));
    syncActive_ = sync_;
    sync_ = SyncRequest();
    const bool started = client_.begin(syncActive_.ip, syncActive_.port,
                                       "/plan-skeleton.json?room=" + urlEncode(syncActive_.room) + "&nonce=" + syncNonce_, nowMs,
                                       3000, EscapeConfig::MAX_PLAN_SKELETON_LEN + 512);
    if (!started) {
      syncHasFailure_ = true;
      syncFailMs_ = nowMs;
      syncFailIp_ = syncActive_.ip;
      syncFailRoomKey_ = syncActive_.roomKey;
    }
    return;
  }
  if (!client_.finished()) return;

  bool stored = false;
  if (client_.state() == HttpClient::State::Done && client_.status() == 200) {
    EscapeJson::Slice blob;
    if (transport_.openDocumentFrameFrom(syncActive_.did, "/plan-skeleton.json", syncNonce_, 200, client_.body().data(),
                                         client_.body().size(), blob)) {
      stored = store_.adopt(blob.str(), syncActive_.room) == SkeletonStore::Result::Stored;
    }
  }
  if (stored) {
    for (uint8_t i = 0; i < host_.componentCount(); i++) {
      std::string name, room;
      host_.identity(i, name, room);
      if (room == syncActive_.room) host_.pushEvent(i, "Raum-Ablaufplan von Nachbargeraet uebernommen");
    }
    markDirty();
    syncHasFailure_ = false;
  } else {
    syncHasFailure_ = true; // wrong/stale/unreachable: back off for this peer and room
    syncFailMs_ = nowMs;
    syncFailIp_ = syncActive_.ip;
    syncFailRoomKey_ = syncActive_.roomKey;
  }
  client_.abort();
}

// ---- Shared mDNS record -----------------------------------------------------------------------------

void Device::serviceMdns(uint32_t nowMs) {
  if (!options_.mdnsPort) return;
  const uint32_t ip = platform_.localIp();
  if (ip != mdnsIp_) { // address changed (DHCP, Wi-Fi reconnect): re-join the group on the new interface
    mdnsIp_ = ip;
    mdns_.close();
    mdnsAnswerPending_ = false;
    if (ip) mdns_.openMulticast(options_.mdnsPort, kMdnsGroup, ip);
  }
  if (!mdns_.isOpen()) return;
  const uint8_t ipBytes[4] = {(uint8_t)(ip >> 24), (uint8_t)(ip >> 16), (uint8_t)(ip >> 8), (uint8_t)ip};
  uint8_t buf[512];
  for (int i = 0; i < 3; i++) {
    uint32_t src = 0;
    uint16_t srcPort = 0;
    const int n = mdns_.receive(buf, sizeof(buf), src, srcPort);
    if (n <= 0) break;
    const MdnsQuery q = parseMdnsQuery(buf, (size_t)n, options_.mdnsHostname.c_str(), ipBytes, EscapeConfig::MDNS_TTL_S);
    if (!q.matches || q.suppressed) continue;
    if (q.unicast) {
      uint8_t answer[128];
      const size_t len = buildMdnsAnswer(answer, sizeof(answer), options_.mdnsHostname.c_str(), ipBytes, EscapeConfig::MDNS_TTL_S);
      if (len) mdns_.send(src, srcPort, answer, len);
    } else if (!mdnsAnswerPending_) {
      uint8_t r[4];
      crypto_.randomBytes(r, sizeof(r));
      mdnsAnswerPending_ = true;
      mdnsAnswerAtMs_ = nowMs + mdnsResponseDelayMs((uint32_t)r[0] << 24 | (uint32_t)r[1] << 16 | (uint32_t)r[2] << 8 | r[3]);
    }
  }
  if (mdnsAnswerPending_ && (int32_t)(nowMs - mdnsAnswerAtMs_) >= 0) {
    mdnsAnswerPending_ = false;
    uint8_t answer[128];
    const size_t len = buildMdnsAnswer(answer, sizeof(answer), options_.mdnsHostname.c_str(), ipBytes, EscapeConfig::MDNS_TTL_S);
    if (len) mdns_.send(kMdnsGroup, options_.mdnsPort, answer, len);
  }
}

// ---- Main slice ---------------------------------------------------------------------------------------

void Device::loop(uint32_t nowMs, uint32_t budgetMicros) {
  if (!begun_) return;
  nowMs_ = nowMs;
  server_.poll(nowMs, budgetMicros);
  receiveAnnouncements(nowMs);
  maybeAnnounce(nowMs);
  peers_.expireStale(nowMs);
  pumpSync(nowMs);
  serviceMdns(nowMs);
}

} // namespace Escape
