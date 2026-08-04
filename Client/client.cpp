// Implementierung von EscapeComponent (siehe client.hpp).
//
// Benoetigte Bibliothek (PlatformIO): bblanchon/ArduinoJson (nur zum Parsen
// eingehender Nachrichten - der /status.json-Response wird bewusst manuell
// als String gebaut, um bei vielen Peers keine grossen ArduinoJson-Dokumente
// im Speicher halten zu muessen).
//
// platformio.ini Beispiel:
//   lib_deps = bblanchon/ArduinoJson @ ^7

#include "client.hpp"
#include <ArduinoJson.h>
#include <esp_system.h>

// manager.html wird ueber PlatformIO's "board_build.embed_files" direkt als
// Binaerblob ins Flash gelinkt (siehe platformio.ini) - die Datei bleibt damit
// eigenstaendig unter Manager/manager.html und muss nicht als C-String im
// Quelltext dupliziert werden. Symbolnamen leiten sich aus dem Dateipfad ab.
extern const uint8_t manager_html_start[] asm("_binary_Manager_manager_html_start");
extern const uint8_t manager_html_end[] asm("_binary_Manager_manager_html_end");

namespace {

// Vergleicht zwei Strings ohne Frueh-Abbruch bei erstem Unterschied, um
// Timing-Angriffe auf den Auth-Token zu erschweren. Die Laenge selbst ist
// ueber die Schleifenzahl minimal beobachtbar, was fuer dieses Bedrohungsmodell
// (LAN-Zugriff, kein hochpraeziser Fernangreifer) akzeptabel ist.
bool constantTimeEquals(const String &a, const char *b) {
  size_t la = a.length();
  size_t lb = strlen(b);
  uint8_t diff = (uint8_t)(la != lb);
  size_t n = la < lb ? la : lb;
  for (size_t i = 0; i < n; i++) {
    diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  }
  return diff == 0;
}

void appendJsonEscaped(String &out, const char *s) {
  if (!s) return;
  for (const char *c = s; *c; c++) {
    switch (*c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if ((uint8_t)*c >= 0x20) out += *c; // sonstige Steuerzeichen verwerfen
    }
  }
}

void copyBounded(char *dst, size_t dstSize, const char *src) {
  strncpy(dst, src ? src : "", dstSize - 1);
  dst[dstSize - 1] = '\0';
}

} // namespace

void EscapeComponent::begin() {
  loadIdentity();

  WiFi.mode(WIFI_STA);
  WiFi.begin(EscapeConfig::WIFI_SSID, EscapeConfig::WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(200);
  }

  _udp.begin(EscapeConfig::UDP_PORT);

  // Pro Geraet fixer Zufalls-Versatz gegen synchrone Broadcast-Bursts,
  // z.B. wenn ein ganzer Raum gleichzeitig eingeschaltet/reconnected wird.
  _jitterOffsetMs = esp_random() % (EscapeConfig::HEARTBEAT_JITTER_MS + 1);

  const char *headerKeys[] = {"X-Auth-Token"};
  _server.collectHeaders(headerKeys, 1);
  _server.on("/", HTTP_GET, [this] { handleRoot(); });
  _server.on("/status.json", HTTP_GET, [this] { handleStatus(); });
  _server.on("/action", HTTP_POST, [this] { handleAction(); });
  _server.on("/action", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.on("/config", HTTP_POST, [this] { handleConfig(); });
  _server.on("/config", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.begin();

  // Gemeinsamer Hostname ueber alle Komponenten: welches Geraet ein Client
  // beim Aufloesen von <MDNS_HOSTNAME>.local letztlich erreicht, entscheidet
  // der mDNS-Resolver des Betriebssystems (i.d.R. die zuerst antwortende
  // Komponente) - dadurch verbindet sich ein neuer Manager ohne Konfiguration
  // mit irgendeiner erreichbaren Komponente.
  MDNS.begin(EscapeConfig::MDNS_HOSTNAME);
  MDNS.addService("http", "tcp", EscapeConfig::HTTP_PORT);
}

void EscapeComponent::loop() {
  _server.handleClient();
  pollIncoming();

  uint32_t now = millis();
  uint32_t interval = EscapeConfig::HEARTBEAT_INTERVAL_MS + _jitterOffsetMs;
  bool heartbeatDue = now - _lastBroadcastMs >= interval;
  bool changeDue = _dirty && (now - _lastBroadcastMs >= EscapeConfig::CHANGE_MIN_GAP_MS);

  if (heartbeatDue || changeDue) {
    sendBroadcast();
    _lastBroadcastMs = now;
    _dirty = false;
  }

  // Nicht jeden loop()-Durchlauf pruefen: Aufraeumen ist unkritisch in seiner
  // Genauigkeit und muss keine CPU-Zeit auf jedem Zyklus kosten.
  if (now - _lastExpireCheckMs >= 2000) {
    expireStalePeers();
    _lastExpireCheckMs = now;
  }
}

void EscapeComponent::markDirty() { _dirty = true; }

void EscapeComponent::onBattery(BatteryProvider cb) { _batteryCb = cb; }
void EscapeComponent::onErrors(StringListProvider cb) { _errorsCb = cb; }
void EscapeComponent::onActions(StringListProvider cb) { _actionsCb = cb; }
void EscapeComponent::onFeed(FeedProvider cb) { _feedCb = cb; }
void EscapeComponent::onPuzzle(PuzzleProvider cb) { _puzzleCb = cb; }
void EscapeComponent::onAction(ActionHandler cb) { _actionHandler = cb; }

// ---- Identitaet (NVS) -------------------------------------------------------

void EscapeComponent::loadIdentity() {
  _prefs.begin("escfg", true);
  String n = _prefs.getString("name", EscapeConfig::DEFAULT_NAME);
  String r = _prefs.getString("room", EscapeConfig::DEFAULT_ROOM);
  _prefs.end();
  copyBounded(_name, sizeof(_name), n.c_str());
  copyBounded(_room, sizeof(_room), r.c_str());
}

void EscapeComponent::saveIdentity(const String &name, const String &room) {
  _prefs.begin("escfg", false);
  _prefs.putString("name", name);
  _prefs.putString("room", room);
  _prefs.end();
  copyBounded(_name, sizeof(_name), name.c_str());
  copyBounded(_room, sizeof(_room), room.c_str());
}

// ---- Broadcast senden -------------------------------------------------------

IPAddress EscapeComponent::broadcastAddress() const {
  IPAddress ip = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();
  if ((uint32_t)mask == 0) return IPAddress(255, 255, 255, 255);
  IPAddress bc;
  for (int i = 0; i < 4; i++) bc[i] = ip[i] | (~mask[i] & 0xFF);
  return bc;
}

void EscapeComponent::sendBroadcast() {
  StaticJsonDocument<768> doc;
  doc["name"] = _name;
  doc["room"] = _room;
  doc["ip"] = WiFi.localIP().toString();
  doc["battery"] = _batteryCb ? _batteryCb() : -1;

  JsonArray errs = doc.createNestedArray("errors");
  if (_errorsCb) {
    String buf[EscapeConfig::MAX_ERRORS];
    size_t n = _errorsCb(buf, EscapeConfig::MAX_ERRORS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ERRORS; i++) errs.add(buf[i]);
  }

  JsonArray acts = doc.createNestedArray("actions");
  if (_actionsCb) {
    String buf[EscapeConfig::MAX_ACTIONS];
    size_t n = _actionsCb(buf, EscapeConfig::MAX_ACTIONS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ACTIONS; i++) acts.add(buf[i]);
  }

  if (_feedCb) {
    String feed = _feedCb();
    if (feed.length()) doc["feed"] = feed;
  }

  if (_puzzleCb) {
    uint16_t step = 0, total = 0;
    String state;
    bool isHtml = false;
    _puzzleCb(step, total, state, isHtml);
    if (total > 0) {
      JsonObject puzzle = doc.createNestedObject("puzzle");
      puzzle["step"] = step;
      puzzle["totalSteps"] = total;
      if (state.length()) puzzle["state"] = state;
      puzzle["isHtml"] = isHtml;
    }
  }

  char buf[800];
  size_t len = serializeJson(doc, buf, sizeof(buf));

  IPAddress bc = broadcastAddress();
  _udp.beginPacket(bc, EscapeConfig::UDP_PORT);
  _udp.write((const uint8_t *)buf, len);
  _udp.endPacket();
}

// ---- Broadcast empfangen / Peer-Tabelle -------------------------------------

PeerInfo *EscapeComponent::findOrCreatePeer(const char *name, const char *room) {
  for (size_t i = 0; i < _peerCount; i++) {
    if (strncmp(_peers[i].name, name, sizeof(_peers[i].name)) == 0 &&
        strncmp(_peers[i].room, room, sizeof(_peers[i].room)) == 0) {
      return &_peers[i];
    }
  }
  if (_peerCount < EscapeConfig::MAX_PEERS) {
    return &_peers[_peerCount++];
  }
  // Tabelle voll (z.B. viele kurzlebige/testweise Komponenten im WLAN):
  // am laengsten nicht gesehenen Eintrag verdraengen statt neue zu verwerfen.
  size_t oldest = 0;
  for (size_t i = 1; i < _peerCount; i++) {
    if (_peers[i].lastSeenMs < _peers[oldest].lastSeenMs) oldest = i;
  }
  return &_peers[oldest];
}

void EscapeComponent::pollIncoming() {
  // Pro loop()-Aufruf begrenzt viele Pakete verarbeiten, damit ein Burst
  // eingehender Broadcasts den HTTP-Server nicht verhungern laesst.
  int processed = 0;
  int packetSize;
  char buf[800];
  while (processed < 5 && (packetSize = _udp.parsePacket()) > 0) {
    processed++;
    int len = _udp.read(buf, sizeof(buf) - 1);
    if (len <= 0) continue;
    buf[len] = '\0';

    StaticJsonDocument<896> doc;
    if (deserializeJson(doc, buf)) continue; // fehlerhaftes/fremdes Paket verwerfen

    const char *name = doc["name"] | "";
    const char *room = doc["room"] | "";
    if (!*name || !*room) continue;
    // eigenen Broadcast ignorieren (Identitaet, nicht IP - siehe IP-Wechsel-Hinweis)
    if (strncmp(name, _name, sizeof(_name)) == 0 && strncmp(room, _room, sizeof(_room)) == 0) continue;

    PeerInfo *p = findOrCreatePeer(name, room);
    if (!p) continue;

    copyBounded(p->name, sizeof(p->name), name);
    copyBounded(p->room, sizeof(p->room), room);
    p->ip = _udp.remoteIP();
    p->battery = doc["battery"] | -1;

    p->errorCount = 0;
    for (JsonVariant v : doc["errors"].as<JsonArray>()) {
      if (p->errorCount >= EscapeConfig::MAX_ERRORS) break;
      copyBounded(p->errors[p->errorCount], sizeof(p->errors[0]), v.as<const char *>());
      p->errorCount++;
    }

    p->actionCount = 0;
    for (JsonVariant v : doc["actions"].as<JsonArray>()) {
      if (p->actionCount >= EscapeConfig::MAX_ACTIONS) break;
      copyBounded(p->actions[p->actionCount], sizeof(p->actions[0]), v.as<const char *>());
      p->actionCount++;
    }

    copyBounded(p->feed, sizeof(p->feed), doc["feed"] | "");

    JsonObject puzzle = doc["puzzle"];
    if (!puzzle.isNull()) {
      p->puzzleStep = puzzle["step"] | 0;
      p->puzzleTotalSteps = puzzle["totalSteps"] | 0;
      copyBounded(p->puzzleState, sizeof(p->puzzleState), puzzle["state"] | "");
      p->puzzleIsHtml = puzzle["isHtml"] | false;
    } else {
      p->puzzleTotalSteps = 0;
    }

    p->lastSeenMs = millis();
  }
}

void EscapeComponent::expireStalePeers() {
  uint32_t now = millis();
  size_t w = 0;
  for (size_t i = 0; i < _peerCount; i++) {
    if (now - _peers[i].lastSeenMs <= EscapeConfig::PEER_TIMEOUT_MS) {
      if (w != i) _peers[w] = _peers[i];
      w++;
    }
  }
  _peerCount = w;
}

// ---- / (manager.html) -------------------------------------------------------

void EscapeComponent::handleRoot() {
  size_t len = manager_html_end - manager_html_start;
  _server.send_P(200, "text/html", (PGM_P)manager_html_start, len);
}

// ---- /status.json ------------------------------------------------------------

void EscapeComponent::fillSelfPeer(PeerInfo &p) const {
  copyBounded(p.name, sizeof(p.name), _name);
  copyBounded(p.room, sizeof(p.room), _room);
  p.ip = WiFi.localIP();
  p.battery = _batteryCb ? _batteryCb() : -1;

  p.errorCount = 0;
  if (_errorsCb) {
    String buf[EscapeConfig::MAX_ERRORS];
    size_t n = _errorsCb(buf, EscapeConfig::MAX_ERRORS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ERRORS; i++) {
      copyBounded(p.errors[i], sizeof(p.errors[0]), buf[i].c_str());
      p.errorCount++;
    }
  }

  p.actionCount = 0;
  if (_actionsCb) {
    String buf[EscapeConfig::MAX_ACTIONS];
    size_t n = _actionsCb(buf, EscapeConfig::MAX_ACTIONS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ACTIONS; i++) {
      copyBounded(p.actions[i], sizeof(p.actions[0]), buf[i].c_str());
      p.actionCount++;
    }
  }

  if (_feedCb) copyBounded(p.feed, sizeof(p.feed), _feedCb().c_str());

  p.puzzleTotalSteps = 0;
  if (_puzzleCb) {
    uint16_t step = 0, total = 0;
    String state;
    bool isHtml = false;
    _puzzleCb(step, total, state, isHtml);
    p.puzzleStep = step;
    p.puzzleTotalSteps = total;
    copyBounded(p.puzzleState, sizeof(p.puzzleState), state.c_str());
    p.puzzleIsHtml = isHtml;
  }

  p.lastSeenMs = millis();
}

void EscapeComponent::writePeerJson(String &out, const PeerInfo &p) const {
  out += '{';
  out += "\"name\":\""; appendJsonEscaped(out, p.name); out += "\",";
  out += "\"room\":\""; appendJsonEscaped(out, p.room); out += "\",";
  out += "\"ip\":\""; out += p.ip.toString(); out += "\",";
  out += "\"battery\":"; out += String(p.battery); out += ',';

  out += "\"errors\":[";
  for (uint8_t i = 0; i < p.errorCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.errors[i]); out += '"';
  }
  out += "],";

  out += "\"actions\":[";
  for (uint8_t i = 0; i < p.actionCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.actions[i]); out += '"';
  }
  out += "],";

  if (p.feed[0]) {
    out += "\"feed\":\""; appendJsonEscaped(out, p.feed); out += "\",";
  }

  if (p.puzzleTotalSteps > 0) {
    out += "\"puzzle\":{";
    out += "\"step\":"; out += String(p.puzzleStep); out += ',';
    out += "\"totalSteps\":"; out += String(p.puzzleTotalSteps); out += ',';
    out += "\"state\":\""; appendJsonEscaped(out, p.puzzleState); out += "\",";
    out += "\"isHtml\":"; out += (p.puzzleIsHtml ? "true" : "false");
    out += "},";
  }

  out += "\"lastSeenMs\":"; out += String(p.lastSeenMs);
  out += '}';
}

void EscapeComponent::handleStatus() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");

  String json;
  json.reserve(256 + (_peerCount + 1) * 300);
  json += '[';

  PeerInfo self;
  fillSelfPeer(self);
  writePeerJson(json, self);

  for (size_t i = 0; i < _peerCount; i++) {
    json += ',';
    writePeerJson(json, _peers[i]);
  }
  json += ']';

  _server.send(200, "application/json", json);
}

// ---- Authentifizierung / CORS ------------------------------------------------

bool EscapeComponent::checkAuth() {
  String token = _server.header("X-Auth-Token");
  return constantTimeEquals(token, EscapeConfig::AUTH_TOKEN);
}

void EscapeComponent::sendCorsPreflight() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  _server.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  _server.sendHeader("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token");
  _server.send(204);
}

// ---- /action -------------------------------------------------------------------

void EscapeComponent::handleAction() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }

  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, _server.arg("plain"))) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }
  const char *action = doc["action"] | "";
  if (!*action || strlen(action) > EscapeConfig::MAX_ACTION_LEN) {
    _server.send(400, "application/json", "{\"error\":\"invalid action\"}");
    return;
  }

  bool ok = _actionHandler ? _actionHandler(String(action)) : false;
  markDirty(); // Zustand hat sich moeglicherweise geaendert -> zeitnah neu broadcasten
  _server.send(ok ? 200 : 422, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

// ---- /config -------------------------------------------------------------------

void EscapeComponent::handleConfig() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }

  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, _server.arg("plain"))) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }
  const char *name = doc["name"] | "";
  const char *room = doc["room"] | "";
  if (!*name || !*room ||
      strlen(name) > EscapeConfig::MAX_NAME_LEN || strlen(room) > EscapeConfig::MAX_ROOM_LEN) {
    _server.send(400, "application/json", "{\"error\":\"invalid name/room\"}");
    return;
  }

  saveIdentity(name, room);
  markDirty();
  _server.send(200, "application/json", "{\"ok\":true}");
}
