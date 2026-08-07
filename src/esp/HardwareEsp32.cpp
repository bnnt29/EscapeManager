// Implementierung von HardwareEsp32.hpp (siehe dort fuer Design-Rationale).

#include "HardwareEsp32.hpp"

#include <esp_system.h>
#include <cstring>
#include <vector>

// manager.html wird ueber PlatformIO's "board_build.embed_files" direkt als
// Binaerblob ins Flash gelinkt (siehe platformio.ini) - die Datei bleibt damit
// eigenstaendig unter src/manager/manager.html und muss nicht als C-String im
// Quelltext dupliziert werden. Symbolnamen leiten sich aus dem (relativ zur
// Projektwurzel angegebenen) Dateipfad ab - siehe board_build.embed_files.
extern const uint8_t manager_html_start[] asm("_binary_src_manager_manager_html_start");
extern const uint8_t manager_html_end[] asm("_binary_src_manager_manager_html_end");

namespace {

// Vergleicht den vom Aufrufer gelieferten Header-Wert (falls vorhanden) gegen
// EscapeConfig::AUTH_TOKEN - Zeitkonstanz siehe EscapeProtocol::constantTimeEquals().
bool checkAuth(WebServer &server) {
  String token = server.header("X-Auth-Token");
  return EscapeProtocol::constantTimeEquals(std::string(token.c_str()), EscapeConfig::AUTH_TOKEN);
}

void sendCorsPreflight(WebServer &server) {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token");
  server.send(204);
}

} // namespace

void HardwareEsp32::initWifiInterface() {
  WiFi.mode(WIFI_STA);
}

void HardwareEsp32::connectWifi() {
  WiFi.begin(EscapeConfig::WIFI_SSID, EscapeConfig::WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(200);
  }

  _udp.begin(EscapeConfig::UDP_PORT);

  // Pro Geraet fixer Zufalls-Versatz gegen synchrone Broadcast-Bursts,
  // z.B. wenn ein ganzer Raum gleichzeitig eingeschaltet/reconnected wird.
  _jitterOffsetMs = esp_random() % (EscapeConfig::HEARTBEAT_JITTER_MS + 1);
}

void HardwareEsp32::beginHttpServer() {
  _server.begin();
}

void HardwareEsp32::beginMdns() {
  // Gemeinsamer Hostname ueber alle Komponenten: welches Geraet ein Client
  // beim Aufloesen von <MDNS_HOSTNAME>.local letztlich erreicht, entscheidet
  // der mDNS-Resolver des Betriebssystems (i.d.R. die zuerst antwortende
  // Komponente) - dadurch verbindet sich ein neuer Manager ohne Konfiguration
  // mit irgendeiner erreichbaren Komponente.
  MDNS.begin(EscapeConfig::MDNS_HOSTNAME);
  MDNS.addService("http", "tcp", EscapeConfig::HTTP_PORT);
}

IPAddress HardwareEsp32::broadcastAddress() const {
  IPAddress ip = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();
  if ((uint32_t)mask == 0) return IPAddress(255, 255, 255, 255);
  IPAddress bc;
  for (int i = 0; i < 4; i++) bc[i] = ip[i] | (~mask[i] & 0xFF);
  return bc;
}

void HardwareEsp32::sendBroadcast(const std::string &payload) {
  IPAddress bc = broadcastAddress();
  _udp.beginPacket(bc, EscapeConfig::UDP_PORT);
  _udp.write((const uint8_t *)payload.data(), payload.size());
  _udp.endPacket();
}

void HardwareEsp32::pollIncoming(int maxPackets,
                                  const std::function<void(const std::string &, const std::string &)> &onPacket) {
  // Puffer skaliert mit MAX_LOCAL_COMPONENTS (andere Boards koennen genauso
  // viele Komponenten in einem Paket buendeln) - static statt Stack-Array, um
  // den (kleinen, fixen) Task-Stack nicht zu belasten.
  static std::vector<char> buf(512 + EscapeConfig::MAX_LOCAL_COMPONENTS * (1536 + EscapeConfig::MAX_PLAN_LEN));
  int processed = 0;
  int packetSize;
  while (processed < maxPackets && (packetSize = _udp.parsePacket()) > 0) {
    processed++;
    int len = _udp.read(buf.data(), buf.size() - 1);
    if (len <= 0) continue;
    buf[len] = '\0';
    std::string senderIp(_udp.remoteIP().toString().c_str());
    onPacket(std::string(buf.data(), (size_t)len), senderIp);
  }
}

void HardwareEsp32::onGet(const char *path, const std::function<EscapeProtocol::HttpResult()> &handler) {
  _server.on(path, HTTP_GET, [this, handler]() {
    _server.sendHeader("Access-Control-Allow-Origin", "*");
    EscapeProtocol::HttpResult r = handler();
    _server.send(r.status, "application/json", r.body.c_str());
  });
}

void HardwareEsp32::onPost(
    const char *path, const std::function<EscapeProtocol::HttpResult(const EscapeProtocol::HttpRequest &)> &handler) {
  _server.on(path, HTTP_POST, [this, handler]() {
    _server.sendHeader("Access-Control-Allow-Origin", "*");
    EscapeProtocol::HttpRequest req;
    req.body = _server.hasArg("plain") ? _server.arg("plain").c_str() : "";
    req.authOk = checkAuth(_server);
    EscapeProtocol::HttpResult r = handler(req);
    _server.send(r.status, "application/json", r.body.c_str());
  });
  _server.on(path, HTTP_OPTIONS, [this]() { sendCorsPreflight(_server); });
}

void HardwareEsp32::serveManagerHtml() {
  _server.on("/", HTTP_GET, [this]() {
    size_t len = manager_html_end - manager_html_start;
    _server.send_P(200, "text/html", (PGM_P)manager_html_start, len);
  });
}

void HardwareEsp32::handleHttpClients() {
  _server.handleClient();
}

std::string HardwareEsp32::loadString(const char *key, const std::string &def) {
  _prefs.begin("escfg", true);
  String v = _prefs.getString(key, def.c_str());
  _prefs.end();
  return std::string(v.c_str());
}

void HardwareEsp32::saveString(const char *key, const std::string &value) {
  _prefs.begin("escfg", false);
  _prefs.putString(key, value.c_str());
  _prefs.end();
}

bool HardwareEsp32::httpGet(const std::string &ip, const char *path, std::string &outBody) {
  WiFiClient client;
  client.setTimeout(1500); // ms - Peer soll das UI/loop() nicht spuerbar blockieren
  if (!client.connect(ip.c_str(), EscapeConfig::HTTP_PORT)) return false;

  client.print(String("GET ") + path + " HTTP/1.1\r\n" +
               "Host: " + ip.c_str() + "\r\n" +
               "Connection: close\r\n\r\n");

  // Statuszeile lesen ("HTTP/1.1 200 OK").
  String statusLine = client.readStringUntil('\n');
  if (statusLine.indexOf(" 200 ") < 0) { client.stop(); return false; }

  // Header ueberspringen, dabei Content-Length merken (robuster als "bis
  // Verbindung schliesst", falls der Server Keep-Alive verwendet).
  long contentLength = -1;
  String line;
  do {
    line = client.readStringUntil('\n');
    line.trim();
    if (line.startsWith("Content-Length:") || line.startsWith("content-length:")) {
      contentLength = line.substring(line.indexOf(':') + 1).toInt();
    }
  } while (line.length() > 0 && client.connected());

  String body;
  if (contentLength >= 0) {
    body.reserve(contentLength);
    while ((long)body.length() < contentLength && client.connected()) {
      while (client.available() && (long)body.length() < contentLength) body += (char)client.read();
    }
  } else {
    while (client.connected() || client.available()) {
      while (client.available()) body += (char)client.read();
    }
  }
  client.stop();
  outBody = body.c_str();
  return true;
}

std::string HardwareEsp32::localIp() const {
  return std::string(WiFi.localIP().toString().c_str());
}

uint32_t HardwareEsp32::nowMs() const {
  return millis();
}

// Siehe HardwareEsp32.hpp: leitet eine stabile, von Name/Raum unabhaengige
// Komponenten-Identitaet von der WLAN-MAC-Adresse des Boards ab. Deterministisch
// statt zufaellig, daher ohne Zufallsquelle/NVS-Race ueber Reboots hinweg
// stabil, und trotzdem pro Board+Komponente eindeutig (MAC + lokaler Index).
// Braucht initWifiInterface() vorher, sonst liefert WiFi.macAddress() ggf. nur
// Nullen. Fallback fuer den Fall, dass WiFi.macAddress() keine brauchbare
// Adresse liefert (alle Bytes 0x00 oder 0xFF, z.B. bei einem WLAN-Treiberfehler
// oder defektem Funkmodul): die 64-Bit Chip-ID aus der eFuse (ESP.getEfuseMac(),
// werkseitig einzigartig pro Chip und unabhaengig vom WLAN-Stack) wird
// stattdessen verwendet, damit trotzdem eine stabile, geraeteweit eindeutige
// Kennung entsteht statt kollidierender Nullen auf mehreren Boards.
std::string HardwareEsp32::macBasedUuid(uint8_t localComponentId) const {
  uint8_t mac[6] = {0};
  WiFi.macAddress(mac);

  bool allSame = true;
  for (uint8_t i = 1; i < 6; i++) {
    if (mac[i] != mac[0]) { allSame = false; break; }
  }
  bool macUnavailable = allSame && (mac[0] == 0x00 || mac[0] == 0xFF);

  char out[EscapeConfig::MAX_UUID_LEN + 1];
  if (macUnavailable) {
    // Nur die unteren 48 Bit sind bei ESP.getEfuseMac() belegt (obere 16 Bit
    // sind 0) - maskieren erzwingt trotzdem exakt 12 Hex-Ziffern im Format,
    // damit "out" niemals ueber MAX_UUID_LEN hinauswaechst.
    uint64_t chipId = ESP.getEfuseMac() & 0xFFFFFFFFFFFFULL;
    snprintf(out, sizeof(out), "chip%012llx-%u", (unsigned long long)chipId, (unsigned)localComponentId);
  } else {
    snprintf(out, sizeof(out), "%02x%02x%02x%02x%02x%02x-%u", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
             (unsigned)localComponentId);
  }
  return std::string(out);
}
