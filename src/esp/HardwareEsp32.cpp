// Implementierung von HardwareEsp32.hpp (siehe dort fuer Design-Rationale).

#include "HardwareEsp32.hpp"

#include <esp_system.h>
#include <mbedtls/base64.h>
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

const char *kAuthTokenStorageKey = "authtoken"; // NVS-Schluessel: max. 15 Zeichen
const char *kAuthTokenCommandPrefix = "ESCAPE_AUTH_TOKEN ";
const char *kAuthTokenSuccess = "ESCAPE_AUTH_TOKEN_OK";
const char *kResetStorageCommand = "ESCAPE_RESET_STORAGE";
const char *kResetStorageSuccess = "ESCAPE_RESET_STORAGE_OK";

void sendCorsPreflight(WebServer &server) {
  server.sendHeader("Access-Control-Allow-Origin", "*");
  server.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
  server.send(204);
}

} // namespace

HardwareEsp32::HardwareEsp32() : _security(EscapeConfig::AUTH_TOKEN, _crypto) {}

void HardwareEsp32::initWifiInterface() {
  // Wird neben Diagnoseausgaben fuer die PlatformIO-Wartungs-Environments
  // verwendet. Das Oeffnen des Ports darf einen ESP32 resetten; das Target
  // wartet deshalb auf den vollstaendigen Neustart und sendet mehrfach.
  Serial.begin(115200);
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

bool HardwareEsp32::beginSecurity() {
  if (_security.ready()) return true;
  std::string authToken = loadString(kAuthTokenStorageKey, EscapeConfig::AUTH_TOKEN);
  if (authToken.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN ||
      authToken.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) {
    authToken = EscapeConfig::AUTH_TOKEN;
  }
  return _security.setAuthToken(authToken) && _security.begin();
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
  _server.on(path, HTTP_POST, [this, handler, path]() {
    _server.sendHeader("Access-Control-Allow-Origin", "*");
    std::string plaintext;
    std::string error;
    int status = 400;
    const std::string envelope = _server.hasArg("plain") ? _server.arg("plain").c_str() : "";
    if (!_security.decryptRequest(path, envelope, plaintext, status, error)) {
      _server.send(status, "application/json", ("{\"error\":\"" + error + "\"}").c_str());
      return;
    }
    EscapeProtocol::HttpRequest req;
    req.body = plaintext;
    req.authOk = true;
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
  pollSerialConfiguration();
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

bool HardwareEsp32::persistAuthToken(const std::string &authToken) {
  if (!_prefs.begin("escfg", false)) return false;
  size_t written = _prefs.putString(kAuthTokenStorageKey, authToken.c_str());
  _prefs.end();
  // Je nach Arduino-ESP32-Version wird die Laenge mit oder ohne abschliessendes
  // Nullbyte gemeldet.
  return written == authToken.size() || written == authToken.size() + 1;
}

bool HardwareEsp32::clearPersistentStorage() {
  if (!_prefs.begin("escfg", false)) return false;
  bool cleared = _prefs.clear();
  _prefs.end();
  return cleared;
}

void HardwareEsp32::processSerialConfigurationLine(const char *line) {
  if (strcmp(line, kResetStorageCommand) == 0) {
    if (!clearPersistentStorage()) {
      Serial.println("ESCAPE_RESET_STORAGE_ERROR storage");
      return;
    }
    Serial.println(kResetStorageSuccess);
    Serial.flush();
    delay(100);
    ESP.restart();
    return;
  }

  const size_t prefixLength = strlen(kAuthTokenCommandPrefix);
  if (strncmp(line, kAuthTokenCommandPrefix, prefixLength) != 0) return;

  const char *encoded = line + prefixLength;
  const size_t encodedLength = strlen(encoded);
  uint8_t decoded[EscapeConfig::MAX_AUTH_TOKEN_LEN + 1] = {0};
  size_t decodedLength = 0;
  if (!encodedLength ||
      mbedtls_base64_decode(decoded, EscapeConfig::MAX_AUTH_TOKEN_LEN, &decodedLength,
                            reinterpret_cast<const uint8_t *>(encoded), encodedLength) != 0) {
    Serial.println("ESCAPE_AUTH_TOKEN_ERROR encoding");
    return;
  }

  if (decodedLength < EscapeConfig::MIN_AUTH_TOKEN_LEN ||
      decodedLength > EscapeConfig::MAX_AUTH_TOKEN_LEN) {
    Serial.println("ESCAPE_AUTH_TOKEN_ERROR length");
    return;
  }
  // Das INI-/Umgebungsvariablen-Format und die Manager-Eingabe bleiben damit
  // eindeutig; insbesondere werden eingebettete Nullbytes ausgeschlossen.
  for (size_t i = 0; i < decodedLength; i++) {
    if (decoded[i] < 0x21 || decoded[i] > 0x7e) {
      Serial.println("ESCAPE_AUTH_TOKEN_ERROR characters");
      return;
    }
  }

  const std::string authToken(reinterpret_cast<const char *>(decoded), decodedLength);
  if (!persistAuthToken(authToken)) {
    Serial.println("ESCAPE_AUTH_TOKEN_ERROR storage");
    return;
  }

  // Token niemals zurueckechoen. Der Neustart erzeugt sofort einen neuen,
  // bereits mit dem gespeicherten Token geschuetzten Boot-Schluessel.
  Serial.println(kAuthTokenSuccess);
  Serial.flush();
  delay(100);
  ESP.restart();
}

void HardwareEsp32::pollSerialConfiguration() {
  static char line[EscapeConfig::MAX_AUTH_TOKEN_LEN * 2 + 32] = {0};
  static size_t length = 0;
  static bool overflow = false;

  while (Serial.available() > 0) {
    char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (overflow) {
        Serial.println("ESCAPE_AUTH_TOKEN_ERROR command-too-long");
      } else if (length) {
        line[length] = '\0';
        processSerialConfigurationLine(line);
      }
      length = 0;
      overflow = false;
      continue;
    }
    if (overflow) continue;
    if (length + 1 >= sizeof(line)) {
      overflow = true;
      continue;
    }
    line[length++] = c;
  }
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
