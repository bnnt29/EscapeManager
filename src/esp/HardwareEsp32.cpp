// Implementierung von HardwareEsp32.hpp (siehe dort fuer Design-Rationale).

#include "HardwareEsp32.hpp"
#include <esp_partition.h>
#include <esp_system.h>
#include <mbedtls/base64.h>
#include <nvs.h>
#include <cstring>
#include <vector>

extern const uint8_t manager_html_start[] asm("_binary_src_EscapeManager_src_manager_manager_html_start");
extern const uint8_t manager_html_end[] asm("_binary_src_EscapeManager_src_manager_manager_html_end");

namespace {

const char *kAuthTokenStorageKey = "authtoken"; // NVS-Schluessel: max. 15 Zeichen
const char *kAuthTokenCommandPrefix = "ESCAPE_AUTH_TOKEN ";
const char *kAuthTokenSuccess = "ESCAPE_AUTH_TOKEN_OK";
const char *kResetStorageCommand = "ESCAPE_RESET_STORAGE";
const char *kResetStorageSuccess = "ESCAPE_RESET_STORAGE_OK";
const uint8_t kMaxSecureRequestsPerSecond = 8;
const char *kPlanNvsPartitionLabel = "plan_nvs";

bool hasPlanNvsPartition() {
  static int8_t cached = -1;
  if (cached >= 0) return cached == 1;

  const esp_partition_t *partition = esp_partition_find_first(
      ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, kPlanNvsPartitionLabel);
  cached = partition ? 1 : 0;
  return partition != nullptr;
}

bool beginPlanPrefs(Preferences &prefs, bool readOnly) {
  if (hasPlanNvsPartition()) {
    return prefs.begin("escfg", readOnly, kPlanNvsPartitionLabel);
  }
  return prefs.begin("escfg", readOnly);
}

bool preferencesNamespaceExists() {
  nvs_handle_t handle;
  esp_err_t err;

  if (hasPlanNvsPartition()) {
    err = nvs_open_from_partition(kPlanNvsPartitionLabel, "escfg", NVS_READONLY, &handle);
  } else {
    err = nvs_open("escfg", NVS_READONLY, &handle);
  }

  if (err == ESP_OK) {
    nvs_close(handle);
    return true;
  }

  return false;
}

bool validNonce(const std::string &nonce) {
  if (nonce.size() < 16 || nonce.size() > 64) return false;
  for (size_t i = 0; i < nonce.size(); i++) {
    char c = nonce[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
          (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  return true;
}

bool allowedManagerOrigin(const String &origin) {
  if (origin == "null" || origin.startsWith("http://localhost") ||
         origin.startsWith("http://127.0.0.1") || origin.startsWith("http://[::1]") ||
         origin.startsWith("https://localhost") || origin.startsWith("https://127.0.0.1") ||
    origin.startsWith("https://[::1]") || origin.startsWith("http://escapemanager.local") ||
    origin.startsWith("https://escapemanager.local")) return true;

  if (!origin.startsWith("http://")) return false;
  String host = origin.substring(7);
  int colon = host.indexOf(':');
  if (colon >= 0) host = host.substring(0, colon);
  int a, b, c, d;
  char extra;
  if (sscanf(host.c_str(), "%d.%d.%d.%d%c", &a, &b, &c, &d, &extra) != 4 ||
      a < 0 || a > 255 || b < 0 || b > 255 || c < 0 || c > 255 || d < 0 || d > 255) return false;
  return a == 10 || (a == 172 && b >= 16 && b <= 31) || (a == 192 && b == 168) ||
    (a == 169 && b == 254);
}

void sendCorsHeader(WebServer &server) {
  String origin = server.header("Origin");
  if (allowedManagerOrigin(origin)) {
    server.sendHeader("Access-Control-Allow-Origin", origin);
    server.sendHeader("Vary", "Origin");
  }
}

void sendCorsPreflight(WebServer &server) {
  String origin = server.header("Origin");
  if (!allowedManagerOrigin(origin)) {
    server.send(403, "application/json", "{\"error\":\"origin not allowed\"}");
    return;
  }
  sendCorsHeader(server);
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
  WiFi.mode(WIFI_STA);
  WiFi.setHostname(EscapeConfig::MDNS_HOSTNAME);
}

bool HardwareEsp32::initNvsSafely() {
  if (_nvsReady) return true;

  esp_err_t err = nvs_flash_init();

  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    Serial.println("EscapeManager: NVS ungültig, lösche und initialisiere neu...");
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }

  if (err != ESP_OK) {
    Serial.printf("EscapeManager: NVS Init fehlgeschlagen: %s\n", esp_err_to_name(err));
    return false;
  }

  _nvsReady = true;
  return true;
}

bool HardwareEsp32::ensurePreferencesNamespace(bool readOnly) {
  if (!initNvsSafely()) return false;

  if (!readOnly) {
    return beginPlanPrefs(_prefs, false);
  }

  if (preferencesNamespaceExists()) {
    return beginPlanPrefs(_prefs, true);
  }

  // Beim ersten Start existiert der Namespace ggf. noch nicht. Ein einmaliges
  // Oeffnen mit Schreibrechten legt ihn an; danach kann normal gelesen werden.
  if (!beginPlanPrefs(_prefs, false)) {
    return false;
  }
  _prefs.end();
  return beginPlanPrefs(_prefs, true);
}

bool HardwareEsp32::openPreferencesFixed() {
  if (ensurePreferencesNamespace(false)) {
    _prefs.end();
    return true;
  }

  Serial.println("EscapeManager: Preferences konnten nicht geöffnet werden.");
  return false;
}


void HardwareEsp32::connectWifi() {
  Serial.printf("EscapeManager: connecting to Wi-Fi \"%s\"\n", EscapeConfig::WIFI_SSID);
  WiFi.begin(EscapeConfig::WIFI_SSID, EscapeConfig::WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(200);
  }

  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("EscapeManager: Wi-Fi connected, IP address: %s\n", WiFi.localIP().toString().c_str());
    ensureMdnsRunning();
  } else {
    Serial.printf("EscapeManager: Wi-Fi connection failed (status %d); manager is unreachable.\n", WiFi.status());
  }

  _udp.begin(EscapeConfig::UDP_PORT);

  // Pro Geraet fixer Zufalls-Versatz gegen synchrone Broadcast-Bursts,
  // z.B. wenn ein ganzer Raum gleichzeitig eingeschaltet/reconnected wird.
  _jitterOffsetMs = esp_random() % (EscapeConfig::HEARTBEAT_JITTER_MS + 1);
}

void HardwareEsp32::beginHttpServer() {
  const char *headers[] = {"Origin"};
  _server.collectHeaders(headers, 1);

  _server.on("/favicon.ico", HTTP_GET, [this]() {
    sendCorsHeader(_server);
    _server.send(204);
  });

  _server.onNotFound([this]() {
    sendCorsHeader(_server);

    if (_server.method() == HTTP_OPTIONS) {
      _server.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
      _server.sendHeader("Access-Control-Allow-Headers", "Content-Type");
      _server.send(204);
      return;
    }

    if (_server.uri() == "/favicon.ico") {
      _server.send(204);
      return;
    }

    _server.send(404, "application/json; charset=utf-8", "{\"ok\":false,\"error\":\"not_found\"}");
  });

  _server.begin();
  if (WiFi.status() == WL_CONNECTED) {
    Serial.printf("EscapeManager: manager available at http://%s/\n", WiFi.localIP().toString().c_str());
  }
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
  ensureMdnsRunning();
}

void HardwareEsp32::ensureMdnsRunning() {
  if (_mdnsStarted) {
    return;
  }

  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("EscapeManager: Wi-Fi nicht verbunden; mDNS wird noch nicht gestartet.");
    return;
  }

  WiFi.setHostname(EscapeConfig::MDNS_HOSTNAME);

  // ESP32 ESPmDNS::begin() only supports the hostname argument.
  // The overload with IPAddress is invalid on this framework version.
  if (!MDNS.begin(EscapeConfig::MDNS_HOSTNAME)) {
    Serial.printf("EscapeManager: mDNS start fehlgeschlagen fuer http://%s.local/\n",
                  EscapeConfig::MDNS_HOSTNAME);
    return;
  }

  MDNS.setInstanceName("EscapeManager");
  MDNS.addService("http", "tcp", EscapeConfig::HTTP_PORT);
  MDNS.addServiceTxt("http", "tcp", "path", "/");
  MDNS.addServiceTxt("http", "tcp", "port", "80");
  MDNS.addServiceTxt("http", "tcp", "u", "/");

  _mdnsStarted = true;

  Serial.printf("EscapeManager: mDNS aktiv unter http://%s.local:%u/\n",
                EscapeConfig::MDNS_HOSTNAME,
                (unsigned)EscapeConfig::HTTP_PORT);
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
  // Base64URL + Auth-Huelle vergroessern das bisherige Broadcast-Maximum um
  // etwa ein Drittel. static vermeidet Belastung des kleinen Task-Stacks.
  const size_t rawMaximum = 512 + EscapeConfig::MAX_LOCAL_COMPONENTS * (1536 + EscapeConfig::MAX_PLAN_LEN);
  static std::vector<char> buf((rawMaximum * 4 + 2) / 3 + 256);
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
    sendCorsHeader(_server);
    EscapeProtocol::HttpResult r = handler();
    _server.send(r.status, "application/json", r.body.c_str());
  });
}

void HardwareEsp32::onAuthenticatedGet(
    const char *path, const std::function<EscapeProtocol::HttpResult()> &handler) {
  _server.on(path, HTTP_GET, [this, handler, path]() {
    sendCorsHeader(_server);
    std::string nonce = _server.hasArg("nonce") ? _server.arg("nonce").c_str() : "";
    if (!validNonce(nonce)) {
      _server.send(400, "application/json", "{\"error\":\"invalid nonce\"}");
      return;
    }
    EscapeProtocol::HttpResult result = handler();
    std::string context = std::string("http-get-v1\n") + path + "\n" + nonce + "\n" +
                          std::to_string(result.status);
    std::string authenticatedBody;
    if (!_security.protectDocument(context, result.body, authenticatedBody)) {
      _server.send(503, "application/json", "{\"error\":\"secure reads unavailable\"}");
      return;
    }
    _server.send(result.status, "application/json", authenticatedBody.c_str());
  });
}

bool HardwareEsp32::allowSecureRequest() {
  uint32_t now = millis();
  if (now - _secureRequestWindowStartMs >= 1000) {
    _secureRequestWindowStartMs = now;
    _secureRequestCount = 0;
  }
  if (_secureRequestCount >= kMaxSecureRequestsPerSecond) return false;
  _secureRequestCount++;
  return true;
}

void HardwareEsp32::onPost(
    const char *path, const std::function<EscapeProtocol::HttpResult(const EscapeProtocol::HttpRequest &)> &handler) {
  _server.on(path, HTTP_POST, [this, handler, path]() {
    sendCorsHeader(_server);
    if (!allowSecureRequest()) {
      _server.send(429, "application/json", "{\"error\":\"rate limit exceeded\"}");
      return;
    }
    const String &rawBody = _server.arg("plain");
    if (rawBody.length() > 12 * 1024) {
      _server.send(413, "application/json", "{\"error\":\"secure envelope too large\"}");
      return;
    }
    std::string plaintext;
    std::string error;
    std::string requestId;
    int status = 400;
    const std::string envelope = _server.hasArg("plain") ? rawBody.c_str() : "";
    if (!_security.decryptRequest(path, envelope, plaintext, status, error, &requestId)) {
      _server.send(status, "application/json", ("{\"error\":\"" + error + "\"}").c_str());
      return;
    }
    EscapeProtocol::HttpRequest req;
    req.body = plaintext;
    req.authOk = true;
    EscapeProtocol::HttpResult r = handler(req);
    std::string context = std::string("http-post-response-v1\n") + path + "\n" + requestId + "\n" +
                          std::to_string(r.status);
    std::string authenticatedBody;
    if (!_security.protectDocument(context, r.body, authenticatedBody)) {
      _server.send(503, "application/json", "{\"error\":\"secure response unavailable\"}");
      return;
    }
    _server.send(r.status, "application/json", authenticatedBody.c_str());
  });
  _server.on(path, HTTP_OPTIONS, [this]() { sendCorsPreflight(_server); });
}

void HardwareEsp32::serveManagerHtml() {
  _server.on("/", HTTP_GET, [this]() {
    size_t length = manager_html_end - manager_html_start;
    _server.send_P(200, "text/html; charset=utf-8", (PGM_P)manager_html_start, length);
  });
}

void HardwareEsp32::handleHttpClients() {
  pollSerialConfiguration();
  ensureMdnsRunning();
  _server.handleClient();
}

std::string HardwareEsp32::loadString(const char *key, const std::string &def) {
  if (!ensurePreferencesNamespace(true)) return def;
  if (!_prefs.isKey(key)) {
    _prefs.end();
    return def;
  }
  String v = _prefs.getString(key, def.c_str());
  _prefs.end();
  return std::string(v.c_str());
}

void HardwareEsp32::saveString(const char *key, const std::string &value) {
  if (!ensurePreferencesNamespace(false)) return;
  _prefs.putString(key, value.c_str());
  _prefs.end();
}

std::string HardwareEsp32::loadBlob(const char *key, const std::string &def) {
  if (!ensurePreferencesNamespace(true)) return def;
  if (!_prefs.isKey(key)) {
    _prefs.end();
    return def;
  }
  size_t size = _prefs.getBytesLength(key);
  if (!size) {
    _prefs.end();
    return def;
  }
  std::string value(size, '\0');
  size_t read = _prefs.getBytes(key, &value[0], size);
  _prefs.end();
  return read == size ? value : def;
}

void HardwareEsp32::saveBlob(const char *key, const std::string &value) {
  if (!ensurePreferencesNamespace(false)) return;
  _prefs.remove(key); // Erlaubt die Migration eines bisherigen String-Werts.
  _prefs.putBytes(key, value.data(), value.size());
  _prefs.end();
}

bool HardwareEsp32::persistAuthToken(const std::string &authToken) {
  if (!ensurePreferencesNamespace(false)) return false;
  size_t written = _prefs.putString(kAuthTokenStorageKey, authToken.c_str());
  _prefs.end();
  // Je nach Arduino-ESP32-Version wird die Laenge mit oder ohne abschliessendes
  // Nullbyte gemeldet.
  return written == authToken.size() || written == authToken.size() + 1;
}

bool HardwareEsp32::clearPersistentStorage() {
  if (!ensurePreferencesNamespace(false)) return false;
  bool configCleared = _prefs.clear();
  _prefs.end();

  bool plansCleared = true;
  if (hasPlanNvsPartition()) {
    if (!initNvsSafely()) return false;
    if (!_prefs.begin("escfg", false, kPlanNvsPartitionLabel)) return false;
    plansCleared = _prefs.clear();
    _prefs.end();
  }

  return configCleared && plansCleared;
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

  char nonceBuffer[17];
  snprintf(nonceBuffer, sizeof(nonceBuffer), "%08lx%08lx",
           (unsigned long)esp_random(), (unsigned long)esp_random());
  std::string nonce(nonceBuffer);
  client.print(String("GET ") + path + "?nonce=" + nonce.c_str() + " HTTP/1.1\r\n" +
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

  const long maxAuthenticatedResponseLength =
      (long)EscapeConfig::MAX_PLAN_SKELETON_STORAGE_LEN * 2;
  if (contentLength > maxAuthenticatedResponseLength) {
    client.stop();
    return false;
  }

  String body;
  if (contentLength >= 0) {
    body.reserve(contentLength);
    while ((long)body.length() < contentLength && client.connected()) {
      while (client.available() && (long)body.length() < contentLength) body += (char)client.read();
    }
  } else {
    while (client.connected() || client.available()) {
      while (client.available()) {
        if ((long)body.length() >= maxAuthenticatedResponseLength) {
          client.stop();
          return false;
        }
        body += (char)client.read();
      }
    }
  }
  client.stop();
  std::string context = std::string("http-get-v1\n") + path + "\n" + nonce + "\n200";
  if (_security.unprotectDocument(context, std::string(body.c_str()), outBody)) return true;
  if (!EscapeConfig::AUTHENTICATE_GET_REQUESTS) {
    outBody = body.c_str();
    return true;
  }
  return false;
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
