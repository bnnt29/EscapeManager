#include "HardwareEsp32.hpp"

#include "../net/Clock.hpp"
#include "../protocol/EscapeConfig.hpp"
#include "../protocol/EscapeVersion.hpp"

#include <WiFi.h>
#include <esp_mac.h>
#include <esp_partition.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <mbedtls/base64.h>
#include <nvs_flash.h>

#include <cstring>

namespace {

const char *kConfigNamespace = "escfg";   // names, rooms, riddle ids, component plan slices, token, Wi-Fi
const char *kPlanNamespace = "escplan";   // plan skeleton blobs
const char *kPlanPartition = "plan_nvs";  // optional dedicated partition (see partitions.csv)
const char *kTokenKey = "authtoken";
const char *kBootKey = "boot";

const uint32_t kWifiFirstBackoffMs = 15000;
const uint32_t kWifiMaxBackoffMs = 60000;

void logLine(const char *text) { Serial.println(text); }

bool printableToken(const std::string &t) {
  if (t.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN || t.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) return false;
  for (size_t i = 0; i < t.size(); i++) {
    if ((uint8_t)t[i] < 0x21 || (uint8_t)t[i] > 0x7e) return false;
  }
  return true;
}

bool decodeBase64(const char *text, std::string &out, size_t maxLen) {
  uint8_t buf[200];
  size_t written = 0;
  const size_t n = strlen(text);
  if (n == 0 || maxLen > sizeof(buf)) return false;
  if (mbedtls_base64_decode(buf, sizeof(buf), &written, (const uint8_t *)text, n) != 0 || written > maxLen) return false;
  out.assign((const char *)buf, written);
  memset(buf, 0, sizeof(buf));
  return true;
}

} // namespace

HardwareEsp32::HardwareEsp32()
    : _skeleton(*this), _storageReady(false), _hasPlanPartition(false), _wifiStarted(false), _wifiOwned(false),
      _serialEnabled(true), _lastWifiAttemptMs(0), _wifiBackoffMs(kWifiFirstBackoffMs), _wasConnected(false),
      _lineLength(0), _lineOverflow(false) {
  _line[0] = '\0';
}

// ---- Storage --------------------------------------------------------------------------------

bool HardwareEsp32::beginStorage() {
  if (_storageReady) return true;
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    logLine("EscapeManager: NVS invalid, erasing");
    nvs_flash_erase();
    err = nvs_flash_init();
  }
  if (err != ESP_OK) {
    Serial.printf("EscapeManager: NVS init failed: %s\n", esp_err_to_name(err));
    return false;
  }
  _hasPlanPartition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, kPlanPartition) != nullptr;
  // Creating the namespaces once makes later read-only opens quiet (no NOT_FOUND noise).
  if (openConfig(false)) _prefs.end();
  if (openPlans(false)) _prefs.end();
  _storageReady = true;
  if (!_hasPlanPartition) {
    // Measured on hardware: the default 20 KB NVS (shared with the Wi-Fi driver) holds about ONE 6 KB
    // plan skeleton, or two of ~3 KB; a rewrite needs room for the old and the new copy at once.
    logLine("EscapeManager: no plan_nvs partition - plan skeletons share the 20 KB default NVS (about one 6 KB plan); see partitions.csv");
  }
  // The pre-proto-2 skeleton collection is obsolete (different format, up to 24 KB): drop it.
  if (openConfig(false)) {
    if (_prefs.isKey("planskel")) _prefs.remove("planskel");
    _prefs.end();
  }
  return true;
}

// Configuration lives in the dedicated partition when the host's partition table has one
// (more room, and it survives other NVS users), otherwise in the default NVS.
bool HardwareEsp32::openConfig(bool readOnly) {
  return _hasPlanPartition ? _prefs.begin(kConfigNamespace, readOnly, kPlanPartition) : _prefs.begin(kConfigNamespace, readOnly);
}

bool HardwareEsp32::openPlans(bool readOnly) {
  return _hasPlanPartition ? _prefs.begin(kPlanNamespace, readOnly, kPlanPartition) : _prefs.begin(kPlanNamespace, readOnly);
}

std::string HardwareEsp32::loadString(const char *key, const std::string &def) {
  if (!beginStorage() || !openConfig(true)) return def; // lazy: addComponent() reads names before begin()
  std::string out = def;
  if (_prefs.isKey(key)) {
    const String v = _prefs.getString(key, def.c_str());
    out = std::string(v.c_str());
  }
  _prefs.end();
  return out;
}

bool HardwareEsp32::saveString(const char *key, const std::string &value) {
  if (!beginStorage() || !openConfig(false)) return false;
  const size_t written = _prefs.putString(key, value.c_str());
  _prefs.end();
  return written == value.size() || written == value.size() + 1;
}

bool HardwareEsp32::NvsBlobs::read(const char *key, std::string &out) {
  if (!_owner._storageReady || !_owner.openPlans(true)) return false;
  bool ok = false;
  if (_owner._prefs.isKey(key)) {
    const size_t size = _owner._prefs.getBytesLength(key);
    if (size > 0 && size <= EscapeConfig::MAX_PLAN_SKELETON_LEN + 512) {
      std::string tmp(size, '\0');
      if (_owner._prefs.getBytes(key, &tmp[0], size) == size) {
        out.swap(tmp);
        ok = true;
      }
    }
  }
  _owner._prefs.end();
  return ok;
}

bool HardwareEsp32::NvsBlobs::write(const char *key, const std::string &data) {
  if (!_owner._storageReady || !_owner.openPlans(false)) return false;
  // putBytes replaces the old value only after the new one is written, so a power loss
  // keeps the previous skeleton (no remove-then-write window).
  const bool ok = _owner._prefs.putBytes(key, data.data(), data.size()) == data.size();
  _owner._prefs.end();
  return ok;
}

bool HardwareEsp32::NvsBlobs::erase(const char *key) {
  if (!_owner._storageReady || !_owner.openPlans(false)) return false;
  const bool ok = _owner._prefs.remove(key);
  _owner._prefs.end();
  return ok;
}

bool HardwareEsp32::clearAllStorage() {
  bool ok = true;
  if (!_storageReady) return false;
  const char *namespaces[2] = {kConfigNamespace, kPlanNamespace};
  for (int p = 0; p < 2; p++) {           // default NVS and, if present, the plan partition
    if (p == 1 && !_hasPlanPartition) break;
    for (int n = 0; n < 2; n++) {
      const bool opened = p == 0 ? _prefs.begin(namespaces[n], false) : _prefs.begin(namespaces[n], false, kPlanPartition);
      if (!opened) continue;
      ok = _prefs.clear() && ok;
      _prefs.end();
    }
  }
  return ok;
}

bool HardwareEsp32::loadToken(std::string &token, Escape::TokenState &state) {
  token = EscapeConfig::AUTH_TOKEN;
  state = Escape::TokenState::Default;
  if (!beginStorage()) return true; // no NVS at all: nothing could have been provisioned
  if (!openConfig(true)) {
    // The namespace exists (created in beginStorage) but cannot be read: do not guess.
    state = Escape::TokenState::Invalid;
    return false;
  }
  const bool present = _prefs.isKey(kTokenKey);
  std::string stored;
  if (present) {
    const String v = _prefs.getString(kTokenKey, "");
    stored = std::string(v.c_str());
  }
  _prefs.end();
  if (!present) return true;
  if (!printableToken(stored)) {
    state = Escape::TokenState::Invalid; // stored but unusable: stay read-only, never fall back silently
    return false;
  }
  token = stored;
  state = Escape::TokenState::Custom;
  return true;
}

// ---- Identity --------------------------------------------------------------------------------

std::string HardwareEsp32::deviceId() const {
  uint8_t mac[6] = {0};
  esp_read_mac(mac, ESP_MAC_WIFI_STA);
  bool unusable = true;
  for (int i = 0; i < 6; i++) unusable = unusable && (mac[i] == 0x00 || mac[i] == 0xFF);
  if (unusable) { // defective radio: fall back to the factory eFuse MAC
    const uint64_t efuse = ESP.getEfuseMac();
    for (int i = 0; i < 6; i++) mac[i] = (uint8_t)(efuse >> (8 * (5 - i)));
  }
  char text[13];
  snprintf(text, sizeof(text), "%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return std::string(text);
}

uint32_t HardwareEsp32::nextBootCounter() {
  uint32_t value = esp_random();
  if (_storageReady && openConfig(false)) {
    const uint32_t previous = _prefs.getUInt(kBootKey, 0);
    value = previous + 1;
    if (_prefs.putUInt(kBootKey, value) == 0) value = esp_random();
    _prefs.end();
  }
  return value ? value : 1;
}

// ---- Wi-Fi -------------------------------------------------------------------------------------

bool HardwareEsp32::loadWifiCredentials(std::string &ssid, std::string &password) {
  ssid = loadString("wifi_ssid", "");
  password = loadString("wifi_pass", "");
  if (ssid.empty()) { // fall back to build-time credentials
    ssid = EscapeConfig::WIFI_SSID;
    password = EscapeConfig::WIFI_PASSWORD;
  }
  return !ssid.empty();
}

bool HardwareEsp32::wifiConnected() const { return WiFi.status() == WL_CONNECTED; }

// True when the host program already brought the Wi-Fi station up itself. After a power cycle the
// driver does not initialise Wi-Fi on its own, so the STA mode bit is only set if the host touched
// Wi-Fi (WiFi.mode()/WiFi.begin()) before the library started.
bool HardwareEsp32::hostConfiguredStation() {
  if (!(WiFi.getMode() & WIFI_MODE_STA)) return false;
  if (WiFi.status() == WL_CONNECTED) return true;
  wifi_config_t config;
  memset(&config, 0, sizeof(config));
  if (esp_wifi_get_config(WIFI_IF_STA, &config) != ESP_OK) return false;
  return config.sta.ssid[0] != 0;
}

void HardwareEsp32::startWifi() {
  if (_wifiStarted) return;
  _wifiStarted = true;
  // Wi-Fi owned by the host program: it already initialised the station AND configured it
  // (connected, or an SSID set through WiFi.begin() even if the link is not up yet). Looking at
  // WiFi.SSID() would not do: it only reports the AP of an already ESTABLISHED connection, so a
  // host that just called WiFi.begin() would be mistaken for "nobody manages Wi-Fi" and the
  // library would override its connection with its own credentials.
  if (hostConfiguredStation()) {
    _wifiOwned = false;
    logLine("EscapeManager: using the host program's Wi-Fi connection");
    return;
  }
  _wifiOwned = true;
  WiFi.persistent(false); // keep our credentials in OUR namespace; the driver must not store a copy
  WiFi.mode(WIFI_STA);
  char hostname[24];
  const std::string id = deviceId();
  snprintf(hostname, sizeof(hostname), "escape-%s", id.substr(8).c_str());
  WiFi.setHostname(hostname);
  // Radio always on (library-owned Wi-Fi only). With the default modem sleep the first request after a
  // quiet moment waits for the next beacon: measured on two ESP32 boards, a median of 244 ms / 48 ms
  // versus 49 ms / 34 ms with the radio on. Battery-powered devices opt out with -DESCAPE_WIFI_ALLOW_SLEEP.
  // A host that owns Wi-Fi decides for itself (WiFi.setSleep()).
#ifndef ESCAPE_WIFI_ALLOW_SLEEP
  WiFi.setSleep(false);
#endif
  if (loadWifiCredentials(_ssid, _password)) {
    Serial.printf("EscapeManager: connecting to Wi-Fi \"%s\" (background)\n", _ssid.c_str());
    WiFi.begin(_ssid.c_str(), _password.c_str());
  } else {
    logLine("EscapeManager: no Wi-Fi credentials (serial ESCAPE_WIFI, build flags) - waiting for the host program's Wi-Fi");
  }
  _lastWifiAttemptMs = Escape::nowMillis();
}

void HardwareEsp32::service(uint32_t nowMs) {
  if (_serialEnabled) pollSerial();
  const bool connected = wifiConnected();
  if (connected != _wasConnected) {
    _wasConnected = connected;
    if (connected) {
      Serial.printf("EscapeManager: Wi-Fi up, IP %s\n", WiFi.localIP().toString().c_str());
      _wifiBackoffMs = kWifiFirstBackoffMs;
    } else {
      logLine("EscapeManager: Wi-Fi link lost");
    }
  }
  if (!_wifiOwned || connected) return;
  // Library-owned link is down: retry with back-off (the driver's own auto-reconnect keeps
  // trying in between; this only recovers from a stuck state, e.g. wrong credentials fixed later).
  if (!_ssid.empty() && nowMs - _lastWifiAttemptMs >= _wifiBackoffMs) {
    _lastWifiAttemptMs = nowMs;
    if (_wifiBackoffMs < kWifiMaxBackoffMs) _wifiBackoffMs *= 2;
    WiFi.disconnect(false);
    WiFi.begin(_ssid.c_str(), _password.c_str());
  }
}

uint32_t HardwareEsp32::localIp() {
  if (!wifiConnected()) return 0;
  const IPAddress ip = WiFi.localIP();
  return ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
}

uint32_t HardwareEsp32::broadcastIp() {
  const IPAddress ip = WiFi.localIP(), mask = WiFi.subnetMask();
  uint32_t a = ((uint32_t)ip[0] << 24) | ((uint32_t)ip[1] << 16) | ((uint32_t)ip[2] << 8) | ip[3];
  uint32_t m = ((uint32_t)mask[0] << 24) | ((uint32_t)mask[1] << 16) | ((uint32_t)mask[2] << 8) | mask[3];
  if (m == 0) return 0xFFFFFFFFu;
  return a | ~m;
}

// ---- Serial provisioning -------------------------------------------------------------------------
// Commands (one per line, arguments base64 so no character can break the framing):
//   ESCAPE_AUTH_TOKEN <b64 token>        ESCAPE_WIFI <b64 ssid> <b64 password>
//   ESCAPE_RESET_STORAGE                 ESCAPE_INFO
// While provisioning is enabled (default) the library OWNS the serial input and consumes
// every received line (lines that are not commands are ignored). A host program that
// reads Serial itself must call EscapeComponent::setSerialProvisioning(false).

void HardwareEsp32::pollSerial() {
  int budget = 128; // bytes per call: never starve the host's loop
  while (budget-- > 0 && Serial.available() > 0) {
    const char c = (char)Serial.read();
    if (c == '\r') continue;
    if (c == '\n') {
      if (_lineOverflow) Serial.println("ESCAPE_ERROR command-too-long");
      else if (_lineLength) {
        _line[_lineLength] = '\0';
        if (_line[0] == 'E') processSerialLine(_line); // anything else is not a command
      }
      _lineLength = 0;
      _lineOverflow = false;
      continue;
    }
    if (_lineOverflow) continue;
    if (_lineLength + 1 >= sizeof(_line)) { _lineOverflow = true; continue; }
    _line[_lineLength++] = c;
  }
}

void HardwareEsp32::processSerialLine(const char *line) {
  if (strcmp(line, "ESCAPE_RESET_STORAGE") == 0) {
    if (!clearAllStorage()) { Serial.println("ESCAPE_RESET_STORAGE_ERROR storage"); return; }
    Serial.println("ESCAPE_RESET_STORAGE_OK");
    Serial.flush();
    delay(100);
    ESP.restart();
    return;
  }
  if (strcmp(line, "ESCAPE_INFO") == 0) {
    std::string token;
    Escape::TokenState state;
    loadToken(token, state);
    Serial.printf("ESCAPE_INFO_OK did=%s fw=%s proto=%u token=%s ip=%s heap=%u\n", deviceId().c_str(), EscapeVersion::FW,
                  (unsigned)EscapeVersion::PROTO, Escape::tokenStateName(state), WiFi.localIP().toString().c_str(),
                  (unsigned)ESP.getFreeHeap());
    return;
  }
  const char *tokenPrefix = "ESCAPE_AUTH_TOKEN ";
  if (strncmp(line, tokenPrefix, strlen(tokenPrefix)) == 0) {
    std::string token;
    if (!decodeBase64(line + strlen(tokenPrefix), token, EscapeConfig::MAX_AUTH_TOKEN_LEN)) { Serial.println("ESCAPE_AUTH_TOKEN_ERROR encoding"); return; }
    if (!printableToken(token)) { Serial.println("ESCAPE_AUTH_TOKEN_ERROR length-or-characters"); return; }
    if (!saveString(kTokenKey, token)) { Serial.println("ESCAPE_AUTH_TOKEN_ERROR storage"); return; }
    Serial.println("ESCAPE_AUTH_TOKEN_OK"); // never echo the token
    Serial.flush();
    delay(100);
    ESP.restart();
    return;
  }
  const char *wifiPrefix = "ESCAPE_WIFI ";
  if (strncmp(line, wifiPrefix, strlen(wifiPrefix)) == 0) {
    char copy[sizeof(_line)];
    strncpy(copy, line + strlen(wifiPrefix), sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    char *space = strchr(copy, ' ');
    std::string ssid, pass;
    if (!space) { Serial.println("ESCAPE_WIFI_ERROR format"); return; }
    *space = '\0';
    if (!decodeBase64(copy, ssid, 32) || ssid.empty() || (space[1] && !decodeBase64(space + 1, pass, 63))) {
      Serial.println("ESCAPE_WIFI_ERROR encoding");
      return;
    }
    if (!saveString("wifi_ssid", ssid) || !saveString("wifi_pass", pass)) { Serial.println("ESCAPE_WIFI_ERROR storage"); return; }
    Serial.println("ESCAPE_WIFI_OK");
    Serial.flush();
    delay(100);
    ESP.restart();
  }
}
