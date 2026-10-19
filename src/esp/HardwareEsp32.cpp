#include "HardwareEsp32.hpp"

#include "../net/Clock.hpp"
#include "../protocol/EscapeConfig.hpp"
#include "../protocol/EscapeVersion.hpp"
#include "SketchConfig.hpp"

#include <WiFi.h>
#include <esp_mac.h>
#include <esp_partition.h>
#include <esp_system.h>
#include <esp_wifi.h>
#include <mbedtls/base64.h>
#include <nvs_flash.h>

#include <cstring>

namespace {

const char *kConfigNamespace = "escfg";   // names, rooms, riddle ids, component plan slices, tokens, Wi-Fi
const char *kPlanNamespace = "escplan";   // plan skeleton blobs
const char *kPlanPartition = "plan_nvs";  // optional dedicated partition (see partitions.csv)
const char *kTokenKey = "authtoken";
const char *kEditTokenKey = "edittoken";
const char *kBootKey = "boot";
const char *kWifiSsidKey = "wifi_ssid";
const char *kWifiPassKey = "wifi_pass";
const char *kWifiOldSsidKey = "wifi_old_ssid";   // fallback while a pushed Wi-Fi is on probation
const char *kWifiOldPassKey = "wifi_old_pass";
const char *kWifiTrialKey = "wifi_try";

const uint32_t kWifiFirstBackoffMs = 15000;
const uint32_t kWifiMaxBackoffMs = 60000;
const uint32_t kSetupRetryMs = 20000;            // station retries while the setup network is up ...
const uint32_t kSetupRetryWithClientMs = 60000;  // ... and rarer while someone is connected to it (scans move the radio)
const uint32_t kForcedSetupMs = 10 * 60 * 1000;  // BOOT button: stays this long
const uint32_t kFailTextAfterMs = 3000;          // a status older than this belongs to the current attempt
const uint32_t kStillConnectingMs = 20000;
const uint32_t kRestartDelayMs = 100;
#ifndef ESCAPE_SETUP_AP_AFTER_LOSS_MS
#define ESCAPE_SETUP_AP_AFTER_LOSS_MS 180000
#endif
// A link that was up and went away (router reboot) opens the setup network only after this much longer
// than a connection that never came up at all: an outage should not turn every device into a setup target.
const uint32_t kSetupAfterLossMs = ESCAPE_SETUP_AP_AFTER_LOSS_MS;

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

// The BOOT button's pin: GPIO0 on ESP32/S2/S3, GPIO9 on the RISC-V chips. A pin that the host program may use for something
// else must not be touched without being asked, so only the BOOT pin is a default (and it is only read, with a pull-up).
int resolveButtonPin(int configured) {
  if (configured != -2) return configured;
#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32C6 || CONFIG_IDF_TARGET_ESP32H2
  return 9;
#else
  return 0;
#endif
}

bool due(uint32_t now, uint32_t deadline) { return (int32_t)(now - deadline) >= 0; }

// Stations connected to the setup network, kept by Wi-Fi events. (WiFi.softAPgetStationNum() takes the driver's
// lock and then blocks for the whole 0.5 s of every station scan: measured on hardware, it would stall the host's
// loop() at every reconnect attempt.)
volatile int g_apStations = 0;
void onApStation(arduino_event_id_t event) {
  if (event == ARDUINO_EVENT_WIFI_AP_STACONNECTED) g_apStations = g_apStations + 1;
  else if (event == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED && g_apStations > 0) g_apStations = g_apStations - 1;
}

const char *phaseName(Escape::WifiPhase p) {
  switch (p) {
    case Escape::WifiPhase::Connecting: return "connecting";
    case Escape::WifiPhase::Connected: return "connected";
    case Escape::WifiPhase::Failed: return "failed";
    case Escape::WifiPhase::Idle:
    default: return "idle";
  }
}

} // namespace

HardwareEsp32::HardwareEsp32()
    : _skeleton(*this), _storageReady(false), _hasPlanPartition(false), _wifiStarted(false), _wifiOwned(false),
      _hostManaged(EscapeConfig::HOST_MANAGED_WIFI), _apPassword(EscapeConfig::SETUP_AP_PASSWORD), _apBlocked(false),
      _buttonPin(resolveButtonPin(EscapeConfig::SETUP_BUTTON_PIN)), _wifiSource("none"), _serialEnabled(true), _wasConnected(false), _retryArmed(false),
      _nextRetryMs(0), _wifiBackoffMs(kWifiFirstBackoffMs), _attemptArmed(false), _attemptStartMs(0), _lostArmed(false),
      _lostSinceMs(0), _everConnected(false), _reconnectArmed(false), _reconnectAtMs(0), _trialActive(false),
      _trialStartMs(0), _apUp(false), _apAuto(false), _lingerArmed(false), _lingerUntilMs(0), _forcedArmed(false), _forcedUntilMs(0),
      _apClients(0), _buttonArmed(false), _buttonWindowEndMs(0), _buttonDown(false), _buttonDownMs(0),
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

bool HardwareEsp32::removeString(const char *key) {
  if (!beginStorage() || !openConfig(false)) return false;
  const bool ok = !_prefs.isKey(key) || _prefs.remove(key);
  _prefs.end();
  return ok;
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

// Reads a stored token. present = the key exists, valid = it is usable. No NVS at all counts as "nothing
// provisioned"; an unreadable namespace is reported as present+invalid (never guess).
bool HardwareEsp32::loadStoredToken(const char *key, std::string &token, bool &present, bool &valid) {
  present = false;
  valid = true;
  token.clear();
  if (!beginStorage()) return true;
  if (!openConfig(true)) {
    present = true;
    valid = false;
    return false;
  }
  present = _prefs.isKey(key);
  if (present) {
    const String v = _prefs.getString(key, "");
    token = std::string(v.c_str());
  }
  _prefs.end();
  if (present && !printableToken(token)) {
    valid = false;
    token.clear();
  }
  return valid;
}

bool HardwareEsp32::loadToken(std::string &token, Escape::TokenState &state) {
  bool present = false, valid = true;
  std::string stored;
  loadStoredToken(kTokenKey, stored, present, valid);
  if (present) {
    if (!valid) { // stored but unusable: stay read-only, never fall back silently
      token.clear();
      state = Escape::TokenState::Invalid;
      return false;
    }
    token = stored;
    state = Escape::TokenState::Custom;
    return true;
  }
  const Escape::SketchConfig &sketch = Escape::SketchConfig::get();
  if (sketch.authInvalid) { // given by the sketch but unusable: read-only, never the public default
    token.clear();
    state = Escape::TokenState::Invalid;
    return false;
  }
  const char *given = !sketch.authToken.empty() ? sketch.authToken.c_str() : EscapeConfig::BUILD_AUTH_TOKEN; // sketch, then build
  if (given[0]) {
    token = given;
    state = token == EscapeConfig::AUTH_TOKEN ? Escape::TokenState::Default : Escape::TokenState::Custom;
    return true;
  }
  token = EscapeConfig::AUTH_TOKEN;
  state = Escape::TokenState::Default;
  return true;
}

bool HardwareEsp32::loadEditToken(std::string &token, Escape::EditState &state) {
  bool present = false, valid = true;
  std::string stored;
  loadStoredToken(kEditTokenKey, stored, present, valid);
  if (present) {
    if (!valid) {
      token.clear();
      state = Escape::EditState::Invalid;
      return false;
    }
    token = stored;
    state = Escape::EditState::Custom;
    return true;
  }
  const Escape::SketchConfig &sketch = Escape::SketchConfig::get();
  if (sketch.editInvalid) { // given by the sketch but unusable: plan sending stays locked
    token.clear();
    state = Escape::EditState::Invalid;
    return false;
  }
  const char *given = !sketch.editToken.empty() ? sketch.editToken.c_str() : EscapeConfig::BUILD_EDIT_TOKEN;
  if (given[0]) {
    token = given;
    state = Escape::EditState::Custom;
    return true;
  }
  token.clear();
  state = Escape::EditState::Unset;
  return true;
}

void HardwareEsp32::currentTokens(Escape::SetupTokens &out) {
  loadToken(out.token, out.tokenState);
  loadEditToken(out.editToken, out.editState);
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

// Stored credentials win over the build flags. Empty SSID = none.
bool HardwareEsp32::loadWifiCredentials(std::string &ssid, std::string &password) {
  ssid = loadString(kWifiSsidKey, "");
  password = loadString(kWifiPassKey, "");
  if (!ssid.empty()) { _wifiSource = "stored"; return true; }
  const Escape::SketchConfig &sketch = Escape::SketchConfig::get();
  if (!sketch.wifiSsid.empty()) { // from the sketch (#define / setWifi())
    ssid = sketch.wifiSsid;
    password = sketch.wifiPassword;
    _wifiSource = "sketch";
    return true;
  }
  ssid = EscapeConfig::WIFI_SSID; // from the build (secrets.ini)
  password = EscapeConfig::WIFI_PASSWORD;
  _wifiSource = "build";
  return !ssid.empty();
}

void HardwareEsp32::applySketchConfig() {
  const Escape::SketchConfig &sketch = Escape::SketchConfig::get();
  _hostManaged = _hostManaged || sketch.hostManagedWifi;
  _apPassword = !sketch.setupApPassword.empty() ? sketch.setupApPassword : std::string(EscapeConfig::SETUP_AP_PASSWORD); // sketch wins over the build flag
  _apBlocked = sketch.setupApInvalid;
  if (sketch.buttonPinSet) _buttonPin = sketch.buttonPin;
}

bool HardwareEsp32::wifiConnected() const { return WiFi.status() == WL_CONNECTED; }

void HardwareEsp32::startWifi() {
  if (_wifiStarted) return;
  _wifiStarted = true;
  applySketchConfig();
  const Escape::SketchConfig &sketch = Escape::SketchConfig::get();
  if (_hostManaged) {
    // The host program owns the radio (ESCAPE_HOST_MANAGED_WIFI): the library does not touch it at all.
    _wifiOwned = false;
    logLine("EscapeManager: Wi-Fi is managed by the host program (no connection handling, no setup network)");
    return;
  }
  _wifiOwned = true;
  WiFi.persistent(false); // keep our credentials in OUR namespace; the driver must not store a copy
  WiFi.mode(WIFI_STA);
  char hostname[24];
  const std::string id = deviceId();
  snprintf(hostname, sizeof(hostname), "escape-%s", id.substr(8).c_str());
  WiFi.setHostname(hostname);
  // Radio always on. With the default modem sleep the first request after a quiet moment waits for the
  // next beacon: measured on two ESP32 boards, a median of 244 ms / 48 ms versus 49 ms / 34 ms with the radio
  // on. Battery-powered devices opt out with -DESCAPE_WIFI_ALLOW_SLEEP.
  bool allowSleep = sketch.allowWifiSleep;
#ifdef ESCAPE_WIFI_ALLOW_SLEEP
  allowSleep = true;
#endif
  if (!allowSleep) WiFi.setSleep(false);
  const uint32_t now = Escape::nowMillis();
  _lostSinceMs = now; // "not connected since start": the setup network opens SETUP_AP_AFTER_MS from now
  _lostArmed = true;
  _trialActive = loadString(kWifiTrialKey, "") == "1"; // a pushed Wi-Fi was still on probation when we stopped
  _trialStartMs = now;
  if (loadWifiCredentials(_ssid, _password)) {
    Serial.printf("EscapeManager: connecting to Wi-Fi \"%s\" (%s, background)\n", _ssid.c_str(), _wifiSource);
    connectStation(now);
  } else {
    logLine("EscapeManager: no Wi-Fi credentials - opening the setup network (also: serial ESCAPE_WIFI, build flags)");
  }
  if (_apBlocked) logLine("EscapeManager: the setup network password is invalid - the setup network will NOT be opened");
  if (_buttonPin >= 0) {
    pinMode(_buttonPin, INPUT_PULLUP);
    _buttonArmed = true;
    _buttonWindowEndMs = now + EscapeConfig::SETUP_BUTTON_WINDOW_MS;
  }
}

void HardwareEsp32::connectStation(uint32_t nowMs) {
  _attemptStartMs = nowMs;
  _attemptArmed = true;
  WiFi.begin(_ssid.c_str(), _password.c_str());
}

// ---- Fallback for pushed Wi-Fi credentials ----------------------------------------------------------

void HardwareEsp32::commitWifiTrial() {
  _trialActive = false;
  removeString(kWifiTrialKey);
  removeString(kWifiOldSsidKey);
  removeString(kWifiOldPassKey);
}

void HardwareEsp32::rollbackWifiTrial(uint32_t nowMs) {
  _trialActive = false;
  const std::string oldSsid = loadString(kWifiOldSsidKey, ""), oldPass = loadString(kWifiOldPassKey, "");
  removeString(kWifiTrialKey);
  removeString(kWifiOldSsidKey);
  removeString(kWifiOldPassKey);
  if (oldSsid.empty()) return; // nothing to go back to
  saveString(kWifiSsidKey, oldSsid);
  saveString(kWifiPassKey, oldPass);
  _ssid = oldSsid;
  _password = oldPass;
  Serial.printf("EscapeManager: the new Wi-Fi did not connect - back to \"%s\"\n", _ssid.c_str());
  WiFi.disconnect(false);
  connectStation(nowMs);
  _lostSinceMs = nowMs;
  _lostArmed = true;
}

// ---- Setup network (access point with the configuration form) --------------------------------------------

void HardwareEsp32::startSetupNetwork(uint32_t nowMs) {
  (void)nowMs;
  _apName = Escape::setupNetworkName(deviceId(), _ssid);
  const char *password = _apPassword.empty() ? nullptr : _apPassword.c_str(); // empty = open
  g_apStations = 0;
  static bool eventsRegistered = false; // the callbacks are trivial: register once, keep them
  if (!eventsRegistered) {
    eventsRegistered = true;
    WiFi.onEvent(onApStation, ARDUINO_EVENT_WIFI_AP_STACONNECTED);
    WiFi.onEvent(onApStation, ARDUINO_EVENT_WIFI_AP_STADISCONNECTED);
  }
  WiFi.mode(WIFI_AP_STA); // the station keeps trying
  const uint32_t apIp = EscapeConfig::SETUP_AP_IP;
  const IPAddress ip((uint8_t)(apIp >> 24), (uint8_t)(apIp >> 16), (uint8_t)(apIp >> 8), (uint8_t)apIp), mask(255, 255, 255, 0);
  WiFi.softAPConfig(ip, ip, mask);
  if (!WiFi.softAP(_apName.c_str(), password, 1, 0, 2)) {
    logLine("EscapeManager: could not start the setup network");
    WiFi.mode(WIFI_STA);
    return;
  }
  _apUp = true;
  _lingerArmed = false;
  _apClients = 0;
  Serial.printf("EscapeManager: setup network \"%s\" (%s) - open http://%s after joining it\n", _apName.c_str(),
                password ? "WPA2" : "open", ip.toString().c_str());
}

void HardwareEsp32::stopSetupNetwork() {
  if (!_apUp) return;
  WiFi.softAPdisconnect(true);
  g_apStations = 0;
  _apUp = false;
  _apAuto = false;
  _lingerArmed = false;
  _forcedArmed = false;
  WiFi.setAutoReconnect(true);
  logLine("EscapeManager: setup network closed");
}

// Opens the setup network when the station cannot connect (no credentials, or no connection for
// SETUP_AP_AFTER_MS - after an established link was lost: kSetupAfterLossMs) or when the BOOT button asked
// for it, and closes it again SETUP_AP_LINGER_MS after the station connected.
void HardwareEsp32::serviceSetupNetwork(uint32_t nowMs, bool connected) {
  const bool noCredentials = _ssid.empty();
  const uint32_t threshold = _everConnected ? kSetupAfterLossMs : EscapeConfig::SETUP_AP_AFTER_MS;
  const bool timedOut = _lostArmed && (uint32_t)(nowMs - _lostSinceMs) >= threshold;
  // Once opened for lack of a connection the network stays until the station connects (new credentials
  // restart the clock but must not close it under the user's hands).
  if (!connected && (noCredentials || timedOut)) _apAuto = true;
  if (connected) _apAuto = false;
  if (_forcedArmed && due(nowMs, _forcedUntilMs)) _forcedArmed = false;
  const bool wanted = _apAuto || _forcedArmed;

  if (wanted && !_apUp && !_apBlocked) startSetupNetwork(nowMs);
  if (!_apUp) return;

  if (wanted) {
    _lingerArmed = false;
  } else {
    if (!_lingerArmed) {
      _lingerArmed = true;
      _lingerUntilMs = nowMs + EscapeConfig::SETUP_AP_LINGER_MS;
    }
    if (due(nowMs, _lingerUntilMs)) stopSetupNetwork();
  }
  // A station address inside the setup subnet would make every LAN client look like a setup client.
  if (_apUp && connected) {
    const uint32_t sta = localIp();
    if ((sta & 0xFFFFFF00u) == (EscapeConfig::SETUP_AP_IP & 0xFFFFFF00u)) stopSetupNetwork();
  }
  if (_apUp) {
    // Scans for the router move the radio and disturb a phone that is just filling in the form: while
    // someone is connected, the driver's own reconnect loop is off and our retries are rarer.
    const int clients = g_apStations;
    if (clients != _apClients) {
      _apClients = clients;
      WiFi.setAutoReconnect(clients == 0);
    }
  }
}

// BOOT button pressed for SETUP_BUTTON_HOLD_MS within SETUP_BUTTON_WINDOW_MS after start. (Holding it while
// RESETTING enters the flash bootloader instead - press it after the board has started.)
void HardwareEsp32::serviceButton(uint32_t nowMs) {
  if (!_buttonArmed) return;
  if (due(nowMs, _buttonWindowEndMs)) {
    _buttonArmed = false;
    return;
  }
  const bool pressed = digitalRead(_buttonPin) == LOW;
  if (!pressed) {
    _buttonDown = false;
    return;
  }
  if (!_buttonDown) {
    _buttonDown = true;
    _buttonDownMs = nowMs;
    return;
  }
  if ((uint32_t)(nowMs - _buttonDownMs) >= EscapeConfig::SETUP_BUTTON_HOLD_MS) {
    _buttonArmed = false;
    _forcedArmed = true;
    _forcedUntilMs = nowMs + kForcedSetupMs;
    logLine("EscapeManager: BOOT button - opening the setup network");
  }
}

uint32_t HardwareEsp32::retryIntervalMs() {
  if (_apUp) return _apClients > 0 ? kSetupRetryWithClientMs : kSetupRetryMs;
  return _wifiBackoffMs;
}

void HardwareEsp32::service(uint32_t nowMs) {
  if (_serialEnabled) pollSerial();
  if (!_wifiOwned) return; // host-managed Wi-Fi: nothing of ours to supervise

  const bool connected = wifiConnected();
  if (connected != _wasConnected) {
    _wasConnected = connected;
    if (connected) {
      Serial.printf("EscapeManager: Wi-Fi up, IP %s\n", WiFi.localIP().toString().c_str());
      _wifiBackoffMs = kWifiFirstBackoffMs;
      _everConnected = true;
      _lostArmed = false;
      _retryArmed = false;
      if (_trialActive) commitWifiTrial();
    } else {
      logLine("EscapeManager: Wi-Fi link lost");
      _lostSinceMs = nowMs;
      _lostArmed = true;
    }
  }

  serviceButton(nowMs);

  // A network push changed the Wi-Fi: reconnect shortly after, so the HTTP answer leaves first.
  if (_reconnectArmed && due(nowMs, _reconnectAtMs)) {
    _reconnectArmed = false;
    WiFi.disconnect(false);
    if (!_ssid.empty()) connectStation(nowMs);
    _retryArmed = false;
    _wifiBackoffMs = kWifiFirstBackoffMs;
  }
  if (_trialActive && !connected && (uint32_t)(nowMs - _trialStartMs) >= EscapeConfig::WIFI_TRY_MS) rollbackWifiTrial(nowMs);

  serviceSetupNetwork(nowMs, connected);
  if (connected || _ssid.empty()) return;

  // The link is down: retry with back-off (the driver's own auto-reconnect keeps trying in between; this
  // only recovers from a stuck state, e.g. wrong credentials fixed later).
  if (!_retryArmed) {
    _retryArmed = true;
    _nextRetryMs = nowMs + retryIntervalMs();
  } else if (due(nowMs, _nextRetryMs)) {
    if (!_apUp && _wifiBackoffMs < kWifiMaxBackoffMs) _wifiBackoffMs *= 2;
    _nextRetryMs = nowMs + retryIntervalMs();
    WiFi.disconnect(false);
    connectStation(nowMs);
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

bool HardwareEsp32::isSetupClient(uint32_t ip) {
  return _apUp && (ip & 0xFFFFFF00u) == (EscapeConfig::SETUP_AP_IP & 0xFFFFFF00u);
}

// ---- SetupSink -------------------------------------------------------------------------------------------------

const char *HardwareEsp32::setupApMode() const {
  if (_hostManaged || _apBlocked) return "none";
  return _apPassword.empty() ? "open" : "wpa2";
}

Escape::WifiPhase HardwareEsp32::wifiPhase() const {
  if (_hostManaged) return wifiConnected() ? Escape::WifiPhase::Connected : Escape::WifiPhase::Idle;
  if (wifiConnected()) return Escape::WifiPhase::Connected;
  if (_ssid.empty()) return Escape::WifiPhase::Idle;
  const uint32_t age = _attemptArmed ? (uint32_t)(Escape::nowMillis() - _attemptStartMs) : 0;
  const wl_status_t status = WiFi.status();
  if (age >= kFailTextAfterMs && (status == WL_NO_SSID_AVAIL || status == WL_CONNECT_FAILED)) return Escape::WifiPhase::Failed;
  return age < kStillConnectingMs ? Escape::WifiPhase::Connecting : Escape::WifiPhase::Failed;
}

std::string HardwareEsp32::wifiAddress() const { return std::string(WiFi.localIP().toString().c_str()); }

const char *HardwareEsp32::wifiFailReason() const {
  switch (WiFi.status()) {
    case WL_NO_SSID_AVAIL: return "Netz nicht gefunden";
    case WL_CONNECT_FAILED: return "Passwort falsch?";
    default: return "keine Verbindung";
  }
}

// Persists a change from POST /setup or the portal form. Wi-Fi: applied shortly afterwards (the answer must
// leave first); a network push keeps the previous Wi-Fi as fallback for WIFI_TRY_MS. Tokens: stored; the
// Device re-derives its keys right after (currentTokens()).
Escape::SetupResult HardwareEsp32::applySetup(const Escape::SetupChange &change, bool viaNetwork) {
  if (change.hasWifi && (_hostManaged || !_wifiOwned)) return Escape::SetupResult::Invalid; // not ours to change
  const uint32_t now = Escape::nowMillis();
  if (change.hasToken) {
    const bool ok = change.token.empty() ? removeString(kTokenKey) : saveString(kTokenKey, change.token);
    if (!ok) return Escape::SetupResult::Storage;
  }
  if (change.hasEditToken) {
    const bool ok = change.editToken.empty() ? removeString(kEditTokenKey) : saveString(kEditTokenKey, change.editToken);
    if (!ok) return Escape::SetupResult::Storage;
  }
  if (change.hasWifi) {
    std::string oldSsid, oldPass;
    const bool haveOld = loadWifiCredentials(oldSsid, oldPass) && !_trialActive; // a trial in progress keeps ITS fallback
    if (!saveString(kWifiSsidKey, change.ssid) || !saveString(kWifiPassKey, change.pass)) return Escape::SetupResult::Storage;
    if (viaNetwork && (haveOld || _trialActive)) {
      if (haveOld) {
        saveString(kWifiOldSsidKey, oldSsid);
        saveString(kWifiOldPassKey, oldPass);
      }
      saveString(kWifiTrialKey, "1");
      _trialActive = true;
      _trialStartMs = now; // 30 s probation, counted from now (the reconnect follows in 700 ms)
    } else {
      commitWifiTrial();
    }
    _ssid = change.ssid;
    _password = change.pass;
    _reconnectArmed = true;
    _reconnectAtMs = now + 700;
    _lostSinceMs = now;
    _lostArmed = true;
    if (WiFi.status() != WL_CONNECTED) _attemptArmed = false; // phase = "connecting" until the new attempt starts
  }
  Serial.println("EscapeManager: settings changed (setup)"); // never print the values
  return Escape::SetupResult::Ok;
}

// ---- Serial provisioning -------------------------------------------------------------------------
// Commands (one per line, arguments base64 so no character can break the framing):
//   ESCAPE_AUTH_TOKEN <b64 token>        ESCAPE_EDIT_TOKEN <b64 token>
//   ESCAPE_CLEAR_AUTH_TOKEN              ESCAPE_CLEAR_EDIT_TOKEN
//   ESCAPE_WIFI <b64 ssid> <b64 password>
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
    delay(kRestartDelayMs);
    ESP.restart();
    return;
  }
  if (strcmp(line, "ESCAPE_INFO") == 0) {
    std::string token, editToken;
    Escape::TokenState state;
    Escape::EditState editState;
    loadToken(token, state);
    loadEditToken(editToken, editState);
    Serial.printf("ESCAPE_INFO_OK did=%s fw=%s proto=%u token=%s edit=%s ip=%s heap=%u wifi=%s setup=%s ap=%s ssid=%s\n",
                  deviceId().c_str(), EscapeVersion::FW, (unsigned)EscapeVersion::PROTO, Escape::tokenStateName(state),
                  Escape::editStateName(editState), WiFi.localIP().toString().c_str(), (unsigned)ESP.getFreeHeap(),
                  phaseName(wifiPhase()), _hostManaged ? "host" : setupApMode(), _apUp ? "up" : "down", _ssid.c_str());
    return;
  }
  // Token commands. They end with a restart (the key schedule is derived once at start-up); never echo the value.
  struct TokenCommand { const char *prefix; const char *name; const char *key; bool edit; };
  static const TokenCommand kTokenCommands[2] = {
      {"ESCAPE_AUTH_TOKEN ", "ESCAPE_AUTH_TOKEN", kTokenKey, false},
      {"ESCAPE_EDIT_TOKEN ", "ESCAPE_EDIT_TOKEN", kEditTokenKey, true}};
  for (size_t i = 0; i < 2; i++) {
    const TokenCommand &c = kTokenCommands[i];
    if (strncmp(line, c.prefix, strlen(c.prefix)) != 0) continue;
    std::string token;
    if (!decodeBase64(line + strlen(c.prefix), token, EscapeConfig::MAX_AUTH_TOKEN_LEN)) { Serial.printf("%s_ERROR encoding\n", c.name); return; }
    if (!printableToken(token)) { Serial.printf("%s_ERROR length-or-characters\n", c.name); return; }
    if (!saveString(c.key, token)) { Serial.printf("%s_ERROR storage\n", c.name); return; }
    Serial.printf("%s_OK\n", c.name);
    Serial.flush();
    delay(kRestartDelayMs);
    ESP.restart();
    return;
  }
  if (strcmp(line, "ESCAPE_CLEAR_AUTH_TOKEN") == 0 || strcmp(line, "ESCAPE_CLEAR_EDIT_TOKEN") == 0) {
    const bool edit = line[13] == 'E'; // ESCAPE_CLEAR_<E>DIT / <A>UTH
    const char *name = edit ? "ESCAPE_CLEAR_EDIT_TOKEN" : "ESCAPE_CLEAR_AUTH_TOKEN";
    if (!removeString(edit ? kEditTokenKey : kTokenKey)) { Serial.printf("%s_ERROR storage\n", name); return; }
    Serial.printf("%s_OK\n", name);
    Serial.flush();
    delay(kRestartDelayMs);
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
    if (!decodeBase64(copy, ssid, EscapeConfig::WIFI_SSID_MAX_LEN) || ssid.empty() ||
        (space[1] && !decodeBase64(space + 1, pass, EscapeConfig::WIFI_PASSWORD_MAX_LEN))) {
      Serial.println("ESCAPE_WIFI_ERROR encoding");
      return;
    }
    if (Escape::isSetupNetworkName(ssid)) { Serial.println("ESCAPE_WIFI_ERROR setup-network"); return; }
    commitWifiTrial(); // serial = physical access: no fallback, forget any probation
    if (!saveString(kWifiSsidKey, ssid) || !saveString(kWifiPassKey, pass)) { Serial.println("ESCAPE_WIFI_ERROR storage"); return; }
    Serial.println("ESCAPE_WIFI_OK");
    Serial.flush();
    delay(kRestartDelayMs);
    ESP.restart();
  }
}
