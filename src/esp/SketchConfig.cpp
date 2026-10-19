#include "SketchConfig.hpp"

#include "../protocol/Setup.hpp"

#include <Arduino.h>

namespace Escape {

SketchConfig &SketchConfig::get() {
  static SketchConfig instance; // function-local: safe against the unspecified order of static initialisers
  return instance;
}

void SketchConfig::complain(const char *what, const char *why) {
  char line[160];
  snprintf(line, sizeof(line), "EscapeManager: %s refused: %s\n", what, why);
  if (deferred) pending += line;
  else Serial.print(line);
}

void SketchConfig::lock() {
  locked = true;
  if (!pending.empty()) {
    Serial.print(pending.c_str());
    pending.clear();
  }
}

bool SketchConfig::setWifi(const char *ssid, const char *password) {
  if (locked) { complain("setWifi()", "begin() was already called"); return false; }
  const std::string s = ssid ? ssid : "", p = password ? password : "";
  if (!validWifiSsid(s)) { complain("Wi-Fi name", "1..32 characters, no control characters"); return false; }
  if (isSetupNetworkName(s)) { complain("Wi-Fi name", "a setup network cannot be used as the Wi-Fi to join"); return false; }
  if (!validWifiPassword(p)) { complain("Wi-Fi password", "empty (open network) or 8..63 characters"); return false; }
  wifiSsid = s;
  wifiPassword = p;
  return true;
}

bool SketchConfig::setAuthToken(const char *token) {
  if (locked) { complain("setAuthToken()", "begin() was already called"); return false; }
  const std::string t = token ? token : "";
  if (t.empty()) { authToken.clear(); authInvalid = false; return true; } // back to "not given"
  if (!validSetupToken(t)) {
    authInvalid = true; // given but unusable: the device stays read-only instead of using the public default
    complain("token", "8..128 printable characters without spaces - the device will be read-only");
    return false;
  }
  authToken = t;
  authInvalid = false;
  return true;
}

bool SketchConfig::setEditToken(const char *token) {
  if (locked) { complain("setEditToken()", "begin() was already called"); return false; }
  const std::string t = token ? token : "";
  if (t.empty()) { editToken.clear(); editInvalid = false; return true; }
  if (!validSetupToken(t)) {
    editInvalid = true; // plan sending stays locked instead of opening to everybody
    complain("edit token", "8..128 printable characters without spaces - sending plans is locked");
    return false;
  }
  editToken = t;
  editInvalid = false;
  return true;
}

bool SketchConfig::setSetupApPassword(const char *password) {
  if (locked) { complain("setSetupApPassword()", "begin() was already called"); return false; }
  const std::string p = password ? password : "";
  if (!validWifiPassword(p)) {
    setupApInvalid = true; // the setup network is NOT opened rather than opened without the password
    complain("setup network password", "empty (open network) or 8..63 characters - the setup network stays closed");
    return false;
  }
  setupApPassword = p;
  setupApInvalid = false;
  return true;
}

bool registerSketchConfig(const char *wifiSsid, const char *wifiPassword, const char *authToken, const char *editToken,
                          const char *setupApPassword, bool hostManagedWifi) {
  SketchConfig &c = SketchConfig::get();
  c.deferComplaints(true);
  if (wifiSsid && wifiSsid[0]) c.setWifi(wifiSsid, wifiPassword);
  if (authToken && authToken[0]) c.setAuthToken(authToken);
  if (editToken && editToken[0]) c.setEditToken(editToken);
  if (setupApPassword && setupApPassword[0]) c.setSetupApPassword(setupApPassword);
  if (hostManagedWifi) c.setHostManagedWifi(true);
  c.deferComplaints(false);
  return true;
}

} // namespace Escape
