#pragma once

// Settings a SKETCH hands to the library at run time, for builds without build flags (the Arduino IDE has no
// way to pass -D options to a library). Two ways lead here, both end up in the same registry:
//   * `#define ESCAPE_WIFI_SSID "..."` (and the other ESCAPE_* secrets) in the sketch BEFORE
//     `#include <EscapeManager.h>`, typically from an `arduino_secrets.h`: the header registers them at
//     start-up (EscapeManager.h);
//   * the setters of EscapeComponent (setWifi(), setAuthToken(), ...) before begin().
// Precedence for each secret (first match wins): value stored on the device (setup form, network push, serial
// command) > SketchConfig > build flag (-DESCAPE_*, e.g. secrets.ini) > default.
//
// A secret that was given but is unusable (wrong length, forbidden characters) is never replaced by something
// weaker silently: an invalid token leaves the device read-only for that token, an invalid setup-network password
// means the setup network is not opened. The reason is printed on Serial.

#include <string>

namespace Escape {

class SketchConfig {
public:
  static SketchConfig &get();

  // Setters validate; false = refused (and remembered as "given but invalid" where that matters, see above).
  bool setWifi(const char *ssid, const char *password);
  bool setAuthToken(const char *token);
  bool setEditToken(const char *token);
  bool setSetupApPassword(const char *password);
  void setHostManagedWifi(bool hostManaged) { hostManagedWifi = hostManaged; }
  void setSetupButtonPin(int pin) { buttonPin = pin; buttonPinSet = true; }
  void setAllowWifiSleep(bool allow) { allowWifiSleep = allow; }

  // Called by EscapeComponent::begin(): afterwards the setters are refused (the keys are derived once). Also prints
  // the complaints that were collected while the sketch's #defines were registered (that happens before the
  // constructor of Serial is guaranteed to have run, so nothing may be printed then).
  void lock();
  bool isLocked() const { return locked; }

  // Values; an empty string means "not given".
  std::string wifiSsid, wifiPassword;
  std::string authToken, editToken, setupApPassword;
  bool authInvalid, editInvalid, setupApInvalid;
  bool hostManagedWifi;
  bool buttonPinSet;
  int buttonPin;
  bool allowWifiSleep;

  // Used by registerSketchConfig(): complaints are collected instead of printed.
  void deferComplaints(bool defer) { deferred = defer; }

private:
  void complain(const char *what, const char *why);
  SketchConfig()
      : authInvalid(false), editInvalid(false), setupApInvalid(false), hostManagedWifi(false), buttonPinSet(false),
        buttonPin(-1), allowWifiSleep(false), locked(false), deferred(false) {}
  bool locked;
  bool deferred;
  std::string pending;
};

// What EscapeManager.h calls at start-up with the sketch's #defines. Empty strings are "not defined" and leave
// everything as it is (so a second translation unit that includes the header without secrets does no harm).
bool registerSketchConfig(const char *wifiSsid, const char *wifiPassword, const char *authToken, const char *editToken,
                          const char *setupApPassword, bool hostManagedWifi);

} // namespace Escape
