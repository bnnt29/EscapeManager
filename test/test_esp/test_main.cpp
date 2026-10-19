// On-device tests of the configuration precedence (stored on the device > sketch > build flag > default).
// Run on a real ESP32:  pio test -e esp32-test-esp    (the environment sets the build flags this file expects)
#include <Arduino.h>
#include <unity.h>

#include "../../src/esp/HardwareEsp32.hpp"
#include "../../src/esp/SketchConfig.hpp"

using Escape::EditState;
using Escape::SetupChange;
using Escape::SketchConfig;
using Escape::TokenState;

// The environment's build flags (platformio.ini [env:esp32-test-esp]).
static const char *kBuildToken = "build-flag-token-1234";
static const char *kBuildEdit = "build-edit-token-1234";
static const char *kBuildApPassword = "build-ap-pass-123";
static const char *kBuildSsid = "BuildNet";

static HardwareEsp32 *hw = nullptr;

void setUp() {
  SketchConfig &c = SketchConfig::get();
  c.wifiSsid.clear();
  c.wifiPassword.clear();
  c.authToken.clear();
  c.editToken.clear();
  c.setupApPassword.clear();
  c.authInvalid = c.editInvalid = c.setupApInvalid = false;
  c.hostManagedWifi = false;
  if (!hw) {
    hw = new HardwareEsp32();
    TEST_ASSERT_TRUE(hw->beginStorage());
  }
  SetupChange wipe; // nothing stored from an earlier test
  wipe.hasToken = wipe.hasEditToken = true;
  hw->applySetup(wipe, false);
  hw->saveString("wifi_ssid", "");
  hw->saveString("wifi_pass", "");
}
void tearDown() {}

static void expectToken(const char *token, TokenState state) {
  std::string t;
  TokenState s;
  hw->loadToken(t, s);
  TEST_ASSERT_TRUE(s == state);
  if (state != TokenState::Invalid) TEST_ASSERT_EQUAL_STRING(token, t.c_str());
  else TEST_ASSERT_TRUE(t.empty());
}
static void expectEdit(const char *token, EditState state) {
  std::string t;
  EditState s;
  hw->loadEditToken(t, s);
  TEST_ASSERT_TRUE(s == state);
  if (state == EditState::Custom) TEST_ASSERT_EQUAL_STRING(token, t.c_str());
  else TEST_ASSERT_TRUE(t.empty());
}

void test_sketch_setters_validate() {
  SketchConfig &c = SketchConfig::get();
  TEST_ASSERT_TRUE(c.setWifi("Heimnetz", "geheimgeheim"));
  TEST_ASSERT_EQUAL_STRING("Heimnetz", c.wifiSsid.c_str());
  TEST_ASSERT_TRUE(c.setWifi("Cafe", ""));                         // open network is a valid choice
  TEST_ASSERT_FALSE(c.setWifi("", "geheimgeheim"));                // no name
  TEST_ASSERT_FALSE(c.setWifi(std::string(33, 'x').c_str(), ""));  // too long
  TEST_ASSERT_FALSE(c.setWifi("Heimnetz", "short"));               // WPA2 needs 8..63
  TEST_ASSERT_FALSE(c.setWifi("EscapeSetup-aabbccddeeff", ""));    // never join a setup network
  TEST_ASSERT_EQUAL_STRING("Cafe", c.wifiSsid.c_str());            // refused values change nothing
  TEST_ASSERT_TRUE(c.setAuthToken("12345678"));
  TEST_ASSERT_FALSE(c.setAuthToken("1234567"));
  TEST_ASSERT_TRUE(c.authInvalid);                                  // remembered: the device must not fall back to the default
  TEST_ASSERT_TRUE(c.setAuthToken(""));                             // "" = not given any more
  TEST_ASSERT_FALSE(c.authInvalid);
  TEST_ASSERT_FALSE(c.setEditToken("has a space inside"));
  TEST_ASSERT_TRUE(c.editInvalid);
  TEST_ASSERT_TRUE(c.setSetupApPassword("12345678"));
  TEST_ASSERT_FALSE(c.setSetupApPassword("1234567"));
  TEST_ASSERT_TRUE(c.setupApInvalid);
  TEST_ASSERT_TRUE(c.setSetupApPassword(""));
  TEST_ASSERT_FALSE(c.setupApInvalid);
}

void test_registering_defines_ignores_empty_values() {
  SketchConfig &c = SketchConfig::get();
  TEST_ASSERT_TRUE(Escape::registerSketchConfig("", "", "", "", "", false));
  TEST_ASSERT_TRUE(c.wifiSsid.empty() && c.authToken.empty() && c.editToken.empty() && c.setupApPassword.empty());
  TEST_ASSERT_TRUE(Escape::registerSketchConfig("Heimnetz", "geheimgeheim", "sketch-token-12345", "sketch-edit-12345", "sketch-ap-pass-1", true));
  TEST_ASSERT_EQUAL_STRING("Heimnetz", c.wifiSsid.c_str());
  TEST_ASSERT_EQUAL_STRING("sketch-token-12345", c.authToken.c_str());
  TEST_ASSERT_TRUE(c.hostManagedWifi);
  TEST_ASSERT_TRUE(Escape::registerSketchConfig("", "", "", "", "", false)); // a second translation unit without secrets: no harm
  TEST_ASSERT_EQUAL_STRING("sketch-token-12345", c.authToken.c_str());
  TEST_ASSERT_TRUE(c.hostManagedWifi);
  // invalid values given through #defines are remembered as invalid, not dropped
  TEST_ASSERT_TRUE(Escape::registerSketchConfig("", "", "short", "", "", false));
  TEST_ASSERT_TRUE(c.authInvalid);
}

void test_token_precedence() {
  SketchConfig &c = SketchConfig::get();
  expectToken(kBuildToken, TokenState::Custom);                    // build flag only
  c.setAuthToken("sketch-token-12345");
  expectToken("sketch-token-12345", TokenState::Custom);           // sketch beats the build flag
  SetupChange stored;
  stored.hasToken = true;
  stored.token = "stored-token-12345";
  TEST_ASSERT_TRUE(hw->applySetup(stored, false) == Escape::SetupResult::Ok);
  expectToken("stored-token-12345", TokenState::Custom);           // stored beats the sketch
  stored.token = "";                                               // removing the stored one ...
  TEST_ASSERT_TRUE(hw->applySetup(stored, false) == Escape::SetupResult::Ok);
  expectToken("sketch-token-12345", TokenState::Custom);           // ... gives the sketch's back
  c.setAuthToken("EscapeManager-Private-WLAN-Default-Token");
  expectToken("EscapeManager-Private-WLAN-Default-Token", TokenState::Default); // the public token stays "default"
}

void test_invalid_sketch_token_is_never_replaced_by_something_weaker() {
  SketchConfig &c = SketchConfig::get();
  c.setAuthToken("short");
  expectToken("", TokenState::Invalid);                            // read-only, NOT the build flag and not the public default
  c.setEditToken("short");
  expectEdit("", EditState::Invalid);                              // plan sending locked, NOT open to everybody
  SetupChange stored;                                              // what is stored on the device still wins
  stored.hasToken = stored.hasEditToken = true;
  stored.token = "stored-token-12345";
  stored.editToken = "stored-edit-12345";
  TEST_ASSERT_TRUE(hw->applySetup(stored, false) == Escape::SetupResult::Ok);
  expectToken("stored-token-12345", TokenState::Custom);
  expectEdit("stored-edit-12345", EditState::Custom);
}

void test_edit_token_precedence() {
  SketchConfig &c = SketchConfig::get();
  expectEdit(kBuildEdit, EditState::Custom);                       // build flag
  c.setEditToken("sketch-edit-12345");
  expectEdit("sketch-edit-12345", EditState::Custom);              // sketch beats the build flag
  SetupChange stored;
  stored.hasEditToken = true;
  stored.editToken = "stored-edit-12345";
  TEST_ASSERT_TRUE(hw->applySetup(stored, false) == Escape::SetupResult::Ok);
  expectEdit("stored-edit-12345", EditState::Custom);              // stored beats the sketch
}

void test_wifi_precedence() {
  SketchConfig &c = SketchConfig::get();
  std::string ssid, pass;
  TEST_ASSERT_TRUE(hw->loadWifiCredentials(ssid, pass));
  TEST_ASSERT_EQUAL_STRING(kBuildSsid, ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("build", hw->wifiCredentialSource());
  c.setWifi("SketchNet", "sketch-wifi-pass");
  TEST_ASSERT_TRUE(hw->loadWifiCredentials(ssid, pass));
  TEST_ASSERT_EQUAL_STRING("SketchNet", ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("sketch-wifi-pass", pass.c_str());
  TEST_ASSERT_EQUAL_STRING("sketch", hw->wifiCredentialSource());
  c.setWifi("OpenCafe", "");                                       // an open network from the sketch really is open
  TEST_ASSERT_TRUE(hw->loadWifiCredentials(ssid, pass));
  TEST_ASSERT_EQUAL_STRING("OpenCafe", ssid.c_str());
  TEST_ASSERT_TRUE(pass.empty());
  hw->saveString("wifi_ssid", "StoredNet");
  hw->saveString("wifi_pass", "stored-wifi-pass");
  TEST_ASSERT_TRUE(hw->loadWifiCredentials(ssid, pass));
  TEST_ASSERT_EQUAL_STRING("StoredNet", ssid.c_str());
  TEST_ASSERT_EQUAL_STRING("stored", hw->wifiCredentialSource());
}

void test_setup_network_password_precedence() {
  SketchConfig &c = SketchConfig::get();
  hw->applySketchConfig();
  TEST_ASSERT_EQUAL_STRING("wpa2", hw->setupApMode());             // the build flag's password
  TEST_ASSERT_FALSE(hw->setupNetworkOpen());
  c.setSetupApPassword("sketch-ap-pass-1");
  hw->applySketchConfig();
  TEST_ASSERT_EQUAL_STRING("wpa2", hw->setupApMode());
  c.setSetupApPassword("short");                                   // given but unusable: no setup network at all
  hw->applySketchConfig();
  TEST_ASSERT_EQUAL_STRING("none", hw->setupApMode());             // never silently an OPEN network
  c.setSetupApPassword("");
  c.setupApInvalid = false;
  hw->applySketchConfig();
  TEST_ASSERT_EQUAL_STRING("wpa2", hw->setupApMode());
}

void test_setters_are_refused_after_begin() {                      // keep this LAST: the lock cannot be undone
  SketchConfig &c = SketchConfig::get();
  c.lock();
  TEST_ASSERT_TRUE(c.isLocked());
  TEST_ASSERT_FALSE(c.setWifi("Late", "late-password-1"));
  TEST_ASSERT_FALSE(c.setAuthToken("late-token-123456"));
  TEST_ASSERT_FALSE(c.setEditToken("late-edit-123456"));
  TEST_ASSERT_FALSE(c.setSetupApPassword("late-ap-pass-1"));
  TEST_ASSERT_TRUE(c.wifiSsid.empty() && c.authToken.empty() && c.editToken.empty() && c.setupApPassword.empty());
}

static void runAll() {
  UNITY_BEGIN();
  RUN_TEST(test_sketch_setters_validate);
  RUN_TEST(test_registering_defines_ignores_empty_values);
  RUN_TEST(test_token_precedence);
  RUN_TEST(test_invalid_sketch_token_is_never_replaced_by_something_weaker);
  RUN_TEST(test_edit_token_precedence);
  RUN_TEST(test_wifi_precedence);
  RUN_TEST(test_setup_network_password_precedence);
  RUN_TEST(test_setters_are_refused_after_begin);
  UNITY_END();
}

void setup() {
  delay(2000);
  runAll();
}
void loop() {}
