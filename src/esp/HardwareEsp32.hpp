#pragma once

// Everything Arduino/ESP32-specific that the portable core (src/net, src/protocol) needs:
//  * NVS storage (Preferences) for configuration and plan skeletons,
//  * the Wi-Fi link: it uses a connection the host program already set up, otherwise it
//    connects itself WITHOUT blocking and reconnects with back-off,
//  * serial provisioning commands (token, Wi-Fi credentials, reset, info),
//  * the device id and boot counter,
//  * the DevicePlatform services (own address, broadcast address).
//
// It knows nothing about the wire protocol; that lives in src/protocol and src/net.

#include "../net/Device.hpp"
#include "MbedTlsCryptoBackend.hpp"

#include <Arduino.h>
#include <Preferences.h>

#include <string>

class HardwareEsp32 : public Escape::DevicePlatform {
public:
  HardwareEsp32();

  // Initialises NVS (erasing it only if it is corrupt) and makes sure the namespaces
  // exist. False if NVS cannot be used at all; then nothing is persisted.
  bool beginStorage();
  bool storageReady() const { return _storageReady; }

  // 12 lowercase hex characters of the Wi-Fi station MAC (eFuse MAC as fallback).
  std::string deviceId() const;
  // Persistent boot counter, incremented once per call; random if NVS fails.
  uint32_t nextBootCounter();

  // Wi-Fi: non-blocking. `service()` supervises the link and handles serial commands;
  // call it from every loop().
  void startWifi();
  void service(uint32_t nowMs);
  bool wifiOwnedByLibrary() const { return _wifiOwned; }
  bool wifiConnected() const;

  // Escape::DevicePlatform
  uint32_t localIp() override;
  uint32_t broadcastIp() override;

  // Configuration strings (name0, room0, riddle0, plan0, authtoken ...).
  std::string loadString(const char *key, const std::string &def);
  bool saveString(const char *key, const std::string &value);

  // Token from NVS. No stored token = Default (public repository token); a stored but
  // unusable token = Invalid, which keeps the device read-only.
  bool loadToken(std::string &token, Escape::TokenState &state);

  Escape::BlobStorage &skeletonStorage() { return _skeleton; }
  Escape::CryptoBackend &crypto() { return _crypto; }

  // Serial provisioning can be switched off if the host program owns the serial port.
  void setSerialProvisioning(bool enabled) { _serialEnabled = enabled; }

private:
  class NvsBlobs : public Escape::BlobStorage {
  public:
    explicit NvsBlobs(HardwareEsp32 &owner) : _owner(owner) {}
    bool read(const char *key, std::string &out) override;
    bool write(const char *key, const std::string &data) override;
    bool erase(const char *key) override;

  private:
    HardwareEsp32 &_owner;
  };

  bool openConfig(bool readOnly);
  bool openPlans(bool readOnly);
  bool clearAllStorage();
  void pollSerial();
  void processSerialLine(const char *line);
  bool loadWifiCredentials(std::string &ssid, std::string &password);
  static bool hostConfiguredStation();

  Escape::MbedTlsCryptoBackend _crypto;
  NvsBlobs _skeleton;
  Preferences _prefs;
  bool _storageReady;
  bool _hasPlanPartition;
  bool _wifiStarted;
  bool _wifiOwned;
  bool _serialEnabled;
  uint32_t _lastWifiAttemptMs;
  uint32_t _wifiBackoffMs;
  bool _wasConnected;
  std::string _ssid, _password;
  char _line[320];
  size_t _lineLength;
  bool _lineOverflow;
};
