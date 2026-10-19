#pragma once

// Everything Arduino/ESP32-specific that the portable core (src/net, src/protocol) needs:
//  * NVS storage (Preferences) for configuration and plan skeletons,
//  * the Wi-Fi link: the library owns the station (unless built with ESCAPE_HOST_MANAGED_WIFI): it
//    connects WITHOUT blocking, reconnects with back-off and, when it cannot connect, opens an
//    unique setup network with a configuration form (PROTOCOL.md 5.8) while it keeps trying,
//  * the tokens and Wi-Fi credentials (NVS, build flags), serial provisioning commands,
//  * the device id and boot counter,
//  * the DevicePlatform services (own address, setup network) and the SetupSink (what a network push
//    or the setup form may change).
//
// It knows nothing about the wire protocol; that lives in src/protocol and src/net.

#include "../net/Device.hpp"
#include "MbedTlsCryptoBackend.hpp"

#include <Arduino.h>
#include <Preferences.h>

#include <string>

class HardwareEsp32 : public Escape::DevicePlatform, public Escape::SetupSink {
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
  // A host program that owns Wi-Fi itself says so BEFORE begin() (or builds with -DESCAPE_HOST_MANAGED_WIFI=1):
  // the library then never touches the radio and offers no setup network.
  void setHostManagedWifi(bool hostManaged) { _hostManaged = hostManaged; }
  bool hostManagedWifi() const { return _hostManaged; }
  bool setupNetworkActive() const { return _apUp; }

  // Escape::DevicePlatform
  uint32_t localIp() override;
  uint32_t broadcastIp() override;
  bool setupNetworkUp() override { return _apUp; }
  bool isSetupClient(uint32_t ip) override;

  // Escape::SetupSink
  Escape::SetupResult applySetup(const Escape::SetupChange &change, bool viaNetwork) override;
  void currentTokens(Escape::SetupTokens &out) override;
  const char *setupApMode() const override;
  std::string setupNetworkName() const override { return _apName; }
  bool setupNetworkOpen() const override { return EscapeConfig::SETUP_AP_PASSWORD[0] == '\0'; }
  std::string configuredSsid() const override { return _ssid; }
  Escape::WifiPhase wifiPhase() const override;
  std::string wifiAddress() const override;
  const char *wifiFailReason() const override;

  // Configuration strings (name0, room0, riddle0, plan0, authtoken ...).
  std::string loadString(const char *key, const std::string &def);
  bool saveString(const char *key, const std::string &value);

  // Token: stored in NVS, else the build flag (-DESCAPE_AUTH_TOKEN, e.g. secrets.ini), else the public
  // repository default. A stored but unusable token = Invalid, which keeps the device read-only.
  bool loadToken(std::string &token, Escape::TokenState &state);
  // Plan-edit token: NVS, else -DESCAPE_EDIT_TOKEN, else Unset. A stored but unusable one = Invalid
  // (plan sending stays locked; the device never falls back to "anybody may edit").
  bool loadEditToken(std::string &token, Escape::EditState &state);

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
  bool removeString(const char *key);
  void pollSerial();
  void processSerialLine(const char *line);
  bool loadWifiCredentials(std::string &ssid, std::string &password);
  bool loadStoredToken(const char *key, std::string &token, bool &present, bool &valid);

  // Wi-Fi supervision (service())
  void connectStation(uint32_t nowMs);
  void commitWifiTrial();
  void rollbackWifiTrial(uint32_t nowMs);
  void startSetupNetwork(uint32_t nowMs);
  void stopSetupNetwork();
  void serviceSetupNetwork(uint32_t nowMs, bool connected);
  void serviceButton(uint32_t nowMs);
  uint32_t retryIntervalMs();

  Escape::MbedTlsCryptoBackend _crypto;
  NvsBlobs _skeleton;
  Preferences _prefs;
  bool _storageReady;
  bool _hasPlanPartition;
  bool _wifiStarted;
  bool _wifiOwned;
  bool _hostManaged;
  bool _serialEnabled;
  bool _wasConnected;
  std::string _ssid, _password;

  // Deadlines are only valid while their `armed` flag is set (a magic 0 breaks the signed comparison in
  // the upper half of the 32-bit clock).
  bool _retryArmed;
  uint32_t _nextRetryMs;
  uint32_t _wifiBackoffMs;
  bool _attemptArmed;            // when the current connection attempt started (phase / failure texts)
  uint32_t _attemptStartMs;
  bool _lostArmed;               // since when the station has not been connected (setup network trigger)
  uint32_t _lostSinceMs;
  bool _everConnected;           // since start
  bool _reconnectArmed;          // deferred reconnect after a network push (lets the answer leave first)
  uint32_t _reconnectAtMs;
  bool _trialActive;             // new Wi-Fi from a network push is on probation (old one kept as fallback)
  uint32_t _trialStartMs;

  bool _apUp;
  bool _apAuto;                  // opened because the station cannot connect (stays until it does)
  std::string _apName;
  bool _lingerArmed;             // setup network stays this long after the station connected
  uint32_t _lingerUntilMs;
  bool _forcedArmed;             // opened by the BOOT button
  uint32_t _forcedUntilMs;
  int _apClients;
  bool _buttonArmed;             // BOOT button window after start
  uint32_t _buttonWindowEndMs;
  bool _buttonDown;
  uint32_t _buttonDownMs;

  char _line[320];
  size_t _lineLength;
  bool _lineOverflow;
};
