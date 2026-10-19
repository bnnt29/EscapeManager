#pragma once

// Wi-Fi and token setup without reflashing (PROTOCOL.md 5.8, README "Setup").
//
//  * SetupChange: the four things an operator may change: Wi-Fi name, Wi-Fi password, the normal
//    token and the plan-edit token. Anything not given stays as it is.
//  * Two doors lead to it: `POST /setup` (authenticated like a plan write, for managers) and the
//    setup network's portal (open or WPA2 access point opened by the ESP32 when it cannot reach its
//    Wi-Fi; plain HTML form, DNS answers everything with the portal address).
//  * SetupSink is what the platform implements: persisting the values and the state of the radio.
//
// Portable and free of hardware: the ESP32 firmware, the simulators and the native tests share it.

#include "EscapeConfig.hpp"
#include "Http.hpp"
#include "SecureTransport.hpp"

#include <cstddef>
#include <cstdint>
#include <string>

namespace Escape {

struct SetupChange {
  bool hasWifi;       // ssid + pass belong together
  std::string ssid;
  std::string pass;   // empty = open network
  bool hasToken;
  std::string token;  // empty = remove the stored token (build flag / public default applies again)
  bool hasEditToken;
  std::string editToken; // empty = remove the edit token (plans can be sent with the normal token again)
  SetupChange() : hasWifi(false), hasToken(false), hasEditToken(false) {}
  bool empty() const { return !hasWifi && !hasToken && !hasEditToken; }
};

enum class SetupResult : uint8_t { Ok, Invalid, Storage };

enum class WifiPhase : uint8_t { Idle, Connecting, Connected, Failed };

// The tokens a device runs with right now (after a change they have to be re-derived).
struct SetupTokens {
  std::string token;
  TokenState tokenState;
  std::string editToken;
  EditState editState;
  SetupTokens() : tokenState(TokenState::Default), editState(EditState::Unset) {}
};

class SetupSink {
public:
  virtual ~SetupSink() {}
  // Persists the change (validated by the caller) and, for Wi-Fi, starts connecting. `viaNetwork` is
  // true for POST /setup: the previous Wi-Fi is then kept as a fallback in case the new one fails.
  virtual SetupResult applySetup(const SetupChange &change, bool viaNetwork) = 0;
  // Tokens as they are stored now (called after a successful change to re-derive the keys).
  virtual void currentTokens(SetupTokens &out) = 0;

  // ---- Portal state (only meaningful on a device with a setup network) ----
  // "none" (this device cannot open one), "open" or "wpa2".
  virtual const char *setupApMode() const { return "none"; }
  virtual std::string setupNetworkName() const { return std::string(); }
  virtual bool setupNetworkOpen() const { return true; }
  virtual std::string configuredSsid() const { return std::string(); }
  virtual WifiPhase wifiPhase() const { return WifiPhase::Idle; }
  virtual std::string wifiAddress() const { return std::string(); }
  virtual const char *wifiFailReason() const { return ""; }
};

// "EscapeSetup-<did>" (24 characters). Unique per device because the did is the Wi-Fi MAC, and never
// derived from the router's name. In the (build-flag/legacy) case that the router network has
// exactly this name, "-S" is appended.
std::string setupNetworkName(const std::string &did, const std::string &routerSsid);
// True for any name that belongs to a setup network (prefix match): a device must never join one.
bool isSetupNetworkName(const std::string &ssid);

// ---- Validation -----------------------------------------------------------------------------------
bool validWifiSsid(const std::string &ssid);            // 1..32 bytes, no control characters
bool validWifiPassword(const std::string &pass);        // empty (open) or 8..63 printable ASCII
bool validSetupToken(const std::string &token);         // 8..128 printable ASCII without space
// Checks every given field. `error` is a short English text.
bool validateSetupChange(const SetupChange &change, std::string &error);

// POST /setup plaintext: {"ssid":"..","pass":"..","token":"..","editToken":".."} (all optional;
// ssid and pass only together).
bool parseSetupJson(const std::string &body, SetupChange &out, std::string &error);
// Setup form (application/x-www-form-urlencoded): ssid, pass, token, edit. Empty fields = unchanged.
bool parseSetupForm(const std::string &body, SetupChange &out, std::string &error);

// ---- Setup network helpers ----------------------------------------------------------------------
// Answers a DNS query with `address` for every A question (and an empty NOERROR answer for other types),
// so every phone's connectivity check lands on the portal. Returns the length of the answer, 0 = ignore.
size_t buildDnsAnswer(const uint8_t *query, size_t length, uint32_t address, uint8_t *out, size_t capacity);

// Serves the portal to a client of the setup network:
//   GET /setup, GET /setup/status, POST /setup/save; every other GET is redirected to /setup (this is
//   how Android/iOS/Windows detect a captive portal). `label` names the device (components and rooms).
//   `tokensChanged` is set when a saved change touched a token (the caller then re-derives the keys).
void handleSetupPortal(const HttpRequest &request, SetupSink &sink, const std::string &did, const std::string &label,
                       HttpResponse &response, bool &tokensChanged);

} // namespace Escape
