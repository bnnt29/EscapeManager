#pragma once

// Setup push (PROTOCOL.md 5.8) for the PC programs: the simulator and the serial host attach this
// SetupSink when started with --setup, so `POST /setup` works and the device advertises the cap "setup".
//
// A PC does not own a Wi-Fi radio: new Wi-Fi credentials are only RECORDED and logged (name, never the
// password). Tokens are applied for real: the Device re-derives its keys from currentTokens() after a
// change. Everything is kept in memory - a restart starts again with --token / --edit-token (or the
// environment), so a test that changed the tokens cannot leave a stale token behind in a state directory.

#include "../../src/protocol/EscapeConfig.hpp"
#include "../../src/protocol/Setup.hpp"

#include <string>

namespace Escape {

// Why `token` cannot be used as a token (empty string: it can). Same rules as POST /setup and the
// firmware's build flags: 8..128 characters, printable ASCII without spaces.
inline std::string tokenProblem(const std::string &token) {
  if (token.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN || token.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) {
    return "must have " + std::to_string(EscapeConfig::MIN_AUTH_TOKEN_LEN) + ".." +
           std::to_string(EscapeConfig::MAX_AUTH_TOKEN_LEN) + " characters";
  }
  if (!validSetupToken(token)) return "may only contain printable ASCII characters (no spaces)";
  return std::string();
}

class SimSetupSink : public SetupSink {
public:
  typedef void (*Logger)(const std::string &line);

  // An empty token means "the public default token"; an empty edit token means "no edit token".
  SimSetupSink(const std::string &token, const std::string &editToken, Logger logger) : logger_(logger) {
    setToken(token);
    setEditToken(editToken);
  }

  SetupResult applySetup(const SetupChange &change, bool /*viaNetwork*/) override {
    std::string error;
    if (!validateSetupChange(change, error)) return SetupResult::Invalid;
    if (change.hasWifi) {
      ssid_ = change.ssid;
      pass_ = change.pass; // recorded only (a PC has no radio); never logged
      log("setup: wifi ssid=" + change.ssid);
    }
    if (change.hasToken) {
      setToken(change.token);
      log(change.token.empty() ? "setup: token removed (public default applies)" : "setup: token changed");
    }
    if (change.hasEditToken) {
      setEditToken(change.editToken);
      log(change.editToken.empty() ? "setup: edit token removed" : "setup: edit token changed");
    }
    return SetupResult::Ok;
  }

  void currentTokens(SetupTokens &out) override {
    out.token = token_;
    out.tokenState = tokenState_;
    out.editToken = editToken_;
    out.editState = editState_;
  }

  const char *setupApMode() const override { return "none"; } // a PC opens no setup network
  std::string configuredSsid() const override { return ssid_; }

  // What the program starts the Device with (and what a later change leaves behind).
  const std::string &token() const { return token_; }
  TokenState tokenState() const { return tokenState_; }
  const std::string &editToken() const { return editToken_; }
  EditState editState() const { return editState_; }

private:
  void setToken(const std::string &t) {
    token_ = t.empty() ? std::string(EscapeConfig::AUTH_TOKEN) : t;
    tokenState_ = t.empty() ? TokenState::Default : TokenState::Custom;
  }
  void setEditToken(const std::string &t) {
    editToken_ = t;
    editState_ = t.empty() ? EditState::Unset : EditState::Custom;
  }
  void log(const std::string &line) const {
    if (logger_) logger_(line);
  }

  Logger logger_;
  std::string token_, editToken_, ssid_, pass_;
  TokenState tokenState_;
  EditState editState_;
};

} // namespace Escape
