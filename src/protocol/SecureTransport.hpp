#pragma once

// Proto-2 secure transport (see PROTOCOL.md sections 3 and 4):
//  * keys: PBKDF2(token) -> HKDF per purpose (request, response, MAC),
//  * POST: AES-256-GCM envelope bound to device id, path and a time stamp, with a
//    replay cache sized for the time window (fail closed),
//  * GET documents and UDP announcements: HMAC frames over the exact document bytes.
// Both the device side (openRequest/sealResponse/frame*) and the client side
// (sealRequest/openResponse/openDocumentFrame) live here so devices can talk to peers
// and tests can play the manager.

#include "CryptoBackend.hpp"
#include "EscapeConfig.hpp"
#include "Json.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Escape {

enum class TokenState : uint8_t { Default, Custom, Invalid };
const char *tokenStateName(TokenState state);

struct OpenResult {
  int status;        // 200 on success, otherwise the HTTP status to answer with
  const char *code;  // machine-readable error code (PROTOCOL.md 5.6), nullptr on success
};

struct DerivedKeys {
  uint8_t master[32];
  uint8_t req[32];
  uint8_t resp[32];
  uint8_t mac[32];
};

class SecureTransport {
public:
  explicit SecureTransport(CryptoBackend &crypto);

  // PROTOCOL.md section 3. Exposed so tests and other implementations can pin the
  // exact key schedule.
  static bool deriveKeys(CryptoBackend &crypto, const std::string &token, DerivedKeys &keys);

  // Derives all keys (PBKDF2, ~230 ms on an ESP32 - call once at start-up). With
  // TokenState::Invalid no keys are derived and the transport stays read-only.
  bool begin(const std::string &token, TokenState state, const std::string &deviceId);

  bool ready() const { return began_; }
  bool writable() const { return keysReady_ && state_ != TokenState::Invalid; }
  TokenState tokenState() const { return state_; }
  const std::string &deviceId() const { return did_; }

  // ---- Device side -----------------------------------------------------------------
  // Authenticates one POST envelope. On success `plaintext` holds the command and
  // `requestIv` the base64url IV (needed to seal the response). When the IV could be
  // read (also on failures after that point) `requestIv` is set so the error can be
  // answered authenticated.
  OpenResult openRequest(const std::string &path, const char *body, size_t length, uint32_t nowMs,
                         std::string &plaintext, std::string &requestIv);
  bool sealResponse(const std::string &path, const std::string &requestIv, int status,
                    const std::string &body, std::string &envelope) const;

  // `{"doc":<doc>,"mac":"..."}` for GET responses; `nonce` must satisfy validNonce().
  bool frameDocument(const std::string &path, const std::string &nonce, int status, const std::string &doc,
                     std::string &frame) const;
  // `{"doc":<doc>,"mac":"..."}` for UDP announcements.
  bool frameAnnouncement(const std::string &doc, std::string &frame) const;
  // Verifies an announcement frame; `doc` points into `data`.
  bool openAnnouncement(const char *data, size_t length, EscapeJson::Slice &doc) const;

  // ---- Client side (device-to-device sync, tests, simulators) ----------------------------
  bool sealRequest(const std::string &path, uint32_t t, const std::string &plaintext, const uint8_t iv[12],
                   std::string &envelope) const;
  bool openResponse(const std::string &path, const std::string &requestIv, int status, const char *body,
                    size_t length, std::string &plaintext) const;
  // Verifies a GET frame from THIS device (id bound = own id); `doc` points into `body`.
  bool openDocumentFrame(const std::string &path, const std::string &nonce, int status, const char *body,
                         size_t length, EscapeJson::Slice &doc) const {
    return openDocumentFrameFrom(did_, path, nonce, status, body, length, doc);
  }
  // Verifies a GET frame produced by the device `fromDid` (a peer): the MAC binds the
  // id of the RESPONDING device.
  bool openDocumentFrameFrom(const std::string &fromDid, const std::string &path, const std::string &nonce,
                             int status, const char *body, size_t length, EscapeJson::Slice &doc) const;

  static bool validNonce(const std::string &nonce);

  // Number of live replay-cache entries (for tests/diagnostics).
  size_t replayEntries(uint32_t nowMs) const;

private:
  struct ReplayEntry {
    uint32_t expiresMs;
    uint8_t iv[8];
    bool used;
  };

  bool computeMac(const char *prefix, size_t prefixLength, const char *doc, size_t docLength,
                  uint8_t out[32]) const;
  bool frame(const std::string &prefix, const std::string &doc, std::string &out) const;
  bool openFrame(const std::string &prefix, const char *body, size_t length, EscapeJson::Slice &doc) const;
  bool seal(const uint8_t key[32], const std::string &aad, const uint8_t iv[12], const std::string &plaintext,
            std::string &ctB64) const;

  CryptoBackend &crypto_;
  std::string did_;
  TokenState state_;
  bool began_;
  bool keysReady_;
  uint8_t kReq_[32];
  uint8_t kResp_[32];
  uint8_t kMac_[32];
  ReplayEntry replay_[EscapeConfig::REPLAY_CACHE_SIZE];
};

} // namespace Escape
