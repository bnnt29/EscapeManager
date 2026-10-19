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
#include "SkeletonStore.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace Escape {

enum class TokenState : uint8_t { Default, Custom, Invalid };
const char *tokenStateName(TokenState state);

// The plan-edit token (PROTOCOL.md 3.1): a second key set that alone may send plans to devices.
// Unset = the normal token may do it (as before the edit token existed).
enum class EditState : uint8_t { Unset, Custom, Invalid };
const char *editStateName(EditState state);

// Which key set authenticated (or has to authenticate) a request / response.
enum class KeyRole : uint8_t { Normal = 0, Edit = 1 };

// Paths that change what the installation does BETWEEN games (plans, network settings). They need the
// edit key set once a device has an edit token; all other POST paths always use the normal key set.
bool isEditPath(const std::string &path);

struct OpenResult {
  int status;        // 200 on success, otherwise the HTTP status to answer with
  const char *code;  // machine-readable error code (PROTOCOL.md 5.6), nullptr on success
  KeyRole role;      // key set to seal the answer with (Edit only after an edit-authenticated success)
  OpenResult(int s, const char *c, KeyRole r = KeyRole::Normal) : status(s), code(c), role(r) {}
};

struct DerivedKeys {
  uint8_t master[32];
  uint8_t req[32];
  uint8_t resp[32];
  uint8_t mac[32];
};

class SecureTransport : public SkeletonSigner {
public:
  explicit SecureTransport(CryptoBackend &crypto);

  // PROTOCOL.md section 3. Exposed so tests and other implementations can pin the
  // exact key schedule. `edit` selects the salt of the edit token.
  static bool deriveKeys(CryptoBackend &crypto, const std::string &token, DerivedKeys &keys, bool edit = false);

  // Derives all keys (PBKDF2, ~230 ms on an ESP32 per token - call once at start-up). With
  // TokenState::Invalid no keys are derived and the transport stays read-only. The edit token is
  // optional; EditState::Custom derives a second key set (another ~230 ms), EditState::Invalid keeps
  // edit-class POSTs refused (never falls back to "anybody may edit").
  bool begin(const std::string &token, TokenState state, const std::string &deviceId,
             const std::string &editToken = std::string(), EditState editState = EditState::Unset);

  bool ready() const { return began_; }
  bool writable() const { return keysReady_ && state_ != TokenState::Invalid; }
  TokenState tokenState() const { return state_; }
  EditState editState() const { return edit_; }
  bool editReady() const { return editReady_; }
  const std::string &deviceId() const { return did_; }

  // ---- Device side -----------------------------------------------------------------
  // Authenticates one POST envelope. On success `plaintext` holds the command and
  // `requestIv` the base64url IV (needed to seal the response). When the IV could be
  // read (also on failures after that point) `requestIv` is set so the error can be
  // answered authenticated.
  // The envelope field "k":"e" selects the edit key set (only valid for edit paths). On an edit path a
  // device with an edit token refuses normal-key requests AFTER authenticating them: 403 edit_required.
  // `result.role` says which key set the answer has to be sealed with.
  OpenResult openRequest(const std::string &path, const char *body, size_t length, uint32_t nowMs,
                         std::string &plaintext, std::string &requestIv);
  bool sealResponse(const std::string &path, const std::string &requestIv, int status,
                    const std::string &body, std::string &envelope, KeyRole role = KeyRole::Normal) const;

  // `{"doc":<doc>,"mac":"..."}` for GET responses; `nonce` must satisfy validNonce().
  bool frameDocument(const std::string &path, const std::string &nonce, int status, const std::string &doc,
                     std::string &frame) const;
  // `{"doc":<doc>,"mac":"..."}` for UDP announcements.
  bool frameAnnouncement(const std::string &doc, std::string &frame) const;
  // Verifies an announcement frame; `doc` points into `data`.
  bool openAnnouncement(const char *data, size_t length, EscapeJson::Slice &doc) const;

  // ---- Client side (device-to-device sync, tests, simulators) ----------------------------
  bool sealRequest(const std::string &path, uint32_t t, const std::string &plaintext, const uint8_t iv[12],
                   std::string &envelope, KeyRole role = KeyRole::Normal) const;
  bool openResponse(const std::string &path, const std::string &requestIv, int status, const char *body,
                    size_t length, std::string &plaintext, KeyRole role = KeyRole::Normal) const;
  // Verifies a GET frame from THIS device (id bound = own id); `doc` points into `body`.
  bool openDocumentFrame(const std::string &path, const std::string &nonce, int status, const char *body,
                         size_t length, EscapeJson::Slice &doc) const {
    return openDocumentFrameFrom(did_, path, nonce, status, body, length, doc);
  }
  // Verifies a GET frame produced by the device `fromDid` (a peer): the MAC binds the
  // id of the RESPONDING device.
  bool openDocumentFrameFrom(const std::string &fromDid, const std::string &path, const std::string &nonce,
                             int status, const char *body, size_t length, EscapeJson::Slice &doc) const;

  // GET /edit.json frame, MACed with the EDIT mac key: proves to a manager that the device has the
  // same edit token. Same layout as frameDocument().
  bool frameEditDocument(const std::string &path, const std::string &nonce, int status, const std::string &doc,
                         std::string &frame) const;
  bool openEditDocumentFrame(const std::string &path, const std::string &nonce, int status, const char *body,
                             size_t length, EscapeJson::Slice &doc) const;

  // SkeletonSigner (emac of skeletons, see SkeletonStore.hpp)
  bool signingEnabled() const override { return editReady_; }
  bool signSkeleton(const std::string &room, uint32_t rev, uint32_t hash, std::string &emac) const override;
  bool verifySkeleton(const std::string &room, uint32_t rev, uint32_t hash, const std::string &emac) const override;

  static bool validNonce(const std::string &nonce);

  // Number of live replay-cache entries (for tests/diagnostics).
  size_t replayEntries(uint32_t nowMs) const;

private:
  struct ReplayEntry {
    uint32_t expiresMs;
    uint8_t iv[8];
    bool used;
  };

  bool computeMac(const uint8_t key[32], const char *prefix, size_t prefixLength, const char *doc, size_t docLength,
                  uint8_t out[32]) const;
  bool frame(const uint8_t key[32], const std::string &prefix, const std::string &doc, std::string &out) const;
  bool openFrame(const uint8_t key[32], const std::string &prefix, const char *body, size_t length,
                 EscapeJson::Slice &doc) const;
  bool seal(const uint8_t key[32], const std::string &aad, const uint8_t iv[12], const std::string &plaintext,
            std::string &ctB64) const;
  const uint8_t *reqKey(KeyRole role) const { return role == KeyRole::Edit ? eReq_ : kReq_; }
  const uint8_t *respKey(KeyRole role) const { return role == KeyRole::Edit ? eResp_ : kResp_; }
  bool roleReady(KeyRole role) const { return role == KeyRole::Edit ? editReady_ : keysReady_; }

  CryptoBackend &crypto_;
  std::string did_;
  TokenState state_;
  EditState edit_;
  bool began_;
  bool keysReady_;
  bool editReady_;
  uint8_t kReq_[32];
  uint8_t kResp_[32];
  uint8_t kMac_[32];
  uint8_t eReq_[32];
  uint8_t eResp_[32];
  uint8_t eMac_[32];
  ReplayEntry replay_[EscapeConfig::REPLAY_CACHE_SIZE];
};

} // namespace Escape
