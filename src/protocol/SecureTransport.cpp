// Implementation of SecureTransport.hpp (protocol: PROTOCOL.md sections 3 and 4).

#include "SecureTransport.hpp"

#include "Base64Url.hpp"
#include "Compat.hpp"
#include "EscapeVersion.hpp"

#include <cstring>

namespace Escape {

namespace {

const char kKdfSalt[] = "EscapeManager/2/token";
const char kEditSalt[] = "EscapeManager/2/edit-token";
const char kInfoReq[] = "EM2 req";
const char kInfoResp[] = "EM2 resp";
const char kInfoMac[] = "EM2 mac";
const char kFrameHead[] = "{\"doc\":";
const size_t kFrameHeadLen = 7;
const char kFrameMacKey[] = ",\"mac\":\"";
const size_t kFrameMacKeyLen = 8;
const size_t kMacTextLen = 43; // base64url of 32 bytes

std::string decimal(uint32_t v) {
  std::string s;
  EscapeJson::appendUInt(s, v);
  return s;
}

} // namespace

// ---- primitives --------------------------------------------------------------------

void secureZero(void *p, size_t n) {
  volatile uint8_t *q = (volatile uint8_t *)p;
  while (n--) *q++ = 0;
}

bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++) diff |= (uint8_t)(a[i] ^ b[i]);
  return diff == 0;
}

bool hkdfSha256(CryptoBackend &crypto, const uint8_t *ikm, size_t ikmLength, const uint8_t *salt,
                size_t saltLength, const uint8_t *info, size_t infoLength, uint8_t *out, size_t outLength) {
  if (outLength > 255 * 32) return false;
  static const uint8_t zeros[32] = {0};
  if (!salt || saltLength == 0) {
    salt = zeros;
    saltLength = sizeof(zeros);
  }
  uint8_t prk[32];
  ByteRange extract[1] = {{ikm, ikmLength}};
  if (!crypto.hmacSha256(salt, saltLength, extract, 1, prk)) return false;

  uint8_t block[32];
  size_t produced = 0;
  uint8_t counter = 1;
  size_t blockLength = 0;
  bool ok = true;
  while (produced < outLength && ok) {
    ByteRange parts[3];
    size_t partCount = 0;
    if (blockLength) parts[partCount++] = ByteRange{block, blockLength};
    if (infoLength) parts[partCount++] = ByteRange{info, infoLength};
    parts[partCount++] = ByteRange{&counter, 1};
    ok = crypto.hmacSha256(prk, sizeof(prk), parts, partCount, block);
    blockLength = sizeof(block);
    const size_t take = (outLength - produced < sizeof(block)) ? outLength - produced : sizeof(block);
    memcpy(out + produced, block, take);
    produced += take;
    counter++;
  }
  secureZero(prk, sizeof(prk));
  secureZero(block, sizeof(block));
  return ok;
}

const char *editStateName(EditState state) {
  switch (state) {
    case EditState::Custom: return "custom";
    case EditState::Invalid: return "invalid";
    case EditState::Unset:
    default: return "unset";
  }
}

bool isEditPath(const std::string &path) {
  return path == "/plan" || path == "/plan-skeleton" || path == "/setup";
}

const char *tokenStateName(TokenState state) {
  switch (state) {
    case TokenState::Custom: return "custom";
    case TokenState::Invalid: return "invalid";
    case TokenState::Default:
    default: return "default";
  }
}

// ---- construction ------------------------------------------------------------------------

SecureTransport::SecureTransport(CryptoBackend &crypto)
    : crypto_(crypto), state_(TokenState::Default), edit_(EditState::Unset), began_(false), keysReady_(false), editReady_(false) {
  memset(kReq_, 0, sizeof(kReq_));
  memset(kResp_, 0, sizeof(kResp_));
  memset(kMac_, 0, sizeof(kMac_));
  memset(eReq_, 0, sizeof(eReq_));
  memset(eResp_, 0, sizeof(eResp_));
  memset(eMac_, 0, sizeof(eMac_));
  memset(replay_, 0, sizeof(replay_));
}

bool SecureTransport::deriveKeys(CryptoBackend &crypto, const std::string &token, DerivedKeys &keys, bool edit) {
  const char *salt = edit ? kEditSalt : kKdfSalt;
  const size_t saltLength = edit ? sizeof(kEditSalt) - 1 : sizeof(kKdfSalt) - 1;
  bool ok = crypto.pbkdf2Sha256((const uint8_t *)token.data(), token.size(), (const uint8_t *)salt,
                                saltLength, EscapeConfig::KDF_ITERATIONS, keys.master, 32);
  ok = ok && hkdfSha256(crypto, keys.master, 32, nullptr, 0, (const uint8_t *)kInfoReq, sizeof(kInfoReq) - 1, keys.req, 32);
  ok = ok && hkdfSha256(crypto, keys.master, 32, nullptr, 0, (const uint8_t *)kInfoResp, sizeof(kInfoResp) - 1, keys.resp, 32);
  ok = ok && hkdfSha256(crypto, keys.master, 32, nullptr, 0, (const uint8_t *)kInfoMac, sizeof(kInfoMac) - 1, keys.mac, 32);
  return ok;
}

bool SecureTransport::begin(const std::string &token, TokenState state, const std::string &deviceId,
                            const std::string &editToken, EditState editState) {
  began_ = true;
  keysReady_ = false;
  editReady_ = false;
  did_ = deviceId;
  state_ = state;
  edit_ = editState;
  secureZero(kReq_, sizeof(kReq_));
  secureZero(kResp_, sizeof(kResp_));
  secureZero(kMac_, sizeof(kMac_));
  secureZero(eReq_, sizeof(eReq_));
  secureZero(eResp_, sizeof(eResp_));
  secureZero(eMac_, sizeof(eMac_));
  memset(replay_, 0, sizeof(replay_));

  bool allOk = true;
  if (editState == EditState::Custom) {
    if (editToken.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN || editToken.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) {
      edit_ = EditState::Invalid; // never "unset": an unusable edit token must not open editing to everybody
      allOk = false;
    } else {
      DerivedKeys keys;
      const bool ok = deriveKeys(crypto_, editToken, keys, true);
      if (ok) {
        memcpy(eReq_, keys.req, 32);
        memcpy(eResp_, keys.resp, 32);
        memcpy(eMac_, keys.mac, 32);
      }
      secureZero(&keys, sizeof(keys));
      editReady_ = ok;
      if (!ok) { edit_ = EditState::Invalid; allOk = false; }
    }
  }
  if (state == TokenState::Invalid) return allOk; // read-only by design

  if (token.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN || token.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) {
    state_ = TokenState::Invalid;
    return false;
  }
  DerivedKeys keys;
  const bool ok = deriveKeys(crypto_, token, keys);
  if (ok) {
    memcpy(kReq_, keys.req, 32);
    memcpy(kResp_, keys.resp, 32);
    memcpy(kMac_, keys.mac, 32);
  }
  secureZero(&keys, sizeof(keys));
  keysReady_ = ok;
  if (!ok) state_ = TokenState::Invalid;
  return ok && allOk;
}

bool SecureTransport::validNonce(const std::string &nonce) {
  if (nonce.size() < 16 || nonce.size() > 64) return false;
  for (size_t i = 0; i < nonce.size(); i++) {
    const char c = nonce[i];
    if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_')) return false;
  }
  return true;
}

// ---- MAC frames ---------------------------------------------------------------------------

bool SecureTransport::computeMac(const uint8_t key[32], const char *prefix, size_t prefixLength, const char *doc,
                                 size_t docLength, uint8_t out[32]) const {
  ByteRange parts[2] = {{(const uint8_t *)prefix, prefixLength}, {(const uint8_t *)doc, docLength}};
  return crypto_.hmacSha256(key, 32, parts, 2, out);
}

bool SecureTransport::frame(const uint8_t key[32], const std::string &prefix, const std::string &doc, std::string &out) const {
  uint8_t mac[32];
  if (!computeMac(key, prefix.data(), prefix.size(), doc.data(), doc.size(), mac)) return false;
  return Escape::guardAlloc([&]() -> bool {
    std::string text;
    base64UrlEncode(mac, sizeof(mac), text);
    out.clear();
    out.reserve(kFrameHeadLen + doc.size() + kFrameMacKeyLen + text.size() + 2);
    out.append(kFrameHead, kFrameHeadLen);
    out += doc;
    out.append(kFrameMacKey, kFrameMacKeyLen);
    out += text;
    out += "\"}";
    return true;
  }, false);
}

bool SecureTransport::openFrame(const uint8_t key[32], const std::string &prefix, const char *body, size_t length,
                                EscapeJson::Slice &doc) const {
  const size_t tail = kFrameMacKeyLen + kMacTextLen + 2;
  if (length < kFrameHeadLen + 2 + tail) return false;
  if (memcmp(body, kFrameHead, kFrameHeadLen) != 0) return false;
  if (body[length - 2] != '"' || body[length - 1] != '}') return false;
  const size_t docEnd = length - tail;
  if (memcmp(body + docEnd, kFrameMacKey, kFrameMacKeyLen) != 0) return false;
  std::vector<uint8_t> mac;
  if (!base64UrlDecode(body + docEnd + kFrameMacKeyLen, kMacTextLen, mac) || mac.size() != 32) return false;
  uint8_t expected[32];
  if (!computeMac(key, prefix.data(), prefix.size(), body + kFrameHeadLen, docEnd - kFrameHeadLen, expected)) return false;
  if (!constantTimeEqual(mac.data(), expected, 32)) return false;
  doc.p = body + kFrameHeadLen;
  doc.n = docEnd - kFrameHeadLen;
  return true;
}

bool SecureTransport::frameDocument(const std::string &path, const std::string &nonce, int status,
                                    const std::string &doc, std::string &out) const {
  if (!validNonce(nonce) || !keysReady_) return false;
  return frame(kMac_, "EM2|get|" + did_ + "|" + path + "|" + nonce + "|" + decimal((uint32_t)status) + "|", doc, out);
}

bool SecureTransport::frameEditDocument(const std::string &path, const std::string &nonce, int status,
                                        const std::string &doc, std::string &out) const {
  if (!validNonce(nonce) || !editReady_) return false;
  return frame(eMac_, "EM2|eget|" + did_ + "|" + path + "|" + nonce + "|" + decimal((uint32_t)status) + "|", doc, out);
}

bool SecureTransport::openEditDocumentFrame(const std::string &path, const std::string &nonce, int status,
                                            const char *body, size_t length, EscapeJson::Slice &doc) const {
  if (!validNonce(nonce) || !editReady_) return false;
  return openFrame(eMac_, "EM2|eget|" + did_ + "|" + path + "|" + nonce + "|" + decimal((uint32_t)status) + "|", body, length, doc);
}

bool SecureTransport::signSkeleton(const std::string &room, uint32_t rev, uint32_t hash, std::string &emac) const {
  if (!editReady_) return false;
  const std::string text = "EM2|skel|" + room + "|" + decimal(rev) + "|" + hex8(hash);
  uint8_t mac[32];
  if (!computeMac(eMac_, text.data(), text.size(), "", 0, mac)) return false;
  return Escape::guardAlloc([&]() -> bool { emac = base64UrlEncode(mac, sizeof(mac)); return true; }, false);
}

bool SecureTransport::verifySkeleton(const std::string &room, uint32_t rev, uint32_t hash, const std::string &emac) const {
  if (!editReady_ || emac.size() != kMacTextLen) return false;
  std::vector<uint8_t> given;
  if (!base64UrlDecode(emac, given) || given.size() != 32) return false;
  const std::string text = "EM2|skel|" + room + "|" + decimal(rev) + "|" + hex8(hash);
  uint8_t expected[32];
  if (!computeMac(eMac_, text.data(), text.size(), "", 0, expected)) return false;
  return constantTimeEqual(given.data(), expected, 32);
}

bool SecureTransport::openDocumentFrameFrom(const std::string &fromDid, const std::string &path,
                                            const std::string &nonce, int status, const char *body,
                                            size_t length, EscapeJson::Slice &doc) const {
  if (!validNonce(nonce) || !keysReady_) return false;
  return openFrame(kMac_, "EM2|get|" + fromDid + "|" + path + "|" + nonce + "|" + decimal((uint32_t)status) + "|", body, length, doc);
}

bool SecureTransport::frameAnnouncement(const std::string &doc, std::string &out) const {
  if (!keysReady_) return false;
  return frame(kMac_, "EM2|udp|", doc, out);
}

bool SecureTransport::openAnnouncement(const char *data, size_t length, EscapeJson::Slice &doc) const {
  if (!keysReady_) return false;
  return openFrame(kMac_, "EM2|udp|", data, length, doc);
}

// ---- AEAD envelopes -----------------------------------------------------------------------

bool SecureTransport::seal(const uint8_t key[32], const std::string &aad, const uint8_t iv[12],
                           const std::string &plaintext, std::string &ctB64) const {
  return Escape::guardAlloc([&]() -> bool {
    std::vector<uint8_t> buffer(plaintext.size() + 16);
    if (!plaintext.empty()) memcpy(buffer.data(), plaintext.data(), plaintext.size());
    uint8_t tag[16];
    if (!crypto_.aes256GcmEncrypt(key, iv, (const uint8_t *)aad.data(), aad.size(), buffer.data(),
                                  plaintext.size(), buffer.data(), tag)) return false;
    memcpy(buffer.data() + plaintext.size(), tag, 16);
    base64UrlEncode(buffer.data(), buffer.size(), ctB64);
    return true;
  }, false);
}

bool SecureTransport::sealRequest(const std::string &path, uint32_t t, const std::string &plaintext,
                                  const uint8_t iv[12], std::string &envelope, KeyRole role) const {
  if (!roleReady(role)) return false;
  const std::string aad = "EM2|req|" + did_ + "|" + path + "|" + decimal(t);
  std::string ct;
  if (!seal(reqKey(role), aad, iv, plaintext, ct)) return false;
  return Escape::guardAlloc([&]() -> bool {
    envelope = "{\"v\":" + decimal(EscapeVersion::PROTO) + ",\"t\":" + decimal(t) + ",\"iv\":\"" +
               base64UrlEncode(iv, 12) + "\",\"ct\":\"" + ct + "\"" + (role == KeyRole::Edit ? ",\"k\":\"e\"" : "") + "}";
    return true;
  }, false);
}

bool SecureTransport::sealResponse(const std::string &path, const std::string &requestIv, int status,
                                   const std::string &body, std::string &envelope, KeyRole role) const {
  if (!roleReady(role)) return false;
  uint8_t iv[12];
  if (!crypto_.randomBytes(iv, sizeof(iv))) return false;
  const std::string aad = "EM2|resp|" + did_ + "|" + path + "|" + requestIv + "|" + decimal((uint32_t)status);
  std::string ct;
  if (!seal(respKey(role), aad, iv, body, ct)) return false;
  return Escape::guardAlloc([&]() -> bool {
    envelope = "{\"v\":" + decimal(EscapeVersion::PROTO) + ",\"iv\":\"" + base64UrlEncode(iv, 12) + "\",\"ct\":\"" + ct + "\"}";
    return true;
  }, false);
}

bool SecureTransport::openResponse(const std::string &path, const std::string &requestIv, int status,
                                   const char *body, size_t length, std::string &plaintext, KeyRole role) const {
  if (!roleReady(role)) return false;
  EscapeJson::Slice sv, siv, sct;
  if (EscapeJson::findField(body, length, "v", sv) != EscapeJson::Scan::Found) return false;
  if (EscapeJson::findField(body, length, "iv", siv) != EscapeJson::Scan::Found) return false;
  if (EscapeJson::findField(body, length, "ct", sct) != EscapeJson::Scan::Found) return false;
  uint32_t v = 0;
  if (!EscapeJson::sliceToUInt(sv, 255, v) || v < EscapeVersion::PROTO_MIN) return false;
  return Escape::guardAlloc([&]() -> bool {
    std::string ivText, ctText;
    std::vector<uint8_t> iv, ct;
    if (!EscapeJson::sliceToString(siv, ivText) || !base64UrlDecode(ivText, iv) || iv.size() != 12) return false;
    if (!EscapeJson::sliceToString(sct, ctText) || !base64UrlDecode(ctText, ct) || ct.size() < 16) return false;
    const std::string aad = "EM2|resp|" + did_ + "|" + path + "|" + requestIv + "|" + decimal((uint32_t)status);
    std::string out(ct.size() - 16, '\0');
    if (!crypto_.aes256GcmDecrypt(respKey(role), iv.data(), (const uint8_t *)aad.data(), aad.size(), ct.data(),
                                  ct.size() - 16, ct.data() + ct.size() - 16,
                                  out.empty() ? nullptr : (uint8_t *)&out[0])) return false;
    plaintext.swap(out);
    return true;
  }, false);
}

OpenResult SecureTransport::openRequest(const std::string &path, const char *body, size_t length,
                                        uint32_t nowMs, std::string &plaintext, std::string &requestIv) {
  plaintext.clear();
  requestIv.clear();
  if (length > EscapeConfig::MAX_BODY_BYTES) return OpenResult{413, "too_large"};

  EscapeJson::Slice sv, st, siv, sct;
  if (EscapeJson::findField(body, length, "v", sv) != EscapeJson::Scan::Found ||
      EscapeJson::findField(body, length, "t", st) != EscapeJson::Scan::Found ||
      EscapeJson::findField(body, length, "iv", siv) != EscapeJson::Scan::Found ||
      EscapeJson::findField(body, length, "ct", sct) != EscapeJson::Scan::Found) {
    return OpenResult{400, "bad_envelope"};
  }
  uint32_t v = 0, t = 0;
  if (!EscapeJson::sliceToUInt(sv, 255, v) || v < EscapeVersion::PROTO_MIN || v > EscapeVersion::PROTO ||
      !EscapeJson::sliceToUInt(st, 0xFFFFFFFFu, t)) {
    return OpenResult{400, "bad_envelope"};
  }
  // Optional key selector (additive field, PROTOCOL.md 3.1). Older devices ignore it and fail to authenticate.
  KeyRole role = KeyRole::Normal;
  {
    EscapeJson::Slice sk;
    const EscapeJson::Scan scan = EscapeJson::findField(body, length, "k", sk);
    if (scan == EscapeJson::Scan::Invalid) return OpenResult{400, "bad_envelope"};
    if (scan == EscapeJson::Scan::Found) {
      if (sk.n == 3 && sk.p[0] == '"' && sk.p[1] == 'e' && sk.p[2] == '"') role = KeyRole::Edit;
      else return OpenResult{400, "bad_envelope"};
    }
  }
  if (role == KeyRole::Edit && !isEditPath(path)) return OpenResult{400, "bad_envelope"};

  struct Local {
    std::string ivText, ctText;
    std::vector<uint8_t> iv, ct;
  };
  OpenResult result = Escape::guardAlloc([&]() -> OpenResult {
    Local l;
    if (!EscapeJson::sliceToString(siv, l.ivText) || !base64UrlDecode(l.ivText, l.iv) || l.iv.size() != 12) {
      return OpenResult{400, "bad_envelope"};
    }
    if (!writable()) return OpenResult{503, "read_only"};
    requestIv = l.ivText; // from here on errors can be answered authenticated
    // Errors are sealed with the NORMAL key set unless the request itself was edit-authenticated: a
    // request that cannot be authenticated must not get an answer only an edit-token holder can read.
    if (isEditPath(path) && edit_ == EditState::Invalid) return OpenResult{503, "read_only"};
    if (role == KeyRole::Edit && !editReady_) return OpenResult{401, "auth_failed"}; // no edit token here

    const int32_t skew = (int32_t)(t - nowMs);
    if (skew > (int32_t)EscapeConfig::TIME_WINDOW_MS || skew < -(int32_t)EscapeConfig::TIME_WINDOW_MS) {
      return OpenResult{409, "stale_time"};
    }
    if (!EscapeJson::sliceToString(sct, l.ctText) || !base64UrlDecode(l.ctText, l.ct) || l.ct.size() < 16) {
      return OpenResult{400, "bad_envelope"};
    }
    const std::string aad = "EM2|req|" + did_ + "|" + path + "|" + decimal(t);
    std::string out(l.ct.size() - 16, '\0');
    if (!crypto_.aes256GcmDecrypt(reqKey(role), l.iv.data(), (const uint8_t *)aad.data(), aad.size(), l.ct.data(),
                                  l.ct.size() - 16, l.ct.data() + l.ct.size() - 16,
                                  out.empty() ? nullptr : (uint8_t *)&out[0])) {
      return OpenResult{401, "auth_failed"};
    }

    // Replay cache: only authenticated requests may enter it.
    ReplayEntry *freeSlot = nullptr;
    for (size_t i = 0; i < EscapeConfig::REPLAY_CACHE_SIZE; i++) {
      ReplayEntry &e = replay_[i];
      if (e.used && (int32_t)(nowMs - e.expiresMs) > 0) e.used = false; // window passed
      if (!e.used) {
        if (!freeSlot) freeSlot = &e;
      } else if (memcmp(e.iv, l.iv.data(), sizeof(e.iv)) == 0) {
        return OpenResult{409, "replay"};
      }
    }
    if (!freeSlot) return OpenResult{429, "rate_limited"}; // fail closed
    freeSlot->used = true;
    freeSlot->expiresMs = t + EscapeConfig::TIME_WINDOW_MS;
    memcpy(freeSlot->iv, l.iv.data(), sizeof(freeSlot->iv));
    // Authenticated with the normal key set, but this path belongs to the edit-token holders.
    if (role == KeyRole::Normal && isEditPath(path) && edit_ == EditState::Custom) {
      return OpenResult{403, "edit_required", KeyRole::Normal};
    }
    plaintext.swap(out);
    return OpenResult{200, nullptr, role};
  }, OpenResult{503, "storage_full"});
  return result;
}

size_t SecureTransport::replayEntries(uint32_t nowMs) const {
  size_t n = 0;
  for (size_t i = 0; i < EscapeConfig::REPLAY_CACHE_SIZE; i++) {
    if (replay_[i].used && (int32_t)(nowMs - replay_[i].expiresMs) <= 0) n++;
  }
  return n;
}

} // namespace Escape
