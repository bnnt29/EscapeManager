#include "SecureTransport.hpp"

#include "EscapeConfig.hpp"

#include "Json.hpp"

#include <algorithm>

namespace EscapeSecurity {

namespace {

const char *kKeyAadContext = "EscapeManager key v2";
const char *kKeyWrapContext = "EscapeManager key-wrap v2";
const char *kRequestContext = "EscapeManager request v2";
const char *kDocumentContext = "EscapeManager document v1";
const size_t kReplayWindow = 32;
const size_t kMaxSecureEnvelopeLength = 12 * 1024;

std::vector<uint8_t> bytes(const std::string &value) {
  return std::vector<uint8_t>(value.begin(), value.end());
}

std::string base64UrlEncode(const uint8_t *data, size_t size) {
  static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  std::string out;
  out.reserve((size * 4 + 2) / 3);
  for (size_t i = 0; i < size; i += 3) {
    uint32_t value = (uint32_t)data[i] << 16;
    if (i + 1 < size) value |= (uint32_t)data[i + 1] << 8;
    if (i + 2 < size) value |= data[i + 2];
    out += alphabet[(value >> 18) & 63];
    out += alphabet[(value >> 12) & 63];
    if (i + 1 < size) out += alphabet[(value >> 6) & 63];
    if (i + 2 < size) out += alphabet[value & 63];
  }
  return out;
}

std::string base64UrlEncode(const std::vector<uint8_t> &data) {
  return base64UrlEncode(data.data(), data.size());
}

int base64UrlValue(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '-') return 62;
  if (c == '_') return 63;
  return -1;
}

bool base64UrlDecode(const std::string &text, std::vector<uint8_t> &out) {
  if (text.empty() || text.find('=') != std::string::npos || text.size() % 4 == 1) return false;
  out.clear();
  out.reserve(text.size() * 3 / 4);
  uint32_t buffer = 0;
  int bits = 0;
  for (size_t i = 0; i < text.size(); i++) {
    int value = base64UrlValue(text[i]);
    if (value < 0) return false;
    buffer = (buffer << 6) | (uint32_t)value;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back((uint8_t)((buffer >> bits) & 0xFF));
    }
  }
  return !bits || (buffer & ((1u << bits) - 1u)) == 0;
}

bool constantTimeEquals(const std::vector<uint8_t> &left, const std::vector<uint8_t> &right) {
  uint8_t difference = (uint8_t)(left.size() != right.size());
  const size_t size = std::min(left.size(), right.size());
  for (size_t i = 0; i < size; i++) difference |= left[i] ^ right[i];
  return difference == 0;
}

std::string fieldString(const EscapeJson::Value &object, const char *key) {
  const EscapeJson::Value *value = object.find(key);
  return value && value->type == EscapeJson::Type::String ? value->stringValue : std::string();
}

std::string keyAad(const std::string &keyId) {
  return std::string(kKeyAadContext) + "\n" + keyId;
}

std::string keyWrapInfo(const std::string &keyId) {
  return std::string(kKeyWrapContext) + "\n" + keyId;
}

std::string requestInfo(const std::string &path, const std::string &keyId) {
  return std::string(kRequestContext) + "\n" + path + "\n" + keyId;
}

std::string requestProof(const std::string &path, const std::string &keyId,
                         const std::string &ephemeralKey, const std::string &salt,
                         const std::string &iv, const std::string &ciphertext) {
  return requestInfo(path, keyId) + "\n" + ephemeralKey + "\n" + salt + "\n" + iv + "\n" + ciphertext;
}

std::string documentProof(const std::string &context, const std::string &encodedPayload) {
  return std::string(kDocumentContext) + "\n" + context + "\n" + encodedPayload;
}

} // namespace

SecureTransport::SecureTransport(const std::string &authToken)
    : authToken_(authToken), crypto_(nullptr) {}

SecureTransport::SecureTransport(const std::string &authToken, CryptoBackend &crypto)
    : authToken_(authToken), crypto_(&crypto) {}

bool SecureTransport::setAuthToken(const std::string &authToken) {
  if (mode_ != Mode::Uninitialized) return false;
  authToken_ = authToken;
  return true;
}

bool SecureTransport::begin() {
  if (mode_ == Mode::SecureReadWrite) return true;

  // Read-only ist ein gueltiger Betriebszustand: dadurch kann der Aufrufer
  // seine GET-Routen auch ohne Krypto-Backend registrieren und starten.
  mode_ = Mode::ReadOnly;
  privateKey_.clear();
  keyId_.clear();
  keySalt_.clear();
  keyIv_.clear();
  encryptedPublicKey_.clear();
  replayIvs_.clear();

  if (!crypto_ || authToken_.size() < EscapeConfig::MIN_AUTH_TOKEN_LEN ||
      authToken_.size() > EscapeConfig::MAX_AUTH_TOKEN_LEN) return true;

  CryptoBackend &crypto = *crypto_;

  std::vector<uint8_t> privateKey;
  std::vector<uint8_t> publicKey;
  std::vector<uint8_t> digest;
  std::vector<uint8_t> salt;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> wrappingKey;
  std::vector<uint8_t> encryptedPublicKey;
  if (!crypto.generateP256KeyPair(privateKey, publicKey) || privateKey.size() != 32 || publicKey.size() != 65 ||
      !crypto.sha256(publicKey, digest) || digest.size() != 32) {
    return true;
  }

  const std::string keyId = base64UrlEncode(digest.data(), 12);
  if (!crypto.randomBytes(16, salt) || !crypto.randomBytes(12, iv) ||
      !crypto.hkdfSha256(bytes(authToken_), salt, keyWrapInfo(keyId), 32, wrappingKey) ||
      !crypto.aes256GcmEncrypt(wrappingKey, iv, keyAad(keyId), publicKey, encryptedPublicKey)) {
    return true;
  }

  // Schluesselmaterial erst veroeffentlichen, nachdem ALLE Schritte
  // erfolgreich waren. Bei Teilfehlern bleibt das Objekt sicher read-only.
  privateKey_.swap(privateKey);
  keyId_ = keyId;
  keySalt_ = base64UrlEncode(salt);
  keyIv_ = base64UrlEncode(iv);
  encryptedPublicKey_ = base64UrlEncode(encryptedPublicKey);
  mode_ = Mode::SecureReadWrite;
  return true;
}

std::string SecureTransport::securityDocument() const {
  const char *allowTokenInUrl = EscapeConfig::ALLOW_AUTH_TOKEN_IN_URL ? "true" : "false";
  const char *authenticatedGets = EscapeConfig::AUTHENTICATE_GET_REQUESTS ? "true" : "false";
  if (mode_ == Mode::Uninitialized) {
    return std::string("{\"version\":2,\"available\":false,\"readOnly\":true,") +
           "\"allowTokenInUrl\":" + allowTokenInUrl + ",\"authenticatedGets\":" + authenticatedGets +
           ",\"reason\":\"not-initialized\"}";
  }
  if (mode_ == Mode::ReadOnly) {
    return std::string("{\"version\":2,\"available\":false,\"readOnly\":true,") +
           "\"allowTokenInUrl\":" + allowTokenInUrl +
           ",\"authenticatedGets\":" + authenticatedGets +
           ",\"reason\":\"secure-writes-unavailable\"}";
  }
  return std::string("{\"version\":2,\"available\":true,\"readOnly\":false,"
                     "\"allowTokenInUrl\":") + allowTokenInUrl +
         ",\"authenticatedGets\":" + authenticatedGets +
         ",\"curve\":\"P-256\",\"keyId\":\"" + keyId_ +
         "\",\"salt\":\"" + keySalt_ + "\",\"iv\":\"" + keyIv_ +
         "\",\"encryptedPublicKey\":\"" + encryptedPublicKey_ + "\"}";
}

bool SecureTransport::protectDocument(const std::string &context, const std::string &plaintext,
                                      std::string &authenticatedDocument) const {
  authenticatedDocument.clear();
  if (mode_ != Mode::SecureReadWrite || !crypto_ || context.empty()) return false;

  const std::string payload = base64UrlEncode(
      reinterpret_cast<const uint8_t *>(plaintext.data()), plaintext.size());
  std::vector<uint8_t> auth;
  if (!crypto_->hmacSha256(bytes(authToken_), documentProof(context, payload), auth) || auth.size() != 32) {
    return false;
  }
  authenticatedDocument = "{\"v\":1,\"payload\":\"" + payload +
                          "\",\"auth\":\"" + base64UrlEncode(auth) + "\"}";
  return true;
}

bool SecureTransport::unprotectDocument(const std::string &context,
                                        const std::string &authenticatedDocument,
                                        std::string &plaintext) const {
  plaintext.clear();
  if (mode_ != Mode::SecureReadWrite || !crypto_ || context.empty()) return false;

  EscapeJson::Value root;
  if (!EscapeJson::parse(authenticatedDocument, root) || root.type != EscapeJson::Type::Object) return false;
  const EscapeJson::Value *version = root.find("v");
  const std::string payload = fieldString(root, "payload");
  const std::string authText = fieldString(root, "auth");
  if (!version || version->asNumber(0) != 1 || payload.empty() || authText.size() > 64) return false;

  std::vector<uint8_t> suppliedAuth;
  std::vector<uint8_t> expectedAuth;
  std::vector<uint8_t> decodedPayload;
  if (!base64UrlDecode(authText, suppliedAuth) || suppliedAuth.size() != 32 ||
      !crypto_->hmacSha256(bytes(authToken_), documentProof(context, payload), expectedAuth) ||
      !constantTimeEquals(suppliedAuth, expectedAuth) || !base64UrlDecode(payload, decodedPayload)) {
    return false;
  }
  plaintext.assign(decodedPayload.begin(), decodedPayload.end());
  return true;
}

bool SecureTransport::decryptRequest(const std::string &path, const std::string &envelopeJson,
                                     std::string &plaintext, int &status, std::string &error,
                                     std::string *requestId) {
  status = 400;
  error = "invalid secure envelope";
  plaintext.clear();
  if (mode_ != Mode::SecureReadWrite || !crypto_) {
    status = 503;
    error = "secure writes unavailable";
    return false;
  }
  CryptoBackend &crypto = *crypto_;
  if (envelopeJson.size() > kMaxSecureEnvelopeLength) {
    status = 413;
    error = "secure envelope too large";
    return false;
  }

  EscapeJson::Value root;
  if (!EscapeJson::parse(envelopeJson, root) || root.type != EscapeJson::Type::Object) return false;
  const EscapeJson::Value *version = root.find("v");
  const std::string keyId = fieldString(root, "keyId");
  const std::string ephemeralKey = fieldString(root, "ephemeralKey");
  const std::string saltText = fieldString(root, "salt");
  const std::string ivText = fieldString(root, "iv");
  const std::string ciphertextText = fieldString(root, "ciphertext");
  const std::string authText = fieldString(root, "auth");
  if (!version || version->asNumber(0) != 2 || keyId != keyId_ || ephemeralKey.size() > 100 ||
      saltText.size() > 32 || ivText.size() > 24 || ciphertextText.size() > 10000 || authText.size() > 64) {
    return false;
  }

  std::vector<uint8_t> suppliedAuth;
  std::vector<uint8_t> expectedAuth;
  const std::string proof = requestProof(path, keyId, ephemeralKey, saltText, ivText, ciphertextText);
  if (!base64UrlDecode(authText, suppliedAuth) || suppliedAuth.size() != 32 ||
      !crypto.hmacSha256(bytes(authToken_), proof, expectedAuth) ||
      !constantTimeEquals(suppliedAuth, expectedAuth)) {
    status = 401;
    error = "unauthorized";
    return false;
  }

  if (std::find(replayIvs_.begin(), replayIvs_.end(), ivText) != replayIvs_.end()) {
    status = 409;
    error = "replayed request";
    return false;
  }

  std::vector<uint8_t> peerPublic;
  std::vector<uint8_t> salt;
  std::vector<uint8_t> iv;
  std::vector<uint8_t> encrypted;
  std::vector<uint8_t> shared;
  std::vector<uint8_t> requestKey;
  std::vector<uint8_t> cleartext;
  const std::string info = requestInfo(path, keyId);
  if (!base64UrlDecode(ephemeralKey, peerPublic) || !base64UrlDecode(saltText, salt) || salt.size() != 16 ||
      !base64UrlDecode(ivText, iv) || iv.size() != 12 || !base64UrlDecode(ciphertextText, encrypted) ||
      encrypted.size() < 16 || !crypto.p256SharedSecret(privateKey_, peerPublic, shared) ||
      !crypto.hkdfSha256(shared, salt, info, 32, requestKey) ||
      !crypto.aes256GcmDecrypt(requestKey, iv, info, encrypted, cleartext)) {
    return false;
  }

  plaintext.assign(cleartext.begin(), cleartext.end());
  if (requestId) *requestId = ivText;
  replayIvs_.push_back(ivText);
  if (replayIvs_.size() > kReplayWindow) replayIvs_.erase(replayIvs_.begin());
  status = 200;
  error.clear();
  return true;
}

} // namespace EscapeSecurity
