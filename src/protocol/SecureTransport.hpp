#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace EscapeSecurity {

// Plattformvertrag fuer die wenigen standardisierten Primitive, die der
// sichere Transport benoetigt. SecureTransport.cpp kennt dadurch weder
// mbedTLS noch OpenSSL noch eine bestimmte Hardware. Eine neue Plattform muss
// nur dieses Interface gegen ihre vorhandene Krypto-Bibliothek implementieren.
class CryptoBackend {
public:
  virtual ~CryptoBackend() {}

  virtual bool randomBytes(size_t size, std::vector<uint8_t> &out) = 0;
  virtual bool sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &out) = 0;
  virtual bool hmacSha256(const std::vector<uint8_t> &key, const std::string &message,
                          std::vector<uint8_t> &out) = 0;
  virtual bool generateP256KeyPair(std::vector<uint8_t> &privateKey,
                                   std::vector<uint8_t> &publicKey) = 0;
  virtual bool p256SharedSecret(const std::vector<uint8_t> &privateKey,
                                const std::vector<uint8_t> &peerPublicKey,
                                std::vector<uint8_t> &sharedSecret) = 0;
  virtual bool hkdfSha256(const std::vector<uint8_t> &inputKey,
                          const std::vector<uint8_t> &salt,
                          const std::string &info, size_t outputSize,
                          std::vector<uint8_t> &out) = 0;
  // ciphertextAndTag enthaelt den 16-Byte-GCM-Tag direkt hinter dem Ciphertext.
  virtual bool aes256GcmEncrypt(const std::vector<uint8_t> &key,
                                const std::vector<uint8_t> &iv,
                                const std::string &aad,
                                const std::vector<uint8_t> &plaintext,
                                std::vector<uint8_t> &ciphertextAndTag) = 0;
  virtual bool aes256GcmDecrypt(const std::vector<uint8_t> &key,
                                const std::vector<uint8_t> &iv,
                                const std::string &aad,
                                const std::vector<uint8_t> &ciphertextAndTag,
                                std::vector<uint8_t> &plaintext) = 0;
};

// Verschluesselt werden ausschliesslich schreibende HTTP-Requests. Der
// Public Key aus /security.json ist selbst per token-abgeleitetem AES-256-GCM
// verschluesselt und authentifiziert. Erst danach folgt pro Request ein
// ephemerer P-256-ECDH-Austausch mit HKDF-SHA-256 und AES-256-GCM. Eine HMAC
// ueber die gesamte Huelle weist den Absender als Token-Inhaber aus, ohne den
// Auth-Token selbst ueber das Netzwerk zu senden.
class SecureTransport {
public:
  enum class Mode : uint8_t {
    Uninitialized,
    ReadOnly,
    SecureReadWrite
  };

  // Plattformen ohne CryptoBackend koennen den sicheren Transport trotzdem
  // im Read-only-Modus betreiben: GET-Endpunkte bleiben erreichbar, waehrend
  // decryptRequest() jeden Schreibversuch mit HTTP 503 ablehnt.
  explicit SecureTransport(const std::string &authToken);
  SecureTransport(const std::string &authToken, CryptoBackend &crypto);

  SecureTransport(const SecureTransport &) = delete;
  SecureTransport &operator=(const SecureTransport &) = delete;

  // Erlaubt Plattformadaptern, einen persistent gespeicherten Token NACH der
  // globalen Objektkonstruktion, aber VOR begin() zu setzen. Nach Beginn des
  // Schluessel-Lebenszyklus ist ein Wechsel absichtlich nicht mehr moeglich.
  bool setAuthToken(const std::string &authToken);

  // Initialisiert mindestens den Read-only-Fallback. Ein fehlendes oder nicht
  // funktionsfaehiges Backend ist deshalb kein Grund, den HTTP-Server nicht zu
  // starten. secureWritesAvailable() unterscheidet beide Betriebsarten.
  bool begin();
  bool ready() const { return mode_ != Mode::Uninitialized; }
  bool secureWritesAvailable() const { return mode_ == Mode::SecureReadWrite; }
  bool readOnly() const { return mode_ == Mode::ReadOnly; }
  Mode mode() const { return mode_; }
  std::string securityDocument() const;

  // Authentifiziert beliebige Protokolldokumente (UDP, GET-Antworten,
  // POST-Antworten) mit dem provisionierten Token. Der Kontext bindet die
  // Signatur an Transportart, Pfad, Nonce bzw. Request-ID.
  bool protectDocument(const std::string &context, const std::string &plaintext,
                       std::string &authenticatedDocument) const;
  bool unprotectDocument(const std::string &context, const std::string &authenticatedDocument,
                         std::string &plaintext) const;

  bool decryptRequest(const std::string &path, const std::string &envelopeJson,
                      std::string &plaintext, int &status, std::string &error,
                      std::string *requestId = nullptr);

private:
  std::string authToken_;
  CryptoBackend *crypto_;
  std::vector<uint8_t> privateKey_;
  std::string keyId_;
  std::string keySalt_;
  std::string keyIv_;
  std::string encryptedPublicKey_;
  std::vector<std::string> replayIvs_;
  Mode mode_ = Mode::Uninitialized;
};

} // namespace EscapeSecurity
