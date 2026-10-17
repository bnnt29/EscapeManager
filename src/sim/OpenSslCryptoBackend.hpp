#pragma once

// CryptoBackend for PC builds (simulator, native tests, tools) on top of OpenSSL
// 3.x (libcrypto; Debian/Ubuntu package libssl-dev).

#include "../protocol/CryptoBackend.hpp"

namespace Escape {

class OpenSslCryptoBackend : public CryptoBackend {
public:
  bool randomBytes(uint8_t *out, size_t length) override;
  bool hmacSha256(const uint8_t *key, size_t keyLength, const ByteRange *parts, size_t partCount,
                  uint8_t out[32]) override;
  bool pbkdf2Sha256(const uint8_t *password, size_t passwordLength, const uint8_t *salt, size_t saltLength,
                    uint32_t iterations, uint8_t *out, size_t outLength) override;
  bool aes256GcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadLength,
                        const uint8_t *in, size_t inLength, uint8_t *out, uint8_t tag[16]) override;
  bool aes256GcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad, size_t aadLength,
                        const uint8_t *in, size_t inLength, const uint8_t tag[16], uint8_t *out) override;
};

} // namespace Escape
