#pragma once

// Platform contract for the few primitives the secure transport needs. The
// portable code (SecureTransport.cpp) knows neither mbedTLS nor OpenSSL; a new
// platform implements this interface against its crypto library. Pointer based so
// large bodies are never copied just to cross this boundary.

#include <cstddef>
#include <cstdint>

namespace Escape {

struct ByteRange {
  const uint8_t *data;
  size_t length;
};

class CryptoBackend {
public:
  virtual ~CryptoBackend() {}

  // Cryptographically secure random bytes.
  virtual bool randomBytes(uint8_t *out, size_t length) = 0;

  // HMAC-SHA-256 over the concatenation of `partCount` ranges.
  virtual bool hmacSha256(const uint8_t *key, size_t keyLength, const ByteRange *parts, size_t partCount,
                          uint8_t out[32]) = 0;

  virtual bool pbkdf2Sha256(const uint8_t *password, size_t passwordLength, const uint8_t *salt,
                            size_t saltLength, uint32_t iterations, uint8_t *out, size_t outLength) = 0;

  // `out` has the same length as `in` (may be the same buffer). tag is 16 bytes.
  virtual bool aes256GcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                size_t aadLength, const uint8_t *in, size_t inLength, uint8_t *out,
                                uint8_t tag[16]) = 0;
  // Must not release plaintext when the tag does not verify (zero `out` and return false).
  virtual bool aes256GcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                size_t aadLength, const uint8_t *in, size_t inLength, const uint8_t tag[16],
                                uint8_t *out) = 0;
};

// HKDF-SHA-256 (RFC 5869) on top of hmacSha256. An empty salt means "HashLen zeros".
// outLength is at most 255 * 32.
bool hkdfSha256(CryptoBackend &crypto, const uint8_t *ikm, size_t ikmLength, const uint8_t *salt,
                size_t saltLength, const uint8_t *info, size_t infoLength, uint8_t *out, size_t outLength);

// Overwrites memory in a way the optimiser may not drop.
void secureZero(void *p, size_t n);

// Compares in constant time (for MACs/tags).
bool constantTimeEqual(const uint8_t *a, const uint8_t *b, size_t n);

} // namespace Escape
