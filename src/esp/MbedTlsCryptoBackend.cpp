#include "MbedTlsCryptoBackend.hpp"

#include <cstring>
#include <esp_system.h>
#if defined(__has_include)
#if __has_include(<esp_random.h>)
#include <esp_random.h> // esp_fill_random() moved here with ESP-IDF 5 (Arduino-ESP32 3.x)
#endif
#endif
#include <mbedtls/gcm.h>
#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/version.h>

namespace Escape {

bool MbedTlsCryptoBackend::randomBytes(uint8_t *out, size_t length) {
  esp_fill_random(out, length);
  return true;
}

bool MbedTlsCryptoBackend::hmacSha256(const uint8_t *key, size_t keyLength, const ByteRange *parts,
                                      size_t partCount, uint8_t out[32]) {
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  bool ok = mbedtls_md_setup(&ctx, info, 1) == 0 && mbedtls_md_hmac_starts(&ctx, key, keyLength) == 0;
  for (size_t i = 0; ok && i < partCount; i++) {
    if (parts[i].length) ok = mbedtls_md_hmac_update(&ctx, parts[i].data, parts[i].length) == 0;
  }
  ok = ok && mbedtls_md_hmac_finish(&ctx, out) == 0;
  mbedtls_md_free(&ctx);
  return ok;
}

bool MbedTlsCryptoBackend::pbkdf2Sha256(const uint8_t *password, size_t passwordLength, const uint8_t *salt,
                                        size_t saltLength, uint32_t iterations, uint8_t *out, size_t outLength) {
#if MBEDTLS_VERSION_NUMBER >= 0x03030000
  // mbedTLS 3.3+ (Arduino-ESP32 3.x): the context-based variant is deprecated and removed from the headers.
  return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, password, passwordLength, salt, saltLength, iterations,
                                       (uint32_t)outLength, out) == 0;
#else
  const mbedtls_md_info_t *info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (!info) return false;
  mbedtls_md_context_t ctx;
  mbedtls_md_init(&ctx);
  bool ok = mbedtls_md_setup(&ctx, info, 1) == 0 &&
            mbedtls_pkcs5_pbkdf2_hmac(&ctx, password, passwordLength, salt, saltLength, iterations,
                                      (uint32_t)outLength, out) == 0;
  mbedtls_md_free(&ctx);
  return ok;
#endif
}

bool MbedTlsCryptoBackend::aes256GcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                            size_t aadLength, const uint8_t *in, size_t inLength, uint8_t *out,
                                            uint8_t tag[16]) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
            mbedtls_gcm_crypt_and_tag(&ctx, MBEDTLS_GCM_ENCRYPT, inLength, iv, 12, aad, aadLength, in, out, 16,
                                      tag) == 0;
  mbedtls_gcm_free(&ctx);
  return ok;
}

bool MbedTlsCryptoBackend::aes256GcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                            size_t aadLength, const uint8_t *in, size_t inLength,
                                            const uint8_t tag[16], uint8_t *out) {
  mbedtls_gcm_context ctx;
  mbedtls_gcm_init(&ctx);
  bool ok = mbedtls_gcm_setkey(&ctx, MBEDTLS_CIPHER_ID_AES, key, 256) == 0 &&
            mbedtls_gcm_auth_decrypt(&ctx, inLength, iv, 12, aad, aadLength, tag, 16, in, out) == 0;
  mbedtls_gcm_free(&ctx);
  if (!ok && out && inLength) memset(out, 0, inLength);
  return ok;
}

} // namespace Escape
