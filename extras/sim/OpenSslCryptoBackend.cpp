#include "OpenSslCryptoBackend.hpp"

#include <cstring>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

namespace Escape {

bool OpenSslCryptoBackend::randomBytes(uint8_t *out, size_t length) {
  return length == 0 || RAND_bytes(out, (int)length) == 1;
}

bool OpenSslCryptoBackend::hmacSha256(const uint8_t *key, size_t keyLength, const ByteRange *parts,
                                      size_t partCount, uint8_t out[32]) {
  static const uint8_t dummy = 0;
  EVP_MAC *mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
  if (!mac) return false;
  EVP_MAC_CTX *ctx = EVP_MAC_CTX_new(mac);
  bool ok = ctx != nullptr;
  if (ok) {
    OSSL_PARAM params[2];
    params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_DIGEST, (char *)"SHA256", 0);
    params[1] = OSSL_PARAM_construct_end();
    ok = EVP_MAC_init(ctx, key ? key : &dummy, keyLength, params) == 1;
    for (size_t i = 0; ok && i < partCount; i++) {
      if (parts[i].length) ok = EVP_MAC_update(ctx, parts[i].data, parts[i].length) == 1;
    }
    size_t produced = 0;
    ok = ok && EVP_MAC_final(ctx, out, &produced, 32) == 1 && produced == 32;
  }
  EVP_MAC_CTX_free(ctx);
  EVP_MAC_free(mac);
  return ok;
}

bool OpenSslCryptoBackend::pbkdf2Sha256(const uint8_t *password, size_t passwordLength, const uint8_t *salt,
                                        size_t saltLength, uint32_t iterations, uint8_t *out, size_t outLength) {
  return PKCS5_PBKDF2_HMAC((const char *)password, (int)passwordLength, salt, (int)saltLength, (int)iterations,
                           EVP_sha256(), (int)outLength, out) == 1;
}

bool OpenSslCryptoBackend::aes256GcmEncrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                            size_t aadLength, const uint8_t *in, size_t inLength, uint8_t *out,
                                            uint8_t tag[16]) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int len = 0;
  bool ok = EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1;
  if (ok && aadLength) ok = EVP_EncryptUpdate(ctx, nullptr, &len, aad, (int)aadLength) == 1;
  if (ok && inLength) ok = EVP_EncryptUpdate(ctx, out, &len, in, (int)inLength) == 1;
  if (ok) ok = EVP_EncryptFinal_ex(ctx, out + inLength, &len) == 1;
  if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) == 1;
  EVP_CIPHER_CTX_free(ctx);
  return ok;
}

bool OpenSslCryptoBackend::aes256GcmDecrypt(const uint8_t key[32], const uint8_t iv[12], const uint8_t *aad,
                                            size_t aadLength, const uint8_t *in, size_t inLength,
                                            const uint8_t tag[16], uint8_t *out) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx) return false;
  int len = 0;
  uint8_t tagCopy[16];
  memcpy(tagCopy, tag, 16);
  bool ok = EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) == 1 &&
            EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) == 1;
  if (ok && aadLength) ok = EVP_DecryptUpdate(ctx, nullptr, &len, aad, (int)aadLength) == 1;
  if (ok && inLength) ok = EVP_DecryptUpdate(ctx, out, &len, in, (int)inLength) == 1;
  if (ok) ok = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tagCopy) == 1;
  if (ok) ok = EVP_DecryptFinal_ex(ctx, out + inLength, &len) == 1;
  EVP_CIPHER_CTX_free(ctx);
  if (!ok && out && inLength) memset(out, 0, inLength); // never release unverified plaintext
  return ok;
}

} // namespace Escape
