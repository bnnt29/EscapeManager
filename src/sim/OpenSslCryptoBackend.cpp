#include "OpenSslCryptoBackend.hpp"

#include <climits>

#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/opensslv.h>
#include <openssl/rand.h>

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/params.h>
#else
#include <openssl/ec.h>
#include <openssl/obj_mac.h>
#endif

namespace {

#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3

const char *kP256GroupName = "prime256v1";

EVP_PKEY *importP256PrivateKey(const std::vector<uint8_t> &privateKey) {
  BIGNUM *privateValue = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
  OSSL_PARAM_BLD *builder = OSSL_PARAM_BLD_new();
  OSSL_PARAM *params = nullptr;
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY *key = nullptr;
  bool ok = privateValue && builder && context &&
            OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME, kP256GroupName, 0) == 1 &&
            OSSL_PARAM_BLD_push_BN(builder, OSSL_PKEY_PARAM_PRIV_KEY, privateValue) == 1 &&
            (params = OSSL_PARAM_BLD_to_param(builder)) != nullptr &&
            EVP_PKEY_fromdata_init(context) == 1 &&
            EVP_PKEY_fromdata(context, &key, EVP_PKEY_KEYPAIR, params) == 1;

  EVP_PKEY_CTX_free(context);
  OSSL_PARAM_free(params);
  OSSL_PARAM_BLD_free(builder);
  BN_free(privateValue);
  if (!ok) {
    EVP_PKEY_free(key);
    key = nullptr;
  }
  return key;
}

EVP_PKEY *importP256PublicKey(const std::vector<uint8_t> &publicKey) {
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                     const_cast<char *>(kP256GroupName), 0),
    OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                      const_cast<uint8_t *>(publicKey.data()), publicKey.size()),
    OSSL_PARAM_construct_end()
  };
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY *key = nullptr;
  bool ok = context && EVP_PKEY_fromdata_init(context) == 1 &&
            EVP_PKEY_fromdata(context, &key, EVP_PKEY_PUBLIC_KEY, params) == 1;
  EVP_PKEY_CTX_free(context);
  if (!ok) {
    EVP_PKEY_free(key);
    key = nullptr;
  }
  return key;
}

#endif

} // namespace

bool OpenSslCryptoBackend::randomBytes(size_t size, std::vector<uint8_t> &out) {
  out.assign(size, 0);
  return size <= (size_t)INT_MAX && RAND_bytes(out.data(), (int)size) == 1;
}

bool OpenSslCryptoBackend::sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &out) {
  out.assign(32, 0);
  unsigned int size = 0;
  return EVP_Digest(input.data(), input.size(), out.data(), &size, EVP_sha256(), nullptr) == 1 && size == out.size();
}

bool OpenSslCryptoBackend::hmacSha256(const std::vector<uint8_t> &key, const std::string &message,
                                      std::vector<uint8_t> &out) {
  out.assign(32, 0);
  unsigned int size = 0;
  return key.size() <= (size_t)INT_MAX &&
         HMAC(EVP_sha256(), key.data(), (int)key.size(),
              reinterpret_cast<const uint8_t *>(message.data()), message.size(), out.data(), &size) != nullptr &&
         size == out.size();
}

bool OpenSslCryptoBackend::generateP256KeyPair(std::vector<uint8_t> &privateKey,
                                               std::vector<uint8_t> &publicKey) {
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  OSSL_PARAM params[] = {
    OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                                     const_cast<char *>(kP256GroupName), 0),
    OSSL_PARAM_construct_end()
  };
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
  EVP_PKEY *key = nullptr;
  BIGNUM *privateValue = nullptr;
  privateKey.assign(32, 0);
  publicKey.assign(65, 0);
  size_t publicSize = 0;
  bool ok = context && EVP_PKEY_keygen_init(context) == 1 &&
            EVP_PKEY_CTX_set_params(context, params) == 1 &&
            EVP_PKEY_keygen(context, &key) == 1 &&
            EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &privateValue) == 1 &&
            BN_bn2binpad(privateValue, privateKey.data(), privateKey.size()) == (int)privateKey.size() &&
            EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY,
                                            publicKey.data(), publicKey.size(), &publicSize) == 1 &&
            publicSize == publicKey.size() && publicKey[0] == 4;
  BN_free(privateValue);
  EVP_PKEY_free(key);
  EVP_PKEY_CTX_free(context);
  return ok;
#else
  EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) return false;
  bool ok = EC_KEY_generate_key(key) == 1;
  const BIGNUM *privateValue = ok ? EC_KEY_get0_private_key(key) : nullptr;
  const EC_GROUP *group = ok ? EC_KEY_get0_group(key) : nullptr;
  const EC_POINT *publicPoint = ok ? EC_KEY_get0_public_key(key) : nullptr;
  privateKey.assign(32, 0);
  publicKey.assign(65, 0);
  if (ok) ok = privateValue && group && publicPoint &&
               BN_bn2binpad(privateValue, privateKey.data(), privateKey.size()) == (int)privateKey.size() &&
               EC_POINT_point2oct(group, publicPoint, POINT_CONVERSION_UNCOMPRESSED,
                                  publicKey.data(), publicKey.size(), nullptr) == publicKey.size();
  EC_KEY_free(key);
  return ok;
#endif
}

bool OpenSslCryptoBackend::p256SharedSecret(const std::vector<uint8_t> &privateKey,
                                            const std::vector<uint8_t> &peerPublicKey,
                                            std::vector<uint8_t> &sharedSecret) {
  if (privateKey.size() != 32 || peerPublicKey.size() != 65 || peerPublicKey[0] != 4) return false;
#if defined(OPENSSL_VERSION_MAJOR) && OPENSSL_VERSION_MAJOR >= 3
  EVP_PKEY *localKey = importP256PrivateKey(privateKey);
  EVP_PKEY *peerKey = importP256PublicKey(peerPublicKey);
  EVP_PKEY_CTX *checkContext = peerKey ? EVP_PKEY_CTX_new_from_pkey(nullptr, peerKey, nullptr) : nullptr;
  bool peerValid = checkContext && EVP_PKEY_public_check(checkContext) == 1;
  EVP_PKEY_CTX_free(checkContext);

  EVP_PKEY_CTX *deriveContext = localKey && peerValid
      ? EVP_PKEY_CTX_new_from_pkey(nullptr, localKey, nullptr)
      : nullptr;
  size_t sharedSize = 0;
  bool ok = deriveContext && EVP_PKEY_derive_init(deriveContext) == 1 &&
            EVP_PKEY_derive_set_peer(deriveContext, peerKey) == 1 &&
            EVP_PKEY_derive(deriveContext, nullptr, &sharedSize) == 1 && sharedSize == 32;
  sharedSecret.assign(32, 0);
  if (ok) {
    ok = EVP_PKEY_derive(deriveContext, sharedSecret.data(), &sharedSize) == 1 && sharedSize == 32;
  }

  EVP_PKEY_CTX_free(deriveContext);
  EVP_PKEY_free(peerKey);
  EVP_PKEY_free(localKey);
  return ok;
#else
  EC_KEY *key = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
  if (!key) return false;
  const EC_GROUP *group = EC_KEY_get0_group(key);
  BIGNUM *privateValue = BN_bin2bn(privateKey.data(), privateKey.size(), nullptr);
  EC_POINT *publicPoint = group ? EC_POINT_new(group) : nullptr;
  EC_POINT *peerPoint = group ? EC_POINT_new(group) : nullptr;
  bool ok = group && privateValue && publicPoint && peerPoint &&
            EC_POINT_mul(group, publicPoint, privateValue, nullptr, nullptr, nullptr) == 1 &&
            EC_KEY_set_private_key(key, privateValue) == 1 &&
            EC_KEY_set_public_key(key, publicPoint) == 1 &&
            EC_POINT_oct2point(group, peerPoint, peerPublicKey.data(), peerPublicKey.size(), nullptr) == 1 &&
            EC_POINT_is_on_curve(group, peerPoint, nullptr) == 1;
  sharedSecret.assign(32, 0);
  if (ok) ok = ECDH_compute_key(sharedSecret.data(), sharedSecret.size(), peerPoint, key, nullptr) ==
               (int)sharedSecret.size();
  EC_POINT_free(peerPoint);
  EC_POINT_free(publicPoint);
  BN_free(privateValue);
  EC_KEY_free(key);
  return ok;
#endif
}

bool OpenSslCryptoBackend::hkdfSha256(const std::vector<uint8_t> &inputKey,
                                      const std::vector<uint8_t> &salt,
                                      const std::string &info, size_t outputSize,
                                      std::vector<uint8_t> &out) {
  EVP_PKEY_CTX *context = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
  if (!context) return false;
  out.assign(outputSize, 0);
  size_t size = outputSize;
  bool ok = inputKey.size() <= (size_t)INT_MAX && salt.size() <= (size_t)INT_MAX && info.size() <= (size_t)INT_MAX &&
            EVP_PKEY_derive_init(context) == 1 &&
            EVP_PKEY_CTX_set_hkdf_md(context, EVP_sha256()) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_salt(context, salt.data(), (int)salt.size()) == 1 &&
            EVP_PKEY_CTX_set1_hkdf_key(context, inputKey.data(), (int)inputKey.size()) == 1 &&
            EVP_PKEY_CTX_add1_hkdf_info(context, reinterpret_cast<const uint8_t *>(info.data()),
                                        (int)info.size()) == 1 &&
            EVP_PKEY_derive(context, out.data(), &size) == 1 && size == outputSize;
  EVP_PKEY_CTX_free(context);
  return ok;
}

bool OpenSslCryptoBackend::aes256GcmEncrypt(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &iv,
                                            const std::string &aad,
                                            const std::vector<uint8_t> &plaintext,
                                            std::vector<uint8_t> &ciphertextAndTag) {
  if (key.size() != 32 || iv.size() != 12 || plaintext.size() > (size_t)INT_MAX || aad.size() > (size_t)INT_MAX) {
    return false;
  }
  ciphertextAndTag.assign(plaintext.size() + 16, 0);
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int written = 0;
  int total = 0;
  bool ok = context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) == 1 &&
            EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
            EVP_EncryptUpdate(context, nullptr, &written,
                              reinterpret_cast<const uint8_t *>(aad.data()), (int)aad.size()) == 1 &&
            EVP_EncryptUpdate(context, ciphertextAndTag.data(), &written,
                              plaintext.data(), (int)plaintext.size()) == 1;
  total = written;
  if (ok) ok = EVP_EncryptFinal_ex(context, ciphertextAndTag.data() + total, &written) == 1;
  if (ok) total += written;
  if (ok) ok = (size_t)total == plaintext.size() &&
               EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, 16,
                                   ciphertextAndTag.data() + plaintext.size()) == 1;
  EVP_CIPHER_CTX_free(context);
  return ok;
}

bool OpenSslCryptoBackend::aes256GcmDecrypt(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &iv,
                                            const std::string &aad,
                                            const std::vector<uint8_t> &ciphertextAndTag,
                                            std::vector<uint8_t> &plaintext) {
  if (key.size() != 32 || iv.size() != 12 || ciphertextAndTag.size() < 16 ||
      ciphertextAndTag.size() - 16 > (size_t)INT_MAX || aad.size() > (size_t)INT_MAX) {
    return false;
  }
  const size_t ciphertextSize = ciphertextAndTag.size() - 16;
  plaintext.assign(ciphertextSize, 0);
  EVP_CIPHER_CTX *context = EVP_CIPHER_CTX_new();
  int written = 0;
  int total = 0;
  bool ok = context && EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
            EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) == 1 &&
            EVP_DecryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) == 1 &&
            EVP_DecryptUpdate(context, nullptr, &written,
                              reinterpret_cast<const uint8_t *>(aad.data()), (int)aad.size()) == 1 &&
            EVP_DecryptUpdate(context, plaintext.data(), &written,
                              ciphertextAndTag.data(), (int)ciphertextSize) == 1;
  total = written;
  if (ok) ok = EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, 16,
                                   const_cast<uint8_t *>(ciphertextAndTag.data() + ciphertextSize)) == 1 &&
               EVP_DecryptFinal_ex(context, plaintext.data() + total, &written) == 1;
  if (ok) total += written;
  EVP_CIPHER_CTX_free(context);
  if (ok) plaintext.resize((size_t)total);
  return ok;
}
