#include "MbedTlsCryptoBackend.hpp"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>

struct MbedTlsCryptoBackend::Impl {
  Impl() : seeded(false) {
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&drbg);
    static const char personalization[] = "EscapeManager-P256";
    seeded = mbedtls_ctr_drbg_seed(
      &drbg, mbedtls_entropy_func, &entropy,
      reinterpret_cast<const uint8_t *>(personalization), sizeof(personalization) - 1) == 0;
  }

  ~Impl() {
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
  }

  mbedtls_entropy_context entropy;
  mbedtls_ctr_drbg_context drbg;
  bool seeded;
};

MbedTlsCryptoBackend::MbedTlsCryptoBackend() : impl_(new Impl()) {}
MbedTlsCryptoBackend::~MbedTlsCryptoBackend() { delete impl_; }
bool MbedTlsCryptoBackend::ready() const { return impl_->seeded; }

bool MbedTlsCryptoBackend::randomBytes(size_t size, std::vector<uint8_t> &out) {
  out.assign(size, 0);
  return impl_->seeded && mbedtls_ctr_drbg_random(&impl_->drbg, out.data(), out.size()) == 0;
}

bool MbedTlsCryptoBackend::sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &out) {
  out.assign(32, 0);
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return md && mbedtls_md(md, input.data(), input.size(), out.data()) == 0;
}

bool MbedTlsCryptoBackend::hmacSha256(const std::vector<uint8_t> &key, const std::string &message,
                                      std::vector<uint8_t> &out) {
  out.assign(32, 0);
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return md && mbedtls_md_hmac(md, key.data(), key.size(),
                               reinterpret_cast<const uint8_t *>(message.data()), message.size(), out.data()) == 0;
}

bool MbedTlsCryptoBackend::generateP256KeyPair(std::vector<uint8_t> &privateKey,
                                               std::vector<uint8_t> &publicKey) {
  if (!impl_->seeded) return false;
  mbedtls_ecp_group group;
  mbedtls_mpi privateValue;
  mbedtls_ecp_point publicPoint;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&privateValue);
  mbedtls_ecp_point_init(&publicPoint);

  bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_ecdh_gen_public(&group, &privateValue, &publicPoint,
                                    mbedtls_ctr_drbg_random, &impl_->drbg) == 0;
  privateKey.assign(32, 0);
  publicKey.assign(65, 0);
  size_t written = 0;
  if (ok) ok = mbedtls_mpi_write_binary(&privateValue, privateKey.data(), privateKey.size()) == 0 &&
               mbedtls_ecp_point_write_binary(&group, &publicPoint, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                              &written, publicKey.data(), publicKey.size()) == 0 &&
               written == publicKey.size();

  mbedtls_ecp_point_free(&publicPoint);
  mbedtls_mpi_free(&privateValue);
  mbedtls_ecp_group_free(&group);
  return ok;
}

bool MbedTlsCryptoBackend::p256SharedSecret(const std::vector<uint8_t> &privateKey,
                                            const std::vector<uint8_t> &peerPublicKey,
                                            std::vector<uint8_t> &sharedSecret) {
  if (!impl_->seeded || privateKey.size() != 32 || peerPublicKey.size() != 65 || peerPublicKey[0] != 4) return false;
  mbedtls_ecp_group group;
  mbedtls_mpi privateValue;
  mbedtls_mpi secret;
  mbedtls_ecp_point peer;
  mbedtls_ecp_group_init(&group);
  mbedtls_mpi_init(&privateValue);
  mbedtls_mpi_init(&secret);
  mbedtls_ecp_point_init(&peer);

  bool ok = mbedtls_ecp_group_load(&group, MBEDTLS_ECP_DP_SECP256R1) == 0 &&
            mbedtls_mpi_read_binary(&privateValue, privateKey.data(), privateKey.size()) == 0 &&
            mbedtls_ecp_point_read_binary(&group, &peer, peerPublicKey.data(), peerPublicKey.size()) == 0 &&
            mbedtls_ecp_check_pubkey(&group, &peer) == 0 &&
            mbedtls_ecdh_compute_shared(&group, &secret, &peer, &privateValue,
                                        mbedtls_ctr_drbg_random, &impl_->drbg) == 0;
  sharedSecret.assign(32, 0);
  if (ok) ok = mbedtls_mpi_write_binary(&secret, sharedSecret.data(), sharedSecret.size()) == 0;

  mbedtls_ecp_point_free(&peer);
  mbedtls_mpi_free(&secret);
  mbedtls_mpi_free(&privateValue);
  mbedtls_ecp_group_free(&group);
  return ok;
}

bool MbedTlsCryptoBackend::hkdfSha256(const std::vector<uint8_t> &inputKey,
                                      const std::vector<uint8_t> &salt,
                                      const std::string &info, size_t outputSize,
                                      std::vector<uint8_t> &out) {
  out.assign(outputSize, 0);
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  return md && mbedtls_hkdf(md, salt.data(), salt.size(), inputKey.data(), inputKey.size(),
                            reinterpret_cast<const uint8_t *>(info.data()), info.size(),
                            out.data(), out.size()) == 0;
}

bool MbedTlsCryptoBackend::aes256GcmEncrypt(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &iv,
                                            const std::string &aad,
                                            const std::vector<uint8_t> &plaintext,
                                            std::vector<uint8_t> &ciphertextAndTag) {
  if (key.size() != 32 || iv.size() != 12) return false;
  ciphertextAndTag.assign(plaintext.size() + 16, 0);
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  bool ok = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), 256) == 0 &&
            mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, plaintext.size(),
                                      iv.data(), iv.size(),
                                      reinterpret_cast<const uint8_t *>(aad.data()), aad.size(),
                                      plaintext.data(), ciphertextAndTag.data(), 16,
                                      ciphertextAndTag.data() + plaintext.size()) == 0;
  mbedtls_gcm_free(&context);
  return ok;
}

bool MbedTlsCryptoBackend::aes256GcmDecrypt(const std::vector<uint8_t> &key,
                                            const std::vector<uint8_t> &iv,
                                            const std::string &aad,
                                            const std::vector<uint8_t> &ciphertextAndTag,
                                            std::vector<uint8_t> &plaintext) {
  if (key.size() != 32 || iv.size() != 12 || ciphertextAndTag.size() < 16) return false;
  const size_t ciphertextSize = ciphertextAndTag.size() - 16;
  plaintext.assign(ciphertextSize, 0);
  mbedtls_gcm_context context;
  mbedtls_gcm_init(&context);
  bool ok = mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key.data(), 256) == 0 &&
            mbedtls_gcm_auth_decrypt(&context, ciphertextSize, iv.data(), iv.size(),
                                     reinterpret_cast<const uint8_t *>(aad.data()), aad.size(),
                                     ciphertextAndTag.data() + ciphertextSize, 16,
                                     ciphertextAndTag.data(), plaintext.data()) == 0;
  mbedtls_gcm_free(&context);
  return ok;
}
