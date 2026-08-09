#pragma once

#include "../protocol/SecureTransport.hpp"

class OpenSslCryptoBackend : public EscapeSecurity::CryptoBackend {
public:
  bool randomBytes(size_t size, std::vector<uint8_t> &out) override;
  bool sha256(const std::vector<uint8_t> &input, std::vector<uint8_t> &out) override;
  bool hmacSha256(const std::vector<uint8_t> &key, const std::string &message,
                  std::vector<uint8_t> &out) override;
  bool generateP256KeyPair(std::vector<uint8_t> &privateKey,
                           std::vector<uint8_t> &publicKey) override;
  bool p256SharedSecret(const std::vector<uint8_t> &privateKey,
                        const std::vector<uint8_t> &peerPublicKey,
                        std::vector<uint8_t> &sharedSecret) override;
  bool hkdfSha256(const std::vector<uint8_t> &inputKey,
                  const std::vector<uint8_t> &salt,
                  const std::string &info, size_t outputSize,
                  std::vector<uint8_t> &out) override;
  bool aes256GcmEncrypt(const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &iv,
                        const std::string &aad,
                        const std::vector<uint8_t> &plaintext,
                        std::vector<uint8_t> &ciphertextAndTag) override;
  bool aes256GcmDecrypt(const std::vector<uint8_t> &key,
                        const std::vector<uint8_t> &iv,
                        const std::string &aad,
                        const std::vector<uint8_t> &ciphertextAndTag,
                        std::vector<uint8_t> &plaintext) override;
};
