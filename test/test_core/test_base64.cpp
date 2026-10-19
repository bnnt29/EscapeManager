#include <unity.h>
#include <cstring>
#include <string>
#include <vector>

#include "../../src/protocol/Base64Url.hpp"
#include "tests.hpp"
#include "vectors.hpp"

namespace {

void test_vectors() {
  for (size_t i = 0; i < sizeof(Vectors::kB64) / sizeof(Vectors::kB64[0]); i++) {
    std::vector<uint8_t> raw;
    TEST_ASSERT_TRUE(Escape::hexDecode(Vectors::kB64[i].hex, strlen(Vectors::kB64[i].hex), raw));
    std::string text = Escape::base64UrlEncode(raw.data(), raw.size());
    TEST_ASSERT_EQUAL_STRING(Vectors::kB64[i].text, text.c_str());
    std::vector<uint8_t> back;
    TEST_ASSERT_TRUE(Escape::base64UrlDecode(text, back));
    TEST_ASSERT_TRUE(back == raw);
  }
}

void test_invalid_inputs() {
  for (size_t i = 0; i < sizeof(Vectors::kB64Invalid) / sizeof(Vectors::kB64Invalid[0]); i++) {
    std::vector<uint8_t> out;
    TEST_ASSERT_FALSE_MESSAGE(Escape::base64UrlDecode(std::string(Vectors::kB64Invalid[i]), out), Vectors::kB64Invalid[i]);
    TEST_ASSERT_TRUE(out.empty());
  }
}

void test_all_lengths_roundtrip() {
  for (size_t len = 0; len < 70; len++) {
    std::vector<uint8_t> raw(len);
    for (size_t i = 0; i < len; i++) raw[i] = (uint8_t)(i * 37 + len);
    std::string text = Escape::base64UrlEncode(raw.data(), raw.size());
    TEST_ASSERT_EQUAL_UINT(Escape::base64UrlDecodedLength(text.size()), len);
    std::vector<uint8_t> back;
    TEST_ASSERT_TRUE(Escape::base64UrlDecode(text, back));
    TEST_ASSERT_TRUE(back == raw);
  }
}

void test_hex() {
  std::vector<uint8_t> v;
  TEST_ASSERT_TRUE(Escape::hexDecode("00ff10", 6, v));
  TEST_ASSERT_EQUAL_UINT(3, v.size());
  std::string s;
  Escape::hexEncode(v.data(), v.size(), s);
  TEST_ASSERT_EQUAL_STRING("00ff10", s.c_str());
  TEST_ASSERT_FALSE(Escape::hexDecode("0g", 2, v));
  TEST_ASSERT_FALSE(Escape::hexDecode("abc", 3, v));
}

} // namespace

void runBase64Tests() {
  RUN_TEST(test_vectors);
  RUN_TEST(test_invalid_inputs);
  RUN_TEST(test_all_lengths_roundtrip);
  RUN_TEST(test_hex);
}
