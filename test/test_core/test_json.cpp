#include <unity.h>
#include <cmath>
#include <cstring>
#include <string>

#include "../../src/protocol/Json.hpp"
#include "tests.hpp"

using namespace EscapeJson;

namespace {

bool ok(const char *text) {
  Value v;
  return parse(std::string(text), v);
}

void test_parse_basic() {
  Value v;
  TEST_ASSERT_TRUE(parse(std::string("{\"name\":\"Laser-1\",\"n\":87,\"b\":true,\"a\":[1,2,\"x\"],\"z\":null}"), v));
  TEST_ASSERT_EQUAL_STRING("Laser-1", v.find("name")->asString().c_str());
  TEST_ASSERT_EQUAL_INT(87, (int)v.find("n")->asNumber());
  TEST_ASSERT_TRUE(v.find("b")->asBool());
  TEST_ASSERT_EQUAL_UINT(3, v.find("a")->arrayValue.size());
  TEST_ASSERT_TRUE(v.find("z")->type == Type::Null);
  TEST_ASSERT_NULL(v.find("missing"));
}

void test_parse_rejects_malformed() {
  const char *bad[] = {"", " ", "{", "}", "{\"a\"}", "{\"a\":}", "{\"a\":1,}", "[1,]", "[1 2]", "{\"a\":1}x", "{a:1}",
                       "tru", "nul", "\"abc", "\"\\x\"", "{\"a\":1 \"b\":2}", "[", "{\"a\":[}"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(ok(bad[i]), bad[i]);
}

void test_numbers_strict() {
  const char *good[] = {"0", "-0", "1", "-12", "1.5", "0.25", "1e3", "1E+3", "1e-3", "-1.5e10", "123456789012"};
  for (size_t i = 0; i < sizeof(good) / sizeof(good[0]); i++) TEST_ASSERT_TRUE_MESSAGE(ok(good[i]), good[i]);
  const char *bad[] = {"01", "+1", "1.", ".5", "1e", "1e+", "-", "--1", "0x10", "1.2.3", "1-2", "NaN", "Infinity", "1e999", "-1e999"};
  for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) TEST_ASSERT_FALSE_MESSAGE(ok(bad[i]), bad[i]);
  Value v;
  TEST_ASSERT_TRUE(parse(std::string("1e-400"), v)); // underflow to 0 is valid JSON
  TEST_ASSERT_TRUE(v.numberValue == 0.0);
}

void test_strings_and_unicode() {
  Value v;
  TEST_ASSERT_TRUE(parse(std::string("\"a\\n\\t\\\"\\\\\\/b\""), v));
  TEST_ASSERT_EQUAL_STRING("a\n\t\"\\/b", v.stringValue.c_str());
  TEST_ASSERT_TRUE(parse(std::string("\"\\u00e9\\u20ac\""), v));
  TEST_ASSERT_EQUAL_STRING("\xc3\xa9\xe2\x82\xac", v.stringValue.c_str());
  TEST_ASSERT_TRUE(parse(std::string("\"\\ud83d\\ude00\""), v)); // surrogate pair -> U+1F600
  TEST_ASSERT_EQUAL_STRING("\xf0\x9f\x98\x80", v.stringValue.c_str());
  TEST_ASSERT_FALSE(ok("\"\\ud83d\""));        // lone high surrogate
  TEST_ASSERT_FALSE(ok("\"\\ude00\""));        // lone low surrogate
  TEST_ASSERT_FALSE(ok("\"\\ud83d\\u0041\"")); // high surrogate + non-low
  TEST_ASSERT_FALSE(ok("\"\\u0000\""));        // embedded NUL
  TEST_ASSERT_FALSE(ok("\"\\u12\""));
  TEST_ASSERT_FALSE(ok("\"a\x01z\""));         // raw control character
  TEST_ASSERT_FALSE(ok("\"\xc3\""));           // truncated UTF-8
  TEST_ASSERT_FALSE(ok("\"\xc0\x80\""));       // overlong
  TEST_ASSERT_FALSE(ok("\"\xed\xa0\x80\""));   // UTF-8 encoded surrogate
  TEST_ASSERT_TRUE(ok("\"\xc3\xa4\""));
}

void test_whitespace() {
  TEST_ASSERT_TRUE(ok(" \t\r\n{ \"a\" :\n1 } \n"));
  TEST_ASSERT_FALSE(ok("\v{}"));
  TEST_ASSERT_FALSE(ok("\f[]"));
}

void test_limits() {
  std::string deep;
  for (int i = 0; i < 9; i++) deep += "[";
  for (int i = 0; i < 9; i++) deep += "]";
  Value v;
  TEST_ASSERT_FALSE(parse(deep, v));                      // default DOM depth is 8
  TEST_ASSERT_TRUE(parse(deep, v, ParseLimits(9, 160)));
  std::string flat = "[";
  for (int i = 0; i < 200; i++) flat += i ? ",0" : "0";
  flat += "]";
  TEST_ASSERT_FALSE(parse(flat, v));                      // 201 nodes > 160
  TEST_ASSERT_TRUE(parse(flat, v, ParseLimits(8, 300)));
  // A hostile body costs bounded memory: parsing stops at the node limit.
  std::string hostile = "[";
  for (int i = 0; i < 6000; i++) hostile += "0,";
  hostile += "0]";
  TEST_ASSERT_FALSE(parse(hostile, v));
  TEST_ASSERT_TRUE(v.arrayValue.empty());
}

void test_duplicate_keys_first_wins() {
  Value v;
  TEST_ASSERT_TRUE(parse(std::string("{\"a\":1,\"a\":2}"), v));
  TEST_ASSERT_EQUAL_INT(1, (int)v.find("a")->asNumber());
  Slice s;
  const char *doc = "{\"a\":1,\"a\":2}";
  TEST_ASSERT_TRUE(findField(doc, strlen(doc), "a", s) == Scan::Found);
  TEST_ASSERT_EQUAL_STRING("1", s.str().c_str());
}

void test_as_int() {
  Value v;
  long long out = 0;
  TEST_ASSERT_TRUE(parse(std::string("{\"id\":3,\"f\":1.5,\"big\":1e12,\"s\":\"3\"}"), v));
  TEST_ASSERT_TRUE(v.find("id")->asInt(0, 255, out));
  TEST_ASSERT_EQUAL_INT(3, (int)out);
  TEST_ASSERT_FALSE(v.find("f")->asInt(0, 255, out));
  TEST_ASSERT_FALSE(v.find("big")->asInt(0, 255, out));
  TEST_ASSERT_FALSE(v.find("s")->asInt(0, 255, out)); // strings are not numbers
}

void test_scanner() {
  const char *doc = "{\"id\":2, \"plan\": {\"a\":[1,{\"b\":\"}\"}]}, \"na\\u006de\":\"x\\ny\", \"n\":null, \"t\":true,\"q\":4294967295}";
  const size_t n = strlen(doc);
  Slice s;
  TEST_ASSERT_TRUE(findField(doc, n, "plan", s) == Scan::Found);
  TEST_ASSERT_EQUAL_STRING("{\"a\":[1,{\"b\":\"}\"}]}", s.str().c_str());
  TEST_ASSERT_EQUAL_INT('o', sliceKind(s));
  TEST_ASSERT_TRUE(validate(s.p, s.n));
  TEST_ASSERT_TRUE(findField(doc, n, "name", s) == Scan::Found); // escaped key
  std::string str;
  TEST_ASSERT_TRUE(sliceToString(s, str));
  TEST_ASSERT_EQUAL_STRING("x\ny", str.c_str());
  uint32_t u = 0;
  TEST_ASSERT_TRUE(findField(doc, n, "id", s) == Scan::Found);
  TEST_ASSERT_TRUE(sliceToUInt(s, 255, u));
  TEST_ASSERT_EQUAL_UINT(2, u);
  TEST_ASSERT_TRUE(findField(doc, n, "q", s) == Scan::Found);
  TEST_ASSERT_TRUE(sliceToUInt(s, 0xFFFFFFFFu, u));
  TEST_ASSERT_EQUAL_UINT32(4294967295u, u);
  TEST_ASSERT_FALSE(sliceToUInt(s, 1000, u));
  TEST_ASSERT_TRUE(findField(doc, n, "n", s) == Scan::Found);
  TEST_ASSERT_TRUE(sliceIsNull(s));
  TEST_ASSERT_EQUAL_INT('z', sliceKind(s));
  bool b = false;
  TEST_ASSERT_TRUE(findField(doc, n, "t", s) == Scan::Found);
  TEST_ASSERT_TRUE(sliceToBool(s, b) && b);
  TEST_ASSERT_TRUE(findField(doc, n, "nope", s) == Scan::Missing);
  TEST_ASSERT_TRUE(findField("[1]", 3, "a", s) == Scan::Invalid);          // not an object
  TEST_ASSERT_TRUE(findField("{\"a\":1", 6, "a", s) == Scan::Invalid);     // truncated
  TEST_ASSERT_TRUE(findField("{\"a\":01}", 8, "a", s) == Scan::Invalid);   // bad number
  TEST_ASSERT_TRUE(findField("{\"a\":1} x", 9, "a", s) == Scan::Invalid);  // trailing
  TEST_ASSERT_TRUE(findField("{}", 2, "a", s) == Scan::Missing);
  // nested key must not be found at top level
  TEST_ASSERT_TRUE(findField("{\"o\":{\"a\":1}}", 13, "a", s) == Scan::Missing);
}

void test_scanner_depth_and_hostile() {
  std::string deep = "{\"a\":";
  for (int i = 0; i < 40; i++) deep += "[";
  for (int i = 0; i < 40; i++) deep += "]";
  deep += "}";
  Slice s;
  TEST_ASSERT_TRUE(findField(deep.data(), deep.size(), "a", s) == Scan::Invalid); // > 16 levels
  TEST_ASSERT_FALSE(validate(deep.data(), deep.size(), 16));
  TEST_ASSERT_TRUE(validate(deep.data(), deep.size(), 64));
  // 12 KB of array elements: no allocation, no tree, still validated.
  std::string big = "{\"a\":[";
  for (int i = 0; i < 6000; i++) big += "0,";
  big += "0]}";
  TEST_ASSERT_TRUE(findField(big.data(), big.size(), "a", s) == Scan::Found);
  TEST_ASSERT_EQUAL_UINT(big.size() - 6, s.n);
}

void test_escape_output() {
  std::string out;
  appendEscaped(out, std::string("a\"b\\c\n\r\t\b\f\x01\x1f"));
  TEST_ASSERT_EQUAL_STRING("a\\\"b\\\\c\\n\\r\\t\\b\\f\\u0001\\u001f", out.c_str());
  out.clear();
  appendEscaped(out, "\xc3\xa4\xe2\x82\xac"); // valid UTF-8 passes through
  TEST_ASSERT_EQUAL_STRING("\xc3\xa4\xe2\x82\xac", out.c_str());
  out.clear();
  appendEscaped(out, "ab\xc3"); // a multi-byte character cut by a size limit
  TEST_ASSERT_EQUAL_STRING("ab\\ufffd", out.c_str());
  // Everything we write parses back.
  std::string text = "\"";
  std::string raw;
  for (int c = 1; c < 128; c++) raw.push_back((char)c);
  appendEscaped(text, raw);
  text += "\"";
  Value v;
  TEST_ASSERT_TRUE(parse(text, v));
  TEST_ASSERT_TRUE(v.stringValue == raw);
}

void test_number_output() {
  std::string o;
  appendNumber(o, 87);        TEST_ASSERT_EQUAL_STRING("87", o.c_str());
  o.clear(); appendNumber(o, -3);       TEST_ASSERT_EQUAL_STRING("-3", o.c_str());
  o.clear(); appendNumber(o, 0.5);      TEST_ASSERT_EQUAL_STRING("0.5", o.c_str());
  o.clear(); appendNumber(o, 0.1);      TEST_ASSERT_EQUAL_STRING("0.1", o.c_str());
  o.clear(); appendNumber(o, NAN);      TEST_ASSERT_EQUAL_STRING("null", o.c_str());
  o.clear(); appendNumber(o, INFINITY); TEST_ASSERT_EQUAL_STRING("null", o.c_str());
  const double samples[] = {1e-7, 1.0 / 3.0, 123456.789, 1e22, 1e308, -2.5e-300, 4294967295.0};
  for (size_t i = 0; i < sizeof(samples) / sizeof(samples[0]); i++) {
    o.clear();
    appendNumber(o, samples[i]);
    Value v;
    TEST_ASSERT_TRUE_MESSAGE(parse(o, v), o.c_str());
    TEST_ASSERT_TRUE_MESSAGE(samples[i] == v.numberValue, o.c_str());
  }
  o.clear(); appendUInt(o, 4294967295u); TEST_ASSERT_EQUAL_STRING("4294967295", o.c_str());
  o.clear(); appendInt(o, -2147483647 - 1); TEST_ASSERT_EQUAL_STRING("-2147483648", o.c_str());
}

void test_stringify_roundtrip_and_cap() {
  Value v;
  TEST_ASSERT_TRUE(parse(std::string("{\"b\":[1,2,{\"c\":\"\\u00e9\"}],\"a\":true,\"s\":\"x\\ny\"}"), v));
  std::string out;
  TEST_ASSERT_TRUE(stringify(v, out));
  Value again;
  TEST_ASSERT_TRUE(parse(out, again));
  std::string out2;
  TEST_ASSERT_TRUE(stringify(again, out2));
  TEST_ASSERT_EQUAL_STRING(out.c_str(), out2.c_str());
  std::string capped;
  TEST_ASSERT_FALSE(stringify(v, capped, 8));
}

} // namespace

void runJsonTests() {
  RUN_TEST(test_parse_basic);
  RUN_TEST(test_parse_rejects_malformed);
  RUN_TEST(test_numbers_strict);
  RUN_TEST(test_strings_and_unicode);
  RUN_TEST(test_whitespace);
  RUN_TEST(test_limits);
  RUN_TEST(test_duplicate_keys_first_wins);
  RUN_TEST(test_as_int);
  RUN_TEST(test_scanner);
  RUN_TEST(test_scanner_depth_and_hostile);
  RUN_TEST(test_escape_output);
  RUN_TEST(test_number_output);
  RUN_TEST(test_stringify_roundtrip_and_cap);
}
