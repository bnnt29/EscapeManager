// Portable core tests: the same suites run on the PC (pio test -e native, with
// address/undefined-behaviour sanitizers) and on the ESP32 (pio test -e esp32-test,
// mbedTLS backend, real stack and heap). Keep everything here C++11 and free of
// host-only APIs (no files, no threads).
#include <unity.h>

#include "tests.hpp"

#ifdef ARDUINO
#include <Arduino.h>
#endif

void setUp() {}
void tearDown() {}

static void runAll() {
  UNITY_BEGIN();
  runJsonTests();
  runBase64Tests();
  runCryptoTests();
  runStoreTests();
  runPeerTests();
  runHttpTests();
  runProtocolTests();
  runFuzzTests();
  UNITY_END();
}

#ifdef ARDUINO
void setup() {
  delay(2000);
  runAll();
}
void loop() {}
#else
int main(int, char **) {
  runAll();
  return 0;
}
#endif
