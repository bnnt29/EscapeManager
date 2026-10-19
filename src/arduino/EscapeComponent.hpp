#pragma once

// Arduino-ESP32 entry point of the library: EscapeComponent (src/esp/client.hpp) on top of
// the portable device core (src/net) and the proto-2 protocol (src/protocol, PROTOCOL.md).
// Crypto is mbedTLS (AES-256-GCM, HMAC-SHA-256, PBKDF2), provided by the Arduino core.

#include "../esp/client.hpp"
