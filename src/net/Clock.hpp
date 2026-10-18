#pragma once

// Millisecond/microsecond clock of the platform: Arduino millis()/micros() on the
// ESP32, a steady clock on the PC. Wraps like millis() on the device (uint32).

#include <cstdint>

// Test hook: -DESCAPE_CLOCK_OFFSET_MS=0xFFFF0000UL starts the library's clock 65 s before the 49.7-day
// wrap of the 32-bit millisecond counter, so the wrap can be exercised on real hardware within a minute.
#ifndef ESCAPE_CLOCK_OFFSET_MS
#define ESCAPE_CLOCK_OFFSET_MS 0
#endif

#if defined(ARDUINO)
#include <Arduino.h>
namespace Escape {
inline uint32_t nowMillis() { return (uint32_t)millis() + (uint32_t)(ESCAPE_CLOCK_OFFSET_MS); }
inline uint32_t nowMicros() { return (uint32_t)micros(); }
} // namespace Escape
#else
#include <chrono>
namespace Escape {
inline uint32_t nowMillis() {
  return (uint32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
inline uint32_t nowMicros() {
  return (uint32_t)std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::steady_clock::now().time_since_epoch()).count();
}
} // namespace Escape
#endif
