#pragma once

// Version identity of this build, published in /security.json and /status.json
// (see PROTOCOL.md section 1). Bump FW_VERSION for every release; PROTO changes
// only when the wire format gains a new level.

#include <cstdint>

namespace EscapeVersion {

  constexpr uint8_t PROTO = 2;        // highest wire level spoken
  constexpr uint8_t PROTO_MIN = 2;    // lowest wire level still accepted
  constexpr const char *FW = "2.1.1";
  constexpr const char *UI = "2.1.1";  // version of the embedded manager.html

  // Hash of the embedded manager.html (first 8 hex chars of SHA-256 over the
  // UNCOMPRESSED file). Provided by the generated src/manager/ui_data.cpp for the
  // firmware; hosts without an embedded UI (tests, simulators) pass their own.
  extern const char *const UI_HASH;

} // namespace EscapeVersion
