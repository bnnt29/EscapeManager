#pragma once

// Configuration constants of the EscapeManager library. Purely declarative (no
// logic, no hardware dependency) so the ESP32 firmware, the C++ simulator and the
// native tests all share one source of truth. Most values can be overridden with
// -DESCAPE_<NAME>=<value> build flags (see the macros below) so a host program with
// tight resources can shrink the library without editing it.

#include <cstddef>
#include <cstdint>

#ifndef ESCAPE_MAX_PEER_ADDRESSES
#define ESCAPE_MAX_PEER_ADDRESSES 64
#endif
#ifndef ESCAPE_MAX_LOCAL_COMPONENTS
#define ESCAPE_MAX_LOCAL_COMPONENTS 4
#endif
#ifndef ESCAPE_STRICT_GET
#define ESCAPE_STRICT_GET 0
#endif
#ifndef ESCAPE_WIFI_SSID
#define ESCAPE_WIFI_SSID ""
#endif
#ifndef ESCAPE_WIFI_PASSWORD
#define ESCAPE_WIFI_PASSWORD ""
#endif

namespace EscapeConfig {

  // ---- Wi-Fi ----------------------------------------------------------------
  // Credentials never belong into the repository. Sources, in order:
  //   1. The host program already connected Wi-Fi -> used unchanged.
  //   2. Credentials stored in NVS (serial command "WIFI", see README).
  //   3. Build flags -DESCAPE_WIFI_SSID=\"..\" -DESCAPE_WIFI_PASSWORD=\"..\"
  //      (e.g. from the untracked secrets.ini).
  // Empty means "no build-time credentials".
  constexpr const char *WIFI_SSID = ESCAPE_WIFI_SSID;
  constexpr const char *WIFI_PASSWORD = ESCAPE_WIFI_PASSWORD;

  // ---- Security ---------------------------------------------------------------
  // Shared secret of the installation, see PROTOCOL.md section 3. The repository
  // default is public on purpose: it lets ESP, simulator and manager work in a
  // closed escape-room network without provisioning ("Standard" level). Set an
  // own token (serial command or `pio run -e update-auth-token`) for shared or
  // less trusted networks.
  constexpr const char *AUTH_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
  constexpr size_t MIN_AUTH_TOKEN_LEN = 8;
  constexpr size_t MAX_AUTH_TOKEN_LEN = 128;
  // Managers and tools warn below this length (the token still works).
  constexpr size_t RECOMMENDED_AUTH_TOKEN_LEN = 20;
  constexpr bool ALLOW_AUTH_TOKEN_IN_URL = true;
  // true: GET requests without a nonce are refused (no unauthenticated viewers).
  constexpr bool STRICT_GET = ESCAPE_STRICT_GET != 0;
  constexpr uint32_t KDF_ITERATIONS = 2048;      // PBKDF2-HMAC-SHA256, once per boot
  constexpr uint32_t MAX_KDF_ITERATIONS = 100000; // upper bound a manager accepts
  // Request freshness: |t - device clock| must not exceed this.
  constexpr uint32_t TIME_WINDOW_MS = 15000;
  // IVs of accepted requests kept for the time window (12 B each). Full = fail closed.
  constexpr size_t REPLAY_CACHE_SIZE = 64;

  // ---- Network ------------------------------------------------------------------
  constexpr uint16_t UDP_PORT = 4210;
  constexpr uint16_t HTTP_PORT = 80;
  // Every device answers for this name (shared mDNS record, see PROTOCOL.md 7).
  constexpr const char *MDNS_HOSTNAME = "escapemanager";
  constexpr uint32_t MDNS_TTL_S = 15;
  constexpr size_t MAX_HTTP_CONNECTIONS = 2;
  constexpr uint32_t HTTP_IDLE_TIMEOUT_MS = 5000;   // no bytes received
  constexpr uint32_t HTTP_REQUEST_TIMEOUT_MS = 10000; // whole request incl. response
  constexpr size_t MAX_HEADER_BYTES = 1024;

  // ---- Broadcast timing ------------------------------------------------------------
  constexpr uint32_t HEARTBEAT_INTERVAL_MS = 4000;
  constexpr uint32_t HEARTBEAT_JITTER_MS = 750;
  constexpr uint32_t CHANGE_MIN_GAP_MS = 300;
  // A peer without announcements for this long is dropped (and from /peers.json).
  constexpr uint32_t PEER_TIMEOUT_MS = 20000;
  constexpr size_t MAX_ANNOUNCEMENT_BYTES = 600;

  // ---- Capacities ------------------------------------------------------------------
  // Peer table entries are small (address, counters, skeleton summary), so the
  // default is modest; raise ESCAPE_MAX_PEER_ADDRESSES for very large installations.
  constexpr size_t MAX_PEER_ADDRESSES = ESCAPE_MAX_PEER_ADDRESSES;
  constexpr size_t MAX_LOCAL_COMPONENTS = ESCAPE_MAX_LOCAL_COMPONENTS;
  constexpr size_t MAX_NAME_LEN = 32;
  constexpr size_t MAX_ROOM_LEN = 32;
  constexpr size_t MAX_ERRORS = 4;
  constexpr size_t MAX_ERROR_LEN = 32;
  constexpr size_t MAX_ACTIONS = 8;
  constexpr size_t MAX_ACTION_LEN = 24;
  constexpr size_t MAX_FEED_LEN = 96;
  constexpr size_t MAX_TIP_LEN = 512;
  constexpr size_t MAX_STATE_LEN = 1664;
  constexpr size_t MAX_IP_LEN = 15;
  constexpr size_t MAX_UUID_LEN = 20;
  constexpr size_t MAX_RIDDLE_ID_LEN = 32;
  constexpr size_t MAX_EVENT_MSG_LEN = 64;
  constexpr size_t MAX_CUSTOM_CONFIGS = 4;
  constexpr size_t MAX_CONFIG_KEY_LEN = 20;
  constexpr size_t MAX_CONFIG_VALUE_LEN = 48;
  constexpr size_t MAX_CONFIG_OPTIONS = 6;
  constexpr size_t MAX_CONFIG_OPTION_LEN = 16;

  // ---- Plan data ----------------------------------------------------------------------
  // The graph logic lives in the manager only; devices store opaque JSON blocks:
  //  - one small slice per component (its lane/connections), at most MAX_PLAN_LEN,
  //  - one skeleton per room that has a local component, at most MAX_PLAN_SKELETON_LEN.
  constexpr size_t MAX_PLAN_LEN = 512;
  constexpr size_t MAX_PLAN_SKELETON_LEN = 6144;
  constexpr size_t MAX_SKELETON_ROOMS = MAX_LOCAL_COMPONENTS;
  constexpr uint32_t SKELETON_SYNC_BACKOFF_MS = 10000;

  // ---- Requests -------------------------------------------------------------------------
  constexpr size_t MAX_BODY_BYTES = 12 * 1024;       // envelope (any POST)
  constexpr size_t MAX_ENVELOPE_FIELD_BYTES = 12 * 1024;
  // Number of JSON DOM nodes / depth allowed for small request bodies. Skeleton, plan
  // slices and envelopes are scanned without building a tree.
  constexpr size_t MAX_JSON_NODES = 160;
  constexpr size_t MAX_JSON_DEPTH = 16;

  // Failed-request budget per source address (token bucket) and global POST budget.
  constexpr uint8_t RATE_SOURCES = 8;
  constexpr uint8_t RATE_BURST = 12;
  constexpr uint32_t RATE_REFILL_MS = 250;   // one token per interval
  constexpr uint8_t GLOBAL_POSTS_PER_SECOND = 30;

  // ---- Default identity ---------------------------------------------------------------------
  constexpr const char *DEFAULT_NAME = "Komponente";
  constexpr const char *DEFAULT_ROOM = "unzugeordnet";

  static_assert(MAX_LOCAL_COMPONENTS >= 1 && MAX_LOCAL_COMPONENTS <= 8, "1..8 local components supported");
  static_assert(MAX_UUID_LEN >= 14, "uuid is <did>-<index>");

} // namespace EscapeConfig
