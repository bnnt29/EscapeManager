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
// Tokens from the build (e.g. the untracked secrets.ini). Empty = not set at build time.
#ifndef ESCAPE_AUTH_TOKEN
#define ESCAPE_AUTH_TOKEN ""
#endif
#ifndef ESCAPE_EDIT_TOKEN
#define ESCAPE_EDIT_TOKEN ""
#endif
// Wi-Fi setup network (ESP32): empty = open network, otherwise WPA2 with this password (8..63).
#ifndef ESCAPE_SETUP_AP_PASSWORD
#define ESCAPE_SETUP_AP_PASSWORD ""
#endif
// How long the station may fail to connect before the setup network starts.
#ifndef ESCAPE_SETUP_AP_AFTER_MS
#define ESCAPE_SETUP_AP_AFTER_MS 30000
#endif
// 1: a host program owns Wi-Fi and the library never touches the radio (no setup network either).
#ifndef ESCAPE_HOST_MANAGED_WIFI
#define ESCAPE_HOST_MANAGED_WIFI 0
#endif
#ifndef ESCAPE_SETUP_AP_IP
#define ESCAPE_SETUP_AP_IP 0x0A634D01u
#endif
// GPIO checked for "open the setup network" during the first seconds after start (-1 disables).
// GPIO0 is the BOOT button on most dev boards; holding it WHILE RESETTING enters the flash
// bootloader instead, so press it shortly AFTER the board started.
#ifndef ESCAPE_SETUP_BUTTON_PIN
#define ESCAPE_SETUP_BUTTON_PIN (-2)   // -2: the BOOT button of the chip (GPIO0; GPIO9 on ESP32-C3/C6/H2); -1: none
#endif

namespace EscapeConfig {

  // constexpr helpers (C++11) to check build-time strings.
  constexpr size_t textLength(const char *s, size_t n = 0) { return s[n] ? textLength(s, n + 1) : n; }
  constexpr bool printableToken(const char *s, size_t i = 0) {
    return s[i] == 0 ? true : ((unsigned char)s[i] >= 0x21 && (unsigned char)s[i] <= 0x7e && printableToken(s, i + 1));
  }

  // ---- Wi-Fi ----------------------------------------------------------------
  // Credentials never belong into the repository. Sources, in order:
  //   1. Credentials stored in NVS (setup network form, serial command ESCAPE_WIFI, network push).
  //   2. Build flags -DESCAPE_WIFI_SSID=\"..\" -DESCAPE_WIFI_PASSWORD=\"..\"
  //      (e.g. from the untracked secrets.ini).
  // Empty means "no build-time credentials". Unless -DESCAPE_HOST_MANAGED_WIFI=1 the library
  // owns the Wi-Fi station; if it cannot connect it opens the setup network (SETUP_AP_*).
  constexpr const char *WIFI_SSID = ESCAPE_WIFI_SSID;
  constexpr const char *WIFI_PASSWORD = ESCAPE_WIFI_PASSWORD;
  constexpr bool HOST_MANAGED_WIFI = ESCAPE_HOST_MANAGED_WIFI != 0;

  // ---- Wi-Fi setup network (ESP32 only) --------------------------------------------------------
  // Opened when the station has no credentials or cannot connect, so a device can be configured
  // without reflashing. Name: SETUP_AP_PREFIX + the full device id (unique per board; never derived
  // from the router's name). Empty password = OPEN network (default); see README for the risk.
  constexpr const char *SETUP_AP_PASSWORD = ESCAPE_SETUP_AP_PASSWORD;
  constexpr const char *SETUP_AP_PREFIX = "EscapeSetup-";
  constexpr uint32_t SETUP_AP_AFTER_MS = ESCAPE_SETUP_AP_AFTER_MS;
  constexpr uint32_t SETUP_AP_LINGER_MS = 15000;   // stays up this long after the station connected
  constexpr uint32_t SETUP_BUTTON_WINDOW_MS = 10000; // BOOT button window after start
  constexpr uint32_t SETUP_BUTTON_HOLD_MS = 1500;
  constexpr int SETUP_BUTTON_PIN = ESCAPE_SETUP_BUTTON_PIN;
  // Address of the setup network and its portal: 10.99.77.1/24. Not the ESP32 default 192.168.4.1, which is also a
  // common router/LAN range (a PC on such a LAN could not reach the portal: found while testing). Override with
  // -DESCAPE_SETUP_AP_IP=0x0A634D01 (hex of a.b.c.d); the setup network must differ from the LAN's subnet.
  constexpr uint32_t SETUP_AP_IP = ESCAPE_SETUP_AP_IP;
  constexpr uint32_t SETUP_DNS_PORT = 53;
  // After a network push of new Wi-Fi credentials the device tries them this long, then falls back
  // to the previous ones.
  constexpr uint32_t WIFI_TRY_MS = 30000;
  constexpr size_t WIFI_SSID_MAX_LEN = 32;
  constexpr size_t WIFI_PASSWORD_MAX_LEN = 63;
  static_assert(textLength(WIFI_SSID) <= WIFI_SSID_MAX_LEN, "ESCAPE_WIFI_SSID must be at most 32 characters");
  static_assert(textLength(WIFI_PASSWORD) == 0 || (textLength(WIFI_PASSWORD) >= 8 && textLength(WIFI_PASSWORD) <= WIFI_PASSWORD_MAX_LEN),
                "ESCAPE_WIFI_PASSWORD must be empty (open network) or 8..63 characters");
  static_assert(textLength(SETUP_AP_PASSWORD) == 0 || (textLength(SETUP_AP_PASSWORD) >= 8 && textLength(SETUP_AP_PASSWORD) <= 63),
                "ESCAPE_SETUP_AP_PASSWORD must be empty (open setup network) or 8..63 characters (WPA2)");

  // ---- Security ---------------------------------------------------------------
  // Shared secret of the installation, see PROTOCOL.md section 3. The repository
  // default is public on purpose: it lets ESP, simulator and manager work in a
  // closed escape-room network without provisioning ("Standard" level). Set an
  // own token (serial command or `pio run -e update-auth-token`) for shared or
  // less trusted networks.
  constexpr const char *AUTH_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
  constexpr size_t MIN_AUTH_TOKEN_LEN = 8;
  constexpr size_t MAX_AUTH_TOKEN_LEN = 128;
  // Token baked into the build (-DESCAPE_AUTH_TOKEN=\"..\", e.g. secrets.ini). A token stored on the
  // device wins over it; it replaces the public default. Use letters, digits and -_. only: other
  // characters need shell/ini escaping.
  constexpr const char *BUILD_AUTH_TOKEN = ESCAPE_AUTH_TOKEN;
  // The plan-edit token: only a holder may SEND plans to devices (PROTOCOL.md 3.1). Empty = none.
  constexpr const char *BUILD_EDIT_TOKEN = ESCAPE_EDIT_TOKEN;
  static_assert(textLength(BUILD_AUTH_TOKEN) == 0 || (textLength(BUILD_AUTH_TOKEN) >= MIN_AUTH_TOKEN_LEN &&
                textLength(BUILD_AUTH_TOKEN) <= MAX_AUTH_TOKEN_LEN && printableToken(BUILD_AUTH_TOKEN)),
                "ESCAPE_AUTH_TOKEN must be empty or 8..128 printable ASCII characters");
  static_assert(textLength(BUILD_EDIT_TOKEN) == 0 || (textLength(BUILD_EDIT_TOKEN) >= MIN_AUTH_TOKEN_LEN &&
                textLength(BUILD_EDIT_TOKEN) <= MAX_AUTH_TOKEN_LEN && printableToken(BUILD_EDIT_TOKEN)),
                "ESCAPE_EDIT_TOKEN must be empty or 8..128 printable ASCII characters");
  // Managers and tools warn below this length (the token still works).
  constexpr size_t RECOMMENDED_AUTH_TOKEN_LEN = 20;
  constexpr bool ALLOW_AUTH_TOKEN_IN_URL = true;
  // true: GET requests without a nonce are refused (no unauthenticated viewers).
  constexpr bool STRICT_GET = ESCAPE_STRICT_GET != 0;
  constexpr uint32_t KDF_ITERATIONS = 2048;      // PBKDF2-HMAC-SHA256, once per boot
  constexpr uint32_t MAX_KDF_ITERATIONS = 100000; // upper bound a manager accepts
  // Request freshness: |t - device clock| must not exceed this.
  constexpr uint32_t TIME_WINDOW_MS = 15000;
  // IVs of accepted requests kept for the time window (16 B each). Full = fail closed.
  // Sized above what ONE source can send in a window at the sustained rate limit
  // (RATE_BURST + window/RATE_REFILL_MS = 72), so a single manager never hits it.
  constexpr size_t REPLAY_CACHE_SIZE = 80;

  // ---- Network ------------------------------------------------------------------
  constexpr uint16_t UDP_PORT = 4210;
  constexpr uint16_t HTTP_PORT = 80;
  // Every device answers for this name (shared mDNS record, see PROTOCOL.md 7).
  constexpr const char *MDNS_HOSTNAME = "escapemanager";
  constexpr uint32_t MDNS_TTL_S = 15;
  constexpr size_t MAX_HTTP_CONNECTIONS = 2;
  // Connections waiting for a free slot. lwIP RESETS connections beyond this (measured: with a backlog of
  // 2, three or more concurrent clients saw occasional resets), so keep it above the usual number of
  // simultaneous browsers; each pending connection costs a few hundred bytes.
  constexpr int HTTP_LISTEN_BACKLOG = 6;
  // A connection that sent nothing for this long may be evicted for a waiting newcomer.
  constexpr uint32_t HTTP_EVICT_SILENT_AFTER_MS = 1000;
  constexpr uint32_t HTTP_IDLE_TIMEOUT_MS = 5000;   // no bytes received
  constexpr uint32_t HTTP_REQUEST_TIMEOUT_MS = 10000; // whole request incl. response
  constexpr size_t MAX_HEADER_BYTES = 1024;

  // ---- Broadcast timing ------------------------------------------------------------
  constexpr uint32_t HEARTBEAT_INTERVAL_MS = 4000;
  constexpr uint32_t HEARTBEAT_JITTER_MS = 750;
  constexpr uint32_t CHANGE_MIN_GAP_MS = 300;
  // The host program's markDirty() is only a hint (some hosts call it on EVERY loop). At most this
  // often the library compares a fingerprint of the component state and bumps `seq` (and announces)
  // only if something really changed.
  constexpr uint32_t HOST_CHANGE_CHECK_MS = 500;
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
