#pragma once

// Vollstaendiger Arduino-ESP32-Adapter: Die echte Implementierung nutzt
// HardwareEsp32 fuer WLAN/UDP/HTTP und MbedTlsCryptoBackend fuer P-256,
// HKDF, HMAC-SHA-256 und AES-256-GCM.

#include "../esp/client.hpp"
