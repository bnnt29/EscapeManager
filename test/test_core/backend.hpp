#pragma once
// Selects the crypto backend: mbedTLS on the ESP32, OpenSSL on the PC.
#ifdef ARDUINO
#include "../../src/esp/MbedTlsCryptoBackend.hpp"
typedef Escape::MbedTlsCryptoBackend TestBackend;
#else
#include "../../extras/sim/OpenSslCryptoBackend.hpp"
typedef Escape::OpenSslCryptoBackend TestBackend;
#endif
