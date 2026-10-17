#!/usr/bin/env bash
# Builds and starts the PC simulator (same portable core as the ESP32 firmware).
#   ./run_sim.sh --http-port 8080 [--component NAME:ROOM[:RIDDLE]]... [--token T] [--manager-html FILE]
# Needs g++ (C++17) and OpenSSL development headers (Debian/Ubuntu: libssl-dev).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .sim-build
g++ -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -pthread -o .sim-build/escape_component_sim \
  src/sim/escape_component_sim.cpp src/sim/OpenSslCryptoBackend.cpp src/net/Device.cpp src/net/Net.cpp \
  src/protocol/*.cpp -lcrypto
exec .sim-build/escape_component_sim "$@"
