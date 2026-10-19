#!/usr/bin/env bash
# Builds and starts the PC simulator (same portable core as the ESP32 firmware).
#   ./run_sim.sh --http-port 8080 [--component NAME:ROOM[:RIDDLE]]... [--token T] [--edit-token T] [--setup]
#                [--manager-html FILE]
#   --token / --edit-token: normal and plan-edit token (defaults: environment ESCAPE_AUTH_TOKEN / ESCAPE_EDIT_TOKEN)
#   --setup: accept POST /setup (token / Wi-Fi changes without restart; tokens only in memory)
# All options: header of extras/sim/escape_component_sim.cpp (or ./run_sim.sh --help).
# Needs g++ (C++17) and OpenSSL development headers (Debian/Ubuntu: libssl-dev).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .sim-build
g++ -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -pthread -o .sim-build/escape_component_sim \
  extras/sim/escape_component_sim.cpp extras/sim/OpenSslCryptoBackend.cpp src/net/Device.cpp src/net/Net.cpp \
  src/protocol/*.cpp -lcrypto
exec .sim-build/escape_component_sim "$@"
