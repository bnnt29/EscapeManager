#!/usr/bin/env bash
# Builds and starts the serial host: lets an ordinary Arduino (no Wi-Fi, no crypto) take part in an
# EscapeManager network over a USB-serial line (same portable core as the ESP32 firmware and run_sim.sh).
#   ./run_serial_host.sh --serial /dev/ttyACM0 [--baud 115200] [--http-port 8080] [--did 12HEX] [--token T]
#                        [--edit-token T] [--setup] [--ip A.B.C.D] [--no-mdns] [--manager-html FILE]
#                        [--state-dir DIR]
#   --token / --edit-token: normal and plan-edit token (defaults: environment ESCAPE_AUTH_TOKEN / ESCAPE_EDIT_TOKEN)
#   --setup: accept POST /setup (token / Wi-Fi changes without restart; tokens only in memory)
# Line protocol and all options: header of src/sim/escape_component_serial_host.cpp.
# Needs g++ (C++17) and OpenSSL development headers (Debian/Ubuntu: libssl-dev).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p .sim-build
g++ -std=c++17 -O2 -Wall -Wextra -Wno-unused-parameter -pthread -o .sim-build/escape_component_serial_host \
  src/sim/escape_component_serial_host.cpp src/sim/OpenSslCryptoBackend.cpp src/net/Device.cpp src/net/Net.cpp \
  src/protocol/*.cpp -lcrypto
exec .sim-build/escape_component_serial_host "$@"
