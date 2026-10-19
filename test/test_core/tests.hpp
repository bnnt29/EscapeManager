#pragma once
// Every suite file defines one runner; test_main.cpp calls them all, on the PC and
// on the ESP32 alike (the portable core is tested on both).
void runJsonTests();
void runBase64Tests();
void runCryptoTests();
void runStoreTests();
void runPeerTests();
void runHttpTests();
void runProtocolTests();
void runSetupTests();
void runFuzzTests();
