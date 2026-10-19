// Minimal - the smallest useful EscapeManager sketch: one puzzle component with a door that can be opened and closed.
//
// 1. Pick your ESP32 board (any ESP32 with Wi-Fi) and upload.
// 2. Wi-Fi: either fill in arduino_secrets.h (next to this sketch) BEFORE uploading, or leave it empty: the board
//    then opens its own Wi-Fi "EscapeSetup-<id>" - join it with a phone and enter your Wi-Fi in the form that
//    opens (http://10.99.77.1).
// 3. Open http://escapemanager.local/ (or the board's IP address) in a browser on the same Wi-Fi.
//
// What a real sketch changes: the callbacks below (what your hardware does) and addComponent() (name, room).
#include "arduino_secrets.h"   // optional: Wi-Fi name/password and tokens
#include <EscapeManager.h>

EscapeComponent component;

static bool doorOpen = false;

void setup() {
  Serial.begin(115200);

  // Name and room are what the manager shows; an operator may rename them in the manager (stored on the board).
  // The third argument identifies the KIND of puzzle (same on every board of that kind).
  uint8_t id = component.addComponent("Door", "Room A", "door-puzzle-v1");

  // Buttons the manager shows for this component.
  component.onActions(id, [](String out[], size_t maxCount) -> size_t {
    out[0] = "open";
    out[1] = "close";
    return 2;
  });

  // Called when someone presses one of them: do the real work here and return true if it worked.
  component.onAction(id, [](const String &action) -> bool {
    if (action == "open") doorOpen = true;
    else if (action == "close") doorOpen = false;
    else return false;
    return true;
  });

  // What the manager shows as the puzzle's progress.
  component.onPuzzle(id, [](uint16_t &step, uint16_t &totalSteps, String &state, bool &isHtml) {
    step = doorOpen ? 1 : 0;
    totalSteps = 1;
    state = doorOpen ? "The door is open" : "The door is closed";
    isHtml = false;
  });

  component.begin();   // returns after ~250 ms; Wi-Fi connects in the background
}

void loop() {
  component.loop();    // cooperative and bounded: never blocks, never calls delay()
  component.markDirty();   // "something shown in the manager MAY have changed" - cheap even on every loop()
}
