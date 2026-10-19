// EspDummy - complete EscapeManager firmware for REAL ESP32 hardware with two SIMULATED puzzle components.
//
// It uses the full stack (Wi-Fi, HTTP server that serves the manager page, UDP discovery, shared mDNS name,
// secure transport) but no real sensors: upload it to two boards and try discovery, plan replication and the
// manager without any puzzle hardware. Each component sends a picture of its steps (HTML state) that changes with
// every step; actions: reset, next_step, solve, toggle_error, drain_battery.
//
// Related tools that do NOT need a board: extras/sim (PC simulator), extras/python (Python device).
//
//   Arduino IDE: open this sketch, pick your ESP32 board, upload; put your Wi-Fi in arduino_secrets.h or join the
//                board's setup Wi-Fi "EscapeSetup-<id>" afterwards.
//   PlatformIO:  pio run -e esp-dummy -t upload && pio device monitor
#include "arduino_secrets.h"
#include <EscapeManager.h>

namespace {

// ESCAPE_DEMO_MAX 1 (build flag or #define above): worst-case variant for memory/timing tests (see HARDWARE_TODO.md): four
// components, every text field at its limit, 8 actions, 4 errors, 4 custom config fields.
#ifndef ESCAPE_DEMO_MAX
#define ESCAPE_DEMO_MAX 0
#endif
#if ESCAPE_DEMO_MAX
constexpr uint8_t kComponentCount = 4;
#else
constexpr uint8_t kComponentCount = 2;
#endif
constexpr uint16_t kTotalSteps = 5;

// Purely simulated state of ONE dummy component, kept in RAM only (counterpart of ComponentState in
// extras/sim/escape_component_sim.cpp). Name, room, custom configuration and plan are persisted by EscapeComponent itself.
struct DummyComponent {
  uint16_t step = 0;
  bool errorActive = false;
  CustomConfigDef brightness;
  CustomConfigDef label;
  CustomConfigDef difficulty;
  CustomConfigDef extra;
};

#if ESCAPE_DEMO_MAX
// Arduino's String(n, c) is NOT "n times c" (it formats n in base c): build repeated text explicitly.
static String repeated(char c, size_t n) {
  String s;
  s.reserve(n);
  for (size_t i = 0; i < n; i++) s += c;
  return s;
}
#endif

// Picture of the steps as HTML state (isHtml): one box per step, finished steps filled, the current one outlined,
// all green when solved, a red frame while the demo's error is on. It changes with every step, so the manager's
// sandboxed state frame visibly follows the puzzle. About 1.1 KB, 1.2 KB with the error frame (the limit is EscapeConfig::MAX_STATE_LEN = 1664).
static String stepPicture(uint16_t step, uint16_t total, bool error) {
  const int boxW = 44, gap = 8, margin = 14, boxY = 8, boxH = 32;
  const int width = margin * 2 + (int)total * boxW + ((int)total - 1) * gap;
  const bool solved = step >= total;
  String svg;
  svg.reserve(900);
  svg += "<svg xmlns='http://www.w3.org/2000/svg' width='" + String(width) + "' height='64' font-family='sans-serif'>";
  for (uint16_t i = 0; i < total; i++) {
    const int x = margin + (int)i * (boxW + gap);
    const bool done = step > i, current = !solved && step == i;
    const char *fill = done ? (solved ? "#2e9e5b" : "#4a90d9") : "#eeeeee";
    const char *stroke = current ? "#4a90d9" : (done ? fill : "#bbbbbb");
    svg += "<rect x='" + String(x) + "' y='" + String(boxY) + "' width='" + String(boxW) + "' height='" + String(boxH) +
           "' rx='5' fill='" + fill + "' stroke='" + stroke + "' stroke-width='" + (current ? "3" : "1") + "'/>";
    svg += "<text x='" + String(x + boxW / 2) + "' y='" + String(boxY + 21) + "' font-size='14' text-anchor='middle' fill='" +
           (done ? "#ffffff" : "#555555") + "'>" + String(i + 1) + "</text>";
  }
  svg += "<text x='" + String(width / 2) + "' y='56' font-size='12' text-anchor='middle' fill='#222222'>";
  svg += solved ? String("gel\xC3\xB6st") : "Schritt " + String(step) + " von " + String(total);
  svg += "</text>";
  if (error) svg += "<rect x='1' y='1' width='" + String(width - 2) + "' height='62' fill='none' stroke='#d33' stroke-width='2'/>";
  svg += "</svg>";
  return svg;
}

DummyComponent g_components[kComponentCount];
uint8_t g_ids[kComponentCount];
int8_t g_battery = 100; // per device, like EscapeComponent::onBattery()

EscapeComponent component;

void initCustomConfig(DummyComponent &c) {
  EscapeProtocol::copyBounded(c.brightness.key, sizeof(c.brightness.key), "brightness");
  c.brightness.type = CustomConfigType::Range;
  c.brightness.rangeMin = 0;
  c.brightness.rangeMax = 100;
  EscapeProtocol::copyBounded(c.brightness.value, sizeof(c.brightness.value), "50");

  EscapeProtocol::copyBounded(c.label.key, sizeof(c.label.key), "label");
  c.label.type = CustomConfigType::Text;
  c.label.textMaxLen = 32;

  EscapeProtocol::copyBounded(c.difficulty.key, sizeof(c.difficulty.key), "difficulty");
  c.difficulty.type = CustomConfigType::Select;
  for (const char *opt : {"easy", "medium", "hard"}) {
    EscapeProtocol::copyBounded(c.difficulty.options[c.difficulty.optionCount],
                                 sizeof(c.difficulty.options[0]), opt);
    c.difficulty.optionCount++;
  }
  EscapeProtocol::copyBounded(c.difficulty.value, sizeof(c.difficulty.value), "medium");

  EscapeProtocol::copyBounded(c.extra.key, sizeof(c.extra.key), "extra");
  c.extra.type = CustomConfigType::Text;
  c.extra.textMaxLen = 48;
}

void registerCallbacks(uint8_t id) {
  component.onErrors(id, [id](String out[], size_t maxCount) -> size_t {
#if ESCAPE_DEMO_MAX
    size_t n = 0;
    for (; n < maxCount && n < 4; n++) out[n] = String("error-with-a-long-name-number-") + String((int)n) + "xxxxxxxx"; // 32+ chars
    return n;
#else
    if (maxCount == 0 || !g_components[id].errorActive) return 0;
    out[0] = "sensor_timeout";
    return 1;
#endif
  });

  component.onActions(id, [](String out[], size_t maxCount) -> size_t {
#if ESCAPE_DEMO_MAX
    static const char *kActions[] = {"reset", "next_step", "solve", "toggle_error", "drain_battery", "action_six_xxxxxxxxx", "action_seven_xxxxxxx", "action_eight_xxxxxxx"};
#else
    static const char *kActions[] = {"reset", "next_step", "solve", "toggle_error", "drain_battery"};
#endif
    size_t n = 0;
    for (const char *action : kActions) {
      if (n >= maxCount) break;
      out[n++] = action;
    }
    return n;
  });

  component.onAction(id, [id](const String &action) -> bool {
    DummyComponent &c = g_components[id];
    if (action == "reset") {
      c.step = 0;
      c.errorActive = false;
    } else if (action == "next_step") {
      c.step = c.step < kTotalSteps ? c.step + 1 : kTotalSteps;
    } else if (action == "solve") {
      c.step = kTotalSteps;
    } else if (action == "toggle_error") {
      c.errorActive = !c.errorActive;
    } else if (action == "drain_battery") {
      g_battery = g_battery > 10 ? g_battery - 10 : 0;
    } else {
      return false;
    }
    return true;
  });

  component.onPlanAction(id, [id](PlanAction action) -> bool {
    DummyComponent &c = g_components[id];
    if (action == PlanAction::Reset) {
      c.step = 0;
      c.errorActive = false;
      return true;
    }
    if (action == PlanAction::Complete) {
      c.step = kTotalSteps;
      return true;
    }
    return false;
  });

  component.onPuzzle(id, [id](uint16_t &step, uint16_t &totalSteps, String &state, bool &isHtml) {
    const DummyComponent &c = g_components[id];
    step = c.step;
    totalSteps = kTotalSteps;
#if ESCAPE_DEMO_MAX
    state = "<svg xmlns='http://www.w3.org/2000/svg' width='300' height='80'>";   // ~1.6 KB of HTML state (the limit is 1664)
    for (int i = 0; state.length() < 1600; i++) state += "<rect x='" + String(i % 200) + "' y='" + String(i % 60) + "' width='9' height='9'/>";
    state += "</svg>";
    isHtml = true;
#else
    state = stepPicture(c.step, kTotalSteps, c.errorActive);
    isHtml = true;
#endif
  });

#if ESCAPE_DEMO_MAX
  component.onFeed(id, []() -> String { return String("http://192.168.29.1/stream/") + repeated('f', 70); });   // ~96 chars
#else
  component.onFeed(id, []() -> String { return "Dummy-Komponente aktiv (keine echte Sensorik verbaut)."; });
#endif

  component.onTip(id, [id]() -> String {
#if ESCAPE_DEMO_MAX
    return repeated('t', 500);   // MAX_TIP_LEN is 512
#else
    return g_components[id].step < kTotalSteps ? "Nächste Aktion: next_step" : "";
#endif
  });

  component.onCustomConfig(id, [id](CustomConfigDef out[], size_t maxCount) -> size_t {
    const DummyComponent &c = g_components[id];
    size_t n = 0;
    if (n < maxCount) out[n++] = c.brightness;
    if (n < maxCount) out[n++] = c.label;
    if (n < maxCount) out[n++] = c.difficulty;
    if (n < maxCount) out[n++] = c.extra;
    return n;
  });

  component.onCustomConfigSet(id, [id](const String &key, const String &value) -> bool {
    DummyComponent &c = g_components[id];
    if (key == "brightness") {
      EscapeProtocol::copyBounded(c.brightness.value, sizeof(c.brightness.value), value.c_str());
      return true;
    }
    if (key == "label") {
      EscapeProtocol::copyBounded(c.label.value, sizeof(c.label.value), value.c_str());
      return true;
    }
    if (key == "extra") {
      EscapeProtocol::copyBounded(c.extra.value, sizeof(c.extra.value), value.c_str());
      return true;
    }
    if (key == "difficulty") {
      EscapeProtocol::copyBounded(c.difficulty.value, sizeof(c.difficulty.value), value.c_str());
      return true;
    }
    return false;
  });
}

} // namespace

void setup() {
  Serial.begin(115200);

  for (uint8_t i = 0; i < kComponentCount; i++) {
    initCustomConfig(g_components[i]);
  }

  // Several demo boards in one network need distinct component names (the manager keys
  // components by room + name): append the last two bytes of the factory MAC. The room is
  // shared on purpose so skeleton replication between the boards can be tried.
  char suffix[8];
  const uint64_t efuse = ESP.getEfuseMac();
  snprintf(suffix, sizeof(suffix), "%02X%02X", (unsigned)((efuse >> 32) & 0xFF), (unsigned)((efuse >> 40) & 0xFF));
  const String camera = String("Dummy-Kamera-") + suffix, laser = String("Dummy-Laser-") + suffix;
  // The riddle id identifies the puzzle TYPE; two boards in one room must not share one (the
  // manager would report a conflict), so the demo makes them unique per board as well.
  g_ids[0] = component.addComponent(camera, "Dummy-Raum", String("dummy-camera-") + suffix);
  g_ids[1] = component.addComponent(laser, "Dummy-Raum", String("dummy-laser-") + suffix);
#if ESCAPE_DEMO_MAX
  g_ids[2] = component.addComponent(String("Dummy-Sensor-") + suffix, "Dummy-Raum", String("dummy-sensor-") + suffix);
  g_ids[3] = component.addComponent(String("Dummy-Schloss-") + suffix, "Dummy-Raum-2", String("dummy-lock-") + suffix);
#endif

  component.onBattery([]() -> int8_t { return g_battery; });

  for (uint8_t i = 0; i < kComponentCount; i++) {
    registerCallbacks(g_ids[i]);
  }

  component.begin();
}

// Resource statistics on Serial every 10 s: free heap, lowest free heap since boot, largest free block, stack
// reserve of the loop() task and the longest/average duration of one component.loop() call (compare with the
// resource budget in the README). Switch off with ESCAPE_DEMO_STATS 0.
#ifndef ESCAPE_DEMO_STATS
#define ESCAPE_DEMO_STATS 1
#endif

void loop() {
#if ESCAPE_DEMO_STATS
  static uint32_t maxLoopUs = 0, sumLoopUs = 0, loopCount = 0, lastReportMs = 0;
  const uint32_t startUs = micros();
  component.loop();
  const uint32_t elapsedUs = micros() - startUs;
  if (elapsedUs > maxLoopUs) maxLoopUs = elapsedUs;
  sumLoopUs += elapsedUs;
  loopCount++;
  const uint32_t nowMs = millis();
  if (nowMs - lastReportMs >= 10000) {
    lastReportMs = nowMs;
    Serial.printf("[stats] heap free=%u min=%u maxblock=%u stackHWM=%u loop max=%luus avg=%luus n=%lu\n",
                  (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMinFreeHeap(),
                  (unsigned)ESP.getMaxAllocHeap(), (unsigned)uxTaskGetStackHighWaterMark(nullptr),
                  (unsigned long)maxLoopUs, (unsigned long)(loopCount ? sumLoopUs / loopCount : 0),
                  (unsigned long)loopCount);
    maxLoopUs = 0; sumLoopUs = 0; loopCount = 0;
  }
#else
  component.loop();
#endif
}
