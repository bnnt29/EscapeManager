// Firmware-Dummy fuer ECHTE ESP32-Hardware: nutzt den vollstaendigen
// Netzwerk-/Protokoll-Stack (WLAN, HTTP-Server inkl. manager.html-Auslieferung,
// UDP-Discovery, mDNS, SecureTransport - alles aus src/esp/client.hpp), aber
// mit rein SIMULIERTEN Komponenten statt echter Sensorik/Aktorik. Damit lassen
// sich zwei komplette Geraete (fuer Peer-Discovery/Konflikterkennung) auf
// echter Hardware hochladen und im Manager testen, ohne Raetsel-Hardware
// anzuschliessen.
//
// Ergaenzt die bestehenden Test-/Dummy-Werkzeuge, ersetzt sie nicht:
//   - src/protocol_dummy/main.cpp: NUR Json/Protocol-Logik, kein Netzwerk.
//   - src/sim/escape_component_sim.cpp: volles Protokoll, aber PC statt
//     echter ESP32-WLAN-/HTTP-Stack.
//   - src/esp_dummy/main.cpp (diese Datei): echte ESP32-Hardware, echtes WLAN,
//     aber simulierte Raetsel-Logik statt echter Sensorik.
//
//   pio run -e esp-dummy -t upload && pio device monitor
#include "../esp/client.hpp"

namespace {

constexpr uint8_t kComponentCount = 2;
constexpr uint16_t kTotalSteps = 5;

// Rein simulierter Zustand EINER Dummy-Komponente (Gegenstueck zu
// ComponentState in escape_component_sim.cpp), nur im RAM gehalten - Identitaet
// /Custom-Konfiguration/Ablaufplan werden weiterhin von EscapeComponent selbst
// in NVS persistiert.
struct DummyComponent {
  uint16_t step = 0;
  bool errorActive = false;
  CustomConfigDef brightness;
  CustomConfigDef label;
  CustomConfigDef difficulty;
};

DummyComponent g_components[kComponentCount];
uint8_t g_ids[kComponentCount];
int8_t g_battery = 100; // geraeteweit, wie bei EscapeComponent::onBattery()

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
}

void registerCallbacks(uint8_t id) {
  component.onErrors(id, [id](String out[], size_t maxCount) -> size_t {
    if (maxCount == 0 || !g_components[id].errorActive) return 0;
    out[0] = "sensor_timeout";
    return 1;
  });

  component.onActions(id, [](String out[], size_t maxCount) -> size_t {
    static const char *kActions[] = {"reset", "next_step", "solve", "toggle_error", "drain_battery"};
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
    state = "Schritt " + String(c.step) + " von " + String(kTotalSteps);
    isHtml = false;
  });

  component.onFeed(id, []() -> String { return "Dummy-Komponente aktiv (keine echte Sensorik verbaut)."; });

  component.onTip(id, [id]() -> String {
    return g_components[id].step < kTotalSteps ? "Naechste Aktion: next_step" : "";
  });

  component.onCustomConfig(id, [id](CustomConfigDef out[], size_t maxCount) -> size_t {
    const DummyComponent &c = g_components[id];
    size_t n = 0;
    if (n < maxCount) out[n++] = c.brightness;
    if (n < maxCount) out[n++] = c.label;
    if (n < maxCount) out[n++] = c.difficulty;
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

  g_ids[0] = component.addComponent("Dummy-Kamera", "Dummy-Raum", "dummy-camera-v1");
  g_ids[1] = component.addComponent("Dummy-Laser", "Dummy-Raum", "dummy-laser-v1");

  component.onBattery([]() -> int8_t { return g_battery; });

  for (uint8_t i = 0; i < kComponentCount; i++) {
    registerCallbacks(g_ids[i]);
  }

  component.begin();
}

void loop() {
  component.loop();
}
