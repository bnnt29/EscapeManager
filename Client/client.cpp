// Implementierung von EscapeComponent (siehe client.hpp).
//
// Benoetigte Bibliothek (PlatformIO): bblanchon/ArduinoJson (nur zum Parsen
// eingehender Nachrichten - der /status.json-Response wird bewusst manuell
// als String gebaut, um bei vielen Peers keine grossen ArduinoJson-Dokumente
// im Speicher halten zu muessen).
//
// platformio.ini Beispiel:
//   lib_deps = bblanchon/ArduinoJson @ ^7

#include "client.hpp"
#include <ArduinoJson.h>
#include <esp_system.h>
#include <cstdlib>
#include <vector>

// manager.html wird ueber PlatformIO's "board_build.embed_files" direkt als
// Binaerblob ins Flash gelinkt (siehe platformio.ini) - die Datei bleibt damit
// eigenstaendig unter Manager/manager.html und muss nicht als C-String im
// Quelltext dupliziert werden. Symbolnamen leiten sich aus dem Dateipfad ab.
extern const uint8_t manager_html_start[] asm("_binary_Manager_manager_html_start");
extern const uint8_t manager_html_end[] asm("_binary_Manager_manager_html_end");

namespace {

// Vergleicht zwei Strings ohne Frueh-Abbruch bei erstem Unterschied, um
// Timing-Angriffe auf den Auth-Token zu erschweren. Die Laenge selbst ist
// ueber die Schleifenzahl minimal beobachtbar, was fuer dieses Bedrohungsmodell
// (LAN-Zugriff, kein hochpraeziser Fernangreifer) akzeptabel ist.
bool constantTimeEquals(const String &a, const char *b) {
  size_t la = a.length();
  size_t lb = strlen(b);
  uint8_t diff = (uint8_t)(la != lb);
  size_t n = la < lb ? la : lb;
  for (size_t i = 0; i < n; i++) {
    diff |= (uint8_t)a[i] ^ (uint8_t)b[i];
  }
  return diff == 0;
}

void appendJsonEscaped(String &out, const char *s) {
  if (!s) return;
  for (const char *c = s; *c; c++) {
    switch (*c) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      default:
        if ((uint8_t)*c >= 0x20) out += *c; // sonstige Steuerzeichen verwerfen
    }
  }
}

void copyBounded(char *dst, size_t dstSize, const char *src) {
  strncpy(dst, src ? src : "", dstSize - 1);
  dst[dstSize - 1] = '\0';
}

const char *customConfigTypeName(CustomConfigType t) {
  switch (t) {
    case CustomConfigType::Range: return "range";
    case CustomConfigType::Select: return "select";
    case CustomConfigType::Text: default: return "text";
  }
}

void writeCustomConfigDefJson(String &out, const CustomConfigDef &d) {
  out += '{';
  out += "\"key\":\""; appendJsonEscaped(out, d.key); out += "\",";
  out += "\"type\":\""; out += customConfigTypeName(d.type); out += "\",";
  switch (d.type) {
    case CustomConfigType::Range:
      out += "\"min\":"; out += String(d.rangeMin); out += ',';
      out += "\"max\":"; out += String(d.rangeMax); out += ',';
      break;
    case CustomConfigType::Text:
      out += "\"maxLength\":"; out += String(d.textMaxLen); out += ',';
      break;
    case CustomConfigType::Select:
      out += "\"options\":[";
      for (uint8_t i = 0; i < d.optionCount; i++) {
        if (i) out += ',';
        out += '"'; appendJsonEscaped(out, d.options[i]); out += '"';
      }
      out += "],";
      break;
  }
  out += "\"value\":\""; appendJsonEscaped(out, d.value); out += "\"";
  out += '}';
}

const CustomConfigDef *findCustomConfigDef(const CustomConfigDef *defs, size_t count, const char *key) {
  for (size_t i = 0; i < count; i++) {
    if (strncmp(defs[i].key, key, sizeof(defs[i].key)) == 0) return &defs[i];
  }
  return nullptr;
}

// Prueft einen von aussen (POST /config) eingegangenen Wert gegen das vom
// Hauptskript deklarierte Schema (Grenzen/erlaubte Werte), bevor er
// uebernommen wird - der Client (Manager) ist eine nicht vertrauenswuerdige
// Eingabequelle.
bool validateCustomConfigValue(const CustomConfigDef &def, const String &value) {
  switch (def.type) {
    case CustomConfigType::Range: {
      if (value.length() == 0) return false;
      char *end = nullptr;
      long v = strtol(value.c_str(), &end, 10);
      if (end == value.c_str() || *end != '\0') return false; // kein sauberer Ganzzahl-String
      return v >= def.rangeMin && v <= def.rangeMax;
    }
    case CustomConfigType::Text:
      return value.length() <= def.textMaxLen;
    case CustomConfigType::Select:
      for (uint8_t i = 0; i < def.optionCount; i++) {
        if (value == def.options[i]) return true;
      }
      return false;
  }
  return false;
}

// Leitet eine stabile, von Name/Raum unabhaengige Komponenten-Identitaet von
// der WLAN-MAC-Adresse des Boards ab (Grundlage fuer die Zuordnung im
// Ablaufplan, siehe Manager/manager.html): deterministisch statt zufaellig,
// daher ohne Zufallsquelle/NVS-Race ueber Reboots hinweg stabil, und trotzdem
// pro Board+Komponente eindeutig (MAC + lokaler Index). Braucht WiFi.mode()/
// WiFi-Init vorher, sonst liefert WiFi.macAddress() ggf. nur Nullen.
// Fallback fuer den Fall, dass WiFi.macAddress() keine brauchbare Adresse
// liefert (alle Bytes 0x00 oder 0xFF, z.B. bei einem WLAN-Treiberfehler oder
// defektem Funkmodul): die 64-Bit Chip-ID aus der eFuse (ESP.getEfuseMac(),
// werkseitig einzigartig pro Chip und unabhaengig vom WLAN-Stack) wird
// stattdessen verwendet, damit trotzdem eine stabile, geraeteweit eindeutige
// Kennung entsteht statt kollidierender Nullen auf mehreren Boards.
// "out" muss mindestens EscapeConfig::MAX_UUID_LEN+1 Bytes gross sein.
void macBasedUuid(uint8_t id, char *out, size_t outSize) {
  uint8_t mac[6] = {0};
  WiFi.macAddress(mac);

  bool allSame = true;
  for (uint8_t i = 1; i < 6; i++) {
    if (mac[i] != mac[0]) { allSame = false; break; }
  }
  bool macUnavailable = allSame && (mac[0] == 0x00 || mac[0] == 0xFF);

  if (macUnavailable) {
    // Nur die unteren 48 Bit sind bei ESP.getEfuseMac() belegt (obere 16 Bit
    // sind 0) - maskieren erzwingt trotzdem exakt 12 Hex-Ziffern im Format,
    // damit "out" niemals ueber MAX_UUID_LEN hinauswaechst.
    uint64_t chipId = ESP.getEfuseMac() & 0xFFFFFFFFFFFFULL;
    snprintf(out, outSize, "chip%012llx-%u", (unsigned long long)chipId, (unsigned)id);
  } else {
    snprintf(out, outSize, "%02x%02x%02x%02x%02x%02x-%u",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], (unsigned)id);
  }
}

} // namespace

void EscapeComponent::begin() {
  WiFi.mode(WIFI_STA);
  for (uint8_t i = 0; i < _componentCount; i++) resolveUuid(i);

  WiFi.begin(EscapeConfig::WIFI_SSID, EscapeConfig::WIFI_PASSWORD);
  uint32_t start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000) {
    delay(200);
  }

  _udp.begin(EscapeConfig::UDP_PORT);

  // Pro Geraet fixer Zufalls-Versatz gegen synchrone Broadcast-Bursts,
  // z.B. wenn ein ganzer Raum gleichzeitig eingeschaltet/reconnected wird.
  _jitterOffsetMs = esp_random() % (EscapeConfig::HEARTBEAT_JITTER_MS + 1);

  const char *headerKeys[] = {"X-Auth-Token"};
  _server.collectHeaders(headerKeys, 1);
  _server.on("/", HTTP_GET, [this] { handleRoot(); });
  _server.on("/status.json", HTTP_GET, [this] { handleStatus(); });
  _server.on("/action", HTTP_POST, [this] { handleAction(); });
  _server.on("/action", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.on("/config", HTTP_POST, [this] { handleConfig(); });
  _server.on("/config", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.on("/plan", HTTP_POST, [this] { handlePlan(); });
  _server.on("/plan", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.on("/plan-skeleton.json", HTTP_GET, [this] { handlePlanSkeletonGet(); });
  _server.on("/plan-skeleton", HTTP_POST, [this] { handlePlanSkeletonPost(); });
  _server.on("/plan-skeleton", HTTP_OPTIONS, [this] { sendCorsPreflight(); });
  _server.begin();

  loadPlanSkeleton();

  // Gemeinsamer Hostname ueber alle Komponenten: welches Geraet ein Client
  // beim Aufloesen von <MDNS_HOSTNAME>.local letztlich erreicht, entscheidet
  // der mDNS-Resolver des Betriebssystems (i.d.R. die zuerst antwortende
  // Komponente) - dadurch verbindet sich ein neuer Manager ohne Konfiguration
  // mit irgendeiner erreichbaren Komponente.
  MDNS.begin(EscapeConfig::MDNS_HOSTNAME);
  MDNS.addService("http", "tcp", EscapeConfig::HTTP_PORT);
}

void EscapeComponent::loop() {
  _server.handleClient();
  pollIncoming();

  uint32_t now = millis();
  uint32_t interval = EscapeConfig::HEARTBEAT_INTERVAL_MS + _jitterOffsetMs;
  bool heartbeatDue = now - _lastBroadcastMs >= interval;
  bool changeDue = _dirty && (now - _lastBroadcastMs >= EscapeConfig::CHANGE_MIN_GAP_MS);

  if (heartbeatDue || changeDue) {
    sendBroadcast();
    _lastBroadcastMs = now;
    _dirty = false;
  }

  // Nicht jeden loop()-Durchlauf pruefen: Aufraeumen ist unkritisch in seiner
  // Genauigkeit und muss keine CPU-Zeit auf jedem Zyklus kosten.
  if (now - _lastExpireCheckMs >= 2000) {
    expireStalePeers();
    _lastExpireCheckMs = now;
  }
}

void EscapeComponent::markDirty() { _dirty = true; }

// Siehe client.hpp: erhoeht den Aktivitaets-Zaehler + setzt die Klartext-
// Meldung einer lokalen Komponente, damit sie im naechsten Broadcast/
// status.json an alle Manager (auch andere, nicht die anfragende Instanz)
// weitergereicht wird - Grundlage der plattformuebergreifenden "jemand hat
// etwas veraendert"-Benachrichtigung in Manager/manager.html.
void EscapeComponent::pushEvent(uint8_t id, const String &msg) {
  if (id >= _componentCount) return;
  LocalComponent &c = _components[id];
  c.eventSeq++;
  copyBounded(c.eventMsg, sizeof(c.eventMsg), msg.c_str());
  markDirty();
}

uint8_t EscapeComponent::addComponent(const String &defaultName, const String &defaultRoom) {
  if (_componentCount >= EscapeConfig::MAX_LOCAL_COMPONENTS) {
    // Kapazitaet erschoepft: liefert die letzte gueltige ID erneut statt eines
    // Fehlercodes, damit ein Aufrufer ohne Rueckgabewertpruefung nicht
    // versehentlich ausserhalb des _components-Arrays schreibt.
    return EscapeConfig::MAX_LOCAL_COMPONENTS - 1;
  }
  uint8_t id = _componentCount++;
  loadIdentity(id, defaultName, defaultRoom);
  return id;
}

void EscapeComponent::onBattery(BatteryProvider cb) { _batteryCb = cb; }
void EscapeComponent::onErrors(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].errorsCb = cb; }
void EscapeComponent::onActions(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].actionsCb = cb; }
void EscapeComponent::onFeed(uint8_t id, FeedProvider cb) { if (id < _componentCount) _components[id].feedCb = cb; }
void EscapeComponent::onPuzzle(uint8_t id, PuzzleProvider cb) { if (id < _componentCount) _components[id].puzzleCb = cb; }
void EscapeComponent::onAction(uint8_t id, ActionHandler cb) { if (id < _componentCount) _components[id].actionHandler = cb; }
void EscapeComponent::onCustomConfig(uint8_t id, CustomConfigProvider cb) { if (id < _componentCount) _components[id].customConfigCb = cb; }
void EscapeComponent::onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb) { if (id < _componentCount) _components[id].customConfigSetCb = cb; }

// ---- Identitaet (NVS) -------------------------------------------------------
// Jede Komponente bekommt eigene NVS-Schluessel (name0/room0, name1/room1, ...),
// damit mehrere Komponenten auf demselben Board unabhaengig konfiguriert und
// persistiert werden koennen.

void EscapeComponent::loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom) {
  String nameKey = "name" + String(id);
  String roomKey = "room" + String(id);
  String planKey = "plan" + String(id);
  _prefs.begin("escfg", true);
  String n = _prefs.getString(nameKey.c_str(), defaultName);
  String r = _prefs.getString(roomKey.c_str(), defaultRoom);
  String p = _prefs.getString(planKey.c_str(), "");
  _prefs.end();
  copyBounded(_components[id].name, sizeof(_components[id].name), n.c_str());
  copyBounded(_components[id].room, sizeof(_components[id].room), r.c_str());
  copyBounded(_components[id].plan, sizeof(_components[id].plan), p.c_str());
}

void EscapeComponent::resolveUuid(uint8_t id) {
  String uuidKey = "uuid" + String(id);
  _prefs.begin("escfg", true);
  String u = _prefs.getString(uuidKey.c_str(), "");
  _prefs.end();

  if (u.length() == 0) {
    // Noch nichts gespeichert: von der MAC-Adresse ableiten und dauerhaft
    // persistieren (ein spaeter manuell in NVS gesetzter Wert haette dank
    // dieser Pruefung Vorrang) - siehe macBasedUuid().
    char generated[EscapeConfig::MAX_UUID_LEN + 1];
    macBasedUuid(id, generated, sizeof(generated));
    _prefs.begin("escfg", false);
    _prefs.putString(uuidKey.c_str(), generated);
    _prefs.end();
    copyBounded(_components[id].uuid, sizeof(_components[id].uuid), generated);
  } else {
    copyBounded(_components[id].uuid, sizeof(_components[id].uuid), u.c_str());
  }
}

void EscapeComponent::saveIdentity(uint8_t id, const String &name, const String &room) {
  String nameKey = "name" + String(id);
  String roomKey = "room" + String(id);
  _prefs.begin("escfg", false);
  _prefs.putString(nameKey.c_str(), name);
  _prefs.putString(roomKey.c_str(), room);
  _prefs.end();
  copyBounded(_components[id].name, sizeof(_components[id].name), name.c_str());
  copyBounded(_components[id].room, sizeof(_components[id].room), room.c_str());
}

void EscapeComponent::loadPlanSkeleton() {
  // Geraeteweit (nicht pro Komponente) - siehe EscapeConfig::MAX_PLAN_SKELETON_LEN.
  _prefs.begin("escfg", true);
  _planSkeleton = _prefs.getString("planskel", "");
  _prefs.end();
}

// ---- Broadcast senden -------------------------------------------------------

IPAddress EscapeComponent::broadcastAddress() const {
  IPAddress ip = WiFi.localIP();
  IPAddress mask = WiFi.subnetMask();
  if ((uint32_t)mask == 0) return IPAddress(255, 255, 255, 255);
  IPAddress bc;
  for (int i = 0; i < 4; i++) bc[i] = ip[i] | (~mask[i] & 0xFF);
  return bc;
}

void EscapeComponent::sendBroadcast() {
  // Ein Broadcast-Paket beschreibt das GESAMTE Board: gemeinsames ip/battery
  // auf oberster Ebene, plus ein "components"-Array mit je einem Objekt pro
  // addComponent()-registrierter Raetsel-Komponente. Kapazitaet skaliert mit
  // MAX_LOCAL_COMPONENTS - auf dem Heap statt auf dem (kleinen, fixen)
  // Task-Stack allokiert, um bei mehreren Komponenten keinen Stack-Overflow
  // zu riskieren. +MAX_PLAN_LEN pro Komponente wegen des optionalen rohen
  // Ablaufplan-Slice (siehe LocalComponent::plan).
  DynamicJsonDocument doc(512 + _componentCount * (1536 + EscapeConfig::MAX_PLAN_LEN));
  doc["ip"] = WiFi.localIP().toString();
  doc["battery"] = _batteryCb ? _batteryCb() : -1;

  JsonArray components = doc.createNestedArray("components");
  for (uint8_t i = 0; i < _componentCount; i++) {
    const LocalComponent &c = _components[i];
    JsonObject comp = components.createNestedObject();
    comp["id"] = i;
    comp["uuid"] = c.uuid;
    comp["name"] = c.name;
    comp["room"] = c.room;

    JsonArray errs = comp.createNestedArray("errors");
    if (c.errorsCb) {
      String buf[EscapeConfig::MAX_ERRORS];
      size_t n = c.errorsCb(buf, EscapeConfig::MAX_ERRORS);
      for (size_t j = 0; j < n && j < EscapeConfig::MAX_ERRORS; j++) errs.add(buf[j]);
    }

    JsonArray acts = comp.createNestedArray("actions");
    if (c.actionsCb) {
      String buf[EscapeConfig::MAX_ACTIONS];
      size_t n = c.actionsCb(buf, EscapeConfig::MAX_ACTIONS);
      for (size_t j = 0; j < n && j < EscapeConfig::MAX_ACTIONS; j++) acts.add(buf[j]);
    }

    if (c.feedCb) {
      String feed = c.feedCb();
      if (feed.length()) comp["feed"] = feed;
    }

    if (c.puzzleCb) {
      uint16_t step = 0, total = 0;
      String state;
      bool isHtml = false;
      c.puzzleCb(step, total, state, isHtml);
      if (total > 0) {
        JsonObject puzzle = comp.createNestedObject("puzzle");
        puzzle["step"] = step;
        puzzle["totalSteps"] = total;
        if (state.length()) puzzle["state"] = state;
        puzzle["isHtml"] = isHtml;
      }
    }

    if (c.customConfigCb) {
      CustomConfigDef defs[EscapeConfig::MAX_CUSTOM_CONFIGS];
      size_t n = c.customConfigCb(defs, EscapeConfig::MAX_CUSTOM_CONFIGS);
      if (n > 0) {
        JsonArray arr = comp.createNestedArray("customConfig");
        for (size_t j = 0; j < n && j < EscapeConfig::MAX_CUSTOM_CONFIGS; j++) {
          JsonObject o = arr.createNestedObject();
          const CustomConfigDef &d = defs[j];
          o["key"] = d.key;
          o["type"] = customConfigTypeName(d.type);
          switch (d.type) {
            case CustomConfigType::Range:
              o["min"] = d.rangeMin;
              o["max"] = d.rangeMax;
              break;
            case CustomConfigType::Text:
              o["maxLength"] = d.textMaxLen;
              break;
            case CustomConfigType::Select: {
              JsonArray opts = o.createNestedArray("options");
              for (uint8_t k = 0; k < d.optionCount; k++) opts.add(d.options[k]);
              break;
            }
          }
          o["value"] = d.value;
        }
      }
    }

    // Roher Ablaufplan-Slice: fuer die Firmware bedeutungslos, wird nur
    // unveraendert weitergereicht (siehe EscapeConfig::MAX_PLAN_LEN).
    if (c.plan[0]) comp["plan"] = serialized(c.plan);

    // Aktivitaets-Benachrichtigung (siehe pushEvent()) - nur senden, wenn
    // bereits mind. ein Ereignis ausgeloest wurde.
    if (c.eventSeq) {
      comp["evtSeq"] = c.eventSeq;
      comp["evtMsg"] = c.eventMsg;
    }
  }

  size_t needed = measureJson(doc) + 1;
  std::vector<char> buf(needed);
  size_t len = serializeJson(doc, buf.data(), buf.size());

  IPAddress bc = broadcastAddress();
  _udp.beginPacket(bc, EscapeConfig::UDP_PORT);
  _udp.write((const uint8_t *)buf.data(), len);
  _udp.endPacket();
}

// ---- Broadcast empfangen / Peer-Tabelle -------------------------------------

PeerInfo *EscapeComponent::findOrCreatePeer(const char *name, const char *room) {
  for (size_t i = 0; i < _peerCount; i++) {
    if (strncmp(_peers[i].name, name, sizeof(_peers[i].name)) == 0 &&
        strncmp(_peers[i].room, room, sizeof(_peers[i].room)) == 0) {
      return &_peers[i];
    }
  }
  if (_peerCount < EscapeConfig::MAX_PEERS) {
    return &_peers[_peerCount++];
  }
  // Tabelle voll (z.B. viele kurzlebige/testweise Komponenten im WLAN):
  // am laengsten nicht gesehenen Eintrag verdraengen statt neue zu verwerfen.
  size_t oldest = 0;
  for (size_t i = 1; i < _peerCount; i++) {
    if (_peers[i].lastSeenMs < _peers[oldest].lastSeenMs) oldest = i;
  }
  return &_peers[oldest];
}

void EscapeComponent::pollIncoming() {
  // Pro loop()-Aufruf begrenzt viele Pakete verarbeiten, damit ein Burst
  // eingehender Broadcasts den HTTP-Server nicht verhungern laesst.
  int processed = 0;
  int packetSize;
  // Puffer skaliert mit MAX_LOCAL_COMPONENTS (andere Boards koennen genauso
  // viele Komponenten in einem Paket buendeln) - als Klassenmitglied statt
  // Stack-Array, um den (kleinen, fixen) Task-Stack nicht zu belasten.
  static std::vector<char> buf(512 + EscapeConfig::MAX_LOCAL_COMPONENTS * (1536 + EscapeConfig::MAX_PLAN_LEN));
  while (processed < 5 && (packetSize = _udp.parsePacket()) > 0) {
    processed++;
    int len = _udp.read(buf.data(), buf.size() - 1);
    if (len <= 0) continue;
    buf[len] = '\0';

    DynamicJsonDocument doc(buf.size());
    if (deserializeJson(doc, buf.data())) continue; // fehlerhaftes/fremdes Paket verwerfen

    JsonArray components = doc["components"].as<JsonArray>();
    if (components.isNull()) continue;
    int8_t senderBattery = doc["battery"] | -1;
    IPAddress senderIp = _udp.remoteIP();

    for (JsonObject comp : components) {
      const char *name = comp["name"] | "";
      const char *room = comp["room"] | "";
      if (!*name || !*room) continue;
      // eigene Komponenten ignorieren (Identitaet, nicht IP - siehe IP-Wechsel-Hinweis)
      bool isSelf = false;
      for (uint8_t i = 0; i < _componentCount; i++) {
        if (strncmp(name, _components[i].name, sizeof(_components[i].name)) == 0 &&
            strncmp(room, _components[i].room, sizeof(_components[i].room)) == 0) {
          isSelf = true;
          break;
        }
      }
      if (isSelf) continue;

      PeerInfo *p = findOrCreatePeer(name, room);
      if (!p) continue;

      p->id = (uint8_t)(comp["id"] | 0);
      copyBounded(p->uuid, sizeof(p->uuid), comp["uuid"] | "");
      copyBounded(p->name, sizeof(p->name), name);
      copyBounded(p->room, sizeof(p->room), room);
      p->ip = senderIp;
      p->battery = senderBattery;

      p->errorCount = 0;
      for (JsonVariant v : comp["errors"].as<JsonArray>()) {
        if (p->errorCount >= EscapeConfig::MAX_ERRORS) break;
        copyBounded(p->errors[p->errorCount], sizeof(p->errors[0]), v.as<const char *>());
        p->errorCount++;
      }

      p->actionCount = 0;
      for (JsonVariant v : comp["actions"].as<JsonArray>()) {
        if (p->actionCount >= EscapeConfig::MAX_ACTIONS) break;
        copyBounded(p->actions[p->actionCount], sizeof(p->actions[0]), v.as<const char *>());
        p->actionCount++;
      }

      copyBounded(p->feed, sizeof(p->feed), comp["feed"] | "");

      JsonObject puzzle = comp["puzzle"];
      if (!puzzle.isNull()) {
        p->puzzleStep = puzzle["step"] | 0;
        p->puzzleTotalSteps = puzzle["totalSteps"] | 0;
        copyBounded(p->puzzleState, sizeof(p->puzzleState), puzzle["state"] | "");
        p->puzzleIsHtml = puzzle["isHtml"] | false;
      } else {
        p->puzzleTotalSteps = 0;
      }

      p->customConfigCount = 0;
      for (JsonObject cc : comp["customConfig"].as<JsonArray>()) {
        if (p->customConfigCount >= EscapeConfig::MAX_CUSTOM_CONFIGS) break;
        CustomConfigDef &d = p->customConfig[p->customConfigCount];
        d = CustomConfigDef();
        copyBounded(d.key, sizeof(d.key), cc["key"] | "");
        const char *type = cc["type"] | "text";
        if (strcmp(type, "range") == 0) {
          d.type = CustomConfigType::Range;
          d.rangeMin = cc["min"] | 0;
          d.rangeMax = cc["max"] | 0;
        } else if (strcmp(type, "select") == 0) {
          d.type = CustomConfigType::Select;
          for (JsonVariant o : cc["options"].as<JsonArray>()) {
            if (d.optionCount >= EscapeConfig::MAX_CONFIG_OPTIONS) break;
            copyBounded(d.options[d.optionCount], sizeof(d.options[0]), o.as<const char *>());
            d.optionCount++;
          }
        } else {
          d.type = CustomConfigType::Text;
          d.textMaxLen = cc["maxLength"] | 0;
        }
        copyBounded(d.value, sizeof(d.value), cc["value"] | "");
        p->customConfigCount++;
      }

      // Roher Ablaufplan-Slice: fuer die Firmware bedeutungslos, wird nur
      // re-serialisiert (nicht interpretiert) in die eigene Peer-Tabelle
      // uebernommen, damit /status.json ihn unveraendert weiterreichen kann.
      if (!comp["plan"].isNull()) {
        String planStr;
        serializeJson(comp["plan"], planStr);
        copyBounded(p->plan, sizeof(p->plan), planStr.c_str());
      } else {
        p->plan[0] = '\0';
      }

      // Aktivitaets-Benachrichtigung durchreichen (siehe pushEvent()) - fehlt
      // das Feld (noch nie ein Ereignis auf der Senderseite), bleibt 0/leer.
      p->eventSeq = comp["evtSeq"] | 0;
      copyBounded(p->eventMsg, sizeof(p->eventMsg), comp["evtMsg"] | "");

      p->lastSeenMs = millis();
    }
  }
}

void EscapeComponent::expireStalePeers() {
  uint32_t now = millis();
  size_t w = 0;
  for (size_t i = 0; i < _peerCount; i++) {
    if (now - _peers[i].lastSeenMs <= EscapeConfig::PEER_TIMEOUT_MS) {
      if (w != i) _peers[w] = _peers[i];
      w++;
    }
  }
  _peerCount = w;
}

// ---- / (manager.html) -------------------------------------------------------

void EscapeComponent::handleRoot() {
  size_t len = manager_html_end - manager_html_start;
  _server.send_P(200, "text/html", (PGM_P)manager_html_start, len);
}

// ---- /status.json ------------------------------------------------------------

void EscapeComponent::fillComponentPeer(PeerInfo &p, uint8_t id) const {
  const LocalComponent &c = _components[id];
  p.id = id;
  copyBounded(p.uuid, sizeof(p.uuid), c.uuid);
  copyBounded(p.name, sizeof(p.name), c.name);
  copyBounded(p.room, sizeof(p.room), c.room);
  copyBounded(p.plan, sizeof(p.plan), c.plan);
  p.eventSeq = c.eventSeq;
  copyBounded(p.eventMsg, sizeof(p.eventMsg), c.eventMsg);
  p.ip = WiFi.localIP();
  p.battery = _batteryCb ? _batteryCb() : -1;

  p.errorCount = 0;
  if (c.errorsCb) {
    String buf[EscapeConfig::MAX_ERRORS];
    size_t n = c.errorsCb(buf, EscapeConfig::MAX_ERRORS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ERRORS; i++) {
      copyBounded(p.errors[i], sizeof(p.errors[0]), buf[i].c_str());
      p.errorCount++;
    }
  }

  p.actionCount = 0;
  if (c.actionsCb) {
    String buf[EscapeConfig::MAX_ACTIONS];
    size_t n = c.actionsCb(buf, EscapeConfig::MAX_ACTIONS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ACTIONS; i++) {
      copyBounded(p.actions[i], sizeof(p.actions[0]), buf[i].c_str());
      p.actionCount++;
    }
  }

  if (c.feedCb) copyBounded(p.feed, sizeof(p.feed), c.feedCb().c_str());

  p.puzzleTotalSteps = 0;
  if (c.puzzleCb) {
    uint16_t step = 0, total = 0;
    String state;
    bool isHtml = false;
    c.puzzleCb(step, total, state, isHtml);
    p.puzzleStep = step;
    p.puzzleTotalSteps = total;
    copyBounded(p.puzzleState, sizeof(p.puzzleState), state.c_str());
    p.puzzleIsHtml = isHtml;
  }

  p.customConfigCount = 0;
  if (c.customConfigCb) {
    CustomConfigDef defs[EscapeConfig::MAX_CUSTOM_CONFIGS];
    size_t n = c.customConfigCb(defs, EscapeConfig::MAX_CUSTOM_CONFIGS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_CUSTOM_CONFIGS; i++) {
      p.customConfig[i] = defs[i];
      p.customConfigCount++;
    }
  }

  p.lastSeenMs = millis();
}

void EscapeComponent::writePeerJson(String &out, const PeerInfo &p) const {
  out += '{';
  out += "\"id\":"; out += String(p.id); out += ',';
  out += "\"uuid\":\""; appendJsonEscaped(out, p.uuid); out += "\",";
  out += "\"name\":\""; appendJsonEscaped(out, p.name); out += "\",";
  out += "\"room\":\""; appendJsonEscaped(out, p.room); out += "\",";
  out += "\"ip\":\""; out += p.ip.toString(); out += "\",";
  out += "\"battery\":"; out += String(p.battery); out += ',';

  out += "\"errors\":[";
  for (uint8_t i = 0; i < p.errorCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.errors[i]); out += '"';
  }
  out += "],";

  out += "\"actions\":[";
  for (uint8_t i = 0; i < p.actionCount; i++) {
    if (i) out += ',';
    out += '"'; appendJsonEscaped(out, p.actions[i]); out += '"';
  }
  out += "],";

  if (p.feed[0]) {
    out += "\"feed\":\""; appendJsonEscaped(out, p.feed); out += "\",";
  }

  if (p.puzzleTotalSteps > 0) {
    out += "\"puzzle\":{";
    out += "\"step\":"; out += String(p.puzzleStep); out += ',';
    out += "\"totalSteps\":"; out += String(p.puzzleTotalSteps); out += ',';
    out += "\"state\":\""; appendJsonEscaped(out, p.puzzleState); out += "\",";
    out += "\"isHtml\":"; out += (p.puzzleIsHtml ? "true" : "false");
    out += "},";
  }

  if (p.customConfigCount) {
    out += "\"customConfig\":[";
    for (uint8_t i = 0; i < p.customConfigCount; i++) {
      if (i) out += ',';
      writeCustomConfigDefJson(out, p.customConfig[i]);
    }
    out += "],";
  }

  if (p.plan[0]) {
    out += "\"plan\":"; out += p.plan; out += ',';
  }

  if (p.eventSeq) {
    out += "\"evtSeq\":"; out += String(p.eventSeq); out += ',';
    out += "\"evtMsg\":\""; appendJsonEscaped(out, p.eventMsg); out += "\",";
  }

  out += "\"lastSeenMs\":"; out += String(p.lastSeenMs);
  out += '}';
}

void EscapeComponent::handleStatus() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");

  String json;
  json.reserve(256 + (_peerCount + _componentCount) * (700 + EscapeConfig::MAX_PLAN_LEN)); // +MAX_PLAN_LEN: optionaler roher Ablaufplan-Slice pro Eintrag
  json += '[';

  for (uint8_t i = 0; i < _componentCount; i++) {
    if (i) json += ',';
    PeerInfo self;
    fillComponentPeer(self, i);
    writePeerJson(json, self);
  }

  for (size_t i = 0; i < _peerCount; i++) {
    if (_componentCount || i) json += ',';
    writePeerJson(json, _peers[i]);
  }
  json += ']';

  _server.send(200, "application/json", json);
}

// ---- Authentifizierung / CORS ------------------------------------------------

bool EscapeComponent::checkAuth() {
  String token = _server.header("X-Auth-Token");
  return constantTimeEquals(token, EscapeConfig::AUTH_TOKEN);
}

void EscapeComponent::sendCorsPreflight() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  _server.sendHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  _server.sendHeader("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token");
  _server.send(204);
}

// ---- /action -------------------------------------------------------------------

void EscapeComponent::handleAction() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }

  StaticJsonDocument<256> doc;
  if (deserializeJson(doc, _server.arg("plain"))) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }
  // "id" waehlt die Ziel-Komponente auf diesem Board aus (siehe addComponent());
  // fehlt es, wird Komponente 0 angenommen (Rueckwaertskompatibel zu Boards mit
  // nur einer Komponente).
  uint8_t id = doc["id"] | 0;
  if (id >= _componentCount) {
    _server.send(400, "application/json", "{\"error\":\"invalid id\"}");
    return;
  }
  const char *action = doc["action"] | "";
  if (!*action || strlen(action) > EscapeConfig::MAX_ACTION_LEN) {
    _server.send(400, "application/json", "{\"error\":\"invalid action\"}");
    return;
  }

  ActionHandler &handler = _components[id].actionHandler;
  bool ok = handler ? handler(String(action)) : false;
  if (ok) pushEvent(id, String("Aktion \"") + action + "\" ausgefuehrt");
  markDirty(); // Zustand hat sich moeglicherweise geaendert -> zeitnah neu broadcasten
  _server.send(ok ? 200 : 422, "application/json", ok ? "{\"ok\":true}" : "{\"ok\":false}");
}

// ---- /config -------------------------------------------------------------------

void EscapeComponent::handleConfig() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }

  // Groesser als noetig fuer nur name/room: erlaubt zusaetzlich ein "config"-
  // Objekt mit mehreren Custom-Konfigurationswerten in derselben Anfrage.
  StaticJsonDocument<640> doc;
  if (deserializeJson(doc, _server.arg("plain"))) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }
  // "id" waehlt die Ziel-Komponente auf diesem Board aus (siehe addComponent());
  // fehlt es, wird Komponente 0 angenommen (Rueckwaertskompatibel zu Boards mit
  // nur einer Komponente). Damit koennen zwei Komponenten desselben Boards
  // unabhaengig voneinander umbenannt/anderen Raeumen zugeordnet werden.
  uint8_t id = doc["id"] | 0;
  if (id >= _componentCount) {
    _server.send(400, "application/json", "{\"error\":\"invalid id\"}");
    return;
  }
  LocalComponent &c = _components[id];

  const char *name = doc["name"] | "";
  const char *room = doc["room"] | "";
  bool identityGiven = *name || *room;
  if (identityGiven &&
      (!*name || !*room || strlen(name) > EscapeConfig::MAX_NAME_LEN || strlen(room) > EscapeConfig::MAX_ROOM_LEN)) {
    _server.send(400, "application/json", "{\"error\":\"invalid name/room\"}");
    return;
  }

  JsonObject customCfg = doc["config"];
  bool customCfgApplied = false;
  if (!customCfg.isNull()) {
    if (!c.customConfigCb) {
      _server.send(400, "application/json", "{\"error\":\"component has no custom config\"}");
      return;
    }
    CustomConfigDef defs[EscapeConfig::MAX_CUSTOM_CONFIGS];
    size_t n = c.customConfigCb(defs, EscapeConfig::MAX_CUSTOM_CONFIGS);

    // Erst alle Werte gegen das deklarierte Schema validieren, dann erst
    // anwenden - vermeidet Teilanwendung bei einer ungueltigen Anfrage.
    for (JsonPair kv : customCfg) {
      const CustomConfigDef *def = findCustomConfigDef(defs, n, kv.key().c_str());
      String value = kv.value().as<String>();
      if (!def || !validateCustomConfigValue(*def, value)) {
        _server.send(400, "application/json", "{\"error\":\"invalid config value\"}");
        return;
      }
    }
    if (c.customConfigSetCb) {
      for (JsonPair kv : customCfg) {
        c.customConfigSetCb(String(kv.key().c_str()), kv.value().as<String>());
      }
    }
    customCfgApplied = true;
  }

  if (identityGiven) saveIdentity(id, name, room);

  String eventMsg;
  if (customCfgApplied) eventMsg += "Konfiguration geaendert";
  if (identityGiven) {
    if (eventMsg.length()) eventMsg += ", ";
    eventMsg += "Name/Raum geaendert";
  }
  if (eventMsg.length()) pushEvent(id, eventMsg);

  markDirty();
  _server.send(200, "application/json", "{\"ok\":true}");
}

// ---- /plan (Ablaufplan-Slice EINER Komponente) ----------------------------------

void EscapeComponent::handlePlan() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }
  String body = _server.arg("plain");
  if (body.length() > EscapeConfig::MAX_PLAN_LEN + 256) {
    _server.send(413, "application/json", "{\"error\":\"plan too large\"}");
    return;
  }

  DynamicJsonDocument doc(body.length() * 2 + 256);
  if (deserializeJson(doc, body)) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }
  // "id" waehlt die Ziel-Komponente auf diesem Board aus (siehe addComponent()).
  uint8_t id = doc["id"] | 0;
  if (id >= _componentCount) {
    _server.send(400, "application/json", "{\"error\":\"invalid id\"}");
    return;
  }

  LocalComponent &c = _components[id];
  if (doc["plan"].isNull()) {
    c.plan[0] = '\0'; // "plan":null loescht die Zuordnung dieser Komponente wieder
  } else {
    String planStr;
    serializeJson(doc["plan"], planStr);
    if (planStr.length() > EscapeConfig::MAX_PLAN_LEN) {
      _server.send(413, "application/json", "{\"error\":\"plan too large\"}");
      return;
    }
    copyBounded(c.plan, sizeof(c.plan), planStr.c_str());
  }

  String planKey = "plan" + String(id);
  _prefs.begin("escfg", false);
  _prefs.putString(planKey.c_str(), c.plan);
  _prefs.end();

  pushEvent(id, doc["plan"].isNull() ? "Ablaufplan-Zuordnung entfernt" : "Ablaufplan aktualisiert");
  markDirty(); // Slice ist Teil des naechsten Broadcasts (siehe sendBroadcast())
  _server.send(200, "application/json", "{\"ok\":true}");
}

// ---- /plan-skeleton(.json) (geraeteweite Ebenen/Lanes/Dummies/Variablen) --------

void EscapeComponent::handlePlanSkeletonGet() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  _server.send(200, "application/json", _planSkeleton.length() ? _planSkeleton : String("{}"));
}

void EscapeComponent::handlePlanSkeletonPost() {
  _server.sendHeader("Access-Control-Allow-Origin", "*");
  if (!checkAuth()) {
    _server.send(401, "application/json", "{\"error\":\"unauthorized\"}");
    return;
  }
  if (!_server.hasArg("plain")) {
    _server.send(400, "application/json", "{\"error\":\"missing body\"}");
    return;
  }
  String body = _server.arg("plain");
  if (body.length() > EscapeConfig::MAX_PLAN_SKELETON_LEN) {
    _server.send(413, "application/json", "{\"error\":\"skeleton too large\"}");
    return;
  }
  // Nur auf gueltiges JSON pruefen - der Inhalt (Ebenen/Lanes/...) ist fuer die
  // Firmware bedeutungslos, sie speichert/liefert ihn nur unveraendert.
  DynamicJsonDocument doc(body.length() * 2 + 256);
  if (deserializeJson(doc, body)) {
    _server.send(400, "application/json", "{\"error\":\"invalid json\"}");
    return;
  }

  _prefs.begin("escfg", false);
  _prefs.putString("planskel", body);
  _prefs.end();
  _planSkeleton = body;

  // Betrifft den ganzen Raum (alle lokalen Komponenten dieses Boards) - jede
  // von ihnen bekommt daher eine eigene Aktivitaets-Meldung, damit Manager,
  // die eine andere Komponente desselben Raums beobachten, es ebenfalls sehen.
  for (uint8_t i = 0; i < _componentCount; i++) pushEvent(i, "Raum-Ablaufplan aktualisiert");

  _server.send(200, "application/json", "{\"ok\":true}");
}
