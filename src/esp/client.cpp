// Implementierung von EscapeComponent (siehe client.hpp).
//
// Enthaelt NUR noch die Verdrahtung zwischen HardwareEsp32 (Netzwerk/NVS) und
// EscapeProtocol (JSON/Validierung/Peer-Tabelle/Anfragebehandlung) sowie die
// Verwaltung der eigenen LocalComponent-Callbacks - keine Protokoll- oder
// Hardware-Details mehr direkt in dieser Datei (siehe HardwareEsp32.cpp bzw.
// Protocol.cpp).

#include "client.hpp"

void EscapeComponent::begin() {
  _hw.initWifiInterface();
  if (!_hw.initNvsSafely()) {
    return;
  }
  _hw.beginSecurity();
  for (uint8_t i = 0; i < _componentCount; i++) resolveUuid(i);

  _hw.connectWifi();
  std::string deviceName = _hw.loadString("device_name", "");
  if (deviceName.empty()) {
    deviceName = "EscapeManager";
    _hw.saveString("device_name", deviceName);
  }
  Serial.printf("EscapeManager: device_name=%s\n", deviceName.c_str());

  if (EscapeConfig::AUTHENTICATE_GET_REQUESTS) {
    _hw.onAuthenticatedGet("/status.json", [this]() {
      _changeLock.noteStatusFetched();
      return EscapeProtocol::HttpResult{200, EscapeProtocol::buildStatusJson(_host, _hw.localIp(), _hw.nowMs())};
    });
    _hw.onAuthenticatedGet("/peers.json", [this]() {
      return EscapeProtocol::HttpResult{200, EscapeProtocol::buildPeersJson(_peers)};
    });
    _hw.onAuthenticatedGet("/plan-skeleton.json", [this]() {
      _changeLock.notePlanSkeletonFetched();
      return EscapeProtocol::handlePlanSkeletonGetRequest(std::string(_planSkeleton.c_str()));
    });
  } else {
    _hw.onGet("/status.json", [this]() {
      _changeLock.noteStatusFetched();
      return EscapeProtocol::HttpResult{200, EscapeProtocol::buildStatusJson(_host, _hw.localIp(), _hw.nowMs())};
    });
    _hw.onGet("/peers.json", [this]() {
      return EscapeProtocol::HttpResult{200, EscapeProtocol::buildPeersJson(_peers)};
    });
    _hw.onGet("/plan-skeleton.json", [this]() {
      _changeLock.notePlanSkeletonFetched();
      return EscapeProtocol::handlePlanSkeletonGetRequest(std::string(_planSkeleton.c_str()));
    });
  }
  _hw.onGet("/security.json", [this]() {
    return EscapeProtocol::HttpResult{_hw.securityReady() ? 200 : 503, _hw.securityDocument()};
  });
  _hw.onPost("/action", [this](const EscapeProtocol::HttpRequest &req) {
    if (_changeLock.isLocked(EscapeProtocol::MutationType::Action)) {
      return EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"};
    }
    EscapeProtocol::HttpResult r = EscapeProtocol::handleActionRequest(_host, req);
    if (r.status == 200) _changeLock.markChanged(EscapeProtocol::MutationType::Action);
    return r;
  });
  _hw.onPost("/plan-action", [this](const EscapeProtocol::HttpRequest &req) {
    if (_changeLock.isLocked(EscapeProtocol::MutationType::PlanAction)) {
      return EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"};
    }
    EscapeProtocol::HttpResult r = EscapeProtocol::handlePlanActionRequest(_host, req);
    if (r.status == 200) _changeLock.markChanged(EscapeProtocol::MutationType::PlanAction);
    return r;
  });
  _hw.onPost("/config", [this](const EscapeProtocol::HttpRequest &req) {
    if (_changeLock.isLocked(EscapeProtocol::MutationType::Config)) {
      return EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"};
    }
    EscapeProtocol::HttpResult r = EscapeProtocol::handleConfigRequest(_host, req);
    if (r.status == 200) _changeLock.markChanged(EscapeProtocol::MutationType::Config);
    return r;
  });
  _hw.onPost("/plan", [this](const EscapeProtocol::HttpRequest &req) {
    if (_changeLock.isLocked(EscapeProtocol::MutationType::Plan)) {
      return EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"};
    }
    EscapeProtocol::HttpResult r = EscapeProtocol::handlePlanRequest(_host, req);
    if (r.status == 200) _changeLock.markChanged(EscapeProtocol::MutationType::Plan);
    return r;
  });
  _hw.onPost("/plan-skeleton", [this](const EscapeProtocol::HttpRequest &req) {
    if (_changeLock.isLocked(EscapeProtocol::MutationType::PlanSkeleton)) {
      return EscapeProtocol::HttpResult{409, "{\"error\":\"locked: previous change not yet fetched\"}"};
    }
    std::string storage(_planSkeleton.c_str());
    EscapeProtocol::HttpResult r = EscapeProtocol::handlePlanSkeletonPostRequest(_host, req, storage);
    if (r.status == 200) {
      _planSkeleton = storage.c_str();
      _hw.saveBlob("planskel", storage);
      _changeLock.markChanged(EscapeProtocol::MutationType::PlanSkeleton);
    }
    return r;
  });
  _hw.serveManagerHtml();
  _hw.beginHttpServer();

  loadPlanSkeleton();
  loadSlave();
  _hw.beginMdns();
}

void EscapeComponent::loop() {
  _hw.handleHttpClients();
  _hw.pollIncoming(5, [this](const std::string &payload, const std::string &senderIp) {
    uint32_t now = _hw.nowMs();
    if (now - _udpAuthWindowStartMs >= 1000) {
      _udpAuthWindowStartMs = now;
      _udpAuthCount = 0;
    }
    if (_udpAuthCount >= 16) return;
    _udpAuthCount++;
    std::string authenticatedPayload;
    if (_hw.unprotectDocument("udp-broadcast-v1", payload, authenticatedPayload)) {
      EscapeProtocol::ingestPeerAnnouncement(authenticatedPayload, senderIp, _hw.localIp(), now, _peers);
    }
  });

  uint32_t now = _hw.nowMs();
  uint32_t interval = EscapeConfig::HEARTBEAT_INTERVAL_MS + _hw.jitterOffsetMs();
  bool heartbeatDue = EscapeProtocol::isHeartbeatDue(now, _lastBroadcastMs, interval);
  bool changeDue = EscapeProtocol::isChangeBroadcastDue(now, _lastBroadcastMs, _dirty);

  if (heartbeatDue || changeDue) {
    std::string payload = EscapeProtocol::buildPeerAnnouncementJson(EscapeConfig::HTTP_PORT,
        _changeLock.hasUnseenStatusChange(), _changeLock.hasUnseenPlanSkeletonChange());
    std::string authenticatedPayload;
    if (_hw.protectDocument("udp-broadcast-v1", payload, authenticatedPayload)) {
      _hw.sendBroadcast(authenticatedPayload);
    }
    _lastBroadcastMs = now;
    _dirty = false;
  }

  // Nicht jeden loop()-Durchlauf pruefen: Aufraeumen ist unkritisch in seiner
  // Genauigkeit und muss keine CPU-Zeit auf jedem Zyklus kosten.
  if (now - _lastExpireCheckMs >= 2000) {
    _peers.expireStale(now);
    _lastExpireCheckMs = now;
  }

  // Ebenfalls gedrosselt (siehe EscapeConfig::RECONCILE_INTERVAL_MS): kann bis
  // zu zwei blockierende HTTP-Anfragen an einen Peer ausloesen (Status- und
  // ggf. Plan-Skeleton-Abgleich).
  if (EscapeProtocol::isHeartbeatDue(now, _lastReconcileMs, EscapeConfig::RECONCILE_INTERVAL_MS)) {
    _lastReconcileMs = now;
    reconcileWithPeers();
  }
}

void EscapeComponent::markDirty() { _dirty = true; }

void EscapeComponent::pushEvent(uint8_t id, const String &msg) {
  if (id >= _componentCount) return;
  LocalComponent &c = _components[id];
  c.eventSeq++;
  EscapeProtocol::copyBounded(c.eventMsg, sizeof(c.eventMsg), msg.c_str());
  markDirty();
}

uint8_t EscapeComponent::addComponent(const String &defaultName, const String &defaultRoom, const String &defaultRiddleId) {
  if (_componentCount >= EscapeConfig::MAX_LOCAL_COMPONENTS) {
    // Kapazitaet erschoepft: liefert die letzte gueltige ID erneut statt eines
    // Fehlercodes, damit ein Aufrufer ohne Rueckgabewertpruefung nicht
    // versehentlich ausserhalb des _components-Arrays schreibt.
    return EscapeConfig::MAX_LOCAL_COMPONENTS - 1;
  }
  uint8_t id = _componentCount++;
  loadIdentity(id, defaultName, defaultRoom);
  // Braucht keine MAC/kein WLAN (esp_random()-basiert), daher schon hier
  // statt erst in begin() aufloesbar - siehe resolveRiddleId().
  resolveRiddleId(id, defaultRiddleId);
  return id;
}

void EscapeComponent::onBattery(BatteryProvider cb) { _batteryCb = cb; }
void EscapeComponent::onErrors(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].errorsCb = cb; }
void EscapeComponent::onActions(uint8_t id, StringListProvider cb) { if (id < _componentCount) _components[id].actionsCb = cb; }
void EscapeComponent::onFeed(uint8_t id, FeedProvider cb) { if (id < _componentCount) _components[id].feedCb = cb; }
void EscapeComponent::onTip(uint8_t id, TipProvider cb) { if (id < _componentCount) _components[id].tipCb = cb; }
void EscapeComponent::onPuzzle(uint8_t id, PuzzleProvider cb) { if (id < _componentCount) _components[id].puzzleCb = cb; }
void EscapeComponent::onAction(uint8_t id, ActionHandler cb) { if (id < _componentCount) _components[id].actionHandler = cb; }
void EscapeComponent::onPlanAction(uint8_t id, PlanActionHandler cb) { if (id < _componentCount) _components[id].planActionHandler = cb; }
void EscapeComponent::onCustomConfig(uint8_t id, CustomConfigProvider cb) { if (id < _componentCount) _components[id].customConfigCb = cb; }
void EscapeComponent::onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb) { if (id < _componentCount) _components[id].customConfigSetCb = cb; }

// ---- Identitaet (NVS via HardwareEsp32) --------------------------------------
// Jede Komponente bekommt eigene NVS-Schluessel (name0/room0, name1/room1, ...),
// damit mehrere Komponenten auf demselben Board unabhaengig konfiguriert und
// persistiert werden koennen.

void EscapeComponent::loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom) {
  String nameKey = "name" + String(id);
  String roomKey = "room" + String(id);
  String planKey = "plan" + String(id);
  std::string n = _hw.loadString(nameKey.c_str(), std::string(defaultName.c_str()));
  std::string r = _hw.loadString(roomKey.c_str(), std::string(defaultRoom.c_str()));
  std::string p = _hw.loadString(planKey.c_str(), "");
  EscapeProtocol::copyBounded(_components[id].name, sizeof(_components[id].name), n.c_str());
  EscapeProtocol::copyBounded(_components[id].room, sizeof(_components[id].room), r.c_str());
  EscapeProtocol::copyBounded(_components[id].plan, sizeof(_components[id].plan), p.c_str());
}

void EscapeComponent::resolveUuid(uint8_t id) {
  String uuidKey = "uuid" + String(id);
  std::string u = _hw.loadString(uuidKey.c_str(), "");
  if (u.empty()) {
    // Noch nichts gespeichert: von der MAC-Adresse ableiten und dauerhaft
    // persistieren (ein spaeter manuell in NVS gesetzter Wert haette dank
    // dieser Pruefung Vorrang) - siehe HardwareEsp32::macBasedUuid().
    std::string generated = _hw.macBasedUuid(id);
    _hw.saveString(uuidKey.c_str(), generated);
    EscapeProtocol::copyBounded(_components[id].uuid, sizeof(_components[id].uuid), generated.c_str());
  } else {
    EscapeProtocol::copyBounded(_components[id].uuid, sizeof(_components[id].uuid), u.c_str());
  }
}

void EscapeComponent::resolveRiddleId(uint8_t id, const String &defaultRiddleId) {
  String riddleKey = "riddle" + String(id);
  std::string r = _hw.loadString(riddleKey.c_str(), "");
  if (r.empty()) {
    // Noch nichts gespeichert/manuell gesetzt: die vom Sketch vorgegebene
    // riddleId uebernehmen (alle Geraete desselben Raetseltyps teilen sich
    // damit automatisch dieselbe ID), sonst zufaellig erzeugen (siehe
    // HardwareEsp32::randomRiddleId() - bewusst NICHT von der MAC
    // abgeleitet, damit ein Ersatzgeraet spaeter per POST /config auf
    // denselben Wert wie das Original gesetzt werden kann).
    std::string value = defaultRiddleId.length() ? std::string(defaultRiddleId.c_str()) : _hw.randomRiddleId();
    _hw.saveString(riddleKey.c_str(), value);
    EscapeProtocol::copyBounded(_components[id].riddleId, sizeof(_components[id].riddleId), value.c_str());
  } else {
    EscapeProtocol::copyBounded(_components[id].riddleId, sizeof(_components[id].riddleId), r.c_str());
  }
}

void EscapeComponent::saveIdentity(uint8_t id, const String &name, const String &room) {
  String nameKey = "name" + String(id);
  String roomKey = "room" + String(id);
  _hw.saveString(nameKey.c_str(), std::string(name.c_str()));
  _hw.saveString(roomKey.c_str(), std::string(room.c_str()));
  EscapeProtocol::copyBounded(_components[id].name, sizeof(_components[id].name), name.c_str());
  EscapeProtocol::copyBounded(_components[id].room, sizeof(_components[id].room), room.c_str());
}

void EscapeComponent::loadPlanSkeleton() {
  // Geraeteweite Sammlung, intern nach Raum getrennt.
  std::string storage = _hw.loadBlob("planskel", "");
  if (storage.empty()) storage = _hw.loadString("planskel", ""); // Legacy-Migration
  _planSkeleton = storage.c_str();
}

void EscapeComponent::loadSlave() {
  _slave = _hw.loadString("slave", "0") == "1";
}

void EscapeComponent::setSlave(bool slave) {
  _slave = slave;
  _hw.saveString("slave", slave ? "1" : "0");
}

void EscapeComponent::reconcileWithPeers() {
  // Frueher stand der volle Zustand aller Peers schon aus dem Broadcast im
  // RAM; jetzt kennt dieses Geraet nur noch IP+Port bekannter Peers (siehe
  // _peers) und muss den Zustand EINES Kandidaten aktiv per HTTP abfragen -
  // ein Rundlauf-Index sorgt dafuer, dass ueber mehrere Takte hinweg alle
  // bekannten Peers an die Reihe kommen.
  size_t peerCount = _peers.count();
  if (peerCount == 0) return;
  if (_reconcileCursor >= peerCount) _reconcileCursor = 0;
  const EscapeProtocol::PeerAddress &candidate = _peers.at(_reconcileCursor);
  _reconcileCursor++;

  std::string statusBody;
  if (!_hw.httpGet(candidate.ip, candidate.httpPort, "/status.json", statusBody)) return;

  // "static" statt Stack-lokal: sizeof(PeerTable) liegt bei ~16 KB (4 x
  // PeerInfo je ~4 KB) - das ist MEHR als der komplette 8 KB grosse
  // loopTask-Stack von Arduino-ESP32 (siehe ARDUINO_LOOP_STACK_SIZE in
  // main.cpp des Frameworks), also ein garantierter Stack-Overflow, sobald
  // ueberhaupt ein Peer bekannt ist (peerCount==0 wurde oben schon
  // rausgefiltert). "static" legt den Speicher stattdessen einmalig im
  // BSS an; clear() vor jeder Benutzung stellt sicher, dass keine
  // Eintraege vom vorherigen Abgleichstakt (evtl. anderer Peer) uebrig
  // bleiben - ingestStatusJson()/parseComponentIntoPeer() ueberschreiben
  // ohnehin jedes Feld eines (wieder-)benutzten Slots vollstaendig.
  static EscapeProtocol::PeerTable candidatePeers;
  candidatePeers.clear();
  EscapeProtocol::ingestStatusJson(statusBody, _hw.nowMs(), candidatePeers);

  const EscapeProtocol::PeerInfo *src = EscapeProtocol::findSkeletonSyncSource(_host, candidatePeers);
  if (!src) return;

  std::string skeletonBody;
  if (!_hw.httpGet(src->ip, src->httpPort, "/plan-skeleton.json", skeletonBody)) return;
  if (skeletonBody.empty()) return;

  std::string mergedStorage;
  if (!EscapeProtocol::mergePlanSkeletonStorage(
          std::string(_planSkeleton.c_str()), skeletonBody, mergedStorage) ||
      mergedStorage == std::string(_planSkeleton.c_str())) return;

  _planSkeleton = mergedStorage.c_str();
  _hw.saveBlob("planskel", mergedStorage);
  for (uint8_t i = 0; i < _componentCount; i++) {
    pushEvent(i, "Ablaufplan-Skeleton von laenger laufendem System uebernommen");
  }
}

void EscapeComponent::setPlanInternal(uint8_t id, const std::string &planJson) {
  if (id >= _componentCount) return;
  LocalComponent &c = _components[id];
  EscapeProtocol::copyBounded(c.plan, sizeof(c.plan), planJson.c_str());
  String planKey = "plan" + String(id);
  _hw.saveString(planKey.c_str(), std::string(c.plan));
}

// ---- Momentaufnahme einer Komponente (Broadcast/status.json) ----------------

void EscapeComponent::fillSnapshot(uint8_t id, EscapeProtocol::PeerInfo &out) const {
  const LocalComponent &c = _components[id];
  EscapeProtocol::copyBounded(out.uuid, sizeof(out.uuid), c.uuid);
  EscapeProtocol::copyBounded(out.riddleId, sizeof(out.riddleId), c.riddleId);
  EscapeProtocol::copyBounded(out.name, sizeof(out.name), c.name);
  EscapeProtocol::copyBounded(out.room, sizeof(out.room), c.room);
  EscapeProtocol::copyBounded(out.plan, sizeof(out.plan), c.plan);
  out.eventSeq = c.eventSeq;
  EscapeProtocol::copyBounded(out.eventMsg, sizeof(out.eventMsg), c.eventMsg);

  out.errorCount = 0;
  if (c.errorsCb) {
    String buf[EscapeConfig::MAX_ERRORS];
    size_t n = c.errorsCb(buf, EscapeConfig::MAX_ERRORS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ERRORS; i++) {
      EscapeProtocol::copyBounded(out.errors[i], sizeof(out.errors[0]), buf[i].c_str());
      out.errorCount++;
    }
  }

  out.actionCount = 0;
  if (c.actionsCb) {
    String buf[EscapeConfig::MAX_ACTIONS];
    size_t n = c.actionsCb(buf, EscapeConfig::MAX_ACTIONS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_ACTIONS; i++) {
      EscapeProtocol::copyBounded(out.actions[i], sizeof(out.actions[0]), buf[i].c_str());
      out.actionCount++;
    }
  }

  out.planActionMask = c.planActionHandler
      ? EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Reset) |
            EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Complete)
      : 0;

  if (c.feedCb) {
    String feed = c.feedCb();
    EscapeProtocol::copyBounded(out.feed, sizeof(out.feed), feed.c_str());
  } else {
    out.feed[0] = '\0';
  }

  if (c.tipCb) {
    String tip = c.tipCb();
    EscapeProtocol::copyBounded(out.tip, sizeof(out.tip), tip.c_str());
  } else {
    out.tip[0] = '\0';
  }

  out.puzzleTotalSteps = 0;
  if (c.puzzleCb) {
    uint16_t step = 0, total = 0;
    String state;
    bool isHtml = false;
    c.puzzleCb(step, total, state, isHtml);
    out.puzzleStep = step;
    out.puzzleTotalSteps = total;
    EscapeProtocol::copyBounded(out.puzzleState, sizeof(out.puzzleState), state.c_str());
    out.puzzleIsHtml = isHtml;
  } else {
    // Ohne Callback muessen ALLE Raetsel-Felder explizit zurueckgesetzt
    // werden (nicht nur puzzleTotalSteps oben) - sonst koennten bei
    // Wiederverwendung von "out" (siehe buildStatusJson: dort ggf. ein
    // "static" PeerInfo statt Stack-lokal) veraltete Werte einer VORHERIGEN
    // Komponente/Anfrage haengen bleiben. writeComponentJson() serialisiert
    // "puzzle" zwar nur bei puzzleTotalSteps>0, aber "feed"/"tip" oben pruefen
    // NUR das jeweilige Feld selbst - daher auch dort der explizite Reset.
    out.puzzleStep = 0;
    out.puzzleState[0] = '\0';
    out.puzzleIsHtml = false;
  }

  out.customConfigCount = 0;
  if (c.customConfigCb) {
    EscapeProtocol::CustomConfigDef defs[EscapeConfig::MAX_CUSTOM_CONFIGS];
    size_t n = c.customConfigCb(defs, EscapeConfig::MAX_CUSTOM_CONFIGS);
    for (size_t i = 0; i < n && i < EscapeConfig::MAX_CUSTOM_CONFIGS; i++) {
      out.customConfig[i] = defs[i];
      out.customConfigCount++;
    }
  }
}

// ---- EscapeComponent::Host (EscapeProtocol::ProtocolAdapter-Anbindung) ------

void EscapeComponent::Host::identity(uint8_t index, std::string &name, std::string &room) const {
  if (index >= owner_._componentCount) return;
  name = owner_._components[index].name;
  room = owner_._components[index].room;
}

void EscapeComponent::Host::snapshot(uint8_t index, EscapeProtocol::PeerInfo &out) const {
  if (index >= owner_._componentCount) return;
  owner_.fillSnapshot(index, out);
}

bool EscapeComponent::Host::applyAction(uint8_t index, const std::string &action) {
  if (index >= owner_._componentCount) return false;
  ActionHandler &handler = owner_._components[index].actionHandler;
  return handler ? handler(String(action.c_str())) : false;
}

bool EscapeComponent::Host::applyPlanAction(uint8_t index, EscapeProtocol::PlanAction action) {
  if (index >= owner_._componentCount) return false;
  PlanActionHandler &handler = owner_._components[index].planActionHandler;
  return handler ? handler(action) : false;
}

void EscapeComponent::Host::setIdentity(uint8_t index, const std::string &name, const std::string &room) {
  if (index >= owner_._componentCount) return;
  owner_.saveIdentity(index, String(name.c_str()), String(room.c_str()));
}

void EscapeComponent::Host::setRiddleId(uint8_t index, const std::string &riddleId) {
  if (index >= owner_._componentCount) return;
  String key = "riddle" + String(index);
  owner_._hw.saveString(key.c_str(), std::string(riddleId));
  EscapeProtocol::copyBounded(owner_._components[index].riddleId, sizeof(owner_._components[index].riddleId), riddleId.c_str());
}

void EscapeComponent::Host::customConfigDefs(uint8_t index, std::vector<EscapeProtocol::CustomConfigDef> &out) const {
  out.clear();
  if (index >= owner_._componentCount) return;
  CustomConfigProvider &cb = owner_._components[index].customConfigCb;
  if (!cb) return;
  EscapeProtocol::CustomConfigDef defs[EscapeConfig::MAX_CUSTOM_CONFIGS];
  size_t n = cb(defs, EscapeConfig::MAX_CUSTOM_CONFIGS);
  out.assign(defs, defs + (n < EscapeConfig::MAX_CUSTOM_CONFIGS ? n : EscapeConfig::MAX_CUSTOM_CONFIGS));
}

bool EscapeComponent::Host::setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) {
  if (index >= owner_._componentCount) return false;
  CustomConfigSetHandler &cb = owner_._components[index].customConfigSetCb;
  return cb ? cb(String(key.c_str()), String(value.c_str())) : false;
}

void EscapeComponent::Host::setPlan(uint8_t index, const std::string &planJson) {
  owner_.setPlanInternal(index, planJson);
}

void EscapeComponent::Host::pushEvent(uint8_t index, const std::string &msg) {
  owner_.pushEvent(index, String(msg.c_str()));
}
