#pragma once

// EscapeComponent: wiederverwendbare Firmware-Bibliothek fuer eine einzelne
// Escape-Room-Komponente (ESP32, Arduino-Framework/PlatformIO).
//
// Diese Datei ist bewusst nur noch eine DUENNE FASSADE, die zwei fachlich
// getrennte Bausteine zusammenfuehrt:
//   - HardwareEsp32.hpp/.cpp: WLAN-Verbindung, UDP-Sockets, HTTP-Server,
//     NVS-Persistenz, mDNS - alles Hardware-/Arduino-spezifisch.
//   - Protocol.hpp/.cpp:      JSON-Wire-Format, Validierung, Peer-Tabelle,
//     Anfragebehandlung (/action, /plan-action, /config, /plan,
//     /plan-skeleton) - komplett
//     plattformunabhaengig und IDENTISCH von Sim/escape_component_sim.cpp
//     wiederverwendet. Aendert sich das Protokoll, reicht eine Aenderung dort.
//
// Ein neues Geraet braucht i.d.R. NUR Aenderungen in EscapeConfig.hpp
// (WLAN-Zugangsdaten, Auth-Token, Timings) sowie die Registrierung eigener
// Callbacks im Hauptskript (Sensordaten, Aktions-Logik) ueber die on*()-
// Methoden unten - die OEFFENTLICHE Schnittstelle von EscapeComponent ist
// durch diese Aufteilung UNVERAENDERT geblieben.

#include "../protocol/EscapeConfig.hpp"
#include "../esp/HardwareEsp32.hpp"
#include "../protocol/Protocol.hpp"

#include <Arduino.h>
#include <functional>

// Rueckwaertskompatible Alias-Namen: das Protokoll-Datenmodell lebt jetzt in
// EscapeProtocol (siehe Protocol.hpp), aber Code, der gegen die bisherige
// (unqualifizierte) client.hpp-Schnittstelle geschrieben wurde - z.B. eigene
// onCustomConfig()-Callbacks, die einen "CustomConfigDef" befuellen - soll
// unveraendert weiterkompilieren.
using CustomConfigDef = EscapeProtocol::CustomConfigDef;
using CustomConfigType = EscapeProtocol::CustomConfigType;
using PlanAction = EscapeProtocol::PlanAction;

// Callback-Typen, ueber die das geraetespezifische Hauptskript seine Sensorik
// und Spiellogik anbindet, ohne das Netzwerk-/Broadcast-Verhalten anzufassen.
using BatteryProvider = std::function<int8_t()>; // -1 = unbekannt/Netzbetrieb
using StringListProvider = std::function<size_t(String out[], size_t maxCount)>;
using FeedProvider = std::function<String()>;
using TipProvider = std::function<String()>;
using PuzzleProvider = std::function<void(uint16_t &step, uint16_t &totalSteps, String &state, bool &isHtml)>;
using ActionHandler = std::function<bool(const String &action)>; // true = ausgefuehrt/ok
using PlanActionHandler = std::function<bool(PlanAction action)>;
// Liefert die aktuelle Liste eigener Custom-Konfigurationsfelder (Schema +
// aktueller Wert) fuer Broadcast/status.json.
using CustomConfigProvider = std::function<size_t(CustomConfigDef out[], size_t maxCount)>;
// Wird pro Schluessel aufgerufen, nachdem ein per POST /config eingegangener
// Wert bereits gegen das eigene Schema validiert wurde (siehe Protocol.cpp).
using CustomConfigSetHandler = std::function<bool(const String &key, const String &value)>;

// Zustand + Callbacks EINER lokalen Raetsel-Komponente auf diesem Board (siehe
// EscapeComponent::addComponent()). Ein Board mit mehreren Komponenten haelt
// mehrere Instanzen davon; Netzwerk/HTTP/Batterie bleiben geraeteweit geteilt.
// Ausschliesslich feste Puffer (keine String-Felder) fuer die dauerhaft
// gehaltenen Werte - vermeidet Heap-Fragmentierung ueber lange Laufzeiten
// (die Callback-SIGNATUREN oben duerfen trotzdem String verwenden, das sind
// nur kurzlebige Werte pro Aufruf).
struct LocalComponent {
  char uuid[EscapeConfig::MAX_UUID_LEN + 1] = {0};
  char name[EscapeConfig::MAX_NAME_LEN + 1] = {0};
  char room[EscapeConfig::MAX_ROOM_LEN + 1] = {0};
  // Roher JSON-Ablaufplan-Slice dieser Komponente (Lane-Zuordnung + eigene
  // Verbindungen), von Manager/manager.html verwaltet - leer = nicht zugeordnet.
  char plan[EscapeConfig::MAX_PLAN_LEN + 1] = {0};
  // Aktivitaets-Benachrichtigung dieser Komponente, siehe EscapeComponent::pushEvent().
  uint32_t eventSeq = 0;
  char eventMsg[EscapeConfig::MAX_EVENT_MSG_LEN + 1] = {0};
  StringListProvider errorsCb;
  StringListProvider actionsCb;
  FeedProvider feedCb;
  TipProvider tipCb;
  PuzzleProvider puzzleCb;
  ActionHandler actionHandler;
  PlanActionHandler planActionHandler;
  CustomConfigProvider customConfigCb;
  CustomConfigSetHandler customConfigSetCb;
};

class EscapeComponent {
public:
  // WLAN verbinden, UDP + HTTP-Server starten. addComponent() muss vorher
  // (in setup(), vor begin()) fuer jede Raetsel-Komponente des Boards
  // aufgerufen worden sein.
  void begin();

  // Muss regelmaessig (jeden loop()-Durchlauf, nicht blockierend) aufgerufen
  // werden: bedient HTTP-Anfragen, verarbeitet eingehende Broadcasts, sendet
  // eigene Broadcasts nach Zeitplan/bei Aenderung, raeumt veraltete Peers auf.
  void loop();

  // Vom Hauptskript aufrufen, wenn sich ein sicherbarer Zustand geaendert hat
  // (z.B. Raetsel-Schritt, neuer Fehler). Loest einen zeitnahen, aber auf
  // EscapeConfig::CHANGE_MIN_GAP_MS begrenzten Broadcast aus statt auf den
  // naechsten regulaeren Heartbeat zu warten.
  void markDirty();

  // Registriert eine neue lokale Raetsel-Komponente (Default-Identitaet, aus
  // NVS ueberschrieben falls dort bereits gespeichert) und liefert deren
  // stabile Komponenten-ID (0-basiert, in Aufrufreihenfolge) fuer die
  // folgenden on*(id, ...)-Aufrufe zurueck. Muss vor begin() erfolgen. Ab dem
  // (MAX_LOCAL_COMPONENTS+1)-ten Aufruf wird die letzte gueltige ID erneut
  // zurueckgegeben (Kapazitaet ist zur Compile-/Bootzeit fest).
  uint8_t addComponent(const String &defaultName, const String &defaultRoom);

  // Batterie ist geraeteweit (ein physischer Akku pro Board), daher ohne
  // Komponenten-ID - gilt fuer alle per addComponent() angemeldeten Komponenten.
  void onBattery(BatteryProvider cb);

  // Alle uebrigen Callbacks sind pro Komponente - id kommt von addComponent().
  void onErrors(uint8_t id, StringListProvider cb);
  void onActions(uint8_t id, StringListProvider cb);
  void onFeed(uint8_t id, FeedProvider cb);
  // Liefert einen optionalen Klartext-Hinweis, den der Manager den Spielern
  // bei Bedarf vorlesen kann. Ein leerer String blendet den Hinweis aus.
  void onTip(uint8_t id, TipProvider cb);
  void onPuzzle(uint8_t id, PuzzleProvider cb);
  void onAction(uint8_t id, ActionHandler cb);
  // Explizite Ablaufplan-Steuerung, getrennt von frei benannten Aktionen.
  // Ein registrierter Handler kuendigt reset+complete als planActions an.
  void onPlanAction(uint8_t id, PlanActionHandler cb);
  void onCustomConfig(uint8_t id, CustomConfigProvider cb);
  void onCustomConfigSet(uint8_t id, CustomConfigSetHandler cb);

  const char *name(uint8_t id) const { return id < _componentCount ? _components[id].name : ""; }
  const char *room(uint8_t id) const { return id < _componentCount ? _components[id].room : ""; }
  const char *uuid(uint8_t id) const { return id < _componentCount ? _components[id].uuid : ""; }
  uint8_t componentCount() const { return _componentCount; }

private:
  // Bindet die on*()-Callbacks/LocalComponent-Daten dieser EscapeComponent-
  // Instanz an die plattformunabhaengige EscapeProtocol::ProtocolAdapter-
  // Schnittstelle an (siehe Protocol.hpp) - das Gegenstueck zu
  // SimProtocolAdapter in sim/escape_component_sim.cpp. Als PRIVATE geschachtelte
  // Klasse (statt EscapeComponent selbst von ProtocolAdapter erben zu lassen),
  // damit EscapeComponent nach aussen kein Protocol.hpp-Interna preisgibt.
  class Host : public EscapeProtocol::ProtocolAdapter {
  public:
    explicit Host(EscapeComponent &owner) : owner_(owner) {}
    uint8_t componentCount() const override { return owner_._componentCount; }
    int8_t battery() const override { return owner_._batteryCb ? owner_._batteryCb() : -1; }
    uint32_t upTimeMs() const override { return owner_._hw.nowMs(); }
    bool isSlave() const override { return owner_._slave; }
    void setSlave(bool slave) override { owner_.setSlave(slave); }
    void identity(uint8_t index, std::string &name, std::string &room) const override;
    void snapshot(uint8_t index, EscapeProtocol::PeerInfo &out) const override;
    bool applyAction(uint8_t index, const std::string &action) override;
    bool applyPlanAction(uint8_t index, EscapeProtocol::PlanAction action) override;
    void setIdentity(uint8_t index, const std::string &name, const std::string &room) override;
    void customConfigDefs(uint8_t index, std::vector<EscapeProtocol::CustomConfigDef> &out) const override;
    bool setCustomConfigValue(uint8_t index, const std::string &key, const std::string &value) override;
    void setPlan(uint8_t index, const std::string &planJson) override;
    void pushEvent(uint8_t index, const std::string &msg) override;
    void markDirty() override { owner_.markDirty(); }

  private:
    EscapeComponent &owner_;
  };

  HardwareEsp32 _hw;
  EscapeProtocol::PeerTable _peers;
  Host _host{*this};

  LocalComponent _components[EscapeConfig::MAX_LOCAL_COMPONENTS];
  uint8_t _componentCount = 0;

  BatteryProvider _batteryCb;

  // Geraeteweite Sammlung aller Ablaufplan-Skeletons der Raeume, denen lokale
  // Komponenten angehoeren - siehe MAX_PLAN_SKELETON_STORAGE_LEN.
  String _planSkeleton;

  // Geraeteweite "Slave"-Rolle (siehe EscapeProtocol::shouldAdoptFromPeer()),
  // in NVS unter "slave" persistiert.
  bool _slave = false;

  bool _dirty = false;
  uint32_t _lastBroadcastMs = 0;
  uint32_t _lastExpireCheckMs = 0;
  uint32_t _lastReconcileMs = 0;
  uint32_t _udpAuthWindowStartMs = 0;
  uint8_t _udpAuthCount = 0;

  void loadIdentity(uint8_t id, const String &defaultName, const String &defaultRoom);
  void saveIdentity(uint8_t id, const String &name, const String &room);
  void loadPlanSkeleton();
  void loadSlave();
  void setSlave(bool slave);
  // Prueft periodisch (EscapeConfig::RECONCILE_INTERVAL_MS), ob eigene
  // Persistenz (Plan-Skeleton/CustomConfig/Plan-Slice) von einem laenger
  // laufenden Peer uebernommen werden sollte - siehe loop().
  void reconcileWithPeers();
  // Muss NACH HardwareEsp32::initWifiInterface() aufgerufen werden (MAC-Adresse
  // ist vorher ggf. nicht verfuegbar) - siehe begin().
  void resolveUuid(uint8_t id);

  // Fuellt eine vollstaendige PeerInfo-Momentaufnahme der Komponente "id"
  // (Fehler/Aktionen/Feed/Tipp/Raetsel/CustomConfig ueber die jeweiligen Callbacks
  // abfragen) - Grundlage fuer Broadcast/status.json, siehe Host::snapshot().
  void fillSnapshot(uint8_t id, EscapeProtocol::PeerInfo &out) const;
  void setPlanInternal(uint8_t id, const std::string &planJson);
  // Erhoeht den Aktivitaets-Zaehler einer lokalen Komponente und setzt deren
  // Klartext-Meldung - loest per markDirty() einen zeitnahen Broadcast aus,
  // damit andere Manager es zuegig sehen.
  void pushEvent(uint8_t id, const String &msg);
};
