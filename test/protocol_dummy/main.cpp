// Minimaler Selbsttest-Sketch fuer src/protocol/*: prueft NUR die reine,
// hardwarefreie Protokoll-/JSON-Logik (Json.cpp, Protocol.cpp) direkt auf
// echter ESP32-Hardware/Toolchain, OHNE WLAN/HTTP/ProtocolAdapter und ohne
// den restlichen Firmware-Code (esp/client.cpp usw.). Damit lassen sich
// Aenderungen an Protocol.hpp/.cpp bzw. Json.hpp/.cpp isoliert per
//   pio run -e protocol-dummy -t upload && pio device monitor
// gegen die tatsaechliche Ziel-Toolchain verifizieren (Endianness, Groessen
// von size_t/double, Rundungsverhalten etc. koennen vom PC abweichen), ohne
// dafuer die volle Firmware oder echte Hardware (Sensoren etc.) zu brauchen.
#include <Arduino.h>

#include "../../src/protocol/Json.hpp"
#include "../../src/protocol/Protocol.hpp"

namespace {

uint16_t g_passed = 0;
uint16_t g_failed = 0;

void check(bool condition, const char *name) {
  if (condition) {
    g_passed++;
    Serial.printf("[PASS] %s\n", name);
  } else {
    g_failed++;
    Serial.printf("[FAIL] %s\n", name);
  }
}

void testJsonRoundtrip() {
  EscapeJson::Value parsed;
  const bool ok = EscapeJson::parse(
      R"({"name":"Laser-1","battery":87,"active":true,"tags":["a","b"]})", parsed);
  check(ok, "Json::parse liefert true fuer gueltiges Objekt");
  check(parsed.find("name") != nullptr && parsed.find("name")->asString() == "Laser-1",
        "Json::parse liest String-Feld korrekt");
  check(parsed.find("battery") != nullptr && parsed.find("battery")->asNumber() == 87,
        "Json::parse liest Zahl-Feld korrekt");
  check(parsed.find("active") != nullptr && parsed.find("active")->asBool() == true,
        "Json::parse liest Bool-Feld korrekt");

  std::string out;
  EscapeJson::stringify(parsed, out);
  EscapeJson::Value reparsed;
  const bool reparsedOk = EscapeJson::parse(out, reparsed);
  check(reparsedOk, "Json::stringify-Ausgabe laesst sich erneut parsen");
  check(reparsed.find("name") != nullptr && reparsed.find("name")->asString() == "Laser-1",
        "Roundtrip erhaelt String-Feld");

  EscapeJson::Value invalid;
  check(!EscapeJson::parse("{invalid", invalid), "Json::parse liefert false fuer kaputtes JSON");
}

void testPlanAction() {
  check(std::string(EscapeProtocol::planActionName(EscapeProtocol::PlanAction::Reset)) == "reset",
        "planActionName(Reset) == \"reset\"");
  check(std::string(EscapeProtocol::planActionName(EscapeProtocol::PlanAction::Complete)) == "complete",
        "planActionName(Complete) == \"complete\"");
  check(EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Reset) !=
            EscapeProtocol::planActionBit(EscapeProtocol::PlanAction::Complete),
        "planActionBit() liefert fuer Reset/Complete unterschiedliche Bits");
}

void testPeerAddressTable() {
  // static: PeerAddressTable ist mit MAX_PEER_ADDRESSES=200 zu gross fuer den
  // 8 KiB loopTask-Stack (siehe testPeerAnnouncementRoundtrip()).
  static EscapeProtocol::PeerAddressTable table;
  EscapeProtocol::PeerAddress *entry = table.findOrCreate("10.0.0.5", 8080);
  check(entry != nullptr, "PeerAddressTable::findOrCreate legt neuen Eintrag an");
  check(table.count() == 1, "PeerAddressTable::count() == 1 nach erstem Eintrag");

  EscapeProtocol::PeerAddress *same = table.findOrCreate("10.0.0.5", 8080);
  check(same == entry, "PeerAddressTable::findOrCreate liefert denselben Eintrag fuer (ip,port) erneut");
  check(table.count() == 1, "kein Duplikat fuer identische (ip,port)-Kombination");

  table.findOrCreate("10.0.0.5", 8081);
  check(table.count() == 2, "unterschiedlicher Port derselben IP zaehlt als eigener Peer");

  table.expireStale(1000000, 1000);
  check(table.count() == 0, "PeerAddressTable::expireStale() entfernt abgelaufene Eintraege");
}

void testPeerAnnouncementRoundtrip() {
  const std::string json = EscapeProtocol::buildPeerAnnouncementJson(8080, true, false);

  // static: zwei PeerAddressTable-Instanzen (~je 4.8 KB bei
  // MAX_PEER_ADDRESSES=200) sprengen zusammen den 8 KiB loopTask-Stack und
  // fuehrten zum Stack-Canary-Crash (memset in der Feld-Initialisierung).
  static EscapeProtocol::PeerAddressTable table;
  EscapeProtocol::ingestPeerAnnouncement(json, "10.0.0.9", "10.0.0.1", 5000, table, 8080);
  check(table.count() == 1, "ingestPeerAnnouncement traegt fremden Absender ein");

  static EscapeProtocol::PeerAddressTable selfTable;
  EscapeProtocol::ingestPeerAnnouncement(json, "10.0.0.1", "10.0.0.1", 5000, selfTable, 8080);
  check(selfTable.count() == 0, "ingestPeerAnnouncement verwirft eigene Ankuendigung (gleiche ip+port)");

  const std::string peersJson = EscapeProtocol::buildPeersJson(table);
  check(peersJson.find("10.0.0.9") != std::string::npos, "buildPeersJson enthaelt eingetragenen Peer");
}

void testChangeLockAndTiming() {
  EscapeProtocol::ChangeLock lock;
  check(!lock.hasUnseenStatusChange(), "ChangeLock startet ohne unbestaetigte Aenderung");
  lock.markChanged(EscapeProtocol::MutationType::Action);
  check(lock.hasUnseenStatusChange(), "markChanged(Action) setzt hasUnseenStatusChange()");
  lock.noteStatusFetched();
  check(!lock.hasUnseenStatusChange(), "noteStatusFetched() loescht unbestaetigte Aenderung");

  check(EscapeProtocol::isHeartbeatDue(10000, 0, 5000), "isHeartbeatDue() greift nach Ablauf des Intervalls");
  check(!EscapeProtocol::isHeartbeatDue(4000, 0, 5000), "isHeartbeatDue() greift NICHT vor Ablauf des Intervalls");
}

} // namespace

void setup() {
  Serial.begin(115200);
  delay(2000);

  Serial.println("\n--- EscapeManager Protocol Self-Test ---");
  testJsonRoundtrip();
  testPlanAction();
  testPeerAddressTable();
  testPeerAnnouncementRoundtrip();
  testChangeLockAndTiming();

  Serial.printf("---------------------------\n%u passed, %u failed\n", g_passed, g_failed);
  Serial.println(g_failed == 0 ? "RESULT: OK" : "RESULT: FAILURES");
}

void loop() {
}
