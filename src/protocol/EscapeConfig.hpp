#pragma once

// Konfigurationskonstanten der EscapeComponent-Firmware/-Bibliothek. Rein
// deklarativ (keine Logik, keine Hardware-/Arduino-Abhaengigkeit) und daher
// sowohl von der ESP32-Firmware (Client/client.hpp+cpp) als auch vom
// PC-Simulator (Sim/escape_component_sim.cpp) direkt einbindbar - vorher
// pflegte der Sim eine eigene "SimConfig"-Kopie dieser Werte, die manuell
// synchron gehalten werden musste.

#include <cstddef>
#include <cstdint>

namespace EscapeConfig {

  // ---- WLAN ---------------------------------------------------------------
  constexpr const char *WIFI_SSID = "BNNT-Netz";
  constexpr const char *WIFI_PASSWORD = "Emsdetten_2004_BNNT";

  // ---- Sicherheit ---------------------------------------------------------
  // Gemeinsames Geheimnis fuer die gesamte Venue/Installation. Der Token wird
  // NICHT ueber das Netzwerk gesendet: Ein daraus abgeleiteter AES-GCM-Key
  // verschluesselt/authentifiziert den Public Key aus /security.json; ausserdem
  // authentifiziert der Token jede verschluesselte POST-Huelle per HMAC-SHA-256.
  // Der oeffentlich bekannte Repo-Default laesst ESP, Simulator und Manager in
  // einem privaten WLAN ohne Provisionierung zusammenarbeiten. Fuer echte
  // Zugriffskontrolle muss venue-weit ein eigener zufaelliger Wert gesetzt werden.
  constexpr const char *AUTH_TOKEN = "EscapeManager-Private-WLAN-Default-Token";
  constexpr size_t MIN_AUTH_TOKEN_LEN = 8;
  constexpr size_t MAX_AUTH_TOKEN_LEN = 128;
  // Erlaubt dem Manager, einen Token aus dem URL-Fragment (#/...?...token=...)
  // zu uebernehmen. Fragmente werden bei HTTP nie an den Server uebertragen.
  constexpr bool ALLOW_AUTH_TOKEN_IN_URL = true;
  // GET-Anfragen und ihre Antworten enthalten nur lesbaren Status und sind
  // standardmaessig weder verschluesselt noch authentifiziert. Auf true setzen,
  // um wieder den bisherigen Nonce+HMAC-geschuetzten GET-Modus zu erzwingen.
  // Schreibende POSTs und UDP-Broadcasts bleiben davon unberuehrt geschuetzt.
  constexpr bool AUTHENTICATE_GET_REQUESTS = false;

  // ---- Ports ---------------------------------------------------------------
  constexpr uint16_t UDP_PORT = 4210;
  constexpr uint16_t HTTP_PORT = 80;

  // ---- Hostname/Auto-Discovery ---------------------------------------------
  // Alle Komponenten einer Venue registrieren denselben mDNS-Hostnamen. Da
  // jede Komponente dieselbe manager.html + status.json (inkl. aller Raeume)
  // ausliefert, landet ein Manager beim Aufruf von http://<MDNS_HOSTNAME>.local/
  // automatisch auf irgendeiner (der zuerst antwortenden, also praktisch
  // zufaellig/naeheliegenden) erreichbaren Komponente - ohne feste IP/Gateway.
  // mDNS funktioniert nur innerhalb desselben L2-Netzsegments (wie UDP-Broadcast).
  constexpr const char *MDNS_HOSTNAME = "escapemanager";

  // ---- Broadcast-Timing (Schutz vor WLAN-Ueberlastung) ---------------------
  // Regulaeres Intervall pro Komponente. Ein zufaelliger, pro Geraet fixer
  // Jitter (0..HEARTBEAT_JITTER_MS) verhindert, dass alle Komponenten exakt
  // synchron senden (z.B. wenn alle gleichzeitig eingeschaltet werden).
  constexpr uint32_t HEARTBEAT_INTERVAL_MS = 4000;
  constexpr uint32_t HEARTBEAT_JITTER_MS = 750;
  // Bei Zustandsaenderungen (markDirty()) wird sofort broadcastet, aber
  // hoechstens alle CHANGE_MIN_GAP_MS - verhindert Flooding bei schnellen
  // aufeinanderfolgenden Aenderungen.
  constexpr uint32_t CHANGE_MIN_GAP_MS = 300;
  // Nach dieser Zeit ohne Broadcast gilt eine andere Komponente als offline
  // und wird aus der eigenen Peer-Tabelle (und damit /status.json) entfernt.
  constexpr uint32_t PEER_TIMEOUT_MS = 20000;

  // ---- Kapazitaeten ---------------------------------------------------------
  // ESP32 hat nur begrenzt RAM: feste Obergrenzen statt dynamischer
  // Allokation, damit Speicherverbrauch unabhaengig von Netzwerkinhalten und
  // der (variablen, nie garantiert vollstaendigen) Anzahl gleichzeitig
  // eingeschalteter Komponenten vorhersagbar bleibt. Der PC-Simulator uebernimmt
  // dieselben Grenzen (nicht weil er sie technisch braeuchte, sondern damit er
  // sich bezueglich Kapazitaet identisch zur echten Firmware verhaelt).
  constexpr size_t MAX_PEERS = 24;
  // Wie viele eigene Raetsel-Komponenten EIN ESP32 gleichzeitig anmelden kann
  // (addComponent()), z.B. mehrere Sensoren/Aktoren, die an einem Board haengen.
  // Jede davon hat eigenen Namen/Raum/Zustand, teilt sich aber Netzwerk-Stack,
  // HTTP-Server und Batteriemessung mit den anderen Komponenten desselben Boards.
  constexpr size_t MAX_LOCAL_COMPONENTS = 4;
  constexpr size_t MAX_NAME_LEN = 32;
  constexpr size_t MAX_ROOM_LEN = 32;
  constexpr size_t MAX_ERRORS = 4;
  constexpr size_t MAX_ERROR_LEN = 32;
  constexpr size_t MAX_ACTIONS = 8;
  constexpr size_t MAX_ACTION_LEN = 24;
  constexpr size_t MAX_FEED_LEN = 96;
  // Kurzer, rein textueller Hinweis fuer den Manager, den dieser bei Bedarf
  // den Spielern vorlesen kann. Kein HTML, damit die Anzeige sicher als Text
  // erfolgen kann.
  constexpr size_t MAX_TIP_LEN = 512;
  constexpr size_t MAX_STATE_LEN = 1664; // HTML oder Text, je nach puzzleIsHtml
  // Textuelle Darstellung einer IPv4-Adresse ("255.255.255.255" + Nullbyte).
  constexpr size_t MAX_IP_LEN = 15;

  // ---- Custom Konfiguration pro Komponente -----------------------------------
  // Jede Komponente kann eine kleine Liste eigener Konfigurationsfelder (z.B.
  // Helligkeit, Anzeige-Text, Schwierigkeitsgrad) per Broadcast/status.json
  // bekanntgeben. Der Manager rendert daraus die Raum-Konfiguration und schickt
  // neue Werte per POST /config zurueck - dort serverseitig gegen genau diese
  // Grenzen validiert, bevor sie uebernommen werden.
  constexpr size_t MAX_CUSTOM_CONFIGS = 4;
  constexpr size_t MAX_CONFIG_KEY_LEN = 20;
  constexpr size_t MAX_CONFIG_VALUE_LEN = 48;
  constexpr size_t MAX_CONFIG_OPTIONS = 6;
  constexpr size_t MAX_CONFIG_OPTION_LEN = 16;

  // ---- Ablaufplan (Raum-weiter Prozessgraph aus Ebenen/Lanes/Verbindungen) --
  // Die eigentliche Graph-Logik (Ebenen, Lanes, Linien, Dummies, Variablen)
  // lebt bewusst NUR im Manager (manager.html) - die Firmware speichert/liefert
  // sie nur als rohe, fuer sie bedeutungslose JSON-Bloecke, aufgeteilt in zwei
  // Teile, um NVS/RAM klein zu halten (kein voller Plan pro Geraet noetig):
  //  - Pro Komponente EIN kleiner "Slice" (eigene Lane-Zuordnung + ausgehende
  //    Verbindungen dieser einen Komponente), analog zu name/room persistiert.
  //  - Pro Raum EIN "Skeleton" (Ebenen/Lanes-Struktur, Dummy-Knoten,
  //    Variablen-Katalog). Ein Geraet mit Komponenten aus mehreren Raeumen
  //    persistiert alle zugehoerigen Skeletons gemeinsam als {"plans":[...]}.
  // "uuid" ist trotz des Feldnamens (Schema-Kompatibilitaet) keine echte
  // Zufalls-UUID, sondern von der WLAN-MAC-Adresse des Boards abgeleitet
  // ("aabbccddeeff-<id>") - deterministisch, kollisionsfrei pro Board+
  // Komponente und ohne Zufallsquelle/NVS-Race ueber Reboots hinweg stabil.
  // Ist die MAC nicht verfuegbar (WiFi.macAddress() liefert nur 0x00/0xFF,
  // z.B. bei WLAN-Treiberfehler), faellt macBasedUuid() auf die eFuse-
  // Chip-ID zurueck ("chip<hex>-<id>") - ebenfalls werkseitig eindeutig und
  // deterministisch, siehe Kommentar dort.
  // Wird trotzdem in NVS gespiegelt (siehe resolveUuid()), damit ein spaeter
  // manuell in NVS gesetzter Wert Vorrang haette. Format braucht deutlich
  // weniger Platz als eine UUIDv4 (36 Zeichen) - "aabbccddeeff-3" sind 14.
  constexpr size_t MAX_UUID_LEN = 20;
  // Bewusst klein gehalten: mit MAX_PEERS=24 kostet jedes zusaetzliche Byte
  // hier 24x RAM (fixe PeerInfo-Tabelle, siehe Kommentar dort). Ebenen-/Lane-
  // IDs im Plan-Slice sind daher kurze, vom Manager vergebene Tokens (z.B.
  // "L0"/"A"), keine UUIDs - nur Komponenten/Dummies selbst brauchen echte
  // UUIDs (stabile Identitaet ueber Reboots/Umbenennungen hinweg).
  constexpr size_t MAX_PLAN_LEN = 512; // Slice EINER Komponente
  constexpr size_t MAX_PLAN_SKELETON_LEN = 6144; // Skeleton genau eines Raums
  // Ein Board kann Komponenten aus bis zu MAX_LOCAL_COMPONENTS verschiedenen
  // Raeumen tragen und muss deshalb deren Skeletons gemeinsam persistieren.
  constexpr size_t MAX_PLAN_SKELETON_STORAGE_LEN =
      MAX_LOCAL_COMPONENTS * MAX_PLAN_SKELETON_LEN + 128;

  // ---- Aktivitaets-Benachrichtigung ("hat ein Manager etwas veraendert?") --
  // Jede Komponente traegt einen monoton steigenden Zaehler + eine kurze
  // Klartext-Meldung des zuletzt ausgeloesten Ereignisses (Aktion ausgefuehrt,
  // Konfiguration/Identitaet/Ablaufplan geaendert). Wird wie plan/customConfig
  // per Broadcast/status.json an alle Peers weitergereicht, damit JEDER offene
  // Manager (jede Browser-Instanz, die irgendeine Komponente im selben Raum
  // pollt) beim naechsten Poll erkennt, dass sich etwas geaendert hat, und eine
  // Benachrichtigung anzeigen kann - unabhaengig davon, welcher Manager die
  // Aenderung ausgeloest hat. Nur RAM (kein NVS) - ueberlebt keinen Reboot,
  // das ist fuer eine reine UI-Benachrichtigung ausreichend.
  constexpr size_t MAX_EVENT_MSG_LEN = 64;

  // ---- Default-Identitaet ---------------------------------------------------
  // Greift nur, solange noch keine Konfiguration im NVS gespeichert wurde.
  constexpr const char *DEFAULT_NAME = "Komponente";
  constexpr const char *DEFAULT_ROOM = "unzugeordnet";

  // ---- Abgleich mit laenger laufenden Peers ("Uptime-Sync") -----------------
  // Ein frisch gebootetes/neu beigetretenes Geraet (Uptime nahe 0) soll seine
  // eigene Persistenz (Ablaufplan-Skeleton, CustomConfig-Werte + Ablaufplan-
  // Slice EIGENER Komponenten) von einem laenger laufenden Peer uebernehmen,
  // statt eigene (moeglicherweise veraltete/zurueckgesetzte) Werte an das
  // restliche System zu verteilen - siehe EscapeProtocol::shouldAdoptFromPeer()/
  // reconcileLocalComponentsFromPeers()/findSkeletonSyncSource(). Deutlich
  // seltener als der Heartbeat, da eine Runde ggf. eine blockierende HTTP-
  // Anfrage an einen Peer ausloest (Plan-Skeleton-Abgleich).
  constexpr uint32_t RECONCILE_INTERVAL_MS = 60000;

} // namespace EscapeConfig
