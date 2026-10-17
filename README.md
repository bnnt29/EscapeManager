# EscapeManager

EscapeManager verbindet ESP32-basierte Escape-Room-Komponenten per UDP-
Discovery mit einer browserbasierten Manager-Oberflaeche. Lesender Status wird
im lokalen Venue-Netz verteilt; schreibende Befehle werden verschluesselt und
authentifiziert.

## Architektur: Peer-Discovery und Aggregation

Es gibt bewusst keine zentrale Server-/Hub-Rolle und kein hartes Geraetelimit:

- Jede Komponente liefert unter `GET /status.json` **ausschliesslich ihre
  eigenen** Komponenten (keine Peer-Daten).
- Jede Komponente sendet alle paar Sekunden eine winzige UDP-Ankuendigung
  (`{"httpPort":80}` - die IP entnimmt der Empfaenger der Absenderadresse) und
  haelt darueber eine leichte Liste erreichbarer Nachbarn (nur IP+Port), die
  sie unter `GET /peers.json` bereitstellt.
- Der Browser oeffnet `manager.html` auf einer beliebigen Komponente (z.B.
  `http://escapemanager.local/` - dank identischer mDNS-Registrierung aller
  Komponenten ist es egal, welche antwortet), fragt dort `/peers.json` ab und
  pollt danach **jede gefundene IP direkt und unabhaengig** per
  `/status.json`. Der Browser selbst aggregiert den Netzzustand fuer die
  Anzeige - keine Komponente muss je den Zustand einer anderen kennen.

Dadurch kostet jede zusaetzliche Komponente dem Netz nur wenige Byte
(IP+Port in der Peer-Liste jeder anderen Komponente) statt - wie in einer
frueheren Version - einer festen, RAM-begrenzten Tabelle mit dem vollen
Zustand aller anderen Geraete. Aktionen (`POST /action` etc.) gehen weiterhin
direkt und verschluesselt vom Browser an die jeweilige Ziel-IP.

## Sicherheit und Verschluesselung

Das Sicherheitsmodell, die Token-Verwaltung, Bedrohungsgrenzen und technischen
Kryptodetails sind in [ENCRYPTION.md](ENCRYPTION.md) dokumentiert.

Lesende GET-Endpunkte und ihre JSON-Antworten sind standardmaessig ungeschuetzt.
Schreibende POSTs und UDP-Broadcasts bleiben verschluesselt und authentifiziert.
Mit `EscapeConfig::AUTHENTICATE_GET_REQUESTS = true` laesst sich fuer GETs der
bisherige Nonce- und HMAC-geschuetzte Modus wieder aktivieren; der Manager kann
beide Antwortformen lesen.

## Hinweise fuer Spieler

Jede Komponente kann optional einen aktuellen Klartext-Hinweis im Feld `tip`
von `status.json` veroeffentlichen. ESP32-Anwendungen registrieren den Wert mit
`onTip(id, callback)`; ein leerer String blendet ihn im Manager aus. Der Text
wird im Manager als reiner Text angezeigt und kann den Spielern bei Bedarf
vorgelesen werden.

## Ablaufplan-Steuerung

Ablaufplanbefehle sind bewusst von frei benannten Komponentenaktionen getrennt.
Eine Komponente kuendigt die unterstuetzten Befehle in `status.json` separat an:

```json
{"planActions":["reset","complete"]}
```

Der Manager sendet einen einzelnen Befehl mit Komponenten-ID an den eigenen
geschuetzten Endpoint:

```http
POST /plan-action
{"id":0,"action":"reset"}
```

Erlaubt sind ausschliesslich `reset` und `complete`. ESP32-Anwendungen
registrieren deren Umsetzung mit `onPlanAction(id, callback)`. Ohne Callback
bleibt `planActions` leer und der Manager sendet keinen Ablaufplanbefehl an
diese Komponente. „Raum zuruecksetzen“ wird auf alle Live-Komponenten des
Raums verteilt; „Ebene zuruecksetzen/abschliessen“ nur auf Komponenten der
betroffenen Ebene. Dummies erhalten keinen Befehl: Der Manager markiert sie
automatisch abgeschlossen, sobald alle in ihre Lane fuehrenden Quellschritte
erreicht sind. Dasselbe Kriterium aktiviert angeschlossene Komponenten; die
Quellkomponente muss dafuer nicht vollstaendig abgeschlossen sein.

Jede Lane enthaelt hoechstens eine Komponente oder einen Dummy. Wird ein Knoten
direkt auf eine Ebene gezogen, legt der Manager automatisch eine neue Lane an.

Ein Geraet mit Komponenten aus mehreren Raeumen speichert die Skeletons aller
dieser Raeume als `{"plans":[...]}`. Ein Update ersetzt nur den Plan desselben
Raums. Auf dem ESP32 liegt diese Sammlung in der separaten NVS-Partition
`plan_nvs`; `reset-persistent-storage` loescht sie zusammen mit der normalen
Konfiguration.

Planvariablen werden automatisch aus `customConfig` der Komponenten des Raums
erzeugt. Typ und aktueller Wert bleiben erhalten. Nur per Checkbox aktivierte
Variablen werden gespeichert; eine Bearbeitung aktiviert die Checkbox. In
Skeleton und Komponenten-Slice werden Variablen ueber die Komponenten-`riddleId`
(nicht die physische, MAC-abgeleitete `uuid` - siehe naechster Abschnitt) und
Feld-`name` referenziert, sodass gleiche Namen auf verschiedenen Komponenten
eindeutig bleiben.

## Raetsel-ID vs. UUID

Jede Komponente traegt zwei getrennte Kennungen:

- **`uuid`**: von der WLAN-MAC-Adresse abgeleitet (`resolveUuid()`), identifiziert
  das physische Board+Komponente. Aendert sich zwangslaeufig bei einem
  Hardwaretausch.
- **`riddleId`**: identifiziert den RAETSELTYP (nicht den in der UI gezeigten
  Namen) - fest im Sketch vergeben (`addComponent(name, room, "camera-puzzle-v1")`,
  siehe `src/arduino/README.md`), damit ALLE Geraete desselben Raetseltyps
  (auch in verschiedenen Raeumen, auch Ersatzgeraete) automatisch dieselbe ID
  tragen. Ohne Angabe (Default) wird sie einmalig zufaellig erzeugt und
  persistiert (`resolveRiddleId()`); jederzeit auch nachtraeglich manuell
  ueberschreibbar (Detailseite "Rätsel-ID" oder `POST /config
  {"riddleId":"..."}`). Referenziert Komponenten im Ablaufplan UND in der
  Raum-Konflikterkennung (`detectRoomConflicts()` in manager.html).

Ein Konflikt-Dialog erscheint nur, wenn dieselbe `riddleId` MEHRFACH IM SELBEN
RAUM auftaucht - dieselbe `riddleId` in zwei GETRENNTEN Raeumen ist erwuenscht
(z.B. zwei baugleiche Raetsel). Um ein defektes Geraet zu ersetzen, dem
Ersatzgeraet auf der Detailseite dieselbe `riddleId` wie das Original geben und
in denselben Raum stellen - der Ablaufplan ordnet es dann automatisch korrekt
zu, obwohl die (MAC-abgeleitete) `uuid` nicht uebereinstimmt.

## Manager-Oberflaeche einbetten

Die Manager-Oberflaeche wird als Gzip-Byte in einem C-Array eingebettet:
`scripts/build_ui.py` erzeugt aus `src/manager/manager.html` sowohl
`src/manager/manager.html.gz` (deterministisches Gzip, mtime 0) als auch
`src/manager/ui_data.cpp` (gleiche Bytes als `EscapeUi::data`/`length` plus
`EscapeVersion::UI_HASH`). Beide Artefakte sind versioniert und werden bei
`manager.html`-Aenderungen automatisch vor jedem Build neu erzeugt
(`extra_scripts = pre:scripts/build_ui.py`, CI-Check: `python3 scripts/build_ui.py --check`).
Die Library liefert die UI ueber das C-Array aus (`Content-Encoding: gzip`;
der Browser entpackt nativ, der ESP32 spart ~70% Flash-Platz) - ein Hostprojekt
braucht dafuer **kein** `board_build.embed_files`.

**Nie** `src/manager/ui_data.cpp` oder `manager.html.gz` direkt bearbeiten -
sie werden bei jedem Build ueberschrieben. Quelle zum Bearbeiten bleibt
`src/manager/manager.html`.

## Als Bibliothek in anderen PlatformIO-Projekten verwenden

EscapeManager wird ueber `lib_deps` mit der Git-URL eingebunden. Das
versionierte `library.json` pinnt den Quellcode-Filter auf
`+<esp/> +<protocol/> +<net/> +<manager/ui_data.cpp>`, damit Simulator
(`src/sim`, eigenes `main()`), Diagnose (`src/diagnostics`) und Python-Code
**nicht** in die Host-Firmware kompiliert werden. `ui_data.cpp` liefert die
eingebettete UI als `EscapeUi::data`/`length` und `EscapeVersion::UI_HASH`;
`src/net/` ist die portierbare Netzwerkschicht, auf der die
ESP32-Plattenschicht aufbaut.

Was das Hostprojekt (z.B. `examples/esp_dummy` in diesem Repo, Abschnitt
`[env:esp-dummy]` in der `platformio.ini` - als Vorlage) selbst bereitstellen
MUSS, da eine Library Board-Optionen nicht von sich aus setzen kann:

- `board_build.partitions` auf `partitions.csv` im libdeps-Pfad,
- die Abhaengigkeit selbst (`lib_deps` mit der Git-URL).

`board_build.embed_files` und `--defsym`-Aliase sind **nicht** mehr
noetig - die UI ist Teil des Library-Codes als C-Array.

## Simulatoren

Der C++-Simulator benoetigt einen C++17-Compiler, pthreads und OpenSSL
(`libcrypto`; unter Debian/Ubuntu Paket `libssl-dev`):

```sh
./run_sim.sh
```

Der Python-Simulator verwendet die produktive Python-Implementierung inklusive
P-256, HKDF, AES-256-GCM, HTTP und UDP-Discovery. Abhaengigkeit installieren
und danach starten:

```sh
python3 -m pip install -r src/python/requirements.txt
python3 src/sim/escape_component_sim.py --http-port 8080
```

Ohne Komponentenparameter startet er vier Demo-Komponenten. Fuer einen
gezielten Test sind Komponenten wiederholbar angebbar:

```sh
python3 src/sim/escape_component_sim.py --component Laser-1:Raum-A --http-port 8080
```

Der Simulator kuendigt sich standardmaessig als `escapemanager.local` per mDNS
an. Mit `--mdns-hostname mein-manager` wird daraus `mein-manager.local`; mit
`--no-mdns` ist die Ankuendigung deaktiviert.

## ESP32 bauen

```sh
$HOME/.platformio/penv/bin/pio run -e firmware
```

Ein neues Programm wird ausschliesslich ueber das Firmware-Environment
geflasht:

```sh
$HOME/.platformio/penv/bin/pio run -e firmware -t upload
```

Das Repository stellt eine Bibliothek bereit. Ein konkretes Firmware-Projekt
muss Arduino-`setup()` und `loop()` definieren; ohne diese kompiliert der
Bibliothekscode, der finale Firmware-Link schlaegt aber erwartungsgemaess fehl.