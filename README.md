# EscapeManager

EscapeManager verbindet ESP32-basierte Escape-Room-Komponenten per UDP-
Discovery mit einer browserbasierten Manager-Oberflaeche. Lesender Status wird
im lokalen Venue-Netz verteilt; schreibende Befehle werden verschluesselt und
authentifiziert.

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
Skeleton und Komponenten-Slice werden Variablen ueber Komponenten-`uuid` und
Feld-`name` referenziert, sodass gleiche Namen auf verschiedenen Komponenten
eindeutig bleiben.

## C++-Simulator

Der aktive Simulator benoetigt einen C++17-Compiler, pthreads und OpenSSL
(`libcrypto`; unter Debian/Ubuntu Paket `libssl-dev`):

```sh
./run_sim.sh
```

Der Python-Simulator ist veraltet und implementiert den sicheren Transport
nicht. Fuer Protokoll- und Manager-Tests den C++-Simulator verwenden.

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