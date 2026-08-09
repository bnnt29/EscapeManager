# EscapeManager

EscapeManager verbindet ESP32-basierte Escape-Room-Komponenten per UDP-
Discovery mit einer browserbasierten Manager-Oberflaeche. Lesender Status wird
im lokalen Venue-Netz verteilt; schreibende Befehle werden verschluesselt und
authentifiziert.

## Sicherheit und Verschluesselung

Das Sicherheitsmodell, die Token-Verwaltung, Bedrohungsgrenzen und technischen
Kryptodetails sind in [ENCRYPTION.md](ENCRYPTION.md) dokumentiert.

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
automatisch abgeschlossen, sobald alle in ihre Lane fuehrenden Vorgaenger
abgeschlossen sind.

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