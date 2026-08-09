# EscapeManager

EscapeManager verbindet ESP32-basierte Escape-Room-Komponenten per UDP-
Discovery mit einer browserbasierten Manager-Oberflaeche. Lesender Status wird
im lokalen Venue-Netz verteilt; schreibende Befehle werden verschluesselt und
authentifiziert.

## Sicherer Schreibtransport

Beim ersten Empfang eines Geraets laedt der Manager `GET /security.json`. Das
Geraet erzeugt pro Boot ein P-256-Schluesselpaar. Sein Public Key wird mit
einem per HKDF-SHA-256 aus dem venue-weiten `AUTH_TOKEN` abgeleiteten
AES-256-GCM-Key verschluesselt und authentifiziert. Uebertragen werden nur
Key-ID, Salt, IV und Ciphertext; der Token und der Klartext-Public-Key verlassen
ihre jeweilige Seite nicht.

ESP, C++-Simulator und Manager verwenden ohne weitere Konfiguration gemeinsam
den oeffentlich bekannten Repo-Default
`EscapeManager-Private-WLAN-Default-Token`. Dadurch funktionieren GET- und
POST-Pfade in einem privaten WLAN direkt nach dem Start. Dieser Default bietet
keine belastbare Zugriffskontrolle: Vor dem Einsatz in einem nicht vollstaendig
vertrauenswuerdigen Netz muss auf allen Geraeten derselbe eigene, starke,
zufaellige Wert persistent gesetzt und einmal in den Manager-Einstellungen
eingegeben werden. Stimmen die Werte nicht ueberein, kann der Manager bereits
den Public Key nicht authentifiziert entschluesseln und sendet keinen POST.
HKDF ist keine Passwort-Haertung. Technisch werden bewusst auch kurze eigene
Tokens ab 8 Zeichen akzeptiert; fuer belastbare Zugriffskontrolle sollte der
Token trotzdem lang und kryptografisch zufaellig sein.

### Auth-Token ohne Firmware-Upload aendern

Die Firmware laedt den Token beim Boot aus dem NVS-Schluessel
`escfg/authtoken`. Liegt dort kein gueltiger Wert, verwendet sie den gemeinsamen
Repo-Default aus `src/protocol/EscapeConfig.hpp`. Nachdem eine Firmware mit
dieser Provisionierungsschnittstelle einmal installiert wurde, koennen alle
weiteren Tokenwechsel ohne Build und ohne Firmware-Upload erfolgen.

Token in `platformio.ini` im Environment `update-auth-token` unter
`custom_auth_token` eintragen, den seriellen Monitor schliessen und ausfuehren:

```sh
$HOME/.platformio/penv/bin/pio run -e update-auth-token
```

Das Environment sendet den Token ueber USB-Serial, schreibt ausschliesslich
diesen NVS-Wert und startet das Board neu. Andere persistente Einstellungen
bleiben erhalten. Falls mehrere Ports vorhanden sind, `custom_device_port` im
Environment setzen oder `--upload-port /dev/ttyUSB0` verwenden.

Damit der Token nicht im Repository steht, hat die Umgebungsvariable Vorrang:

```sh
ESCAPE_AUTH_TOKEN='einen-starken-zufaelligen-wert-eintragen' \
	$HOME/.platformio/penv/bin/pio run -e update-auth-token
```

Erlaubt sind 8 bis 128 druckbare ASCII-Zeichen ohne Leerzeichen. Das Target
und die Firmware geben den Token weder in der Konsole noch ueber Serial aus.

### Persistente Konfiguration zuruecksetzen

Falls eine Fehlkonfiguration das Geraet unbrauchbar macht, loescht das separate
Environment nur den kompletten Preferences-Namespace `escfg` und startet das
Board neu:

```sh
$HOME/.platformio/penv/bin/pio run -e reset-persistent-storage
```

Das geflashte Programm bleibt unveraendert. Geloescht werden jedoch bewusst
alle persistenten Namen, Raeume, UUID-Spiegelungen, Plaene, Slave-Markierungen,
Custom-Konfigurationen und der gespeicherte Auth-Token. Danach gelten wieder
die Firmware-Defaults. Bei mehreren seriellen Ports im jeweiligen Environment
`custom_device_port` setzen oder `--upload-port` verwenden.

Jeder Request an `/action`, `/plan-action`, `/config`, `/plan` oder
`/plan-skeleton` verwendet:

- ein frisches ephemeres P-256-ECDH-Schluesselpaar,
- HKDF-SHA-256 zur Ableitung eines AES-256-Schluessels,
- AES-256-GCM fuer Vertraulichkeit und Integritaet des JSON-Bodys,
- HMAC-SHA-256 ueber Zielpfad und gesamte Huelle zur Absenderauthentifizierung,
- einen Cache der letzten 32 IVs auf dem Geraet gegen Replay-Angriffe.

Die Boot-Key-ID ist in Key-Wrap, Request-HKDF, AES-GCM-AAD und HMAC gebunden.
Nach einem Neustart laedt der Manager den neuen verschluesselten Public Key und
wiederholt einen wegen des alten Keys abgewiesenen Request genau einmal.

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

`/status.json`, `/plan-skeleton.json`, UDP-Broadcasts und POST-Antworten werden
mit dem Venue-Token per HMAC authentifiziert. GET-Anfragen verwenden eine
Client-Nonce; POST-Antworten sind an die konkrete Request-IV gebunden. Die
Payloads bleiben lesbar, Manipulationen werden jedoch verworfen.

### Schutz gegen Ressourcenangriffe

Verschluesselte POST-Envelopes sind auf 12 KiB begrenzt. Der gemeinsame
JSON-Parser verwirft Strukturen tiefer als 24 Ebenen. ESP32 und Simulator
bearbeiten global hoechstens acht teure POST-Kryptoanfragen pro Sekunde;
UDP-HMAC-Pruefungen sind ebenfalls begrenzt. Diese Grenzen reduzieren CPU-,
Heap- und Stack-Angriffe, ersetzen aber keinen vorgeschalteten Netzwerkfilter.

### Bedrohungsgrenze

Die Verschluesselung verhindert passives Mitschneiden von Befehlen und weist
Geraet sowie Token-Inhaber kryptografisch aus. `manager.html` mit der darin
eingebetteten Kryptoimplementierung wird auf ausdruecklichen Wunsch weiterhin
ueber HTTP vom Geraet ausgeliefert. Ein aktiver Angreifer,
der diese JavaScript-Auslieferung manipulieren kann, kann deshalb auch den im
Browser eingegebenen Token stehlen. Fuer diesen Fall ist weiterhin ein
isoliertes WPA2/3-Venue-WLAN erforderlich; vollstaendigen Schutz bietet erst
eine vertrauenswuerdige HTTPS-Auslieferung oder eine lokal installierte App.
Der Manager speichert den Token deshalb nur noch fuer die aktuelle
Browser-Sitzung (`sessionStorage`), nicht dauerhaft. Ohne gespeicherten Wert
verwendet er den gemeinsamen Repo-Default.

### Auth-Token per Link uebergeben

Ein Manager-Link kann den Token als URL-codierten Fragmentparameter enthalten:

```text
http://escapemanager.local/#/plan?token=meinToken
```

Der Teil nach `#` wird bei einem HTTP-Request nicht an den Server uebertragen.
Der Manager entfernt `token` sofort aus der aktuellen Browser-History-URL und
haelt den Wert danach nur in `sessionStorage`. Vor der Uebernahme prueft er
`allowTokenInUrl` aus `/security.json`. Server-seitig laesst sich die Funktion
mit `EscapeConfig::ALLOW_AUTH_TOKEN_IN_URL = false` vollstaendig deaktivieren.
Der Fragment-Link bleibt ein Bearer-Geheimnis: Wer den urspruenglichen Link
liest oder weitergegeben bekommt, kennt den Token.

## Browser-Krypto

Die portable Browser-Implementierung fuer P-256, SHA-256, HMAC, HKDF und
AES-GCM ist direkt in `manager.html` eingebettet. Es gibt weder externe
Client-Dateien noch npm-/Node-Abhaengigkeiten. Das ist erforderlich, weil die
native Web-Crypto-API auf normalen `http://192.168.x.x`-Origins nicht
verfuegbar ist.

## Neue C++-Plattform anbinden

`src/protocol/SecureTransport.cpp` enthaelt nur Standard-C++11, Wire-Format,
Schluessel-Lebenszyklus, Validierung und Replay-Schutz. Es inkludiert keine
Plattform- oder Krypto-Bibliothek. Eine neue Plattform implementiert lediglich
`EscapeSecurity::CryptoBackend` aus `SecureTransport.hpp` fuer Zufall,
SHA-256/HMAC/HKDF, P-256 und AES-256-GCM und injiziert diese Instanz in den
`SecureTransport`-Konstruktor.

Vorhandene Adapter:

- `src/esp/MbedTlsCryptoBackend.*` fuer ESP32/mbedTLS
- `src/sim/OpenSslCryptoBackend.*` fuer den C++-Simulator/OpenSSL

## C++-Simulator

Der aktive Simulator benoetigt einen C++17-Compiler, pthreads und OpenSSL
(`libcrypto`; unter Debian/Ubuntu Paket `libssl-dev`):

```sh
./run_sim.sh
```

Ohne `ESCAPE_AUTH_TOKEN` verwendet der Simulator den gemeinsamen Repo-Default.
Ein explizites `--token` hat Vorrang vor der Umgebungsvariable; diese hat
Vorrang vor dem Default.

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