#!/usr/bin/env python3
"""Erzeugt src/manager/manager.html.gz aus src/manager/manager.html.

Wird von PlatformIO automatisch vor jedem Firmware-Build ausgefuehrt (siehe
"extra_scripts = pre:scripts/compress_manager_html.py" in platformio.ini) -
kein manueller Schritt noetig. Kann bei Bedarf auch direkt aufgerufen werden:

    python3 scripts/compress_manager_html.py

Die .gz-Datei wird per board_build.embed_files (siehe platformio.ini) als
Binaerblob ins Flash eingebettet und von HardwareEsp32::serveManagerHtml() mit
"Content-Encoding: gzip" ausgeliefert - alle gaengigen Browser entpacken Gzip
nativ, der ESP32 selbst muss nichts entpacken UND spart ~70-80% Flash-Platz
fuer diese Datei (siehe partitions.csv/README.md). Bewusst KEINE zusaetzliche
HTML/JS/CSS-Minifizierung: das Risiko, dabei versehentlich Stringliterale/
Kommentar-aehnliche Inhalte in JS-Strings zu beschaedigen, ueberwiegt den
kleinen Zusatzgewinn gegenueber der ohnehin sehr guten Gzip-Kompression bei
dieser stark repetitiven HTML/CSS/JS-Datei.

"mtime=0" haelt den Gzip-Header reproduzierbar (sonst wuerde sich der
eingebettete Blob bei IDENTISCHEM Inhalt von Build zu Build durch einen neuen
Zeitstempel unterscheiden und unnoetige Neuverlinkungen ausloesen).
"""
# pyright: reportMissingImports=false, reportMissingModuleSource=false, reportUndefinedVariable=false
import gzip
import pathlib
import sys


def resolve_repo_root() -> pathlib.Path:
    # Als PlatformIO "pre"-Extra-Script fuehrt SCons diese Datei per
    # exec(compile(...), ...) aus - dabei ist "__file__" NICHT gesetzt
    # (NameError: name '__file__' is not defined). PlatformIO exportiert in
    # diesem Fall aber "env" (siehe Import("env")), dessen PROJECT_DIR
    # zuverlaessig den Projekt-Root liefert. Nur bei manuellem Standalone-
    # Aufruf (python3 scripts/compress_manager_html.py) gibt es kein "env" -
    # dann auf __file__ zurueckfallen.
    try:
        Import("env")  # noqa: F821 - von SCons zur Laufzeit injiziert
        return pathlib.Path(env["PROJECT_DIR"]).resolve()  # noqa: F821
    except NameError:
        return pathlib.Path(__file__).resolve().parent.parent


REPO_ROOT = resolve_repo_root()
SOURCE = REPO_ROOT / "src" / "manager" / "manager.html"
TARGET = REPO_ROOT / "src" / "manager" / "manager.html.gz"


def build() -> None:
    if not SOURCE.exists():
        print(f"[compress_manager_html] Quelle fehlt: {SOURCE}", file=sys.stderr)
        sys.exit(1)
    data = SOURCE.read_bytes()
    compressed = gzip.compress(data, compresslevel=9, mtime=0)
    TARGET.write_bytes(compressed)
    saved_percent = 100 - (len(compressed) * 100 // len(data))
    print(f"[compress_manager_html] {SOURCE.name}: {len(data)} -> {len(compressed)} Byte (-{saved_percent}%)")


build()
