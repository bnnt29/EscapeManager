#!/usr/bin/env python3
"""Builds the GitHub-Pages demo: src/manager/manager.html + tools/demo/demo.js -> one HTML file.

The demo script becomes the FIRST script of <head> (before the manager's boot stage and crypto bundle), so it can
redirect localStorage and replace window.fetch before the manager reads them. manager.html itself stays untouched
(CI checks its gzip/C++ outputs and the firmware's UI hash against it).

  python3 scripts/build_demo.py                       # -> build/demo/index.html
  python3 scripts/build_demo.py --out _site/index.html
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "manager" / "manager.html"
DEMO = ROOT / "tools" / "demo" / "demo.js"
DEFAULT_OUT = ROOT / "build" / "demo" / "index.html"
ANCHOR = "<head>"


def build(out: pathlib.Path) -> None:
    html = SOURCE.read_text(encoding="utf-8")
    script = DEMO.read_text(encoding="utf-8")
    if "</script" in script.lower() or "<!--" in script:
        sys.exit("demo.js must not contain '</script' or '<!--' (it is inlined)")
    if html.count(ANCHOR) != 1:
        sys.exit("manager.html must contain exactly one %r (found %d)" % (ANCHOR, html.count(ANCHOR)))
    injected = html.replace(ANCHOR, ANCHOR + "\n<script>\n" + script + "</script>", 1)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(injected, encoding="utf-8")
    print("wrote %s (%d bytes)" % (out, len(injected.encode("utf-8"))))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=pathlib.Path, default=DEFAULT_OUT)
    args = parser.parse_args()
    build(args.out.resolve())


if __name__ == "__main__":
    main()
