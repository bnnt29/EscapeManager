#!/usr/bin/env python3
"""Checks that the repository is a valid Arduino AND PlatformIO library and that both agree.

  python3 scripts/check_library.py

* library.properties, library.json and EscapeVersion::FW carry the same version;
* the Arduino IDE compiles EVERY .cpp below src/ (recursively), so src/ may only hold what belongs to the firmware:
  the .cpp files must lie in the directories library.json's srcFilter names, and no file there may bring its own
  main()/setup()/loop() or need a host library (OpenSSL: that is extras/sim);
* every example is a folder with a .ino of the same name (Arduino rule), listed in library.json;
* the header named by `includes=` exists, keywords.txt exists.
(arduino-lint and real builds are done by CI; this is the quick, dependency-free part.)
"""
import json
import pathlib
import re
import sys

root = pathlib.Path(__file__).resolve().parent.parent
problems = []


def fail(message):
    problems.append(message)


def read_properties(path):
    props = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip() and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            props[key.strip()] = value.strip()
    return props


props = read_properties(root / "library.properties")
meta = json.loads((root / "library.json").read_text(encoding="utf-8"))
fw = re.search(r'FW = "([^"]+)"', (root / "src/protocol/EscapeVersion.hpp").read_text()).group(1)
if not (props.get("version") == meta.get("version") == fw):
    fail("versions differ: library.properties %s, library.json %s, EscapeVersion::FW %s" % (props.get("version"), meta.get("version"), fw))
for key in ("name", "version", "author", "maintainer", "sentence", "paragraph", "category", "url", "architectures", "includes"):
    if not props.get(key):
        fail("library.properties lacks %s" % key)
if props.get("name") != meta.get("name"):
    fail("library name differs between library.properties and library.json")
if not (root / "src" / props.get("includes", "-")).is_file():
    fail("src/%s (includes=) does not exist" % props.get("includes"))
if props.get("includes") != meta.get("headers"):
    fail("includes= and library.json headers differ")
if not (root / "keywords.txt").is_file():
    fail("keywords.txt is missing")

# What the two build systems compile: Arduino = everything under src/, PlatformIO = the srcFilter.
allowed = [f.strip("+<>/ ") for f in meta["build"]["srcFilter"]]
for cpp in sorted((root / "src").rglob("*.cpp")):
    rel = cpp.relative_to(root / "src").as_posix()
    if not any(rel == a or rel.startswith(a.rstrip("/") + "/") for a in allowed):
        fail("src/%s is compiled by the Arduino IDE but not part of the PlatformIO srcFilter" % rel)
    text = cpp.read_text(encoding="utf-8", errors="replace")
    if re.search(r"^\s*int\s+main\s*\(", text, re.M) or re.search(r"^\s*void\s+(setup|loop)\s*\(\s*\)", text, re.M):
        fail("src/%s defines main()/setup()/loop(): that belongs into examples/ or extras/" % rel)
for source in sorted((root / "src").rglob("*")):
    if source.suffix in (".cpp", ".hpp", ".h") and re.search(r"#\s*include\s*<openssl/", source.read_text(encoding="utf-8", errors="replace")):
        fail("%s needs OpenSSL: host-only code belongs into extras/" % source.relative_to(root).as_posix())
for stray in ("sim", "python", "diagnostics"):
    if (root / "src" / stray).exists():
        fail("src/%s must not exist (extras/ or examples/)" % stray)

# Examples
listed = {e["name"]: e for e in meta.get("examples", [])}
folders = sorted(p.name for p in (root / "examples").iterdir() if p.is_dir())
for name in folders:
    if not (root / "examples" / name / (name + ".ino")).is_file():
        fail("examples/%s has no %s.ino (the Arduino IDE needs a sketch of the same name)" % (name, name))
    if name not in listed:
        fail("examples/%s is not listed in library.json" % name)
for name, entry in listed.items():
    for f in entry.get("files", []):
        if not (root / entry["base"] / f).is_file():
            fail("library.json example %s lists missing file %s" % (name, f))
for name in folders:
    shim = root / "scripts" / "pio_shims" / (name + ".cpp")
    if not shim.is_file():
        fail("scripts/pio_shims/%s.cpp (PlatformIO wrapper of the example) is missing" % name)

if problems:
    print("\n".join("FAIL " + p for p in problems))
    sys.exit(1)
print("library layout OK (version %s, %d examples)" % (fw, len(folders)))
