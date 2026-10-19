#!/usr/bin/env python3
"""Fails if the firmware outgrew the resource budget (scripts/size_budget.json).

  pio run -e esp-dummy | tee build.log && python3 scripts/check_size.py build.log

The numbers come from PlatformIO's summary lines ("RAM: ... (used N bytes ..." and
"Flash: ..."). They describe the complete demo firmware (Arduino core + Wi-Fi stack + this
library), so they track what the library adds on top of any host program; raise a budget
deliberately and say why in the commit message.
"""
import json
import pathlib
import re
import sys

budget = json.loads((pathlib.Path(__file__).parent / "size_budget.json").read_text())
text = pathlib.Path(sys.argv[1]).read_text(errors="replace")
bad = False
for key, label in (("ram", "RAM"), ("flash", "Flash")):
    m = re.search(r"%s:\s+\[[^\]]*\]\s+[\d.]+%% \(used (\d+) bytes" % label, text)
    if not m:
        print("could not find the %s line in the build log" % label)
        sys.exit(2)
    used, limit = int(m.group(1)), budget[key]
    ok = used <= limit
    print("%-5s used %7d bytes, budget %7d  %s (%+.1f%%)" % (label, used, limit, "OK" if ok else "OVER BUDGET", (used - limit) * 100.0 / limit))
    bad = bad or not ok
sys.exit(1 if bad else 0)
