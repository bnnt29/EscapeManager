"""Manual cross-browser check of the UI self-upgrade in Firefox (needs selenium + geckodriver).

  python3 test/manager/manual_firefox_selfupgrade.py <host-with-OLD-ui> <host-with-NEWER-ui>

Both hosts must be devices or simulators of the same network, the second one serving a higher
UI_VERSION. Not part of CI (needs a Firefox + driver); Chromium is covered by selfupgrade.test.mjs.
"""
import time, json, hashlib, urllib.request, sys
OLD, NEW = sys.argv[1], sys.argv[2]
from selenium import webdriver
from selenium.webdriver.firefox.options import Options
from selenium.webdriver.firefox.service import Service
opts = Options(); opts.add_argument("--headless"); opts.page_load_strategy = 'none'   # do not wait for the load event: we want to SEE what happens
svc = Service(__import__("shutil").which("geckodriver") or "/snap/bin/geckodriver")
def ok(n, c, d=""): print(("PASS " if c else "FAIL ") + n + (("  -- " + str(d)) if d else ""))
drv = webdriver.Firefox(options=opts, service=svc)
try:
    drv.set_page_load_timeout(30)
    import gzip
    raw_b = urllib.request.urlopen("http://%s/" % NEW).read()
    b_html = gzip.decompress(raw_b) if raw_b[:2] == b'\x1f\x8b' else raw_b
    b_hash = hashlib.sha256(b_html).hexdigest()[:8]
    drv.get("http://%s/" % OLD)
    time.sleep(3)
    ok("Firefox runs the served (old) UI", drv.execute_script("return window.UI_VERSION") == "2.1.0", drv.execute_script("return window.UI_VERSION"))
    cache = None
    for _ in range(80):
        raw = drv.execute_script("return localStorage.getItem('em.ui.cache')")
        if raw: cache = json.loads(raw); break
        time.sleep(0.5)
    ok("newer UI downloaded and cached in Firefox", bool(cache) and cache["ver"] == "2.1.1", cache and (cache["ver"], cache["hash"]))
    ok("hash equals what board B serves", bool(cache) and cache["hash"] == b_hash, (cache or {}).get("hash"))
    ok("no automatic swap", drv.execute_script("return window.UI_VERSION") == "2.1.0")
    drv.refresh(); time.sleep(6)
    print('INFO  readyState after the swap:', drv.execute_script('return document.readyState'))
    v = drv.execute_script("return window.UI_VERSION")
    ok("after reload the cached UI runs (document swap works in Firefox)", v == "2.1.1", v)
    ok("swapped page has exactly one app (no duplicate ids)", drv.execute_script("return document.querySelectorAll('#grid').length") == 1,
       drv.execute_script("return document.querySelectorAll('#grid').length"))
    time.sleep(12)
    st = drv.execute_script("return {trial: localStorage.getItem('em.ui.trial'), n: window.__em ? window.__em.snapshot().devices.length : -1}")
    ok("trial cleared and devices listed", st["trial"] is None and st["n"] >= 4, st)
finally:
    drv.quit()
