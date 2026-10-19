"""End-to-end tests of the serial host (src/sim/escape_component_serial_host.cpp).

Run from anywhere (the tests locate the repository themselves):

    python3 test/serial_host/test_serial_host.py            # plain unittest, stdlib only
    python3 -m pytest test/serial_host -q                   # or pytest, if installed

The program is built once into .sim-build/escape_component_serial_host with the g++ line of
run_serial_host.sh (set SERIAL_HOST_BIN=/path/to/binary to test an existing build instead). Every test starts one or more hosts on a pseudo-terminal pair (os.openpty()) and plays a
fake Arduino on the master side; the host is then examined through the Node reference client
scripts/em_client.mjs (authenticated reads/POSTs, proto 2) and through plain HTTP. The edit-token and --setup tests
(PROTOCOL.md 3.1 / 5.8) need POSTs sealed with either key set, which em_client.mjs does not offer: they use the small
stand-alone node client SEALED_POST_JS below (Host.sealed_post) and the Node-generated vectors of test/fixtures/proto2.

Ports: HTTP 9300..9399, discovery UDP 14230 (shared by the hosts of one test, which use a random token of their own
so announcements of other programs on the machine are ignored). Only processes started here are ever signalled.
"""

from __future__ import annotations

import atexit
import fcntl
import glob
import http.client
import json
import os
import random
import secrets
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("SERIAL_HOST_BIN") or ROOT / ".sim-build" / "escape_component_serial_host")  # override: test another build
CLIENT = ROOT / "scripts" / "em_client.mjs"
SCRATCH = Path("/tmp/opencode")
LOG_DIR = SCRATCH / "serial-host-logs"
UDP_PORT = 14230
PORT_RANGE = (9300, 9399)

SOURCES = ["src/sim/escape_component_serial_host.cpp", "src/sim/OpenSslCryptoBackend.cpp", "src/net/Device.cpp", "src/net/Net.cpp"]
BUILD_CMD = ["g++", "-std=c++17", "-O2", "-Wall", "-Wextra", "-Wno-unused-parameter", "-pthread"]  # as run_serial_host.sh


# ---- build -----------------------------------------------------------------------------------------------------

def build() -> Path:
    """Builds the host unless the binary is newer than every source and header it depends on (never with SERIAL_HOST_BIN)."""
    if os.environ.get("SERIAL_HOST_BIN"):
        return BIN
    sources = [str(ROOT / s) for s in SOURCES] + sorted(glob.glob(str(ROOT / "src" / "protocol" / "*.cpp")))
    deps = sources + [p for d in ("net", "protocol", "sim") for ext in ("*.hpp", "*.cpp") for p in glob.glob(str(ROOT / "src" / d / ext))]
    newest = max(os.path.getmtime(p) for p in deps)
    if BIN.exists() and BIN.stat().st_mtime >= newest:
        return BIN
    SCRATCH.mkdir(parents=True, exist_ok=True)
    with open(SCRATCH / "serial-host-build.lock", "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if BIN.exists() and BIN.stat().st_mtime >= newest:
            return BIN
        BIN.parent.mkdir(exist_ok=True)
        tmp = BIN.with_name(BIN.name + ".%d.tmp" % os.getpid())
        proc = subprocess.run(BUILD_CMD + ["-o", str(tmp)] + sources + ["-lcrypto"], cwd=str(ROOT), capture_output=True, text=True)
        if proc.returncode != 0:
            raise RuntimeError("build failed:\n" + proc.stdout + proc.stderr)
        os.replace(tmp, BIN)
    return BIN


# ---- helpers ---------------------------------------------------------------------------------------------------

_used_ports: set = set()


def free_port() -> int:
    for _ in range(300):
        port = random.randint(*PORT_RANGE)
        if port in _used_ports:
            continue
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
        except OSError:
            continue
        finally:
            probe.close()
        _used_ports.add(port)
        return port
    raise RuntimeError("no free port in %d..%d" % PORT_RANGE)


def wait_for(cond, timeout=10.0, interval=0.05):
    deadline = time.monotonic() + timeout
    while True:
        try:
            value = cond()
        except (OSError, ValueError, KeyError, IndexError, TypeError, http.client.HTTPException):
            value = None
        if value:
            return value
        if time.monotonic() >= deadline:
            return None
        time.sleep(interval)


def http_get(port, path, timeout=5.0):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    try:
        conn.request("GET", path)
        resp = conn.getresponse()
        return resp.status, dict(resp.getheaders()), resp.read()
    finally:
        conn.close()


def bare_status(port):
    """Viewer-mode /status.json (no nonce): the bare document, as text and parsed."""
    status, _, body = http_get(port, "/status.json")
    assert status == 200, status
    return body.decode(), json.loads(body)


# Sealed POSTs with either key set (PROTOCOL.md 3 and 3.1). scripts/em_client.mjs only knows the normal keys, so the
# edit-token tests use this small stand-alone client (node:crypto only, JSON request on stdin, JSON result on stdout):
#   {"port", "path", "body" (object), "role": "normal"|"edit", "token", "editToken", "k": optional envelope member override}
#   -> {"status", "code", "plain" (parsed answer), "sealedWith": "edit"|"normal"|null, "raw"}
# The answer is opened with the edit response key first and then with the normal one (3.1: errors that are decided before
# authentication are sealed with the normal key).
SEALED_POST_JS = r"""
const crypto = require("node:crypto");
const req = JSON.parse(require("node:fs").readFileSync(0, "utf8"));
const b64u = (b) => Buffer.from(b).toString("base64url");
const keySet = (token, salt, iter) => {
  const master = crypto.pbkdf2Sync(Buffer.from(token), salt, iter, 32, "sha256");
  const k = (info) => Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0), Buffer.from(info), 32));
  return { req: k("EM2 req"), resp: k("EM2 resp") };
};
(async () => {
  const base = "http://127.0.0.1:" + req.port;
  const sec = await (await fetch(base + "/security.json", { cache: "no-store" })).json();
  const normal = keySet(req.token, "EscapeManager/2/token", sec.kdf.iter);
  const edit = req.editToken ? keySet(req.editToken, "EscapeManager/2/edit-token", sec.kdf.iter) : null;
  const role = req.role || "normal";
  const sealKeys = role === "edit" ? edit : normal;
  const t = sec.time >>> 0;
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", sealKeys.req, iv);
  c.setAAD(Buffer.from("EM2|req|" + sec.did + "|" + req.path + "|" + t));
  const ct = Buffer.concat([c.update(Buffer.from(JSON.stringify(req.body))), c.final(), c.getAuthTag()]);
  const envelope = { v: 2, t, iv: b64u(iv), ct: b64u(ct) };
  if (req.k !== undefined ? req.k : role === "edit") envelope.k = "e";
  const res = await fetch(base + req.path, { method: "POST", body: JSON.stringify(envelope), headers: { "content-type": "application/json" } });
  const raw = await res.text();
  const out = { status: res.status, code: null, plain: null, sealedWith: null, raw };
  let parsed = null;
  try { parsed = JSON.parse(raw); } catch (e) { /* not JSON */ }
  if (parsed && parsed.ct && parsed.iv) {
    const data = Buffer.from(parsed.ct, "base64url");
    for (const [name, ks] of [["edit", edit], ["normal", normal]]) {
      if (!ks || data.length < 16) continue;
      try {
        const d = crypto.createDecipheriv("aes-256-gcm", ks.resp, Buffer.from(parsed.iv, "base64url"));
        d.setAAD(Buffer.from("EM2|resp|" + sec.did + "|" + req.path + "|" + b64u(iv) + "|" + res.status));
        d.setAuthTag(data.subarray(data.length - 16));
        out.plain = JSON.parse(Buffer.concat([d.update(data.subarray(0, data.length - 16)), d.final()]).toString());
        out.sealedWith = name;
        break;
      } catch (e) { /* the other key set */ }
    }
  } else if (parsed) {
    out.plain = parsed;
  }
  if (out.plain) out.code = out.plain.code || null;
  process.stdout.write(JSON.stringify(out));
})().catch((e) => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def rss_kb(pid, field="VmRSS"):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith(field + ":"):
                return int(line.split()[1])
    raise RuntimeError("no " + field)


class Cleanup:
    """Everything that has to be stopped/removed at the end of a test, in reverse order."""

    def __init__(self):
        self.items = []

    def add(self, fn):
        self.items.append(fn)

    def run(self):
        while self.items:
            try:
                self.items.pop()()
            except Exception as exc:  # noqa: BLE001 - cleanup must go on
                print("cleanup:", exc, file=sys.stderr)


_live_procs: list = []


@atexit.register
def _kill_leftovers():  # only our own children
    for proc in _live_procs:
        if proc.poll() is None:
            proc.kill()


# ---- the fake Arduino ----------------------------------------------------------------------------------------

def make_component(cid, name, room, riddle):
    return {
        "id": cid, "uuid": "ard-%d" % cid, "riddleId": riddle, "name": name, "room": room, "errors": [],
        "actions": ["next", "reset", "fail"], "planActions": ["reset", "complete"],
        "puzzle": {"step": 0, "totalSteps": 3, "state": "bereit", "isHtml": False}, "tip": "Taste 'next' druecken",
        "feed": "http://192.168.7.7/feed",
        "customConfig": [
            {"key": "brightness", "type": "range", "min": 0, "max": 100, "value": "50"},
            {"key": "label", "type": "text", "maxLength": 8, "value": ""},
            {"key": "mode", "type": "select", "options": ["a", "b"], "value": "a"},
        ],
        "evtSeq": 0, "evtMsg": "",
    }


class FakeArduino:
    """A pty pair; the host opens the slave side, this object is the sketch on the master side."""

    def __init__(self, components=None, battery=87, *, answer=True, junk=True, apply_identity=True, crlf=False):
        self.master, slave = os.openpty()
        self.path = os.ttyname(slave)
        os.close(slave)  # the pts node lives as long as the master; only the host opens (and configures) the slave side
        self.components = components if components is not None else [
            make_component(7, "Tuer", "Raum-A", "door-v1"), make_component(3, "Laser", "Raum-A", "laser-v1")]
        self.battery = battery
        self.answer, self.junk, self.apply_identity, self.crlf = answer, junk, apply_identity, crlf
        self.paused = False  # True: the sketch stops reading its serial input (the host's output piles up)
        self.rx = []        # every JSON command received, in order
        self.rx_lines = []  # raw lines
        self.lock = threading.Lock()
        self.wlock = threading.Lock()
        self.stop_flag = threading.Event()
        self.closed = False
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    # -- plumbing
    def write(self, data: bytes):
        view = memoryview(data)
        with self.wlock:
            while view and not self.stop_flag.is_set():
                try:
                    n = os.write(self.master, view[:4096])
                except OSError:
                    return False
                view = view[n:]
        return True

    def _run(self):
        buf = b""
        while not self.stop_flag.is_set():
            if self.paused:
                time.sleep(0.02)
                continue
            ready, _, _ = select.select([self.master], [], [], 0.05)
            if not ready:
                continue
            try:
                data = os.read(self.master, 4096)
            except OSError:  # EIO: the slave side is closed (host restarting); it comes back when the host re-opens it
                time.sleep(0.02)
                continue
            if not data:
                time.sleep(0.02)
                continue
            buf += data
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                self._handle(line)

    def close(self):
        """Unplugs the Arduino: both ends of the pty go away."""
        if self.closed:
            return
        self.closed = True
        self.stop_flag.set()
        self.thread.join(2)
        try:
            os.close(self.master)
        except OSError:
            pass

    # -- behaviour
    def comp(self, cid):
        return next((c for c in self.components if c["id"] == cid), None)

    def state_line(self):
        doc = {"type": "state", "components": self.components}
        if self.battery is not None:
            doc["battery"] = self.battery
        return json.dumps(doc, separators=(",", ":")).encode()

    def send_state(self):
        nl = b"\r\n" if self.crlf else b"\n"
        if self.junk:
            self.write(b"DEBUG: boot ok, free ram 1234\r\n\x00\xff\xfe line noise \x80\n"
                       b'{"type":"log","msg":"not a state"}\n{"type":"state",\n  \n')
        self.write(self.state_line() + nl)
        if self.junk:
            self.write(b"loop took 3 ms\n")

    def _handle(self, line):
        text = line.decode("utf-8", "replace").strip()
        with self.lock:
            self.rx_lines.append(text)
        try:
            msg = json.loads(text)
        except ValueError:
            return
        with self.lock:
            self.rx.append(msg)
        if not self.answer:
            return
        kind, c = msg.get("type"), self.comp(msg.get("id", -1))
        if kind == "getState":
            self.send_state()
            return
        if c is None:
            return
        if kind == "action":
            if msg["action"] == "next":
                c["puzzle"]["step"] = min(c["puzzle"]["step"] + 1, c["puzzle"]["totalSteps"])
            elif msg["action"] == "reset":
                c["puzzle"]["step"], c["errors"] = 0, []
            elif msg["action"] == "fail":
                c["errors"] = ["sensor_timeout"]
        elif kind == "planAction":
            c["puzzle"]["step"] = 0 if msg["action"] == "reset" else c["puzzle"]["totalSteps"]
        elif kind == "setIdentity" and self.apply_identity:
            c["name"], c["room"] = msg["name"], msg["room"]
        elif kind == "setRiddleId" and self.apply_identity:
            c["riddleId"] = msg["value"]
        elif kind == "setConfig":
            for d in c["customConfig"]:
                if d["key"] == msg["key"]:
                    d["value"] = msg["value"]
        elif kind == "setPlan":
            if msg["plan"] is None:
                c.pop("plan", None)
            else:
                c["plan"] = msg["plan"]
        elif kind == "event":
            c["evtSeq"] += 1
            c["evtMsg"] = msg["message"]
        self.send_state()

    def commands(self, kind=None):
        with self.lock:
            return [m for m in self.rx if kind is None or m.get("type") == kind]

    def raw_lines(self):
        with self.lock:
            return list(self.rx_lines)

    def clear(self):
        with self.lock:
            self.rx.clear()
            self.rx_lines.clear()


# ---- the host process ----------------------------------------------------------------------------------------

class Host:
    def __init__(self, test, serial, *, did=None, state_dir=None, extra=(), name="host", token=None, edit_token=None, setup=False, env=None):
        self.test = test
        self.port = free_port()
        self.token = token or test.token
        self.edit_token = edit_token  # None: no --edit-token
        self.state_dir = str(state_dir or Path(test.tmp) / ("state-%d" % self.port))
        argv = [str(BIN), "--serial", str(serial), "--ip", "127.0.0.1", "--no-mdns", "--udp-port", str(UDP_PORT),
                "--http-port", str(self.port), "--token", self.token, "--state-dir", self.state_dir] + list(extra)
        if did:
            argv += ["--did", did]
        if edit_token:
            argv += ["--edit-token", edit_token]
        if setup:
            argv += ["--setup"]
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_path = LOG_DIR / ("%s-%s-%d.log" % (test.id().split(".")[-1], name, self.port))
        self.log = open(self.log_path, "w")
        if env is None:  # hermetic: a token exported in the developer's shell must not leak into the host under test
            env = {k: v for k, v in os.environ.items() if k not in ("ESCAPE_AUTH_TOKEN", "ESCAPE_EDIT_TOKEN")}
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT, cwd=str(ROOT), env=env)
        _live_procs.append(self.proc)
        test.cleanup.add(self.stop)
        up = wait_for(self.up, 20)
        test.assertTrue(up, "host did not start:\n" + self.output())

    def up(self):
        if self.proc.poll() is not None:
            raise AssertionError("host exited with %s:\n%s" % (self.proc.returncode, self.output()))
        try:
            return http_get(self.port, "/security.json", 2)[0] == 200
        except OSError:
            return False

    def output(self):
        if not self.log.closed:
            self.log.flush()
        return self.log_path.read_text(errors="replace")

    def stop(self, sig=signal.SIGTERM):
        code = self.proc.poll()
        if code is None:
            self.proc.send_signal(sig)
            try:
                code = self.proc.wait(timeout=8)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                code = self.proc.wait()
        if not self.log.closed:
            self.log.close()
        return code

    # -- clients
    def node(self, *args, retries=40):
        """Runs scripts/em_client.mjs (retrying while the per-source POST budget of loopback is exhausted)."""
        for _ in range(retries):
            proc = subprocess.run(["node", str(CLIENT), "127.0.0.1:%d" % self.port, "--token", self.token] + [str(a) for a in args],
                                  capture_output=True, text=True, timeout=30)
            out = proc.stdout.strip()
            if '"rate_limited"' in out and args and args[0] in ("post", "action"):
                time.sleep(0.5)
                continue
            self.test.assertEqual(proc.returncode, 0, "em_client %s failed: %s %s" % (args, proc.stdout, proc.stderr))
            return json.loads(out)
        raise AssertionError("rate limited for too long")

    def security(self):
        status, _, body = http_get(self.port, "/security.json")
        assert status == 200, status
        return json.loads(body)

    def sealed_post(self, path, body, role="normal", *, token=None, edit_token=None, k=None, retries=40):
        """Sealed POST with the normal or the edit key set (see SEALED_POST_JS). Retries while the per-source POST budget is used up."""
        req = {"port": self.port, "path": path, "body": body, "role": role, "token": token or self.token,
               "editToken": edit_token if edit_token is not None else self.edit_token}
        if k is not None:
            req["k"] = k
        for _ in range(retries):
            proc = subprocess.run(["node", "-e", SEALED_POST_JS], input=json.dumps(req), capture_output=True, text=True, timeout=60)
            self.test.assertEqual(proc.returncode, 0, "sealed POST %s failed: %s %s" % (path, proc.stdout, proc.stderr))
            out = json.loads(proc.stdout)
            if out["status"] == 429:
                time.sleep(0.5)
                continue
            return out
        raise AssertionError("rate limited for too long")

    def status(self):
        return self.node("status")

    def post(self, path, body):
        return self.node("post", path, json.dumps(body, separators=(",", ":")))

    def action(self, cid, name):
        return self.node("action", cid, name)


class SerialHostTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build()
        if shutil.which("node") is None:
            raise unittest.SkipTest("node (>= 18) is needed for scripts/em_client.mjs")

    def setUp(self):
        self.cleanup = Cleanup()
        self.addCleanup(self.cleanup.run)
        SCRATCH.mkdir(parents=True, exist_ok=True)
        self.tmp = tempfile.mkdtemp(prefix="serial-host-", dir=str(SCRATCH))
        self.cleanup.add(lambda: shutil.rmtree(self.tmp, ignore_errors=True))
        self.token = "serial-host-test-" + secrets.token_hex(10)

    def arduino(self, *args, **kwargs):
        a = FakeArduino(*args, **kwargs)
        self.cleanup.add(a.close)
        return a

    def host(self, serial, **kwargs):
        return Host(self, serial, **kwargs)

    def wait(self, cond, what, timeout=10.0, host=None):
        value = wait_for(cond, timeout)
        self.assertTrue(value, "timeout waiting for " + what + ("\n--- host log ---\n" + host.output()[-3000:] if host else ""))
        return value

    def state_dir_json(self, host):
        return json.loads((Path(host.state_dir) / "state.json").read_text())


# ---- tests ------------------------------------------------------------------------------------------------------

class StatusTests(SerialHostTestCase):
    def test_status_shows_components_and_ignores_debug_noise(self):
        ard = self.arduino(crlf=True)  # junk lines around every snapshot and CRLF line ends
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        st = host.status()  # authenticated read through the reference client
        self.assertEqual((st["proto"], st["pmin"], st["port"], st["ip"], st["token"]), (2, 2, host.port, "127.0.0.1", "custom"))
        self.assertRegex(st["did"], r"^[0-9a-f]{12}$")
        self.assertEqual(st["battery"], 87)
        self.assertEqual([c["id"] for c in st["components"]], [0, 1])  # host indices, not the sketch's ids 7 and 3
        c0, c1 = st["components"]
        self.assertEqual((c0["name"], c0["room"], c0["riddleId"]), ("Tuer", "Raum-A", "door-v1"))
        self.assertEqual(c1["name"], "Laser")
        self.assertEqual(c0["uuid"], st["did"] + "-0")                       # <did>-<index>, not the sketch's "ard-7"
        self.assertEqual(c0["errors"], [])
        self.assertEqual(c0["actions"], ["next", "reset", "fail"])
        self.assertEqual(c0["planActions"], ["reset", "complete"])
        self.assertEqual(c0["puzzle"], {"step": 0, "totalSteps": 3, "state": "bereit", "isHtml": False})
        self.assertEqual(c0["tip"], "Taste 'next' druecken")
        self.assertEqual(c0["feed"], "http://192.168.7.7/feed")
        self.assertEqual([(d["key"], d["type"]) for d in c0["customConfig"]], [("brightness", "range"), ("label", "text"), ("mode", "select")])
        self.assertEqual((c0["customConfig"][0]["min"], c0["customConfig"][0]["max"], c0["customConfig"][0]["value"]), (0, 100, "50"))
        self.assertEqual(c0["customConfig"][1]["maxLength"], 8)
        self.assertEqual(c0["customConfig"][2]["options"], ["a", "b"])
        self.assertNotIn("serial_offline", json.dumps(st))
        self.assertNotIn("evtSeq", c0)  # nothing happened yet
        # the debug lines did not hurt, and valid JSON of another type is silently ignored
        self.assertIsNone(host.proc.poll())
        self.assertNotIn("Traceback", host.output())

    def test_battery_rules(self):
        ard = self.arduino()
        host = self.host(ard.path)
        self.wait(lambda: bare_status(host.port)[1].get("battery") == 87, "battery 87", host=host)
        for value, expected in ((55, 55), (0, None), (250, 100), (-1, None), (1, 1), (None, None)):
            ard.battery = value  # None: the member is missing altogether
            ard.send_state()
            if expected is None:
                self.wait(lambda: "battery" not in bare_status(host.port)[1], "battery %r omitted" % (value,), host=host)
            else:
                self.wait(lambda: bare_status(host.port)[1].get("battery") == expected, "battery %r -> %r" % (value, expected), host=host)
        ard.battery = 0
        ard.send_state()
        self.wait(lambda: "battery" not in bare_status(host.port)[1], "battery omitted for 0", host=host)
        self.assertNotIn("battery", host.status())  # also in the authenticated document

    def test_identical_snapshots_do_not_bump_seq_but_changes_do(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        time.sleep(0.5)
        seq = bare_status(host.port)[1]["seq"]
        for _ in range(20):
            ard.send_state()
        time.sleep(0.5)
        self.assertEqual(bare_status(host.port)[1]["seq"], seq, "identical snapshots must not change seq")
        ard.components[0]["puzzle"]["step"] = 2
        ard.send_state()
        self.wait(lambda: bare_status(host.port)[1]["seq"] > seq, "seq bump after a change", host=host)
        self.assertEqual(bare_status(host.port)[1]["components"][0]["puzzle"]["step"], 2)

    def test_limits_and_defaults_of_snapshots(self):
        comps = [make_component(i, "N" * 40, "R" * 40, "x" * 40) for i in range(6)]  # too many and too long
        comps[0]["name"] = "Taste-\u00e4\u00f6\u00fc" * 4                              # multi-byte text cut on a character boundary
        del comps[1]["room"]
        comps[1]["name"] = ""
        comps[2]["feed"] = "ftp://nope"
        comps[2]["actions"] = ["a" * 30, "ok", ""] + ["b%d" % i for i in range(12)]
        comps[2]["errors"] = ["e%d" % i for i in range(9)]
        ard = self.arduino(comps, junk=False)
        host = self.host(ard.path)
        st = self.wait(lambda: (lambda s: s if len(s["components"]) == 4 else None)(bare_status(host.port)[1]), "4 components", host=host)
        self.assertEqual(len(st["components"]), 4)  # MAX_LOCAL_COMPONENTS
        self.assertEqual(len(st["components"][3]["name"].encode()), 32)
        self.assertTrue(len(st["components"][0]["name"].encode()) <= 32)
        st["components"][0]["name"].encode("utf-8")  # still valid UTF-8 (json.loads would have failed otherwise)
        self.assertEqual((st["components"][1]["name"], st["components"][1]["room"]), ("Komponente", "unzugeordnet"))
        self.assertNotIn("feed", st["components"][2])
        self.assertEqual(st["components"][2]["actions"][:2], ["ok", "b0"])
        self.assertEqual(len(st["components"][2]["actions"]), 8)
        self.assertEqual(len(st["components"][2]["errors"]), 4)


    def test_burst_of_snapshots_in_one_read_is_applied_in_order(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        burst = b""
        for step in range(1, 61):  # 60 snapshots and 60 debug lines in a few reads: none of the later ones may be lost
            ard.components[0]["puzzle"]["step"] = step % 4
            burst += b"free ram %d\n" % step + ard.state_line() + b"\n" + b'{"type":"log","n":%d}\n' % step
        ard.components[0]["puzzle"]["step"] = 2
        burst += ard.state_line() + b"\n"
        ard.write(burst)
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == 2, "last snapshot of the burst", host=host)

    def test_getstate_is_sent_on_connect_and_every_five_seconds(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        self.assertGreaterEqual(len(ard.commands("getState")), 1)  # on connect
        ard.clear()
        time.sleep(11.5)
        n = len(ard.commands("getState"))
        self.assertIn(n, (2, 3), "expected a poll about every 5 s while the Arduino answers, got %d in 11.5 s" % n)
        self.assertEqual([m for m in ard.commands() if m["type"] != "getState"], [])


class CommandTests(SerialHostTestCase):
    def test_action_reaches_the_arduino_and_the_new_state_shows_up(self):
        ard = self.arduino()
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        ard.clear()
        res = host.action(1, "next")  # host index 1 is the sketch's component id 3
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}), res)
        self.wait(lambda: ard.commands("action"), "action line at the Arduino", host=host)
        self.assertEqual(ard.commands("action"), [{"type": "action", "id": 3, "action": "next"}])
        self.assertIn('{"type":"action","id":3,"action":"next"}', ard.raw_lines())  # exact old wire format
        ev = ard.commands("event")
        self.assertEqual(len(ev), 1)
        self.assertEqual((ev[0]["id"], ev[0]["message"]), (3, 'Aktion "next" ausgefuehrt'))
        # the host asks for the resulting state right behind the command lines (not just with its 5 s poll)
        self.wait(lambda: len(ard.commands()) >= 3, "action, event, getState", 2, host)
        self.assertEqual([m["type"] for m in ard.commands()][:3], ["action", "event", "getState"])
        st = self.wait(lambda: (lambda s: s if s["components"][1]["puzzle"]["step"] == 1 else None)(bare_status(host.port)[1]),
                       "new state", host=host)
        self.assertEqual(st["components"][0]["puzzle"]["step"], 0)
        self.assertEqual((st["components"][1]["evtSeq"], st["components"][1]["evtMsg"]), (1, 'Aktion "next" ausgefuehrt'))
        # a second component and the error flag travel the same way
        self.assertEqual(host.action(0, "fail")["status"], 200)
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["errors"] == ["sensor_timeout"], "error shown", host=host)
        self.assertEqual(ard.commands("action")[-1], {"type": "action", "id": 7, "action": "fail"})

    def test_plan_action_config_and_error_codes(self):
        ard = self.arduino()
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        host.action(0, "next")
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == 1, "step 1", host=host)
        ard.clear()
        res = host.post("/plan-action", {"id": 0, "action": "reset"})
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}))
        self.wait(lambda: ard.commands("planAction"), "planAction line", host=host)
        self.assertEqual(ard.commands("planAction")[0], {"type": "planAction", "id": 7, "action": "reset"})
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == 0, "reset applied", host=host)
        # config values are validated by the core against the announced schema, then forwarded as strings
        res = host.post("/config", {"id": 1, "config": {"brightness": 70, "mode": "b", "label": "abc"}})
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}), res)
        self.wait(lambda: len(ard.commands("setConfig")) == 3, "three setConfig lines", host=host)
        got = {(m["id"], m["key"], m["value"]) for m in ard.commands("setConfig")}
        self.assertEqual(got, {(3, "brightness", "70"), (3, "mode", "b"), (3, "label", "abc")})
        vals = {d["key"]: d["value"] for d in self.wait(lambda: (lambda s: s if s["components"][1]["customConfig"][0]["value"] == "70" else None)(bare_status(host.port)[1]), "config echoed", host=host)["components"][1]["customConfig"]}
        self.assertEqual(vals, {"brightness": "70", "label": "abc", "mode": "b"})
        # rejected / invalid requests never reach the Arduino
        ard.clear()
        self.assertEqual(host.post("/config", {"id": 0, "config": {"brightness": 500}})["status"], 400)
        self.assertEqual(host.post("/action", {"id": 9, "action": "next"})["body"]["code"], "bad_id")
        self.assertEqual(host.post("/plan-action", {"id": 0, "action": "explode"})["body"]["code"], "bad_action")
        time.sleep(0.3)
        self.assertEqual([m for m in ard.commands() if m["type"] not in ("getState",)], [])

    def test_silent_arduino_at_start_lists_nothing_and_is_asked_again(self):
        ard = self.arduino(answer=False)
        host = self.host(ard.path)
        time.sleep(1.0)
        st = host.status()
        self.assertEqual(st["components"], [])  # nothing known yet
        self.assertEqual(host.post("/action", {"id": 0, "action": "next"})["body"]["code"], "bad_id")
        self.assertEqual(ard.commands("action"), [])
        self.wait(lambda: len(ard.commands("getState")) >= 2, "repeated getState while waiting for the first state", 6, host)


class PersistenceTests(SerialHostTestCase):
    def test_identity_forwarded_persisted_and_restored_after_restart(self):
        state = Path(self.tmp) / "state"
        ard = self.arduino()
        host = self.host(ard.path, state_dir=state)
        st = self.wait(lambda: (lambda s: s if len(s["components"]) == 2 else None)(bare_status(host.port)[1]), "components", host=host)
        did, boot = st["did"], st["boot"]
        ard.clear()
        res = host.post("/config", {"id": 0, "name": "Neu", "room": "Raum-Z"})  # identity alone is persisted at once, on its own
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}), res)
        self.assertEqual(self.state_dir_json(host)["ov"], [{"id": 7, "name": "Neu", "room": "Raum-Z"}])
        res = host.post("/config", {"id": 0, "riddleId": "rid-9"})
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}), res)
        self.assertEqual(self.state_dir_json(host)["ov"], [{"id": 7, "name": "Neu", "room": "Raum-Z", "riddleId": "rid-9"}])
        self.wait(lambda: ard.commands("setIdentity") and ard.commands("setRiddleId"), "identity commands", host=host)
        self.assertEqual(ard.commands("setIdentity")[0], {"type": "setIdentity", "id": 7, "name": "Neu", "room": "Raum-Z"})
        self.assertEqual(ard.commands("setRiddleId")[0], {"type": "setRiddleId", "id": 7, "value": "rid-9"})
        st = self.wait(lambda: (lambda s: s if s["components"][0]["name"] == "Neu" else None)(host.status()), "new identity in status", host=host)
        self.assertEqual((st["components"][0]["room"], st["components"][0]["riddleId"]), ("Raum-Z", "rid-9"))
        # persisted atomically on the PC
        saved = self.state_dir_json(host)
        self.assertEqual(saved["ov"], [{"id": 7, "name": "Neu", "room": "Raum-Z", "riddleId": "rid-9"}])  # written immediately
        self.assertEqual([p for p in os.listdir(state) if p.endswith(".tmp")], [])
        self.assertEqual(host.stop(), 0)
        # the cache of the last reported component list (throttled while running) is flushed at shutdown
        self.assertEqual([(k["id"], k["name"], k["room"]) for k in self.state_dir_json(host)["known"]], [(7, "Neu", "Raum-Z"), (3, "Laser", "Raum-A")])
        self.assertEqual([p for p in os.listdir(state) if p.endswith(".tmp")], [])
        ard.close()

        # restart: the new sketch run reports the OLD identity and ignores setIdentity (no storage of its own)
        old = self.arduino(apply_identity=False)
        host2 = self.host(old.path, state_dir=state)  # no --did: the derived one must be stable
        st2 = self.wait(lambda: (lambda s: s if len(s["components"]) == 2 else None)(bare_status(host2.port)[1]), "components after restart", host=host2)
        self.assertEqual(st2["did"], did)
        self.assertEqual(st2["boot"], boot + 1)
        self.assertEqual((st2["components"][0]["name"], st2["components"][0]["room"], st2["components"][0]["riddleId"]), ("Neu", "Raum-Z", "rid-9"))
        self.assertEqual(old.components[0]["name"], "Tuer")  # the Arduino itself still reports the old name
        self.wait(lambda: old.commands("setIdentity") and old.commands("setRiddleId"), "identity re-sent after reconnect", host=host2)
        self.assertEqual(old.commands("setIdentity")[0], {"type": "setIdentity", "id": 7, "name": "Neu", "room": "Raum-Z"})
        self.assertEqual(old.commands("setRiddleId")[0]["value"], "rid-9")
        self.assertEqual(old.commands("setIdentity").__len__(), 1, "once per connection, not on every snapshot")
        self.assertEqual(host2.stop(), 0)

    def test_stored_components_are_listed_offline_and_skeletons_survive_a_silent_arduino(self):
        state = Path(self.tmp) / "state"
        ard = self.arduino()
        host = self.host(ard.path, state_dir=state)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        sk = {"planId": "p1", "layers": [{"id": "L1", "lanes": []}]}
        res = host.post("/plan-skeleton", {"room": "Raum-A", "baseRev": 0, "sk": sk})
        self.assertEqual(res["status"], 200, res)
        rev = res["body"]["rev"]
        self.assertEqual(host.stop(), 0)
        ard.close()

        # the Arduino does not answer at all after the restart: the room (and its skeleton) must still be known
        mute = self.arduino(answer=False)
        host2 = self.host(mute.path, state_dir=state)
        st = host2.status()
        self.assertEqual([(c["name"], c["room"], c["riddleId"]) for c in st["components"]], [("Tuer", "Raum-A", "door-v1"), ("Laser", "Raum-A", "laser-v1")])
        for c in st["components"]:
            self.assertIn("serial_offline", c["errors"])
        self.assertEqual(host2.post("/action", {"id": 0, "action": "next"})["body"]["code"], "rejected")
        self.assertEqual(mute.commands("action"), [])
        blob = host2.node("skeleton", "Raum-A")
        self.assertEqual((blob["room"], blob["rev"], blob["sk"]), ("Raum-A", rev, sk))
        # the Arduino finally answers: offline marker disappears
        mute.answer = True
        mute.send_state()
        self.wait(lambda: "serial_offline" not in json.dumps(bare_status(host2.port)[1]), "back online", host=host2)

    def test_plan_slice_verbatim_forwarded_and_persisted(self):
        state = Path(self.tmp) / "state"
        ard = self.arduino()
        host = self.host(ard.path, state_dir=state)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        plan = '{"z":1,"a":[1,2,{"k":"v"}],"m":2.50}'  # key order and number text must survive byte for byte
        ard.clear()
        res = host.post("/plan", {"id": 1, "plan": json.loads(plan)})
        self.assertEqual((res["status"], res["body"]), (200, {"ok": True}), res)
        self.wait(lambda: ard.commands("setPlan"), "setPlan line", host=host)
        self.assertEqual(ard.commands("setPlan")[0]["id"], 3)
        self.assertEqual(ard.commands("setPlan")[0]["plan"], json.loads(plan))
        text, st = bare_status(host.port)
        self.assertIn('"plan":{"z":1,"a":[1,2,{"k":"v"}],"m":2.5}', text)  # em_client re-serialises 2.50 as 2.5; the rest is verbatim
        self.assertEqual(st["components"][1]["plan"], json.loads(plan))
        self.assertNotIn("plan", st["components"][0])
        saved = self.state_dir_json(host)
        self.assertEqual([o for o in saved["ov"] if o["id"] == 3][0]["plan"], '{"z":1,"a":[1,2,{"k":"v"}],"m":2.5}')
        # too large plans are refused by the core and never forwarded
        ard.clear()
        self.assertEqual(host.post("/plan", {"id": 1, "plan": {"big": "x" * 600}})["status"], 413)
        time.sleep(0.3)
        self.assertEqual(ard.commands("setPlan"), [])
        self.assertEqual(host.stop(), 0)
        ard.close()

        # restart with a sketch that forgot its plan: the stored slice is shown and pushed again
        fresh = self.arduino(apply_identity=False)
        host2 = self.host(fresh.path, state_dir=state)
        text2 = self.wait(lambda: (lambda t: t if len(json.loads(t)["components"]) == 2 else None)(bare_status(host2.port)[0]), "components", host=host2)
        self.assertIn('"plan":{"z":1,"a":[1,2,{"k":"v"}],"m":2.5}', text2)
        self.wait(lambda: fresh.commands("setPlan"), "plan re-sent", host=host2)
        # clearing: setPlan with null, shown as no plan, persisted as cleared
        fresh.clear()
        self.assertEqual(host2.post("/plan", {"id": 1, "plan": None})["status"], 200)
        self.wait(lambda: fresh.commands("setPlan"), "setPlan null", host=host2)
        self.assertEqual(fresh.commands("setPlan")[0], {"type": "setPlan", "id": 3, "plan": None})
        self.wait(lambda: "plan" not in bare_status(host2.port)[1]["components"][1], "plan cleared in status", host=host2)

    def test_did_is_derived_once_and_explicit_did_wins(self):
        state = Path(self.tmp) / "state"
        ard = self.arduino()
        h1 = self.host(ard.path, state_dir=state)
        did = bare_status(h1.port)[1]["did"]
        self.assertEqual((state / "did").read_text().strip(), did)
        self.assertEqual(h1.stop(), 0)
        h2 = self.host(ard.path, state_dir=state)
        self.assertEqual(bare_status(h2.port)[1]["did"], did)
        self.assertEqual(h2.stop(), 0)
        h3 = self.host(ard.path, state_dir=Path(self.tmp) / "other", did="0A1b2c3d4e5F")  # upper case is accepted and normalised
        self.assertEqual(bare_status(h3.port)[1]["did"], "0a1b2c3d4e5f")
        # a new state dir with the same serial port name derives the same id (hostname + port name), so a lost state dir does not
        # make the room see a "new" device; another port name gives another id
        h4 = self.host(ard.path, state_dir=Path(self.tmp) / "other2")
        self.assertEqual(bare_status(h4.port)[1]["did"], did)
        h5 = self.host(self.arduino().path, state_dir=Path(self.tmp) / "other3")
        self.assertNotEqual(bare_status(h5.port)[1]["did"], did)


class RobustnessTests(SerialHostTestCase):
    def snapshot_ok(self, host, ard, step):
        ard.components[0]["puzzle"]["step"] = step
        ard.send_state()
        return self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == step, "snapshot step %d" % step, 8, host)

    def test_oversized_invalid_and_hostile_lines_are_survived(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        self.snapshot_ok(host, ard, 1)
        deep = "[" * 40 + "]" * 40
        nodes = "[" + ",".join(["1"] * 5000) + "]"
        hostile = [
            b'{"type":"state","pad":"' + b"A" * 100_000 + b'"}\n',                                 # 100 KB line (limit is 16 KB)
            b"x" * 70_000 + b"\n",                                                                    # junk without JSON start
            b'{"type":"state","components":' + b"[" * 70_000 + b"\n",                                  # long and invalid
            b'{"type":"state","components":[{"id":1,"name":"a"}\n',                                    # truncated JSON
            b'{not json at all}\n', b'{"type":"state"}\n', b'{"type":"state","components":"x"}\n',
            b'{"type":"state","components":[1,2,3]}\n',
            b'{"type":"state","components":[{"id":300,"name":"a","room":"b"}]}\n',                   # id out of range
            b'{"type":"state","components":[{"id":1,"name":"a","room":"b"},{"id":1,"name":"c","room":"d"}]}\n',  # duplicate id
            ('{"type":"state","components":[{"id":1,"name":"a","room":"b","plan":%s}]}\n' % deep).encode(),  # too deep
            ('{"type":"state","components":[{"id":1,"name":"a","room":"b","tip":%s}]}\n' % nodes).encode(),  # too many nodes
            b'{"type":"state","components":[{"id":1,"name":"a\xff","room":"b"}]}\n',                  # invalid UTF-8
            b"\x00\x01\x02\xff\xfe\n" * 1000,
            b"{" * 2_000_000,                                                                         # 2 MB without any newline
            b"\n",
        ]
        for line in hostile:
            ard.write(line)
        ard.write(b"x" * 2_000_000)  # more garbage, still no newline: joins the previous (discarded) line
        ard.write(b"\n")
        time.sleep(0.5)
        self.assertIsNone(host.proc.poll(), "host died:\n" + host.output()[-2000:])
        st = bare_status(host.port)[1]
        self.assertEqual(len(st["components"]), 2)                          # none of the hostile snapshots was applied
        self.assertEqual(st["components"][0]["puzzle"]["step"], 1)
        self.assertEqual(st["components"][0]["name"], "Tuer")
        self.snapshot_ok(host, ard, 2)                                       # and the line is in sync again
        self.assertIn("longer than", host.output())
        self.assertNotIn("Traceback", host.output())

    def test_babbling_arduino_does_not_grow_memory_or_block_http(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        self.snapshot_ok(host, ard, 1)
        pid = host.proc.pid
        for _ in range(3):  # warm up allocator pools
            ard.write(b"{" + b"y" * 20000 + b"\n")
        time.sleep(0.5)
        base_rss, base_hwm = rss_kb(pid), rss_kb(pid, "VmHWM")
        chunk = b"{" + b"w" * 1_000_000
        for _ in range(100):  # 100 MB without a single newline: must be discarded after 16 KB, not collected
            ard.write(chunk)
        ard.write(b"\n")
        time.sleep(0.3)
        self.assertLess(rss_kb(pid, "VmHWM") - base_hwm, 2 * 1024, "a 100 MB line without newline grew the host by %d kB" % (rss_kb(pid, "VmHWM") - base_hwm))
        valid = [json.dumps({"type": "state", "battery": 50 + i, "components": ard.components}, separators=(",", ":")).encode() + b"\n" for i in range(40)]
        stop = threading.Event()
        written = [0]

        def babble():
            rnd = random.Random(1)
            kinds = [lambda: os.urandom(8192), lambda: b"{" + b"q" * 120_000, lambda: b"z" * 50_000 + b"\n",
                     lambda: rnd.choice(valid), lambda: b'{"type":"state","components":[' * 400 + b"\n",
                     lambda: b"\n" * 2000, lambda: b'{"type":"getState"}\n' * 50]
            while not stop.is_set():
                data = rnd.choice(kinds)()
                written[0] += len(data)
                if not ard.write(data):
                    break

        t = threading.Thread(target=babble, daemon=True)
        t.start()
        latencies = []
        try:
            end = time.monotonic() + 6
            while time.monotonic() < end:
                t0 = time.monotonic()
                text, st = bare_status(host.port)
                latencies.append(time.monotonic() - t0)
                self.assertEqual(len(st["components"]), 2)
                time.sleep(0.2)
            peak_rss = rss_kb(pid)
            res = host.action(0, "next")  # authenticated POST while the line babbles
            self.assertEqual(res["status"], 200, res)
        finally:
            stop.set()
            t.join(10)
        print("\n    babble: %.1f MB written, RSS %d -> %d kB (peak growth %d kB), worst HTTP latency %.3f s"
              % (written[0] / 1e6, base_rss, peak_rss, rss_kb(pid, "VmHWM") - base_hwm, max(latencies)), file=sys.stderr)
        self.assertGreater(written[0], 5_000_000, "babbler too slow to be meaningful")
        self.assertLess(max(latencies), 2.0, "HTTP stalled while the line babbled: %r" % latencies)
        self.assertLess(peak_rss - base_rss, 6 * 1024, "RSS grew %d kB (base %d kB)" % (peak_rss - base_rss, base_rss))
        self.assertLess(rss_kb(pid, "VmHWM") - base_hwm, 8 * 1024, "peak RSS grew by %d kB" % (rss_kb(pid, "VmHWM") - base_hwm))
        self.assertIsNone(host.proc.poll(), "host died:\n" + host.output()[-2000:])
        ard.write(b"\n")
        ard.battery = 61
        ard.components[0]["puzzle"]["step"] = 3
        ard.send_state()
        st = self.wait(lambda: (lambda s: s if s["components"][0]["puzzle"]["step"] == 3 and s.get("battery") == 61 else None)(bare_status(host.port)[1]),
                       "valid state after the babble", 10, host)
        self.assertEqual(host.stop(), 0)

    def test_a_regular_file_is_never_opened_as_serial_port(self):
        target = Path(self.tmp) / "not-a-tty.txt"
        target.write_text("precious\n")
        host = self.host(target)
        time.sleep(1.5)
        self.assertEqual(target.read_text(), "precious\n")
        self.assertEqual(bare_status(host.port)[1]["components"], [])
        self.assertIn("not a terminal device", host.output())
        self.assertEqual(host.stop(), 0)


class BackpressureTests(SerialHostTestCase):
    FLOOD = """
import {Device} from %r;
const d = new Device('127.0.0.1:' + process.argv[1], process.argv[2]);
await d.init();
let ok = 0, last = null;
for (let i = 0; i < Number(process.argv[3]); i++) {
  for (;;) {
    const r = await d.post('/plan', {id: 0, plan: {n: i, pad: 'p'.repeat(420)}});
    if (r.status === 429) { await new Promise(r => setTimeout(r, 300)); continue; }
    last = r.status; if (r.status === 200) ok++; break;
  }
}
console.log(JSON.stringify({ok, last}));
""" % str(CLIENT)

    def test_a_sketch_that_stops_reading_never_blocks_the_host(self):
        ard = self.arduino(junk=False)
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        pid = host.proc.pid
        base = rss_kb(pid)
        ard.paused = True  # the host writes into a full tty buffer from now on
        count = 60
        flood = subprocess.Popen(["node", "--input-type=module", "-e", self.FLOOD, str(host.port), host.token, str(count)], stdout=subprocess.PIPE, text=True)
        self.cleanup.add(flood.stdout.close)
        self.cleanup.add(lambda: flood.poll() is None and flood.kill())
        latencies = []

        def probe():
            t0 = time.monotonic()
            self.assertEqual(len(bare_status(host.port)[1]["components"]), 2)
            latencies.append(time.monotonic() - t0)

        while flood.poll() is None:  # ~600 B setPlan lines pile up: 8 KB kernel buffer, 8 KB queue
            probe()
            time.sleep(0.1)
        self.assertEqual(json.loads(flood.stdout.read()), {"ok": count, "last": 200})
        self.assertIn("queue full", host.output())
        # still blocked: after 5 s without progress the queued output is dropped (stale commands must not arrive minutes late)
        end = time.monotonic() + 9
        while "no progress" not in host.output() and time.monotonic() < end:
            probe()
            time.sleep(0.1)
        self.assertIn("no progress", host.output())
        self.assertLess(max(latencies), 1.0, "HTTP stalled while the serial output was blocked: %r" % max(latencies))
        self.assertLess(rss_kb(pid) - base, 2 * 1024)
        self.assertIsNone(host.proc.poll())
        # the sketch reads again (well within the 15 s offline limit): the operator's plan, which was dropped with the queue,
        # is pushed again, whatever the sketch receives is made of complete lines apart from at most one cut-off line per drop
        ard.paused = False
        ard.send_state()
        self.wait(lambda: ard.commands("setPlan") and ard.commands("setPlan")[-1]["plan"]["n"] == count - 1, "the latest plan reaches the sketch", 10, host)
        broken = []
        for line in ard.raw_lines():
            try:
                json.loads(line)
            except ValueError:
                broken.append(line)
        self.assertLessEqual(len(broken), 3, broken)
        self.assertNotIn("serial_offline", json.dumps(bare_status(host.port)[1]))
        ard.clear()
        self.assertEqual(host.action(0, "next")["status"], 200)
        self.wait(lambda: ard.commands("action"), "commands work again", host=host)
        self.assertEqual(host.stop(), 0)


class ReconnectTests(SerialHostTestCase):
    def point(self, link, target):
        tmp = link + ".new"
        if os.path.lexists(tmp):
            os.unlink(tmp)
        os.symlink(target, tmp)
        os.replace(tmp, link)

    def test_host_starts_before_the_device_exists_and_survives_unplugging(self):
        link = str(Path(self.tmp) / "ttyFAKE0")
        host = self.host(link)  # the port does not exist yet
        time.sleep(1.2)
        self.assertEqual(bare_status(host.port)[1]["components"], [])
        self.assertIn("cannot open", host.output())

        first = self.arduino()
        self.point(link, first.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "first device found by the back-off retry", 15, host)
        self.assertEqual(host.action(0, "next")["status"], 200)
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == 1, "action works", host=host)

        # unplug: the pty disappears completely
        seq_online = bare_status(host.port)[1]["seq"]
        first.close()
        self.wait(lambda: "lost" in host.output(), "loss noticed", host=host)
        st = self.wait(lambda: (lambda s: s if all("serial_offline" in c["errors"] for c in s["components"]) else None)(bare_status(host.port)[1]),
                       "components marked offline", host=host)
        self.assertEqual(len(st["components"]), 2)
        seq_offline = st["seq"]
        self.assertGreater(seq_offline, seq_online, "going offline is an observable change: seq must move so managers refetch")
        self.assertEqual(host.post("/action", {"id": 0, "action": "next"})["body"]["code"], "rejected")
        log_lines = host.output().count("cannot open")
        time.sleep(4)  # several failed re-open attempts, with growing delays (no hot loop, no log flood)
        self.assertLess(host.output().count("cannot open") - log_lines, 6)
        self.assertIsNone(host.proc.poll())

        # plug in a different board at the same name: re-opened automatically, state and commands work again
        second = self.arduino([make_component(5, "Kamera", "Raum-A", "cam-v1")], battery=33)
        self.point(link, second.path)
        st = self.wait(lambda: (lambda s: s if [c["name"] for c in s["components"]] == ["Kamera"] and "serial_offline" not in json.dumps(s) else None)(
            bare_status(host.port)[1]), "second device reconnected", 20, host)
        self.assertEqual(st["battery"], 33)
        self.assertGreater(st["seq"], seq_offline)
        self.assertTrue(second.commands("getState"), "getState right after re-opening")
        ack = host.action(0, "next")
        self.assertEqual(ack["status"], 200, ack)
        self.wait(lambda: second.commands("action"), "action reaches the second device", host=host)
        self.assertEqual(second.commands("action")[0], {"type": "action", "id": 5, "action": "next"})
        self.wait(lambda: bare_status(host.port)[1]["components"][0]["puzzle"]["step"] == 1, "state of the second device", host=host)
        self.assertEqual(host.stop(), 0)

    def test_open_attempts_back_off(self):
        """Counts the open() calls of the host on a path it cannot use (a regular file), with inotify: the log is throttled
        on purpose and cannot show a hot retry loop."""
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        if not hasattr(libc, "inotify_init1"):
            self.skipTest("no inotify")
        target = Path(self.tmp) / "regular.txt"
        target.write_text("x")
        fd = libc.inotify_init1(os.O_NONBLOCK)
        self.assertGreaterEqual(fd, 0)
        self.cleanup.add(lambda: os.close(fd))
        IN_OPEN = 0x20
        self.assertGreaterEqual(libc.inotify_add_watch(fd, str(target).encode(), IN_OPEN), 0)
        host = self.host(target)
        t0 = time.monotonic()
        opens, times = 0, []
        while time.monotonic() - t0 < 9:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                data = os.read(fd, 4096)
                n = len(data) // 16  # struct inotify_event without a name is 16 bytes
                opens += n
                times += [time.monotonic() - t0] * n
        # attempts at ~0, 0.5, 1.5, 3.5, 7.5 s (500 ms doubling up to 5 s); a hot loop would show hundreds
        self.assertTrue(3 <= opens <= 7, "open attempts in 9 s: %d at %r" % (opens, times))
        self.assertGreater(times[-1] - times[-2], 2.0, "delays must have grown: %r" % times)

    def test_device_that_answers_late_is_polled_until_it_does(self):
        ard = self.arduino(answer=False)
        host = self.host(ard.path)
        self.wait(lambda: len(ard.commands("getState")) >= 2, "getState retries", 8, host)
        ard.answer = True
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "first answer accepted", 8, host)

    def test_silent_arduino_goes_offline_and_comes_back(self):
        ard = self.arduino()
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        seq_online = bare_status(host.port)[1]["seq"]
        ard.answer = False
        st = self.wait(lambda: (lambda s: s if all("serial_offline" in c["errors"] for c in s["components"]) else None)(bare_status(host.port)[1]),
                       "marked offline after 15 s of silence", 25, host)
        self.assertGreater(st["seq"], seq_online)
        self.assertGreaterEqual(len(ard.commands("getState")), 3)  # polled every 5 s / 1 s
        ard.answer = True
        ard.send_state()
        self.wait(lambda: "serial_offline" not in json.dumps(bare_status(host.port)[1]), "back online", host=host)


class NetworkTests(SerialHostTestCase):
    def test_second_host_in_the_same_room_discovers_the_first_and_syncs_skeletons(self):
        a_ard = self.arduino()
        b_ard = self.arduino([make_component(1, "Kamera", "Raum-A", "cam-v1")])
        a = self.host(a_ard.path, did="a1a1a1a1a1a1", name="A")
        b = self.host(b_ard.path, did="b2b2b2b2b2b2", name="B")
        self.wait(lambda: len(bare_status(a.port)[1]["components"]) == 2 and len(bare_status(b.port)[1]["components"]) == 1, "both hosts have state", host=a)
        peers_b = self.wait(lambda: (lambda p: p if any(x["did"] == "a1a1a1a1a1a1" for x in p["peers"]) else None)(b.node("peers")),
                            "B discovers A through the discovery port", 15, b)
        entry = [x for x in peers_b["peers"] if x["did"] == "a1a1a1a1a1a1"][0]
        self.assertEqual((entry["ip"], entry["port"], entry["proto"]), ("127.0.0.1", a.port, 2))
        self.assertEqual(peers_b["self"]["did"], "b2b2b2b2b2b2")
        peers_a = self.wait(lambda: (lambda p: p if any(x["did"] == "b2b2b2b2b2b2" for x in p["peers"]) else None)(a.node("peers")),
                            "A discovers B", 15, a)
        self.assertEqual([x["did"] for x in peers_a["peers"]], ["b2b2b2b2b2b2"])
        # a skeleton written to A for the shared room is adopted by B (the Device core syncs it, the serial adapter only hosts the rooms)
        sk = {"planId": "shared", "layers": [{"id": "L", "lanes": [{"id": "A"}]}]}
        res = a.post("/plan-skeleton", {"room": "Raum-A", "baseRev": 0, "sk": sk})
        self.assertEqual(res["status"], 200, res)
        blob = self.wait(lambda: (lambda r: r if r.get("room") == "Raum-A" else None)(b.node("skeleton", "Raum-A")), "skeleton synced to B", 20, b)
        self.assertEqual((blob["rev"], blob["sk"]), (res["body"]["rev"], sk))
        # B reports the sync as an event to its component
        self.wait(lambda: any("Raum-Ablaufplan" in m["message"] for m in b_ard.commands("event")), "event for the adopted skeleton", host=b)
        self.assertEqual(a.stop(), 0)
        self.assertEqual(b.stop(), 0)

    def test_manager_html_is_served_with_its_hash(self):
        page = Path(self.tmp) / "ui.html"
        page.write_text("<!doctype html><title>x</title><p>serial host</p>\n")
        host = self.host(self.arduino().path, extra=["--manager-html", str(page)])
        status, headers, body = http_get(host.port, "/")
        self.assertEqual((status, body), (200, page.read_bytes()))
        import hashlib
        h = hashlib.sha256(page.read_bytes()).hexdigest()[:8]
        self.assertEqual(headers.get("ETag"), '"%s"' % h)
        self.assertEqual(json.loads(http_get(host.port, "/security.json")[2])["uih"], h)

    def test_serves_the_repository_manager_html_by_default(self):
        host = self.host(self.arduino().path)
        status, headers, body = http_get(host.port, "/")
        self.assertEqual(status, 200)
        self.assertEqual(body, (ROOT / "src" / "manager" / "manager.html").read_bytes())


class EditTokenTests(SerialHostTestCase):
    """--edit-token / ESCAPE_EDIT_TOKEN (PROTOCOL.md 3.1): plans may only be sent with the edit key set."""

    def setUp(self):
        super().setUp()
        self.edit_token = "edit-" + secrets.token_hex(10)

    def start(self, **kwargs):
        ard = self.arduino()
        host = self.host(ard.path, **kwargs)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        return ard, host

    def test_edit_state_is_published_and_unset_without_the_option(self):
        _, host = self.start(edit_token=self.edit_token)
        sec = host.security()
        self.assertEqual((sec["token"], sec["edit"]), ("custom", "custom"))
        self.assertIn("edit", sec["caps"])
        self.assertEqual(bare_status(host.port)[1]["edit"], "custom")
        self.assertIn("edit=custom", host.output())
        self.assertNotIn(self.edit_token, host.output())  # the token is never logged
        self.assertEqual(http_get(host.port, "/edit.json")[0], 400)  # the nonce is mandatory
        status, _, body = http_get(host.port, "/edit.json?nonce=0123456789abcdef")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["doc"], {"proto": 2, "edit": "custom"})

        _, plain = self.start()  # no --edit-token (and none in the environment of the tests)
        sec = plain.security()
        self.assertEqual(sec["edit"], "unset")
        self.assertIn("edit", sec["caps"])  # the capability is the device's, the state is the token's
        self.assertEqual(bare_status(plain.port)[1]["edit"], "unset")
        status, _, body = http_get(plain.port, "/edit.json?nonce=0123456789abcdef")
        self.assertEqual(status, 404, body)
        self.assertEqual(json.loads(body)["code"], "edit_unset")
        self.assertIn("edit=unset", plain.output())

    def test_edit_proof_equals_the_reference_vector(self):
        vec = json.loads((ROOT / "test" / "fixtures" / "proto2" / "vectors.json").read_text())
        _, host = self.start(did=vec["did"], token=vec["edit"]["normalToken"], edit_token=vec["edit"]["editToken"])
        proof = vec["edit"]["proof"]
        status, _, body = http_get(host.port, "%s?nonce=%s" % (proof["path"], proof["nonce"]))
        self.assertEqual(status, proof["status"])
        self.assertEqual(body.decode(), proof["frame"])  # byte for byte what the Node reference produced

    def test_plan_writes_need_the_edit_key_set(self):
        ard, host = self.start(edit_token=self.edit_token)
        plan = {"lane": "A1", "layer": "L1"}
        ard.clear()
        # normal keys: authenticated, then refused (sealed with the normal response key)
        res = host.sealed_post("/plan", {"id": 1, "plan": plan}, "normal")
        self.assertEqual((res["status"], res["code"], res["sealedWith"]), (403, "edit_required", "normal"), res)
        res = host.sealed_post("/plan-skeleton", {"room": "Raum-A"}, "normal")
        self.assertEqual((res["status"], res["code"]), (403, "edit_required"), res)
        time.sleep(0.3)
        self.assertEqual(ard.commands("setPlan"), [])  # nothing reached the Arduino
        # edit keys: the plan goes through, the answer is sealed with the edit response key
        res = host.sealed_post("/plan", {"id": 1, "plan": plan}, "edit")
        self.assertEqual((res["status"], res["plain"], res["sealedWith"]), (200, {"ok": True}, "edit"), res)
        self.wait(lambda: ard.commands("setPlan"), "setPlan line", host=host)
        self.assertEqual(ard.commands("setPlan")[0], {"type": "setPlan", "id": 3, "plan": plan})
        # the wrong edit token does not authenticate
        res = host.sealed_post("/plan", {"id": 1, "plan": None}, "edit", edit_token="wrong-edit-token-" + "x" * 8)
        self.assertEqual((res["status"], res["code"]), (401, "auth_failed"), res)
        self.assertEqual(bare_status(host.port)[1]["components"][1]["plan"], plan)
        # everything else stays on the normal token: actions work with it, and "k":"e" on such a path is a bad envelope
        ard.clear()
        res = host.sealed_post("/action", {"id": 0, "action": "next"}, "normal")
        self.assertEqual((res["status"], res["plain"]), (200, {"ok": True}), res)
        self.wait(lambda: ard.commands("action"), "action line", host=host)
        res = host.sealed_post("/action", {"id": 0, "action": "next"}, "edit")
        self.assertEqual((res["status"], res["code"]), (400, "bad_envelope"), res)
        # a normal-key request cannot be turned into an edit one by adding the member either
        res = host.sealed_post("/plan", {"id": 1, "plan": None}, "normal", k="e")
        self.assertEqual(res["status"], 401, res)

    def test_without_an_edit_token_the_normal_key_may_send_plans_and_k_e_fails(self):
        ard, host = self.start()
        plan = {"lane": "A2", "layer": "L1"}
        res = host.sealed_post("/plan", {"id": 0, "plan": plan}, "normal")
        self.assertEqual((res["status"], res["plain"]), (200, {"ok": True}), res)
        self.wait(lambda: ard.commands("setPlan"), "setPlan line", host=host)
        res = host.sealed_post("/plan", {"id": 0, "plan": plan}, "edit", edit_token="some-edit-token-" + "y" * 8)
        self.assertEqual((res["status"], res["code"]), (401, "auth_failed"), res)  # "k":"e" towards a device without edit token

    def test_environment_variable_and_precedence_of_the_option(self):
        env_token = "env-edit-" + secrets.token_hex(10)
        env = dict(os.environ, ESCAPE_EDIT_TOKEN=env_token)
        _, host = self.start(env=env)  # (Host strips ESCAPE_*_TOKEN from the environment unless it is given one)
        self.assertEqual(host.security()["edit"], "custom")
        res = host.sealed_post("/plan", {"id": 0, "plan": None}, "edit", edit_token=env_token)
        self.assertEqual(res["status"], 200, res)
        res = host.sealed_post("/plan", {"id": 0, "plan": None}, "normal")
        self.assertEqual((res["status"], res["code"]), (403, "edit_required"), res)
        # the option wins over the environment
        _, host2 = self.start(env=env, edit_token=self.edit_token)
        res = host2.sealed_post("/plan", {"id": 0, "plan": None}, "edit", edit_token=env_token)
        self.assertEqual((res["status"], res["code"]), (401, "auth_failed"), res)
        res = host2.sealed_post("/plan", {"id": 0, "plan": None}, "edit")
        self.assertEqual(res["status"], 200, res)


class SetupTests(SerialHostTestCase):
    """--setup: POST /setup (PROTOCOL.md 5.8) with an in-memory sink; without it the device has no such path."""

    def start(self, **kwargs):
        ard = self.arduino()
        host = self.host(ard.path, **kwargs)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        return ard, host

    def test_without_setup_there_is_no_cap_and_the_path_is_404(self):
        _, host = self.start()
        sec = host.security()
        self.assertNotIn("setup", sec["caps"])
        self.assertEqual(sec["setupAp"], "none")
        self.assertIn("setup=off", host.output())
        conn = http.client.HTTPConnection("127.0.0.1", host.port, timeout=5)
        try:
            conn.request("POST", "/setup", body=json.dumps({"v": 2, "t": 1, "iv": "AAECAwQFBgcICQoL", "ct": "x" * 40}))
            resp = conn.getresponse()
            self.assertEqual(resp.status, 404, resp.read())
        finally:
            conn.close()
        self.assertEqual(http_get(host.port, "/setup")[0], 404)  # the portal does not exist on a PC either

    def test_setup_advertised_and_wifi_change_is_recorded_without_secrets(self):
        _, host = self.start(setup=True)
        sec = host.security()
        self.assertIn("setup", sec["caps"])
        self.assertEqual(sec["setupAp"], "none")
        self.assertIn("setup=on", host.output())
        pw, secret_token = "wifi-password-" + secrets.token_hex(6), "new-token-" + secrets.token_hex(10)
        res = host.sealed_post("/setup", {"ssid": "Venue-WLAN", "pass": pw}, "normal")  # no edit token: the normal key may do it
        self.assertEqual((res["status"], res["plain"], res["sealedWith"]), (200, {"ok": True}, "normal"), res)
        self.wait(lambda: "setup: wifi ssid=Venue-WLAN" in host.output(), "wifi log line", host=host)
        res = host.sealed_post("/setup", {"token": secret_token}, "normal")
        self.assertEqual(res["status"], 200, res)
        self.wait(lambda: "setup: token changed" in host.output(), "token log line", host=host)
        log = host.output()
        self.assertNotIn(pw, log)
        self.assertNotIn(secret_token, log)
        self.assertNotIn(host.token, log)

    def test_setup_validation_and_empty_change(self):
        _, host = self.start(setup=True)
        for bad in ({"token": "short"}, {"token": "has a space in it"}, {"ssid": "EscapeSetup-123456", "pass": ""}, {"ssid": "Venue", "pass": "tiny"},
                    {"ssid": "only-ssid"}, {"editToken": "x" * 129}, {}):
            res = host.sealed_post("/setup", bad, "normal")
            self.assertEqual((res["status"], res["code"]), (400, "bad_request"), (bad, res))
        self.assertEqual(host.security()["token"], "custom")
        self.assertNotIn("setup: ", host.output())  # nothing was applied

    def test_token_change_takes_effect_without_restart_and_can_be_removed(self):
        _, host = self.start(setup=True)
        old, new = host.token, "changed-" + secrets.token_hex(10)
        res = host.sealed_post("/setup", {"token": new}, "normal")  # answered with the OLD keys
        self.assertEqual((res["status"], res["plain"]), (200, {"ok": True}), res)
        self.assertEqual(host.security()["token"], "custom")
        # the new token works for the reference client, the old one does not
        host.token = new
        self.assertEqual(host.status()["token"], "custom")
        res = host.sealed_post("/action", {"id": 0, "action": "next"}, "normal", token=old)
        self.assertEqual((res["status"], res["plain"]), (401, None), res)  # sealed with the device's (new) key: "token does not match"
        res = host.sealed_post("/action", {"id": 0, "action": "next"}, "normal", token=new)
        self.assertEqual(res["status"], 200, res)
        # "" removes it: the public default token applies again
        res = host.sealed_post("/setup", {"token": ""}, "normal", token=new)
        self.assertEqual(res["status"], 200, res)
        self.assertEqual(host.security()["token"], "default")
        default = "EscapeManager-Private-WLAN-Default-Token"
        res = host.sealed_post("/action", {"id": 0, "action": "next"}, "normal", token=default)
        self.assertEqual(res["status"], 200, res)
        self.assertIn("setup: token removed", host.output())

    def test_edit_token_set_and_removed_over_the_network(self):
        ard, host = self.start(setup=True)
        edit = "pushed-edit-" + secrets.token_hex(8)
        self.assertEqual(host.security()["edit"], "unset")
        res = host.sealed_post("/setup", {"editToken": edit}, "normal")
        self.assertEqual(res["status"], 200, res)
        self.assertEqual(host.security()["edit"], "custom")
        self.assertEqual(bare_status(host.port)[1]["edit"], "custom")
        # from now on plans need the edit key set, and so does /setup itself
        res = host.sealed_post("/plan", {"id": 0, "plan": None}, "normal")
        self.assertEqual((res["status"], res["code"]), (403, "edit_required"), res)
        res = host.sealed_post("/setup", {"ssid": "Venue-WLAN", "pass": ""}, "normal")
        self.assertEqual((res["status"], res["code"]), (403, "edit_required"), res)
        self.assertNotIn("setup: wifi", host.output())
        res = host.sealed_post("/plan", {"id": 0, "plan": None}, "edit", edit_token=edit)
        self.assertEqual((res["status"], res["sealedWith"]), (200, "edit"), res)
        status, _, body = http_get(host.port, "/edit.json?nonce=0123456789abcdef")
        self.assertEqual(status, 200, body)
        # removing it (sealed with the edit keys) returns to "the normal token may send plans"
        res = host.sealed_post("/setup", {"editToken": ""}, "edit", edit_token=edit)
        self.assertEqual(res["status"], 200, res)
        self.assertEqual(host.security()["edit"], "unset")
        self.assertEqual(http_get(host.port, "/edit.json?nonce=0123456789abcdef")[0], 404)
        res = host.sealed_post("/plan", {"id": 0, "plan": None}, "normal")
        self.assertEqual(res["status"], 200, res)
        self.assertIn("setup: edit token removed", host.output())

    def test_setup_with_an_edit_token_requires_the_edit_keys(self):
        _, host = self.start(setup=True, edit_token="startup-edit-" + secrets.token_hex(8))
        res = host.sealed_post("/setup", {"ssid": "Venue-WLAN", "pass": ""}, "normal")
        self.assertEqual((res["status"], res["code"]), (403, "edit_required"), res)
        res = host.sealed_post("/setup", {"ssid": "Venue-WLAN", "pass": ""}, "edit")
        self.assertEqual(res["status"], 200, res)
        self.wait(lambda: "setup: wifi ssid=Venue-WLAN" in host.output(), "wifi log line", host=host)


class CommandLineTests(SerialHostTestCase):
    def run_host(self, *args, timeout=15):
        return subprocess.run([str(BIN)] + list(args), capture_output=True, text=True, timeout=timeout, cwd=str(ROOT))

    def test_usage_errors_exit_with_2_and_help_with_0(self):
        self.assertEqual(self.run_host().returncode, 2)  # --serial missing
        self.assertEqual(self.run_host("--serial", "/dev/null", "--baud", "12345").returncode, 2)
        self.assertEqual(self.run_host("--serial", "/dev/null", "--http-port", "99999").returncode, 2)
        self.assertEqual(self.run_host("--serial", "/dev/null", "--did", "xyz", "--state-dir", self.tmp, "--no-mdns", "--http-port", str(free_port())).returncode, 2)
        self.assertEqual(self.run_host("--serial", "/dev/null", "--bogus").returncode, 2)
        self.assertEqual(self.run_host("--serial", "/dev/null", "--token", "short").returncode, 2)
        help_run = self.run_host("--help")
        self.assertEqual(help_run.returncode, 0)
        self.assertIn("usage", help_run.stdout)
        for flag in ("--edit-token", "--setup", "ESCAPE_EDIT_TOKEN"):
            self.assertIn(flag, help_run.stdout)

    def test_token_options_are_validated(self):
        ok_token = "valid-token-" + secrets.token_hex(8)
        for args, what in ((("--edit-token", "short"), "edit token"), (("--edit-token", "x" * 129), "edit token"),
                           (("--edit-token", "has a space in it"), "edit token"), (("--edit-token", "umlaut-\u00e4-token"), "edit token"),
                           (("--token", "has a space in it"), "token"), (("--token", "x" * 129), "token")):
            proc = self.run_host("--serial", "/dev/null", "--no-mdns", "--http-port", str(free_port()), "--state-dir", self.tmp, *args)
            self.assertEqual(proc.returncode, 2, (args, proc.stdout, proc.stderr))
            self.assertIn("the " + what + " ", proc.stderr)
            self.assertNotIn(args[1], proc.stderr)  # the offending token is not echoed
        proc = self.run_host("--serial", "/dev/null", "--edit-token")  # value missing
        self.assertEqual(proc.returncode, 2, proc.stderr)
        # the environment is validated like the option
        proc = subprocess.run([str(BIN), "--serial", "/dev/null", "--state-dir", self.tmp], capture_output=True, text=True, timeout=15, cwd=str(ROOT),
                              env=dict(os.environ, ESCAPE_EDIT_TOKEN="tiny"))
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("the edit token ", proc.stderr)
        # a valid edit token alone starts the host (the program then only fails later, on the serial device)
        ard = self.arduino()
        host = self.host(ard.path, edit_token=ok_token, setup=True)
        self.assertEqual(host.security()["edit"], "custom")

    def test_busy_http_port_is_a_fatal_error(self):
        port = free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("0.0.0.0", port))
        blocker.listen(1)
        self.cleanup.add(blocker.close)
        proc = self.run_host("--serial", "/dev/null", "--ip", "127.0.0.1", "--no-mdns", "--udp-port", str(UDP_PORT), "--http-port", str(port),
                             "--state-dir", self.tmp)
        self.assertEqual(proc.returncode, 1, proc.stdout + proc.stderr)
        self.assertIn("cannot listen on HTTP port %d" % port, proc.stderr)

    def test_sigint_and_sigterm_stop_cleanly_and_sigpipe_is_ignored(self):
        ard = self.arduino()
        host = self.host(ard.path)
        self.wait(lambda: len(bare_status(host.port)[1]["components"]) == 2, "components", host=host)
        host.proc.send_signal(signal.SIGPIPE)
        time.sleep(0.3)
        self.assertIsNone(host.proc.poll(), "SIGPIPE must be ignored")
        self.assertEqual(host.stop(signal.SIGINT), 0)
        self.assertIn("shutting down", host.output())
        host2 = self.host(ard.path)
        self.assertEqual(host2.stop(signal.SIGTERM), 0)

    def test_default_state_dir_and_token_from_the_environment(self):
        ard = self.arduino()
        port = free_port()
        token = "env-token-" + secrets.token_hex(10)
        env = dict(os.environ, XDG_STATE_HOME=self.tmp + "/xdg", ESCAPE_AUTH_TOKEN=token)
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        log = open(LOG_DIR / ("default-state-%d.log" % port), "w")
        self.cleanup.add(log.close)
        proc = subprocess.Popen([str(BIN), "--serial", ard.path, "--ip", "127.0.0.1", "--no-mdns", "--udp-port", str(UDP_PORT), "--http-port", str(port)],
                                env=env, stdout=log, stderr=subprocess.STDOUT, cwd=str(ROOT))
        _live_procs.append(proc)
        self.cleanup.add(lambda: proc.poll() is None and (proc.terminate(), proc.wait(8)))
        self.wait(lambda: http_get(port, "/security.json", 2)[0] == 200, "host up")
        self.wait(lambda: len(bare_status(port)[1]["components"]) == 2, "components")
        sub = "dev_pts_" + ard.path.rsplit("/", 1)[1]
        base = Path(self.tmp) / "xdg" / "escape-serial-host" / sub
        self.wait(lambda: (base / "did").exists(), "default state dir %s" % base)
        self.assertEqual(oct(base.stat().st_mode & 0o777), "0o700")
        # the environment token is in effect: the reference client succeeds with it only
        out = subprocess.run(["node", str(CLIENT), "127.0.0.1:%d" % port, "--token", token, "status"], capture_output=True, text=True, timeout=30)
        self.assertEqual(out.returncode, 0, out.stderr)
        bad = subprocess.run(["node", str(CLIENT), "127.0.0.1:%d" % port, "--token", "wrong-token-" + "x" * 12, "status"], capture_output=True, text=True, timeout=30)
        self.assertNotEqual(bad.returncode, 0)
        self.assertEqual(json.loads(http_get(port, "/security.json")[2])["token"], "custom")

    def test_run_script_builds_and_starts(self):
        proc = subprocess.run([str(ROOT / "run_serial_host.sh"), "--help"], capture_output=True, text=True, timeout=300, cwd="/")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("usage", proc.stdout)
        self.assertTrue(BIN.exists())


if __name__ == "__main__":
    unittest.main(verbosity=2)
