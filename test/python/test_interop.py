"""Interop: the C++ reference simulator and the Python simulator talk to each other and to the Node client.

Skipped (with the reason) when ``node`` or the C++ simulator binary is missing. Build the binary once with

    cd /games/Projekte/EscapeManager && mkdir -p .sim-build && g++ -std=c++17 -O1 -pthread \\
        -o .sim-build/escape_component_sim extras/sim/escape_component_sim.cpp extras/sim/OpenSslCryptoBackend.cpp \\
        src/net/Device.cpp src/net/Net.cpp src/protocol/*.cpp -lcrypto

(``run_sim.sh`` is not suitable: it ``exec``s the simulator.)  Both simulators run on loopback with
``--ip 127.0.0.1 --no-mdns``, distinct HTTP ports and device ids, the SAME discovery port and a random token.
"""

from __future__ import annotations

import json
import secrets
import shutil
import subprocess
import sys
import time

import pytest

import escape_component as ec
from helpers import DISCOVERY_PORT, Manager, ROOT, free_http_port, get, wait_for

CPP_SIM = ROOT / ".sim-build" / "escape_component_sim"
PY_SIM = ROOT / "extras" / "sim" / "escape_component_sim.py"
NODE_CLIENT = ROOT / "scripts" / "em_client.mjs"
BUILD_HINT = ("cd %s && mkdir -p .sim-build && g++ -std=c++17 -O1 -pthread -o .sim-build/escape_component_sim "
              "extras/sim/escape_component_sim.cpp extras/sim/OpenSslCryptoBackend.cpp src/net/Device.cpp src/net/Net.cpp "
              "src/protocol/*.cpp -lcrypto" % ROOT)

pytestmark = pytest.mark.interop

SK1 = '{"planId":"p1","layers":[{"id":"L1","lanes":[]}]}'
SK2 = '{"planId":"p1","layers":[{"id":"L1","lanes":[{"id":"A"}]}]}'


def node_client(port, token, *args, check=True):
    """Runs scripts/em_client.mjs and returns (returncode, parsed JSON or text).

    A POST answered with the plain (unauthenticated) 429 of the per-source budget is retried after a pause:
    on loopback every test shares one source address (and failed authentication costs 4 tokens)."""
    for _ in range(40):
        proc = node_process(port, token, *args)
        out = proc.stdout.strip()
        limited = '"rate_limited"' in out and '"authenticated": false' in out and args and args[0] in ("post", "action")
        if not limited:
            break
        time.sleep(0.5)
    return finish(proc, args, check)


def node_process(port, token, *args):
    return subprocess.run(["node", str(NODE_CLIENT), "127.0.0.1:%d" % port, "--token", token] + list(args),
                          capture_output=True, text=True, timeout=30)


def finish(proc, args, check):
    out = proc.stdout.strip()
    try:
        parsed = json.loads(out)
    except ValueError:
        parsed = out
    if check:
        assert proc.returncode == 0, "em_client %s failed: %s %s" % (args, proc.stdout, proc.stderr)
    return proc.returncode, parsed


class Sims:
    def __init__(self, tmp_path_factory):
        self.token = "interop-" + secrets.token_hex(12)
        self.procs = []
        self.logs = []
        self.cpp_port, self.py_port = free_http_port(), free_http_port()
        while self.py_port == self.cpp_port:
            self.py_port = free_http_port()
        self.cpp_did, self.py_did = "c0c0c0c0c0c0", "9090909090a1"
        common = ["--ip", "127.0.0.1", "--no-mdns", "--udp-port", str(DISCOVERY_PORT), "--token", self.token,
                  "--component", "Laser:Raum-I:laser-v1", "--component", "Kamera:Raum-I:cam-v1"]
        self.start([str(CPP_SIM), "--http-port", str(self.cpp_port), "--did", self.cpp_did,
                    "--state-dir", str(tmp_path_factory.mktemp("cpp"))] + common, self.cpp_port, "cpp")
        self.start([sys.executable, str(PY_SIM), "--http-port", str(self.py_port), "--did", self.py_did,
                    "--state-dir", str(tmp_path_factory.mktemp("py"))] + common, self.py_port, "py")

    def start(self, argv, port, name):
        log = open("/tmp/opencode/interop-%s-%d.log" % (name, port), "w")
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, cwd=str(ROOT))
        self.procs.append(proc)
        self.logs.append(log)

        def up():
            if proc.poll() is not None:
                raise AssertionError("%s simulator exited with %s (see %s)" % (name, proc.returncode, log.name))
            try:
                return get(port, "/security.json").status == 200
            except OSError:
                return False

        assert wait_for(up, 20), "%s simulator did not come up" % name

    def stop(self):
        for proc in self.procs:  # only the processes started here
            if proc.poll() is None:
                proc.terminate()
        for proc in self.procs:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        for log in self.logs:
            log.close()


@pytest.fixture(scope="module")
def sims(tmp_path_factory):
    if shutil.which("node") is None:
        pytest.skip("interop test needs `node` (>= 18) for scripts/em_client.mjs")
    if not CPP_SIM.exists():
        pytest.skip("C++ simulator binary missing (%s). Build it once with: %s" % (CPP_SIM, BUILD_HINT))
    s = Sims(tmp_path_factory)
    yield s
    s.stop()


def test_both_simulators_report_the_same_document_shapes(sims):
    _, cpp_sec = node_client(sims.cpp_port, sims.token, "security")
    _, py_sec = node_client(sims.py_port, sims.token, "security")
    assert set(cpp_sec) == set(py_sec)
    assert cpp_sec["kdf"] == py_sec["kdf"] and cpp_sec["limits"] == py_sec["limits"] and cpp_sec["caps"] == py_sec["caps"]
    assert (cpp_sec["proto"], cpp_sec["pmin"], cpp_sec["fw"], cpp_sec["ui"]) == (py_sec["proto"], py_sec["pmin"], py_sec["fw"], py_sec["ui"])
    assert cpp_sec["token"] == py_sec["token"] == "custom" and py_sec["writable"] is True
    _, cpp_status = node_client(sims.cpp_port, sims.token, "status")
    _, py_status = node_client(sims.py_port, sims.token, "status")
    assert set(cpp_status) == set(py_status)
    assert len(py_status["components"]) == len(cpp_status["components"]) == 2
    for cpp_comp, py_comp in zip(cpp_status["components"], py_status["components"]):
        assert set(cpp_comp) == set(py_comp), (sorted(cpp_comp), sorted(py_comp))
        assert cpp_comp["actions"] == py_comp["actions"] and cpp_comp["planActions"] == py_comp["planActions"]
        assert cpp_comp["customConfig"] == py_comp["customConfig"] and cpp_comp["puzzle"] == py_comp["puzzle"]
        assert cpp_comp["tip"] == py_comp["tip"]
    assert py_status["battery"] == cpp_status["battery"] == 100
    assert py_status["components"][0]["riddleId"] == "laser-v1" and py_status["components"][1]["riddleId"] == "cam-v1"


def test_each_sees_the_other_in_peers_json(sims):
    def sees(port, did):
        _, peers = node_client(port, sims.token, "peers")
        return did in [p["did"] for p in peers["peers"]]

    assert wait_for(lambda: sees(sims.cpp_port, sims.py_did), 20), "the C++ simulator never saw the Python simulator"
    assert wait_for(lambda: sees(sims.py_port, sims.cpp_did), 20), "the Python simulator never saw the C++ simulator"
    _, peers = node_client(sims.py_port, sims.token, "peers")
    other = next(p for p in peers["peers"] if p["did"] == sims.cpp_did)
    assert other["ip"] == "127.0.0.1" and other["port"] == sims.cpp_port and other["proto"] == 2
    assert peers["self"]["did"] == sims.py_did and peers["self"]["port"] == sims.py_port


def test_skeleton_written_to_cpp_reaches_python(sims):
    _, r = node_client(sims.cpp_port, sims.token, "post", "/plan-skeleton",
                       '{"room":"Raum-I","baseRev":0,"sk":%s}' % SK1)
    assert r["status"] == 200 and r["body"]["rev"] == 1 and r["body"]["hash"] == ec.hex8(ec.fnv1a32(SK1))

    def synced():
        _, doc = node_client(sims.py_port, sims.token, "skeleton", "Raum-I")
        return isinstance(doc, dict) and doc.get("rev") == 1

    assert wait_for(synced, 25), "the skeleton written to the C++ simulator never reached the Python simulator"
    cpp, py = Manager(sims.cpp_port, sims.token).init(), Manager(sims.py_port, sims.token).init()
    cpp_resp, cpp_doc = cpp.get("/plan-skeleton.json", "room=Raum-I")
    py_resp, py_doc = py.get("/plan-skeleton.json", "room=Raum-I")
    assert cpp_doc is not None and py_doc is not None
    assert json.loads(py_doc)["sk"] == json.loads(SK1)
    assert cpp_doc.split(b',"sk":')[1] == py_doc.split(b',"sk":')[1] == SK1.encode() + b"}"     # byte-for-byte on both


def test_skeleton_written_to_python_reaches_cpp(sims):
    _, r = node_client(sims.py_port, sims.token, "post", "/plan-skeleton",
                       '{"room":"Raum-I","baseRev":1,"sk":%s}' % SK2)
    assert r["status"] == 200 and r["body"]["rev"] == 2

    def synced():
        _, doc = node_client(sims.cpp_port, sims.token, "skeleton", "Raum-I")
        return isinstance(doc, dict) and doc.get("rev") == 2

    assert wait_for(synced, 25), "the skeleton written to the Python simulator never reached the C++ simulator"
    cpp, py = Manager(sims.cpp_port, sims.token).init(), Manager(sims.py_port, sims.token).init()
    cpp_doc = cpp.get("/plan-skeleton.json", "room=Raum-I")[1]
    py_doc = py.get("/plan-skeleton.json", "room=Raum-I")[1]
    assert cpp_doc == py_doc                                          # identical blobs, byte for byte
    assert cpp_doc.split(b',"sk":')[1] == SK2.encode() + b"}"
    # a stale writer is told about the conflict by both implementations
    for port in (sims.cpp_port, sims.py_port):
        _, r = node_client(port, sims.token, "post", "/plan-skeleton", '{"room":"Raum-I","baseRev":1,"sk":{"x":1}}')
        assert r["status"] == 409 and r["body"]["code"] == "rev_conflict" and r["body"]["rev"] == 2


def test_action_post_works_against_the_python_simulator(sims):
    _, r = node_client(sims.py_port, sims.token, "action", "0", "next_step")
    assert r["status"] == 200 and r["authenticated"] is True and r["body"] == {"ok": True}
    _, status = node_client(sims.py_port, sims.token, "status")
    comp = status["components"][0]
    assert comp["puzzle"]["step"] == 1 and comp["puzzle"]["state"] == "Schritt 1 von 5"
    assert comp["evtSeq"] >= 1 and "next_step" in comp["evtMsg"]
    _, r = node_client(sims.py_port, sims.token, "action", "0", "bogus")
    assert r["status"] == 422 and r["body"]["code"] == "rejected"
    _, r = node_client(sims.py_port, sims.token, "post", "/plan-action", '{"id":1,"action":"complete"}')
    assert r["status"] == 200
    _, status = node_client(sims.py_port, sims.token, "status")
    assert status["components"][1]["puzzle"]["step"] == 5 and "tip" not in status["components"][1]  # an empty tip is omitted
    # the same protocol calls behave the same against the C++ reference
    _, cpp = node_client(sims.cpp_port, sims.token, "action", "0", "next_step")
    assert cpp["status"] == 200 and cpp["body"] == {"ok": True}


def test_config_and_plan_roundtrip_against_the_python_simulator(sims):
    _, r = node_client(sims.py_port, sims.token, "post", "/config",
                       '{"id":0,"name":"Laser-Neu","config":{"brightness":"70","difficulty":"hard"},"room":"Raum-I"}')
    assert r["status"] == 200
    _, r = node_client(sims.py_port, sims.token, "post", "/config", '{"id":0,"config":{"brightness":"700"}}')
    assert r["status"] == 400 and r["body"]["code"] == "bad_request"
    _, r = node_client(sims.py_port, sims.token, "post", "/plan", '{"id":0,"plan":{"lane":"A","n":[1,2]}}')
    assert r["status"] == 200
    _, status = node_client(sims.py_port, sims.token, "status")
    comp = status["components"][0]
    assert comp["name"] == "Laser-Neu" and comp["plan"] == {"lane": "A", "n": [1, 2]}
    values = {c["key"]: c["value"] for c in comp["customConfig"]}
    assert values["brightness"] == "70" and values["difficulty"] == "hard"


def test_python_client_library_talks_to_the_cpp_simulator(sims):
    # our crypto against the C++ implementation (not just against the Node vectors)
    m = Manager(sims.cpp_port, sims.token).init()
    assert m.post("/action", {"id": 1, "action": "next_step"}).status == 200
    r = m.post("/plan", '{"id":1,"plan":{"k":"v"}}')
    assert (r.status, r.body) == (200, {"ok": True})
    assert m.get_json("/status.json")["components"][1]["plan"] == {"k": "v"}
    r = m.post("/action", {"id": 7, "action": "x"})
    assert (r.status, r.body["code"]) == (400, "bad_id")
    r = m.post("/action", {"id": 0, "action": "x"}, t=(m.device_time() + 1_000_000) & 0xFFFFFFFF)
    assert (r.status, r.body["code"]) == (409, "stale_time") and "time" in r.body


def test_wrong_token_is_rejected_by_both(sims):
    for port in (sims.cpp_port, sims.py_port):
        rc, out = node_client(port, "not-the-right-token-123", "post", "/action", '{"id":0,"action":"next_step"}', check=False)
        assert rc != 0                                            # the client cannot even decrypt the 401
        proc = node_process(port, "not-the-right-token-123", "status")
        assert proc.returncode != 0 and "MAC mismatch" in proc.stderr
        wrong = Manager(port, "not-the-right-token-123").init()
        r = wrong.post("/action", {"id": 0, "action": "next_step"})
        assert r.status == 401 and not r.authenticated
        response, doc = wrong.get("/status.json")
        assert doc is None                                         # frames do not verify with another token


def test_ui_hash_matches_what_is_served(sims):
    for port in (sims.cpp_port, sims.py_port):
        _, out = node_client(port, sims.token, "ui")
        assert "OK" in out and "MISMATCH" not in out, out


# ---- differential test: the same plaintext commands, answered by the C++ reference and by Python ------------------

SKELETON_DEEP_OK = '{"a":' + "[" * 14 + "]" * 14 + "}"
SKELETON_TOO_DEEP = '{"a":' + "[" * 15 + "]" * 15 + "}"

DIFFERENTIAL_CASES = [
    ("/action", '{"id":0,"action":"next_step"}'), ("/action", '{"action":"next_step"}'), ("/action", '{"id":0,"action":"bogus"}'),
    ("/action", '{"id":2,"action":"x"}'), ("/action", '{"id":256,"action":"x"}'), ("/action", '{"id":"1","action":"x"}'),
    ("/action", '{"id":1.5,"action":"x"}'), ("/action", '{"id":-1,"action":"x"}'), ("/action", '{"id":null,"action":"x"}'),
    ("/action", '{"id":1.0,"action":"reset"}'), ("/action", '{"id":0}'), ("/action", '{"id":0,"action":5}'),
    ("/action", '{"id":0,"action":""}'), ("/action", '{"id":0,"action":"' + "a" * 25 + '"}'),
    ("/action", '{"id":0,"action":"' + "\\u00e9" * 12 + '"}'), ("/action", '{"id":0,"action":"' + "\\u00e9" * 13 + '"}'),
    ("/action", ""), ("/action", "[]"), ("/action", "{broken"), ("/action", " " * 3000), ("/action", '{"id":0,"action":"reset"} x'),
    ("/action", '{"id":0,"id":9,"action":"reset"}'), ("/action", '{"a":' + "[" * 9 + "]" * 9 + "}"),
    ("/plan-action", '{"id":0,"action":"reset"}'), ("/plan-action", '{"id":1,"action":"complete"}'),
    ("/plan-action", '{"id":0,"action":"explode"}'), ("/plan-action", '{"id":9,"action":"reset"}'),
    ("/config", '{"id":0,"config":{"brightness":"70","label":"' + "x" * 40 + '"}}'),
    ("/config", '{"id":0,"name":"X","config":{"brightness":"101"}}'),
    ("/config", '{"id":0,"name":"Neu","room":"Raum-I","riddleId":"' + "r" * 33 + '"}'),
    ("/config", '{"id":0,"name":"OnlyName"}'), ("/config", '{"id":0,"name":"","room":"R"}'),
    ("/config", '{"id":0,"name":"' + "n" * 33 + '","room":"R"}'), ("/config", '{"id":0,"config":{"nokey":"1"}}'),
    ("/config", '{"id":0,"config":[1]}'), ("/config", '{"id":0,"riddleId":""}'), ("/config", '{"id":0,"config":{"brightness":70}}'),
    ("/config", '{"id":0,"config":{"brightness":70.5}}'), ("/config", '{"id":0,"config":{"brightness":null}}'),
    ("/config", '{"id":0,"config":{"difficulty":"hard","label":"ok"}}'), ("/config", '{"id":0,"config":{"difficulty":"x"}}'),
    ("/config", '{"id":0,"slave":true}'), ("/config", '{"id":0,"config":{"brightness":"+1"}}'),
    ("/config", '{"id":0,"name":"Laser","room":"Raum-I","riddleId":"laser-v1"}'),
    ("/plan", '{"id":0,"plan":{"planId":"p","layer":"L1","lane":"A"}}'), ("/plan", '{"id":0,"plan":null}'),
    ("/plan", '{"id":0,"plan":[1]}'), ("/plan", '{"id":0,"plan":{"a":"' + "x" * 520 + '"}}'), ("/plan", '{"id":7,"plan":null}'),
    ("/plan", '{"id":"0","plan":null}'), ("/plan", '{"id":0,"plan":{broken}'), ("/plan", ""),
    ("/plan", '{"id":1,"plan":{"a":"' + "x" * 504 + '"}}'), ("/plan", '{"id":1,"plan":{"a":"' + "x" * 505 + '"}}'),
    ("/plan", '{"id":0,"plan":{"a":' + "[" * 14 + "]" * 14 + "}}"), ("/plan", '{"id":0,"plan":{"a":' + "[" * 15 + "]" * 15 + "}}"),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":0,"sk":' + SK1 + "}"), ("/plan-skeleton", '{"room":"Raum-I","baseRev":0,"sk":' + SK1 + "}"),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":0,"sk":' + SK2 + "}"), ("/plan-skeleton", '{"room":"Raum-I","baseRev":1,"sk":' + SK2 + "}"),
    ("/plan-skeleton", '{"room":"Nowhere","baseRev":0,"sk":' + SK1 + "}"), ("/plan-skeleton", '{"room":"Raum-I","sk":' + SK1 + "}"),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":2,"sk":[1]}'), ("/plan-skeleton", '{"room":"Raum-I","baseRev":2,"sk":{"x":"' + "a" * 7000 + '"}}'),
    ("/plan-skeleton", '{"room":"","baseRev":0,"sk":{}}'), ("/plan-skeleton", '{"room":"Raum-I","baseRev":-1,"sk":{}}'),
    ("/plan-skeleton", ""), ("/plan-skeleton", " " * 7000), ("/plan-skeleton", '{"room":"Raum-I","baseRev":2,"sk":{ "a" : 1.50 }}'),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":2,"sk":{ "a" : 1.50 }}'), ("/plan-skeleton", '{"room":"Raum-I","baseRev":3,"sk":null}'),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":4294967296,"sk":{"z":1}}'), ("/plan-skeleton", '{"room":"Raum-I","baseRev":1.0,"sk":{"z":1}}'),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":3,"sk":' + SKELETON_DEEP_OK + "}"),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":4,"sk":' + SKELETON_TOO_DEEP + "}"),
    ("/plan-skeleton", '{"room":"Raum-I","baseRev":4,"sk":{"b":"\\ud800"}}'), ("/plan-skeleton", '{"baseRev":4,"room":"Raum-I","sk":{"o":1}}'),
]


@pytest.fixture(scope="module")
def isolated_sims(tmp_path_factory):
    """Two simulators with DIFFERENT tokens so they never sync with each other: identical command sequences."""
    if shutil.which("node") is None:
        pytest.skip("interop test needs `node` (>= 18)")
    if not CPP_SIM.exists():
        pytest.skip("C++ simulator binary missing (%s). Build it once with: %s" % (CPP_SIM, BUILD_HINT))
    s = Sims.__new__(Sims)
    s.procs, s.logs = [], []
    s.cpp_port, s.py_port = free_http_port(), free_http_port()
    while s.py_port == s.cpp_port:
        s.py_port = free_http_port()
    s.cpp_token, s.py_token = "diff-c-" + secrets.token_hex(10), "diff-p-" + secrets.token_hex(10)
    common = ["--ip", "127.0.0.1", "--no-mdns", "--udp-port", str(DISCOVERY_PORT),
              "--component", "Laser:Raum-I:laser-v1", "--component", "Kamera:Raum-I:cam-v1"]
    s.start([str(CPP_SIM), "--http-port", str(s.cpp_port), "--did", "c0c0c0c0c0c1", "--token", s.cpp_token,
             "--state-dir", str(tmp_path_factory.mktemp("dcpp"))] + common, s.cpp_port, "diff-cpp")
    s.start([sys.executable, str(PY_SIM), "--http-port", str(s.py_port), "--did", "9090909090a2", "--token", s.py_token,
             "--state-dir", str(tmp_path_factory.mktemp("dpy"))] + common, s.py_port, "diff-py")
    yield s
    s.stop()


def test_command_handlers_answer_exactly_like_the_cpp_reference(isolated_sims):
    """The same plaintext commands (valid, malformed, boundary) against both implementations: identical
    status and body (code AND error text), authenticated both times."""
    cpp = Manager(isolated_sims.cpp_port, isolated_sims.cpp_token).init()
    py = Manager(isolated_sims.py_port, isolated_sims.py_token).init()
    differences = []
    for path, body in DIFFERENTIAL_CASES:
        answers = []
        for manager in (cpp, py):
            r = manager.post(path, body, retry_stale=False)
            answers.append((r.status, r.body if r.authenticated else ("unauthenticated", r.response.body)))
        if answers[0] != answers[1]:
            differences.append((path, body[:80], answers))
        time.sleep(0.27)   # stays under the per-source budget (4/s) and keeps < 80 IVs in the 15 s replay window
    assert not differences, "\n".join("%s %r\n  C++: %s\n  Py : %s" % (p, b, a[0], a[1]) for p, b, a in differences)
    # the resulting device state agrees as well (skeleton blob byte for byte, component fields)
    cpp_blob = cpp.get("/plan-skeleton.json", "room=Raum-I")[1]
    py_blob = py.get("/plan-skeleton.json", "room=Raum-I")[1]
    assert cpp_blob is not None and cpp_blob == py_blob
    cpp_status, py_status = cpp.get_json("/status.json"), py.get_json("/status.json")
    for a, b in zip(cpp_status["components"], py_status["components"]):
        for key in ("name", "room", "riddleId", "plan", "puzzle", "customConfig", "errors", "tip"):
            assert a.get(key) == b.get(key), key


HTTP_REQUESTS = [
    b"GET /security.json HTTP/1.1\r\n\r\n", b"GET /nope HTTP/1.1\r\n\r\n", b"GET /favicon.ico HTTP/1.1\r\n\r\n",
    b"HEAD /security.json HTTP/1.1\r\n\r\n", b"HEAD /nope HTTP/1.1\r\n\r\n",
    b"OPTIONS /action HTTP/1.1\r\nOrigin: http://escapemanager.local\r\n\r\n", b"OPTIONS /nope HTTP/1.1\r\nOrigin: null\r\n\r\n",
    b"OPTIONS /action HTTP/1.1\r\nOrigin: http://evil.example\r\n\r\n", b"OPTIONS /action HTTP/1.1\r\n\r\n",
    b"BREW /x HTTP/1.1\r\n\r\n", b"GET / HTTP/9.9\r\n\r\n", b"GARBAGE\r\n\r\n", b"GET /" + b"a" * 600 + b" HTTP/1.1\r\n\r\n",
    b"GET / HTTP/1.1\r\nX: " + b"a" * 1100 + b"\r\n\r\n", b"POST /action HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
    b"GET /status.json HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd", b"POST /action HTTP/1.1\r\nContent-Length: 12289\r\n\r\n",
    b"POST /action HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n", b"POST /action HTTP/1.1\r\nContent-Length: -1\r\n\r\n",
    b"POST /action HTTP/1.1\r\nContent-Length: abc\r\n\r\n", b"POST /action HTTP/1.1\r\nContent-Length: 2147483648\r\n\r\n",
    b"POST /action HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", b"POST /action HTTP/1.1\r\n\r\n",
    b"POST /action HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}", b"POST /status.json HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    b"GET /status.json?nonce=short HTTP/1.1\r\n\r\n", b"GET /status.json?nonce=0123456789abcdef! HTTP/1.1\r\n\r\n",
    b"GET /plan-skeleton.json?room= HTTP/1.1\r\n\r\n", b"GET /status.json HTTP/1.0\r\n\r\n",
    b"GET /security.json HTTP/1.1\r\nOrigin: http://192.168.1.5:3000\r\n\r\n", b"GET /status.json HTTP/1.1\r\nOrigin: https://evil.example\r\n\r\n",
    b"GET /security.json HTTP/1.1\r\nOrigin: http://169.254.1.1\r\n\r\n",
]
SAME_HEADERS = ("content-type", "connection", "cache-control", "access-control-allow-origin", "access-control-allow-methods",
                "access-control-allow-headers", "access-control-max-age", "vary", "etag")


def test_http_layer_answers_like_the_cpp_reference(isolated_sims):
    """Parser errors, routes, HEAD/OPTIONS and CORS: same status, same relevant headers, same error bodies."""
    import gzip
    from helpers import exchange
    differences = []
    for request in HTTP_REQUESTS:
        cpp = exchange(isolated_sims.cpp_port, request)
        py = exchange(isolated_sims.py_port, request)
        same = cpp.status == py.status and all(cpp.headers.get(h) == py.headers.get(h) for h in SAME_HEADERS)
        if cpp.status != 200:
            same = same and cpp.body == py.body and cpp.headers.get("content-length") == py.headers.get("content-length")
        if not same:
            differences.append((request[:60], cpp.status, py.status, cpp.headers, py.headers, cpp.body[:80], py.body[:80]))
        time.sleep(0.1)
    assert not differences, "\n".join(map(str, differences))
    # the UI: the same document (the Python simulator serves it gzipped like the firmware), the same hash
    cpp, py = exchange(isolated_sims.cpp_port, b"GET / HTTP/1.1\r\n\r\n"), exchange(isolated_sims.py_port, b"GET / HTTP/1.1\r\n\r\n")
    assert cpp.status == py.status == 200 and cpp.headers["etag"] == py.headers["etag"]
    assert gzip.decompress(py.body) == cpp.body
    inm = b'GET / HTTP/1.1\r\nIf-None-Match: ' + cpp.headers["etag"].encode() + b"\r\n\r\n"
    assert exchange(isolated_sims.cpp_port, inm).status == exchange(isolated_sims.py_port, inm).status == 304
