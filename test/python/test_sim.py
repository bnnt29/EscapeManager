"""The Python simulator (extras/sim/escape_component_sim.py) as a process: CLI, behaviour, persistence."""

from __future__ import annotations

import secrets
import signal
import socket
import subprocess
import sys

import pytest

from helpers import DISCOVERY_PORT, Manager, ROOT, free_http_port, get, wait_for

SIM = ROOT / "extras" / "sim" / "escape_component_sim.py"


class Sim:
    def __init__(self, tmp_path, *extra, state_dir=None, token=None, port=None):
        self.token = token or "sim-" + secrets.token_hex(12)
        self.port = port or free_http_port()
        self.log_path = tmp_path / ("sim-%d.log" % self.port)
        self.log = open(self.log_path, "w")
        argv = [sys.executable, str(SIM), "--http-port", str(self.port), "--udp-port", str(DISCOVERY_PORT), "--ip", "127.0.0.1",
                "--no-mdns", "--token", self.token, "--state-dir", str(state_dir or tmp_path / "state")] + list(extra)
        self.proc = subprocess.Popen(argv, stdout=self.log, stderr=subprocess.STDOUT, cwd=str(ROOT))
        assert wait_for(self.up, 20), "simulator did not start: %s" % self.output()
        self.manager = Manager(self.port, self.token).init()

    def up(self):
        if self.proc.poll() is not None:
            raise AssertionError("simulator exited with %s: %s" % (self.proc.returncode, self.output()))
        try:
            return get(self.port, "/security.json").status == 200
        except OSError:
            return False

    def output(self):
        self.log.flush()
        return self.log_path.read_text()

    def status(self):
        return self.manager.get_json("/status.json")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGTERM)
        try:
            code = self.proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        self.log.close()
        return code


@pytest.fixture
def sim_factory(tmp_path):
    sims = []

    def factory(*extra, **kwargs):
        s = Sim(tmp_path, *extra, **kwargs)
        sims.append(s)
        return s

    yield factory
    for s in sims:
        s.stop()


def test_defaults_match_the_cpp_simulator(sim_factory):
    s = sim_factory()
    status = s.status()
    assert status["did"] == "5e%02x%02xabcdef" % (s.port >> 8, s.port & 255)         # derived from the port like the C++ sim
    assert status["battery"] == 100 and status["token"] == "custom" and status["port"] == s.port and status["ip"] == "127.0.0.1"
    assert [(c["name"], c["room"], c["riddleId"]) for c in status["components"]] == [
        ("Laser-1", "Raum-A", "sim-Laser-1"), ("Kamera-1", "Raum-A", "sim-Kamera-1")]
    comp = status["components"][0]
    assert comp["actions"] == ["reset", "next_step", "solve", "toggle_error", "drain_battery"]
    assert comp["planActions"] == ["reset", "complete"] and comp["errors"] == []
    assert comp["puzzle"] == {"step": 0, "totalSteps": 5, "state": "Schritt 0 von 5", "isHtml": False}
    assert comp["tip"] == "Naechste Aktion: next_step"
    assert [(d["key"], d["type"]) for d in comp["customConfig"]] == [("brightness", "range"), ("label", "text"), ("difficulty", "select")]
    assert comp["customConfig"][2]["options"] == ["easy", "medium", "hard"]
    out = s.output()
    assert "did=%s" % status["did"] in out and "component 0: Laser-1 / Raum-A" in out
    assert s.stop() == 0                                                         # SIGTERM = clean shutdown


def test_default_token_state_without_token_option(tmp_path):
    port = free_http_port()
    proc = subprocess.Popen([sys.executable, str(SIM), "--http-port", str(port), "--udp-port", "0", "--ip", "127.0.0.1", "--no-mdns",
                             "--state-dir", str(tmp_path / "s")], cwd=str(ROOT), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        assert wait_for(lambda: _try(lambda: get(port, "/security.json").status == 200), 20)
        assert get(port, "/security.json").json()["token"] == "default"
        m = Manager(port, "EscapeManager-Private-WLAN-Default-Token").init()
        assert m.post("/action", {"id": 0, "action": "next_step"}).status == 200      # the public default token works
    finally:
        proc.terminate()
        proc.wait(timeout=10)


def _try(fn):
    try:
        return fn()
    except OSError:
        return False


def test_puzzle_actions_errors_battery_and_plan_actions(sim_factory):
    s = sim_factory("--total-steps", "3", "--battery", "25", "--component", "Tuer:Raum-B:door-v1")
    m = s.manager
    comp = lambda: s.status()["components"][0]
    assert (comp()["name"], comp()["room"], comp()["riddleId"]) == ("Tuer", "Raum-B", "door-v1")
    for expected in (1, 2, 3, 3):                                                # saturates at the total
        assert m.post("/action", {"id": 0, "action": "next_step"}).status == 200
        assert comp()["puzzle"]["step"] == expected
    assert "tip" not in comp()                                                   # solved: no tip
    assert m.post("/action", {"id": 0, "action": "toggle_error"}).status == 200
    assert comp()["errors"] == ["sensor_timeout"]
    assert m.post("/action", {"id": 0, "action": "reset"}).status == 200
    assert comp()["puzzle"]["step"] == 0 and comp()["errors"] == []
    assert m.post("/action", {"id": 0, "action": "solve"}).status == 200 and comp()["puzzle"]["step"] == 3
    assert m.post("/plan-action", {"id": 0, "action": "reset"}).status == 200 and comp()["puzzle"]["step"] == 0
    assert m.post("/plan-action", {"id": 0, "action": "complete"}).status == 200 and comp()["puzzle"]["step"] == 3
    r = m.post("/action", {"id": 0, "action": "explode"})
    assert (r.status, r.body["code"]) == (422, "rejected")
    assert s.status()["battery"] == 25
    assert m.post("/action", {"id": 0, "action": "drain_battery"}).status == 200 and s.status()["battery"] == 15
    assert m.post("/action", {"id": 0, "action": "drain_battery"}).status == 200 and s.status()["battery"] == 5
    assert m.post("/action", {"id": 0, "action": "drain_battery"}).status == 200
    assert "battery" not in s.status()                                           # empty battery: not reported (<= 0)
    assert comp()["evtSeq"] >= 5 and comp()["evtMsg"]


def test_battery_zero_is_not_reported_and_html_state(sim_factory):
    s = sim_factory("--battery", "0", "--html-state", "--total-steps", "4")
    status = s.status()
    assert "battery" not in status
    puzzle = status["components"][0]["puzzle"]
    assert puzzle["isHtml"] is True and puzzle["state"] == "<svg width='160' height='40'><rect width='0' height='40' fill='#4a90d9'/></svg>"
    s.manager.post("/action", {"id": 0, "action": "next_step"})
    assert "width='40'" in s.status()["components"][0]["puzzle"]["state"]


def test_config_and_identity_persist_across_restarts(sim_factory, tmp_path):
    state = tmp_path / "persist"
    s = sim_factory(state_dir=state, token="persist-token-abcdefghij12")
    assert s.manager.post("/config", {"id": 0, "name": "Neu", "config": {"brightness": "70", "label": "hallo", "difficulty": "hard"}, "room": "Raum-Z"}).status == 200
    assert s.manager.post("/plan", '{"id":0,"plan":{"lane":"A"}}').status == 200
    assert s.stop() == 0
    again = sim_factory(state_dir=state, token="persist-token-abcdefghij12")
    comp = again.status()["components"][0]
    assert (comp["name"], comp["room"]) == ("Neu", "Raum-Z") and comp["plan"] == {"lane": "A"}
    assert {c["key"]: c["value"] for c in comp["customConfig"]} == {"brightness": "70", "label": "hallo", "difficulty": "hard"}
    assert again.status()["boot"] == 2


def test_invalid_options_exit_with_a_message(tmp_path):
    for argv, code in ((["--bogus"], 2), (["--component", "OnlyName"], 2), (["--did", "XYZ"], 2), (["--ip", "nope"], 2),
                       (["--total-steps", "0"], 2)):
        proc = subprocess.run([sys.executable, str(SIM)] + argv, cwd=str(ROOT), capture_output=True, text=True, timeout=30)
        assert proc.returncode == code, (argv, proc.stderr)
        assert proc.stderr.strip()


def test_http_port_in_use_exits_with_1(tmp_path):
    blocker = socket.socket()
    blocker.bind(("0.0.0.0", 0))
    blocker.listen(1)
    port = blocker.getsockname()[1]
    try:
        proc = subprocess.run([sys.executable, str(SIM), "--http-port", str(port), "--udp-port", "0", "--no-mdns",
                               "--state-dir", str(tmp_path / "s")], cwd=str(ROOT), capture_output=True, text=True, timeout=30)
    finally:
        blocker.close()
    assert proc.returncode == 1 and "cannot listen on HTTP port %d" % port in proc.stderr
