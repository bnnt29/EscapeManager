#!/usr/bin/env python3
"""PC simulator of an EscapeManager device, built on the Python library (src/python/escape_component.py).

The same behaviour and command line as the C++ simulator (src/sim/escape_component_sim.cpp): simulated puzzle
components (steps, errors, actions, custom config, tips, battery) behind the real proto-2 stack - secure
POST envelopes, authenticated GET frames, UDP discovery, skeleton sync and the shared mDNS record.

    python3 src/sim/escape_component_sim.py --http-port 8080                    two demo components in "Raum-A"
    python3 src/sim/escape_component_sim.py --http-port 8081 --did 111111111111 --component Tuer:Raum-B:door-v1

Several simulators on one PC need different --http-port and --did values; they find each other through the
shared UDP discovery port (--udp-port) and the loopback/LAN broadcast. Needs the ``cryptography`` package
(src/python/requirements.txt).

Options:
  --http-port N          HTTP port (default 8080)
  --udp-port N           discovery port shared by all devices (default 4210)
  --did HEX12            device id (default: derived from the HTTP port, stable across restarts)
  --ip A.B.C.D           address announced to peers (default: the LAN address; 127.0.0.1 if there is none)
  --broadcast A.B.C.D    broadcast address for announcements (default: that of the LAN interface, 127.255.255.255 on loopback)
  --component NAME:ROOM[:RIDDLE]   a simulated component (repeatable, at most 4; default: two in "Raum-A")
  --token T              provision a custom token, 8..128 printable ASCII characters (default: $ESCAPE_AUTH_TOKEN,
                         else the public default token)
  --edit-token T         plan-edit token (PROTOCOL.md 3.1, same rules; default: $ESCAPE_EDIT_TOKEN, else none): with
                         one, POST /plan, /plan-skeleton and /setup need the edit keys and GET /edit.json proves it
  --setup                accept POST /setup (PROTOCOL.md 5.8, cap "setup"): token changes take effect at once but are
                         kept in memory only, a Wi-Fi change is only logged ("setup: wifi ssid=..", never the
                         password) because a PC has no radio. Without --setup: 404 for /setup, no cap.
  --manager-html FILE    UI to serve (raw or .gz; default: src/manager/manager.html)
  --state-dir DIR        persistent state (default: /tmp/escape-pysim-<did>-<port>)
  --no-mdns / --mdns-port N / --mdns-hostname NAME   the shared mDNS record (default: escapemanager.local, port 5353;
                         only answered with --http-port 80, the port a URL without port number reaches)
  --battery N            reported battery percent (default 100; <= 0 = none)
  --total-steps N        steps of every simulated puzzle (default 5)
  --html-state           report the puzzle state as HTML (an SVG progress bar) instead of text
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
import threading
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
import escape_component as ec  # noqa: E402

SIM_CONFIG_KEY = "simcfg"


class SimSetupSink(ec.SetupSink):
    """In-memory setup sink (the same as src/sim/SimSetupSink.hpp): tokens apply for real, Wi-Fi is only recorded."""

    def __init__(self, token: Optional[str], edit_token: Optional[str]) -> None:
        self.ssid = ""
        self._pass = ""  # recorded only (a PC has no radio); never logged
        self._set_token(token or "")
        self._set_edit_token(edit_token or "")

    def _set_token(self, token: str) -> None:
        self._token = token or ec.AUTH_TOKEN_DEFAULT
        self._token_state = ec.TokenState.CUSTOM if token else ec.TokenState.DEFAULT

    def _set_edit_token(self, token: str) -> None:
        self._edit_token = token
        self._edit_state = ec.EditState.CUSTOM if token else ec.EditState.UNSET

    def apply_setup(self, change: ec.SetupChange, via_network: bool) -> ec.SetupResult:
        ok, _ = ec.validate_setup_change(change)
        if not ok:
            return ec.SetupResult.INVALID
        if change.has_wifi:
            self.ssid, self._pass = change.ssid, change.pass_
            print("[sim] setup: wifi ssid=%s" % change.ssid, flush=True)
        if change.has_token:
            self._set_token(change.token)
            print("[sim] setup: token %s" % ("changed" if change.token else "removed (public default applies)"), flush=True)
        if change.has_edit_token:
            self._set_edit_token(change.edit_token)
            print("[sim] setup: edit token %s" % ("changed" if change.edit_token else "removed"), flush=True)
        return ec.SetupResult.OK

    def current_tokens(self) -> ec.SetupTokens:
        return ec.SetupTokens(self._token, self._token_state, self._edit_token, self._edit_state)

    def setup_ap_mode(self) -> str:
        return "none"  # a PC opens no setup network

    def configured_ssid(self) -> str:
        return self.ssid


class SimPuzzle:
    """The state of one simulated component (the sketch's game logic in a real device)."""

    def __init__(self, total: int, html_state: bool) -> None:
        self.total = total
        self.html_state = html_state
        self.step = 0
        self.error_active = False
        self.config: Dict[str, str] = {"brightness": "50", "label": "", "difficulty": "medium"}
        self.lock = threading.Lock()

    ACTIONS = ["reset", "next_step", "solve", "toggle_error", "drain_battery"]

    def actions(self) -> List[str]:
        return list(self.ACTIONS)

    def errors(self) -> List[str]:
        with self.lock:
            return ["sensor_timeout"] if self.error_active else []

    def tip(self) -> str:
        with self.lock:
            return "Naechste Aktion: next_step" if self.step < self.total else ""

    def puzzle(self) -> Tuple[int, int, str, bool]:
        with self.lock:
            if self.html_state:
                width = self.step * 160 // (self.total or 1)
                state = "<svg width='160' height='40'><rect width='%d' height='40' fill='#4a90d9'/></svg>" % width
            else:
                state = "Schritt %d von %d" % (self.step, self.total)
            return self.step, self.total, state, self.html_state

    def custom_config(self) -> List[ec.CustomConfigDef]:
        with self.lock:
            return [
                ec.CustomConfigDef("brightness", "range", self.config["brightness"], 0, 100),
                ec.CustomConfigDef("label", "text", self.config["label"], text_max_len=32),
                ec.CustomConfigDef("difficulty", "select", self.config["difficulty"], options=["easy", "medium", "hard"]),
            ]

    def set_config(self, key: str, value: str) -> bool:
        with self.lock:
            if key not in self.config:
                return False
            self.config[key] = value
            return True

    def action(self, name: str, drain_battery: Callable[[], None]) -> bool:
        with self.lock:
            if name == "reset":
                self.step, self.error_active = 0, False
            elif name == "next_step":
                self.step = self.step + 1 if self.step < self.total else self.total
            elif name == "solve":
                self.step = self.total
            elif name == "toggle_error":
                self.error_active = not self.error_active
            elif name == "drain_battery":
                drain_battery()
            else:
                return False
            return True

    def plan_action(self, action: ec.PlanAction) -> bool:
        with self.lock:
            if action == ec.PlanAction.RESET:
                self.step, self.error_active = 0, False
            else:
                self.step = self.total
            return True


def parse_component(spec: str) -> Tuple[str, str, Optional[str]]:
    parts = spec.split(":")
    if len(parts) < 2 or not parts[0] or not parts[1]:
        raise argparse.ArgumentTypeError("--component expects NAME:ROOM[:RIDDLE_ID]")
    return parts[0], parts[1], parts[2] if len(parts) > 2 and parts[2] else None


def read_ui(path: str) -> bytes:
    candidates = [path] if path else []
    candidates += [str(Path(__file__).resolve().parents[1] / "manager" / "manager.html"),
                   "src/manager/manager.html", "../manager/manager.html"]
    for candidate in candidates:
        try:
            return Path(candidate).read_bytes()
        except OSError:
            continue
    print("[sim] no manager.html found (use --manager-html); GET / will return 404", file=sys.stderr)
    return b""


def load_config(storage: ec.BlobStorage, puzzles: List[SimPuzzle]) -> None:
    """Custom config values survive restarts (the simulator's stand-in for NVS)."""
    raw = storage.read(SIM_CONFIG_KEY)
    if raw is None:
        return
    try:
        values = ec.parse_json(raw, 4, 200)
    except ec.JsonError:
        return
    if not isinstance(values, list):
        return
    for puzzle, entry in zip(puzzles, values):
        if isinstance(entry, dict):
            for key in puzzle.config:
                if isinstance(entry.get(key), str):
                    puzzle.config[key] = entry[key]


def save_config(storage: ec.BlobStorage, puzzles: List[SimPuzzle]) -> None:
    storage.write(SIM_CONFIG_KEY, json.dumps([p.config for p in puzzles], ensure_ascii=False,
                                             separators=(",", ":")).encode("utf-8"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--component", action="append", default=[], type=parse_component, metavar="NAME:ROOM[:RIDDLE]")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--udp-port", type=int, default=ec.EscapeConfig.UDP_PORT)
    parser.add_argument("--mdns-port", type=int, default=5353)
    parser.add_argument("--mdns-hostname", default=ec.EscapeConfig.MDNS_HOSTNAME + ".local")
    parser.add_argument("--did", default="")
    parser.add_argument("--token", default="")
    parser.add_argument("--edit-token", default="")
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--ip", default="")
    parser.add_argument("--broadcast", default="")
    parser.add_argument("--manager-html", default="")
    parser.add_argument("--state-dir", default="")
    parser.add_argument("--battery", type=int, default=100)
    parser.add_argument("--total-steps", type=int, default=5)
    parser.add_argument("--no-mdns", action="store_true")
    parser.add_argument("--html-state", action="store_true")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING, format="[sim] %(levelname)s %(message)s")

    did = args.did or "5e%02x%02x%02x%02x%02x" % (args.http_port >> 8 & 0xFF, args.http_port & 0xFF, 0xAB, 0xCD, 0xEF)
    if not ec.valid_did(did):
        parser.error("--did must be 12 lowercase hex characters")
    if args.ip and ec.parse_ipv4(args.ip) is None:
        parser.error("--ip must be a dotted IPv4 address")
    if args.broadcast and ec.parse_ipv4(args.broadcast) is None:
        parser.error("--broadcast must be a dotted IPv4 address")
    if args.total_steps < 1:
        parser.error("--total-steps must be at least 1")
    state_dir = args.state_dir or "/tmp/escape-pysim-%s-%d" % (did, args.http_port)
    specs = args.component or [("Laser-1", "Raum-A", None), ("Kamera-1", "Raum-A", None)]

    try:
        storage: ec.BlobStorage = ec.FileStorage(state_dir)
    except OSError as error:
        print("[sim] cannot use state directory %s: %s" % (state_dir, error), file=sys.stderr)
        return 1
    token = args.token or os.environ.get("ESCAPE_AUTH_TOKEN") or None
    edit_token = args.edit_token or os.environ.get("ESCAPE_EDIT_TOKEN") or None
    if edit_token is not None and not ec.valid_setup_token(edit_token):
        parser.error("the edit token must have 8..128 printable ASCII characters (no spaces)")
    setup_sink = SimSetupSink(token, edit_token) if args.setup else None
    # A shared name without a port only reaches HTTP port 80; on another port the name would send
    # browsers to whatever else listens on port 80 of this PC (e.g. a local web server).
    mdns_enabled = not args.no_mdns and args.http_port == 80
    component = ec.EscapeComponent(
        host_name="python-sim", auth_token=token, http_port=args.http_port, udp_port=args.udp_port,
        local_ip=args.ip or None, broadcast_ip=args.broadcast or None, manager_html=read_ui(args.manager_html),
        mdns_hostname=args.mdns_hostname, mdns_enabled=mdns_enabled, mdns_port=args.mdns_port,
        did=did, storage=storage, edit_token=edit_token, setup_sink=setup_sink)

    battery = {"value": args.battery}
    component.on_battery(lambda: battery["value"])

    def drain() -> None:
        battery["value"] = battery["value"] - 10 if battery["value"] > 10 else 0

    puzzles: List[SimPuzzle] = []
    for name, room, riddle in specs[:ec.EscapeConfig.MAX_LOCAL_COMPONENTS]:
        index = component.add_component(name, room, riddle or "sim-" + name)
        puzzle = SimPuzzle(args.total_steps, args.html_state)
        puzzles.append(puzzle)
        component.on_errors(index, puzzle.errors)
        component.on_actions(index, puzzle.actions)
        component.on_tip(index, puzzle.tip)
        component.on_puzzle(index, puzzle.puzzle)
        component.on_custom_config(index, puzzle.custom_config)

        def set_config(key: str, value: str, puzzle: SimPuzzle = puzzle) -> bool:
            ok = puzzle.set_config(key, value)
            if ok:
                save_config(storage, puzzles)
            return ok

        component.on_custom_config_set(index, set_config)
        component.on_action(index, lambda action, puzzle=puzzle: puzzle.action(action, drain))
        component.on_plan_action(index, puzzle.plan_action)
    load_config(storage, puzzles)

    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        component.begin()
    except OSError as error:
        print("[sim] cannot listen on HTTP port %d (%s)" % (args.http_port, error), file=sys.stderr)
        component.close()
        return 1
    print("[sim] did=%s http=%s:%d udp=%d token=%s edit=%s setup=%s ui=%s state=%s" % (
        did, component.ip, args.http_port, args.udp_port, component.token_state.value, component.edit_state.value,
        "on" if setup_sink else "off", component.ui_hash, state_dir), flush=True)
    for i in range(component.component_count):
        print("[sim]   component %d: %s / %s" % (i, component.name(i), component.room(i)), flush=True)
    if not args.no_mdns and not mdns_enabled:
        print("[sim] mDNS off: %s can only point to HTTP port 80 (use --http-port 80 to act as a failover for it)"
              % args.mdns_hostname, flush=True)
    try:
        while not stop.is_set():
            component.loop()
            stop.wait(0.003)
    finally:
        component.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
