#!/usr/bin/env python3
"""Run an EscapeManager test device using the real Python implementation.

This simulator uses ``src/python/escape_component.py`` for HTTP, encrypted
POST commands, authenticated UDP discovery and the manager UI.  It only adds
interactive demo puzzle state, analogous to the C++ simulator.

Examples:
    python3 src/sim/escape_component_sim.py --http-port 8080
    python3 src/sim/escape_component_sim.py --component Laser-1:Raum-A \
        --component Button-1:Raum-A --http-port 8080
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from escape_component import (  # noqa: E402
    AUTH_TOKEN_DEFAULT,
    CustomConfigDef,
    EscapeComponent,
    PlanAction,
)

DEFAULT_COMPONENTS = [
    ("Laser-1", "Raum-C"),
    ("Kartenleser-1", "Raum-C"),
    ("Kamera-1", "Raum-D"),
    ("Drucksensor-1", "Raum-D"),
]


@dataclass
class DemoPuzzle:
    total_steps: int
    step: int = 0
    error_active: bool = False
    config: Dict[str, str] = field(default_factory=lambda: {
        "brightness": "50", "label": "", "difficulty": "medium",
    })
    lock: threading.Lock = field(default_factory=threading.Lock)

    def actions(self) -> List[str]:
        return ["reset", "next_step", "solve", "toggle_error", "drain_battery"]

    def errors(self) -> List[str]:
        with self.lock:
            return ["sensor_timeout"] if self.error_active else []

    def tip(self) -> str:
        with self.lock:
            if self.step >= self.total_steps:
                return "Das Raetsel ist geloest."
            return f"Hinweis fuer Schritt {self.step + 1}: Achtet auf die Reihenfolge der Signale."

    def puzzle(self) -> Tuple[int, int, str, bool]:
        with self.lock:
            return self.step, self.total_steps, f'<div style="font-family:sans-serif">Schritt {self.step}/{self.total_steps}</div>', True

    def custom_config(self) -> List[CustomConfigDef]:
        with self.lock:
            return [
                CustomConfigDef("brightness", "range", self.config["brightness"], 0, 100),
                CustomConfigDef("label", "text", self.config["label"], text_max_len=32),
                CustomConfigDef("difficulty", "select", self.config["difficulty"], options=["easy", "medium", "hard"]),
            ]

    def set_config(self, key: str, value: str) -> bool:
        with self.lock:
            if key not in self.config:
                return False
            self.config[key] = value
            return True

    def action(self, action: str, drain_battery: Callable[[], None]) -> bool:
        with self.lock:
            if action == "reset":
                self.step, self.error_active = 0, False
            elif action == "next_step":
                self.step = min(self.total_steps, self.step + 1)
            elif action == "solve":
                self.step = self.total_steps
            elif action == "toggle_error":
                self.error_active = not self.error_active
            elif action == "drain_battery":
                drain_battery()
            else:
                return False
            return True

    def plan_action(self, action: PlanAction) -> bool:
        with self.lock:
            if action is PlanAction.RESET:
                self.step, self.error_active = 0, False
            elif action is PlanAction.COMPLETE:
                self.step = self.total_steps
            else:
                return False
            return True


def parse_component(spec: str) -> Tuple[str, str]:
    name, separator, room = spec.partition(":")
    if not separator or not name or not room:
        raise argparse.ArgumentTypeError("--component erwartet NAME:ROOM")
    return name, room


def manager_html(path: str) -> str:
    candidate = Path(path) if path else Path(__file__).resolve().parents[1] / "manager" / "manager.html"
    try:
        return candidate.read_text(encoding="utf-8")
    except OSError:
        return ""


def default_settings_path(http_port: int) -> Path:
    return Path("/tmp") / f"escape_python_sim_{http_port}.json"


def load_settings(path: Path) -> Dict[str, Dict[str, Any]]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value.get("components", {}) if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(path: Path, states: Dict[str, DemoPuzzle]) -> None:
    value = {
        "components": {
            identifier: {"step": item.step, "error": item.error_active, "config": item.config}
            for identifier, item in states.items()
        }
    }
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", help="Name einer einzelnen Komponente")
    parser.add_argument("--room", help="Raum einer einzelnen Komponente")
    parser.add_argument("--component", action="append", default=[], type=parse_component, metavar="NAME:ROOM",
                        help="weitere Komponente; mehrfach verwendbar")
    parser.add_argument("--udp-port", type=int, default=4210)
    parser.add_argument("--http-port", type=int, default=80)
    parser.add_argument("--token", default=os.environ.get("ESCAPE_AUTH_TOKEN", AUTH_TOKEN_DEFAULT))
    parser.add_argument("--total-steps", type=int, default=5)
    parser.add_argument("--mdns-hostname", default="escapemanager", help="Hostname ohne .local")
    parser.add_argument("--no-mdns", action="store_true", help="mDNS-Ankuendigung deaktivieren")
    parser.add_argument("--manager-html", default="", help="alternativer Pfad zu manager.html")
    parser.add_argument("--settings-file", default="", help="JSON-Persistenzdatei, Standard: /tmp")
    args = parser.parse_args()

    if args.component:
        components = args.component
    elif args.name or args.room:
        components = [(args.name or "Sim-1", args.room or "Sim-Room")]
    else:
        components = DEFAULT_COMPONENTS
    if args.total_steps < 1:
        parser.error("--total-steps muss mindestens 1 sein")

    settings_path = Path(args.settings_file) if args.settings_file else default_settings_path(args.http_port)
    saved = load_settings(settings_path)
    battery = {"value": 100}
    component = EscapeComponent(
        host_name="python-sim",
        auth_token=args.token,
        http_port=args.http_port,
        udp_port=args.udp_port,
        manager_html=manager_html(args.manager_html),
        mdns_hostname=args.mdns_hostname,
        mdns_enabled=not args.no_mdns,
    )
    component.on_battery(lambda: battery["value"])
    states: Dict[str, DemoPuzzle] = {}

    for index, (name, room) in enumerate(components):
        identifier = f"python-sim-{args.http_port}-{index}"
        state = DemoPuzzle(args.total_steps)
        previous = saved.get(identifier, {})
        state.step = min(state.total_steps, max(0, int(previous.get("step", 0))))
        state.error_active = bool(previous.get("error", False))
        if isinstance(previous.get("config"), dict):
            state.config.update({key: str(value) for key, value in previous["config"].items() if key in state.config})
        states[identifier] = state
        component_id = component.add_component(name, room, identifier)
        component.on_errors(component_id, state.errors)
        component.on_actions(component_id, state.actions)
        component.on_tip(component_id, state.tip)
        component.on_puzzle(component_id, state.puzzle)
        component.on_custom_config(component_id, state.custom_config)
        component.on_custom_config_set(component_id, state.set_config)
        component.on_action(component_id, lambda action, state=state: state.action(
            action, lambda: battery.update(value=max(0, battery["value"] - 10))
        ))
        component.on_plan_action(component_id, state.plan_action)

    stop = False

    def request_stop(_signal: int, _frame: object) -> None:
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    component.begin()
    descriptions = ", ".join(f"{name} ({room}) [id={index}]" for index, (name, room) in enumerate(components))
    print(f"[sim] {descriptions} auf {component._ip}:{args.http_port}, UDP-Port {args.udp_port}")
    print(f"[sim] Manager: http://{component._ip}:{args.http_port}/")
    if not args.no_mdns:
        print(f"[sim] mDNS: http://{args.mdns_hostname}.local:{args.http_port}/")
    print(f"[sim] Persistenz: {settings_path}")
    try:
        while not stop:
            component.loop()
            time.sleep(0.02)
    finally:
        save_settings(settings_path, states)
        component.close()


if __name__ == "__main__":
    main()
