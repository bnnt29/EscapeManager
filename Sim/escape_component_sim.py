#!/usr/bin/env python3
"""Simuliert eine Escape-Room-Komponente auf dem PC.

Implementiert exakt dasselbe Protokoll wie die ESP32-Firmware
(Client/client.hpp + client.cpp) und Manager/manager.html:
  - UDP-Broadcast (Heartbeat + Jitter + Change-getriebene Broadcasts)
  - UDP-Empfang fremder Broadcasts -> eigene Peer-Tabelle
  - HTTP GET  /status.json  (eigener Zustand + bekannte Peers, unauthentifiziert)
  - HTTP POST /action       (X-Auth-Token erforderlich)
  - HTTP POST /config       (X-Auth-Token erforderlich, setzt Name/Raum)

Damit kann dieses Skript sowohl vom Manager (manager.html) als auch von
echten ESP32-Komponenten wie eine "echte" Komponente behandelt werden.

Beispiel:
  python3 escape_component_sim.py --name Laser-1 --room Raum-A --http-port 8080

Hinweis Portwahl: manager.html und die ESP32-Firmware gehen von Port 80 fuer
/action und /config aus (keine Port-Angabe in der URL). Auf einem PC laufen
mehrere Simulator-Instanzen mit derselben IP - jede braucht daher einen
eigenen --http-port, wenn mehrere gleichzeitig laufen sollen. Aktionen ueber
die Manager-Oberflaeche funktionieren dann nur fuer die Instanz auf Port 80
(ggf. root/CAP_NET_BIND_SERVICE noetig). Fuer volle Mehrkomponenten-Tests mit
funktionierenden Aktions-Buttons empfiehlt sich je Instanz eine eigene IP
(z.B. per Docker-Container/Netzwerk-Namespace).
"""

import argparse
import hmac
import json
import random
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_PEERS = 24
PEER_TIMEOUT_S = 20.0
HEARTBEAT_INTERVAL_S = 4.0
HEARTBEAT_JITTER_S = 0.75
CHANGE_MIN_GAP_S = 0.3


def get_local_ip() -> str:
    """Ermittelt die ausgehende LAN-IP ohne tatsaechlich Pakete zu senden (UDP-connect)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


class ComponentState:
    """Zustand der simulierten Komponente selbst (analog PeerInfo/Callbacks in client.cpp)."""

    def __init__(self, name: str, room: str, total_steps: int):
        self.lock = threading.Lock()
        self.name = name
        self.room = room
        self.battery = 100
        self.errors: list[str] = []
        self.actions = ["reset", "next_step", "solve", "toggle_error", "drain_battery"]
        self.feed = ""
        self.step = 0
        self.total_steps = total_steps
        self.is_html = True
        self.dirty = threading.Event()

    def _puzzle_state_html(self) -> str:
        return f"<div style=\"font-family:sans-serif\">Schritt {self.step}/{self.total_steps}</div>"

    def apply_action(self, action: str) -> bool:
        with self.lock:
            if action == "reset":
                self.step = 0
                self.errors.clear()
            elif action == "next_step":
                self.step = min(self.total_steps, self.step + 1)
            elif action == "solve":
                self.step = self.total_steps
            elif action == "toggle_error":
                if "sensor_timeout" in self.errors:
                    self.errors.remove("sensor_timeout")
                else:
                    self.errors.append("sensor_timeout")
            elif action == "drain_battery":
                self.battery = max(0, self.battery - 10)
            else:
                return False
        self.dirty.set()
        return True

    def set_identity(self, name: str, room: str) -> None:
        with self.lock:
            self.name = name
            self.room = room
        self.dirty.set()

    def snapshot(self, ip: str) -> dict:
        with self.lock:
            return {
                "name": self.name,
                "room": self.room,
                "ip": ip,
                "battery": self.battery,
                "errors": list(self.errors),
                "actions": list(self.actions),
                "feed": self.feed,
                "puzzle": {
                    "step": self.step,
                    "totalSteps": self.total_steps,
                    "state": self._puzzle_state_html(),
                    "isHtml": self.is_html,
                },
            }

    def identity(self):
        with self.lock:
            return self.name, self.room


class PeerTable:
    """Aggregierte, zuletzt bekannte Zustaende anderer Komponenten (aus UDP-Broadcasts)."""

    def __init__(self):
        self.lock = threading.Lock()
        self.peers: dict[tuple[str, str], tuple[dict, float]] = {}

    def ingest(self, data: dict, now: float) -> None:
        name = data.get("name")
        room = data.get("room")
        if not isinstance(name, str) or not isinstance(room, str) or not name or not room:
            return
        key = (room, name)
        with self.lock:
            if key not in self.peers and len(self.peers) >= MAX_PEERS:
                oldest_key = min(self.peers, key=lambda k: self.peers[k][1])
                del self.peers[oldest_key]
            self.peers[key] = (data, now)

    def expire(self, now: float) -> None:
        with self.lock:
            stale = [k for k, (_, ts) in self.peers.items() if now - ts > PEER_TIMEOUT_S]
            for k in stale:
                del self.peers[k]

    def snapshot(self) -> list:
        with self.lock:
            return [d for d, _ in self.peers.values()]


def broadcast_loop(sock: socket.socket, udp_port: int, state: ComponentState, ip: str,
                    jitter_s: float, stop_event: threading.Event) -> None:
    last_send = 0.0
    while not stop_event.is_set():
        now = time.monotonic()
        interval = HEARTBEAT_INTERVAL_S + jitter_s
        due_heartbeat = now - last_send >= interval
        due_change = state.dirty.is_set() and now - last_send >= CHANGE_MIN_GAP_S
        if due_heartbeat or due_change:
            payload = json.dumps(state.snapshot(ip)).encode("utf-8")
            try:
                sock.sendto(payload, ("255.255.255.255", udp_port))
            except OSError:
                pass
            last_send = now
            state.dirty.clear()
        time.sleep(0.05)


def listen_loop(udp_port: int, state: ComponentState, peers: PeerTable,
                 stop_event: threading.Event) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass  # z.B. auf Plattformen ohne SO_REUSEPORT: nur eine Instanz kann lauschen
    sock.bind(("", udp_port))
    sock.settimeout(1.0)
    try:
        while not stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                msg = json.loads(data.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(msg, dict):
                continue
            own_name, own_room = state.identity()
            if msg.get("name") == own_name and msg.get("room") == own_room:
                continue  # eigenes Broadcast ignorieren
            msg["ip"] = msg.get("ip") or addr[0]
            peers.ingest(msg, time.monotonic())
    finally:
        sock.close()


def make_handler(state: ComponentState, peers: PeerTable, token: str, ip: str):
    class Handler(BaseHTTPRequestHandler):
        server_version = "EscapeComponentSim/1.0"

        def log_message(self, fmt, *args):
            pass  # Konsole waehrend Tests nicht mit Zugriffslogs fluten

        def _cors(self):
            self.send_header("Access-Control-Allow-Origin", "*")

        def _check_auth(self) -> bool:
            supplied = self.headers.get("X-Auth-Token", "")
            return hmac.compare_digest(supplied, token)

        def _send_json(self, code: int, obj) -> None:
            body = json.dumps(obj).encode("utf-8")
            self.send_response(code)
            self._cors()
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_OPTIONS(self):
            self.send_response(204)
            self._cors()
            self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            self.send_header("Access-Control-Allow-Headers", "Content-Type, X-Auth-Token")
            self.end_headers()

        def do_GET(self):
            if self.path == "/status.json":
                now = time.monotonic()
                peers.expire(now)
                devices = [state.snapshot(ip)] + peers.snapshot()
                self._send_json(200, devices)
            elif self.path == "/":
                name, room = state.identity()
                body = f"EscapeComponentSim: {name} ({room}) auf {ip}\n".encode("utf-8")
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self._cors()
                self.end_headers()

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0) or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                body = json.loads(raw.decode("utf-8")) if raw else {}
            except (ValueError, UnicodeDecodeError):
                self._send_json(400, {"error": "invalid json"})
                return
            if not isinstance(body, dict):
                self._send_json(400, {"error": "invalid json"})
                return

            if self.path == "/action":
                if not self._check_auth():
                    self._send_json(401, {"error": "unauthorized"})
                    return
                action = str(body.get("action", ""))
                ok = state.apply_action(action) if action else False
                self._send_json(200 if ok else 422, {"ok": ok})
            elif self.path == "/config":
                if not self._check_auth():
                    self._send_json(401, {"error": "unauthorized"})
                    return
                name = str(body.get("name", "")).strip()
                room = str(body.get("room", "")).strip()
                if not name or not room:
                    self._send_json(400, {"error": "invalid name/room"})
                    return
                state.set_identity(name, room)
                self._send_json(200, {"ok": True})
            else:
                self.send_response(404)
                self._cors()
                self.end_headers()

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="Sim-1", help="Geraetename (wie Client/client.hpp DEFAULT_NAME)")
    parser.add_argument("--room", default="Sim-Room", help="Raum (wie Client/client.hpp DEFAULT_ROOM)")
    parser.add_argument("--udp-port", type=int, default=4210, help="muss zu EscapeConfig::UDP_PORT passen")
    parser.add_argument("--http-port", type=int, default=80, help="muss zu EscapeConfig::HTTP_PORT passen")
    parser.add_argument("--token", default="changeme-venue-token", help="muss zu EscapeConfig::AUTH_TOKEN passen")
    parser.add_argument("--total-steps", type=int, default=5)
    args = parser.parse_args()

    ip = get_local_ip()
    state = ComponentState(args.name, args.room, args.total_steps)
    peers = PeerTable()
    stop_event = threading.Event()

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    jitter_s = random.uniform(0, HEARTBEAT_JITTER_S)

    threads = [
        threading.Thread(target=broadcast_loop, args=(send_sock, args.udp_port, state, ip, jitter_s, stop_event), daemon=True),
        threading.Thread(target=listen_loop, args=(args.udp_port, state, peers, stop_event), daemon=True),
    ]
    for t in threads:
        t.start()

    handler = make_handler(state, peers, args.token, ip)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.http_port), handler)

    print(f"[sim] {args.name} ({args.room}) auf {ip}:{args.http_port}, UDP-Broadcast Port {args.udp_port}")
    print("[sim] Manager-Einstellungen: Quelle = http://{}:{}".format(ip, args.http_port))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        httpd.shutdown()
        send_sock.close()


if __name__ == "__main__":
    main()
