#!/usr/bin/env python3
"""Simuliert eine Escape-Room-Komponente auf dem PC.

Implementiert exakt dasselbe Protokoll wie die ESP32-Firmware
(Client/client.hpp + client.cpp) und Manager/manager.html:
  - UDP-Broadcast (Heartbeat + Jitter + Change-getriebene Broadcasts)
  - UDP-Empfang fremder Broadcasts -> eigene Peer-Tabelle
  - HTTP GET  /             (liefert Manager/manager.html, wie die ESP32-Firmware)
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


/games/Projekte/EscapeManager/.venv/bin/python Sim/escape_component_sim.py --name Laser-1 --room Raum-A --http-port 8080

"""

import argparse
import fcntl
import hmac
import json
import os
import random
import socket
import struct
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

SIOCGIFADDR = 0x8915
SIOCGIFNETMASK = 0x891B

MDNS_ADDR = "224.0.0.251"
MDNS_PORT = 5353

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


def _ioctl_ip(sock: socket.socket, ifname: str, request: int) -> str:
    packed = struct.pack("256s", ifname[:15].encode("utf-8"))
    res = fcntl.ioctl(sock.fileno(), request, packed)
    return socket.inet_ntoa(res[20:24])


def compute_broadcast_address(local_ip: str) -> str:
    """Ermittelt die Subnetz-Broadcast-Adresse (ip | ~mask) des Interfaces mit
    local_ip - analog zu EscapeComponent::broadcastAddress() in client.cpp.
    Auf Rechnern mit mehreren Interfaces/VPNs ist die pauschale Adresse
    255.255.255.255 mehrdeutig geroutet; die gerichtete Subnetz-Broadcast-
    Adresse erzwingt den Versand ueber das richtige Interface.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            for _, ifname in socket.if_nameindex():
                try:
                    addr = _ioctl_ip(s, ifname, SIOCGIFADDR)
                except OSError:
                    continue
                if addr != local_ip:
                    continue
                try:
                    mask = _ioctl_ip(s, ifname, SIOCGIFNETMASK)
                except OSError:
                    return "255.255.255.255"
                ip_int = struct.unpack("!I", socket.inet_aton(addr))[0]
                mask_int = struct.unpack("!I", socket.inet_aton(mask))[0]
                bcast_int = ip_int | (~mask_int & 0xFFFFFFFF)
                return socket.inet_ntoa(struct.pack("!I", bcast_int))
        finally:
            s.close()
    except OSError:
        pass
    return "255.255.255.255"


# ---- Minimaler mDNS-Responder ----------------------------------------------
# Beantwortet A-Record-Anfragen fuer <hostname>.local per Multicast, analog zu
# MDNS.begin() + addService() in client.cpp: alle Komponenten/Simulatoren
# registrieren denselben Hostnamen, sodass http://<hostname>.local/ auf eine
# beliebige erreichbare Instanz zeigt. Kein externes mDNS-Lib noetig - nur so
# viel DNS-Paketbau/-Parsing wie fuer diesen einen Zweck noetig.

def _encode_dns_name(name: str) -> bytes:
    out = bytearray()
    for label in name.split("."):
        label_bytes = label.encode("utf-8")
        out.append(len(label_bytes))
        out += label_bytes
    out.append(0)
    return bytes(out)


def _build_mdns_a_answer(name: str, ip: str) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)  # QR=1, AA=1; ANCOUNT=1
    rr_name = _encode_dns_name(name)
    rr_type_class = struct.pack("!HH", 1, 0x8001)  # TYPE=A, CLASS=IN + Cache-Flush-Bit
    rr_ttl = struct.pack("!I", 120)
    rdata = socket.inet_aton(ip)
    rr_rdlength = struct.pack("!H", len(rdata))
    return header + rr_name + rr_type_class + rr_ttl + rr_rdlength + rdata


def _decode_dns_name(data: bytes, offset: int):
    labels = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:  # Kompressionszeiger: in Fragen nicht erwartet
            offset += 2
            break
        offset += 1
        labels.append(data[offset:offset + length].decode("utf-8", errors="replace"))
        offset += length
    return ".".join(labels), offset


def _mdns_query_matches(data: bytes, target_name: str) -> bool:
    if len(data) < 12:
        return False
    _id, flags, qdcount, _an, _ns, _ar = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000:  # ist Antwort, keine Anfrage
        return False
    offset = 12
    for _ in range(qdcount):
        name, offset = _decode_dns_name(data, offset)
        if offset + 4 > len(data):
            return False
        qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
        offset += 4
        if name.lower() == target_name and qtype in (1, 255) and (qclass & 0x7FFF) == 1:
            return True
    return False


def mdns_loop(hostname: str, ip: str, stop_event: threading.Event) -> None:
    target_name = f"{hostname}.local".lower()

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if hasattr(socket, "SO_REUSEPORT"):
        try:
            recv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except OSError:
            pass
    try:
        recv_sock.bind(("", MDNS_PORT))
    except OSError as e:
        print(f"[sim] mDNS deaktiviert (Port {MDNS_PORT} nicht verfuegbar: {e})")
        return
    try:
        mreq = socket.inet_aton(MDNS_ADDR) + socket.inet_aton(ip)
        recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
    except OSError as e:
        print(f"[sim] mDNS deaktiviert (Multicast-Beitritt fehlgeschlagen: {e})")
        recv_sock.close()
        return
    recv_sock.settimeout(1.0)
    recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    recv_sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))

    answer = _build_mdns_a_answer(target_name, ip)

    # Antworten muessen laut RFC 6762 vom UDP-Quellport 5353 gesendet werden,
    # sonst verwerfen strikte mDNS-Resolver (z.B. nss-mdns/Avahi) sie
    # stillschweigend - daher denselben Socket wie zum Empfangen nutzen statt
    # einen separaten Sende-Socket mit zufaelligem Quellport.
    try:
        while not stop_event.is_set():
            try:
                data, _addr = recv_sock.recvfrom(2048)
            except socket.timeout:
                continue
            except OSError:
                break
            if _mdns_query_matches(data, target_name):
                try:
                    recv_sock.sendto(answer, (MDNS_ADDR, MDNS_PORT))
                except OSError:
                    pass
    finally:
        recv_sock.close()


def default_manager_html_path() -> str:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(script_dir, "..", "Manager", "manager.html")


def load_manager_html(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except OSError as e:
        print(f"[sim] Warnung: manager.html nicht lesbar ({path}): {e}")
        return ""


def _validate_custom_config_value(definition: dict, value: str) -> bool:
    """Serverseitige Validierung eines von aussen (POST /config) eingegangenen
    Werts gegen das deklarierte Schema - der Manager ist eine nicht
    vertrauenswuerdige Eingabequelle (analog validateCustomConfigValue in
    Client/client.cpp)."""
    kind = definition.get("type")
    if kind == "range":
        try:
            v = int(value)
        except (ValueError, TypeError):
            return False
        return definition.get("min", 0) <= v <= definition.get("max", 0)
    if kind == "text":
        return len(value) <= definition.get("maxLength", 0)
    if kind == "select":
        return value in definition.get("options", [])
    return False


def _config_value_to_str(value) -> str:
    """Wie ArduinoJson's JsonVariant::as<String>(): Zahlen/Bools ebenfalls als
    String behandeln, nicht nur echte JSON-Strings."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value)


class Device:
    """Geraeteweit geteilter Zustand ALLER lokalen Komponenten dieses Prozesses:
    eine physische Batterie (analog EscapeComponent::onBattery in
    Client/client.hpp, das absichtlich KEINE Komponenten-ID kennt) und ein
    gemeinsames "dirty"-Signal, das jede Komponente bei Aenderungen setzt und
    das den naechsten Change-getriebenen Broadcast des gesamten Geraets ausloest."""

    def __init__(self):
        self.lock = threading.Lock()
        self.battery = 100
        self.dirty = threading.Event()

    def drain_battery(self) -> None:
        with self.lock:
            self.battery = max(0, self.battery - 10)
        self.dirty.set()

    def get_battery(self) -> int:
        with self.lock:
            return self.battery


class ComponentState:
    """Zustand EINER simulierten Raetsel-Komponente auf diesem Geraet (analog
    LocalComponent in Client/client.hpp). Ein Geraet/Prozess kann mehrere davon
    halten, jede mit eigenem Namen/Raum/Zustand - Batterie bleibt geraeteweit
    in Device (siehe oben)."""

    def __init__(self, comp_id: int, name: str, room: str, total_steps: int, device: "Device"):
        self.lock = threading.Lock()
        self.id = comp_id
        self.device = device
        self.name = name
        self.room = room
        self.errors: list[str] = []
        self.actions = ["reset", "next_step", "solve", "toggle_error", "drain_battery"]
        self.feed = ""
        self.step = 0
        self.total_steps = total_steps
        self.is_html = True
        # Beispielhafte Custom-Konfiguration (Name/Typ/erlaubte Werte je Feld),
        # um das Protokoll end-to-end testen zu koennen (Manager-Oberflaeche
        # <-> /status.json <-> POST /config). "value" wird immer als String
        # transportiert, analog zu CustomConfigDef in Client/client.hpp.
        self.custom_config: list[dict] = [
            {"key": "brightness", "type": "range", "min": 0, "max": 100, "value": "50"},
            {"key": "label", "type": "text", "maxLength": 32, "value": ""},
            {"key": "difficulty", "type": "select", "options": ["easy", "medium", "hard"], "value": "medium"},
        ]

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
                self.device.drain_battery()  # setzt bereits device.dirty
                return True
            else:
                return False
        self.device.dirty.set()
        return True

    def set_identity(self, name: str, room: str) -> None:
        with self.lock:
            self.name = name
            self.room = room
        self.device.dirty.set()

    def apply_custom_config(self, values: dict) -> bool:
        """Prueft alle Werte gegen das eigene Schema und wendet sie erst dann
        alles-oder-nichts an - analog handleConfig() in Client/client.cpp."""
        with self.lock:
            for key, value in values.items():
                definition = next((d for d in self.custom_config if d["key"] == key), None)
                if definition is None or not _validate_custom_config_value(definition, value):
                    return False
            for key, value in values.items():
                for d in self.custom_config:
                    if d["key"] == key:
                        d["value"] = value
        self.device.dirty.set()
        return True

    def snapshot(self) -> dict:
        """Nur die komponenteneigenen Felder - ip/battery kommen geraeteweit
        von aussen dazu (siehe device_broadcast_payload()/flatten_self())."""
        with self.lock:
            return {
                "id": self.id,
                "name": self.name,
                "room": self.room,
                "errors": list(self.errors),
                "actions": list(self.actions),
                "feed": self.feed,
                "puzzle": {
                    "step": self.step,
                    "totalSteps": self.total_steps,
                    "state": self._puzzle_state_html(),
                    "isHtml": self.is_html,
                },
                "customConfig": [dict(d) for d in self.custom_config],
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


def broadcast_loop(sock: socket.socket, udp_port: int, components: list[ComponentState], device: Device, ip: str,
                    broadcast_ip: str, jitter_s: float, stop_event: threading.Event) -> None:
    last_send = 0.0
    while not stop_event.is_set():
        now = time.monotonic()
        interval = HEARTBEAT_INTERVAL_S + jitter_s
        due_heartbeat = now - last_send >= interval
        due_change = device.dirty.is_set() and now - last_send >= CHANGE_MIN_GAP_S
        if due_heartbeat or due_change:
            # Ein Paket pro Geraet: gemeinsames ip/battery, plus ein
            # "components"-Array mit je einem Eintrag pro ComponentState -
            # analog zu EscapeComponent::sendBroadcast() in Client/client.cpp.
            payload_obj = {
                "ip": ip,
                "battery": device.get_battery(),
                "components": [c.snapshot() for c in components],
            }
            payload = json.dumps(payload_obj).encode("utf-8")
            try:
                sock.sendto(payload, (broadcast_ip, udp_port))
            except OSError:
                pass
            last_send = now
            device.dirty.clear()
        time.sleep(0.05)


def listen_loop(udp_port: int, components: list[ComponentState], peers: PeerTable,
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
            comp_list = msg.get("components")
            if not isinstance(comp_list, list):
                continue
            sender_ip = msg.get("ip") or addr[0]
            sender_battery = msg.get("battery", -1)
            own_identities = {c.identity() for c in components}
            now = time.monotonic()
            for comp in comp_list:
                if not isinstance(comp, dict):
                    continue
                if (comp.get("name"), comp.get("room")) in own_identities:
                    continue  # eigene Komponente ignorieren
                flat = dict(comp)
                flat["ip"] = sender_ip
                flat["battery"] = sender_battery
                peers.ingest(flat, now)
    finally:
        sock.close()


def make_handler(components: list[ComponentState], device: Device, peers: PeerTable, token: str, ip: str,
                  manager_html: str):
    components_by_id = {c.id: c for c in components}

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
                battery = device.get_battery()
                # Ein flacher Eintrag pro lokaler Komponente (nicht pro Geraet) -
                # ip/battery werden geraeteweit in jeden Eintrag hineinkopiert,
                # damit manager.html unveraendert eine flache Liste erwarten kann.
                own = [{**c.snapshot(), "ip": ip, "battery": battery} for c in components]
                self._send_json(200, own + peers.snapshot())
            elif self.path == "/":
                if manager_html:
                    body = manager_html.encode("utf-8")
                    content_type = "text/html; charset=utf-8"
                else:
                    names = ", ".join(f"{c.name} ({c.room})" for c in components)
                    body = f"EscapeComponentSim: {names} auf {ip}\n".encode("utf-8")
                    content_type = "text/plain; charset=utf-8"
                self.send_response(200)
                self._cors()
                self.send_header("Content-Type", content_type)
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
                # "id" waehlt die Ziel-Komponente dieses Prozesses aus (siehe
                # ComponentState.id); fehlt es, wird Komponente 0 angenommen
                # (rueckwaertskompatibel zu Ein-Komponenten-Aufrufen).
                try:
                    comp_id = int(body.get("id", 0))
                except (TypeError, ValueError):
                    self._send_json(400, {"error": "invalid id"})
                    return
                state = components_by_id.get(comp_id)
                if state is None:
                    self._send_json(400, {"error": "invalid id"})
                    return
                action = str(body.get("action", ""))
                ok = state.apply_action(action) if action else False
                self._send_json(200 if ok else 422, {"ok": ok})
            elif self.path == "/config":
                if not self._check_auth():
                    self._send_json(401, {"error": "unauthorized"})
                    return
                try:
                    comp_id = int(body.get("id", 0))
                except (TypeError, ValueError):
                    self._send_json(400, {"error": "invalid id"})
                    return
                state = components_by_id.get(comp_id)
                if state is None:
                    self._send_json(400, {"error": "invalid id"})
                    return
                name = str(body.get("name", "")).strip()
                room = str(body.get("room", "")).strip()
                identity_given = bool(name or room)
                if identity_given and (not name or not room):
                    self._send_json(400, {"error": "invalid name/room"})
                    return
                config = body.get("config")
                if isinstance(config, dict):
                    values = {str(k): _config_value_to_str(v) for k, v in config.items()}
                    if not state.apply_custom_config(values):
                        self._send_json(400, {"error": "invalid config value"})
                        return
                if identity_given:
                    state.set_identity(name, room)
                self._send_json(200, {"ok": True})
            else:
                self.send_response(404)
                self._cors()
                self.end_headers()

    return Handler


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--name", default="Sim-1", help="Geraetename der ersten Komponente (ignoriert, falls --component angegeben)")
    parser.add_argument("--room", default="Sim-Room", help="Raum der ersten Komponente (ignoriert, falls --component angegeben)")
    parser.add_argument(
        "--component", action="append", default=[], metavar="NAME:ROOM",
        help="Registriert eine weitere Raetsel-Komponente auf diesem simulierten Geraet "
             "(mehrfach angebbar, z.B. --component Laser-1:Raum-A --component Button-1:Raum-B). "
             "Komponenten koennen unterschiedlichen Raeumen zugeordnet sein, teilen sich aber "
             "IP/Port/Batterie dieses einen Prozesses (analog mehreren addComponent()-Aufrufen "
             "auf einem ESP32, siehe Client/client.hpp). Ohne --component wird genau eine "
             "Komponente aus --name/--room angelegt.",
    )
    parser.add_argument("--udp-port", type=int, default=4210, help="muss zu EscapeConfig::UDP_PORT passen")
    parser.add_argument("--http-port", type=int, default=80, help="muss zu EscapeConfig::HTTP_PORT passen")
    parser.add_argument("--token", default="changeme-venue-token", help="muss zu EscapeConfig::AUTH_TOKEN passen")
    parser.add_argument("--total-steps", type=int, default=5)
    parser.add_argument("--mdns-hostname", default="escapemanager", help="wie EscapeConfig::MDNS_HOSTNAME")
    parser.add_argument("--no-mdns", action="store_true", help="mDNS-Responder deaktivieren")
    parser.add_argument("--manager-html", default="", help="Pfad zu Manager/manager.html (Default: relativ zum Skript ermittelt)")
    args = parser.parse_args()

    component_specs: list[tuple[str, str]] = []
    for spec in args.component:
        if ":" not in spec:
            parser.error(f"--component erwartet NAME:ROOM, bekommen: {spec!r}")
        name, room = spec.split(":", 1)
        if not name or not room:
            parser.error(f"--component erwartet NAME:ROOM (beide nicht leer), bekommen: {spec!r}")
        component_specs.append((name, room))
    if not component_specs:
        component_specs = [(args.name, args.room)]

    ip = get_local_ip()
    broadcast_ip = compute_broadcast_address(ip)
    device = Device()
    components = [ComponentState(i, name, room, args.total_steps, device) for i, (name, room) in enumerate(component_specs)]
    peers = PeerTable()
    stop_event = threading.Event()

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    jitter_s = random.uniform(0, HEARTBEAT_JITTER_S)

    threads = [
        threading.Thread(target=broadcast_loop, args=(send_sock, args.udp_port, components, device, ip, broadcast_ip, jitter_s, stop_event), daemon=True),
        threading.Thread(target=listen_loop, args=(args.udp_port, components, peers, stop_event), daemon=True),
    ]
    if not args.no_mdns:
        threads.append(threading.Thread(target=mdns_loop, args=(args.mdns_hostname, ip, stop_event), daemon=True))
    for t in threads:
        t.start()

    manager_html_path = args.manager_html or default_manager_html_path()
    manager_html = load_manager_html(manager_html_path)

    handler = make_handler(components, device, peers, args.token, ip, manager_html)
    httpd = ThreadingHTTPServer(("0.0.0.0", args.http_port), handler)

    comp_desc = ", ".join(f"{c.name} ({c.room}) [id={c.id}]" for c in components)
    print(f"[sim] {comp_desc} auf {ip}:{args.http_port}, UDP-Broadcast Port {args.udp_port} -> {broadcast_ip}")
    print("[sim] Manager-Einstellungen: Quelle = http://{}:{}".format(ip, args.http_port))
    if not args.no_mdns:
        print(f"[sim] mDNS: http://{args.mdns_hostname}.local:{args.http_port}/ (falls vom Betriebssystem unterstuetzt)")
    if manager_html:
        print(f"[sim] manager.html geladen von {manager_html_path}")
    else:
        print("[sim] Warnung: manager.html nicht gefunden - \"/\" liefert nur Klartext (siehe --manager-html).")
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
