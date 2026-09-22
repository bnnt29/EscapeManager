#!/usr/bin/env python3
"""Runnable Python EscapeManager component with secure HTTP and UDP transport."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import select
import socket
import struct
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
except ImportError as error:
    raise RuntimeError("Install dependencies from src/python/requirements.txt") from error

AUTH_TOKEN_DEFAULT = "EscapeManager-Private-WLAN-Default-Token"
HTTP_PORT = 80
UDP_PORT = 4210
HEARTBEAT_SECONDS = 4.0
CHANGE_GAP_SECONDS = 0.3
PEER_TIMEOUT_SECONDS = 20.0
MAX_POST_BYTES = 12 * 1024
MDNS_ADDRESS = "224.0.0.251"
MDNS_PORT = 5353


def _b64encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64decode(value: str) -> bytes:
    if not value or "=" in value or len(value) % 4 == 1:
        raise ValueError("invalid base64url")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _text(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    return "" if value is None else str(value)


def _encode_dns_name(name: str) -> bytes:
    encoded = bytearray()
    for label in name.split("."):
        value = label.encode("ascii")
        if not 0 < len(value) <= 63:
            raise ValueError("invalid mDNS hostname")
        encoded.append(len(value))
        encoded.extend(value)
    encoded.append(0)
    return bytes(encoded)


def _decode_dns_name(data: bytes, offset: int) -> Tuple[str, int]:
    labels: List[str] = []
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return ".".join(labels), offset + 1
        if length & 0xC0:
            if offset + 1 >= len(data):
                raise ValueError("invalid DNS pointer")
            return ".".join(labels), offset + 2
        offset += 1
        if offset + length > len(data):
            raise ValueError("truncated DNS name")
        labels.append(data[offset:offset + length].decode("ascii"))
        offset += length
    raise ValueError("truncated DNS name")


def _mdns_query_matches(data: bytes, name: str) -> Tuple[bool, bool]:
    if len(data) < 12:
        return False, False
    _identifier, flags, questions, _answers, _authority, _additional = struct.unpack("!HHHHHH", data[:12])
    if flags & 0x8000:
        return False, False
    offset = 12
    try:
        for _ in range(questions):
            question_name, offset = _decode_dns_name(data, offset)
            if offset + 4 > len(data):
                return False, False
            query_type, query_class = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            if question_name.lower() == name.lower() and query_type in (1, 255) and (query_class & 0x7FFF) == 1:
                return True, bool(query_class & 0x8000)
    except (UnicodeDecodeError, ValueError):
        return False, False
    return False, False


def _mdns_answer(name: str, ip: str) -> bytes:
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0)
    record = _encode_dns_name(name)
    record += struct.pack("!HHI", 1, 0x8001, 120)
    address = socket.inet_aton(ip)
    return header + record + struct.pack("!H", len(address)) + address


class PlanAction(str, Enum):
    RESET = "reset"
    COMPLETE = "complete"


@dataclass
class CustomConfigDef:
    key: str
    type: str = "text"
    value: str = ""
    range_min: int = 0
    range_max: int = 0
    text_max_len: int = 0
    options: List[str] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        result: Dict[str, Any] = {"key": self.key, "type": self.type, "value": self.value}
        if self.type == "range":
            result.update({"min": self.range_min, "max": self.range_max})
        elif self.type == "select":
            result["options"] = self.options
        else:
            result["maxLength"] = self.text_max_len
        return result

    def accepts(self, value: str) -> bool:
        if self.type == "range":
            try:
                number = int(value)
            except ValueError:
                return False
            return str(number) == value and self.range_min <= number <= self.range_max
        if self.type == "select":
            return value in self.options
        return len(value) <= self.text_max_len


@dataclass
class PeerInfo:
    id: int
    uuid: str
    name: str
    room: str
    ip: str = ""
    http_port: int = HTTP_PORT
    battery: int = -1
    errors: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    plan_actions: List[str] = field(default_factory=list)
    feed: str = ""
    tip: str = ""
    puzzle: Optional[Tuple[int, int, str, bool]] = None
    custom_config: List[CustomConfigDef] = field(default_factory=list)
    plan: Optional[Any] = None
    event_seq: int = 0
    event_msg: str = ""
    uptime_ms: int = 0
    slave: bool = False
    last_seen_ms: int = 0

    def as_dict(self, device_fields: bool = True) -> Dict[str, Any]:
        result: Dict[str, Any] = {
            "id": self.id, "uuid": self.uuid, "name": self.name, "room": self.room,
            "errors": self.errors, "actions": self.actions, "planActions": self.plan_actions,
        }
        if device_fields:
            result.update({"ip": self.ip, "httpPort": self.http_port, "battery": self.battery,
                           "upTimeMs": self.uptime_ms, "slave": self.slave, "lastSeenMs": self.last_seen_ms})
        if self.feed:
            result["feed"] = self.feed
        if self.tip:
            result["tip"] = self.tip
        if self.puzzle and self.puzzle[1] > 0:
            result["puzzle"] = {"step": self.puzzle[0], "totalSteps": self.puzzle[1],
                                "state": self.puzzle[2], "isHtml": self.puzzle[3]}
        if self.custom_config:
            result["customConfig"] = [item.as_dict() for item in self.custom_config]
        if self.plan is not None:
            result["plan"] = self.plan
        if self.event_seq:
            result.update({"evtSeq": self.event_seq, "evtMsg": self.event_msg})
        return result


@dataclass
class PeerAddress:
    """Leichte Discovery-Adresse eines anderen Geraets (siehe /peers.json).

    Ersetzt seit der Umstellung auf browserseitige Aggregation die vormalige
    Speicherung des VOLLEN Peer-Zustands: ein Geraet muss nur noch wissen, WER
    sonst erreichbar ist (IP+Port), nicht mehr WAS jeder Peer gerade tut - der
    Browser fragt dazu jeden gefundenen Peer direkt per GET /status.json ab
    (siehe manager.html poll()/ingest()).
    """

    ip: str
    http_port: int = HTTP_PORT
    last_seen_ms: int = 0

    def as_dict(self) -> Dict[str, Any]:
        return {"ip": self.ip, "httpPort": self.http_port, "lastSeenMs": self.last_seen_ms}


class SecureTransport:
    """Wire-compatible implementation of EscapeSecurity::SecureTransport."""

    def __init__(self, auth_token: str) -> None:
        if not 8 <= len(auth_token) <= 128:
            raise ValueError("auth token must contain 8 to 128 characters")
        self._token = auth_token.encode("ascii")
        self._private = ec.generate_private_key(ec.SECP256R1())
        self._public = self._private.public_key().public_bytes(Encoding.X962, PublicFormat.UncompressedPoint)
        self._key_id = _b64encode(hashlib.sha256(self._public).digest()[:12])
        self._salt, self._iv = os.urandom(16), os.urandom(12)
        wrapping_key = self._hkdf(self._token, self._salt, self._key_wrap_info(self._key_id))
        self._encrypted_public = AESGCM(wrapping_key).encrypt(self._iv, self._public, self._key_aad(self._key_id).encode())
        self._replay_ivs: List[str] = []

    @staticmethod
    def _hkdf(key: bytes, salt: bytes, info: str) -> bytes:
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt, info=info.encode()).derive(key)

    @staticmethod
    def _key_aad(key_id: str) -> str:
        return f"EscapeManager key v2\n{key_id}"

    @staticmethod
    def _key_wrap_info(key_id: str) -> str:
        return f"EscapeManager key-wrap v2\n{key_id}"

    @staticmethod
    def _request_info(path: str, key_id: str) -> str:
        return f"EscapeManager request v2\n{path}\n{key_id}"

    def security_document(self) -> Dict[str, Any]:
        return {"version": 2, "available": True, "readOnly": False, "allowTokenInUrl": True,
                "authenticatedGets": False, "curve": "P-256", "keyId": self._key_id,
                "salt": _b64encode(self._salt), "iv": _b64encode(self._iv),
                "encryptedPublicKey": _b64encode(self._encrypted_public)}

    def protect_document(self, context: str, plaintext: str) -> str:
        payload = _b64encode(plaintext.encode())
        proof = f"EscapeManager document v1\n{context}\n{payload}".encode()
        return _json({"v": 1, "payload": payload, "auth": _b64encode(hmac.digest(self._token, proof, "sha256"))})

    def unprotect_document(self, context: str, envelope_json: str) -> str:
        try:
            envelope = json.loads(envelope_json)
            payload = envelope["payload"]
            proof = f"EscapeManager document v1\n{context}\n{payload}".encode()
            if envelope.get("v") != 1 or not hmac.compare_digest(_b64decode(envelope["auth"]), hmac.digest(self._token, proof, "sha256")):
                raise ValueError("unauthorized document")
            return _b64decode(payload).decode()
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid authenticated document") from error

    def decrypt_request(self, path: str, envelope_json: str) -> Tuple[str, str]:
        if len(envelope_json.encode()) > MAX_POST_BYTES:
            raise ValueError("secure envelope too large")
        try:
            envelope = json.loads(envelope_json)
            key_id, ephemeral = envelope["keyId"], envelope["ephemeralKey"]
            salt_text, iv_text, ciphertext = envelope["salt"], envelope["iv"], envelope["ciphertext"]
            proof = f"{self._request_info(path, key_id)}\n{ephemeral}\n{salt_text}\n{iv_text}\n{ciphertext}".encode()
            if envelope.get("v") != 2 or key_id != self._key_id:
                raise ValueError("invalid secure envelope")
            if not hmac.compare_digest(_b64decode(envelope["auth"]), hmac.digest(self._token, proof, "sha256")):
                raise PermissionError("unauthorized")
            if iv_text in self._replay_ivs:
                raise RuntimeError("replayed request")
            salt, iv = _b64decode(salt_text), _b64decode(iv_text)
            if len(salt) != 16 or len(iv) != 12:
                raise ValueError("invalid secure envelope")
            peer = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), _b64decode(ephemeral))
            info = self._request_info(path, key_id)
            key = self._hkdf(self._private.exchange(ec.ECDH(), peer), salt, info)
            clear = AESGCM(key).decrypt(iv, _b64decode(ciphertext), info.encode()).decode()
            self._replay_ivs.append(iv_text)
            del self._replay_ivs[:-32]
            return clear, iv_text
        except (PermissionError, RuntimeError):
            raise
        except (KeyError, TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("invalid secure envelope") from error


@dataclass
class _Component:
    uuid: str
    name: str
    room: str
    plan: Optional[Any] = None
    event_seq: int = 0
    event_msg: str = ""
    errors: Optional[Callable[[], List[str]]] = None
    actions: Optional[Callable[[], List[str]]] = None
    feed: Optional[Callable[[], str]] = None
    tip: Optional[Callable[[], str]] = None
    puzzle: Optional[Callable[[], Tuple[int, int, str, bool]]] = None
    action: Optional[Callable[[str], bool]] = None
    plan_action: Optional[Callable[[PlanAction], bool]] = None
    custom_config: Optional[Callable[[], List[CustomConfigDef]]] = None
    set_custom_config: Optional[Callable[[str, str], bool]] = None


class EscapeComponent:
    """A complete Python peer. Call ``begin`` once and ``loop`` regularly."""

    def __init__(self, host_name: str = "python-component", auth_token: str = AUTH_TOKEN_DEFAULT,
                 http_port: int = HTTP_PORT, udp_port: int = UDP_PORT, local_ip: Optional[str] = None,
                 manager_html: str = "", mdns_hostname: str = "escapemanager",
                 mdns_enabled: bool = True) -> None:
        self.host_name, self.http_port, self.udp_port = host_name, http_port, udp_port
        self._ip = local_ip or self._local_ip()
        self._security = SecureTransport(auth_token)
        self._manager_html = manager_html
        self._mdns_name = f"{mdns_hostname}.local"
        self._mdns_enabled = mdns_enabled
        self._components: List[_Component] = []
        self._peer_addresses: Dict[str, PeerAddress] = {}
        self._battery: Optional[Callable[[], int]] = None
        self._slave, self._plan_skeleton, self._dirty = False, "", True
        self._started, self._last_broadcast, self._last_expire = time.monotonic(), 0.0, 0.0
        self._udp: Optional[socket.socket] = None
        self._http: Optional[ThreadingHTTPServer] = None
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._mdns_thread: Optional[threading.Thread] = None

    @staticmethod
    def _local_ip() -> str:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
            try:
                probe.connect(("8.8.8.8", 80))
                return probe.getsockname()[0]
            except OSError:
                return "127.0.0.1"

    def begin(self) -> None:
        if self._http:
            return
        self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self._udp.bind(("", self.udp_port))
        self._udp.setblocking(False)
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_OPTIONS(self) -> None:  # noqa: N802
                self.send_response(204); self._headers(); self.end_headers()

            def do_GET(self) -> None:  # noqa: N802
                owner._get(self)

            def do_POST(self) -> None:  # noqa: N802
                owner._post(self)

            def _headers(self) -> None:
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type")

            def log_message(self, _format: str, *_args: Any) -> None:
                return

        self._http = ThreadingHTTPServer(("", self.http_port), Handler)
        threading.Thread(target=self._http.serve_forever, name="escape-http", daemon=True).start()
        if self._mdns_enabled:
            self._stop.clear()
            self._mdns_thread = threading.Thread(target=self._mdns_loop, name="escape-mdns", daemon=True)
            self._mdns_thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._http:
            self._http.shutdown(); self._http.server_close(); self._http = None
        if self._udp:
            self._udp.close(); self._udp = None
        if self._mdns_thread and self._mdns_thread is not threading.current_thread():
            self._mdns_thread.join(timeout=1)
        self._mdns_thread = None

    def _mdns_loop(self) -> None:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as mdns:
                mdns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    try:
                        mdns.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                    except OSError:
                        pass
                mdns.bind(("", MDNS_PORT))
                mdns.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                socket.inet_aton(MDNS_ADDRESS) + socket.inet_aton(self._ip))
                mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(self._ip))
                mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                answer = _mdns_answer(self._mdns_name, self._ip)
                last_announcement = 0.0
                while not self._stop.is_set():
                    now = time.monotonic()
                    if now - last_announcement >= 60.0:
                        mdns.sendto(answer, (MDNS_ADDRESS, MDNS_PORT))
                        last_announcement = now
                    ready, _, _ = select.select([mdns], [], [], 0.5)
                    if not ready:
                        continue
                    request, source = mdns.recvfrom(2048)
                    matches, unicast = _mdns_query_matches(request, self._mdns_name)
                    if matches:
                        mdns.sendto(answer, source if unicast else (MDNS_ADDRESS, MDNS_PORT))
        except OSError:
            # mDNS is discovery-only; HTTP and the authenticated protocol remain usable.
            return

    def loop(self) -> None:
        if not self._udp:
            raise RuntimeError("call begin() before loop()")
        self._receive_udp()
        now = time.monotonic()
        if (self._dirty and now - self._last_broadcast >= CHANGE_GAP_SECONDS) or now - self._last_broadcast >= HEARTBEAT_SECONDS:
            self._send_udp(); self._last_broadcast, self._dirty = now, False
        if now - self._last_expire >= 2.0:
            threshold = self._uptime_ms() - int(PEER_TIMEOUT_SECONDS * 1000)
            self._peer_addresses = {ip: peer for ip, peer in self._peer_addresses.items() if peer.last_seen_ms >= threshold}
            self._last_expire = now

    def mark_dirty(self) -> None:
        self._dirty = True

    def add_component(self, default_name: str, default_room: str, component_uuid: Optional[str] = None) -> int:
        self._components.append(_Component(component_uuid or str(uuid.uuid4()), default_name, default_room))
        self.mark_dirty()
        return len(self._components) - 1

    def on_battery(self, callback: Callable[[], int]) -> None: self._battery = callback
    def on_errors(self, identifier: int, callback: Callable[[], List[str]]) -> None: self._component(identifier).errors = callback
    def on_actions(self, identifier: int, callback: Callable[[], List[str]]) -> None: self._component(identifier).actions = callback
    def on_feed(self, identifier: int, callback: Callable[[], str]) -> None: self._component(identifier).feed = callback
    def on_tip(self, identifier: int, callback: Callable[[], str]) -> None: self._component(identifier).tip = callback
    def on_puzzle(self, identifier: int, callback: Callable[[], Tuple[int, int, str, bool]]) -> None: self._component(identifier).puzzle = callback
    def on_action(self, identifier: int, callback: Callable[[str], bool]) -> None: self._component(identifier).action = callback
    def on_plan_action(self, identifier: int, callback: Callable[[PlanAction], bool]) -> None: self._component(identifier).plan_action = callback
    def on_custom_config(self, identifier: int, callback: Callable[[], List[CustomConfigDef]]) -> None: self._component(identifier).custom_config = callback
    def on_custom_config_set(self, identifier: int, callback: Callable[[str, str], bool]) -> None: self._component(identifier).set_custom_config = callback

    def push_event(self, identifier: int, message: str) -> None:
        component = self._component(identifier)
        component.event_seq += 1; component.event_msg = message; self.mark_dirty()

    def peers(self) -> List[PeerAddress]:
        return list(self._peer_addresses.values())

    def status_json(self) -> str:
        now = self._uptime_ms()
        result = [self._snapshot(index).as_dict() for index in range(len(self._components))]
        for item in result:
            item["lastSeenMs"] = now
        return _json(result)

    def peers_json(self) -> str:
        return _json([peer.as_dict() for peer in self._peer_addresses.values()])

    def _component(self, identifier: int) -> _Component:
        if not isinstance(identifier, int) or not 0 <= identifier < len(self._components):
            raise IndexError("invalid component id")
        return self._components[identifier]

    def _uptime_ms(self) -> int:
        return int((time.monotonic() - self._started) * 1000)

    def _snapshot(self, identifier: int) -> PeerInfo:
        item = self._component(identifier)
        return PeerInfo(identifier, item.uuid, item.name, item.room, self._ip, self.http_port,
                        self._battery() if self._battery else -1, list(item.errors() if item.errors else [])[:4],
                        list(item.actions() if item.actions else [])[:8],
                        [action.value for action in PlanAction] if item.plan_action else [],
                        item.feed() if item.feed else "", item.tip() if item.tip else "",
                        item.puzzle() if item.puzzle else None,
                        list(item.custom_config() if item.custom_config else [])[:4], item.plan,
                        item.event_seq, item.event_msg, self._uptime_ms(), self._slave)

    def _broadcast(self) -> str:
        # Nur eine leichte Discovery-Ankuendigung (IP kommt beim Empfaenger aus
        # der UDP-Absenderadresse, nicht aus diesem Payload) - der Browser
        # aggregiert den vollen Zustand seit dieser Umstellung selbst per
        # /peers.json + direktem /status.json-Poll jeder gefundenen Adresse.
        return _json({"httpPort": self.http_port})

    def _send_udp(self) -> None:
        assert self._udp
        self._udp.sendto(self._security.protect_document("udp-broadcast-v1", self._broadcast()).encode(), ("255.255.255.255", self.udp_port))

    def _receive_udp(self) -> None:
        assert self._udp
        for _ in range(5):
            try:
                body, address = self._udp.recvfrom(65535)
                payload = json.loads(self._security.unprotect_document("udp-broadcast-v1", body.decode()))
                self.ingest_peer_announcement(payload, address[0])
            except BlockingIOError:
                return
            except (UnicodeDecodeError, ValueError, json.JSONDecodeError):
                continue

    def ingest_peer_announcement(self, payload: Dict[str, Any], sender_ip: Optional[str] = None) -> None:
        """Verarbeitet eine leichte Discovery-Ankuendigung (siehe _broadcast()).

        Traegt NUR ip+httpPort ein - der volle Zustand eines Peers wird nicht
        mehr per Broadcast verteilt, sondern vom Browser bei Bedarf direkt per
        HTTP GET /status.json abgefragt (siehe manager.html poll()/ingest()).
        """
        if not sender_ip or not isinstance(payload, dict):
            return
        http_port = payload.get("httpPort", HTTP_PORT)
        if not isinstance(http_port, int) or not 1 <= http_port <= 65535:
            http_port = HTTP_PORT
        # Nicht nur nach IP filtern/schluesseln: mehrere Instanzen auf demselben
        # Rechner (siehe escape_component_sim.py --http-port) teilen sich
        # dieselbe IP und unterscheiden sich nur durch den Port.
        if sender_ip == self._ip and http_port == self.http_port:
            return  # eigene (Loopback-)Broadcasts ignorieren
        self._peer_addresses[f"{sender_ip}:{http_port}"] = PeerAddress(sender_ip, http_port, self._uptime_ms())

    def _reply(self, handler: BaseHTTPRequestHandler, status: int, body: str,
               content_type: str = "application/json; charset=utf-8") -> None:
        handler.send_response(status); handler.send_header("Content-Type", content_type)
        handler.send_header("Access-Control-Allow-Origin", "*"); handler.end_headers(); handler.wfile.write(body.encode())

    def _get(self, handler: BaseHTTPRequestHandler) -> None:
        path = handler.path.split("?", 1)[0]
        if path == "/":
            body = self._manager_html or "EscapeManager Python simulator\n"
            content_type = "text/html; charset=utf-8" if self._manager_html else "text/plain; charset=utf-8"
            self._reply(handler, 200, body, content_type)
        elif path == "/security.json": self._reply(handler, 200, _json(self._security.security_document()))
        elif path == "/status.json": self._reply(handler, 200, self.status_json())
        elif path == "/peers.json": self._reply(handler, 200, self.peers_json())
        elif path == "/plan-skeleton.json": self._reply(handler, 200, self._plan_skeleton or '{"plans":[]}')
        else: self._reply(handler, 404, '{"error":"not found"}')

    def _post(self, handler: BaseHTTPRequestHandler) -> None:
        path = handler.path.split("?", 1)[0]
        if path not in {"/action", "/plan-action", "/config", "/plan", "/plan-skeleton"}:
            self._reply(handler, 404, '{"error":"not found"}'); return
        try:
            length = int(handler.headers.get("Content-Length", "0"))
            if length > MAX_POST_BYTES: raise ValueError("secure envelope too large")
            body, request_id = self._security.decrypt_request(path, handler.rfile.read(length).decode())
            status, result = self._dispatch(path, body)
        except PermissionError: self._reply(handler, 401, '{"error":"unauthorized"}'); return
        except RuntimeError: self._reply(handler, 409, '{"error":"replayed request"}'); return
        except (UnicodeDecodeError, ValueError): self._reply(handler, 400, '{"error":"invalid secure envelope"}'); return
        context = f"http-post-response-v1\n{path}\n{request_id}\n{status}"
        self._reply(handler, status, self._security.protect_document(context, result))

    def _dispatch(self, path: str, body: str) -> Tuple[int, str]:
        try: request = json.loads(body)
        except json.JSONDecodeError: return 400, '{"error":"invalid json"}'
        if not isinstance(request, dict): return 400, '{"error":"invalid json"}'
        if path == "/plan-skeleton": return self._set_skeleton(request, body)
        identifier = request.get("id", 0)
        if not isinstance(identifier, int) or not 0 <= identifier < len(self._components): return 400, '{"error":"invalid id"}'
        if path == "/action": return self._action(identifier, request)
        if path == "/plan-action": return self._plan_action(identifier, request)
        if path == "/config": return self._config(identifier, request)
        return self._plan(identifier, request)

    def _action(self, identifier: int, request: Dict[str, Any]) -> Tuple[int, str]:
        action = request.get("action"); callback = self._component(identifier).action
        if not isinstance(action, str) or not action or len(action) > 24: return 400, '{"error":"invalid action"}'
        ok = bool(callback and callback(action))
        if ok: self.push_event(identifier, f'Aktion "{action}" ausgefuehrt')
        self.mark_dirty(); return (200, '{"ok":true}') if ok else (422, '{"ok":false}')

    def _plan_action(self, identifier: int, request: Dict[str, Any]) -> Tuple[int, str]:
        try: action = PlanAction(request.get("action"))
        except ValueError: return 400, '{"error":"invalid plan action"}'
        callback = self._component(identifier).plan_action
        if not callback: return 422, '{"error":"plan action unsupported"}'
        ok = bool(callback(action))
        if ok: self.push_event(identifier, "Ablaufplan-Fortschritt zurueckgesetzt" if action is PlanAction.RESET else "Ablaufplan-Komponente abgeschlossen")
        self.mark_dirty(); return (200, '{"ok":true}') if ok else (422, '{"ok":false}')

    def _config(self, identifier: int, request: Dict[str, Any]) -> Tuple[int, str]:
        item, name, room = self._component(identifier), request.get("name"), request.get("room")
        if name is not None or room is not None:
            if not isinstance(name, str) or not isinstance(room, str) or not name or not room or len(name) > 32 or len(room) > 32: return 400, '{"error":"invalid name/room"}'
        values = request.get("config")
        if values is not None:
            if not isinstance(values, dict) or not item.custom_config or not item.set_custom_config: return 400, '{"error":"component has no custom config"}'
            definitions = {definition.key: definition for definition in item.custom_config()}
            parsed = {str(key): _text(value) for key, value in values.items()}
            if any(key not in definitions or not definitions[key].accepts(value) for key, value in parsed.items()): return 400, '{"error":"invalid config value"}'
            for key, value in parsed.items(): item.set_custom_config(key, value)
        if name is not None: item.name, item.room = name, room
        if "slave" in request: self._slave = bool(request["slave"])
        self.push_event(identifier, "Konfiguration geaendert"); return 200, '{"ok":true}'

    def _plan(self, identifier: int, request: Dict[str, Any]) -> Tuple[int, str]:
        plan = request.get("plan"); text = _json(plan) if plan is not None else ""
        if len(text.encode()) > 512: return 413, '{"error":"plan too large"}'
        self._component(identifier).plan = plan
        self.push_event(identifier, "Ablaufplan-Zuordnung entfernt" if plan is None else "Ablaufplan aktualisiert")
        return 200, '{"ok":true}'

    def _set_skeleton(self, request: Dict[str, Any], body: str) -> Tuple[int, str]:
        room = request.get("room")
        if not isinstance(room, str) or not room: return 400, '{"error":"missing plan room"}'
        if len(body.encode()) > 6144: return 413, '{"error":"skeleton too large"}'
        current = json.loads(self._plan_skeleton or '{"plans":[]}')
        plans = {item.get("room"): item for item in current.get("plans", []) if isinstance(item, dict) and item.get("room")}
        plans[room] = request; self._plan_skeleton = _json({"plans": list(plans.values())})
        for index, item in enumerate(self._components):
            if item.room == room: self.push_event(index, "Raum-Ablaufplan aktualisiert")
        return 200, '{"ok":true}'


__all__ = ["AUTH_TOKEN_DEFAULT", "CustomConfigDef", "EscapeComponent", "PeerAddress", "PeerInfo", "PlanAction", "SecureTransport"]
