"""Shared helpers for the Python protocol tests: ports, a raw HTTP client and a manager-side client."""

from __future__ import annotations

import json
import random
import secrets
import socket
import sys
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src" / "python"))

import escape_component as ec  # noqa: E402

#: a token only these tests use, so announcements of other sims on the shared discovery port are ignored
TEST_TOKEN = "pytest-" + secrets.token_hex(12)
#: the discovery port all agents on this machine share (see the task's port rules)
DISCOVERY_PORT = 14210

_port_lock = threading.Lock()
_next_port = [random.randint(9100, 9199)]


def free_http_port() -> int:
    """A currently free port in 9100..9199."""
    for _ in range(200):
        with _port_lock:
            port = 9100 + (_next_port[0] - 9100) % 100
            _next_port[0] += 1
        probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            probe.bind(("127.0.0.1", port))
            return port
        except OSError:
            continue
        finally:
            probe.close()
    raise RuntimeError("no free port in 9100..9199")


def wait_for(condition: Callable[[], Any], timeout: float = 8.0, interval: float = 0.05) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if condition():
            return True
        time.sleep(interval)
    return bool(condition())


def random_did(first: str = "") -> str:
    return (first + secrets.token_hex(6))[:12]


def make_component(components: Tuple[Tuple[str, str], ...] = (("Laser", "Raum A"),), *, begin: bool = True,
                   background: bool = True, **kwargs: Any) -> "ec.EscapeComponent":
    """An in-process device on loopback with in-memory storage, no UDP and no mDNS by default."""
    kwargs.setdefault("storage", ec.MemoryStorage())
    kwargs.setdefault("local_ip", "127.0.0.1")
    kwargs.setdefault("udp_port", 0)
    kwargs.setdefault("mdns_enabled", False)
    kwargs.setdefault("auth_token", TEST_TOKEN)
    kwargs.setdefault("did", random_did())
    explicit_port = kwargs.get("http_port") is not None
    last_error: Optional[Exception] = None
    for _ in range(20):
        kwargs["http_port"] = kwargs["http_port"] if explicit_port else free_http_port()
        component = ec.EscapeComponent(**kwargs)
        for name, room in components:
            component.add_component(name, room)
        if not begin:
            return component
        try:
            component.begin(background=background)
            return component
        except OSError as error:  # port taken by someone else a moment ago
            last_error = error
            component.close()
            if explicit_port:
                break
    raise RuntimeError("could not start a component: %s" % last_error)


# ---- raw HTTP --------------------------------------------------------------------------------------

@dataclass
class Response:
    status: int = 0
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    raw: bytes = b""

    def json(self) -> Any:
        return json.loads(self.body.decode("utf-8"))


def parse_http(raw: bytes) -> Response:
    if not raw.startswith(b"HTTP/1.1 "):
        return Response(0, {}, b"", raw)
    head, _, body = raw.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return Response(int(lines[0].split(" ")[1]), headers, body, raw)


def read_all(sock: socket.socket, timeout: float = 5.0, limit: int = 4_000_000) -> bytes:
    sock.settimeout(timeout)
    data = b""
    try:
        while len(data) < limit:
            chunk = sock.recv(65536)
            if not chunk:
                break
            data += chunk
    except (socket.timeout, ConnectionResetError):
        pass
    return data


def exchange(port: int, request: bytes, timeout: float = 5.0, host: str = "127.0.0.1") -> Response:
    """Sends ``request`` and reads until the server closes the connection."""
    with socket.create_connection((host, port), timeout=timeout) as sock:
        try:
            sock.sendall(request)
        except OSError:
            pass
        return parse_http(read_all(sock, timeout))


def get(port: int, target: str, headers: str = "") -> Response:
    return exchange(port, ("GET %s HTTP/1.1\r\nHost: x\r\n%s\r\n" % (target, headers)).encode())


# ---- the manager's view --------------------------------------------------------------------------------

@dataclass
class PostResult:
    status: int
    body: Optional[Dict[str, Any]]    # decrypted JSON, None if the answer was not authenticated
    authenticated: bool
    response: Response

    @property
    def code(self) -> Optional[str]:
        if self.body is not None:
            return self.body.get("code")
        try:
            return self.response.json().get("code")
        except (ValueError, AttributeError):
            return None


class Manager:
    """Plays manager.html: learns did and clock from /security.json, then talks the protocol."""

    def __init__(self, port: int, token: str = TEST_TOKEN, host: str = "127.0.0.1") -> None:
        self.port = port
        self.host = host
        self.token = token
        self.did = ""
        self.offset = 0
        self.transport = ec.SecureTransport()
        self.security: Dict[str, Any] = {}

    def init(self, did: Optional[str] = None) -> "Manager":
        started = time.monotonic()
        response = get(self.port, "/security.json")
        self.security = response.json()
        midpoint = (time.monotonic() + started) / 2 * 1000
        self.offset = int(self.security["time"] - midpoint)
        self.did = did or self.security["did"]
        self.transport.begin(self.token, ec.TokenState.CUSTOM, self.did)
        return self

    def device_time(self) -> int:
        return int(time.monotonic() * 1000 + self.offset) & 0xFFFFFFFF

    def get(self, path: str, query: str = "", nonce: Optional[str] = None) -> Tuple[Response, Optional[bytes]]:
        """Authenticated GET: (response, verified document bytes or None)."""
        nonce = nonce or ec.b64u_encode(secrets.token_bytes(16))
        response = get(self.port, "%s?nonce=%s%s" % (path, nonce, "&" + query if query else ""))
        doc = self.transport.open_document_frame(path, nonce, response.status, response.body)
        return response, doc

    def get_json(self, path: str, query: str = "") -> Any:
        response, doc = self.get(path, query)
        assert doc is not None, "frame did not verify (status %d): %r" % (response.status, response.body[:200])
        return json.loads(doc)

    def post_raw(self, path: str, envelope: bytes, headers: str = "") -> Response:
        request = ("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n%s\r\n" % (path, len(envelope), headers)).encode() + envelope
        return exchange(self.port, request)

    def post(self, path: str, body: Union[str, dict, list], t: Optional[int] = None, iv: Optional[bytes] = None,
             retry_rate_limit: bool = True, retry_stale: bool = True) -> PostResult:
        text = body if isinstance(body, str) else json.dumps(body, separators=(",", ":"), ensure_ascii=False)
        for attempt in range(40):
            iv_bytes = iv or secrets.token_bytes(12)
            envelope = self.transport.seal_request(path, self.device_time() if t is None else t, text, iv_bytes)
            assert envelope is not None
            response = self.post_raw(path, envelope)
            if response.status == 429 and retry_rate_limit and b"rate_limited" in response.body and b'"ct"' not in response.body:
                time.sleep(0.3)  # the per-source bucket is shared with discovery traffic on loopback
                continue
            plain = self.transport.open_response(path, ec.b64u_encode(iv_bytes), response.status, response.body)
            body_json = json.loads(plain) if plain is not None else None
            if response.status == 409 and body_json and body_json.get("code") == "stale_time" and retry_stale and t is None:
                self.offset = int(body_json["time"] - time.monotonic() * 1000)
                retry_stale = False
                continue
            return PostResult(response.status, body_json, plain is not None, response)
        raise AssertionError("rate limiter never released")


# ---- a host for handler tests ---------------------------------------------------------------------------

class FakeHost(ec.ProtocolAdapter):
    """A configurable stand-in for the host program's components that records every call."""

    def __init__(self) -> None:
        self.count = 2
        self.battery_value = -1
        self.names = ["Laser", "Kamera", "", ""]
        self.rooms = ["Raum A", "Raum B", "", ""]
        self.riddle = ["laser-v1", "cam-v1", "", ""]
        self.plans = ["", "", "", ""]
        self.mask = [3, 0, 0, 0]
        self.tip = ""
        self.feed = ""
        self.state_text = ""
        self.cfg = [ec.CustomConfigDef("brightness", "range", "50", 0, 100),
                    ec.CustomConfigDef("label", "text", "", text_max_len=8)]
        self.action_result = True
        self.plan_action_result = True
        self.dirty = 0
        self.set_calls = 0
        self.events: List[str] = []
        self.actions_applied: List[str] = []
        self.last_cfg: Tuple[str, str] = ("", "")

    def battery(self) -> int: return self.battery_value
    def mark_dirty(self) -> None: self.dirty += 1
    def component_count(self) -> int: return self.count
    def identity(self, index: int) -> Tuple[str, str]: return self.names[index], self.rooms[index]

    def snapshot(self, index: int) -> "ec.ComponentSnapshot":
        s = ec.ComponentSnapshot(uuid="aabbccddeeff-%d" % index, riddle_id=self.riddle[index], name=self.names[index],
                                 room=self.rooms[index], plan_action_mask=self.mask[index], tip=self.tip,
                                 feed=self.feed, plan=self.plans[index])
        if index == 0:
            s.errors = ["sensor_timeout"]
            s.actions = ["open"]
            s.puzzle_step, s.puzzle_total_steps, s.puzzle_state, s.puzzle_is_html = 2, 5, self.state_text, False
            s.custom_config = list(self.cfg)
            s.event_seq, s.event_msg = 3, 'Aktion "open" ausgefuehrt'
        return s

    def custom_config_defs(self, index: int) -> List["ec.CustomConfigDef"]:
        return list(self.cfg) if index == 0 else []

    def apply_action(self, index: int, action: str) -> bool:
        self.actions_applied.append(action)
        return self.action_result

    def apply_plan_action(self, index: int, action: "ec.PlanAction") -> bool: return self.plan_action_result

    def set_identity(self, index: int, name: str, room: str) -> None:
        self.names[index], self.rooms[index] = name, room
        self.set_calls += 1

    def set_riddle_id(self, index: int, riddle_id: str) -> None:
        self.riddle[index] = riddle_id
        self.set_calls += 1

    def set_custom_config_value(self, index: int, key: str, value: str) -> bool:
        self.last_cfg = (key, value)
        self.set_calls += 1
        return True

    def set_plan(self, index: int, plan_json: str) -> None:
        self.plans[index] = plan_json
        self.set_calls += 1

    def push_event(self, index: int, message: str) -> None: self.events.append(message)
