#!/usr/bin/env python3
"""EscapeManager device library for Python (wire protocol level 2, see PROTOCOL.md).

This is a port of the C++ reference implementation (``src/protocol``, ``src/net``): the
same key schedule, envelopes, limits, error codes and discovery rules, so a Python
component, an ESP32 and the C++ simulator can talk to each other and to
``manager.html`` without knowing which one they are talking to.

Public API (kept close to the Arduino ``EscapeComponent`` class)::

    component = EscapeComponent(http_port=8080)
    laser = component.add_component("Laser-1", "Raum-A", "laser-v1")
    component.on_actions(laser, lambda: ["reset"])
    component.on_action(laser, lambda action: action == "reset")
    component.begin()
    while True:
        component.loop()      # discovery, announcements, mDNS, skeleton sync

HTTP is served from worker threads (bounded: at most 8 connections, every socket
operation has a timeout); ``loop()`` is cooperative and never blocks. All shared state
is protected by one re-entrant lock - user callbacks run while it is held, so they must
be quick and must not wait for another thread that calls back into the component.
"""

from __future__ import annotations

import abc
import base64
import gzip
import hashlib
import hmac
import json
import logging
import math
import os
import re
import secrets
import socket
import struct
import tempfile
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple, Union

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError as error:  # pragma: no cover - environment problem
    raise RuntimeError("Install dependencies from src/python/requirements.txt") from error

log = logging.getLogger("escape_component")

# ---- Version identity (PROTOCOL.md section 1) --------------------------------------------

PROTO = 2          # highest wire level spoken
PROTO_MIN = 2      # lowest wire level still accepted
FW_VERSION = "2.0.0"
UI_VERSION = "2.0.0"


class EscapeConfig:
    """Limits and timing, mirrored from src/protocol/EscapeConfig.hpp."""

    AUTH_TOKEN = "EscapeManager-Private-WLAN-Default-Token"
    MIN_AUTH_TOKEN_LEN = 8
    MAX_AUTH_TOKEN_LEN = 128
    RECOMMENDED_AUTH_TOKEN_LEN = 20
    ALLOW_AUTH_TOKEN_IN_URL = True
    STRICT_GET = False
    KDF_ITERATIONS = 2048
    MAX_KDF_ITERATIONS = 100000
    TIME_WINDOW_MS = 15000
    REPLAY_CACHE_SIZE = 80

    UDP_PORT = 4210
    HTTP_PORT = 80
    MDNS_HOSTNAME = "escapemanager"
    MDNS_TTL_S = 15
    MAX_HTTP_CONNECTIONS = 8          # threads are cheap on a PC; the C++ core uses 2
    HTTP_IDLE_TIMEOUT_MS = 5000       # no bytes received
    HTTP_REQUEST_TIMEOUT_MS = 10000   # whole request including the response
    MAX_HEADER_BYTES = 1024

    HEARTBEAT_INTERVAL_MS = 4000
    HEARTBEAT_JITTER_MS = 750
    CHANGE_MIN_GAP_MS = 300
    PEER_TIMEOUT_MS = 20000
    MAX_ANNOUNCEMENT_BYTES = 600

    MAX_PEER_ADDRESSES = 64
    MAX_LOCAL_COMPONENTS = 4
    MAX_NAME_LEN = 32
    MAX_ROOM_LEN = 32
    MAX_ERRORS = 4
    MAX_ERROR_LEN = 32
    MAX_ACTIONS = 8
    MAX_ACTION_LEN = 24
    MAX_FEED_LEN = 96
    MAX_TIP_LEN = 512
    MAX_STATE_LEN = 1664
    MAX_UUID_LEN = 20
    MAX_RIDDLE_ID_LEN = 32
    MAX_EVENT_MSG_LEN = 64
    MAX_CUSTOM_CONFIGS = 4
    MAX_CONFIG_KEY_LEN = 20
    MAX_CONFIG_VALUE_LEN = 48
    MAX_CONFIG_OPTIONS = 6
    MAX_CONFIG_OPTION_LEN = 16

    MAX_PLAN_LEN = 512
    MAX_PLAN_SKELETON_LEN = 6144
    MAX_SKELETON_ROOMS = MAX_LOCAL_COMPONENTS
    SKELETON_SYNC_BACKOFF_MS = 10000
    SKELETON_SYNC_TIMEOUT_MS = 3000

    MAX_BODY_BYTES = 12 * 1024
    MAX_JSON_NODES = 160
    MAX_JSON_DEPTH = 16

    RATE_SOURCES = 8
    RATE_BURST = 12
    RATE_REFILL_MS = 250
    GLOBAL_POSTS_PER_SECOND = 30

    DEFAULT_NAME = "Komponente"
    DEFAULT_ROOM = "unzugeordnet"


AUTH_TOKEN_DEFAULT = EscapeConfig.AUTH_TOKEN
HTTP_PORT = EscapeConfig.HTTP_PORT
UDP_PORT = EscapeConfig.UDP_PORT
INVALID_COMPONENT_ID = 255
_U32 = 0xFFFFFFFF


def s32(value: int) -> int:
    """Interprets the low 32 bits of ``value`` as a signed integer (millis() arithmetic)."""
    value &= _U32
    return value - 0x100000000 if value & 0x80000000 else value


def u32(value: int) -> int:
    return value & _U32


# ---- base64url, hex, FNV-1a --------------------------------------------------------------

_B64_ALPHABET_RE = re.compile(rb"[A-Za-z0-9_-]*")


def b64u_encode(data: Union[bytes, bytearray, memoryview]) -> str:
    """base64url without padding."""
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64u_decode(text: Union[str, bytes]) -> bytes:
    """Strict base64url: alphabet only, no padding, canonical (unused bits are zero).

    Raises ``ValueError`` for anything else, so one value has exactly one text form.
    """
    if isinstance(text, str):
        try:
            raw = text.encode("ascii")
        except UnicodeEncodeError:
            raise ValueError("invalid base64url") from None
    else:
        raw = bytes(text)
    if not _B64_ALPHABET_RE.fullmatch(raw) or len(raw) % 4 == 1:
        raise ValueError("invalid base64url")
    decoded = base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))
    if b64u_encode(decoded).encode("ascii") != raw:
        raise ValueError("non-canonical base64url")
    return decoded


def fnv1a32(data: Union[str, bytes]) -> int:
    if isinstance(data, str):
        data = data.encode("utf-8")
    h = 0x811C9DC5
    for byte in data:
        h = ((h ^ byte) * 0x01000193) & _U32
    return h


def hex8(value: int) -> str:
    return "%08x" % (value & _U32)


_HEX8_RE = re.compile(r"[0-9a-f]{8}")


def parse_hex8(text: str) -> Optional[int]:
    """Exactly 8 lowercase hex digits (one canonical text per value)."""
    if not isinstance(text, str) or not _HEX8_RE.fullmatch(text):
        return None
    return int(text, 16)


def room_key(room: str) -> str:
    """Storage/announcement key of a room: fnv1a32(UTF-8) as 8 hex characters."""
    return hex8(fnv1a32(room))


# ---- Text helpers --------------------------------------------------------------------------

_SURROGATE_RE = re.compile("[\ud800-\udfff]")


def _clean(text: str) -> str:
    return _SURROGATE_RE.sub("\ufffd", text) if _SURROGATE_RE.search(text) else text


def json_escape(text: str) -> str:
    """JSON-escaped CONTENT of ``text`` (no quotes); control characters become \\u00XX."""
    return json.dumps(_clean(text), ensure_ascii=False)[1:-1]


def jstr(text: str) -> str:
    """``text`` as a JSON string literal."""
    return '"' + json_escape(text) + '"'


def bounded(value: Any, max_bytes: int) -> str:
    """Truncates to ``max_bytes`` of UTF-8 at a character boundary (C buffers in the firmware).

    Text ends at the first NUL, like a C string.
    """
    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    if "\x00" in text:
        text = text.split("\x00", 1)[0]
    raw = text.encode("utf-8", "replace")
    if len(raw) <= max_bytes:
        return raw.decode("utf-8")
    return raw[:max_bytes].decode("utf-8", "ignore")


def utf8_len(text: str) -> int:
    return len(text.encode("utf-8", "replace"))


# ---- JSON: strict scanner and bounded DOM -------------------------------------------------
# Two ways to read JSON, as in src/protocol/Json.hpp: a validating scanner that hands out
# the RAW bytes of a member (skeletons, plan slices and envelopes must be stored verbatim -
# never re-serialised) and a small DOM with hard limits for the short command bodies.
# Both implement strict RFC 8259 grammar: no leading zeros or '+', no control characters in
# strings, valid UTF-8, \u escapes with proper surrogate pairs, no embedded NUL, whitespace
# limited to space/tab/CR/LF, non-finite numbers rejected.

class JsonError(ValueError):
    pass


_WS_RE = re.compile(rb"[ \t\n\r]*")
_PLAIN_RE = re.compile(rb'[^"\\\x00-\x1f]*')   # no nested quantifier: linear time on hostile input
_HEX4_RE = re.compile(rb"[0-9a-fA-F]{4}")
_NUM_RE = re.compile(rb"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_SIMPLE_ESCAPES = {
    0x22: '"', 0x5C: "\\", 0x2F: "/", 0x62: "\b", 0x66: "\f", 0x6E: "\n", 0x72: "\r", 0x74: "\t",
}


def _unescape(text: str) -> Optional[str]:
    """Decodes the escapes of an already syntax-checked string body (None: lone surrogate/NUL)."""
    out: List[str] = []
    i = 0
    n = len(text)
    while i < n:
        j = text.find("\\", i)
        if j < 0:
            out.append(text[i:])
            break
        out.append(text[i:j])
        e = text[j + 1]
        if e == "u":
            cp = int(text[j + 2:j + 6], 16)
            i = j + 6
            if 0xD800 <= cp <= 0xDBFF:
                if text[i:i + 2] != "\\u":
                    return None
                try:
                    low = int(text[i + 2:i + 6], 16)
                except ValueError:
                    return None
                if not 0xDC00 <= low <= 0xDFFF:
                    return None
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00)
                i += 6
            elif 0xDC00 <= cp <= 0xDFFF:
                return None
            if cp == 0:
                return None
            out.append(chr(cp))
        else:
            out.append(_SIMPLE_ESCAPES[ord(e)])
            i = j + 2
    return "".join(out)


def _scan_string(data: bytes, i: int, decode: bool = False) -> Tuple[int, Optional[str]]:
    """Scans a string starting at the opening quote: (end index, decoded text or None); end -1 if invalid."""
    n = len(data)
    if i >= n or data[i] != 0x22:
        return -1, None
    j = i + 1
    has_escape = False
    has_u = False
    while True:
        j = _PLAIN_RE.match(data, j).end()
        if j >= n:
            return -1, None
        c = data[j]
        if c == 0x22:
            break
        if c != 0x5C:
            return -1, None  # control character
        has_escape = True
        j += 1
        if j >= n:
            return -1, None
        e = data[j]
        if e in _SIMPLE_ESCAPES:
            j += 1
        elif e == 0x75:
            if not _HEX4_RE.match(data, j + 1):
                return -1, None
            has_u = True
            j += 5
        else:
            return -1, None
    try:
        text = data[i + 1:j].decode("utf-8")  # strict: no overlongs, surrogates or > U+10FFFF
    except UnicodeDecodeError:
        return -1, None
    if has_u or (decode and has_escape):
        decoded = _unescape(text)
        if decoded is None:
            return -1, None
        text = decoded
    return j + 1, text if decode else None


def _skip_value(data: bytes, i: int, depth: int, max_depth: int) -> int:
    """Validating skip of one value; returns the index after it or -1."""
    n = len(data)
    i = _WS_RE.match(data, i).end()
    if i >= n:
        return -1
    c = data[i]
    if c == 0x7B:  # {
        if depth + 1 > max_depth:
            return -1
        i = _WS_RE.match(data, i + 1).end()
        if i < n and data[i] == 0x7D:
            return i + 1
        while True:
            i = _WS_RE.match(data, i).end()
            i, _ = _scan_string(data, i)
            if i < 0:
                return -1
            i = _WS_RE.match(data, i).end()
            if i >= n or data[i] != 0x3A:
                return -1
            i = _skip_value(data, i + 1, depth + 1, max_depth)
            if i < 0:
                return -1
            i = _WS_RE.match(data, i).end()
            if i >= n:
                return -1
            if data[i] == 0x2C:
                i += 1
                continue
            if data[i] == 0x7D:
                return i + 1
            return -1
    if c == 0x5B:  # [
        if depth + 1 > max_depth:
            return -1
        i = _WS_RE.match(data, i + 1).end()
        if i < n and data[i] == 0x5D:
            return i + 1
        while True:
            i = _skip_value(data, i, depth + 1, max_depth)
            if i < 0:
                return -1
            i = _WS_RE.match(data, i).end()
            if i >= n:
                return -1
            if data[i] == 0x2C:
                i += 1
                continue
            if data[i] == 0x5D:
                return i + 1
            return -1
    if c == 0x22:
        return _scan_string(data, i)[0]
    if c == 0x74:
        return i + 4 if data.startswith(b"true", i) else -1
    if c == 0x66:
        return i + 5 if data.startswith(b"false", i) else -1
    if c == 0x6E:
        return i + 4 if data.startswith(b"null", i) else -1
    m = _NUM_RE.match(data, i)
    if not m or m.end() - i > 63:
        return -1
    if not math.isfinite(float(data[i:m.end()])):
        return -1
    return m.end()


def json_validate(data: Union[bytes, str], max_depth: int = 16) -> bool:
    """True iff ``data`` is exactly one valid JSON value within the depth limit."""
    raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
    end = _skip_value(raw, 0, 0, max_depth)
    if end < 0:
        return False
    return _WS_RE.match(raw, end).end() == len(raw)


class Scan(Enum):
    FOUND = "found"
    MISSING = "missing"
    INVALID = "invalid"


def find_fields(data: bytes, keys: Iterable[str], max_depth: int = 16) -> Optional[Dict[str, bytes]]:
    """Raw bytes of TOP-LEVEL members of a JSON object (strings include their quotes).

    Duplicate keys: the first wins. The whole document is validated; ``None`` for malformed
    input or non-objects. Missing members are simply absent from the result.
    """
    wanted = set(keys)
    n = len(data)
    i = _WS_RE.match(data, 0).end()
    if i >= n or data[i] != 0x7B:
        return None
    i = _WS_RE.match(data, i + 1).end()
    found: Dict[str, bytes] = {}
    if i < n and data[i] == 0x7D:
        i += 1
    else:
        while True:
            i = _WS_RE.match(data, i).end()
            i, key = _scan_string(data, i, decode=True)
            if i < 0:
                return None
            i = _WS_RE.match(data, i).end()
            if i >= n or data[i] != 0x3A:
                return None
            i = _WS_RE.match(data, i + 1).end()
            end = _skip_value(data, i, 1, max_depth)
            if end < 0:
                return None
            if key in wanted and key not in found:
                found[key] = data[i:end]
            i = _WS_RE.match(data, end).end()
            if i >= n:
                return None
            if data[i] == 0x2C:
                i += 1
                continue
            if data[i] == 0x7D:
                i += 1
                break
            return None
    if _WS_RE.match(data, i).end() != n:
        return None
    return found


def find_field(data: bytes, key: str, max_depth: int = 16) -> Tuple[Scan, Optional[bytes]]:
    found = find_fields(data, (key,), max_depth)
    if found is None:
        return Scan.INVALID, None
    if key not in found:
        return Scan.MISSING, None
    return Scan.FOUND, found[key]


def slice_to_string(raw: Optional[bytes]) -> Optional[str]:
    """Decodes a slice that holds a JSON string (with quotes); None if it is anything else."""
    if not raw or len(raw) < 2:
        return None
    end, text = _scan_string(raw, 0, decode=True)
    return text if end == len(raw) else None


def slice_to_uint(raw: Optional[bytes], max_value: int) -> Optional[int]:
    """Integer without sign/fraction/exponent/leading zeros in [0, max_value]."""
    if not raw or len(raw) > 10 or (len(raw) > 1 and raw[0] == 0x30):
        return None
    for byte in raw:
        if not 0x30 <= byte <= 0x39:
            return None
    value = int(raw)
    return value if value <= max_value else None


def slice_is_null(raw: Optional[bytes]) -> bool:
    return raw == b"null"


def slice_kind(raw: Optional[bytes]) -> str:
    """'o'bject, 'a'rray, 's'tring, 'n'umber, 'b'ool, 'z' (null), '' if empty."""
    if not raw:
        return ""
    c = raw[0:1]
    if c == b"{":
        return "o"
    if c == b"[":
        return "a"
    if c == b'"':
        return "s"
    if c in (b"t", b"f"):
        return "b"
    if c == b"n":
        return "z"
    if c in b"-0123456789":
        return "n"
    return ""


class _Dom:
    def __init__(self, data: bytes, max_depth: int, max_nodes: int) -> None:
        self.data = data
        self.i = 0
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self.nodes = 0

    def document(self) -> Any:
        value = self.value(0)
        self.ws()
        if self.i != len(self.data):
            raise JsonError("trailing characters")
        return value

    def ws(self) -> None:
        self.i = _WS_RE.match(self.data, self.i).end()

    def string(self) -> str:
        end, text = _scan_string(self.data, self.i, decode=True)
        if end < 0:
            raise JsonError("invalid string")
        self.i = end
        return text or ""

    def value(self, depth: int) -> Any:
        self.nodes += 1
        if self.nodes > self.max_nodes:
            raise JsonError("too many values")
        self.ws()
        data = self.data
        if self.i >= len(data):
            raise JsonError("unexpected end")
        c = data[self.i]
        if c == 0x7B:
            return self.obj(depth + 1)
        if c == 0x5B:
            return self.arr(depth + 1)
        if c == 0x22:
            return self.string()
        for word, result in ((b"true", True), (b"false", False), (b"null", None)):
            if c == word[0]:
                if not data.startswith(word, self.i):
                    raise JsonError("invalid literal")
                self.i += len(word)
                return result
        m = _NUM_RE.match(data, self.i)
        if not m or m.end() - self.i > 63:
            raise JsonError("invalid number")
        number = float(data[self.i:m.end()])
        if not math.isfinite(number):
            raise JsonError("number out of range")
        self.i = m.end()
        return number

    def obj(self, depth: int) -> Dict[str, Any]:
        if depth > self.max_depth:
            raise JsonError("too deep")
        result: Dict[str, Any] = {}
        data = self.data
        self.i += 1
        self.ws()
        if self.i < len(data) and data[self.i] == 0x7D:
            self.i += 1
            return result
        while True:
            self.ws()
            key = self.string()
            self.ws()
            if self.i >= len(data) or data[self.i] != 0x3A:
                raise JsonError("expected ':'")
            self.i += 1
            value = self.value(depth)
            if key not in result:  # first occurrence wins, like find_field
                result[key] = value
            self.ws()
            if self.i >= len(data):
                raise JsonError("unexpected end")
            if data[self.i] == 0x2C:
                self.i += 1
                continue
            if data[self.i] == 0x7D:
                self.i += 1
                return result
            raise JsonError("expected ',' or '}'")

    def arr(self, depth: int) -> List[Any]:
        if depth > self.max_depth:
            raise JsonError("too deep")
        result: List[Any] = []
        data = self.data
        self.i += 1
        self.ws()
        if self.i < len(data) and data[self.i] == 0x5D:
            self.i += 1
            return result
        while True:
            result.append(self.value(depth))
            self.ws()
            if self.i >= len(data):
                raise JsonError("unexpected end")
            if data[self.i] == 0x2C:
                self.i += 1
                continue
            if data[self.i] == 0x5D:
                self.i += 1
                return result
            raise JsonError("expected ',' or ']'")


def parse_json(data: Union[bytes, str], max_depth: int = 8, max_nodes: int = EscapeConfig.MAX_JSON_NODES) -> Any:
    """Parses exactly one JSON value (objects -> dict, arrays -> list, numbers -> float).

    Hard limits on nesting depth (root container = 1) and on the number of values bound the
    memory an input can cost. Raises ``JsonError``; never anything else.
    """
    raw = data.encode("utf-8", "surrogatepass") if isinstance(data, str) else bytes(data)
    try:
        return _Dom(raw, max_depth, max_nodes).document()
    except RecursionError:  # pragma: no cover - depth is limited long before this
        raise JsonError("too deep") from None


def json_int(value: Any, lo: int, hi: int) -> Optional[int]:
    """Integer in [lo, hi] without fraction from a DOM number (as ``Value::asInt``)."""
    if isinstance(value, bool) or not isinstance(value, float) or not math.isfinite(value):
        return None
    if value < lo or value > hi or value != math.floor(value):
        return None
    return int(value)


def number_text(value: float) -> str:
    if not math.isfinite(value):
        return "null"
    if value == math.floor(value) and abs(value) < 1e15:
        return str(int(value))
    text = "%.15g" % value
    if float(text) != value:
        text = "%.17g" % value
    return text


def json_text_loose(value: Any) -> str:
    """Strings as they are, numbers and booleans converted to text (config values may be either)."""
    if isinstance(value, str):
        return value
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, float):
        return number_text(value)
    return ""


# ---- Keys and the secure transport (PROTOCOL.md sections 3 and 4) -------------------------

class TokenState(str, Enum):
    DEFAULT = "default"
    CUSTOM = "custom"
    INVALID = "invalid"


KDF_SALT = b"EscapeManager/2/token"
_INFO_REQ = b"EM2 req"
_INFO_RESP = b"EM2 resp"
_INFO_MAC = b"EM2 mac"
_FRAME_HEAD = b'{"doc":'
_FRAME_MAC_KEY = b',"mac":"'
_MAC_TEXT_LEN = 43  # base64url of 32 bytes


def hkdf_sha256(ikm: bytes, salt: Optional[bytes], info: bytes, length: int) -> bytes:
    """HKDF-SHA256 (RFC 5869); an empty salt means 32 zero bytes."""
    if length > 255 * 32:
        raise ValueError("HKDF output too long")
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@dataclass
class DerivedKeys:
    master: bytes
    req: bytes
    resp: bytes
    mac: bytes


def derive_keys(token: Union[str, bytes], iterations: int = EscapeConfig.KDF_ITERATIONS) -> DerivedKeys:
    """token -> PBKDF2-HMAC-SHA256 (salt "EscapeManager/2/token") -> HKDF per purpose."""
    raw = token.encode("utf-8") if isinstance(token, str) else bytes(token)
    master = hashlib.pbkdf2_hmac("sha256", raw, KDF_SALT, iterations, 32)
    return DerivedKeys(master, hkdf_sha256(master, b"", _INFO_REQ, 32), hkdf_sha256(master, b"", _INFO_RESP, 32),
                       hkdf_sha256(master, b"", _INFO_MAC, 32))


def valid_nonce(nonce: str) -> bool:
    return isinstance(nonce, str) and 16 <= len(nonce) <= 64 and re.fullmatch(r"[A-Za-z0-9_-]+", nonce) is not None


def _as_bytes(value: Union[str, bytes, bytearray]) -> bytes:
    return value.encode("utf-8") if isinstance(value, str) else bytes(value)


@dataclass
class OpenResult:
    status: int                  # 200 on success, otherwise the HTTP status to answer with
    code: Optional[str] = None   # machine-readable error code (PROTOCOL.md 5.6)
    plaintext: bytes = b""
    request_iv: str = ""         # set whenever the IV could be read: errors can then be answered authenticated


class SecureTransport:
    """Proto-2 secure transport: POST envelopes, authenticated GET frames, UDP frames.

    Both sides live here (like in the C++ class) so devices can talk to peers and tests can
    play the manager. The replay cache has its own lock, everything else is immutable
    after ``begin()``.
    """

    def __init__(self) -> None:
        self._did = ""
        self._state = TokenState.DEFAULT
        self._began = False
        self._keys_ready = False
        self._k_mac = b""
        self._aead_req: Optional[AESGCM] = None
        self._aead_resp: Optional[AESGCM] = None
        self._replay: List[Tuple[int, bytes]] = []   # (expires_ms, first 8 bytes of the IV)
        self._replay_lock = threading.Lock()

    # ---- state ----------------------------------------------------------------------

    def begin(self, token: Union[str, bytes], state: TokenState, device_id: str) -> bool:
        """Derives all keys (PBKDF2 once at start-up). ``INVALID`` derives nothing: read-only."""
        self._began = True
        self._keys_ready = False
        self._did = device_id
        self._state = state
        self._k_mac = b""
        self._aead_req = self._aead_resp = None
        with self._replay_lock:
            self._replay = []
        if state == TokenState.INVALID:
            return True  # read-only by design
        raw = _as_bytes(token)
        if not EscapeConfig.MIN_AUTH_TOKEN_LEN <= len(raw) <= EscapeConfig.MAX_AUTH_TOKEN_LEN:
            self._state = TokenState.INVALID
            return False
        keys = derive_keys(raw)
        self._k_mac = keys.mac
        self._aead_req = AESGCM(keys.req)
        self._aead_resp = AESGCM(keys.resp)
        self._keys_ready = True
        return True

    @property
    def ready(self) -> bool:
        return self._began

    @property
    def writable(self) -> bool:
        return self._keys_ready and self._state != TokenState.INVALID

    @property
    def token_state(self) -> TokenState:
        return self._state

    @property
    def device_id(self) -> str:
        return self._did

    # ---- MAC frames ---------------------------------------------------------------------

    def _mac(self, prefix: bytes, doc: bytes) -> bytes:
        return hmac.new(self._k_mac, prefix + doc, hashlib.sha256).digest()

    def _frame(self, prefix: bytes, doc: Union[str, bytes]) -> Optional[bytes]:
        if not self._keys_ready:
            return None
        body = _as_bytes(doc)
        mac = b64u_encode(self._mac(prefix, body)).encode("ascii")
        return _FRAME_HEAD + body + _FRAME_MAC_KEY + mac + b'"}'

    def _open_frame(self, prefix: bytes, data: bytes) -> Optional[bytes]:
        if not self._keys_ready:
            return None
        data = bytes(data)
        tail = len(_FRAME_MAC_KEY) + _MAC_TEXT_LEN + 2
        n = len(data)
        if n < len(_FRAME_HEAD) + 2 + tail or not data.startswith(_FRAME_HEAD) or not data.endswith(b'"}'):
            return None
        doc_end = n - tail
        if data[doc_end:doc_end + len(_FRAME_MAC_KEY)] != _FRAME_MAC_KEY:
            return None
        try:
            mac = b64u_decode(data[doc_end + len(_FRAME_MAC_KEY):n - 2])
        except ValueError:
            return None
        doc = data[len(_FRAME_HEAD):doc_end]
        if len(mac) != 32 or not hmac.compare_digest(mac, self._mac(prefix, doc)):
            return None
        return doc

    @staticmethod
    def _get_prefix(did: str, path: str, nonce: str, status: int) -> bytes:
        return ("EM2|get|%s|%s|%s|%d|" % (did, path, nonce, status)).encode("utf-8")

    def frame_document(self, path: str, nonce: str, status: int, doc: Union[str, bytes]) -> Optional[bytes]:
        """``{"doc":<doc>,"mac":"..."}`` for GET responses; ``nonce`` must satisfy ``valid_nonce``."""
        if not valid_nonce(nonce):
            return None
        return self._frame(self._get_prefix(self._did, path, nonce, status), doc)

    def open_document_frame_from(self, from_did: str, path: str, nonce: str, status: int,
                                 body: bytes) -> Optional[bytes]:
        """Verifies a GET frame produced by the device ``from_did`` (the MAC binds the RESPONDING id)."""
        if not valid_nonce(nonce):
            return None
        return self._open_frame(self._get_prefix(from_did, path, nonce, status), body)

    def open_document_frame(self, path: str, nonce: str, status: int, body: bytes) -> Optional[bytes]:
        return self.open_document_frame_from(self._did, path, nonce, status, body)

    def frame_announcement(self, doc: Union[str, bytes]) -> Optional[bytes]:
        return self._frame(b"EM2|udp|", doc)

    def open_announcement(self, data: bytes) -> Optional[bytes]:
        return self._open_frame(b"EM2|udp|", data)

    # ---- AEAD envelopes ----------------------------------------------------------------------

    @staticmethod
    def _seal(aead: AESGCM, aad: str, iv: bytes, plaintext: bytes) -> str:
        return b64u_encode(aead.encrypt(iv, plaintext, aad.encode("utf-8")))

    def seal_request(self, path: str, t: int, plaintext: Union[str, bytes],
                     iv: Optional[bytes] = None) -> Optional[bytes]:
        """Client side: the POST body for ``path`` (``iv`` defaults to 12 random bytes)."""
        if not self._keys_ready or self._aead_req is None:
            return None
        iv = secrets.token_bytes(12) if iv is None else bytes(iv)
        if len(iv) != 12:
            raise ValueError("IV must be 12 bytes")
        aad = "EM2|req|%s|%s|%d" % (self._did, path, t)
        ct = self._seal(self._aead_req, aad, iv, _as_bytes(plaintext))
        return ('{"v":%d,"t":%d,"iv":"%s","ct":"%s"}' % (PROTO, t, b64u_encode(iv), ct)).encode("ascii")

    def seal_response(self, path: str, request_iv: str, status: int, body: Union[str, bytes],
                      iv: Optional[bytes] = None) -> Optional[bytes]:
        if not self._keys_ready or self._aead_resp is None:
            return None
        iv = secrets.token_bytes(12) if iv is None else bytes(iv)
        aad = "EM2|resp|%s|%s|%s|%d" % (self._did, path, request_iv, status)
        ct = self._seal(self._aead_resp, aad, iv, _as_bytes(body))
        return ('{"v":%d,"iv":"%s","ct":"%s"}' % (PROTO, b64u_encode(iv), ct)).encode("ascii")

    def open_response(self, path: str, request_iv: str, status: int, body: bytes) -> Optional[bytes]:
        """Client side: decrypts a response envelope; None if anything does not verify."""
        if not self._keys_ready or self._aead_resp is None:
            return None
        found = find_fields(bytes(body), ("v", "iv", "ct"))
        if found is None or len(found) != 3:
            return None
        v = slice_to_uint(found["v"], 255)
        if v is None or v < PROTO_MIN:
            return None
        try:
            iv = b64u_decode(slice_to_string(found["iv"]) or "\x00")
            ct = b64u_decode(slice_to_string(found["ct"]) or "\x00")
        except ValueError:
            return None
        if len(iv) != 12 or len(ct) < 16:
            return None
        aad = "EM2|resp|%s|%s|%s|%d" % (self._did, path, request_iv, status)
        try:
            return self._aead_resp.decrypt(iv, ct, aad.encode("utf-8"))
        except InvalidTag:
            return None

    def open_request(self, path: str, body: bytes, now_ms: int) -> OpenResult:
        """Device side: authenticates one POST envelope (checks in the order of PROTOCOL.md 4.2)."""
        body = bytes(body)
        if len(body) > EscapeConfig.MAX_BODY_BYTES:
            return OpenResult(413, "too_large")
        found = find_fields(body, ("v", "t", "iv", "ct"))
        if found is None or len(found) != 4:
            return OpenResult(400, "bad_envelope")
        v = slice_to_uint(found["v"], 255)
        t = slice_to_uint(found["t"], _U32)
        if v is None or v < PROTO_MIN or v > PROTO or t is None:
            return OpenResult(400, "bad_envelope")
        iv_text = slice_to_string(found["iv"])
        try:
            iv = b64u_decode(iv_text) if iv_text is not None else b""
        except ValueError:
            iv = b""
        if len(iv) != 12:
            return OpenResult(400, "bad_envelope")
        if not self.writable or self._aead_req is None:
            return OpenResult(503, "read_only")
        request_iv = iv_text or ""  # from here on errors can be answered authenticated

        skew = s32(t - now_ms)
        if skew > EscapeConfig.TIME_WINDOW_MS or skew < -EscapeConfig.TIME_WINDOW_MS:
            return OpenResult(409, "stale_time", request_iv=request_iv)
        ct_text = slice_to_string(found["ct"])
        try:
            ct = b64u_decode(ct_text) if ct_text is not None else b""
        except ValueError:
            ct = b""
        if len(ct) < 16:
            return OpenResult(400, "bad_envelope", request_iv=request_iv)
        aad = ("EM2|req|%s|%s|%d" % (self._did, path, t)).encode("utf-8")
        try:
            plaintext = self._aead_req.decrypt(iv, ct, aad)
        except InvalidTag:
            return OpenResult(401, "auth_failed", request_iv=request_iv)

        # Replay cache: only authenticated requests may enter it; full of fresh entries = fail closed.
        iv8 = iv[:8]
        with self._replay_lock:
            live = [entry for entry in self._replay if s32(now_ms - entry[0]) <= 0]
            self._replay = live
            for _expires, known in live:
                if known == iv8:
                    return OpenResult(409, "replay", request_iv=request_iv)
            if len(live) >= EscapeConfig.REPLAY_CACHE_SIZE:
                return OpenResult(429, "rate_limited", request_iv=request_iv)
            live.append((u32(t + EscapeConfig.TIME_WINDOW_MS), iv8))
        return OpenResult(200, None, plaintext, request_iv)

    def replay_entries(self, now_ms: int) -> int:
        with self._replay_lock:
            return sum(1 for entry in self._replay if s32(now_ms - entry[0]) <= 0)


# ---- Rate limiting -----------------------------------------------------------------------------

class RateLimiter:
    """Per-source token buckets plus a global per-second budget (src/protocol/RateLimiter.hpp)."""

    class _Slot:
        __slots__ = ("used", "source", "last_ms", "tokens")

        def __init__(self) -> None:
            self.used = False
            self.source = 0
            self.last_ms = 0
            self.tokens = 0

    def __init__(self) -> None:
        self._slots = [RateLimiter._Slot() for _ in range(EscapeConfig.RATE_SOURCES)]
        self._window_start = 0
        self._window_count = 0

    def allow_source(self, source: int, now_ms: int, cost: int = 1) -> bool:
        slot = None
        oldest = self._slots[0]
        for candidate in self._slots:
            if candidate.used and candidate.source == source:
                slot = candidate
            if not candidate.used or s32(oldest.last_ms - candidate.last_ms) > 0:
                oldest = candidate
        if slot is None:  # new source: take over the least recently used slot with a full bucket
            slot = oldest
            slot.used = True
            slot.source = source
            slot.tokens = EscapeConfig.RATE_BURST
            slot.last_ms = u32(now_ms)
        gained = u32(now_ms - slot.last_ms) // EscapeConfig.RATE_REFILL_MS
        if gained:
            slot.tokens = min(EscapeConfig.RATE_BURST, slot.tokens + gained)
            slot.last_ms = u32(slot.last_ms + gained * EscapeConfig.RATE_REFILL_MS)
        if slot.tokens < cost:
            return False
        slot.tokens -= cost
        return True

    def allow_global(self, now_ms: int) -> bool:
        if u32(now_ms - self._window_start) >= 1000:
            self._window_start = u32(now_ms)
            self._window_count = 0
        if self._window_count >= EscapeConfig.GLOBAL_POSTS_PER_SECOND:
            return False
        self._window_count += 1
        return True


# ---- Addresses, announcements and the peer table (PROTOCOL.md 4.3) -----------------------

_IPV4_RE = re.compile(r"(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})\.(0|[1-9][0-9]{0,2})")
_DID_RE = re.compile(r"[0-9a-f]{12}")


def parse_ipv4(text: str) -> Optional[int]:
    """"a.b.c.d" -> 32-bit integer; strict (no leading zeros, no spaces, parts <= 255)."""
    if not isinstance(text, str):
        return None
    m = _IPV4_RE.fullmatch(text)
    if not m:
        return None
    parts = [int(g) for g in m.groups()]
    if any(p > 255 for p in parts):
        return None
    return (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]


def ipv4_to_str(value: int) -> str:
    return "%d.%d.%d.%d" % ((value >> 24) & 255, (value >> 16) & 255, (value >> 8) & 255, value & 255)


def valid_did(text: str) -> bool:
    """Device ids are 12 lowercase hex characters."""
    return isinstance(text, str) and _DID_RE.fullmatch(text) is not None


MAX_ANNOUNCED_ROOMS = 8


@dataclass
class AnnouncedSkeleton:
    room_key: int
    rev: int
    hash: int


@dataclass
class Announcement:
    did: str
    ip: str
    port: int
    version: int          # `v`: protocol level used by the sender
    pmin: int
    boot: int
    ctr: int
    seq: int
    uih: int
    skh: int
    sk: List[AnnouncedSkeleton] = field(default_factory=list)


def build_announcement_doc(did: str, ip: str, port: int, boot: int, ctr: int, seq: int, pmin: int, ui_hash: str,
                           skeleton_summary_json: str, skeleton_summary_hash: int) -> str:
    """The announcement DOC (before MAC framing); field order is part of the byte-exact format."""
    return ('{"v":2,"did":"%s","ip":"%s","port":%d,"boot":%d,"ctr":%d,"seq":%d,"pmin":%d,"uih":"%s",'
            '"skh":"%s","sk":%s}' % (did, ip, port, boot, ctr, seq, pmin, ui_hash,
                                      hex8(skeleton_summary_hash), skeleton_summary_json))


def parse_announcement(doc: bytes) -> Optional[Announcement]:
    """Strict parser of an announcement DOC; None for anything malformed or out of range."""
    fields = find_fields(bytes(doc), ("v", "port", "pmin", "boot", "ctr", "seq", "did", "ip", "uih", "skh", "sk"), 8)
    if fields is None:
        return None
    v = slice_to_uint(fields.get("v"), 255)
    port = slice_to_uint(fields.get("port"), 65535)
    pmin = slice_to_uint(fields.get("pmin"), 255)
    boot = slice_to_uint(fields.get("boot"), _U32)
    ctr = slice_to_uint(fields.get("ctr"), _U32)
    seq = slice_to_uint(fields.get("seq"), _U32)
    did = slice_to_string(fields.get("did"))
    ip = slice_to_string(fields.get("ip"))
    uih_text = slice_to_string(fields.get("uih"))
    if None in (v, port, pmin, boot, ctr, seq) or not port or did is None or ip is None or uih_text is None:
        return None
    if not valid_did(did) or len(ip) > 15 or parse_ipv4(ip) is None:
        return None
    uih = parse_hex8(uih_text)
    if uih is None:
        return None
    sk_raw = fields.get("sk")
    if sk_raw is None or slice_kind(sk_raw) != "a":
        return None
    if "skh" in fields:
        skh_text = slice_to_string(fields["skh"])
        skh = parse_hex8(skh_text) if skh_text is not None else None
        if skh is None:
            return None
    else:
        # PROTOCOL.md 4.3 does not list `skh`; the C++ code sends and requires it. A peer that
        # follows the document literally gets the same fingerprint the C++ side would compute.
        skh = fnv1a32(sk_raw)
    try:
        arr = parse_json(sk_raw, 3, 1 + MAX_ANNOUNCED_ROOMS * 4)
    except JsonError:
        return None
    if not isinstance(arr, list) or len(arr) > MAX_ANNOUNCED_ROOMS:
        return None
    sk: List[AnnouncedSkeleton] = []
    for entry in arr:
        if not isinstance(entry, list) or len(entry) != 3 or not isinstance(entry[0], str) or not isinstance(entry[2], str):
            return None
        rev = json_int(entry[1], 0, _U32)
        key = parse_hex8(entry[0])
        digest = parse_hex8(entry[2])
        if rev is None or key is None or digest is None:
            return None
        sk.append(AnnouncedSkeleton(key, rev, digest))
    return Announcement(did, ip, port, v, pmin, boot, ctr, seq, uih, skh, sk)  # type: ignore[arg-type]


@dataclass
class PeerEntry:
    did: str
    proto: int
    pmin: int
    port: int
    ip: str
    boot: int
    ctr: int
    seq: int
    uih: int
    skh: int
    last_seen_ms: int


class IngestResult(Enum):
    ACCEPTED = "accepted"
    OWN = "own"
    BAD_SOURCE = "bad_source"
    REPLAY = "replay"


class PeerTable:
    """Compact table of the devices heard on the network (entries: address, counters, fingerprints)."""

    def __init__(self, capacity: int = EscapeConfig.MAX_PEER_ADDRESSES) -> None:
        self._capacity = capacity
        self._peers: List[PeerEntry] = []

    def ingest(self, a: Announcement, source_ip: str, own_did: str, now_ms: int) -> IngestResult:
        """Freshness rules of PROTOCOL.md 4.3: ``ip`` must equal the datagram source and
        (boot, ctr) must be strictly larger than the last accepted pair of that device."""
        if a.did == own_did:
            return IngestResult.OWN
        if not source_ip or source_ip != a.ip or parse_ipv4(a.ip) is None:
            return IngestResult.BAD_SOURCE
        entry = next((p for p in self._peers if p.did == a.did), None)
        if entry is not None:
            if not (a.boot > entry.boot or (a.boot == entry.boot and a.ctr > entry.ctr)):
                return IngestResult.REPLAY
        elif len(self._peers) < self._capacity:
            entry = PeerEntry(a.did, 0, 0, 0, "", 0, 0, 0, 0, 0, 0)
            self._peers.append(entry)
        else:  # table full: evict the peer heard longest ago
            entry = self._peers[0]
            for p in self._peers[1:]:
                if s32(entry.last_seen_ms - p.last_seen_ms) > 0:
                    entry = p
            entry.did = a.did
        entry.proto, entry.pmin, entry.port, entry.ip = a.version, a.pmin, a.port, a.ip
        entry.boot, entry.ctr, entry.seq, entry.uih, entry.skh = a.boot, a.ctr, a.seq, a.uih, a.skh
        entry.last_seen_ms = u32(now_ms)
        return IngestResult.ACCEPTED

    def expire_stale(self, now_ms: int, timeout_ms: int = EscapeConfig.PEER_TIMEOUT_MS) -> None:
        self._peers = [p for p in self._peers if u32(now_ms - p.last_seen_ms) <= timeout_ms]

    @property
    def count(self) -> int:
        return len(self._peers)

    def entries(self) -> List[PeerEntry]:
        return list(self._peers)

    def at(self, index: int) -> PeerEntry:
        return self._peers[index]

    def find_by_did(self, did: str) -> Optional[PeerEntry]:
        return next((p for p in self._peers if p.did == did), None)

    def clear(self) -> None:
        self._peers = []


# ---- Persistent storage and the skeleton store (PROTOCOL.md 5.4) ---------------------------

_STORAGE_KEY_RE = re.compile(r"[A-Za-z0-9_]{1,15}")


class BlobStorage(abc.ABC):
    """Persistent key/value blobs (the firmware uses NVS, the Python port files). Keys: [A-Za-z0-9_]{1,15}."""

    @abc.abstractmethod
    def read(self, key: str) -> Optional[bytes]:
        """None if the key does not exist (or cannot be read)."""

    @abc.abstractmethod
    def write(self, key: str, data: bytes) -> bool:
        """False if the value could not be stored. Must not damage the old value."""

    @abc.abstractmethod
    def erase(self, key: str) -> bool:
        ...


class MemoryStorage(BlobStorage):
    """RAM-backed storage with an optional capacity limit, for tests and volatile devices."""

    def __init__(self) -> None:
        self._data: Dict[str, bytes] = {}
        self.capacity = 0
        self.fail_writes = False
        self.write_count = 0
        self._lock = threading.Lock()

    def read(self, key: str) -> Optional[bytes]:
        with self._lock:
            return self._data.get(key)

    def write(self, key: str, data: bytes) -> bool:
        data = _as_bytes(data)
        with self._lock:
            if self.fail_writes:
                return False
            if self.capacity:
                used = len(data) + sum(len(v) for k, v in self._data.items() if k != key)
                if used > self.capacity:
                    return False
            self._data[key] = data
            self.write_count += 1
            return True

    def erase(self, key: str) -> bool:
        with self._lock:
            return self._data.pop(key, None) is not None

    def has(self, key: str) -> bool:
        with self._lock:
            return key in self._data

    def key_count(self) -> int:
        with self._lock:
            return len(self._data)


class FileStorage(BlobStorage):
    """One file per key; writes are atomic (temp file, fsync, rename) so a crash keeps the old value."""

    def __init__(self, directory: str) -> None:
        self.directory = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)

    def _path(self, key: str) -> Optional[str]:
        if not _STORAGE_KEY_RE.fullmatch(key):
            return None
        return os.path.join(self.directory, key)

    def read(self, key: str) -> Optional[bytes]:
        path = self._path(key)
        if path is None:
            return None
        try:
            with open(path, "rb") as handle:
                return handle.read()
        except OSError:
            return None

    def write(self, key: str, data: bytes) -> bool:
        path = self._path(key)
        if path is None:
            return False
        tmp = "%s.%d.%d.tmp" % (path, os.getpid(), threading.get_ident())
        try:
            with open(tmp, "wb") as handle:
                handle.write(_as_bytes(data))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, path)
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            return False
        try:  # make the rename durable; best effort
            dir_fd = os.open(self.directory, os.O_RDONLY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass
        return True

    def erase(self, key: str) -> bool:
        path = self._path(key)
        if path is None:
            return False
        try:
            os.unlink(path)
            return True
        except OSError:
            return False

    def sub(self, name: str) -> "FileStorage":
        return FileStorage(os.path.join(self.directory, name))


def valid_room_name(room: Any) -> bool:
    return isinstance(room, str) and 0 < utf8_len(room) <= EscapeConfig.MAX_ROOM_LEN


@dataclass
class SkeletonInfo:
    room: str
    rev: int
    hash: int


class SkeletonResult(Enum):
    STORED = "stored"              # new revision written
    UNCHANGED = "unchanged"        # identical content already stored (idempotent)
    CONFLICT = "conflict"          # baseRev does not match the stored revision
    TOO_LARGE = "too_large"
    INVALID = "invalid"            # not a JSON object / bad room / bad blob
    ROOM_LIMIT = "room_limit"      # more rooms than MAX_SKELETON_ROOMS
    KEY_COLLISION = "key_collision"  # two different rooms share a storage key
    STORAGE_ERROR = "storage_error"
    NOT_NEWER = "not_newer"        # adopt(): offered blob is not newer


_INDEX_KEY = "skidx"


def skeleton_is_newer(rev: int, digest: int, cur_rev: int, cur_digest: int) -> bool:
    """True if (rev, hash) beats (cur_rev, cur_hash), compared lexicographically."""
    return rev > cur_rev or (rev == cur_rev and digest > cur_digest)


class SkeletonStore:
    """Per-room plan skeletons, stored opaque with a revision and a content hash.

    ``(rev, hash)`` decides convergence (never uptime or who wrote last). The raw bytes of ``sk``
    are kept verbatim; only a small index (room, rev, hash) lives in RAM. NOT thread safe:
    the owner serialises access.
    """

    def __init__(self, storage: BlobStorage) -> None:
        self._storage = storage
        self._index: List[SkeletonInfo] = []

    # ---- reading ----------------------------------------------------------------------------

    def load(self) -> bool:
        """Reads the index. A missing index is an empty store; a damaged one is dropped."""
        self._index = []
        raw = self._storage.read(_INDEX_KEY)
        if raw is None:
            return True
        try:
            doc = parse_json(raw)
        except JsonError:
            return False
        if not isinstance(doc, list):
            return False
        for entry in doc:
            if len(self._index) >= EscapeConfig.MAX_SKELETON_ROOMS:
                break
            if not isinstance(entry, dict):
                continue
            room, rev, digest = entry.get("r"), json_int(entry.get("v"), 0, _U32), None
            if isinstance(entry.get("h"), str):
                digest = parse_hex8(entry["h"])
            if not valid_room_name(room) or rev is None or digest is None:
                continue  # damaged entry: drop it, keep the rest
            self._index.append(SkeletonInfo(room, rev, digest))
        return True

    @property
    def count(self) -> int:
        return len(self._index)

    def at(self, index: int) -> SkeletonInfo:
        return self._index[index]

    def infos(self) -> List[SkeletonInfo]:
        return list(self._index)

    def find(self, room: str) -> Optional[SkeletonInfo]:
        return next((s for s in self._index if s.room == room), None)

    def get(self, room: str) -> Optional[bytes]:
        """The stored blob ``{"room":..,"rev":..,"hash":..,"sk":{...}}``."""
        if self.find(room) is None:
            return None
        return self._storage.read(self._blob_key(room))

    @staticmethod
    def _blob_key(room: str) -> str:
        return "sk_" + room_key(room)

    def _key_collides(self, room: str) -> bool:
        key = fnv1a32(room)
        return any(s.room != room and fnv1a32(s.room) == key for s in self._index)

    # ---- writing --------------------------------------------------------------------------------

    def _save_index(self) -> bool:
        text = "[" + ",".join('{"r":%s,"v":%d,"h":"%s"}' % (jstr(s.room), s.rev, hex8(s.hash))
                              for s in self._index) + "]"
        return self._storage.write(_INDEX_KEY, text.encode("utf-8"))

    def _store(self, room: str, rev: int, digest: int, sk: bytes) -> SkeletonResult:
        blob = ('{"room":%s,"rev":%d,"hash":"%s","sk":' % (jstr(room), rev, hex8(digest))).encode("utf-8") + sk + b"}"
        if not self._storage.write(self._blob_key(room), blob):
            return SkeletonResult.STORAGE_ERROR
        entry = self.find(room)
        previous = SkeletonInfo(entry.room, entry.rev, entry.hash) if entry else None
        if entry is None:
            entry = SkeletonInfo(room, rev, digest)
            self._index.append(entry)
        else:
            entry.rev, entry.hash = rev, digest
        if not self._save_index():
            # Keep RAM and storage consistent: roll the index back; the orphaned blob is harmless.
            if previous is not None:
                entry.rev, entry.hash = previous.rev, previous.hash
            else:
                self._index.pop()
            return SkeletonResult.STORAGE_ERROR
        return SkeletonResult.STORED

    def put(self, room: str, base_rev: int, sk: bytes) -> Tuple[SkeletonResult, int, int]:
        """Manager write: stores ``sk`` (raw JSON object) as revision base_rev+1 if the stored
        revision equals base_rev (0 for a room without skeleton). Returns (result, rev, hash)."""
        sk = bytes(sk)
        if not valid_room_name(room):
            return SkeletonResult.INVALID, 0, 0
        if len(sk) > EscapeConfig.MAX_PLAN_SKELETON_LEN:
            return SkeletonResult.TOO_LARGE, 0, 0
        if len(sk) < 2 or sk[0:1] != b"{" or not json_validate(sk, 16):
            return SkeletonResult.INVALID, 0, 0
        new_hash = fnv1a32(sk)
        existing = self.find(room)
        cur_rev = existing.rev if existing else 0
        if existing and existing.hash == new_hash:
            return SkeletonResult.UNCHANGED, existing.rev, existing.hash  # identical content: retries are harmless
        if base_rev != cur_rev:
            return SkeletonResult.CONFLICT, cur_rev, existing.hash if existing else 0
        if not existing and len(self._index) >= EscapeConfig.MAX_SKELETON_ROOMS:
            return SkeletonResult.ROOM_LIMIT, 0, 0
        if not existing and self._key_collides(room):
            return SkeletonResult.KEY_COLLISION, 0, 0
        if cur_rev == _U32:
            return SkeletonResult.INVALID, 0, 0
        result = self._store(room, cur_rev + 1, new_hash, sk)
        if result == SkeletonResult.STORED:
            return result, cur_rev + 1, new_hash
        return result, 0, 0

    def adopt(self, blob: bytes, expected_room: str) -> SkeletonResult:
        """Sync write: takes a complete blob from a peer, re-validates it (room, hash over ``sk``)
        and stores it, byte for byte, if it is newer than what we have."""
        blob = bytes(blob)
        if len(blob) > EscapeConfig.MAX_PLAN_SKELETON_LEN + 160:
            return SkeletonResult.TOO_LARGE
        fields = find_fields(blob, ("room", "rev", "hash", "sk"))
        if fields is None or len(fields) != 4:
            return SkeletonResult.INVALID
        room = slice_to_string(fields["room"])
        rev = slice_to_uint(fields["rev"], _U32)
        hash_text = slice_to_string(fields["hash"])
        digest = parse_hex8(hash_text) if hash_text is not None else None
        if room is None or room != expected_room or not valid_room_name(room) or not rev or digest is None:
            return SkeletonResult.INVALID
        sk = fields["sk"]
        if len(sk) > EscapeConfig.MAX_PLAN_SKELETON_LEN:
            return SkeletonResult.TOO_LARGE
        if len(sk) < 2 or sk[0:1] != b"{" or not json_validate(sk, 16):
            return SkeletonResult.INVALID
        if fnv1a32(sk) != digest:
            return SkeletonResult.INVALID  # content does not match its claimed hash
        existing = self.find(room)
        if existing and not skeleton_is_newer(rev, digest, existing.rev, existing.hash):
            return SkeletonResult.NOT_NEWER
        if not existing and len(self._index) >= EscapeConfig.MAX_SKELETON_ROOMS:
            return SkeletonResult.ROOM_LIMIT
        if not existing and self._key_collides(room):
            return SkeletonResult.KEY_COLLISION
        return self._store(room, rev, digest, sk)

    def keep_only(self, rooms: Iterable[str]) -> None:
        """Drops skeletons of rooms that have no local component any more."""
        keep = set(rooms)
        changed = False
        for info in list(self._index):
            if info.room not in keep:
                self._storage.erase(self._blob_key(info.room))
                self._index.remove(info)
                changed = True
        if changed:
            self._save_index()

    # ---- fingerprints ----------------------------------------------------------------------------

    def summary_json(self) -> str:
        """``[["room8",rev,"hash8"],...]`` - the `sk` member of announcements."""
        return "[" + ",".join('["%s",%d,"%s"]' % (room_key(s.room), s.rev, hex8(s.hash)) for s in self._index) + "]"

    def summary_hash(self) -> int:
        return fnv1a32(self.summary_json())


# ---- Protocol: data model, documents and the five mutating endpoints -----------------------

class PlanAction(str, Enum):
    """Explicit plan commands, separate from free-form component actions."""

    RESET = "reset"
    COMPLETE = "complete"


def plan_action_bit(action: PlanAction) -> int:
    return 1 << (0 if action == PlanAction.RESET else 1)


ALL_PLAN_ACTIONS = plan_action_bit(PlanAction.RESET) | plan_action_bit(PlanAction.COMPLETE)


@dataclass
class CustomConfigDef:
    """One configurable field of a component (type, limits, current value)."""

    key: str
    type: str = "text"          # "range" | "text" | "select"
    value: str = ""
    range_min: int = 0
    range_max: int = 0
    text_max_len: int = 0
    options: List[str] = field(default_factory=list)

    def accepts(self, value: str) -> bool:
        return validate_custom_config_value(self, value)


def normalize_config_def(d: CustomConfigDef) -> CustomConfigDef:
    """Applies the firmware's fixed buffer sizes (key 20, value 48, up to 6 options of 16 bytes)."""
    kind = d.type if d.type in ("range", "select") else "text"
    return CustomConfigDef(
        bounded(d.key, EscapeConfig.MAX_CONFIG_KEY_LEN), kind, bounded(d.value, EscapeConfig.MAX_CONFIG_VALUE_LEN),
        max(-0x80000000, min(0x7FFFFFFF, int(d.range_min))), max(-0x80000000, min(0x7FFFFFFF, int(d.range_max))),
        max(0, min(0xFFFF, int(d.text_max_len))),
        [bounded(o, EscapeConfig.MAX_CONFIG_OPTION_LEN) for o in list(d.options)[:EscapeConfig.MAX_CONFIG_OPTIONS]])


_RANGE_RE = re.compile(r"-?[0-9]+")


def validate_custom_config_value(d: CustomConfigDef, value: str) -> bool:
    """Checks a value arriving from outside against the schema the component declared."""
    if d.type == "range":
        if not value or len(value) > 12 or not _RANGE_RE.fullmatch(value):  # strict integer text
            return False
        return d.range_min <= int(value) <= d.range_max
    if d.type == "select":
        return value in list(d.options)[:EscapeConfig.MAX_CONFIG_OPTIONS]
    return utf8_len(value) <= d.text_max_len and utf8_len(value) <= EscapeConfig.MAX_CONFIG_VALUE_LEN


@dataclass
class ComponentSnapshot:
    """One local component as it appears in status.json."""

    uuid: str = ""
    riddle_id: str = ""
    name: str = ""
    room: str = ""
    errors: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    plan_action_mask: int = 0
    feed: str = ""
    tip: str = ""
    puzzle_step: int = 0
    puzzle_total_steps: int = 0   # 0 == no puzzle information
    puzzle_state: str = ""
    puzzle_is_html: bool = False
    custom_config: List[CustomConfigDef] = field(default_factory=list)
    plan: str = ""                # opaque plan slice (JSON object text)
    event_seq: int = 0
    event_msg: str = ""


@dataclass
class DeviceInfo:
    """Device-wide values for the documents."""

    did: str = ""
    ui_hash: str = "00000000"
    ip: str = ""
    port: int = EscapeConfig.HTTP_PORT
    boot: int = 0
    seq: int = 0
    now_ms: int = 0
    battery: int = -1                 # percent; <= 0 means "no battery / unknown"
    token: TokenState = TokenState.DEFAULT
    writable: bool = True


class ProtocolAdapter(abc.ABC):
    """The single type an integration implements (``EscapeComponent`` does, tests use fakes)."""

    @abc.abstractmethod
    def battery(self) -> int:
        """Percent; <= 0: no battery / unknown."""

    @abc.abstractmethod
    def mark_dirty(self) -> None:
        """Observable state changed: bump `seq` and announce soon."""

    @abc.abstractmethod
    def component_count(self) -> int: ...

    @abc.abstractmethod
    def identity(self, index: int) -> Tuple[str, str]:
        """(name, room)"""

    @abc.abstractmethod
    def snapshot(self, index: int) -> ComponentSnapshot: ...

    @abc.abstractmethod
    def custom_config_defs(self, index: int) -> List[CustomConfigDef]: ...

    # commands (already authenticated and validated by the protocol layer)
    @abc.abstractmethod
    def apply_action(self, index: int, action: str) -> bool: ...

    @abc.abstractmethod
    def apply_plan_action(self, index: int, action: PlanAction) -> bool: ...

    @abc.abstractmethod
    def set_identity(self, index: int, name: str, room: str) -> None: ...

    @abc.abstractmethod
    def set_riddle_id(self, index: int, riddle_id: str) -> None: ...

    @abc.abstractmethod
    def set_custom_config_value(self, index: int, key: str, value: str) -> bool: ...

    @abc.abstractmethod
    def set_plan(self, index: int, plan_json: str) -> None: ...

    @abc.abstractmethod
    def push_event(self, index: int, message: str) -> None: ...


def hosted_rooms(host: ProtocolAdapter) -> List[str]:
    """Distinct rooms of the local components (for skeleton hosting and cleanup)."""
    rooms: List[str] = []
    for i in range(host.component_count()):
        _name, room = host.identity(i)
        if room and room not in rooms:
            rooms.append(room)
    return rooms


# ---- Documents ---------------------------------------------------------------------------------

def _is_http_url(text: str) -> bool:
    return text.startswith("http://") or text.startswith("https://")


def _write_config_def(d: CustomConfigDef) -> str:
    out = '{"key":%s,"type":"%s",' % (jstr(d.key), d.type)
    if d.type == "range":
        out += '"min":%d,"max":%d,' % (d.range_min, d.range_max)
    elif d.type == "select":
        out += '"options":[' + ",".join(jstr(o) for o in d.options[:EscapeConfig.MAX_CONFIG_OPTIONS]) + "],"
    else:
        out += '"maxLength":%d,' % d.text_max_len
    return out + '"value":%s}' % jstr(d.value)


def _write_component(index: int, c: ComponentSnapshot) -> str:
    cfg = EscapeConfig
    out = '{"id":%d,"uuid":%s,"riddleId":%s,"name":%s,"room":%s' % (
        index, jstr(bounded(c.uuid, cfg.MAX_UUID_LEN)), jstr(bounded(c.riddle_id, cfg.MAX_RIDDLE_ID_LEN)),
        jstr(bounded(c.name, cfg.MAX_NAME_LEN)), jstr(bounded(c.room, cfg.MAX_ROOM_LEN)))
    out += ',"errors":[' + ",".join(jstr(bounded(e, cfg.MAX_ERROR_LEN)) for e in c.errors[:cfg.MAX_ERRORS]) + "]"
    out += ',"actions":[' + ",".join(jstr(bounded(a, cfg.MAX_ACTION_LEN)) for a in c.actions[:cfg.MAX_ACTIONS]) + "]"
    plan_actions = [a.value for a in (PlanAction.RESET, PlanAction.COMPLETE) if c.plan_action_mask & plan_action_bit(a)]
    out += ',"planActions":[' + ",".join('"%s"' % a for a in plan_actions) + "]"
    feed = bounded(c.feed, cfg.MAX_FEED_LEN)
    if feed and _is_http_url(feed):
        out += ',"feed":%s' % jstr(feed)
    tip = bounded(c.tip, cfg.MAX_TIP_LEN)
    if tip:
        out += ',"tip":%s' % jstr(tip)
    if c.puzzle_total_steps > 0:
        out += ',"puzzle":{"step":%d,"totalSteps":%d,"state":%s,"isHtml":%s}' % (
            max(0, min(0xFFFF, int(c.puzzle_step))), min(0xFFFF, int(c.puzzle_total_steps)),
            jstr(bounded(c.puzzle_state, cfg.MAX_STATE_LEN)), "true" if c.puzzle_is_html else "false")
    if c.custom_config:
        out += ',"customConfig":[' + ",".join(_write_config_def(normalize_config_def(d))
                                              for d in c.custom_config[:cfg.MAX_CUSTOM_CONFIGS]) + "]"
    plan = bounded(c.plan, cfg.MAX_PLAN_LEN)
    if plan and json_validate(plan, 16):
        out += ',"plan":' + plan  # verbatim: the slice is opaque to the device
    if c.event_seq:
        out += ',"evtSeq":%d,"evtMsg":%s' % (c.event_seq & _U32, jstr(bounded(c.event_msg, cfg.MAX_EVENT_MSG_LEN)))
    return out + "}"


def _common_device_fields(info: DeviceInfo) -> str:
    return '"proto":%d,"pmin":%d,"fw":"%s","ui":"%s","uih":"%s","did":"%s"' % (
        PROTO, PROTO_MIN, FW_VERSION, UI_VERSION, info.ui_hash, info.did)


def build_security_doc(info: DeviceInfo) -> str:
    cfg = EscapeConfig
    return ('{%s,"time":%d,"token":"%s","writable":%s,"strictGet":%s,"allowTokenInUrl":%s,'
            '"kdf":{"alg":"pbkdf2-sha256","iter":%d},"caps":["plan","cfg"],'
            '"limits":{"body":%d,"skeleton":%d,"plan":%d,"name":%d,"room":%d,"riddle":%d}}' % (
                _common_device_fields(info), u32(info.now_ms), TokenState(info.token).value,
                "true" if info.writable else "false", "true" if cfg.STRICT_GET else "false",
                "true" if cfg.ALLOW_AUTH_TOKEN_IN_URL else "false", cfg.KDF_ITERATIONS, cfg.MAX_BODY_BYTES,
                cfg.MAX_PLAN_SKELETON_LEN, cfg.MAX_PLAN_LEN, cfg.MAX_NAME_LEN, cfg.MAX_ROOM_LEN,
                cfg.MAX_RIDDLE_ID_LEN))


def build_status_doc(host: ProtocolAdapter, info: DeviceInfo) -> str:
    out = '{%s,"ip":%s,"port":%d,"boot":%d,"seq":%d,"up":%d' % (
        _common_device_fields(info), jstr(info.ip), info.port, u32(info.boot), u32(info.seq), u32(info.now_ms))
    if info.battery > 0:  # <= 0 means no battery / unknown and is not reported
        out += ',"battery":%d' % min(info.battery, 100)
    out += ',"token":"%s","components":[' % TokenState(info.token).value
    comps = []
    for i in range(host.component_count()):
        comps.append(_write_component(i, host.snapshot(i)))
    return out + ",".join(comps) + "]}"


def build_peers_doc(peers: PeerTable, info: DeviceInfo, self_skeleton_summary_hash: int) -> str:
    out = ('{"proto":%d,"self":{"did":"%s","ip":%s,"port":%d,"proto":%d,"seq":%d,"uih":"%s","skh":"%s","age":0},"peers":['
           % (PROTO, info.did, jstr(info.ip), info.port, PROTO, u32(info.seq), info.ui_hash,
              hex8(self_skeleton_summary_hash)))
    entries = []
    for p in peers.entries():
        entries.append('{"did":"%s","ip":"%s","port":%d,"proto":%d,"seq":%d,"uih":"%s","skh":"%s","age":%d}' % (
            p.did, p.ip, p.port, p.proto, p.seq, hex8(p.uih), hex8(p.skh), u32(info.now_ms - p.last_seen_ms)))
    return out + ",".join(entries) + "]}"


def build_skeleton_index_doc(store: SkeletonStore) -> str:
    rooms = ",".join('{"room":%s,"rev":%d,"hash":"%s"}' % (jstr(s.room), s.rev, hex8(s.hash)) for s in store.infos())
    return '{"proto":%d,"rooms":[%s]}' % (PROTO, rooms)


# ---- Handlers ---------------------------------------------------------------------------------------

@dataclass
class HttpResult:
    status: int = 200
    body: str = ""


def error_body(code: str, text: str, extra_members: str = "") -> str:
    out = '{"ok":false,"code":"%s","error":%s' % (code, jstr(text))
    if extra_members:
        out += "," + extra_members
    return out + "}"


def error_result(status: int, code: str, text: str, extra_members: str = "") -> HttpResult:
    return HttpResult(status, error_body(code, text, extra_members))


_MAX_SMALL_BODY = 2048

def _ok() -> HttpResult:
    return HttpResult(200, '{"ok":true}')


def _parse_command(body: Union[bytes, str]) -> Tuple[Optional[Dict[str, Any]], Optional[HttpResult]]:
    raw = _as_bytes(body)
    if not raw:
        return None, error_result(400, "bad_request", "missing body")
    if len(raw) > _MAX_SMALL_BODY:
        return None, error_result(413, "too_large", "body too large")
    try:
        doc = parse_json(raw)
    except JsonError:
        return None, error_result(400, "bad_request", "invalid json")
    if not isinstance(doc, dict):
        return None, error_result(400, "bad_request", "invalid json")
    return doc, None


def _read_component_id(doc: Dict[str, Any], host: ProtocolAdapter) -> Optional[int]:
    """"id" selects the component; a missing id means component 0."""
    value = 0
    if "id" in doc:
        parsed = json_int(doc["id"], 0, 255)
        if parsed is None:
            return None
        value = parsed
    return value if value < host.component_count() else None


def _string_field(doc: Dict[str, Any], key: str) -> str:
    value = doc.get(key)
    return value if isinstance(value, str) else ""


def handle_action(host: ProtocolAdapter, body: Union[bytes, str]) -> HttpResult:
    doc, err = _parse_command(body)
    if err or doc is None:
        return err or error_result(400, "bad_request", "invalid json")
    cid = _read_component_id(doc, host)
    if cid is None:
        return error_result(400, "bad_id", "invalid component id")
    action = _string_field(doc, "action")
    if not action or utf8_len(action) > EscapeConfig.MAX_ACTION_LEN:
        return error_result(400, "bad_action", "invalid action")
    ok = host.apply_action(cid, action)
    if ok:
        host.push_event(cid, 'Aktion "%s" ausgefuehrt' % action)
    host.mark_dirty()
    return _ok() if ok else error_result(422, "rejected", "action rejected")


def handle_plan_action(host: ProtocolAdapter, body: Union[bytes, str]) -> HttpResult:
    doc, err = _parse_command(body)
    if err or doc is None:
        return err or error_result(400, "bad_request", "invalid json")
    cid = _read_component_id(doc, host)
    if cid is None:
        return error_result(400, "bad_id", "invalid component id")
    text = _string_field(doc, "action")
    if text == PlanAction.RESET.value:
        action = PlanAction.RESET
    elif text == PlanAction.COMPLETE.value:
        action = PlanAction.COMPLETE
    else:
        return error_result(400, "bad_action", "invalid plan action")
    if not host.snapshot(cid).plan_action_mask & plan_action_bit(action):
        return error_result(422, "unsupported", "plan action unsupported")
    ok = host.apply_plan_action(cid, action)
    if ok:
        host.push_event(cid, "Ablaufplan-Fortschritt zurueckgesetzt" if action == PlanAction.RESET
                        else "Ablaufplan-Komponente abgeschlossen")
    host.mark_dirty()
    return _ok() if ok else error_result(422, "rejected", "plan action rejected")


def handle_config(host: ProtocolAdapter, body: Union[bytes, str]) -> HttpResult:
    doc, err = _parse_command(body)
    if err or doc is None:
        return err or error_result(400, "bad_request", "invalid json")
    cid = _read_component_id(doc, host)
    if cid is None:
        return error_result(400, "bad_id", "invalid component id")

    # 1. Validate EVERYTHING before applying anything.
    identity_given = "name" in doc or "room" in doc
    name = room = riddle_id = ""
    if identity_given:
        name_v, room_v = doc.get("name"), doc.get("room")
        if not isinstance(name_v, str) or not isinstance(room_v, str):
            return error_result(400, "bad_request", "name and room must be given together")
        name, room = name_v, room_v
        if (not name or not room or utf8_len(name) > EscapeConfig.MAX_NAME_LEN
                or utf8_len(room) > EscapeConfig.MAX_ROOM_LEN):
            return error_result(400, "bad_request", "invalid name/room")
    has_riddle = "riddleId" in doc
    if has_riddle:
        riddle_v = doc["riddleId"]
        if (not isinstance(riddle_v, str) or not riddle_v
                or utf8_len(riddle_v) > EscapeConfig.MAX_RIDDLE_ID_LEN):
            return error_result(400, "bad_request", "invalid riddleId")
        riddle_id = riddle_v
    has_config = "config" in doc
    config: Dict[str, str] = {}
    if has_config:
        cfg_v = doc["config"]
        if not isinstance(cfg_v, dict):
            return error_result(400, "bad_request", "config must be an object")
        defs = host.custom_config_defs(cid)
        if not defs and cfg_v:
            return error_result(400, "bad_request", "component has no custom config")
        for key in sorted(cfg_v):
            definition = next((d for d in defs if d.key == key), None)
            text = json_text_loose(cfg_v[key])
            if definition is None or not validate_custom_config_value(definition, text):
                return error_result(400, "bad_request", "invalid config value")
            config[key] = text

    # 2. Apply.
    cfg_applied = False
    for key in sorted(config):
        if host.set_custom_config_value(cid, key, config[key]):
            cfg_applied = True
    if identity_given:
        host.set_identity(cid, name, room)
    if has_riddle:
        host.set_riddle_id(cid, riddle_id)

    parts: List[str] = []
    if cfg_applied:
        parts.append("Konfiguration geaendert")
    if identity_given:
        parts.append("Name/Raum geaendert")
    if has_riddle:
        parts.append("Raetsel-ID geaendert")
    if parts:
        host.push_event(cid, ", ".join(parts))
    host.mark_dirty()
    return _ok()


def handle_plan(host: ProtocolAdapter, body: Union[bytes, str]) -> HttpResult:
    raw = _as_bytes(body)
    if not raw:
        return error_result(400, "bad_request", "missing body")
    if len(raw) > EscapeConfig.MAX_PLAN_LEN + 128:
        return error_result(413, "too_large", "plan too large")
    found = find_fields(raw, ("id", "plan"))
    if found is None:
        return error_result(400, "bad_request", "invalid json")
    cid = 0
    if "id" in found:
        parsed = slice_to_uint(found["id"], 255)
        if parsed is None:
            return error_result(400, "bad_id", "invalid component id")
        cid = parsed
    if cid >= host.component_count():
        return error_result(400, "bad_id", "invalid component id")
    plan = found.get("plan")
    cleared = plan is None or slice_is_null(plan)
    plan_text = ""
    if not cleared:
        assert plan is not None
        if slice_kind(plan) != "o":
            return error_result(400, "bad_request", "plan must be an object")
        if len(plan) > EscapeConfig.MAX_PLAN_LEN:
            return error_result(413, "too_large", "plan too large")
        plan_text = plan.decode("utf-8")
    host.set_plan(cid, plan_text)
    host.push_event(cid, "Ablaufplan-Zuordnung entfernt" if cleared else "Ablaufplan aktualisiert")
    host.mark_dirty()
    return _ok()


def handle_plan_skeleton(host: ProtocolAdapter, store: SkeletonStore, body: Union[bytes, str]) -> HttpResult:
    raw = _as_bytes(body)
    if not raw:
        return error_result(400, "bad_request", "missing body")
    if len(raw) > EscapeConfig.MAX_PLAN_SKELETON_LEN + 512:
        return error_result(413, "too_large", "skeleton too large")
    found = find_fields(raw, ("room", "baseRev", "sk"))
    if found is None or len(found) != 3:
        return error_result(400, "bad_request", "room, baseRev and sk are required")
    room = slice_to_string(found["room"])
    base_rev = slice_to_uint(found["baseRev"], _U32)
    if room is None or not room or utf8_len(room) > EscapeConfig.MAX_ROOM_LEN or base_rev is None:
        return error_result(400, "bad_request", "invalid room or baseRev")
    sk = found["sk"]
    if len(sk) > EscapeConfig.MAX_PLAN_SKELETON_LEN:
        return error_result(413, "too_large", "skeleton too large")
    if room not in hosted_rooms(host):
        return error_result(422, "room_not_hosted", "no local component in this room")

    result, rev, digest = store.put(room, base_rev, sk)
    rev_members = '"rev":%d,"hash":"%s"' % (rev, hex8(digest))
    if result == SkeletonResult.STORED:
        for i in range(host.component_count()):
            if host.identity(i)[1] == room:
                host.push_event(i, "Raum-Ablaufplan aktualisiert")
        host.mark_dirty()
        return HttpResult(200, '{"ok":true,%s}' % rev_members)
    if result == SkeletonResult.UNCHANGED:
        return HttpResult(200, '{"ok":true,%s}' % rev_members)
    if result == SkeletonResult.CONFLICT:
        return error_result(409, "rev_conflict", "skeleton was changed by someone else", rev_members)
    if result == SkeletonResult.TOO_LARGE:
        return error_result(413, "too_large", "skeleton too large")
    if result == SkeletonResult.INVALID:
        return error_result(400, "bad_request", "sk must be a JSON object")
    if result == SkeletonResult.ROOM_LIMIT:
        return error_result(422, "room_limit", "too many rooms stored")
    if result == SkeletonResult.KEY_COLLISION:
        return error_result(422, "room_limit", "room key collision")
    return error_result(500, "storage_full", "could not store skeleton")


# ---- Timing helpers (overflow-safe millis() arithmetic) ---------------------------------------

def is_heartbeat_due(now_ms: int, last_broadcast_ms: int, interval_ms: int) -> bool:
    return u32(now_ms - last_broadcast_ms) >= interval_ms


def is_change_broadcast_due(now_ms: int, last_broadcast_ms: int, dirty: bool) -> bool:
    return dirty and u32(now_ms - last_broadcast_ms) >= EscapeConfig.CHANGE_MIN_GAP_MS


# ---- HTTP building blocks (src/protocol/Http.cpp) and a bounded threaded server ----------

class Method(Enum):
    GET = "GET"
    HEAD = "HEAD"
    POST = "POST"
    OPTIONS = "OPTIONS"


@dataclass
class HttpRequest:
    method: Method = Method.GET
    path: str = ""
    query: str = ""             # raw text after '?' (bytes as latin-1 characters)
    origin: str = ""
    if_none_match: str = ""
    content_length: int = 0
    expect_continue: bool = False
    body: bytes = b""


@dataclass
class HttpResponse:
    status: int = 200
    content_type: str = ""
    body: bytes = b""
    gzip: bool = False
    etag: str = ""              # without quotes; sent as ETag: "<etag>"
    no_store: bool = True       # Cache-Control: no-store

    @property
    def body_length(self) -> int:
        return len(self.body)


class RouteInfo:
    __slots__ = ("found", "max_body")

    def __init__(self, found: bool, max_body: int = 0) -> None:
        self.found = found
        self.max_body = max_body


class HttpHandler(abc.ABC):
    @abc.abstractmethod
    def route(self, method: Method, path: str) -> RouteInfo:
        """Whether (method, path) exists and how large a body it accepts (checked from Content-Length)."""

    @abc.abstractmethod
    def handle(self, request: HttpRequest, remote_ip: str) -> HttpResponse: ...


def _valid_target(target: str) -> bool:
    if not target or target[0] != "/" or len(target) > 512:
        return False
    return all(0x20 < ord(c) != 0x7F for c in target)


def parse_request_head(head: bytes) -> Union[HttpRequest, int]:
    """Parses the request line and headers (``head`` ends with the blank line).

    Returns an ``HttpRequest`` or the HTTP status describing the failure
    (400/405/413/414/431/501/505), exactly like the C++ parser.
    """
    text = head.decode("latin-1")
    line_end = text.find("\r\n")
    if line_end < 0:
        return 400
    line = text[:line_end]
    sp1 = line.find(" ")
    sp2 = line.find(" ", sp1 + 1) if sp1 >= 0 else -1
    if sp1 < 0 or sp2 < 0:
        return 400
    method_text, target, version = line[:sp1], line[sp1 + 1:sp2], line[sp2 + 1:]
    req = HttpRequest()
    if method_text in ("GET", "HEAD", "POST", "OPTIONS"):
        req.method = Method(method_text)
    else:
        return 405
    if " " in version:
        return 400  # extra token in the request line
    if version not in ("HTTP/1.1", "HTTP/1.0"):
        return 505
    if len(target) > 512:
        return 414
    if not _valid_target(target):
        return 400
    q = target.find("?")
    req.path = target if q < 0 else target[:q]
    if q >= 0:
        req.query = target[q + 1:]

    have_length = False
    pos = line_end + 2
    while pos < len(text):
        e = text.find("\r\n", pos)
        if e < 0:
            return 400
        if e == pos:
            break  # blank line: end of headers
        header = text[pos:e]
        pos = e + 2
        if header[0] in " \t":
            return 400  # obsolete line folding
        colon = header.find(":")
        if colon <= 0:
            return 400
        name = header[:colon].lower()
        value = header[colon + 1:].strip(" \t")
        if name == "content-length":
            if not value or len(value) > 10 or not all("0" <= c <= "9" for c in value):
                return 400
            number = int(value)
            if have_length and number != req.content_length:
                return 400
            if number > 0x7FFFFFFF:
                return 413
            req.content_length = number
            have_length = True
        elif name == "transfer-encoding":
            return 501
        elif name == "origin":
            if len(value) <= 128:
                req.origin = value
        elif name == "if-none-match":
            if len(value) <= 128:
                req.if_none_match = value
        elif name == "expect":
            req.expect_continue = value.lower() == "100-continue"
    return req


_HEX_DIGITS = b"0123456789abcdefABCDEF"


def percent_decode(text: str) -> Optional[bytes]:
    """%XX decoding to bytes ('+' stays '+'); None for a '%' without two hex digits."""
    try:
        raw = text.encode("latin-1")
    except UnicodeEncodeError:
        raw = text.encode("utf-8")
    out = bytearray()
    i = 0
    n = len(raw)
    while i < n:
        if raw[i] == 0x25:
            if i + 2 >= n or raw[i + 1] not in _HEX_DIGITS or raw[i + 2] not in _HEX_DIGITS:
                return None
            out.append(int(raw[i + 1:i + 3], 16))
            i += 3
        else:
            out.append(raw[i])
            i += 1
    return bytes(out)


def query_param(query: str, name: str) -> Optional[bytes]:
    """Value of ``name`` in a raw query string (percent-decoded); None if absent or undecodable."""
    for pair in query.split("&"):
        eq = pair.find("=")
        key = pair if eq < 0 else pair[:eq]
        decoded_key = percent_decode(key)
        if decoded_key is not None and decoded_key == name.encode("utf-8"):
            if eq < 0:
                return b""
            return percent_decode(pair[eq + 1:])
    return None


def origin_allowed(origin: str) -> bool:
    """CORS policy of PROTOCOL.md section 4: "null", localhost/loopback, *.local and private IPv4 ranges."""
    if origin == "null":
        return True
    if origin.startswith("http://"):
        rest = origin[7:]
    elif origin.startswith("https://"):
        rest = origin[8:]
    else:
        return False
    host = rest
    if host.startswith("["):  # IPv6 literal: only loopback
        return host.startswith("[::1]") and (len(host) == 5 or host[5] == ":")
    colon = host.find(":")
    if colon >= 0:
        port = host[colon + 1:]
        if not all("0" <= c <= "9" for c in port):
            return False
        host = host[:colon]
    if not host or len(host) > 100:
        return False
    if not all(("a" <= c <= "z") or ("A" <= c <= "Z") or ("0" <= c <= "9") or c in ".-" for c in host):
        return False
    lower = host.lower()
    if lower == "localhost":
        return True
    if len(lower) > 6 and lower.endswith(".local"):
        return True
    m = re.fullmatch(r"([0-9]+)\.([0-9]+)\.([0-9]+)\.([0-9]+)", lower)  # IPv4 literal in a private/loopback range
    if not m:
        return False
    a, b, c, d = (int(g) for g in m.groups())
    if a > 255 or b > 255 or c > 255 or d > 255:
        return False
    return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or (a == 169 and b == 254)


_STATUS_TEXT = {
    200: "OK", 204: "No Content", 304: "Not Modified", 400: "Bad Request", 401: "Unauthorized", 404: "Not Found",
    405: "Method Not Allowed", 409: "Conflict", 413: "Payload Too Large", 414: "URI Too Long",
    422: "Unprocessable Entity", 429: "Too Many Requests", 431: "Request Header Fields Too Large",
    500: "Internal Server Error", 501: "Not Implemented", 503: "Service Unavailable",
    505: "HTTP Version Not Supported",
}


def status_text(status: int) -> str:
    return _STATUS_TEXT.get(status, "Status")


def format_response_head(r: HttpResponse, origin: str, preflight: bool) -> bytes:
    """Status line and headers (ending with the blank line); always ``Connection: close``."""
    h = "HTTP/1.1 %d %s\r\n" % (r.status, status_text(r.status))
    if r.content_type:
        h += "Content-Type: %s\r\n" % r.content_type
    h += "Content-Length: %d\r\nConnection: close\r\n" % r.body_length
    if r.gzip:
        h += "Content-Encoding: gzip\r\n"
    if r.etag:
        h += 'ETag: "%s"\r\nCache-Control: no-cache\r\n' % r.etag
    elif r.no_store:
        h += "Cache-Control: no-store\r\n"
    if origin and origin_allowed(origin):
        h += "Access-Control-Allow-Origin: %s\r\nVary: Origin\r\n" % origin
        if preflight:
            h += ("Access-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type\r\n"
                  "Access-Control-Max-Age: 600\r\n")
    return (h + "\r\n").encode("latin-1", "replace")


def _error_code_for(status: int) -> str:
    return {404: "not_found", 413: "too_large"}.get(status, "bad_request")


class _Abort(Exception):
    """Ends a connection silently (timeout, peer closed, socket error)."""


class _Connection:
    def __init__(self, server: "HttpServer", sock: socket.socket, remote_ip: str) -> None:
        self.server = server
        self.sock = sock
        self.remote_ip = remote_ip
        now = time.monotonic()
        self.deadline = now + server.request_timeout   # whole request incl. the response
        self.last_rx = now                             # idle timeout: no bytes received
        self.responded = False

    # ---- bounded socket operations ---------------------------------------------------------
    def recv(self, n: int) -> bytes:
        now = time.monotonic()
        wait = min(self.deadline - now, self.last_rx + self.server.idle_timeout - now)
        if wait <= 0:
            raise _Abort()
        try:
            self.sock.settimeout(wait)
            data = self.sock.recv(n)
        except OSError:  # includes timeouts and resets
            raise _Abort() from None
        if not data:
            raise _Abort()  # peer closed before sending a full request
        self.last_rx = time.monotonic()
        return data

    def send(self, data: bytes) -> None:
        wait = self.deadline - time.monotonic()
        if wait <= 0:
            raise _Abort()
        try:
            self.sock.settimeout(wait)
            self.sock.sendall(data)
        except OSError:
            raise _Abort() from None

    def respond(self, req: Optional[HttpRequest], r: HttpResponse, preflight: bool = False) -> None:
        origin = req.origin if req else ""
        head = format_response_head(r, origin, preflight)
        head_only = req is not None and req.method == Method.HEAD
        self.responded = True
        self.send(head if head_only else head + r.body)

    def drain(self) -> None:
        """The request was rejected before its body arrived. Closing now would reset the connection
        while the client is still sending, and the reset can destroy the response in flight:
        half-close, then swallow the rest briefly."""
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            return
        start = time.monotonic()
        drained = 0
        while drained < EscapeConfig.MAX_BODY_BYTES * 4:
            now = time.monotonic()
            wait = min(1.5 - (now - start), self.deadline - now)
            if wait <= 0:
                break
            try:
                self.sock.settimeout(wait)
                data = self.sock.recv(4096)
            except OSError:
                break
            if not data:
                break
            drained += len(data)

    def reject(self, req: Optional[HttpRequest], status: int) -> None:
        body = '{"ok":false,"code":"%s","error":%s}' % (_error_code_for(status), jstr(status_text(status)))
        self.respond(req, HttpResponse(status, "application/json", body.encode("utf-8")))
        self.drain()

    # ---- the request -------------------------------------------------------------------------
    def run(self) -> None:
        try:
            self._run()
        except _Abort:
            raise
        except Exception:  # whatever goes wrong while serving: a JSON 500, never a silently dropped connection
            log.exception("request failed")
            if not self.responded:
                self.respond(None, HttpResponse(500, "application/json",
                                                error_body("internal_error", "internal error").encode("utf-8")))

    def _run(self) -> None:
        limit = EscapeConfig.MAX_HEADER_BYTES
        buf = b""
        while True:
            end = buf.find(b"\r\n\r\n", 0, limit)  # the terminator must lie within the first `limit` bytes
            if end >= 0:
                break
            if len(buf) > limit:
                return self.reject(None, 431)
            buf += self.recv(4096)
        parsed = parse_request_head(buf[:end + 4])
        prefix = buf[end + 4:]
        if isinstance(parsed, int):
            return self.reject(None, parsed)
        req = parsed

        if req.method == Method.OPTIONS:  # CORS preflight: any path
            self.respond(req, HttpResponse(204), preflight=True)
            if req.content_length:
                self.drain()
            return
        handler = self.server.handler
        route = handler.route(Method.GET if req.method == Method.HEAD else req.method, req.path)
        if not route.found:
            return self.reject(req, 404)
        body = b""
        if req.content_length:
            if req.method != Method.POST:
                return self.reject(req, 400)
            if req.content_length > route.max_body:
                return self.reject(req, 413)  # decided from Content-Length alone: no body byte is read
            if req.expect_continue:
                self.send(b"HTTP/1.1 100 Continue\r\n\r\n")
            body = prefix[:req.content_length]
            while len(body) < req.content_length:
                body += self.recv(min(4096, req.content_length - len(body)))
        req.body = body
        try:
            response = handler.handle(req, self.remote_ip)
        except Exception:  # every handler failure becomes a JSON 500, never a dropped connection
            log.exception("handler failed for %s %s", req.method.value, req.path)
            response = HttpResponse(500, "application/json",
                                    error_body("internal_error", "internal error").encode("utf-8"))
        self.respond(req, response)


class HttpServer:
    """Threaded HTTP/1.1 server with hard resource bounds.

    * header block <= 1024 bytes (431), per-route body limit decided from Content-Length
      before any body byte is read (413), no chunked bodies (501);
    * idle timeout (no bytes received) and total request timeout (including the response);
    * at most ``max_connections`` concurrent connections - the next client is told 503;
    * ``Connection: close`` on every response, HEAD and OPTIONS handled.
    """

    BUSY = (b"HTTP/1.1 503 Service Unavailable\r\nRetry-After: 1\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")

    def __init__(self, handler: HttpHandler, port: int, host: str = "",
                 max_connections: int = EscapeConfig.MAX_HTTP_CONNECTIONS,
                 idle_timeout: float = EscapeConfig.HTTP_IDLE_TIMEOUT_MS / 1000.0,
                 request_timeout: float = EscapeConfig.HTTP_REQUEST_TIMEOUT_MS / 1000.0) -> None:
        self.handler = handler
        self.host = host
        self._requested_port = port
        self.max_connections = max_connections
        self.idle_timeout = idle_timeout
        self.request_timeout = request_timeout
        self._listener: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._active = 0
        self._sockets: Set[socket.socket] = set()

    @property
    def port(self) -> int:
        return self._listener.getsockname()[1] if self._listener else self._requested_port

    @property
    def active_connections(self) -> int:
        with self._lock:
            return self._active

    def start(self) -> None:
        """Binds and starts accepting. Raises ``OSError`` if the port cannot be opened."""
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.host, self._requested_port))
            listener.listen(16)
            listener.settimeout(0.2)
        except OSError:
            listener.close()
            raise
        self._listener = listener
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="escape-http", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass
        with self._lock:
            sockets = list(self._sockets)
        for sock in sockets:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        thread, self._thread = self._thread, None
        if thread is not None and thread is not threading.current_thread():
            thread.join(timeout=2.0)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            listener = self._listener
            if listener is None:
                return
            try:
                conn, addr = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                time.sleep(0.05)  # e.g. out of file descriptors: back off, never die
                continue
            try:
                self._admit(conn, addr[0])
            except Exception:  # pragma: no cover - defensive
                log.exception("could not admit connection")
                try:
                    conn.close()
                except OSError:
                    pass

    def _admit(self, conn: socket.socket, remote_ip: str) -> None:
        with self._lock:
            full = self._active >= self.max_connections
            if not full:
                self._active += 1
                self._sockets.add(conn)
        if full:  # all slots are taken: tell the client to come back later
            try:
                conn.settimeout(0.5)
                conn.sendall(self.BUSY)
            except OSError:
                pass
            finally:
                conn.close()
            return
        try:
            threading.Thread(target=self._serve, args=(conn, remote_ip), name="escape-http-conn", daemon=True).start()
        except RuntimeError:  # cannot start another thread
            self._release(conn)

    def _release(self, conn: socket.socket) -> None:
        try:
            conn.close()
        except OSError:
            pass
        with self._lock:
            self._sockets.discard(conn)
            self._active -= 1

    def _serve(self, conn: socket.socket, remote_ip: str) -> None:
        try:
            _Connection(self, conn, remote_ip).run()
        except _Abort:
            pass
        except Exception:  # pragma: no cover - run() already converts everything into a response
            log.exception("connection failed")
        finally:
            self._release(conn)


def http_get(ip: str, port: int, target: str, timeout: float, max_body: int) -> Optional[Tuple[int, bytes]]:
    """Minimal bounded HTTP/1.1 GET (device-to-device skeleton sync): (status, body) or None.

    ``timeout`` is the deadline for everything; the header block is limited to 1024 bytes, the
    body to ``max_body`` and must be announced by Content-Length.
    """
    deadline = time.monotonic() + timeout
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def remaining() -> float:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError()
        return left

    try:
        sock.settimeout(remaining())
        sock.connect((ip, port))
        sock.settimeout(remaining())
        sock.sendall(("GET %s HTTP/1.1\r\nHost: %s\r\nAccept: application/json\r\nConnection: close\r\n\r\n"
                      % (target, ip)).encode("ascii"))
        data = b""
        while True:
            end = data.find(b"\r\n\r\n")
            if end >= 0:
                break
            if len(data) > EscapeConfig.MAX_HEADER_BYTES:
                return None
            sock.settimeout(remaining())
            chunk = sock.recv(1024)
            if not chunk:
                return None
            data += chunk
        head, body = data[:end + 2], data[end + 4:]
        m = re.match(rb"HTTP/1\.[01] ([0-9]{3})", head)
        length_match = re.search(rb"\r\ncontent-length:[ \t]*([0-9]{1,9})[ \t]*\r\n", head, re.IGNORECASE)
        if not m or not length_match:
            return None
        length = int(length_match.group(1))
        if length > max_body or len(body) > length:
            return None
        while len(body) < length:
            sock.settimeout(remaining())
            chunk = sock.recv(min(4096, length - len(body)))
            if not chunk:
                return None
            body += chunk
        return int(m.group(1)), body
    except (OSError, ValueError):  # includes TimeoutError and socket.timeout
        return None
    finally:
        try:
            sock.close()
        except OSError:
            pass


# ---- mDNS: one shared A record (PROTOCOL.md section 7, src/protocol/Mdns.cpp) ----------------

MDNS_GROUP = "224.0.0.251"


@dataclass
class MdnsQuery:
    matches: bool = False      # a question for our name (A or ANY, class IN)
    unicast: bool = False      # the question has the QU bit: answer the sender directly
    suppressed: bool = False   # known-answer suppression: the asker already has our address


def _lower_ascii(c: int) -> int:
    return c + 32 if 65 <= c <= 90 else c


def _read_name(p: bytes, offset: int, target: bytes) -> Optional[Tuple[bool, int]]:
    """Walks a (possibly compressed) name, comparing it case-insensitively with ``target``
    ("a.b.local"). Returns (equal, offset after the name in the original position), or None for
    malformed data. Compression pointers are followed at most 6 times."""
    n = len(p)
    pos = offset
    target_pos = 0
    target_len = len(target)
    jumped = False
    hops = 0
    total = 0
    equal = True
    after = offset
    while True:
        if pos >= n:
            return None
        length = p[pos]
        if length == 0:
            if not jumped:
                after = pos + 1
            if target_pos != target_len:
                equal = False
            return equal, after
        if (length & 0xC0) == 0xC0:
            hops += 1
            if pos + 1 >= n or hops > 6:
                return None
            pointer = ((length & 0x3F) << 8) | p[pos + 1]
            if pointer >= n:
                return None
            if not jumped:
                after = pos + 2
            jumped = True
            pos = pointer
            continue
        if (length & 0xC0) != 0 or length > 63 or pos + 1 + length > n:
            return None
        total += length + 1
        if total > 255:
            return None
        if target_pos != 0:  # label separator in the target
            if target_pos < target_len and target[target_pos] == 0x2E:
                target_pos += 1
            else:
                equal = False
        for k in range(length):
            if target_pos >= target_len or _lower_ascii(target[target_pos]) != _lower_ascii(p[pos + 1 + k]):
                equal = False
            else:
                target_pos += 1
        pos += 1 + length


def parse_mdns_query(packet: bytes, hostname: str, ip: bytes, ttl_seconds: int) -> MdnsQuery:
    """Parses a received datagram. Responses (QR bit) and anything malformed or oversized give no match."""
    p = bytes(packet)
    n = len(p)
    if n < 12 or n > 1500:
        return MdnsQuery()
    flags = struct.unpack_from("!H", p, 2)[0]
    if flags & 0x8000:
        return MdnsQuery()          # a response
    if (flags >> 11) & 0x0F:
        return MdnsQuery()          # opcode != QUERY
    qd, an = struct.unpack_from("!HH", p, 4)
    if qd == 0 or qd > 16 or an > 32:
        return MdnsQuery()
    target = hostname.encode("ascii", "replace")
    offset = 12
    match = unicast = False
    for _ in range(qd):
        name = _read_name(p, offset, target)
        if name is None or name[1] + 4 > n:
            return MdnsQuery()
        equal, after = name
        qtype, qclass = struct.unpack_from("!HH", p, after)
        offset = after + 4
        if equal and qtype in (1, 255) and (qclass & 0x7FFF) == 1:
            match = True
            unicast = unicast or bool(qclass & 0x8000)
    if not match:
        return MdnsQuery()
    suppressed = False
    for _ in range(an):  # known answers
        name = _read_name(p, offset, target)
        if name is None or name[1] + 10 > n:
            break
        equal, after = name
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", p, after)
        offset = after + 10
        if offset + rdlen > n:
            break
        if (equal and rtype == 1 and (rclass & 0x7FFF) == 1 and rdlen == 4 and p[offset:offset + 4] == ip
                and ttl >= ttl_seconds // 2):
            suppressed = True
        offset += rdlen
    return MdnsQuery(True, unicast, suppressed)


def build_mdns_answer(hostname: str, ip: bytes, ttl_seconds: int) -> bytes:
    """The answer packet: QR+AA, one A record, cache-flush bit NOT set (shared record). b"" if the name is unusable."""
    try:
        name = hostname.encode("ascii")
    except UnicodeEncodeError:
        return b""
    if not name or len(name) > 253:
        return b""
    out = bytearray(b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00")
    for label in name.split(b"."):
        if not label or len(label) > 63:
            return b""
        out.append(len(label))
        out += label
    out.append(0)
    out += struct.pack("!HHIH", 1, 1, ttl_seconds, 4) + bytes(ip)
    return bytes(out)


def mdns_response_delay_ms(random_value: int) -> int:
    """Random delay in [20, 120] ms for multicast answers (RFC 6762 section 6.3)."""
    return 20 + (random_value & _U32) % 101


# ---- The device -------------------------------------------------------------------------------

def _detect_local_ip() -> str:
    """The address of the interface that would be used to reach the LAN (nothing is sent)."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        probe.connect(("192.0.2.1", 80))  # TEST-NET: connect() on UDP only selects a route
        return probe.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        probe.close()


def _default_state_dir(http_port: int) -> str:
    home = os.path.expanduser("~")
    base = os.path.join(home, ".escape-manager") if not home.startswith("~") else \
        os.path.join(tempfile.gettempdir(), "escape-manager")
    return os.path.join(base, "python-%d" % http_port)


@dataclass
class _Component:
    uuid: str
    riddle_id: str
    name: str
    room: str
    plan: str = ""
    event_seq: int = 0
    event_msg: str = ""
    errors: Optional[Callable[[], List[str]]] = None
    actions: Optional[Callable[[], List[str]]] = None
    feed: Optional[Callable[[], str]] = None
    tip: Optional[Callable[[], str]] = None
    puzzle: Optional[Callable[[], Tuple[int, int, str, bool]]] = None
    action: Optional[Callable[[str], bool]] = None
    plan_action: Optional[Callable[[PlanAction], bool]] = None
    plan_action_mask: int = ALL_PLAN_ACTIONS
    custom_config: Optional[Callable[[], List[CustomConfigDef]]] = None
    set_custom_config: Optional[Callable[[str, str], bool]] = None


@dataclass
class _SyncRequest:
    ip: str
    port: int
    room_key: int
    room: str
    did: str


class _Host(ProtocolAdapter):
    """Connects the protocol handlers to the registered components (like ``EscapeComponent::Host``)."""

    def __init__(self, owner: "EscapeComponent") -> None:
        self._o = owner

    @staticmethod
    def _call(fn: Callable[[], Any], default: Any, what: str) -> Any:
        try:
            return fn()
        except Exception:  # a host callback must never take the HTTP server down
            log.exception("callback %s failed", what)
            return default

    def battery(self) -> int:
        cb = self._o._battery
        if cb is None:
            return -1
        value = self._call(cb, -1, "battery")
        try:
            return int(value)
        except (TypeError, ValueError):
            return -1

    def mark_dirty(self) -> None:
        self._o.mark_dirty()

    def component_count(self) -> int:
        return len(self._o._components)

    def identity(self, index: int) -> Tuple[str, str]:
        if not 0 <= index < len(self._o._components):
            return "", ""
        c = self._o._components[index]
        return c.name, c.room

    def snapshot(self, index: int) -> ComponentSnapshot:
        out = ComponentSnapshot()
        if not 0 <= index < len(self._o._components):
            return out
        c = self._o._components[index]
        cfg = EscapeConfig
        out.uuid, out.riddle_id, out.name, out.room, out.plan = c.uuid, c.riddle_id, c.name, c.room, c.plan
        out.event_seq, out.event_msg = c.event_seq, c.event_msg
        if c.errors:
            out.errors = [bounded(e, cfg.MAX_ERROR_LEN) for e in list(self._call(c.errors, [], "errors") or [])[:cfg.MAX_ERRORS]]
        if c.actions:
            out.actions = [bounded(a, cfg.MAX_ACTION_LEN) for a in list(self._call(c.actions, [], "actions") or [])[:cfg.MAX_ACTIONS]]
        out.plan_action_mask = c.plan_action_mask if c.plan_action else 0
        if c.feed:
            out.feed = bounded(self._call(c.feed, "", "feed") or "", cfg.MAX_FEED_LEN)
        if c.tip:
            out.tip = bounded(self._call(c.tip, "", "tip") or "", cfg.MAX_TIP_LEN)
        if c.puzzle:
            result = self._call(c.puzzle, None, "puzzle")
            try:
                step, total, state, is_html = result
                out.puzzle_step, out.puzzle_total_steps = int(step), int(total)
                out.puzzle_state, out.puzzle_is_html = bounded(state, cfg.MAX_STATE_LEN), bool(is_html)
            except (TypeError, ValueError):
                out.puzzle_total_steps = 0
        out.custom_config = self.custom_config_defs(index)
        return out

    def custom_config_defs(self, index: int) -> List[CustomConfigDef]:
        if not 0 <= index < len(self._o._components) or not self._o._components[index].custom_config:
            return []
        defs = self._call(self._o._components[index].custom_config, [], "custom_config") or []
        return [normalize_config_def(d) for d in list(defs)[:EscapeConfig.MAX_CUSTOM_CONFIGS]
                if isinstance(d, CustomConfigDef)]

    def apply_action(self, index: int, action: str) -> bool:
        if not 0 <= index < len(self._o._components) or not self._o._components[index].action:
            return False
        return bool(self._call(lambda: self._o._components[index].action(action), False, "action"))  # type: ignore[misc]

    def apply_plan_action(self, index: int, action: PlanAction) -> bool:
        if not 0 <= index < len(self._o._components) or not self._o._components[index].plan_action:
            return False
        return bool(self._call(lambda: self._o._components[index].plan_action(action), False, "plan_action"))  # type: ignore[misc]

    def set_identity(self, index: int, name: str, room: str) -> None:
        if 0 <= index < len(self._o._components):
            c = self._o._components[index]
            c.name, c.room = bounded(name, EscapeConfig.MAX_NAME_LEN), bounded(room, EscapeConfig.MAX_ROOM_LEN)
            self._o._save_string("name%d" % index, c.name)
            self._o._save_string("room%d" % index, c.room)

    def set_riddle_id(self, index: int, riddle_id: str) -> None:
        if 0 <= index < len(self._o._components):
            c = self._o._components[index]
            c.riddle_id = bounded(riddle_id, EscapeConfig.MAX_RIDDLE_ID_LEN)
            self._o._save_string("riddle%d" % index, c.riddle_id)

    def set_custom_config_value(self, index: int, key: str, value: str) -> bool:
        if not 0 <= index < len(self._o._components) or not self._o._components[index].set_custom_config:
            return False
        return bool(self._call(lambda: self._o._components[index].set_custom_config(key, value), False,  # type: ignore[misc]
                               "set_custom_config"))

    def set_plan(self, index: int, plan_json: str) -> None:
        if 0 <= index < len(self._o._components):
            c = self._o._components[index]
            c.plan = bounded(plan_json, EscapeConfig.MAX_PLAN_LEN)
            self._o._save_string("plan%d" % index, c.plan)

    def push_event(self, index: int, message: str) -> None:
        self._o.push_event(index, message)


class _Http(HttpHandler):
    """The HTTP face of a device: routes and request handling (``Escape::Device::route/handle``)."""

    _GET = ("/", "/security.json", "/status.json", "/peers.json", "/plan-skeleton.json", "/favicon.ico")
    _POST = ("/action", "/plan-action", "/config", "/plan", "/plan-skeleton")

    def __init__(self, owner: "EscapeComponent") -> None:
        self._o = owner

    def route(self, method: Method, path: str) -> RouteInfo:
        if method == Method.GET and path in self._GET:
            return RouteInfo(True, 0)
        if method == Method.POST and path in self._POST:
            return RouteInfo(True, EscapeConfig.MAX_BODY_BYTES)
        return RouteInfo(False, 0)

    def handle(self, request: HttpRequest, remote_ip: str) -> HttpResponse:
        with self._o._lock:  # ALL shared state (replay cache, store, peers, seq, components) is serialised here
            if request.method == Method.POST:
                return self._o._handle_post(request, remote_ip)
            return self._o._handle_get(request)


def _plain_error(status: int, code: str, text: str, extra: str = "") -> HttpResponse:
    return HttpResponse(status, "application/json", error_body(code, text, extra).encode("utf-8"))


class EscapeComponent:
    """A complete Python device: HTTP server, discovery, shared mDNS record, skeleton sync.

    Register components (``add_component``) and callbacks, call ``begin()`` once and ``loop()``
    regularly (or ``begin(background=True)``). The class is safe to use from several threads.
    """

    def __init__(self, host_name: str = "python-component", auth_token: Optional[str] = None,
                 http_port: int = HTTP_PORT, udp_port: int = UDP_PORT, local_ip: Optional[str] = None,
                 manager_html: Union[str, bytes, None] = "", mdns_hostname: str = EscapeConfig.MDNS_HOSTNAME,
                 mdns_enabled: bool = True, *, did: Optional[str] = None, state_dir: Optional[str] = None,
                 storage: Optional[BlobStorage] = None, broadcast_ip: Optional[str] = None, mdns_port: int = 5353,
                 ui_hash: Optional[str] = None, token_state: Optional[TokenState] = None,
                 clock: Optional[Callable[[], int]] = None, http_idle_timeout: Optional[float] = None,
                 http_request_timeout: Optional[float] = None, http_bind_host: str = "") -> None:
        """``auth_token``: None (or the public default) = "default" token state, anything else =
        "custom". An unusable token (length outside 8..128 bytes) or ``token_state=INVALID`` makes
        the device read-only (``writable:false``); it never falls back to the default token.
        ``udp_port=0`` disables discovery, ``mdns_port=0`` / ``mdns_enabled=False`` the mDNS record.
        ``state_dir`` (default ~/.escape-manager/python-<http_port>) persists boot counter, identity,
        riddle ids, plan slices and skeletons; ``storage`` overrides it (e.g. ``MemoryStorage()``)."""
        self.host_name = host_name
        self.http_port = http_port
        self.udp_port = udp_port
        self._lock = threading.RLock()
        self._clock = clock
        self._t0 = time.monotonic()
        self._begun = False
        self._http_bind_host = http_bind_host
        self._http_idle_timeout = http_idle_timeout
        self._http_request_timeout = http_request_timeout

        # persistent storage
        if storage is None:
            directory = state_dir or _default_state_dir(http_port)
            try:
                storage = FileStorage(directory)
            except OSError as error:
                log.warning("state directory %s unusable (%s): running without persistence", directory, error)
                storage = MemoryStorage()
        self._storage: BlobStorage = storage
        self._store = SkeletonStore(storage)

        # identity of the board
        if did is not None and not valid_did(did):
            raise ValueError("did must be 12 lowercase hex characters")
        if did is None:
            stored = storage.read("did")
            did = stored.decode("ascii", "replace") if stored else None
            if did is None or not valid_did(did):
                raw = bytearray(secrets.token_bytes(6))
                raw[0] = (raw[0] | 0x02) & 0xFE  # locally administered, unicast: never collides with a real MAC
                did = raw.hex()
                storage.write("did", did.encode("ascii"))
        self._did = did

        # token
        if token_state is None:
            token_state = TokenState.DEFAULT if auth_token is None or auth_token == AUTH_TOKEN_DEFAULT else TokenState.CUSTOM
        self._token_state = token_state
        self._token = AUTH_TOKEN_DEFAULT if auth_token is None and token_state == TokenState.DEFAULT else (auth_token or "")
        if token_state == TokenState.CUSTOM and len(_as_bytes(self._token)) < EscapeConfig.RECOMMENDED_AUTH_TOKEN_LEN:
            log.warning("token shorter than %d characters: accepted, but weak", EscapeConfig.RECOMMENDED_AUTH_TOKEN_LEN)

        # manager UI (raw or gzip bytes); the hash is always over the UNCOMPRESSED document
        self._ui_gz = b""
        plain = b""
        if manager_html:
            raw_ui = _as_bytes(manager_html)
            if raw_ui[:2] == b"\x1f\x8b":
                try:
                    plain = gzip.decompress(raw_ui)
                    self._ui_gz = raw_ui
                except (OSError, EOFError, ValueError):
                    log.warning("manager_html is not valid gzip data: no UI served")
            else:
                plain = raw_ui
                self._ui_gz = gzip.compress(raw_ui, 9, mtime=0)
        self._ui_hash = ui_hash or (hashlib.sha256(plain).hexdigest()[:8] if plain else "00000000")

        # network configuration
        self._ip = local_ip or _detect_local_ip()
        ip_int = parse_ipv4(self._ip)
        if ip_int is None:
            raise ValueError("local_ip must be a dotted IPv4 address")
        self._ip_int = ip_int
        self._broadcast = broadcast_ip or ("127.255.255.255" if (ip_int >> 24) == 127 else "255.255.255.255")
        self._mdns_enabled = mdns_enabled and bool(mdns_port)
        self._mdns_port = mdns_port
        self._mdns_name = mdns_hostname if "." in mdns_hostname else mdns_hostname + ".local"

        # state
        self._components: List[_Component] = []
        self._battery: Optional[Callable[[], int]] = None
        self._peers = PeerTable()
        self._limiter = RateLimiter()
        self._udp_limiter = RateLimiter()  # discovery datagrams use their own budget
        self._transport = SecureTransport()
        self._host = _Host(self)
        self._http_handler = _Http(self)
        self._server: Optional[HttpServer] = None
        self._udp: Optional[socket.socket] = None
        self._mdns: Optional[socket.socket] = None
        self._boot = 0
        self._seq = 1
        self._ctr = 0
        self._dirty = True
        self._last_announce = 0
        self._jitter = secrets.randbelow(EscapeConfig.HEARTBEAT_JITTER_MS + 1)
        self._announcements_sent = 0
        self._mdns_pending = False
        self._mdns_at = 0
        self._sync_pending: Optional[_SyncRequest] = None
        self._sync_busy = False
        self._sync_thread: Optional[threading.Thread] = None
        self._sync_failures: Dict[Tuple[str, int], int] = {}
        self._stop_background = threading.Event()
        self._background: Optional[threading.Thread] = None
        self._warned: Dict[str, float] = {}

    # ---- persistence -------------------------------------------------------------------------------

    def _load_string(self, key: str, default: str) -> str:
        raw = self._storage.read(key)
        if raw is None:
            return default
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            return default

    def _save_string(self, key: str, value: str) -> None:
        if not self._storage.write(key, value.encode("utf-8")):
            log.warning("could not persist %s", key)

    def _next_boot_counter(self) -> int:
        raw = self._storage.read("boot")
        previous = 0
        if raw is not None and raw.strip().isdigit() and int(raw) <= _U32:
            previous = int(raw)
        value = u32(previous + 1)
        if not self._storage.write("boot", str(value).encode("ascii")):
            value = secrets.randbits(32)  # storage failed: random, like the firmware
        return value

    # ---- registration -------------------------------------------------------------------------------

    def add_component(self, name: str, room: str, riddle_id: Optional[str] = None) -> int:
        """Registers a local component and returns its id (0-based, in call order).

        Names and rooms saved by an operator override the defaults. ``riddle_id`` identifies the
        puzzle TYPE (PROTOCOL.md); empty = generate ``riddle-<16 hex>`` once and persist it.
        Beyond ``MAX_LOCAL_COMPONENTS`` the call is ignored and 255 is returned; the on_*() calls
        ignore that id, so unchecked callers cannot corrupt another component."""
        with self._lock:
            index = len(self._components)
            if index >= EscapeConfig.MAX_LOCAL_COMPONENTS:
                log.warning("add_component: at most %d components are supported", EscapeConfig.MAX_LOCAL_COMPONENTS)
                return INVALID_COMPONENT_ID
            stored_riddle = self._load_string("riddle%d" % index, "")
            if not stored_riddle:
                # First start: the sketch's puzzle-type id, otherwise a random one an operator can overwrite.
                # Deliberately NOT derived from the board so a replacement can be given the original's id.
                stored_riddle = bounded(riddle_id or "", EscapeConfig.MAX_RIDDLE_ID_LEN) or "riddle-" + secrets.token_hex(8)
                self._save_string("riddle%d" % index, stored_riddle)
            self._components.append(_Component(
                uuid="%s-%d" % (self._did, index), riddle_id=stored_riddle,
                name=bounded(self._load_string("name%d" % index, name), EscapeConfig.MAX_NAME_LEN),
                room=bounded(self._load_string("room%d" % index, room), EscapeConfig.MAX_ROOM_LEN),
                plan=bounded(self._load_string("plan%d" % index, ""), EscapeConfig.MAX_PLAN_LEN)))
            self.mark_dirty()
            return index

    def _component(self, identifier: int) -> Optional[_Component]:
        if isinstance(identifier, int) and 0 <= identifier < len(self._components):
            return self._components[identifier]
        return None

    def on_battery(self, callback: Callable[[], int]) -> None:
        """Battery is per device; percent, <= 0 = no battery / unknown (not reported)."""
        self._battery = callback

    def on_errors(self, identifier: int, callback: Callable[[], List[str]]) -> None:
        c = self._component(identifier)
        if c:
            c.errors = callback

    def on_actions(self, identifier: int, callback: Callable[[], List[str]]) -> None:
        c = self._component(identifier)
        if c:
            c.actions = callback

    def on_feed(self, identifier: int, callback: Callable[[], str]) -> None:
        c = self._component(identifier)
        if c:
            c.feed = callback

    def on_tip(self, identifier: int, callback: Callable[[], str]) -> None:
        c = self._component(identifier)
        if c:
            c.tip = callback

    def on_puzzle(self, identifier: int, callback: Callable[[], Tuple[int, int, str, bool]]) -> None:
        """``callback() -> (step, total_steps, state, is_html)``; total_steps == 0 hides the puzzle."""
        c = self._component(identifier)
        if c:
            c.puzzle = callback

    def on_action(self, identifier: int, callback: Callable[[str], bool]) -> None:
        c = self._component(identifier)
        if c:
            c.action = callback

    def on_plan_action(self, identifier: int, callback: Callable[[PlanAction], bool],
                       supported: Optional[Iterable[PlanAction]] = None) -> None:
        """Registering a handler announces reset+complete as ``planActions`` (or just ``supported``)."""
        c = self._component(identifier)
        if c:
            c.plan_action = callback
            c.plan_action_mask = ALL_PLAN_ACTIONS if supported is None else \
                sum(plan_action_bit(a) for a in set(supported))

    def on_custom_config(self, identifier: int, callback: Callable[[], List[CustomConfigDef]]) -> None:
        c = self._component(identifier)
        if c:
            c.custom_config = callback

    def on_custom_config_set(self, identifier: int, callback: Callable[[str, str], bool]) -> None:
        """Called per key AFTER the value was validated against the component's own schema."""
        c = self._component(identifier)
        if c:
            c.set_custom_config = callback

    def name(self, identifier: int) -> str:
        c = self._component(identifier)
        return c.name if c else ""

    def room(self, identifier: int) -> str:
        c = self._component(identifier)
        return c.room if c else ""

    def uuid(self, identifier: int) -> str:
        c = self._component(identifier)
        return c.uuid if c else ""

    def riddle_id(self, identifier: int) -> str:
        c = self._component(identifier)
        return c.riddle_id if c else ""

    @property
    def component_count(self) -> int:
        return len(self._components)

    # ---- state ----------------------------------------------------------------------------------------

    def mark_dirty(self) -> None:
        """Observable state changed (puzzle step, new error, ...): bump `seq` and announce soon."""
        with self._lock:
            self._seq = u32(self._seq + 1)
            self._dirty = True

    def push_event(self, identifier: int, message: str) -> None:
        """Records an activity message for a component (shown in the manager's log)."""
        with self._lock:
            c = self._component(identifier)
            if c is None:
                return
            c.event_seq = u32(c.event_seq + 1)
            c.event_msg = bounded(message, EscapeConfig.MAX_EVENT_MSG_LEN)
            self.mark_dirty()

    def hosted_rooms_changed(self) -> None:
        """Rooms may have changed: drop skeletons of rooms without a local component."""
        with self._lock:
            self._store.keep_only(hosted_rooms(self._host))

    def _now_ms(self) -> int:
        if self._clock is not None:
            return u32(self._clock())
        return u32(int((time.monotonic() - self._t0) * 1000))

    @property
    def did(self) -> str:
        return self._did

    @property
    def ip(self) -> str:
        return self._ip

    @property
    def boot(self) -> int:
        return self._boot

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def ui_hash(self) -> str:
        return self._ui_hash

    @property
    def token_state(self) -> TokenState:
        return self._transport.token_state if self._transport.ready else self._token_state

    @property
    def transport(self) -> SecureTransport:
        return self._transport

    @property
    def store(self) -> SkeletonStore:
        return self._store

    @property
    def lock(self) -> "threading.RLock":
        return self._lock  # type: ignore[return-value]

    @property
    def announcements_sent(self) -> int:
        return self._announcements_sent

    @property
    def listening_port(self) -> int:
        """The bound HTTP port (differs from ``http_port`` only if that was 0)."""
        return self._server.port if self._server else self.http_port

    def peers(self) -> List[PeerEntry]:
        with self._lock:
            return self._peers.entries()

    def device_info(self) -> DeviceInfo:
        with self._lock:
            return DeviceInfo(self._did, self._ui_hash, self._ip, self.listening_port, self._boot, self._seq,
                              self._now_ms(), self._host.battery(), self.token_state, self._transport.writable)

    def status_json(self) -> str:
        with self._lock:
            return build_status_doc(self._host, self.device_info())

    def peers_json(self) -> str:
        with self._lock:
            return build_peers_doc(self._peers, self.device_info(), self._store.summary_hash())

    def security_json(self) -> str:
        return build_security_doc(self.device_info())

    # ---- lifecycle ----------------------------------------------------------------------------------------

    def begin(self, background: bool = False) -> None:
        """Derives the keys, loads stored skeletons and opens the sockets.

        Raises ``OSError`` if the HTTP port cannot be opened. Discovery (UDP) and mDNS are best
        effort: the HTTP side works without them. With ``background=True`` a thread calls
        ``loop()`` for you."""
        with self._lock:
            if self._begun:
                return
            self._boot = self._next_boot_counter()
            valid = self._transport.begin(self._token, self._token_state, self._did)
            if not valid:
                log.warning("token unusable (needs %d..%d bytes): device is read-only", EscapeConfig.MIN_AUTH_TOKEN_LEN,
                            EscapeConfig.MAX_AUTH_TOKEN_LEN)
            self._store.load()
            self._store.keep_only(hosted_rooms(self._host))
            kwargs: Dict[str, Any] = {"host": self._http_bind_host}
            if self._http_idle_timeout is not None:
                kwargs["idle_timeout"] = self._http_idle_timeout
            if self._http_request_timeout is not None:
                kwargs["request_timeout"] = self._http_request_timeout
            server = HttpServer(self._http_handler, self.http_port, **kwargs)
            server.start()  # OSError propagates: nothing else has been opened yet
            self._server = server
            self._open_udp()
            self._open_mdns()
            self._dirty = True
            self._begun = True
        if background:
            self.start_background()

    def _open_udp(self) -> None:
        if not self.udp_port:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.bind(("", self.udp_port))
                sock.setblocking(False)
            except OSError:
                sock.close()
                raise
            self._udp = sock
        except OSError as error:
            log.warning("discovery disabled: cannot open UDP port %d (%s)", self.udp_port, error)

    def _open_mdns(self) -> None:
        if not self._mdns_enabled:
            return
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if hasattr(socket, "SO_REUSEPORT"):
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                sock.bind(("", self._mdns_port))
                sock.setblocking(False)
                iface = socket.inet_aton(self._ip)
                try:
                    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MDNS_GROUP) + iface)
                except OSError as error:  # still answers unicast (QU) queries
                    log.warning("mDNS: could not join %s on %s (%s)", MDNS_GROUP, self._ip, error)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, iface)
            except OSError:
                sock.close()
                raise
            self._mdns = sock
        except OSError as error:
            log.warning("mDNS disabled: cannot open UDP port %d (%s)", self._mdns_port, error)

    def start_background(self, interval: float = 0.005) -> None:
        """Runs ``loop()`` in a daemon thread until ``close()``."""
        if self._background is not None:
            return
        self._stop_background.clear()

        def run() -> None:
            while not self._stop_background.is_set():
                self.loop()
                self._stop_background.wait(interval)

        self._background = threading.Thread(target=run, name="escape-loop", daemon=True)
        self._background.start()

    def close(self) -> None:
        """Stops the server, the loop thread and all sockets. Safe to call twice."""
        self._stop_background.set()
        background, self._background = self._background, None
        if background is not None and background is not threading.current_thread():
            background.join(timeout=2.0)
        server, self._server = self._server, None
        if server is not None:
            server.stop()
        with self._lock:
            for name in ("_udp", "_mdns"):
                sock = getattr(self, name)
                setattr(self, name, None)
                if sock is not None:
                    try:
                        sock.close()
                    except OSError:
                        pass
            self._begun = False
        sync = self._sync_thread
        if sync is not None and sync is not threading.current_thread():
            sync.join(timeout=EscapeConfig.SKELETON_SYNC_TIMEOUT_MS / 1000.0 + 0.5)

    def __enter__(self) -> "EscapeComponent":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # ---- the cooperative loop -------------------------------------------------------------------------------

    def _guard(self, stage: str, fn: Callable[..., None], *args: Any) -> None:
        try:
            fn(*args)
        except Exception:  # discovery must never take the host program down
            now = time.monotonic()
            if now - self._warned.get(stage, -1e9) > 30.0:
                self._warned[stage] = now
                log.exception("loop stage %s failed", stage)

    def loop(self) -> None:
        """One bounded slice of work: receive announcements, announce, expire peers, sync skeletons, mDNS.
        Never blocks; network errors are swallowed."""
        if not self._begun:
            return
        now = self._now_ms()
        self._guard("udp-receive", self._receive_announcements, now)
        self._guard("udp-announce", self._maybe_announce, now)
        with self._lock:
            self._peers.expire_stale(now)
        self._guard("sync", self._pump_sync, now)
        self._guard("mdns", self._service_mdns, now)

    # ---- UDP discovery ---------------------------------------------------------------------------------------

    def _receive_announcements(self, now: int) -> None:
        sock = self._udp
        if sock is None:
            return
        for _ in range(64):
            try:
                data, addr = sock.recvfrom(EscapeConfig.MAX_ANNOUNCEMENT_BYTES + 16)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            # Cheap rejections before any parsing or crypto: size and shape.
            if len(data) > EscapeConfig.MAX_ANNOUNCEMENT_BYTES or len(data) < 20 or not data.startswith(b'{"doc":'):
                continue
            source = addr[0]
            with self._lock:
                source_int = parse_ipv4(source)
                if source_int is None or not self._udp_limiter.allow_source(source_int, now):
                    continue
                doc = self._transport.open_announcement(data)
                if doc is None:
                    continue
                announcement = parse_announcement(doc)
                if announcement is None or announcement.pmin > PROTO:
                    continue  # malformed, or the peer needs a newer protocol than we speak
                if self._peers.ingest(announcement, source, self._did, now) == IngestResult.ACCEPTED:
                    self._consider_sync(announcement, now)

    def _maybe_announce(self, now: int) -> None:
        sock = self._udp
        if sock is None or not self._ip_int:
            return
        with self._lock:
            interval = EscapeConfig.HEARTBEAT_INTERVAL_MS + self._jitter
            if not (is_heartbeat_due(now, self._last_announce, interval)
                    or is_change_broadcast_due(now, self._last_announce, self._dirty)):
                return
            self._last_announce = now
            self._dirty = False
            self._ctr = u32(self._ctr + 1)
            doc = build_announcement_doc(self._did, self._ip, self.listening_port, self._boot, self._ctr, self._seq,
                                         PROTO_MIN, self._ui_hash, self._store.summary_json(),
                                         self._store.summary_hash())
            frame = self._transport.frame_announcement(doc)
        if frame is None or len(frame) > EscapeConfig.MAX_ANNOUNCEMENT_BYTES:
            return
        try:
            sock.sendto(frame, (self._broadcast, self.udp_port))
            self._announcements_sent += 1
        except OSError:
            pass  # network down / no route: the next heartbeat retries

    # ---- skeleton sync -----------------------------------------------------------------------------------------

    def _consider_sync(self, a: Announcement, now: int) -> None:
        """Lock held. If a peer announces a newer (rev, hash) for a room we host, queue ONE fetch."""
        if self._sync_pending is not None or self._sync_busy:
            return  # one at a time; the next announcement retries
        rooms = hosted_rooms(self._host)
        for announced in a.sk:
            for room in rooms:
                if room_key(room) != hex8(announced.room_key):
                    continue
                own = self._store.find(room)
                if own is not None and not skeleton_is_newer(announced.rev, announced.hash, own.rev, own.hash):
                    continue
                failed_at = self._sync_failures.get((a.did, announced.room_key))
                if failed_at is not None and u32(now - failed_at) < EscapeConfig.SKELETON_SYNC_BACKOFF_MS:
                    continue
                self._sync_pending = _SyncRequest(a.ip, a.port, announced.room_key, room, a.did)
                return

    def _pump_sync(self, now: int) -> None:
        with self._lock:
            request = self._sync_pending
            if request is None or self._sync_busy:
                return
            self._sync_pending = None
            self._sync_busy = True
        try:
            thread = threading.Thread(target=self._sync_job, args=(request,), name="escape-sync", daemon=True)
            self._sync_thread = thread
            thread.start()
        except RuntimeError:
            with self._lock:
                self._sync_busy = False

    def _sync_job(self, request: _SyncRequest) -> None:
        """Worker thread: fetch the peer's skeleton (authenticated frame bound to the PEER's did), adopt it."""
        stored = False
        try:
            nonce = b64u_encode(secrets.token_bytes(16))
            target = "/plan-skeleton.json?room=%s&nonce=%s" % (
                urllib.parse.quote(request.room.encode("utf-8"), safe="-_.~"), nonce)
            result = http_get(request.ip, request.port, target, EscapeConfig.SKELETON_SYNC_TIMEOUT_MS / 1000.0,
                              EscapeConfig.MAX_PLAN_SKELETON_LEN + 512)
            if result is not None and result[0] == 200:
                doc = self._transport.open_document_frame_from(request.did, "/plan-skeleton.json", nonce, 200, result[1])
                if doc is not None:
                    with self._lock:
                        if request.room in hosted_rooms(self._host):
                            stored = self._store.adopt(doc, request.room) == SkeletonResult.STORED
                        if stored:
                            for i in range(len(self._components)):
                                if self._components[i].room == request.room:
                                    self.push_event(i, "Raum-Ablaufplan von Nachbargeraet uebernommen")
                            self.mark_dirty()
        except Exception:
            log.exception("skeleton sync failed")
        finally:
            with self._lock:
                key = (request.did, request.room_key)
                if stored:
                    self._sync_failures.pop(key, None)
                else:  # wrong/stale/unreachable: back off for this peer and room
                    self._sync_failures[key] = self._now_ms()
                now = self._now_ms()
                self._sync_failures = {k: v for k, v in self._sync_failures.items()
                                       if u32(now - v) < EscapeConfig.SKELETON_SYNC_BACKOFF_MS}
                self._sync_busy = False

    @property
    def sync_in_flight(self) -> bool:
        return self._sync_busy or self._sync_pending is not None

    # ---- shared mDNS record ------------------------------------------------------------------------------------

    def _service_mdns(self, now: int) -> None:
        sock = self._mdns
        if sock is None:
            return
        ip_bytes = struct.pack("!I", self._ip_int)
        ttl = EscapeConfig.MDNS_TTL_S
        for _ in range(8):
            try:
                data, addr = sock.recvfrom(512)
            except (BlockingIOError, InterruptedError):
                break
            except OSError:
                break
            query = parse_mdns_query(data, self._mdns_name, ip_bytes, ttl)
            if not query.matches or query.suppressed:
                continue
            if query.unicast:  # QU bit: an immediate unicast answer
                answer = build_mdns_answer(self._mdns_name, ip_bytes, ttl)
                if answer:
                    try:
                        sock.sendto(answer, addr)
                    except OSError:
                        pass
            elif not self._mdns_pending:
                self._mdns_pending = True
                self._mdns_at = u32(now + mdns_response_delay_ms(secrets.randbits(32)))
        if self._mdns_pending and s32(now - self._mdns_at) >= 0:
            self._mdns_pending = False
            answer = build_mdns_answer(self._mdns_name, ip_bytes, ttl)
            if answer:
                try:
                    sock.sendto(answer, (MDNS_GROUP, self._mdns_port))
                except OSError:
                    pass

    # ---- HTTP (called with the lock held) --------------------------------------------------------------------------

    def _serve_ui(self, request: HttpRequest) -> HttpResponse:
        if not self._ui_gz:
            return _plain_error(404, "not_found", "no embedded UI")
        r = HttpResponse(200, "text/html; charset=utf-8", gzip=True, etag=self._ui_hash)
        inm = request.if_none_match
        if inm.startswith("W/"):
            inm = inm[2:]
        if inm == '"%s"' % r.etag:  # browser already has this build
            r.status = 304
            r.gzip = False
            return r
        r.body = self._ui_gz
        return r

    def _send_document(self, request: HttpRequest, path: str, status: int, doc: Union[str, bytes]) -> HttpResponse:
        """Authenticated frame when a nonce was sent, bare document otherwise (viewer mode)."""
        body = _as_bytes(doc)
        nonce_raw = query_param(request.query, "nonce")
        if nonce_raw is None:
            if EscapeConfig.STRICT_GET:
                return _plain_error(401, "auth_required", "authenticated read required")
            return HttpResponse(status, "application/json", body)
        try:
            nonce = nonce_raw.decode("ascii")
        except UnicodeDecodeError:
            nonce = ""
        if not valid_nonce(nonce):
            return _plain_error(400, "bad_request", "invalid nonce")
        frame = self._transport.frame_document(path, nonce, status, body)
        if frame is None:
            return _plain_error(503, "read_only", "authenticated reads unavailable")
        return HttpResponse(status, "application/json", frame)

    def _handle_get(self, request: HttpRequest) -> HttpResponse:
        path = request.path
        if path == "/":
            return self._serve_ui(request)
        if path == "/favicon.ico":
            return HttpResponse(204, "application/json")
        info = self.device_info()
        if path == "/security.json":
            return HttpResponse(200, "application/json", build_security_doc(info).encode("utf-8"))
        if path == "/status.json":
            return self._send_document(request, path, 200, build_status_doc(self._host, info))
        if path == "/peers.json":
            return self._send_document(request, path, 200, build_peers_doc(self._peers, info, self._store.summary_hash()))
        if path == "/plan-skeleton.json":
            room_raw = query_param(request.query, "room")
            if room_raw is None:
                return self._send_document(request, path, 200, build_skeleton_index_doc(self._store))
            try:
                room = room_raw.decode("utf-8")
            except UnicodeDecodeError:
                room = ""
            blob = self._store.get(room) if room else None
            if blob is None:
                return self._send_document(request, path, 404, error_body("no_plan", "no skeleton stored for this room"))
            return self._send_document(request, path, 200, blob)
        return _plain_error(404, "not_found", "unknown path")

    def _handle_post(self, request: HttpRequest, remote_ip: str) -> HttpResponse:
        now = self._now_ms()
        source = parse_ipv4(remote_ip) or 0
        if not (self._limiter.allow_global(now) and self._limiter.allow_source(source, now)):
            return _plain_error(429, "rate_limited", "too many requests")
        opened = self._transport.open_request(request.path, request.body, now)
        if opened.status != 200:
            if opened.status == 401:
                self._limiter.allow_source(source, now, 3)  # failed authentication costs extra
            extra = '"time":%d' % now if opened.code == "stale_time" else ""
            result = error_result(opened.status, opened.code or "bad_request", opened.code or "bad_request", extra)
            if not opened.request_iv or not self._transport.writable:  # cannot be authenticated: plain
                return HttpResponse(result.status, "application/json", result.body.encode("utf-8"))
        else:
            try:
                result = self._dispatch(request.path, opened.plaintext)
            except Exception:  # an authenticated request still gets an authenticated answer
                log.exception("handler for %s failed", request.path)
                result = error_result(500, "internal_error", "internal error")
        sealed = self._transport.seal_response(request.path, opened.request_iv, result.status, result.body)
        if sealed is None:
            return _plain_error(503, "busy", "could not seal response")
        return HttpResponse(result.status, "application/json", sealed)

    def _dispatch(self, path: str, plaintext: bytes) -> HttpResult:
        if path == "/action":
            return handle_action(self._host, plaintext)
        if path == "/plan-action":
            return handle_plan_action(self._host, plaintext)
        if path == "/config":
            result = handle_config(self._host, plaintext)
            if result.status == 200:
                self.hosted_rooms_changed()
            return result
        if path == "/plan":
            return handle_plan(self._host, plaintext)
        return handle_plan_skeleton(self._host, self._store, plaintext)


__all__ = [
    "ALL_PLAN_ACTIONS", "AUTH_TOKEN_DEFAULT", "Announcement", "BlobStorage", "ComponentSnapshot", "CustomConfigDef",
    "DerivedKeys", "DeviceInfo", "EscapeComponent", "EscapeConfig", "FileStorage", "HttpRequest", "HttpResponse",
    "HttpResult", "HttpServer", "IngestResult", "JsonError", "MemoryStorage", "Method", "OpenResult", "PeerEntry",
    "PeerTable", "PlanAction", "ProtocolAdapter", "RateLimiter", "Scan", "SecureTransport", "SkeletonResult",
    "SkeletonStore", "TokenState", "b64u_decode", "b64u_encode", "derive_keys", "fnv1a32", "hex8", "hkdf_sha256",
]
