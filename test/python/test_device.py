"""Device-level behaviour: announcements on the wire, concurrency, mDNS timing, lifecycle and constructor rules."""

from __future__ import annotations

import json
import socket
import struct
import threading
import time

import pytest

import escape_component as ec
import helpers
from helpers import DISCOVERY_PORT, Manager, exchange, get, wait_for


# ---- announcements as seen on the wire -------------------------------------------------------------------------------

def listen_udp():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    sock.bind(("", DISCOVERY_PORT))
    sock.settimeout(0.5)
    return sock


def collect(sock, did, count, timeout=12.0):
    verifier = ec.SecureTransport()
    verifier.begin(helpers.TEST_TOKEN, ec.TokenState.CUSTOM, "000000000000")
    docs = []
    deadline = time.monotonic() + timeout
    while len(docs) < count and time.monotonic() < deadline:
        try:
            data, addr = sock.recvfrom(2048)
        except socket.timeout:
            continue
        doc = verifier.open_announcement(data)
        if doc is not None and json.loads(doc)["did"] == did:
            docs.append((data, doc, addr))
    return docs


def test_announcements_on_the_wire(component):
    sock = listen_udp()
    c = component((("Laser", "Raum A"), ("Kamera", "Raum B")), udp_port=DISCOVERY_PORT)
    m = Manager(c.listening_port).init()
    assert m.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":{"a":1}}').status == 200
    docs = collect(sock, c.did, 3, 16.0)          # startup, the change caused by the POST, then a heartbeat
    sock.close()
    assert len(docs) >= 3
    ctrs = []
    for data, doc, addr in docs:
        assert len(data) <= ec.EscapeConfig.MAX_ANNOUNCEMENT_BYTES and data.startswith(b'{"doc":{"v":2,"did":"%s","ip":"127.0.0.1"' % c.did.encode())
        assert addr[0] == "127.0.0.1"                                   # the announced ip equals the datagram source
        d = json.loads(doc)
        assert d["port"] == c.listening_port and d["boot"] == c.boot and d["pmin"] == 2 and d["uih"] == c.ui_hash
        assert d["skh"] == ec.hex8(ec.fnv1a32(json.dumps(d["sk"], separators=(",", ":"))))
        ctrs.append(d["ctr"])
        last = d
    assert ctrs == sorted(ctrs) and len(set(ctrs)) == len(ctrs) and ctrs[0] >= 1        # strictly increasing, starts at 1 per boot
    assert last["sk"] == [[ec.room_key("Raum A"), 1, ec.hex8(ec.fnv1a32('{"a":1}'))]]    # the skeleton summary
    assert last["seq"] >= 3
    assert list(json.loads(docs[0][1])) == ["v", "did", "ip", "port", "boot", "ctr", "seq", "pmin", "uih", "skh", "sk"]


def test_change_broadcast_has_a_minimum_gap_and_heartbeat_is_periodic(component):
    sock = listen_udp()
    c = component(udp_port=DISCOVERY_PORT)
    time.sleep(0.8)
    while True:                                                           # drain what the startup produced
        try:
            sock.recvfrom(2048)
        except socket.timeout:
            break
    stamps = []
    start = time.monotonic()
    for i in range(30):                                                   # a burst of REAL changes
        c.push_event(0, "tick %d" % i)
        time.sleep(0.02)
    docs = collect(sock, c.did, 3, 1.0)
    sock.close()
    assert 1 <= len(docs) <= 3                                           # not one datagram per change: >= 300 ms apart
    time.sleep(0.1)
    sent = c.announcements_sent
    assert wait_for(lambda: c.announcements_sent > sent, 6)             # idle: the heartbeat (4 s + <= 750 ms jitter) fires


def test_announcements_keep_the_uint32_counters_in_range(component):
    c = component(udp_port=DISCOVERY_PORT)
    c._seq = 0xFFFFFFFF
    c._bump()
    assert c.seq == 0                                                     # wraps like the C++ uint32
    assert wait_for(lambda: c.announcements_sent > 0, 3)


def test_host_hints_are_coalesced_and_verified(component):
    # A host may call mark_dirty() on EVERY loop iteration: that must not make `seq` climb or the
    # device announce at that rate. Only a real change counts (mirrors the C++ Device test).
    c = component(udp_port=DISCOVERY_PORT)
    time.sleep(1.2)
    seq0, sent0 = c.seq, c.announcements_sent
    end = time.monotonic() + 3.0
    while time.monotonic() < end:
        c.mark_dirty()
        time.sleep(0.001)
    assert c.seq == seq0                                                   # nothing changed -> no new revision
    assert c.announcements_sent - sent0 <= 2                               # heartbeat pace, not every 300 ms
    c.push_event(0, "something happened")                                  # a real change behind a hint
    assert wait_for(lambda: c.seq == seq0 + 1, 3)
    time.sleep(1.2)
    assert c.seq == seq0 + 1                                               # exactly once
    c._components[0].plan = '{"planId":"silent"}'                          # a change WITHOUT a hint is not looked for
    time.sleep(1.2)
    assert c.seq == seq0 + 1


# ---- concurrency: one lock protects everything ----------------------------------------------------------------

def test_concurrent_identical_envelopes_are_accepted_exactly_once(component):
    c = component()
    m = Manager(c.listening_port).init()
    envelope = m.transport.seal_request("/action", m.device_time(), '{"id":0,"action":"x"}', b"Q" * 12)
    results = []
    barrier = threading.Barrier(8)

    def post():
        barrier.wait()
        results.append(m.post_raw("/action", envelope).status)

    threads = [threading.Thread(target=post) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(results) == [409] * 7 + [422]                          # exactly one request got through (no action handler: 422)


def test_parallel_readers_writers_and_state_changes_stay_consistent(component):
    c = component((("Laser", "Raum A"), ("Kamera", "Raum A")))
    counter = {"n": 0}
    c.on_action(0, lambda a: counter.__setitem__("n", counter["n"] + 1) or True)
    errors = []
    stop = threading.Event()

    def reader():
        while not stop.is_set():
            r = get(c.listening_port, "/status.json")
            if r.status != 200:
                errors.append(r.status)
                continue
            try:
                json.loads(r.body)
            except ValueError:
                errors.append("bad json")

    def mutator():
        while not stop.is_set():
            c.mark_dirty()
            c.push_event(0, "tick")
            c.peers()

    threads = [threading.Thread(target=reader) for _ in range(3)] + [threading.Thread(target=mutator)]
    for t in threads:
        t.start()
    m = Manager(c.listening_port).init()
    for _ in range(10):
        assert m.post("/action", {"id": 0, "action": "go"}).status == 200
    stop.set()
    for t in threads:
        t.join()
    assert counter["n"] == 10 and errors == []


# ---- mDNS timing ----------------------------------------------------------------------------------------------------------

def test_multicast_answer_is_delayed_and_not_repeated_while_pending(component):
    port = 15353
    c = component(mdns_enabled=True, mdns_port=port)
    asker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    asker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    asker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    asker.bind(("", port))
    try:
        asker.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(ec.MDNS_GROUP) + socket.inet_aton("127.0.0.1"))
        asker.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton("127.0.0.1"))
    except OSError:
        pytest.skip("multicast on the loopback interface is not available here")
    query = (struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + bytes([13]) + b"escapemanager" + bytes([5]) + b"local\x00"
             + struct.pack("!HH", 1, 1))                                  # multicast question (QU bit cleared)
    asker.settimeout(1.5)
    t0 = time.monotonic()
    asker.sendto(query, (ec.MDNS_GROUP, port))
    asker.sendto(query, (ec.MDNS_GROUP, port))                            # a second question while the answer is pending
    seen = []
    try:
        while True:
            data, _ = asker.recvfrom(512)
            seen.append((time.monotonic() - t0, data))
    except socket.timeout:
        pass
    asker.close()
    if not any(d[2] == 0x00 for _t, d in seen):
        pytest.skip("multicast loopback does not deliver our own query here")
    answers = [(t, d) for t, d in seen if d[2] == 0x84]
    assert len(answers) == 1, "one delayed answer, not one per question"
    delay = answers[0][0]
    assert 0.015 <= delay <= 0.4, delay                                  # 20-120 ms plus loop granularity
    assert answers[0][1] == ec.build_mdns_answer("escapemanager.local", bytes([127, 0, 0, 1]), ec.EscapeConfig.MDNS_TTL_S)


# ---- lifecycle, constructor ------------------------------------------------------------------------------------------------

def test_begin_twice_close_twice_and_context_manager():
    port = helpers.free_http_port()
    with ec.EscapeComponent(http_port=port, udp_port=0, local_ip="127.0.0.1", mdns_enabled=False, storage=ec.MemoryStorage()) as c:
        c.add_component("L", "R")
        c.begin()
        c.begin()                                                         # second call is a no-op
        assert get(port, "/security.json").status == 200
        c.loop()
    c.close()                                                             # closing again is harmless
    with pytest.raises(OSError):
        socket.create_connection(("127.0.0.1", port), timeout=1)
    c.begin()                                                             # and a closed device can be started again
    assert get(port, "/security.json").status == 200
    c.close()


def test_begin_raises_oserror_if_the_http_port_is_taken_and_leaves_nothing_open(component):
    first = component()
    second = helpers.make_component(begin=False, http_port=first.listening_port)
    with pytest.raises(OSError):
        second.begin()
    assert second._udp is None and second._mdns is None and second._server is None
    assert get(first.listening_port, "/security.json").status == 200
    second.close()


def test_loop_before_begin_is_a_noop():
    c = helpers.make_component(begin=False)
    c.loop()
    c.close()


def test_component_limit_and_ignored_ids():
    c = helpers.make_component(components=(), begin=False)
    ids = [c.add_component("C%d" % i, "R") for i in range(6)]
    assert ids == [0, 1, 2, 3, 255, 255] and c.component_count == 4
    c.on_actions(255, lambda: ["boom"])                                  # ignored, cannot corrupt another component
    c.on_action(-1, lambda a: True)
    c.on_errors(99, lambda: ["x"])
    c.push_event(255, "ignored")
    assert all(not comp.actions and not comp.action for comp in c._components)
    assert c.name(255) == "" and c.room(7) == ""


def test_constructor_validation_and_token_states():
    with pytest.raises(ValueError):
        ec.EscapeComponent(did="NOTHEX", storage=ec.MemoryStorage())
    with pytest.raises(ValueError):
        ec.EscapeComponent(local_ip="not-an-ip", storage=ec.MemoryStorage())
    mem = ec.MemoryStorage
    assert ec.EscapeComponent(storage=mem(), local_ip="127.0.0.1").token_state == ec.TokenState.DEFAULT
    assert ec.EscapeComponent(storage=mem(), local_ip="127.0.0.1", auth_token=ec.AUTH_TOKEN_DEFAULT).token_state == ec.TokenState.DEFAULT
    assert ec.EscapeComponent(storage=mem(), local_ip="127.0.0.1", auth_token="a-custom-token-value-123").token_state == ec.TokenState.CUSTOM


def test_default_token_device_works_with_the_public_default_token(component):
    c = component(auth_token=None)
    assert c.token_state == ec.TokenState.DEFAULT
    m = Manager(c.listening_port, ec.AUTH_TOKEN_DEFAULT).init()
    assert m.security["token"] == "default"
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422
    assert Manager(c.listening_port, "something-else-entirely-1").init().post("/action", {"id": 0, "action": "x"}).status == 401


def test_get_without_nonce_in_strict_mode(component, monkeypatch):
    monkeypatch.setattr(ec.EscapeConfig, "STRICT_GET", True)
    c = component()
    r = get(c.listening_port, "/status.json")
    assert r.status == 401 and r.json()["code"] == "auth_required"
    assert Manager(c.listening_port).init().get_json("/status.json")["did"] == c.did   # framed reads still work
    assert get(c.listening_port, "/security.json").status == 200


# ---- hostile HTTP traffic ------------------------------------------------------------------------------------------------------

def test_random_http_garbage_never_kills_the_server(component):
    import random
    c = component(http_idle_timeout=0.3, http_request_timeout=1.0)
    rnd = random.Random(42)
    valid = b"POST /action HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\nOrigin: null\r\n\r\n" + b"x" * 20
    seeds = [valid, b"GET /status.json?nonce=0123456789abcdef HTTP/1.1\r\n\r\n", b"OPTIONS /plan HTTP/1.1\r\nOrigin: http://a.local\r\n\r\n"]
    for i in range(80):
        if i % 4 == 0:
            payload = bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 3000)))
        else:
            data = bytearray(rnd.choice(seeds))
            for _ in range(rnd.randrange(1, 8)):
                data[rnd.randrange(len(data))] = rnd.randrange(256)
            payload = bytes(data[:rnd.randrange(1, len(data) + 1)])
        try:
            with socket.create_connection(("127.0.0.1", c.listening_port), timeout=2) as s:
                s.sendall(payload)
                if i % 3 == 0:
                    s.shutdown(socket.SHUT_WR)
                if i % 5 == 0:
                    continue                                              # hang up without reading
                s.settimeout(0.3)
                try:
                    s.recv(65536)
                except OSError:
                    pass
        except OSError:
            pass
    assert helpers.wait_for(lambda: c._server.active_connections == 0, 8)
    assert get(c.listening_port, "/status.json").status == 200


def test_connection_reset_while_responding_is_harmless(component):
    c = component(manager_html="y" * 3_000_000)
    for _ in range(10):
        s = socket.socket()
        s.connect(("127.0.0.1", c.listening_port))
        s.sendall(b"GET / HTTP/1.1\r\n\r\n")
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()                                                         # RST in the middle of the response
    assert helpers.wait_for(lambda: c._server.active_connections == 0, 8)
    assert exchange(c.listening_port, b"GET /security.json HTTP/1.1\r\n\r\n").status == 200


def test_default_timeouts_are_enforced_with_the_real_values(component):
    c = component()                                                       # idle 5 s, total 10 s
    results = {}

    def idle():
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", c.listening_port), timeout=15) as s:
            s.settimeout(15)
            results["idle"] = (s.recv(10), time.monotonic() - t0)

    def dribble():
        t0 = time.monotonic()
        with socket.create_connection(("127.0.0.1", c.listening_port), timeout=15) as s:
            s.settimeout(0.5)
            closed = None
            for i in range(40):
                try:
                    s.sendall(b"X-")
                    if s.recv(1) == b"":
                        closed = time.monotonic() - t0
                        break
                except socket.timeout:
                    pass
                except OSError:
                    closed = time.monotonic() - t0
                    break
                time.sleep(2.5)                                           # never idle for 5 s, never finishes the request
            results["dribble"] = closed

    threads = [threading.Thread(target=idle), threading.Thread(target=dribble)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    data, idle_for = results["idle"]
    assert data == b"" and 4.5 <= idle_for <= 7.0, idle_for               # 5 s without a byte
    assert results["dribble"] is not None and 9.0 <= results["dribble"] <= 13.5, results["dribble"]   # 10 s in total

def test_everything_works_with_the_clock_just_before_the_32_bit_wrap(component):
    # The device clock is a uint32 millisecond counter that wraps after 49.7 days. A deadline initialised to
    # 0 and compared as a signed difference stalls its feature while the clock is in the upper half (found on
    # real ESP32 hardware in the C++ core). Start the clock 3 s before the wrap and run across it.
    t0 = time.monotonic()
    c = component(udp_port=DISCOVERY_PORT, clock=lambda: (0xFFFFFFFF - 3000 + int((time.monotonic() - t0) * 1000)) & 0xFFFFFFFF)
    assert wait_for(lambda: c.announcements_sent > 0, 3)                   # announcements flow in the upper half
    c.push_event(0, "before the wrap")                                       # a hint: the host-change check must run
    assert wait_for(lambda: c.seq > 1, 3)
    m = helpers.Manager(c.listening_port).init()
    assert m.device_time() > 0xFFFFF000
    r = m.post("/action", {"id": 0, "action": "x"})
    assert r.status in (200, 422)                                           # authenticated and processed (the action may be unknown)
    time.sleep(3.5)                                                         # across the wrap
    assert m.device_time() < 0x10000000
    seq = c.seq
    c.push_event(0, "after the wrap")
    assert wait_for(lambda: c.seq > seq, 3)
    r = m.post("/action", {"id": 0, "action": "x"})
    assert r.status in (200, 422)
