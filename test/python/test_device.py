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
from helpers import DISCOVERY_PORT, Manager, RecordingSink, exchange, get, wait_for


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


# ---- plan-edit token (PROTOCOL.md 3.1; mirrors test_edit_* in test/test_net/test_device.cpp) -------------------------------

EDIT_TOKEN = "edit-token-for-the-tests"
EDIT = ec.KeyRole.EDIT
NORMAL = ec.KeyRole.NORMAL


def sealed_with(manager, path, response, request_iv, role):
    """The plaintext of an answer if it opens with the key set ``role`` (else None)."""
    return manager.transport.open_response(path, ec.b64u_encode(request_iv), response.status, response.body, role)


def test_edit_token_guards_sending_plans(component):
    a = component((("Laser", "Raum A"),), edit_token=EDIT_TOKEN)
    b = component((("Kamera", "Raum B"),))                              # no edit token: as before
    done = []
    a.on_action(0, lambda action: done.append(action) or True)
    normal = Manager(a.listening_port).init()
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    sk = '{"planId":"p1","layers":[]}'
    sk_body = '{"room":"Raum A","baseRev":0,"sk":%s}' % sk

    # Game operation needs only the normal token.
    r = normal.post("/action", {"id": 0, "action": "open"})
    assert (r.status, r.authenticated, r.body) == (200, True, {"ok": True}) and done == ["open"]
    assert normal.post("/config", {"id": 0, "name": "Laser", "room": "Raum A"}).status == 200
    assert normal.post("/plan-action", {"id": 0, "action": "reset"}).code == "unsupported"   # authenticated and processed

    # Sending a plan with the normal token alone is refused - but the refusal is authenticated (normal keys).
    r = normal.post("/plan-skeleton", sk_body)
    assert (r.status, r.authenticated, r.code) == (403, True, "edit_required") and normal.last_role == NORMAL
    assert r.body["ok"] is False and r.response.headers["content-length"] == str(len(r.response.body))
    r = normal.post("/plan", '{"id":0,"plan":{"x":1}}')
    assert (r.status, r.code) == (403, "edit_required")
    assert a.store.find("Raum A") is None and a._components[0].plan == ""
    assert normal.post("/setup", '{"token":"another-token-123"}').status == 404        # no sink: unknown path (route)

    # With the edit token it works, and the answer is sealed with the edit keys.
    iv = b"E" * 12
    envelope = editor.transport.seal_request("/plan-skeleton", editor.device_time(), sk_body, iv, EDIT)
    response = editor.post_raw("/plan-skeleton", envelope)
    assert response.status == 200
    assert sealed_with(editor, "/plan-skeleton", response, iv, EDIT) is not None
    assert sealed_with(editor, "/plan-skeleton", response, iv, NORMAL) is None         # ek_resp, not k_resp
    r = editor.post("/plan-skeleton", '{"room":"Raum A","baseRev":1,"sk":{"planId":"p2"}}', role=EDIT)
    assert (r.status, r.authenticated, r.body["rev"]) == (200, True, 2) and editor.last_role == EDIT
    r = editor.post("/plan", '{"id":0,"plan":{"x":1}}', role=EDIT)
    assert (r.status, r.body) == (200, {"ok": True}) and a._components[0].plan == '{"x":1}'
    assert editor.post("/plan", '{"id":0,"plan":{"x":2}}', role=EDIT).status == 200

    # The stored skeleton is stamped (emac) so peers with the edit token accept it; anyone may READ it.
    blob = normal.get_json("/plan-skeleton.json", "room=Raum%20A")
    assert blob["rev"] == 2 and len(blob["emac"]) == 43 and blob["sk"] == {"planId": "p2"}
    raw_blob = a.store.get("Raum A")
    assert ec.find_field(raw_blob, "emac")[0] == ec.Scan.FOUND
    assert a.transport.verify_skeleton("Raum A", 2, ec.fnv1a32('{"planId":"p2"}'), blob["emac"])
    assert normal.get_json("/plan-skeleton.json")["rooms"][0]["rev"] == 2

    # A wrong edit token is refused like any other bad authentication (answer sealed with the normal keys).
    wrong = Manager(a.listening_port, edit_token="not-the-edit-token-0000").init()
    r = wrong.post("/plan", '{"id":0,"plan":null}', role=EDIT)
    assert (r.status, r.authenticated, r.code) == (401, True, "auth_failed") and wrong.last_role == NORMAL
    assert a._components[0].plan == '{"x":1}'.replace("1", "2")
    # The edit keys never authorise normal operation: "k":"e" on a non-edit path is a bad envelope (unauthenticated).
    r = editor.post("/action", {"id": 0, "action": "open"}, role=EDIT)
    assert (r.status, r.authenticated) == (400, False) and r.code == "bad_envelope" and done == ["open"]
    # ... and a request sealed with the NORMAL keys but claiming "k":"e" does not authenticate either
    bad = normal.transport.seal_request("/plan", normal.device_time(), "{}", b"X" * 12)[:-1] + b',"k":"e"}'
    r = normal.post_raw("/plan", bad)
    assert r.status == 401
    assert sealed_with(normal, "/plan", r, b"X" * 12, NORMAL) is not None            # a normal-key holder can read the refusal

    # A device WITHOUT an edit token behaves exactly as before (mixed fleets): the normal token sends plans.
    for_b = Manager(b.listening_port).init()
    assert for_b.post("/plan", '{"id":0,"plan":{"y":2}}').status == 200
    assert for_b.post("/plan-skeleton", '{"room":"Raum B","baseRev":0,"sk":{"planId":"b"}}').status == 200
    assert "emac" not in json.loads(b.store.get("Raum B"))
    # ... and an edit-keyed request cannot even be verified there.
    edit_for_b = Manager(b.listening_port, edit_token=EDIT_TOKEN).init()
    r = edit_for_b.post("/plan", '{"id":0,"plan":null}', role=EDIT)
    assert (r.status, r.authenticated, r.code) == (401, True, "auth_failed") and edit_for_b.last_role == NORMAL

    # Published states: security.json is public, status.json is framed.
    sec_a, sec_b = get(a.listening_port, "/security.json").json(), get(b.listening_port, "/security.json").json()
    assert sec_a["edit"] == "custom" and sec_b["edit"] == "unset"
    assert sec_a["caps"] == sec_b["caps"] == ["plan", "cfg", "edit"] and sec_a["setupAp"] == "none"
    assert sec_a["writable"] is True and sec_a["token"] == "custom"
    assert normal.get_json("/status.json")["edit"] == "custom" and for_b.get_json("/status.json")["edit"] == "unset"
    assert a.edit_state == ec.EditState.CUSTOM and b.edit_state == ec.EditState.UNSET
    assert a.token_state == ec.TokenState.CUSTOM
    assert a.transport.signing_enabled and not b.transport.signing_enabled


def test_edit_token_roles_on_every_path_and_errors_before_authentication(component):
    a = component((("Laser", "Raum A"),), edit_token=EDIT_TOKEN)
    normal = Manager(a.listening_port).init()
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    # every edit path with the normal keys: 403; the IV was consumed, a resend is a replay (authenticated)
    for i, path in enumerate(("/plan", "/plan-skeleton")):
        iv = bytes([0x52 + i] * 12)
        envelope = normal.transport.seal_request(path, normal.device_time(), "{}", iv)
        assert normal.post_raw(path, envelope).status == 403
        again = normal.post_raw(path, envelope)
        assert again.status == 409 and json.loads(sealed_with(normal, path, again, iv, NORMAL))["code"] == "replay"
    # Errors decided before authentication are sealed with the NORMAL key even for an edit request.
    r = editor.post("/plan", '{"id":0,"plan":null}', t=(editor.device_time() + 100_000) & 0xFFFFFFFF, role=EDIT, retry_stale=False)
    assert (r.status, r.code, r.authenticated) == (409, "stale_time", True) and editor.last_role == NORMAL
    assert abs(r.body["time"] - a._now_ms()) < 2000
    # a replayed edit request: authenticated with the edit keys, answered with the NORMAL keys (error decided at the cache)
    iv = b"Z" * 12
    envelope = editor.transport.seal_request("/plan", editor.device_time(), '{"id":0,"plan":null}', iv, EDIT)
    assert editor.post_raw("/plan", envelope).status == 200
    again = editor.post_raw("/plan", envelope)
    assert again.status == 409 and sealed_with(editor, "/plan", again, iv, NORMAL) is not None
    assert sealed_with(editor, "/plan", again, iv, EDIT) is None
    # a garbled "k" is a bad envelope, unauthenticated
    garbled = editor.transport.seal_request("/plan", editor.device_time(), "{}", b"G" * 12, EDIT).replace(b'"k":"e"', b'"k":"x"')
    r = editor.post_raw("/plan", garbled)
    assert r.status == 400 and r.json()["code"] == "bad_envelope" and b'"ct"' not in r.body
    # the edit key set never authorises normal paths, with any token
    assert editor.post_raw("/config", editor.transport.seal_request("/plan", 0, "{}", b"H" * 12, EDIT)).status == 400


def test_invalid_edit_token_never_opens_editing(component):
    for kwargs in ({"edit_token": "short"}, {"edit_token": EDIT_TOKEN, "edit_state": ec.EditState.INVALID},
                   {"edit_token": None, "edit_state": ec.EditState.INVALID}):
        a = component((("Laser", "Raum A"),), **kwargs)
        assert a.edit_state == ec.EditState.INVALID
        normal = Manager(a.listening_port).init()
        assert normal.security["edit"] == "invalid" and normal.security["writable"] is True
        # edit paths are closed to EVERYBODY (503), with the answer sealed with the normal keys
        for path, body in (("/plan", '{"id":0,"plan":null}'), ("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":{}}')):
            r = normal.post(path, body)
            assert (r.status, r.authenticated, r.code) == (503, True, "read_only"), (path, kwargs)
        editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
        r = editor.post("/plan", '{"id":0,"plan":null}', role=EDIT)
        assert (r.status, r.code) == (503, "read_only")
        assert a.store.count == 0
        # game operation stays available
        assert normal.post("/action", {"id": 0, "action": "x"}).status == 422
        assert normal.get_json("/status.json")["edit"] == "invalid"
        assert editor.edit_proof()[0].status == 404 and editor.edit_proof()[1] is None


def test_edit_proof_endpoint(component):
    a = component((("Laser", "Raum A"),), edit_token=EDIT_TOKEN)
    b = component((("Kamera", "Raum A"),))
    nonce = "0123456789abcdefghijklmnop"
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    response, doc = editor.edit_proof(nonce)
    assert response.status == 200 and doc == b'{"proto":2,"edit":"custom"}'
    assert response.headers["content-type"] == "application/json" and response.headers["cache-control"] == "no-store"
    assert response.body.startswith(b'{"doc":{"proto":2,"edit":"custom"},"mac":"') and response.body.endswith(b'"}')
    # byte-exact against the key schedule of the vectors' construction: HMAC(ek_mac, "EM2|eget|did|/edit.json|nonce|200|DOC")
    keys = ec.derive_keys(EDIT_TOKEN, edit=True)
    import hashlib
    import hmac
    mac = hmac.new(keys.mac, b"EM2|eget|%s|/edit.json|%s|200|{\"proto\":2,\"edit\":\"custom\"}" % (a.did.encode(), nonce.encode()),
                   hashlib.sha256).digest()
    assert response.body == b'{"doc":{"proto":2,"edit":"custom"},"mac":"%s"}' % ec.b64u_encode(mac).encode()
    # Only a holder of the SAME edit token can verify it; the normal token cannot, nor can another edit token.
    normal_only = Manager(a.listening_port).init()
    assert normal_only.edit_proof(nonce)[1] is None
    assert normal_only.transport.open_document_frame("/edit.json", nonce, 200, response.body) is None
    other = Manager(a.listening_port, edit_token="some-other-edit-token-1").init()
    assert other.edit_proof(nonce)[1] is None
    assert Manager(a.listening_port, edit_token=EDIT_TOKEN).init(did="112233445566").edit_proof(nonce)[1] is None  # bound to the did
    # a normal frame is no proof (and a proof is no normal frame)
    normal_frame = normal_only.get("/status.json", nonce=nonce)[0]
    assert editor.transport.open_edit_document_frame("/edit.json", nonce, 200, normal_frame.body) is None
    # A nonce is mandatory (no unauthenticated variant)
    for target in ("/edit.json", "/edit.json?nonce=short", "/edit.json?nonce=0123456789abcdef!", "/edit.json?nonce=",
                   "/edit.json?x=1"):
        r = get(a.listening_port, target)
        assert (r.status, r.json()["code"], r.json()["ok"]) == (400, "bad_request", False), target
    assert get(a.listening_port, "/edit.json?nonce=%zz").status == 400
    assert exchange(a.listening_port, b"HEAD /edit.json?nonce=" + nonce.encode() + b" HTTP/1.1\r\n\r\n").status == 200
    assert exchange(a.listening_port, b"POST /edit.json HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").status == 404   # GET only
    # A device without an edit token says so (unauthenticated, plain)
    for target in ("/edit.json?nonce=" + nonce, "/edit.json"):
        r = get(b.listening_port, target)
        assert (r.status, r.json()["code"]) == (404, "edit_unset") and b'"doc"' not in r.body


def test_device_without_edit_token_keeps_the_old_behaviour(component):
    a = component((("Laser", "Raum A"),))
    m = Manager(a.listening_port).init()
    assert a.edit_state == ec.EditState.UNSET and m.security["edit"] == "unset"
    assert m.post("/plan", '{"id":0,"plan":{"a":1}}').status == 200
    assert m.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":{"a":1}}').status == 200
    assert m.last_role == NORMAL and "emac" not in json.loads(a.store.get("Raum A"))
    # "k":"e" towards a device whose edit state is not custom fails authentication (401 auth_failed)
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    r = editor.post("/plan", '{"id":0,"plan":null}', role=EDIT)
    assert (r.status, r.authenticated, r.code) == (401, True, "auth_failed")
    assert editor.edit_proof()[0].status == 404
    # an empty edit token is "unset" too
    empty = component((("Laser", "Raum A"),), edit_token="")
    assert empty.edit_state == ec.EditState.UNSET and Manager(empty.listening_port).init().security["edit"] == "unset"


def test_edit_token_constructor_rules(component):
    assert ec.EscapeComponent(storage=ec.MemoryStorage(), local_ip="127.0.0.1").edit_state == ec.EditState.UNSET
    assert ec.EscapeComponent(storage=ec.MemoryStorage(), local_ip="127.0.0.1", edit_token=EDIT_TOKEN).edit_state == ec.EditState.CUSTOM
    assert ec.EscapeComponent(storage=ec.MemoryStorage(), local_ip="127.0.0.1", edit_token=EDIT_TOKEN,
                              edit_state=ec.EditState.UNSET).edit_state == ec.EditState.UNSET
    # nothing is derived before begin(); the transport reflects the usable state afterwards ("short" -> invalid)
    short = component((("L", "R"),), edit_token="short")
    assert short.edit_state == ec.EditState.INVALID and short.transport.edit_state == ec.EditState.INVALID
    assert short.token_state == ec.TokenState.CUSTOM
    # the edit token is independent of the normal one: a default-token device can have an edit token
    d = component((("L", "R"),), auth_token=None, edit_token=EDIT_TOKEN)
    assert d.token_state == ec.TokenState.DEFAULT and d.edit_state == ec.EditState.CUSTOM
    m = Manager(d.listening_port, ec.AUTH_TOKEN_DEFAULT, edit_token=EDIT_TOKEN).init()
    assert m.post("/plan", '{"id":0,"plan":{"a":1}}', role=EDIT).status == 200
    assert Manager(d.listening_port, ec.AUTH_TOKEN_DEFAULT).init().post("/plan", '{"id":0,"plan":null}').code == "edit_required"
    # tokens are runtime configuration (like auth_token): nothing about them is persisted
    storage = ec.MemoryStorage()
    e = component((("L", "R"),), storage=storage, edit_token=EDIT_TOKEN, auth_token="a-normal-token-for-this-test")
    Manager(e.listening_port, "a-normal-token-for-this-test", edit_token=EDIT_TOKEN).init().post(
        "/plan-skeleton", '{"room":"R","baseRev":0,"sk":{"a":1}}', role=EDIT)
    assert storage.key_count() > 0
    assert all(EDIT_TOKEN.encode() not in value and b"a-normal-token" not in value for value in storage._data.values())


# ---- POST /setup (PROTOCOL.md 5.8; mirrors test_setup_push_* in test/test_net/test_device.cpp) -------------------------------

def test_setup_push_over_the_network(component):
    sink = RecordingSink()
    a = component((("Laser", "Raum A"),), setup_sink=sink)
    b = component((("Kamera", "Raum B"),))
    m = Manager(a.listening_port).init()
    sec = get(a.listening_port, "/security.json").json()
    assert sec["caps"] == ["plan", "cfg", "edit", "setup"] and sec["setupAp"] == "open"          # advertised only with a sink
    sec_b = get(b.listening_port, "/security.json").json()
    assert "setup" not in sec_b["caps"] and sec_b["setupAp"] == "none"

    r = m.post("/setup", '{"ssid":"Heimnetz","pass":"geheimgeheim"}')
    assert (r.status, r.body, r.authenticated) == (200, {"ok": True}, True)
    assert sink.applied == 1 and sink.via_network is True                                         # the old Wi-Fi stays as fallback
    assert (sink.last.has_wifi, sink.last.ssid, sink.last.pass_) == (True, "Heimnetz", "geheimgeheim")
    assert not sink.last.has_token and not sink.last.has_edit_token
    # Invalid requests change nothing (and are authenticated 400s).
    for body in ('{"ssid":"x"}', '{"token":"short"}', '{"ssid":"EscapeSetup-aaaaaaaaaaaa","pass":""}', "{}", "[]", "broken",
                 '{"editToken":5}', '{"ssid":"Netz","pass":"short"}'):
        r = m.post("/setup", body)
        assert (r.status, r.code, r.authenticated) == (400, "bad_request", True), body
    assert sink.applied == 1
    r = m.post("/setup", " " * 1100)
    assert (r.status, r.code) == (400, "bad_request") and sink.applied == 1
    # The unauthenticated routes: GET /setup does not exist; a device without a sink does not know POST /setup at all
    assert get(a.listening_port, "/setup").status == 404
    forb = Manager(b.listening_port).init()
    envelope = forb.transport.seal_request("/setup", forb.device_time(), '{"token":"a-brand-new-token-1"}')
    r = forb.post_raw("/setup", envelope)
    assert r.status == 404 and r.json()["code"] == "not_found" and b'"ct"' not in r.body
    assert exchange(b.listening_port, b"POST /setup HTTP/1.1\r\nContent-Length: 999999\r\n\r\n").status == 404

    # A token change is answered with the OLD keys, then the device runs with the new ones.
    iv = b"S" * 12
    envelope = m.transport.seal_request("/setup", m.device_time(), '{"token":"a-brand-new-token-1"}', iv)
    response = m.post_raw("/setup", envelope)
    assert response.status == 200
    assert m.transport.open_response("/setup", ec.b64u_encode(iv), 200, response.body) == b'{"ok":true}'
    r = m.post("/action", {"id": 0, "action": "open"})
    assert (r.status, r.authenticated) == (401, False)                                            # the old token is gone
    renewed = Manager(a.listening_port, "a-brand-new-token-1").init()
    assert renewed.post("/action", {"id": 0, "action": "open"}).status == 422                      # authenticated, no handler
    assert renewed.get_json("/status.json")["token"] == "custom" and a.token_state == ec.TokenState.CUSTOM
    assert sink.tokens.token == "a-brand-new-token-1" and sink.applied == 2
    assert renewed.post("/setup", '{"ssid":"Zweitnetz","pass":""}').status == 200 and sink.last.pass_ == ""
    # removing the token (""): the public default applies again
    r = renewed.post("/setup", '{"token":""}')
    assert r.status == 200
    assert a.token_state == ec.TokenState.DEFAULT
    assert get(a.listening_port, "/security.json").json()["token"] == "default"
    default = Manager(a.listening_port, ec.AUTH_TOKEN_DEFAULT).init()
    assert default.post("/action", {"id": 0, "action": "x"}).status == 422


def test_setup_push_needs_the_edit_token_when_there_is_one(component):
    sink = RecordingSink(edit_token=EDIT_TOKEN)
    a = component((("Laser", "Raum A"),), edit_token=EDIT_TOKEN, setup_sink=sink)
    normal = Manager(a.listening_port).init()
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    r = normal.post("/setup", '{"ssid":"Heimnetz","pass":"geheimgeheim"}')
    assert (r.status, r.authenticated, r.code) == (403, True, "edit_required") and sink.applied == 0
    r = editor.post("/setup", '{"editToken":"a-second-edit-token-2"}', role=EDIT)
    assert (r.status, r.body, editor.last_role) == (200, {"ok": True}, EDIT)                       # answered with the OLD edit keys
    assert sink.applied == 1 and sink.last.edit_token == "a-second-edit-token-2"
    # The edit token changed: the old edit keys are dead, the new ones work.
    r = editor.post("/plan", '{"id":0,"plan":null}', role=EDIT)
    assert (r.status, r.code) == (401, "auth_failed")
    renewed = Manager(a.listening_port, edit_token="a-second-edit-token-2").init()
    assert renewed.post("/plan", '{"id":0,"plan":{"q":1}}', role=EDIT).status == 200
    assert a.edit_state == ec.EditState.CUSTOM and renewed.edit_proof()[1] == b'{"proto":2,"edit":"custom"}'
    assert editor.edit_proof()[1] is None                                                         # the old token cannot prove anything
    # Changing the NORMAL token through the edit path keeps the edit token
    r = renewed.post("/setup", '{"token":"a-brand-new-token-1"}', role=EDIT)
    assert r.status == 200
    again = Manager(a.listening_port, "a-brand-new-token-1", edit_token="a-second-edit-token-2").init()
    assert again.post("/plan", '{"id":0,"plan":null}', role=EDIT).status == 200
    assert normal.post("/action", {"id": 0, "action": "x"}).authenticated is False
    # Removing the edit token ("") hands plan sending back to the normal token.
    r = again.post("/setup", '{"editToken":""}', role=EDIT)
    assert r.status == 200 and a.edit_state == ec.EditState.UNSET
    assert get(a.listening_port, "/security.json").json()["edit"] == "unset"
    plain = Manager(a.listening_port, "a-brand-new-token-1").init()
    assert plain.post("/plan", '{"id":0,"plan":{"z":3}}').status == 200
    assert a._components[0].plan == '{"z":3}'
    assert plain.edit_proof()[0].status == 404


def test_setup_can_introduce_an_edit_token_and_stamps_later_writes(component):
    sink = RecordingSink()
    a = component((("Laser", "Raum A"),), setup_sink=sink)
    m = Manager(a.listening_port).init()
    sk = '{"planId":"p1"}'
    assert m.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % sk).status == 200
    assert "emac" not in json.loads(a.store.get("Raum A"))                      # stored before the edit token existed
    assert m.post("/setup", '{"editToken":"a-brand-new-edit-1"}').status == 200  # the normal token may do it (edit unset)
    assert a.edit_state == ec.EditState.CUSTOM and a.transport.signing_enabled
    assert m.post("/plan", '{"id":0,"plan":null}').code == "edit_required"       # ... and is out of the game afterwards
    editor = Manager(a.listening_port, edit_token="a-brand-new-edit-1").init()
    # re-sending the SAME content with the edit token stamps the stored skeleton without a new revision
    r = editor.post("/plan-skeleton", '{"room":"Raum A","baseRev":1,"sk":%s}' % sk, role=EDIT)
    assert (r.status, r.body["rev"]) == (200, 1) and a.store.find("Raum A").rev == 1
    blob = json.loads(a.store.get("Raum A"))
    assert a.transport.verify_skeleton("Raum A", 1, ec.fnv1a32(sk), blob["emac"])
    assert editor.get_json("/status.json")["edit"] == "custom"


def test_setup_reload_with_unusual_sink_answers(component):
    # a sink that reports "default token" without text: the public default applies (never an unusable read-only device)
    class EmptyDefault(RecordingSink):
        def current_tokens(self):
            return ec.SetupTokens()

    a = component((("Laser", "Raum A"),), setup_sink=EmptyDefault())
    assert Manager(a.listening_port).init().post("/setup", '{"token":"a-brand-new-token-1"}').status == 200
    assert a.token_state == ec.TokenState.DEFAULT and a.transport.writable and a.edit_state == ec.EditState.UNSET
    assert Manager(a.listening_port, ec.AUTH_TOKEN_DEFAULT).init().post("/action", {"id": 0, "action": "x"}).status == 422

    # a sink that hands out an unusable edit token: edit paths close (503), the game stays available
    class BadEdit(RecordingSink):
        def current_tokens(self):
            return ec.SetupTokens(self.tokens.token, ec.TokenState.CUSTOM, "short", ec.EditState.CUSTOM)

    b = component((("Laser", "Raum A"),), setup_sink=BadEdit())
    m = Manager(b.listening_port).init()
    assert m.post("/setup", '{"editToken":"whatever-edit-token"}').status == 200
    assert b.edit_state == ec.EditState.INVALID and b.transport.writable
    assert m.post("/plan", '{"id":0,"plan":null}').code == "read_only"
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422

    # a failing sink never changes the keys: authenticated 500, the old token still works
    class Failing(RecordingSink):
        def apply_setup(self, change, via_network):
            raise RuntimeError("disk on fire")

    c = component((("Laser", "Raum A"),), setup_sink=Failing())
    m = Manager(c.listening_port).init()
    r = m.post("/setup", '{"token":"a-brand-new-token-1"}')
    assert (r.status, r.authenticated, r.code) == (500, True, "internal_error")
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422

    # a sink that cannot tell the new tokens afterwards: the sealed answer still reaches the caller, the old keys stay
    class Mute(RecordingSink):
        def current_tokens(self):
            raise RuntimeError("no idea")

    e = component((("Laser", "Raum A"),), setup_sink=Mute())
    m = Manager(e.listening_port).init()
    r = m.post("/setup", '{"token":"a-brand-new-token-1"}')
    assert (r.status, r.authenticated, r.body) == (200, True, {"ok": True})
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422

    # storage trouble and a rejection by the sink are reported; nothing is re-derived
    sink = RecordingSink()
    d = component((("Laser", "Raum A"),), setup_sink=sink)
    m = Manager(d.listening_port).init()
    sink.result = ec.SetupResult.STORAGE
    r = m.post("/setup", '{"token":"a-brand-new-token-1"}')
    assert (r.status, r.code) == (500, "storage_full") and m.post("/action", {"id": 0, "action": "x"}).status == 422
    sink.result = ec.SetupResult.INVALID
    assert m.post("/setup", '{"token":"a-brand-new-token-1"}').code == "bad_request"
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422


def test_setup_sink_that_reports_a_strange_ap_mode_is_published_as_none(component):
    sink = RecordingSink(ap_mode='wpa2"},"evil":{"x')
    a = component((("Laser", "Raum A"),), setup_sink=sink)
    sec = get(a.listening_port, "/security.json").json()
    assert sec["setupAp"] == "none" and "evil" not in sec and "setup" in sec["caps"]
    sink.ap_mode = "wpa2"
    assert get(a.listening_port, "/security.json").json()["setupAp"] == "wpa2"
    sink.ap_mode = None                                   # type: ignore[assignment]
    assert get(a.listening_port, "/security.json").json()["setupAp"] == "none"


def test_setup_replay_cache_is_cleared_by_a_token_change(component):
    sink = RecordingSink()
    a = component((("Laser", "Raum A"),), setup_sink=sink)
    m = Manager(a.listening_port).init()
    envelope = m.transport.seal_request("/action", m.device_time(), '{"id":0,"action":"x"}', b"A" * 12)
    assert m.post_raw("/action", envelope).status == 422
    assert a.transport.replay_entries(a._now_ms()) == 1
    assert m.post("/setup", '{"token":"a-brand-new-token-1"}').status == 200
    assert a.transport.replay_entries(a._now_ms()) == 0                                           # begin() starts a fresh cache
    assert m.post_raw("/action", envelope).status == 401                                          # and the old keys are dead
