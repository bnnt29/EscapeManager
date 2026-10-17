"""The HTTP server and the secure endpoints end to end, plus hostile-input hardening."""

from __future__ import annotations

import gzip
import hashlib
import json
import random
import socket
import threading
import time

import pytest

import escape_component as ec
import helpers
from helpers import Manager, exchange, get, parse_http, read_all


def connect(port):
    return socket.create_connection(("127.0.0.1", port), timeout=5)


# ---- documents over HTTP --------------------------------------------------------------------------------------

def test_security_json_and_response_headers(component):
    c = component()
    r = get(c.listening_port, "/security.json")
    assert r.status == 200
    assert r.headers["content-type"] == "application/json"
    assert r.headers["connection"] == "close"
    assert int(r.headers["content-length"]) == len(r.body)
    assert r.headers["cache-control"] == "no-store"
    doc = r.json()
    assert doc["proto"] == 2 and doc["pmin"] == 2 and doc["did"] == c.did and doc["token"] == "custom"
    assert doc["writable"] is True and doc["kdf"]["iter"] == 2048 and doc["limits"]["body"] == 12288
    assert isinstance(doc["time"], int)


def test_authenticated_get_frames_and_viewer_mode(component):
    c = component((("Laser", "Raum A"), ("Kamera", "Raum A")))
    c.on_battery(lambda: 61)
    m = Manager(c.listening_port).init()
    status = m.get_json("/status.json")
    assert status["battery"] == 61 and status["did"] == c.did and len(status["components"]) == 2
    assert status["components"][0]["uuid"] == c.did + "-0" and status["components"][0]["riddleId"].startswith("riddle-")
    assert m.get_json("/peers.json")["self"]["did"] == c.did
    assert m.get_json("/plan-skeleton.json") == {"proto": 2, "rooms": []}
    response, doc = m.get("/plan-skeleton.json", "room=Raum%20A")
    assert response.status == 404 and doc is not None and json.loads(doc)["code"] == "no_plan"
    # a client with the wrong token cannot verify the frame
    wrong = Manager(c.listening_port, token="another-token-value-xyz").init(did=c.did)
    response, doc = wrong.get("/status.json")
    assert response.status == 200 and doc is None
    # viewer mode (no nonce) returns the bare document; a bad nonce is refused
    r = get(c.listening_port, "/status.json")
    assert r.status == 200 and r.body.startswith(b'{"proto":2,') and r.json()["did"] == c.did
    assert get(c.listening_port, "/status.json?nonce=short").status == 400
    assert get(c.listening_port, "/status.json?nonce=0123456789abcdef!").status == 400
    assert get(c.listening_port, "/status.json?nonce=%zz").status == 200       # undecodable query: treated as no nonce


def test_frame_is_byte_exact_on_the_wire(component):
    c = component()
    nonce = "0123456789abcdefGHIJ_-"
    r = get(c.listening_port, "/security.json?nonce=" + nonce)
    assert r.body.startswith(b'{"proto":2')                  # /security.json is never framed
    r = get(c.listening_port, "/status.json?nonce=" + nonce)
    tail = r.body.rindex(b',"mac":"')
    assert r.body.startswith(b'{"doc":{"proto":2,') and r.body.endswith(b'"}')
    doc = r.body[7:tail]
    mac = ec.b64u_decode(r.body[tail + 8:-2])
    import hmac
    key = ec.derive_keys(helpers.TEST_TOKEN).mac
    expected = hmac.new(key, ("EM2|get|%s|/status.json|%s|200|" % (c.did, nonce)).encode() + doc, hashlib.sha256).digest()
    assert mac == expected                                   # exactly the documented construction
    assert json.loads(doc)["did"] == c.did


def test_status_reflects_callbacks_and_sim_style_components(component):
    c = component((("Laser", "Raum A"),))
    c.on_errors(0, lambda: ["e1", "e2"])
    c.on_actions(0, lambda: ["reset", "open"])
    c.on_tip(0, lambda: "Tipp")
    c.on_feed(0, lambda: "https://cam/stream")
    c.on_puzzle(0, lambda: (1, 4, "<b>x</b>", True))
    c.on_custom_config(0, lambda: [ec.CustomConfigDef("b", "range", "5", 0, 9)])
    c.on_plan_action(0, lambda a: True)
    m = Manager(c.listening_port).init()
    comp = m.get_json("/status.json")["components"][0]
    assert comp["errors"] == ["e1", "e2"] and comp["actions"] == ["reset", "open"] and comp["tip"] == "Tipp"
    assert comp["feed"] == "https://cam/stream" and comp["puzzle"] == {"step": 1, "totalSteps": 4, "state": "<b>x</b>", "isHtml": True}
    assert comp["customConfig"] == [{"key": "b", "type": "range", "min": 0, "max": 9, "value": "5"}]
    assert comp["planActions"] == ["reset", "complete"]


def test_throwing_callbacks_never_break_the_status(component):
    c = component()
    def boom():
        raise RuntimeError("sensor exploded")
    c.on_errors(0, boom); c.on_tip(0, boom); c.on_puzzle(0, boom); c.on_battery(boom); c.on_custom_config(0, boom)
    r = get(c.listening_port, "/status.json")
    assert r.status == 200 and r.json()["components"][0]["name"] == "Laser"
    c.on_action(0, boom)
    m = Manager(c.listening_port).init()
    result = m.post("/action", {"id": 0, "action": "x"})
    assert result.status == 422 and result.code == "rejected"                 # a raising handler is just a rejected action


def test_ui_is_served_with_etag_and_304(component):
    html = "<html><body>Manager ä</body></html>"
    c = component(manager_html=html)
    r = get(c.listening_port, "/")
    assert r.status == 200 and r.headers["content-encoding"] == "gzip" and r.headers["content-type"].startswith("text/html")
    assert r.headers["etag"] == '"%s"' % c.ui_hash and r.headers["cache-control"] == "no-cache"
    assert gzip.decompress(r.body).decode() == html
    assert hashlib.sha256(gzip.decompress(r.body)).hexdigest()[:8] == c.ui_hash == json.loads(c.security_json())["uih"]
    r2 = get(c.listening_port, "/", 'If-None-Match: "%s"\r\n' % c.ui_hash)
    assert r2.status == 304 and r2.body == b"" and r2.headers["etag"] == '"%s"' % c.ui_hash
    assert get(c.listening_port, "/", 'If-None-Match: W/"%s"\r\n' % c.ui_hash).status == 304
    assert get(c.listening_port, "/", 'If-None-Match: "deadbeef"\r\n').status == 200
    head = exchange(c.listening_port, b"HEAD / HTTP/1.1\r\n\r\n")
    assert head.status == 200 and head.body == b"" and int(head.headers["content-length"]) == len(r.body)
    # a pre-gzipped UI is served as is, the hash is over the uncompressed document
    c2 = component(manager_html=gzip.compress(html.encode()))
    assert c2.ui_hash == c.ui_hash
    assert get(c2.listening_port, "/").body == get(c2.listening_port, "/").body
    c3 = component()
    assert get(c3.listening_port, "/").status == 404 and c3.ui_hash == "00000000"
    assert get(c3.listening_port, "/favicon.ico").status == 204


def test_routes_methods_and_status_codes(component):
    c = component()
    p = c.listening_port
    assert get(p, "/nope").status == 404 and get(p, "/nope").json()["code"] == "not_found"
    assert exchange(p, b"POST /status.json HTTP/1.1\r\nContent-Length: 1\r\n\r\nx").status == 404        # wrong method
    assert exchange(p, b"GET /action HTTP/1.1\r\n\r\n").status == 404
    assert exchange(p, b"BREW /x HTTP/1.1\r\n\r\n").status == 405
    assert exchange(p, b"DELETE /status.json HTTP/1.1\r\n\r\n").status == 405
    assert exchange(p, b"GET / HTTP/9.9\r\n\r\n").status == 505
    assert exchange(p, b"garbage\r\n\r\n").status == 400
    assert exchange(p, b"GET /" + b"a" * 600 + b" HTTP/1.1\r\n\r\n").status == 414
    assert exchange(p, b"GET / HTTP/1.1\r\nX: " + b"a" * 1100 + b"\r\n\r\n").status == 431
    assert exchange(p, b"POST /action HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n").status == 501
    assert exchange(p, b"GET /status.json HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd").status == 400       # GET with a body
    r = exchange(p, b"HEAD /security.json HTTP/1.1\r\n\r\n")
    assert r.status == 200 and r.body == b"" and int(r.headers["content-length"]) > 100
    r = exchange(p, b"HEAD /nope HTTP/1.1\r\n\r\n")
    assert r.status == 404 and r.body == b""
    r = exchange(p, b"GET /status.json?x=1 HTTP/1.0\r\n\r\n")
    assert r.status == 200 and r.headers["connection"] == "close"
    for bad in (get(p, "/nope"), exchange(p, b"BREW / HTTP/1.1\r\n\r\n")):
        assert int(bad.headers["content-length"]) == len(bad.body) and bad.json()["ok"] is False


def test_header_limit_is_exactly_1024_bytes(component):
    c = component()
    base = b"GET /security.json HTTP/1.1\r\nX: "
    fill = 1024 - len(base) - 4                                   # head incl. the blank line: exactly 1024 bytes
    assert exchange(c.listening_port, base + b"a" * fill + b"\r\n\r\n").status == 200
    assert exchange(c.listening_port, base + b"a" * (fill + 1) + b"\r\n\r\n").status == 431
    r = exchange(c.listening_port, b"GET /security.json HTTP/1.1\r\nX: " + b"a" * 100_000)      # unbounded header never accepted
    assert r.status == 431


def test_cors_and_preflight(component):
    c = component()
    p = c.listening_port
    r = exchange(p, b"OPTIONS /action HTTP/1.1\r\nOrigin: http://escapemanager.local\r\n\r\n")
    assert r.status == 204 and r.body == b"" and r.headers["access-control-allow-origin"] == "http://escapemanager.local"
    assert r.headers["access-control-allow-methods"] == "GET, POST, OPTIONS" and r.headers["vary"] == "Origin"
    assert r.headers["content-length"] == "0"
    assert "access-control-allow-origin" not in exchange(p, b"OPTIONS /action HTTP/1.1\r\nOrigin: http://evil.example\r\n\r\n").headers
    assert "access-control-allow-origin" not in exchange(p, b"OPTIONS /action HTTP/1.1\r\n\r\n").headers      # no Origin: served
    assert exchange(p, b"OPTIONS /anything HTTP/1.1\r\nOrigin: null\r\n\r\n").status == 204
    r = get(p, "/status.json", "Origin: http://192.168.1.5:3000\r\n")
    assert r.headers["access-control-allow-origin"] == "http://192.168.1.5:3000"
    assert "access-control-allow-origin" not in get(p, "/status.json", "Origin: https://evil.example\r\n").headers
    assert get(p, "/status.json", "Origin: https://evil.example\r\n").status == 200    # still served
    # errors carry CORS headers too, so a browser can read them
    r = get(p, "/nope", "Origin: http://localhost:8080\r\n")
    assert r.status == 404 and r.headers["access-control-allow-origin"] == "http://localhost:8080"


# ---- body limits, malformed lengths ------------------------------------------------------------------------------------

def test_oversized_body_is_refused_from_content_length_alone(component):
    c = component()
    p = c.listening_port
    before = c.seq
    for length in (12289, 100_000, 2_000_000_000):
        t0 = time.monotonic()
        with connect(p) as s:
            s.sendall(("POST /action HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % length).encode())   # NOT a single body byte
            r = parse_http(read_all(s, 3))
        assert r.status == 413, length
        assert r.json()["code"] == "too_large"
        assert time.monotonic() - t0 < 2.0, "answered only after waiting for the body"
    assert c.seq == before and c.transport.replay_entries(c._now_ms()) == 0
    assert exchange(p, b"POST /action HTTP/1.1\r\nContent-Length: 2147483648\r\n\r\n").status == 413
    assert exchange(p, b"POST /action HTTP/1.1\r\nContent-Length: 99999999999\r\n\r\n").status == 400


@pytest.mark.parametrize("value", ["-1", "-5", "abc", "", "1.5", "0x10", "+5", "1 2", "12345678901", "٣", "5,5", "5;"])
def test_garbage_content_length_is_400(component, value):
    c = component()
    r = exchange(c.listening_port, ("POST /action HTTP/1.1\r\nContent-Length: %s\r\n\r\n" % value).encode("utf-8"))
    assert r.status == 400 and r.json()["code"] == "bad_request"


def test_duplicate_conflicting_content_length_is_400(component):
    c = component()
    r = exchange(c.listening_port, b"POST /action HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
    assert r.status == 400


def test_post_without_body_or_with_junk_body_is_bad_envelope(component):
    c = component()
    p = c.listening_port
    r = exchange(p, b"POST /action HTTP/1.1\r\n\r\n")
    assert r.status == 400 and r.json()["code"] == "bad_envelope"
    r = exchange(p, b"POST /action HTTP/1.1\r\nContent-Length: 4\r\n\r\njunk")      # extra bytes beyond Content-Length are ignored
    assert r.status == 400 and r.json()["code"] == "bad_envelope"


def test_body_at_the_limit_is_read_completely(component):
    c = component()
    envelope = b'{"v":2,"t":1,"iv":"AAECAwQFBgcICQoL","ct":"' + b"A" * (12288 - 46) + b'"}'
    envelope += b" " * (12288 - len(envelope))
    assert len(envelope) == 12288
    r = exchange(c.listening_port, b"POST /action HTTP/1.1\r\nContent-Length: 12288\r\n\r\n" + envelope)
    assert r.status in (400, 409, 401)                                         # read in full and looked at
    assert r.json().get("code") != "too_large"


def test_early_rejection_is_delivered_even_while_the_client_keeps_sending(component):
    c = component()
    with connect(c.listening_port) as s:
        s.sendall(b"POST /nope HTTP/1.1\r\nContent-Length: 60000\r\n\r\n")
        sent = 0
        s.settimeout(0.5)
        for _ in range(60):
            try:
                s.sendall(b"x" * 1000)
                sent += 1000
            except OSError:
                break
        r = parse_http(read_all(s, 3))
    assert r.status == 404 and r.json()["code"] == "not_found"
    assert sent > 0


def test_expect_100_continue(component):
    c = component()
    m = Manager(c.listening_port).init()
    envelope = m.transport.seal_request("/action", m.device_time(), '{"id":0,"action":"x"}')
    with connect(c.listening_port) as s:
        s.sendall(b"POST /action HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: %d\r\n\r\n" % len(envelope))
        s.settimeout(3)
        assert s.recv(1024).startswith(b"HTTP/1.1 100 Continue\r\n\r\n")
        s.sendall(envelope)
        r = parse_http(read_all(s, 3))
    assert r.status == 422 and b'"ct"' in r.body                              # authenticated answer: no action handler -> rejected
    # no 100 for requests that are refused before the body
    with connect(c.listening_port) as s:
        s.sendall(b"POST /action HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 99999\r\n\r\n")
        data = read_all(s, 3)
    assert data.startswith(b"HTTP/1.1 413") and b"100 Continue" not in data


# ---- slow clients, connection limits ---------------------------------------------------------------------------------------

def test_default_timeouts_are_the_documented_ones():
    assert ec.EscapeConfig.HTTP_IDLE_TIMEOUT_MS == 5000 and ec.EscapeConfig.HTTP_REQUEST_TIMEOUT_MS == 10000
    assert ec.EscapeConfig.MAX_HTTP_CONNECTIONS <= 8 and ec.EscapeConfig.MAX_HEADER_BYTES == 1024
    server = ec.HttpServer(None, 0)  # type: ignore[arg-type]
    assert (server.idle_timeout, server.request_timeout, server.max_connections) == (5.0, 10.0, 8)


def test_idle_client_is_dropped_after_the_idle_timeout(component):
    c = component(http_idle_timeout=0.6, http_request_timeout=5.0)
    t0 = time.monotonic()
    with connect(c.listening_port) as s:
        data = read_all(s, 4)                   # sends nothing at all
    assert data == b"" and 0.5 < time.monotonic() - t0 < 2.5
    with connect(c.listening_port) as s:
        s.sendall(b"GET /sec")                  # stops in the middle of the request line
        t0 = time.monotonic()
        assert read_all(s, 4) == b"" and time.monotonic() - t0 < 2.5
    assert wait_idle(c)


def test_slowloris_is_dropped_after_the_request_timeout(component):
    c = component(http_idle_timeout=1.0, http_request_timeout=2.0)
    t0 = time.monotonic()
    with connect(c.listening_port) as s:
        s.settimeout(0.2)
        closed_at = None
        for i in range(40):                     # one byte per 0.4 s: never idle for long, never done
            try:
                s.sendall(b"G" if i == 0 else b"E")
            except OSError:
                closed_at = time.monotonic() - t0
                break
            try:
                if s.recv(1) == b"":
                    closed_at = time.monotonic() - t0
                    break
            except socket.timeout:
                pass
            except OSError:
                closed_at = time.monotonic() - t0
                break
            time.sleep(0.2)
    assert closed_at is not None and closed_at < 4.0
    assert wait_idle(c)


def test_slow_reader_of_a_response_is_dropped(component):
    c = component(http_idle_timeout=1.0, http_request_timeout=2.0, manager_html="x" * 4_000_000)
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
    s.connect(("127.0.0.1", c.listening_port))
    s.sendall(b"GET / HTTP/1.1\r\n\r\n")        # incompressible-ish big body, then never read
    assert wait_idle(c, 8), "the server kept the connection although nobody reads the response"
    s.close()


def wait_idle(c, timeout=6.0):
    return helpers.wait_for(lambda: c._server.active_connections == 0, timeout)


def test_connection_limit_and_recovery(component):
    c = component(http_idle_timeout=30.0, http_request_timeout=60.0)
    held = [connect(c.listening_port) for _ in range(ec.EscapeConfig.MAX_HTTP_CONNECTIONS)]
    assert helpers.wait_for(lambda: c._server.active_connections == ec.EscapeConfig.MAX_HTTP_CONNECTIONS)
    with connect(c.listening_port) as extra:
        busy = read_all(extra, 3)
    assert busy.startswith(b"HTTP/1.1 503") and b"Retry-After" in busy
    assert c._server.active_connections == ec.EscapeConfig.MAX_HTTP_CONNECTIONS      # still bounded
    for s in held:
        s.close()
    assert helpers.wait_for(lambda: c._server.active_connections == 0)
    assert get(c.listening_port, "/security.json").status == 200


def test_many_parallel_clients_are_all_served(component):
    c = component()
    results = []
    def worker():
        for _ in range(5):
            results.append(get(c.listening_port, "/status.json").status)
    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads: t.start()
    for t in threads: t.join()
    assert results.count(200) >= 25                                                  # a busy server may answer 503, never hang
    assert set(results) <= {200, 503}


# ---- every exception becomes a JSON 500 ------------------------------------------------------------------------------------------

def test_handler_exception_is_a_json_500_and_the_server_survives(component, monkeypatch):
    c = component()
    def explode(*_a, **_k):
        raise RuntimeError("boom")
    monkeypatch.setattr(c, "_handle_get", explode)
    r = get(c.listening_port, "/status.json")
    assert r.status == 500 and r.json() == {"ok": False, "code": "internal_error", "error": "internal error"}
    assert int(r.headers["content-length"]) == len(r.body) and r.headers["connection"] == "close"
    monkeypatch.undo()
    assert get(c.listening_port, "/status.json").status == 200


def test_post_handler_exception_is_an_authenticated_500(component, monkeypatch):
    c = component()
    m = Manager(c.listening_port).init()
    monkeypatch.setattr(c, "_dispatch", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("boom")))
    result = m.post("/action", {"id": 0, "action": "x"})
    assert result.status == 500 and result.authenticated and result.body["code"] == "internal_error"
    monkeypatch.undo()
    assert m.post("/action", {"id": 0, "action": "x"}).status == 422


def test_route_exception_does_not_drop_the_connection(component, monkeypatch):
    c = component()
    monkeypatch.setattr(c._http_handler, "route", lambda *_a: (_ for _ in ()).throw(ValueError("x")))
    r = get(c.listening_port, "/status.json")
    assert r.status == 500 and r.json()["code"] == "internal_error"      # even a failing router answers with a JSON 500
    monkeypatch.undo()
    assert get(c.listening_port, "/status.json").status == 200
    assert wait_idle(c)


# ---- secure POST end to end -----------------------------------------------------------------------------------------------------

def test_secure_post_flow(component):
    c = component((("Laser", "Raum A"),))
    done = []
    c.on_action(0, lambda a: done.append(a) or a == "open")
    m = Manager(c.listening_port).init()
    seq = c.seq
    r = m.post("/action", {"id": 0, "action": "open"})
    assert (r.status, r.authenticated, r.body) == (200, True, {"ok": True})
    assert done == ["open"] and c.seq > seq
    r = m.post("/action", {"id": 0, "action": "nope"})
    assert (r.status, r.body["code"]) == (422, "rejected")
    r = m.post("/action", {"id": 5, "action": "open"})
    assert (r.status, r.body["code"]) == (400, "bad_id")
    r = m.post("/plan-action", {"id": 0, "action": "reset"})
    assert (r.status, r.body["code"]) == (422, "unsupported")
    # status shows the event log
    comp = m.get_json("/status.json")["components"][0]
    assert comp["evtSeq"] >= 1 and "open" in comp["evtMsg"]


def test_stale_time_is_authenticated_and_carries_the_device_clock(component):
    c = component()
    m = Manager(c.listening_port).init()
    r = m.post("/action", {"id": 0, "action": "x"}, t=(m.device_time() + 100_000) & 0xFFFFFFFF)
    assert r.status == 409 and r.authenticated and r.body["code"] == "stale_time"
    assert abs(r.body["time"] - c._now_ms()) < 2000
    r = m.post("/action", {"id": 0, "action": "x"}, t=(m.device_time() - 20_000) & 0xFFFFFFFF)
    assert r.status == 409 and r.body["code"] == "stale_time"
    # the manager re-synchronises from `time` and retries once
    m.offset += 500_000
    r = m.post("/action", {"id": 0, "action": "x"})
    assert r.status == 422 and r.authenticated


def test_replay_is_rejected_authenticated(component):
    c = component()
    m = Manager(c.listening_port).init()
    envelope = m.transport.seal_request("/action", m.device_time(), '{"id":0,"action":"x"}', b"A" * 12)
    first = m.post_raw("/action", envelope)
    again = m.post_raw("/action", envelope)
    assert first.status == 422 and again.status == 409
    plain = m.transport.open_response("/action", ec.b64u_encode(b"A" * 12), 409, again.body)
    assert json.loads(plain)["code"] == "replay"


def test_wrong_token_path_and_device_id(component):
    c = component()
    other = component()
    good = Manager(c.listening_port).init()
    wrong_token = Manager(c.listening_port, token="another-token-value-xyz").init(did=c.did)
    r = wrong_token.post("/action", {"id": 0, "action": "x"})
    # the 401 is sealed with the DEVICE's response key (the IV was readable), so a wrong-token client cannot open it
    assert r.status == 401 and not r.authenticated and b'"ct"' in r.response.body
    # an envelope for another device id (same token) is useless against this one
    for_other = Manager(other.listening_port).init()
    envelope = for_other.transport.seal_request("/action", good.device_time(), '{"id":0,"action":"x"}')
    r = good.post_raw("/action", envelope)
    assert r.status == 401
    # an envelope sealed for /action cannot be moved to /config
    envelope = good.transport.seal_request("/action", good.device_time(), '{"id":0,"action":"x"}')
    assert good.post_raw("/config", envelope).status == 401
    assert c.transport.replay_entries(c._now_ms()) == 0           # nothing entered the replay cache
    assert good.post("/action", {"id": 0, "action": "x"}).status == 422


def test_read_only_device_refuses_writes_but_serves_reads(component):
    c = component(token_state=ec.TokenState.INVALID, auth_token=None)
    m = Manager(c.listening_port).init()
    assert m.security["token"] == "invalid" and m.security["writable"] is False
    envelope = ec.SecureTransport()
    envelope.begin(helpers.TEST_TOKEN, ec.TokenState.CUSTOM, c.did)
    body = envelope.seal_request("/action", m.device_time(), '{"id":0,"action":"x"}')
    r = exchange(c.listening_port, b"POST /action HTTP/1.1\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    assert r.status == 503 and r.json()["code"] == "read_only" and b'"ct"' not in r.body
    assert get(c.listening_port, "/status.json").status == 200                 # viewer mode still works
    assert get(c.listening_port, "/status.json?nonce=0123456789abcdef").status == 503   # frames need a key


def test_rate_limit_answers_429_unauthenticated(component):
    c = component()
    codes = []
    for _ in range(20):
        r = exchange(c.listening_port, b"POST /action HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}")
        codes.append((r.status, r.json()["code"]))
    assert codes[0] == (400, "bad_envelope")
    assert (429, "rate_limited") in codes
    assert codes.index((429, "rate_limited")) <= ec.EscapeConfig.RATE_BURST + 1
    time.sleep(0.6)
    assert exchange(c.listening_port, b"POST /action HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}").status == 400   # budget refills


def test_failed_authentication_costs_extra_tokens(component):
    c = component()
    wrong = Manager(c.listening_port, token="another-token-value-xyz").init(did=c.did)
    statuses = []
    for _ in range(8):
        envelope = wrong.transport.seal_request("/action", wrong.device_time(), "{}")
        statuses.append(wrong.post_raw("/action", envelope).status)
    assert statuses[:3] == [401, 401, 401] and 429 in statuses                  # 4 tokens per failure: ~3 attempts per burst


def test_config_and_plan_and_skeleton_over_http(component):
    c = component((("Laser", "Raum A"),))
    c.on_custom_config(0, lambda: [ec.CustomConfigDef("brightness", "range", "50", 0, 100)])
    values = {}
    c.on_custom_config_set(0, lambda k, v: values.__setitem__(k, v) or True)
    m = Manager(c.listening_port).init()
    assert m.post("/config", {"id": 0, "name": "Neu", "room": "Raum B", "riddleId": "r-2", "config": {"brightness": "70"}}).status == 200
    assert values == {"brightness": "70"} and (c.name(0), c.room(0), c.riddle_id(0)) == ("Neu", "Raum B", "r-2")
    assert m.post("/config", {"id": 0, "config": {"brightness": "700"}}).code == "bad_request" and values == {"brightness": "70"}
    assert m.post("/plan", '{"id":0,"plan":{"lane":"A"}}').status == 200
    assert m.get_json("/status.json")["components"][0]["plan"] == {"lane": "A"}
    sk = '{"planId":"p","layers":[]}'
    r = m.post("/plan-skeleton", '{"room":"Raum B","baseRev":0,"sk":%s}' % sk)
    assert r.status == 200 and r.body["rev"] == 1
    assert m.get_json("/plan-skeleton.json")["rooms"] == [{"room": "Raum B", "rev": 1, "hash": ec.hex8(ec.fnv1a32(sk))}]
    doc = m.get_json("/plan-skeleton.json", "room=Raum%20B")
    assert doc == {"room": "Raum B", "rev": 1, "hash": ec.hex8(ec.fnv1a32(sk)), "sk": {"planId": "p", "layers": []}}
    # moving the only component out of the room drops the skeleton (only rooms with a local component are stored)
    assert m.post("/config", {"id": 0, "name": "Neu", "room": "Raum C"}).status == 200
    assert m.get_json("/plan-skeleton.json")["rooms"] == []
    assert c.store.count == 0


# ---- UDP junk ------------------------------------------------------------------------------------------------------------------------

def test_junk_udp_datagrams_do_not_kill_the_process(component):
    c = component(udp_port=helpers.DISCOVERY_PORT)
    assert c._udp is not None
    rnd = random.Random(1)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    junk = [b"", b"{", b'{"doc":', b'{"doc":{},"mac":"x"}', b"\x00" * 700, b"[" * 10_000, b'{"doc":' + b"[" * 10_000,
            b'{"doc":' + b"x" * 593, b'{"doc":' + b"x" * 594, b"\xff\xfe" * 300]
    junk += [bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 700))) for _ in range(120)]
    junk += [b'{"doc":' + bytes(rnd.randrange(256) for _ in range(rnd.randrange(14, 590))) for _ in range(60)]
    # structurally valid frames with a wrong MAC (wrong key): must be rejected by the MAC check
    other = ec.SecureTransport()
    other.begin("a-completely-different-token", ec.TokenState.CUSTOM, "ffffffffffff")
    forged = other.frame_announcement(ec.build_announcement_doc("ffffffffffff", "127.0.0.1", 9, 1, 1, 1, 2, "00000000", "[]", 0))
    junk += [forged] * 10
    assert len(junk) >= 200
    for datagram in junk:
        sock.sendto(datagram, ("127.0.0.1", helpers.DISCOVERY_PORT))
    sock.close()
    time.sleep(1.0)
    assert c._background.is_alive()
    sent_before = c.announcements_sent
    c.mark_dirty()
    assert helpers.wait_for(lambda: c.announcements_sent > sent_before, 3)       # the loop still runs and announces
    assert c.peers() == []                                                       # nothing junk ever became a peer
    assert get(c.listening_port, "/status.json").status == 200
    assert c._background.is_alive()


def test_udp_prefilter_drops_before_any_parsing(component, monkeypatch):
    c = component(udp_port=helpers.DISCOVERY_PORT)
    seen = []
    real = c._transport.open_announcement
    monkeypatch.setattr(c._transport, "open_announcement", lambda data: seen.append(bytes(data)) or real(data))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    dropped = [b"x" * 100, b'{"doc":' + b"A" * 700, b"[" * 10_000, b'{"doc":123', b'{"doc":' + b"A" * 594]
    for datagram in dropped:                                     # wrong shape, too small (< 20) or larger than 600 bytes
        sock.sendto(datagram, ("127.0.0.1", helpers.DISCOVERY_PORT))
    examined = b'{"doc":' + b"A" * 593                           # exactly 600 bytes: still examined (and then rejected by the MAC)
    sock.sendto(examined, ("127.0.0.1", helpers.DISCOVERY_PORT))
    assert helpers.wait_for(lambda: examined in seen, 3)
    sock.close()
    assert not any(d in seen for d in dropped)                   # none of these reached the MAC check, let alone the parser
    assert all(len(d) <= 600 for d in seen)
    assert c.peers() == []


def test_oserror_in_udp_send_and_receive_never_kills_the_loop(component):
    c = component(udp_port=helpers.DISCOVERY_PORT)
    real = c._udp

    class Broken:
        def recvfrom(self, *_a):
            raise ConnectionRefusedError("icmp")
        def sendto(self, *_a):
            raise OSError("network unreachable")
        def close(self):
            real.close()

    c._udp = Broken()
    c.mark_dirty()
    time.sleep(0.8)
    assert c._background.is_alive()
    assert get(c.listening_port, "/security.json").status == 200
    c._udp = real


def test_loop_swallows_unexpected_errors_in_a_stage(component, monkeypatch):
    c = component(udp_port=helpers.DISCOVERY_PORT)
    monkeypatch.setattr(c, "_maybe_announce", lambda *_a: (_ for _ in ()).throw(RuntimeError("stage bug")))
    time.sleep(0.5)
    assert c._background.is_alive()
