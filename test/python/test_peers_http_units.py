"""Announcements, peer table, rate limiter, HTTP parsing helpers and the mDNS codec
(mirrors test_peers.cpp and test_http.cpp)."""

from __future__ import annotations

import struct

import pytest

import escape_component as ec


# ---- announcements -------------------------------------------------------------------------------------------------

def doc(**o):
    args = dict(did="112233445566", ip="192.168.1.30", port=8080, boot=2, ctr=4, seq=99, pmin=2, ui_hash="1a2b3c4d",
                sk="[]", skh=0xDEADBEEF)
    args.update(o)
    return ec.build_announcement_doc(args["did"], args["ip"], args["port"], args["boot"], args["ctr"], args["seq"],
                                     args["pmin"], args["ui_hash"], args["sk"], args["skh"])


def test_announcement_roundtrip_and_exact_text():
    d = doc(sk='[["a1b2c3d4",3,"9f8e7d6c"]]')
    assert d == ('{"v":2,"did":"112233445566","ip":"192.168.1.30","port":8080,"boot":2,"ctr":4,"seq":99,"pmin":2,'
                 '"uih":"1a2b3c4d","skh":"deadbeef","sk":[["a1b2c3d4",3,"9f8e7d6c"]]}')
    a = ec.parse_announcement(d.encode())
    assert a is not None
    assert (a.did, a.ip, a.port, a.version, a.pmin, a.boot, a.ctr, a.seq) == ("112233445566", "192.168.1.30", 8080, 2, 2, 2, 4, 99)
    assert a.uih == 0x1A2B3C4D and a.skh == 0xDEADBEEF
    assert [(s.room_key, s.rev, s.hash) for s in a.sk] == [(0xA1B2C3D4, 3, 0x9F8E7D6C)]
    assert len(doc().encode()) < 250


def test_announcement_frame_stays_under_the_limit_with_max_rooms():
    sk = "[" + ",".join('["a1b2c3d4",4294967295,"9f8e7d6c"]' for _ in range(4)) + "]"
    t = ec.SecureTransport()
    t.begin("a-token-long-enough", ec.TokenState.CUSTOM, "112233445566")
    frame = t.frame_announcement(doc(sk=sk, boot=4294967295, ctr=4294967295, seq=4294967295, ip="255.255.255.255", port=65535))
    assert len(frame) <= ec.EscapeConfig.MAX_ANNOUNCEMENT_BYTES


def test_announcement_without_skh_is_tolerated_like_the_spec_text():
    # PROTOCOL.md 4.3 does not list `skh`; the C++ sender includes it. A literal-spec sender omits it.
    literal = ('{"v":2,"did":"112233445566","ip":"192.168.1.30","port":80,"boot":5,"ctr":123,"seq":17,"pmin":2,'
               '"uih":"1a2b3c4d","sk":[["a1b2c3d4",3,"9f8e7d6c"]]}')
    a = ec.parse_announcement(literal.encode())
    assert a is not None and a.skh == ec.fnv1a32('[["a1b2c3d4",3,"9f8e7d6c"]]')
    assert ec.parse_announcement(literal.replace('"sk":', '"skh":"zz","sk":').encode()) is None   # present but malformed


@pytest.mark.parametrize("mutate", [
    lambda d: d.replace('"v":2', '"v":"2"'), lambda d: d.replace('"v":2', '"v":256'),
    lambda d: d.replace('"port":8080', '"port":0'), lambda d: d.replace('"port":8080', '"port":65536'),
    lambda d: d.replace('"port":8080', '"port":-1'), lambda d: d.replace('"port":8080', '"port":80.5'),
    lambda d: d.replace('"boot":2', '"boot":4294967296'), lambda d: d.replace('"ctr":4,', ""),
    lambda d: d.replace("112233445566", "1122334455"), lambda d: d.replace("112233445566", "11223344556A"),
    lambda d: d.replace("192.168.1.30", "192.168.1"), lambda d: d.replace("192.168.1.30", "192.168.01.30"),
    lambda d: d.replace("192.168.1.30", "192.168.1.256"), lambda d: d.replace("192.168.1.30", "192.168.1.30 "),
    lambda d: d.replace('"1a2b3c4d"', '"1A2B3C4D"'), lambda d: d.replace('"1a2b3c4d"', '"1a2b3c4"'),
    lambda d: d.replace('"sk":[]', '"sk":{}'), lambda d: d.replace('"sk":[]', '"sk":[[1]]'),
    lambda d: d.replace('"sk":[]', '"sk":[["a1b2c3d4",-1,"9f8e7d6c"]]'),
    lambda d: d.replace('"sk":[]', '"sk":[["A1B2C3D4",1,"9f8e7d6c"]]'),
    lambda d: d.replace('"sk":[]', '"sk":[["a1b2c3d4",1.5,"9f8e7d6c"]]'),
    lambda d: d.replace('"sk":[]', '"sk":[' + ",".join(['["a1b2c3d4",1,"9f8e7d6c"]'] * 9) + "]"),
    lambda d: d.replace('"sk":[]', '"sk":[[["a1b2c3d4"],1,"9f8e7d6c"]]'),
    lambda d: d + " x", lambda d: "[" + d + "]", lambda d: "",
])
def test_announcement_rejections(mutate):
    assert ec.parse_announcement(mutate(doc()).encode()) is None


# ---- peer table ----------------------------------------------------------------------------------------------------

def ann(**o):
    a = ec.parse_announcement(doc(**o).encode())
    assert a is not None
    return a


def test_peer_table_freshness_rules():
    table = ec.PeerTable()
    own = "000000000001"
    assert table.ingest(ann(), "192.168.1.30", own, 1000) == ec.IngestResult.ACCEPTED
    assert table.ingest(ann(did=own), "192.168.1.30", own, 1000) == ec.IngestResult.OWN
    assert table.ingest(ann(did="aaaaaaaaaaaa"), "10.0.0.9", own, 1000) == ec.IngestResult.BAD_SOURCE   # ip != source
    assert table.count == 1
    assert table.ingest(ann(ctr=4), "192.168.1.30", own, 1100) == ec.IngestResult.REPLAY               # equal pair
    assert table.ingest(ann(ctr=3), "192.168.1.30", own, 1100) == ec.IngestResult.REPLAY               # older
    assert table.ingest(ann(ctr=5, seq=100), "192.168.1.30", own, 1200) == ec.IngestResult.ACCEPTED
    assert table.at(0).seq == 100 and table.at(0).last_seen_ms == 1200
    assert table.ingest(ann(boot=1, ctr=900), "192.168.1.30", own, 1300) == ec.IngestResult.REPLAY     # older boot
    assert table.ingest(ann(boot=3, ctr=1), "192.168.1.30", own, 1400) == ec.IngestResult.ACCEPTED     # reboot: larger boot wins
    assert table.ingest(ann(boot=3, ctr=1), "192.168.1.30", own, 1500) == ec.IngestResult.REPLAY
    assert table.ingest(ann(ip="192.168.1.31"), "192.168.1.31", own, 1600) == ec.IngestResult.REPLAY    # (boot, ctr) per did, not per ip
    assert table.count == 1


def test_peer_table_expiry_and_eviction():
    table = ec.PeerTable(capacity=3)
    own = "000000000001"
    for i in range(3):
        did = "%012x" % (0x10 + i)
        assert table.ingest(ann(did=did), "192.168.1.30", own, 1000 + i * 100) == ec.IngestResult.ACCEPTED
    assert table.count == 3
    assert table.ingest(ann(did="%012x" % 0x99), "192.168.1.30", own, 2000) == ec.IngestResult.ACCEPTED   # full: evicts the oldest
    assert table.count == 3 and table.find_by_did("%012x" % 0x10) is None and table.find_by_did("%012x" % 0x99)
    table.expire_stale(1200 + 20000 + 1)
    assert table.count == 1                                           # only the one heard at 2000 survives
    table.expire_stale(2000 + 20001)
    assert table.count == 0
    # uint32 wrap
    table.ingest(ann(did="%012x" % 0x11), "192.168.1.30", own, 0xFFFFFF00)
    table.expire_stale(100)
    assert table.count == 1
    table.clear()
    assert table.count == 0


def test_peer_table_default_capacity_is_64():
    table = ec.PeerTable()
    for i in range(100):
        table.ingest(ann(did="%012x" % (i + 1)), "192.168.1.30", "000000000000", i)
    assert table.count == 64


# ---- address helpers -----------------------------------------------------------------------------------------------

def test_ipv4_parsing():
    assert ec.parse_ipv4("192.168.1.30") == (192 << 24) | (168 << 16) | (1 << 8) | 30
    assert ec.ipv4_to_str(ec.parse_ipv4("10.0.0.255")) == "10.0.0.255"
    for bad in ("", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.256", " 1.2.3.4", "1.2.3.4 ", "1.2.3.", "a.b.c.d", "1..2.3", "1.2.3.4\n", "١.2.3.4"):
        assert ec.parse_ipv4(bad) is None, bad
    assert ec.valid_did("aabbccddeeff") and not ec.valid_did("AABBCCDDEEFF") and not ec.valid_did("aabbccddeef")


# ---- rate limiter ----------------------------------------------------------------------------------------------------

def test_rate_limiter_token_bucket():
    rl = ec.RateLimiter()
    src = 0x7F000001
    assert all(rl.allow_source(src, 1000) for _ in range(ec.EscapeConfig.RATE_BURST))   # burst
    assert not rl.allow_source(src, 1000)
    assert not rl.allow_source(src, 1249)                                                 # one token per 250 ms
    assert rl.allow_source(src, 1250)
    assert not rl.allow_source(src, 1250)
    assert rl.allow_source(src, 1250 + 12 * 250 + 5000)                                   # refill is capped at the burst
    other = 0x7F000002
    assert rl.allow_source(other, 1250)                                                   # other sources have their own bucket


def test_rate_limiter_cost_and_isolation():
    rl = ec.RateLimiter()
    assert rl.allow_source(1, 0, 3) and rl.allow_source(1, 0, 3) and rl.allow_source(1, 0, 3) and rl.allow_source(1, 0, 3)
    assert not rl.allow_source(1, 0, 3)            # 12 tokens spent
    assert rl.allow_source(2, 0)                   # untouched by source 1


def test_rate_limiter_global_budget_and_wrap():
    rl = ec.RateLimiter()
    assert all(rl.allow_global(5000) for _ in range(ec.EscapeConfig.GLOBAL_POSTS_PER_SECOND))
    assert not rl.allow_global(5999)
    assert rl.allow_global(6000)
    rl = ec.RateLimiter()
    assert rl.allow_global(0xFFFFFFF0) and rl.allow_global(5)    # across the uint32 wrap


def test_rate_limiter_source_slots_are_bounded():
    rl = ec.RateLimiter()
    for source in range(1000):
        rl.allow_source(source, 0)
    assert len(rl._slots) == ec.EscapeConfig.RATE_SOURCES


# ---- HTTP parsing helpers ------------------------------------------------------------------------------------------------

def head(text):
    return text.replace("\n", "\r\n").encode() + b"\r\n\r\n"


def test_parse_get():
    r = ec.parse_request_head(head('GET /status.json?nonce=abc&x=1 HTTP/1.1\nHost: escapemanager.local\n'
                                   'Origin: http://escapemanager.local\nIf-None-Match: "abc"'))
    assert isinstance(r, ec.HttpRequest)
    assert (r.method, r.path, r.query) == (ec.Method.GET, "/status.json", "nonce=abc&x=1")
    assert r.origin == "http://escapemanager.local" and r.if_none_match == '"abc"' and r.content_length == 0


def test_parse_post_and_headers():
    r = ec.parse_request_head(head("POST /action HTTP/1.1\ncontent-length: 7\nContent-Type: text/plain\nExpect: 100-Continue"))
    assert r.method == ec.Method.POST and r.content_length == 7 and r.expect_continue
    r = ec.parse_request_head(head("POST /action HTTP/1.0\nContent-Length:   7  \nContent-Length: 7"))
    assert r.content_length == 7
    r = ec.parse_request_head(head("GET / HTTP/1.1\nOrigin: " + "a" * 129))
    assert r.origin == ""                                      # oversized values are dropped
    assert ec.parse_request_head(head("HEAD / HTTP/1.1")).method == ec.Method.HEAD
    assert ec.parse_request_head(head("OPTIONS /x HTTP/1.1")).method == ec.Method.OPTIONS


@pytest.mark.parametrize("request_text,status", [
    ("BREW / HTTP/1.1", 405), ("get / HTTP/1.1", 405), ("PUT / HTTP/1.1", 405), ("DELETE / HTTP/1.1", 405),
    ("GET / HTTP/2.0", 505), ("GET / HTTP/9.9", 505), ("GET / HTTP/1.2", 505), ("GET /", 400), ("GET noslash HTTP/1.1", 400),
    ("GET /a b HTTP/1.1", 400), ("GET / HTTP/1.1 x", 400), ("GET  HTTP/1.1", 400), ("GET /\x7f HTTP/1.1", 400),
    ("GET / HTTP/1.1\nBadHeader", 400), ("GET / HTTP/1.1\n folded: x", 400), ("GET / HTTP/1.1\n\tfolded: x", 400),
    ("GET / HTTP/1.1\n: novalue", 400),
    ("POST / HTTP/1.1\nContent-Length: abc", 400), ("POST / HTTP/1.1\nContent-Length: -5", 400),
    ("POST / HTTP/1.1\nContent-Length: +5", 400), ("POST / HTTP/1.1\nContent-Length: ", 400),
    ("POST / HTTP/1.1\nContent-Length: 1.5", 400), ("POST / HTTP/1.1\nContent-Length: 0x10", 400),
    ("POST / HTTP/1.1\nContent-Length: 5\nContent-Length: 6", 400),
    ("POST / HTTP/1.1\nContent-Length: 99999999999", 400),         # absurd length text (> 10 digits)
    ("POST / HTTP/1.1\nContent-Length: 2147483648", 413),
    ("POST / HTTP/1.1\nTransfer-Encoding: chunked", 501),
    ("GET /" + "a" * 600 + " HTTP/1.1", 414),
])
def test_parse_errors(request_text, status):
    assert ec.parse_request_head(head(request_text)) == status


def test_query_and_percent_decoding():
    assert ec.query_param("room=Raum%20A&nonce=x", "room") == b"Raum A"
    assert ec.query_param("room=K%C3%A4fig%2FX", "room") == "Käfig/X".encode()
    assert ec.query_param("a=1&room=a+b", "room") == b"a+b"                    # '+' stays literal
    assert ec.query_param("flag", "flag") == b""
    assert ec.query_param("a=1", "room") is None
    assert ec.query_param("room=%zz", "room") is None
    assert ec.query_param("room=%4", "room") is None
    assert ec.query_param("room=%", "room") is None
    assert ec.query_param("", "room") is None
    assert ec.query_param("ro%6fm=x", "room") == b"x"                          # keys are decoded too
    assert ec.query_param("room=%41", "room") == b"A"
    assert ec.query_param("room=%ff", "room") == b"\xff"


def test_cors_policy():
    allowed = ["null", "http://localhost", "http://localhost:8080", "http://127.0.0.1:8080", "http://escapemanager.local",
               "https://x.local:81", "http://192.168.1.20", "http://10.1.2.3", "http://172.16.0.1", "http://172.31.255.255",
               "http://169.254.1.1", "http://[::1]:80", "http://LOCALHOST", "http://X.LOCAL"]
    denied = ["", "http://evil.example", "https://github.com", "http://172.32.0.1", "http://172.15.0.1", "http://192.169.1.1",
              "http://8.8.8.8", "http://localhost.evil.com", "http://evil.local.com", "ftp://192.168.1.1",
              "http://192.168.1.1.evil.com", "http://", "http://192.168.1", "javascript:alert(1)", "http://[fe80::1]",
              "http://a b.local", "http://localhost:80a", "http://localhost/path", "HTTP://localhost", "http://.local",
              "http://999.1.1.1", "http://10.0.0.256", "null ", "http://[::1]x"]
    for origin in allowed:
        assert ec.origin_allowed(origin), origin
    for origin in denied:
        assert not ec.origin_allowed(origin), origin


def test_response_head():
    r = ec.HttpResponse(200, "application/json", b'{"a":1}')
    h = ec.format_response_head(r, "http://192.168.1.5", False).decode()
    assert h.startswith("HTTP/1.1 200 OK\r\n") and h.endswith("\r\n\r\n")
    assert "Content-Length: 7\r\n" in h and "Connection: close\r\n" in h and "Cache-Control: no-store" in h
    assert "Access-Control-Allow-Origin: http://192.168.1.5\r\n" in h
    assert "Access-Control-Allow-Origin" not in ec.format_response_head(r, "http://evil.example", False).decode()
    assert "Access-Control-Allow-Origin" not in ec.format_response_head(r, "", False).decode()
    ui = ec.HttpResponse(200, "text/html; charset=utf-8", b"\x01\x02\x03", gzip=True, etag="1a2b3c4d")
    h = ec.format_response_head(ui, "", False).decode()
    assert "Content-Encoding: gzip\r\n" in h and 'ETag: "1a2b3c4d"\r\n' in h and "Cache-Control: no-cache" in h
    assert "Content-Length: 3\r\n" in h and "no-store" not in h
    h = ec.format_response_head(ec.HttpResponse(204), "null", True).decode()
    assert h.startswith("HTTP/1.1 204 No Content") and "Access-Control-Allow-Methods: GET, POST, OPTIONS" in h
    assert ec.status_text(999) == "Status"


# ---- mDNS ----------------------------------------------------------------------------------------------------------------

HOST = "escapemanager.local"
IP = bytes([192, 168, 1, 7])


def make_query(name=HOST, qtype=1, qclass=1, known=None, known_ttl=15, qd=1, flags=0):
    p = struct.pack("!HHHHHH", 0, flags, qd, 1 if known else 0, 0, 0)
    enc = b"".join(bytes([len(label)]) + label.encode() for label in name.split(".")) + b"\x00"
    p += enc + struct.pack("!HH", qtype, qclass)
    if known:
        p += b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, known_ttl, 4) + known
    return p


def test_mdns_answer_bytes():
    expected = (bytes([0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0]) + bytes([13]) + b"escapemanager" + bytes([5]) + b"local" + b"\x00"
                + bytes([0, 1, 0, 1])                      # A, IN - cache-flush bit NOT set
                + bytes([0, 0, 0, 15, 0, 4, 192, 168, 1, 7]))
    assert ec.build_mdns_answer(HOST, IP, 15) == expected
    assert ec.build_mdns_answer("", IP, 15) == b"" and ec.build_mdns_answer("a..b", IP, 15) == b""
    assert ec.build_mdns_answer("x" * 64 + ".local", IP, 15) == b"" and ec.build_mdns_answer("é.local", IP, 15) == b""


def test_mdns_query_matching():
    q = ec.parse_mdns_query(make_query(), HOST, IP, 15)
    assert (q.matches, q.unicast, q.suppressed) == (True, False, False)
    assert ec.parse_mdns_query(make_query(qclass=0x8001), HOST, IP, 15).unicast               # QU bit
    assert ec.parse_mdns_query(make_query(qtype=255), HOST, IP, 15).matches                    # ANY
    assert ec.parse_mdns_query(make_query(name="ESCAPEMANAGER.Local"), HOST, IP, 15).matches   # case-insensitive
    for q in (make_query(name="other.local"), make_query(name="escapemanager.local.x"), make_query(name="manager.local"),
              make_query(qtype=28), make_query(qclass=3), make_query(flags=0x8400), make_query(flags=0x2800)):
        assert not ec.parse_mdns_query(q, HOST, IP, 15).matches
    # known-answer suppression: only when our address is listed with at least half the TTL
    assert ec.parse_mdns_query(make_query(known=IP, known_ttl=15), HOST, IP, 15).suppressed
    assert ec.parse_mdns_query(make_query(known=IP, known_ttl=7), HOST, IP, 15).suppressed
    assert not ec.parse_mdns_query(make_query(known=IP, known_ttl=6), HOST, IP, 15).suppressed
    assert not ec.parse_mdns_query(make_query(known=bytes([1, 2, 3, 4])), HOST, IP, 15).suppressed
    assert ec.parse_mdns_query(make_query(known=bytes([1, 2, 3, 4])), HOST, IP, 15).matches


def test_mdns_compression_pointer_and_hops():
    # the known answer already uses a pointer to the question name (see make_query); a pointer loop must not hang
    loop = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\xc0\x0c" + struct.pack("!HH", 1, 1)
    assert not ec.parse_mdns_query(loop, HOST, IP, 15).matches
    chain = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0)
    chain += b"".join(struct.pack("!H", 0xC000 | (12 + 2 * (i + 1))) for i in range(10)) + b"\x00"
    assert not ec.parse_mdns_query(chain, HOST, IP, 15).matches
    forward = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + b"\xc0\xff" + struct.pack("!HH", 1, 1)   # pointer beyond the packet
    assert not ec.parse_mdns_query(forward, HOST, IP, 15).matches


def test_mdns_rejects_garbage_and_never_raises():
    p = make_query()
    for cut in range(len(p)):                                  # truncations never crash
        ec.parse_mdns_query(p[:cut], HOST, IP, 15)
    assert not ec.parse_mdns_query(p + b"\x00" * 1500, HOST, IP, 15).matches      # oversized
    assert not ec.parse_mdns_query(struct.pack("!HHHHHH", 0, 0, 0, 0, 0, 0), HOST, IP, 15).matches   # no question
    assert not ec.parse_mdns_query(struct.pack("!HHHHHH", 0, 0, 17, 0, 0, 0) + p[12:] * 17, HOST, IP, 15).matches
    long_label = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + bytes([64]) + b"a" * 64 + b"\x00" + struct.pack("!HH", 1, 1)
    assert not ec.parse_mdns_query(long_label, HOST, IP, 15).matches
    reserved = struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + bytes([0x80]) + b"a" * 64 + b"\x00" + struct.pack("!HH", 1, 1)
    assert not ec.parse_mdns_query(reserved, HOST, IP, 15).matches
    import random
    rnd = random.Random(7)
    for _ in range(3000):
        junk = bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 200)))
        ec.parse_mdns_query(junk, HOST, IP, 15)
        mutated = bytearray(p)
        mutated[rnd.randrange(len(mutated))] = rnd.randrange(256)
        ec.parse_mdns_query(bytes(mutated), HOST, IP, 15)


def test_mdns_response_delay_is_20_to_120_ms():
    assert ec.mdns_response_delay_ms(0) == 20 and ec.mdns_response_delay_ms(100) == 120
    assert all(20 <= ec.mdns_response_delay_ms(r) <= 120 for r in range(0, 100000, 37))
