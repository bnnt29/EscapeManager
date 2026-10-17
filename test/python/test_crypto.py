"""Crypto, envelopes and frames against the independent Node vectors (test/fixtures/proto2/vectors.json).

Mirrors test/test_core/test_crypto.cpp and test_base64.cpp.
"""

from __future__ import annotations

import pytest

import escape_component as ec


def tokens(vectors):
    return vectors["tokens"]


@pytest.fixture(params=[0, 1], ids=["default-token", "custom-token"])
def vec(request, vectors):
    return vectors["tokens"][request.param]


def begun(vec, vectors, did=None):
    t = ec.SecureTransport()
    assert t.begin(vec["token"], ec.TokenState.CUSTOM, did or vectors["did"])
    assert t.writable
    return t


# ---- primitives -----------------------------------------------------------------------------------

def test_base64url_vectors(vectors):
    for v in vectors["b64u"]:
        raw = bytes.fromhex(v["hex"])
        assert ec.b64u_encode(raw) == v["text"]
        assert ec.b64u_decode(v["text"]) == raw


def test_base64url_is_strict(vectors):
    for text in vectors["b64uInvalid"]:
        with pytest.raises(ValueError):
            ec.b64u_decode(text)
    for text in ["AA==", "AAE=", "A\n", " AAAA", "AAAA ", "AAA\u00e4", "AA/A", "AA+A", "AB", "AAF", "AAAAB"]:
        with pytest.raises(ValueError):
            ec.b64u_decode(text)
    assert ec.b64u_decode(b"AAEC") == b"\x00\x01\x02"  # bytes input works too
    assert "=" not in ec.b64u_encode(b"\x00")


def test_fnv1a32_vectors(vectors):
    for v in vectors["fnv1a32"]:
        assert ec.hex8(ec.fnv1a32(v["text"])) == v["hash"]
        assert ec.hex8(ec.fnv1a32(v["text"].encode("utf-8"))) == v["hash"]
    assert ec.parse_hex8("00ff10ab") == 0x00FF10AB
    assert ec.parse_hex8("00FF10AB") is None   # one canonical (lowercase) text
    assert ec.parse_hex8("00ff10a") is None
    assert ec.parse_hex8("00ff10abc") is None


def test_hkdf_rfc5869(vectors):
    v = vectors["hkdfRfc5869"]
    okm = ec.hkdf_sha256(bytes.fromhex(v["ikm"]), bytes.fromhex(v["salt"]), bytes.fromhex(v["info"]), v["length"])
    assert okm.hex() == v["okm"]
    with pytest.raises(ValueError):
        ec.hkdf_sha256(b"x", b"", b"", 255 * 32 + 1)
    assert len(ec.hkdf_sha256(b"x", b"", b"", 255 * 32)) == 255 * 32


def test_key_schedule_matches_vectors(vec, vectors):
    assert vectors["kdf"] == {"salt": "EscapeManager/2/token", "iter": 2048}
    keys = ec.derive_keys(vec["token"])
    assert keys.master.hex() == vec["master"]
    assert keys.req.hex() == vec["kReq"]
    assert keys.resp.hex() == vec["kResp"]
    assert keys.mac.hex() == vec["kMac"]
    assert ec.derive_keys(vec["token"].encode()).req == keys.req


# ---- POST envelopes ---------------------------------------------------------------------------------

def test_open_request_vector_then_replay(vec, vectors):
    t = begun(vec, vectors)
    post = vec["post"]
    env = post["envelope"].encode()
    r = t.open_request(post["path"], env, post["t"] + 1000)
    assert (r.status, r.code) == (200, None)
    assert r.plaintext.decode() == post["plaintext"]
    assert r.request_iv == post["iv"]
    r = t.open_request(post["path"], env, post["t"] + 1500)   # the very same envelope again is a replay
    assert (r.status, r.code) == (409, "replay")
    assert r.plaintext == b""
    assert r.request_iv == post["iv"]                        # readable, so the error can be authenticated


def test_seal_request_matches_vector(vec, vectors):
    t = begun(vec, vectors)
    post = vec["post"]
    env = t.seal_request(post["path"], post["t"], post["plaintext"], bytes(range(12)))
    assert env.decode() == post["envelope"]  # byte-identical to the Node reference


def test_response_envelope_vector(vec, vectors):
    t = begun(vec, vectors)
    post, resp = vec["post"], vec["postResponse"]
    assert resp["aad"] == "EM2|resp|aabbccddeeff|/action|%s|200" % post["iv"]
    sealed = t.seal_response(post["path"], post["iv"], 200, resp["plaintext"], bytes(range(12, 24)))
    assert sealed.decode() == resp["envelope"]
    env = resp["envelope"].encode()
    assert t.open_response(post["path"], post["iv"], 200, env).decode() == resp["plaintext"]
    assert t.open_response(post["path"], post["iv"], 409, env) is None                   # status is bound
    assert t.open_response("/config", post["iv"], 200, env) is None                      # path is bound
    assert t.open_response(post["path"], "AAAAAAAAAAAAAAAA", 200, env) is None           # request is bound
    one = t.seal_response("/plan", "AAECAwQFBgcICQoL", 409, '{"ok":false,"code":"rev_conflict"}')
    two = t.seal_response("/plan", "AAECAwQFBgcICQoL", 409, '{"ok":false,"code":"rev_conflict"}')
    assert one != two                                                                    # fresh random IV every time
    assert t.open_response("/plan", "AAECAwQFBgcICQoL", 409, one) == b'{"ok":false,"code":"rev_conflict"}'


def test_aad_layout_is_the_documented_one(vec, vectors):
    post = vec["post"]
    assert post["aad"] == "EM2|req|%s|%s|%d" % (vectors["did"], post["path"], post["t"])


def test_request_rejections(vectors):
    vec = vectors["tokens"][0]
    post = vec["post"]
    env = post["envelope"].encode()

    t = begun(vec, vectors)
    r = t.open_request(post["path"], env, post["t"] + 15001)
    assert (r.status, r.code) == (409, "stale_time")
    assert r.request_iv == post["iv"]                         # stale answers can be authenticated
    assert t.open_request(post["path"], env, post["t"] - 15001).code == "stale_time"
    assert t.open_request(post["path"], env, post["t"] + 15000).status == 200   # exactly at the edge: accepted

    t = begun(vec, vectors)
    r = t.open_request("/config", env, post["t"])             # the path is bound
    assert (r.status, r.code) == (401, "auth_failed")
    assert t.replay_entries(post["t"]) == 0                   # failures never enter the cache

    t = begun(vec, vectors, did="112233445566")               # the device id is bound
    assert t.open_request(post["path"], env, post["t"]).code == "auth_failed"

    t = begun(vectors["tokens"][1], vectors)                  # another token
    assert t.open_request(post["path"], env, post["t"]).code == "auth_failed"

    t = begun(vec, vectors)
    pos = post["envelope"].index('"ct":"') + 8
    flipped = post["envelope"][:pos] + ("B" if post["envelope"][pos] == "A" else "A") + post["envelope"][pos + 1:]
    assert t.open_request(post["path"], flipped.encode(), post["t"]).code == "auth_failed"
    moved = post["envelope"].replace('"t":123456', '"t":123457')  # t is authenticated too
    assert t.open_request(post["path"], moved.encode(), post["t"]).code == "auth_failed"


@pytest.mark.parametrize("body", [
    b"", b"{}", b"[]", b"garbage", b'{"v":2}',
    b'{"v":1,"t":1,"iv":"AAECAwQFBgcICQoL","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":3,"t":1,"iv":"AAECAwQFBgcICQoL","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":-1,"iv":"AAECAwQFBgcICQoL","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":01,"iv":"AAECAwQFBgcICQoL","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":4294967296,"iv":"AAECAwQFBgcICQoL","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":1,"iv":"AAEC","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":1,"iv":"AAECAwQFBgcICQoL=","ct":"AAAAAAAAAAAAAAAAAAAAAA"}',
    b'{"v":2,"t":0,"iv":"AAECAwQFBgcICQoL","ct":"AAAA"}',
    b'{"v":2,"t":0,"iv":"AAECAwQFBgcICQoL","ct":5}',
])
def test_malformed_envelopes_are_bad_envelope(vectors, body):
    t = begun(vectors["tokens"][0], vectors)
    r = t.open_request("/action", body, 0)
    assert (r.status, r.code) == (400, "bad_envelope"), body


def test_oversized_envelope_is_413(vectors):
    t = begun(vectors["tokens"][0], vectors)
    r = t.open_request("/action", b"x" * (ec.EscapeConfig.MAX_BODY_BYTES + 1), 0)
    assert (r.status, r.code) == (413, "too_large")


def test_read_only_states(vectors):
    t = ec.SecureTransport()
    assert t.begin("", ec.TokenState.INVALID, vectors["did"])
    assert not t.writable
    assert t.token_state == ec.TokenState.INVALID
    env = vectors["tokens"][0]["post"]["envelope"].encode()
    r = t.open_request("/action", env, vectors["tokens"][0]["post"]["t"])
    assert (r.status, r.code, r.request_iv) == (503, "read_only", "")
    assert t.frame_document("/status.json", "0123456789abcdef", 200, "{}") is None
    assert t.frame_announcement("{}") is None
    short = ec.SecureTransport()
    assert not short.begin("short", ec.TokenState.CUSTOM, vectors["did"])       # < 8 bytes
    assert not short.writable and short.token_state == ec.TokenState.INVALID    # never falls back to the default
    assert not ec.SecureTransport().begin("x" * 129, ec.TokenState.CUSTOM, vectors["did"])


def test_invalid_token_device_is_read_only_and_not_default(component):
    c = component(token_state=ec.TokenState.INVALID, auth_token=None)
    assert c.token_state == ec.TokenState.INVALID
    assert not c.transport.writable
    doc = __import__("json").loads(c.security_json())
    assert doc["token"] == "invalid" and doc["writable"] is False
    short = component(auth_token="short")          # unusable token: invalid, not the public default
    assert short.token_state == ec.TokenState.INVALID
    assert __import__("json").loads(short.security_json())["writable"] is False


# ---- GET frames and UDP frames ------------------------------------------------------------------------------

def test_document_frames(vec, vectors):
    t = begun(vec, vectors)
    g = vec["get"]
    frame = t.frame_document(g["path"], g["nonce"], 200, g["doc"])
    assert frame.decode() == g["frame"]                       # byte-identical to the Node reference
    assert t.open_document_frame(g["path"], g["nonce"], 200, frame).decode() == g["doc"]
    assert t.open_document_frame(g["path"], "0123456789abcdefXYZ", 200, frame) is None     # nonce is bound
    assert t.open_document_frame(g["path"], g["nonce"], 404, frame) is None                # status is bound
    assert t.open_document_frame("/peers.json", g["nonce"], 200, frame) is None            # path is bound
    tampered = frame.replace(b'"seq":17', b'"seq":18')
    assert t.open_document_frame(g["path"], g["nonce"], 200, tampered) is None
    assert t.open_document_frame(g["path"], g["nonce"], 200, frame[:-3]) is None           # truncated
    assert t.open_document_frame(g["path"], g["nonce"], 200, b"{}") is None
    other = begun(vec, vectors, did="112233445566")           # frames are bound to the responding device
    assert other.open_document_frame(g["path"], g["nonce"], 200, frame) is None
    assert other.open_document_frame_from(vectors["did"], g["path"], g["nonce"], 200, frame) is not None
    assert t.frame_document(g["path"], "short", 200, g["doc"]) is None                     # nonce rules
    assert t.frame_document(g["path"], "0123456789abcdef!", 200, g["doc"]) is None
    assert t.frame_document(g["path"], "x" * 65, 200, g["doc"]) is None


def test_frame_layout_is_byte_exact(vec, vectors):
    t = begun(vec, vectors)
    frame = t.frame_document("/status.json", "0123456789abcdef", 200, '{"a": 1}')   # whitespace inside doc is kept
    assert frame.startswith(b'{"doc":{"a": 1},"mac":"') and frame.endswith(b'"}')
    assert len(frame) == len(b'{"doc":{"a": 1},"mac":"') + 43 + 2


def test_announcement_frames(vec, vectors):
    t = begun(vec, vectors)
    u = vec["udp"]
    frame = t.frame_announcement(u["doc"])
    assert frame.decode() == u["frame"]
    assert t.open_announcement(frame).decode() == u["doc"]
    assert t.open_announcement(frame.replace(b'"ctr":123', b'"ctr":124')) is None
    get = t.frame_document("/status.json", "0123456789abcdef", 200, u["doc"])
    assert t.open_announcement(get) is None                   # a GET frame is not an announcement (different MAC domain)


def test_mac_noncanonical_text_is_rejected(vec, vectors):
    t = begun(vec, vectors)
    u = vec["udp"]
    frame = t.frame_announcement(u["doc"]).decode()
    mac = frame[-46:-3]
    assert t.open_announcement(frame.encode()) is not None
    padded = frame[:-3] + "=" + "\"}"                         # 44 characters: wrong length
    assert t.open_announcement(padded.encode()) is None
    assert t.open_announcement(frame.replace(mac, mac[:-1] + ("A" if mac[-1] != "A" else "B")).encode()) is None


# ---- replay cache, clock ---------------------------------------------------------------------------------------

def test_replay_cache_is_bounded_and_fails_closed(vectors):
    t = begun(vectors["tokens"][0], vectors)
    now = 1_000_000
    for i in range(ec.EscapeConfig.REPLAY_CACHE_SIZE):
        iv = bytes((i * 3 + k + 1) & 0xFF for k in range(12))
        env = t.seal_request("/action", now, '{"id":0,"action":"x"}', iv)
        assert t.open_request("/action", env, now).status == 200, i
    assert t.replay_entries(now) == ec.EscapeConfig.REPLAY_CACHE_SIZE
    extra = bytes(range(99, 87, -1))
    env = t.seal_request("/action", now, "{}", extra)
    r = t.open_request("/action", env, now)
    assert (r.status, r.code) == (429, "rate_limited")        # fail closed
    assert t.replay_entries(now) == ec.EscapeConfig.REPLAY_CACHE_SIZE
    # an unauthenticated flood cannot fill the cache: garbage never enters it
    for i in range(200):
        bad = t.seal_request("/action", now, "{}", bytes([i % 256] * 12)).replace(b'"ct":"', b'"ct":"A')
        assert t.open_request("/action", bad, now).status in (400, 401)
    assert t.replay_entries(now) == ec.EscapeConfig.REPLAY_CACHE_SIZE
    # after the window the capacity returns - and the old IVs cannot be replayed (their t is outside the window)
    later = now + ec.EscapeConfig.TIME_WINDOW_MS + 1
    env = t.seal_request("/action", later, "{}", extra)
    assert t.open_request("/action", env, later).status == 200
    first = bytes((0 * 3 + k + 1) & 0xFF for k in range(12))
    env = t.seal_request("/action", now, '{"id":0,"action":"x"}', first)
    assert t.open_request("/action", env, later).code == "stale_time"


def test_replay_matches_on_the_first_8_bytes_of_the_iv(vectors):
    t = begun(vectors["tokens"][0], vectors)
    env = t.seal_request("/action", 5, "{}", b"ABCDEFGH" + b"1234")
    assert t.open_request("/action", env, 5).status == 200
    env = t.seal_request("/action", 5, "{}", b"ABCDEFGH" + b"9999")  # different tail, same 8-byte prefix
    assert t.open_request("/action", env, 5).code == "replay"


def test_clock_wraparound(vectors):
    # The device clock is a uint32 millisecond counter that wraps after 49.7 days.
    t = begun(vectors["tokens"][0], vectors)
    env = t.seal_request("/action", 0xFFFFFF00, "{}", bytes(range(1, 13)))
    assert t.open_request("/action", env, 5000).status == 200        # clock already wrapped
    env = t.seal_request("/action", 4000, "{}", bytes([9] * 12))
    assert t.open_request("/action", env, 0xFFFFFF00).status == 200
    assert ec.s32(0xFFFFFFFF) == -1 and ec.s32(0x80000000) == -(2 ** 31) and ec.s32(5) == 5


def test_nonce_rules():
    assert ec.valid_nonce("0123456789abcdef")
    assert ec.valid_nonce("A" * 64)
    assert ec.valid_nonce("0123456789abcdefGHIJ_-")
    assert not ec.valid_nonce("0123456789abcde")        # 15
    assert not ec.valid_nonce("A" * 65)
    assert not ec.valid_nonce("0123456789abcdef!")
    assert not ec.valid_nonce("0123456789abcdef\n")
    assert not ec.valid_nonce("")


def test_constant_time_compare_is_used_for_macs():
    import inspect
    source = inspect.getsource(ec.SecureTransport._open_frame)
    assert "compare_digest" in source
