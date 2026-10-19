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


# ---- plan-edit token (PROTOCOL.md 3.1; mirrors test_edit_* in test/test_core/test_crypto.cpp) -----------------------

EDIT_PATHS = ("/plan", "/plan-skeleton", "/setup")
OTHER_PATHS = ("/action", "/plan-action", "/config")


def begun_edit(vectors, did=None):
    e = vectors["edit"]
    t = ec.SecureTransport()
    assert t.begin(e["normalToken"], ec.TokenState.CUSTOM, did or vectors["did"], e["editToken"], ec.EditState.CUSTOM)
    assert t.writable and t.edit_ready and t.edit_state == ec.EditState.CUSTOM
    return t


def test_edit_key_schedule_matches_vectors(vectors):
    e = vectors["edit"]
    assert e["salt"] == "EscapeManager/2/edit-token" and ec.EDIT_KDF_SALT == e["salt"].encode()
    keys = ec.derive_keys(e["editToken"], edit=True)
    assert keys.master.hex() == e["master"]
    assert keys.req.hex() == e["kReq"]
    assert keys.resp.hex() == e["kResp"]
    assert keys.mac.hex() == e["kMac"]
    # The salt separates the two key sets: the same text as the NORMAL token gives other keys.
    same = ec.derive_keys(e["editToken"])
    assert same.master != keys.master and same.req != keys.req and same.mac != keys.mac
    assert ec.derive_keys(e["editToken"].encode(), edit=True).req == keys.req


def test_is_edit_path():
    for path in EDIT_PATHS:
        assert ec.is_edit_path(path), path
    for path in OTHER_PATHS + ("/plan-skeleton.json", "/plan/", "/Plan", "/setup/save", "", "/edit.json"):
        assert not ec.is_edit_path(path), path


def test_edit_envelope_vectors(vectors):
    e = vectors["edit"]
    post, resp = e["post"], e["postResponse"]
    t = begun_edit(vectors)
    assert post["aad"] == "EM2|req|%s|%s|%d" % (vectors["did"], post["path"], post["t"])
    r = t.open_request(post["path"], post["envelope"].encode(), post["t"] + 1000)
    assert (r.status, r.code, r.role) == (200, None, ec.KeyRole.EDIT)
    assert r.plaintext.decode() == post["plaintext"] and r.request_iv == post["iv"]
    r = t.open_request(post["path"], post["envelope"].encode(), post["t"] + 1500)
    assert (r.status, r.code) == (409, "replay")
    assert r.role == ec.KeyRole.NORMAL and r.plaintext == b""        # the role to answer with is edit only after a success

    # The client side produces exactly the reference bytes (k:e is the LAST member).
    sealed = t.seal_request(post["path"], post["t"], post["plaintext"], bytes(range(12)), ec.KeyRole.EDIT)
    assert sealed.decode() == post["envelope"] and sealed.endswith(b',"k":"e"}')
    normal = t.seal_request(post["path"], post["t"], post["plaintext"], bytes(range(12)))
    assert normal.decode() == post["normalEnvelope"] and b'"k"' not in normal

    # The answer to an edit-authenticated request is sealed with ek_resp.
    assert resp["aad"] == "EM2|resp|%s|%s|%s|200" % (vectors["did"], post["path"], post["iv"])
    env = resp["envelope"].encode()
    assert t.open_response(post["path"], post["iv"], 200, env, ec.KeyRole.EDIT).decode() == resp["plaintext"]
    assert t.open_response(post["path"], post["iv"], 200, env, ec.KeyRole.NORMAL) is None
    assert t.open_response(post["path"], post["iv"], 200, env) is None
    assert t.seal_response(post["path"], post["iv"], 200, resp["plaintext"], bytes(range(12, 24)),
                           ec.KeyRole.EDIT).decode() == resp["envelope"]
    mine = t.seal_response("/plan", post["iv"], 200, '{"ok":true}', role=ec.KeyRole.EDIT)
    assert t.open_response("/plan", post["iv"], 200, mine, ec.KeyRole.EDIT) == b'{"ok":true}'
    assert t.open_response("/plan", post["iv"], 200, mine, ec.KeyRole.NORMAL) is None


def test_edit_required_after_authentication(vectors):
    e = vectors["edit"]
    post = e["post"]
    t = begun_edit(vectors)
    r = t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"])   # valid, but with the NORMAL keys
    assert (r.status, r.code) == (403, "edit_required")
    assert r.role == ec.KeyRole.NORMAL                      # sealed with the normal keys: the sender proved the normal token
    assert r.plaintext == b"" and r.request_iv == post["iv"]
    # Every edit path, with normal keys, is refused; the authenticated refusal consumed the IV (replay cache).
    for i, path in enumerate(EDIT_PATHS):
        env = t.seal_request(path, post["t"], "{}", bytes([20 + i] * 12))
        r = t.open_request(path, env, post["t"])
        assert (r.status, r.code) == (403, "edit_required"), path
        assert t.open_request(path, env, post["t"]).code == "replay"
    # Other paths are unaffected by the edit token.
    for i, path in enumerate(OTHER_PATHS):
        env = t.seal_request(path, post["t"], "{}", bytes([40 + i] * 12))
        r = t.open_request(path, env, post["t"])
        assert (r.status, r.role) == (200, ec.KeyRole.NORMAL), path
    # The edit key set does not authorise normal operation: "k":"e" on a non-edit path is a bad envelope.
    for i, path in enumerate(OTHER_PATHS):
        env = t.seal_request(path, post["t"], "{}", bytes([77 + i] * 12), ec.KeyRole.EDIT)
        r = t.open_request(path, env, post["t"])
        assert (r.status, r.code) == (400, "bad_envelope"), path
    # Edit-keyed requests work on every edit path.
    for i, path in enumerate(EDIT_PATHS):
        env = t.seal_request(path, post["t"], "{}", bytes([90 + i] * 12), ec.KeyRole.EDIT)
        r = t.open_request(path, env, post["t"])
        assert (r.status, r.role) == (200, ec.KeyRole.EDIT), path


def test_edit_unset_keeps_old_behaviour(vectors):
    e = vectors["edit"]
    post = e["post"]
    t = ec.SecureTransport()
    assert t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"])
    assert t.edit_state == ec.EditState.UNSET and not t.edit_ready and not t.signing_enabled
    r = t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"])
    assert (r.status, r.role) == (200, ec.KeyRole.NORMAL)           # the normal token may still send plans
    t2 = ec.SecureTransport()
    assert t2.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"])
    r = t2.open_request(post["path"], post["envelope"].encode(), post["t"])
    assert (r.status, r.code) == (401, "auth_failed")               # an edit envelope cannot be verified without an edit token
    assert r.role == ec.KeyRole.NORMAL and r.request_iv == post["iv"]  # ... and the refusal is sealed with the normal keys
    assert t2.frame_edit_document("/edit.json", e["proof"]["nonce"], 200, "{}") is None
    assert t2.open_edit_document_frame("/edit.json", e["proof"]["nonce"], 200, e["proof"]["frame"].encode()) is None
    assert t2.sign_skeleton("R", 1, 1) is None and not t2.verify_skeleton("R", 1, 1, e["skeleton"]["emac"])
    assert t2.seal_request("/plan", 1, "{}", bytes(12), ec.KeyRole.EDIT) is None
    assert t2.seal_response("/plan", "AAECAwQFBgcICQoL", 200, "{}", role=ec.KeyRole.EDIT) is None
    assert t2.open_response("/plan", "AAECAwQFBgcICQoL", 200, post["normalEnvelope"].encode(), ec.KeyRole.EDIT) is None
    # An empty edit token with edit_state UNSET is "unset" too (nothing is derived).
    t3 = ec.SecureTransport()
    assert t3.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], "", ec.EditState.UNSET)
    assert not t3.edit_ready


def test_unusable_edit_token_never_opens_editing(vectors):
    e = vectors["edit"]
    post = e["post"]
    t = ec.SecureTransport()
    assert not t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], "short", ec.EditState.CUSTOM)
    assert t.edit_state == ec.EditState.INVALID and not t.edit_ready and not t.signing_enabled
    assert t.writable                                               # game operation stays available
    r = t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"])
    assert (r.status, r.code) == (503, "read_only")
    assert r.request_iv == post["iv"] and r.role == ec.KeyRole.NORMAL   # authenticated refusal, normal keys
    for path in EDIT_PATHS:
        env = t.seal_request(path, post["t"], "{}", bytes([5] * 12))
        assert t.open_request(path, env, post["t"]).code == "read_only", path
    assert t.replay_entries(post["t"]) == 0
    env = t.seal_request("/action", post["t"], "{}", bytes([6] * 12))
    assert t.open_request("/action", env, post["t"]).status == 200
    # an edit-keyed request cannot even be tried: the edit path is closed before anything is verified
    assert t.open_request(post["path"], post["envelope"].encode(), post["t"]).code == "read_only"
    assert not t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], "x" * 129, ec.EditState.CUSTOM)
    assert t.edit_state == ec.EditState.INVALID and t.writable

    t = ec.SecureTransport()                                        # stored but unreadable
    assert t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], "", ec.EditState.INVALID)
    assert t.edit_state == ec.EditState.INVALID and not t.edit_ready
    assert t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"]).status == 503

    # an invalid NORMAL token still makes everything read-only, an edit token or not
    t = ec.SecureTransport()
    assert t.begin("", ec.TokenState.INVALID, vectors["did"], e["editToken"], ec.EditState.CUSTOM)
    assert not t.writable and t.edit_ready
    assert t.open_request(post["path"], post["envelope"].encode(), post["t"]).code == "read_only"


def test_edit_check_order_matches_the_reference(vectors):
    """The exact order of checks of SecureTransport::openRequest (C++), error codes and the key set of the answer."""
    e = vectors["edit"]
    post = e["post"]
    good = post["envelope"]
    t = begun_edit(vectors)

    def open_(envelope, path="/plan", now=None):
        return t.open_request(path, envelope.encode() if isinstance(envelope, str) else envelope, post["t"] if now is None else now)

    # "k" must be exactly the string "e": anything else is a bad envelope, even before the IV is looked at
    for bad_k in ('"x"', '"E"', '"ee"', '""', '1', 'null', 'true', '["e"]', '{}', '"\\u0065"'):
        env = good.replace('"k":"e"', '"k":%s' % bad_k)
        r = open_(env)
        assert (r.status, r.code, r.request_iv) == (400, "bad_envelope", ""), bad_k
    r = open_(good.replace('"iv":"AAECAwQFBgcICQoL"', '"iv":"AAEC"'))
    assert (r.status, r.code, r.request_iv) == (400, "bad_envelope", "")      # a broken IV is still a bad envelope
    # "k":"e" on a non-edit path is 400 before the key set, the IV, read-only or the clock are looked at
    for path in OTHER_PATHS + ("/nope",):
        assert open_(good, path).code == "bad_envelope", path
        assert open_(good, path, now=post["t"] + 99999).code == "bad_envelope", path
    # Without the edit key set: auth_failed (sealed with the normal keys), whatever the clock says
    plain = ec.SecureTransport()
    plain.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"])
    r = plain.open_request("/plan", good.encode(), post["t"] + 99999)
    assert (r.status, r.code, r.request_iv, r.role) == (401, "auth_failed", post["iv"], ec.KeyRole.NORMAL)
    # With an edit token: errors decided before authentication are sealed with the NORMAL keys
    r = open_(good, now=post["t"] + 15001)
    assert (r.status, r.code, r.request_iv, r.role) == (409, "stale_time", post["iv"], ec.KeyRole.NORMAL)
    assert open_(good, now=post["t"] - 15001).code == "stale_time"
    assert open_(good, now=post["t"] + 15000).status == 200          # exactly at the edge
    t = begun_edit(vectors)
    # a wrong tag is auth_failed and never enters the replay cache
    pos = good.index('"ct":"') + 8
    flipped = good[:pos] + ("B" if good[pos] == "A" else "A") + good[pos + 1:]
    r = open_(flipped)
    assert (r.status, r.code, r.role) == (401, "auth_failed", ec.KeyRole.NORMAL)
    assert t.replay_entries(post["t"]) == 0
    # a stripped k fails authentication (edit keys cannot be read with the normal ones), an added k as well
    stripped = open_(good.replace(',"k":"e"', ""))
    assert (stripped.status, stripped.code) == (401, "auth_failed")
    added = open_(post["normalEnvelope"][:-1] + ',"k":"e"}')
    assert (added.status, added.code) == (401, "auth_failed")
    # the position of k does not matter, duplicates: the first one wins
    first = good.replace('{"v":2,', '{"k":"e","v":2,').replace(',"k":"e"}', "}")
    assert open_(first).status == 200
    t = begun_edit(vectors)
    dup = good[:-1] + ',"k":"x"}'
    assert open_(dup).status == 200
    t = begun_edit(vectors)
    dup = good.replace('{"v":2,', '{"k":"x","v":2,')
    assert open_(dup).code == "bad_envelope"
    # a normal-key request with the IV of an accepted edit request is a replay: one cache for both key sets
    t = begun_edit(vectors)
    assert open_(good).status == 200
    assert open_(post["normalEnvelope"]).code == "replay"
    # the oversized check still comes first
    assert open_("x" * (ec.EscapeConfig.MAX_BODY_BYTES + 1)).code == "too_large"


def test_edit_proof_frame_and_skeleton_mac(vectors):
    e = vectors["edit"]
    proof, sk = e["proof"], e["skeleton"]
    t = begun_edit(vectors)
    frame = t.frame_edit_document(proof["path"], proof["nonce"], 200, proof["doc"])
    assert frame.decode() == proof["frame"]                          # byte-identical to the Node reference
    assert t.open_edit_document_frame(proof["path"], proof["nonce"], 200, frame) == proof["doc"].encode()
    assert t.open_edit_document_frame(proof["path"], proof["nonce"], 200, proof["frame"].encode()) is not None
    # bound to nonce, status, path and the responding device
    assert t.open_edit_document_frame(proof["path"], "0123456789abcdefGHIJ_x", 200, frame) is None
    assert t.open_edit_document_frame(proof["path"], proof["nonce"], 404, frame) is None
    assert t.open_edit_document_frame("/status.json", proof["nonce"], 200, frame) is None
    assert begun_edit(vectors, did="112233445566").open_edit_document_frame(proof["path"], proof["nonce"], 200, frame) is None
    assert t.frame_edit_document(proof["path"], "short", 200, proof["doc"]) is None            # nonce rules
    assert t.open_edit_document_frame(proof["path"], "short", 200, frame) is None
    # A frame MACed with the NORMAL key never passes as edit proof and vice versa (different key AND domain).
    normal_frame = t.frame_document(proof["path"], proof["nonce"], 200, proof["doc"])
    assert normal_frame != frame
    assert t.open_edit_document_frame(proof["path"], proof["nonce"], 200, normal_frame) is None
    assert t.open_document_frame(proof["path"], proof["nonce"], 200, frame) is None
    # the domain prefix is "EM2|eget|": the same MAC key over the normal prefix is not accepted
    forged = ec.SecureTransport._frame(t, t._e_mac, b"EM2|get|%s|/edit.json|%s|200|" % (vectors["did"].encode(), proof["nonce"].encode()), proof["doc"])
    assert t.open_edit_document_frame(proof["path"], proof["nonce"], 200, forged) is None

    # skeleton MAC
    digest = int(sk["hash"], 16)
    emac = t.sign_skeleton(sk["room"], sk["rev"], digest)
    assert emac == sk["emac"] and len(emac) == 43
    assert t.signing_enabled
    assert t.verify_skeleton(sk["room"], sk["rev"], digest, emac)
    assert not t.verify_skeleton(sk["room"], sk["rev"] + 1, digest, emac)         # bound to the revision
    assert not t.verify_skeleton("Raum-B", sk["rev"], digest, emac)               # ... the room
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest + 1, emac)         # ... and the hash
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, emac[1:])         # wrong length
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, emac + "A")
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, "A" * 43)
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, "")
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, emac[:-1] + "=")  # not base64url
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, emac.replace(emac[0], "!", 1))
    assert not t.verify_skeleton(sk["room"], sk["rev"], digest, None)             # type: ignore[arg-type]
    other = ec.SecureTransport()                                                   # another edit token: another MAC
    other.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], "another-edit-token-1", ec.EditState.CUSTOM)
    assert not other.verify_skeleton(sk["room"], sk["rev"], digest, emac)
    normal_only = ec.SecureTransport()
    normal_only.begin(e["editToken"], ec.TokenState.CUSTOM, vectors["did"])      # the edit token text as NORMAL token
    assert not normal_only.signing_enabled and normal_only.sign_skeleton(sk["room"], sk["rev"], digest) is None
    assert t.sign_skeleton("Käfig/Ü", 7, 0xDEADBEEF) is not None                   # non-ASCII rooms are MACed as UTF-8
    assert t.verify_skeleton("Käfig/Ü", 7, 0xDEADBEEF, t.sign_skeleton("Käfig/Ü", 7, 0xDEADBEEF))


def test_begin_resets_everything_when_the_tokens_change(vectors):
    # POST /setup re-derives the keys on a running device: the old keys and the replay cache must be gone.
    e = vectors["edit"]
    post = e["post"]
    t = begun_edit(vectors)
    assert t.open_request(post["path"], post["envelope"].encode(), post["t"]).status == 200
    assert t.replay_entries(post["t"]) == 1
    assert t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"])                # edit token removed
    assert t.edit_state == ec.EditState.UNSET and not t.edit_ready and t.replay_entries(post["t"]) == 0
    assert t.open_request(post["path"], post["envelope"].encode(), post["t"]).code == "auth_failed"
    assert t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"]).status == 200
    assert t.begin(e["normalToken"], ec.TokenState.CUSTOM, vectors["did"], e["editToken"], ec.EditState.CUSTOM)
    assert t.open_request(post["path"], post["normalEnvelope"].encode(), post["t"]).code == "edit_required"
    assert t.begin("a-completely-new-token", ec.TokenState.CUSTOM, vectors["did"], e["editToken"], ec.EditState.CUSTOM)
    assert t.open_request(post["path"], post["envelope"].encode(), post["t"]).status == 200   # edit keys are independent
    assert t.open_request("/action", t.seal_request("/action", post["t"], "{}", bytes([3] * 12)), post["t"]).status == 200
