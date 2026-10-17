"""Documents and the five mutating handlers (mirrors test/test_core/test_protocol.cpp)."""

from __future__ import annotations

import json

import escape_component as ec
from helpers import FakeHost


def info(**overrides):
    d = ec.DeviceInfo(did="aabbccddeeff", ui_hash="0badc0de", ip="192.168.1.20", port=80, boot=5, seq=17,
                      now_ms=123456, battery=87)
    for k, v in overrides.items():
        setattr(d, k, v)
    return d


def is_code(result, status, code):
    body = json.loads(result.body)
    return result.status == status and body.get("code") == code and body.get("ok") is False


# ---- documents -----------------------------------------------------------------------------------------

def test_status_doc_structure():
    host = FakeHost()
    host.tip = "Dreh den Schluessel"
    host.feed = "http://192.168.1.5/stream"
    host.state_text = "Schritt 2"
    host.plans[0] = '{"planId":"p","layer":"L1"}'
    doc = ec.build_status_doc(host, info())
    v = json.loads(doc)
    assert v["proto"] == 2 and v["pmin"] == 2 and v["did"] == "aabbccddeeff" and v["uih"] == "0badc0de"
    assert v["seq"] == 17 and v["battery"] == 87 and v["token"] == "default" and v["boot"] == 5
    assert v["ip"] == "192.168.1.20" and v["port"] == 80 and v["up"] == 123456 and "fw" in v and "ui" in v
    comps = v["components"]
    assert len(comps) == 2
    c0, c1 = comps
    assert c0["name"] == "Laser" and c0["riddleId"] == "laser-v1" and c0["uuid"] == "aabbccddeeff-0" and c0["id"] == 0
    assert c0["planActions"] == ["reset", "complete"]
    assert c0["errors"] == ["sensor_timeout"] and c0["actions"] == ["open"]
    assert c0["puzzle"] == {"step": 2, "totalSteps": 5, "state": "Schritt 2", "isHtml": False}
    assert c0["feed"] == "http://192.168.1.5/stream" and c0["tip"] == "Dreh den Schluessel"
    assert c0["plan"] == {"planId": "p", "layer": "L1"}              # plan slice embedded as an object
    assert c0["customConfig"][0] == {"key": "brightness", "type": "range", "min": 0, "max": 100, "value": "50"}
    assert c0["customConfig"][1] == {"key": "label", "type": "text", "maxLength": 8, "value": ""}
    assert c0["evtSeq"] == 3
    assert "puzzle" not in c1 and "evtSeq" not in c1 and c1["planActions"] == []
    for gone in ("ip", "battery", "slave", "upTimeMs"):               # removed in proto 2: per-component device fields
        assert gone not in c0
    # exact byte layout of the head (key order is part of the format)
    assert doc.startswith('{"proto":2,"pmin":2,"fw":"2.0.0","ui":"2.0.0","uih":"0badc0de","did":"aabbccddeeff","ip":"192.168.1.20",'
                          '"port":80,"boot":5,"seq":17,"up":123456,"battery":87,"token":"default","components":[{"id":0,')


def test_status_plan_slice_is_embedded_verbatim():
    host = FakeHost()
    host.plans[0] = '{"b":  1, "a":[1,2.50,"\\u00e4"]}'
    assert '"plan":{"b":  1, "a":[1,2.50,"\\u00e4"]}' in ec.build_status_doc(host, info())


def test_status_battery_convention():
    host = FakeHost()
    for value, expected in ((0, None), (-1, None), (-100, None), (1, 1), (87, 87), (250, 100)):
        v = json.loads(ec.build_status_doc(host, info(battery=value)))
        assert v.get("battery") == expected, value


def test_status_doc_sanitizes_hostile_component_data():
    host = FakeHost()
    host.names[0] = 'Evil"<script>\n\\\ud800' + "é" * 40
    host.feed = "javascript:alert(1)"
    host.tip = "x" * 2000
    host.plans[0] = "{broken json"        # an invalid slice must never poison the document
    host.state_text = "<b>" + "y" * 5000
    doc = ec.build_status_doc(host, info())
    assert ec.json_validate(doc)           # always valid JSON, valid UTF-8
    c0 = json.loads(doc)["components"][0]
    assert "feed" not in c0                # not http(s)
    assert "plan" not in c0
    assert len(c0["tip"]) == ec.EscapeConfig.MAX_TIP_LEN
    assert len(c0["puzzle"]["state"]) == ec.EscapeConfig.MAX_STATE_LEN
    assert len(c0["name"].encode()) <= ec.EscapeConfig.MAX_NAME_LEN


def test_status_limits_lists_and_fields():
    class Many(FakeHost):
        def snapshot(self, index):
            s = super().snapshot(index)
            s.errors = ["e%d" % i for i in range(10)]
            s.actions = ["a" * 40 + str(i) for i in range(20)]
            s.custom_config = [ec.CustomConfigDef("k%d" % i, "select", "v", options=["o%d" % j * 10 for j in range(10)])
                               for i in range(9)]
            return s

    c0 = json.loads(ec.build_status_doc(Many(), info()))["components"][0]
    assert len(c0["errors"]) == 4 and len(c0["actions"]) == 8 and all(len(a) <= 24 for a in c0["actions"])
    assert len(c0["customConfig"]) == 4 and len(c0["customConfig"][0]["options"]) == 6
    assert all(len(o.encode()) <= 16 for o in c0["customConfig"][0]["options"])


def test_security_doc():
    doc = json.loads(ec.build_security_doc(info(token=ec.TokenState.INVALID, writable=False)))
    assert doc["token"] == "invalid" and doc["writable"] is False and doc["time"] == 123456
    assert doc["kdf"] == {"alg": "pbkdf2-sha256", "iter": 2048}
    assert doc["limits"] == {"body": 12288, "skeleton": 6144, "plan": 512, "name": 32, "room": 32, "riddle": 32}
    assert doc["caps"] == ["plan", "cfg"] and doc["strictGet"] is False and doc["allowTokenInUrl"] is True
    assert doc["proto"] == 2 and doc["pmin"] == 2 and doc["fw"] and doc["ui"] and doc["did"] == "aabbccddeeff"


def test_peers_doc():
    table = ec.PeerTable()
    doc = ec.build_announcement_doc("112233445566", "192.168.1.30", 8080, 2, 4, 99, 2, "1a2b3c4d", "[]", 0xDEADBEEF)
    a = ec.parse_announcement(doc.encode())
    assert a is not None
    assert table.ingest(a, "192.168.1.30", "000000000001", 1000) == ec.IngestResult.ACCEPTED
    v = json.loads(ec.build_peers_doc(table, info(now_ms=3500), 0x01020304))
    assert v["proto"] == 2
    assert v["self"] == {"did": "aabbccddeeff", "ip": "192.168.1.20", "port": 80, "proto": 2, "seq": 17,
                         "uih": "0badc0de", "skh": "01020304", "age": 0}
    p = v["peers"][0]
    assert p == {"did": "112233445566", "ip": "192.168.1.30", "port": 8080, "proto": 2, "seq": 99, "uih": "1a2b3c4d",
                 "skh": "deadbeef", "age": 2500}


def test_skeleton_index_doc():
    store = ec.SkeletonStore(ec.MemoryStorage())
    assert json.loads(ec.build_skeleton_index_doc(store)) == {"proto": 2, "rooms": []}
    store.put("Raum A", 0, b'{"a":1}')
    v = json.loads(ec.build_skeleton_index_doc(store))
    assert v["rooms"] == [{"room": "Raum A", "rev": 1, "hash": ec.hex8(ec.fnv1a32(b'{"a":1}'))}]


# ---- /action, /plan-action -------------------------------------------------------------------------------------

def test_action():
    host = FakeHost()
    r = ec.handle_action(host, '{"id":0,"action":"open"}')
    assert (r.status, r.body) == (200, '{"ok":true}')
    assert host.actions_applied == ["open"] and len(host.events) == 1 and host.dirty > 0
    assert host.events[0] == 'Aktion "open" ausgefuehrt'
    assert ec.handle_action(host, '{"action":"x"}').status == 200       # id defaults to 0
    host.action_result = False
    assert is_code(ec.handle_action(host, '{"id":0,"action":"x"}'), 422, "rejected")
    assert is_code(ec.handle_action(host, '{"id":2,"action":"x"}'), 400, "bad_id")
    assert is_code(ec.handle_action(host, '{"id":256,"action":"x"}'), 400, "bad_id")    # no uint8 wrap-around
    assert is_code(ec.handle_action(host, '{"id":"1","action":"x"}'), 400, "bad_id")    # strings are not ids
    assert is_code(ec.handle_action(host, '{"id":1.5,"action":"x"}'), 400, "bad_id")
    assert is_code(ec.handle_action(host, '{"id":-1,"action":"x"}'), 400, "bad_id")
    assert is_code(ec.handle_action(host, '{"id":null,"action":"x"}'), 400, "bad_id")
    assert is_code(ec.handle_action(host, '{"id":0}'), 400, "bad_action")
    assert is_code(ec.handle_action(host, '{"id":0,"action":5}'), 400, "bad_action")
    assert is_code(ec.handle_action(host, '{"id":0,"action":""}'), 400, "bad_action")
    assert is_code(ec.handle_action(host, '{"id":0,"action":"%s"}' % ("a" * 25)), 400, "bad_action")
    assert ec.handle_action(host, '{"id":0,"action":"%s"}' % ("a" * 24)).status == 422    # 24 is allowed
    assert is_code(ec.handle_action(host, ""), 400, "bad_request")
    assert is_code(ec.handle_action(host, "[]"), 400, "bad_request")
    assert is_code(ec.handle_action(host, "{broken"), 400, "bad_request")
    assert is_code(ec.handle_action(host, " " * 3000), 413, "too_large")
    flood = '{"id":0,"x":[' + "0," * 1000 + "0]}"                                       # DOM limits, not memory exhaustion
    assert ec.handle_action(host, flood).status in (400, 413)
    assert ec.handle_action(host, b'{"id":0,"action":"\xff"}').status == 400             # invalid UTF-8


def test_action_length_limit_counts_bytes():
    host = FakeHost()
    assert ec.handle_action(host, '{"id":0,"action":"%s"}' % ("é" * 12)).status == 200      # 24 bytes
    assert is_code(ec.handle_action(host, '{"id":0,"action":"%s"}' % ("é" * 13)), 400, "bad_action")  # 26 bytes


def test_plan_action():
    host = FakeHost()
    assert ec.handle_plan_action(host, '{"id":0,"action":"reset"}').status == 200
    assert ec.handle_plan_action(host, '{"id":0,"action":"complete"}').status == 200
    assert is_code(ec.handle_plan_action(host, '{"id":1,"action":"reset"}'), 422, "unsupported")   # mask 0
    assert is_code(ec.handle_plan_action(host, '{"id":0,"action":"explode"}'), 400, "bad_action")
    assert is_code(ec.handle_plan_action(host, '{"id":0}'), 400, "bad_action")
    assert is_code(ec.handle_plan_action(host, '{"id":9,"action":"reset"}'), 400, "bad_id")
    host.plan_action_result = False
    assert is_code(ec.handle_plan_action(host, '{"id":0,"action":"reset"}'), 422, "rejected")
    host.mask[0] = 1  # only reset announced
    assert is_code(ec.handle_plan_action(host, '{"id":0,"action":"complete"}'), 422, "unsupported")


# ---- /config -------------------------------------------------------------------------------------------------------

def test_config_is_atomic():
    host = FakeHost()
    # valid + invalid together: nothing may be applied
    assert is_code(ec.handle_config(host, '{"id":0,"config":{"brightness":"70","label":"waytoolongvalue"}}'), 400, "bad_request")
    assert host.set_calls == 0
    assert is_code(ec.handle_config(host, '{"id":0,"name":"X","config":{"brightness":"101"}}'), 400, "bad_request")
    assert host.set_calls == 0 and host.names[0] == "Laser"
    # identity valid but riddleId invalid: nothing applied (used to apply the identity first)
    bad_riddle = '{"id":0,"name":"Neu","room":"Raum Z","riddleId":"%s"}' % ("r" * 33)
    assert is_code(ec.handle_config(host, bad_riddle), 400, "bad_request")
    assert host.set_calls == 0 and host.names[0] == "Laser"
    assert is_code(ec.handle_config(host, '{"id":0,"name":"OnlyName"}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"room":"OnlyRoom"}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"name":"","room":"R"}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"name":5,"room":"R"}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"name":"%s","room":"R"}' % ("n" * 33)), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"config":{"nokey":"1"}}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":1,"config":{"brightness":"1"}}'), 400, "bad_request")  # component without config
    assert is_code(ec.handle_config(host, '{"id":0,"config":[1]}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"riddleId":""}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"riddleId":7}'), 400, "bad_request")
    assert host.set_calls == 0
    r = ec.handle_config(host, '{"id":0,"name":"Neu","room":"Raum Z","riddleId":"new-v2","config":{"brightness":70,"label":"ok"}}')
    assert r.status == 200
    assert (host.names[0], host.rooms[0], host.riddle[0]) == ("Neu", "Raum Z", "new-v2")
    assert host.last_cfg == ("label", "ok")                       # keys are applied in sorted order; numbers accepted as text
    assert len(host.events) == 1 and host.events[0] == "Konfiguration geaendert, Name/Raum geaendert, Raetsel-ID geaendert"
    assert ec.handle_config(host, '{"id":0,"slave":true}').status == 200   # no `slave` field any more: ignored
    assert ec.handle_config(host, '{"id":0}').status == 200
    assert ec.handle_config(host, '{"id":0,"config":{}}').status == 200
    assert ec.handle_config(host, '{"id":1,"config":{}}').status == 200   # empty config for a component without schema


def test_config_numbers_booleans_and_null_follow_the_loose_text_rules():
    host = FakeHost()
    host.cfg.append(ec.CustomConfigDef("flag", "select", "true", options=["true", "false"]))
    assert ec.handle_config(host, '{"id":0,"config":{"flag":true}}').status == 200 and host.last_cfg == ("flag", "true")
    assert ec.handle_config(host, '{"id":0,"config":{"brightness":70.0}}').status == 200 and host.last_cfg == ("brightness", "70")
    assert is_code(ec.handle_config(host, '{"id":0,"config":{"brightness":70.5}}'), 400, "bad_request")
    assert is_code(ec.handle_config(host, '{"id":0,"config":{"brightness":null}}'), 400, "bad_request")  # "" is no integer


def test_config_range_value_strictness():
    d = ec.CustomConfigDef("r", "range", "0", -5, 5)
    for ok in ("-5", "0", "5"):
        assert ec.validate_custom_config_value(d, ok), ok
    for bad in ("6", "-6", "", "-", "+1", "1.0", "1e1", " 1", "1 ", "0x1", "abc", "99999999999999", "١"):
        assert not ec.validate_custom_config_value(d, bad), bad
    s = ec.CustomConfigDef("s", "select", "easy", options=["easy", "hard"])
    assert ec.validate_custom_config_value(s, "hard")
    assert not ec.validate_custom_config_value(s, "medium") and not ec.validate_custom_config_value(s, "")
    t = ec.CustomConfigDef("t", "text", "", text_max_len=3)
    assert ec.validate_custom_config_value(t, "abc") and ec.validate_custom_config_value(t, "")
    assert not ec.validate_custom_config_value(t, "abcd") and not ec.validate_custom_config_value(t, "äbc")  # 4 bytes
    long = ec.CustomConfigDef("t", "text", "", text_max_len=500)
    assert ec.validate_custom_config_value(long, "x" * 48) and not ec.validate_custom_config_value(long, "x" * 49)


# ---- /plan ---------------------------------------------------------------------------------------------------------

def test_plan_slice():
    host = FakeHost()
    assert ec.handle_plan(host, '{"id":0,"plan":{"planId":"p","layer":"L1","lane":"A"}}').status == 200
    assert host.plans[0] == '{"planId":"p","layer":"L1","lane":"A"}'                    # verbatim
    assert ec.handle_plan(host, '{"id":0,"plan":{ "k" :  [1 , 2.50 ] }}').status == 200
    assert host.plans[0] == '{ "k" :  [1 , 2.50 ] }'                                    # whitespace and number text untouched
    assert ec.handle_plan(host, '{"id":0,"plan":null}').status == 200 and host.plans[0] == ""
    assert ec.handle_plan(host, '{"id":0}').status == 200                              # missing = clear
    assert is_code(ec.handle_plan(host, '{"id":0,"plan":[1]}'), 400, "bad_request")
    assert is_code(ec.handle_plan(host, '{"id":0,"plan":"x"}'), 400, "bad_request")
    assert is_code(ec.handle_plan(host, '{"id":0,"plan":{"a":"%s"}}' % ("x" * 520)), 413, "too_large")
    assert is_code(ec.handle_plan(host, '{"id":0,"plan":{"a":"%s"}}' % ("x" * 2000)), 413, "too_large")
    assert is_code(ec.handle_plan(host, '{"id":7,"plan":null}'), 400, "bad_id")
    assert is_code(ec.handle_plan(host, '{"id":"0","plan":null}'), 400, "bad_id")
    assert is_code(ec.handle_plan(host, '{"id":256,"plan":null}'), 400, "bad_id")
    assert is_code(ec.handle_plan(host, '{"id":0,"plan":{broken}'), 400, "bad_request")
    assert is_code(ec.handle_plan(host, ""), 400, "bad_request")
    exact = '{"a":"%s"}' % ("x" * (ec.EscapeConfig.MAX_PLAN_LEN - 8))
    assert len(exact) == ec.EscapeConfig.MAX_PLAN_LEN
    assert ec.handle_plan(host, '{"id":1,"plan":%s}' % exact).status == 200
    assert len(host.plans[1]) == ec.EscapeConfig.MAX_PLAN_LEN
    plan_with_unicode = '{"n":"Käfig \\u00fc 😀"}'
    assert ec.handle_plan(host, '{"id":0,"plan":%s}' % plan_with_unicode).status == 200
    assert host.plans[0] == plan_with_unicode


# ---- /plan-skeleton -------------------------------------------------------------------------------------------------

def test_skeleton_handler():
    host = FakeHost()
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    sk = '{"planId":"p","layers":[]}'
    r = ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":0,"sk":%s}' % sk)
    assert r.status == 200
    v = json.loads(r.body)
    assert v["rev"] == 1 and v["hash"] == ec.hex8(ec.fnv1a32(sk))
    assert len(host.events) == 1                                   # the component in that room was notified
    r = ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":0,"sk":%s}' % sk)   # same content: idempotent
    assert r.status == 200 and len(host.events) == 1
    sk2 = '{"planId":"p","layers":[1]}'
    r = ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":0,"sk":%s}' % sk2)   # stale writer
    assert is_code(r, 409, "rev_conflict")
    assert json.loads(r.body)["rev"] == 1 and json.loads(r.body)["hash"] == ec.hex8(ec.fnv1a32(sk))
    assert ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":1,"sk":%s}' % sk2).status == 200
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Nowhere","baseRev":0,"sk":%s}' % sk), 422, "room_not_hosted")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Raum A","sk":%s}' % sk), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":2,"sk":[1]}'), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":2,"sk":{"x":"%s"}}' % ("a" * 7000)), 413, "too_large")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"","baseRev":0,"sk":{}}'), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Raum A","baseRev":-1,"sk":{}}'), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"%s","baseRev":0,"sk":{}}' % ("r" * 33)), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, ""), 400, "bad_request")
    assert is_code(ec.handle_plan_skeleton(host, store, " " * 7000), 413, "too_large")
    mem.fail_writes = True
    assert is_code(ec.handle_plan_skeleton(host, store, '{"room":"Raum B","baseRev":0,"sk":%s}' % sk), 500, "storage_full")
    assert ec.hosted_rooms(host) == ["Raum A", "Raum B"]               # hosted rooms follow identity changes
    host.rooms[1] = "Raum A"
    assert ec.hosted_rooms(host) == ["Raum A"]


def test_skeleton_raw_bytes_are_preserved_verbatim():
    host = FakeHost()
    store = ec.SkeletonStore(ec.MemoryStorage())
    sk = '{ "z" : 1.50 ,"a":[ 1 , "\\u00e4", "ä" ] }'
    body = '{"baseRev":0,"room":"Raum A","sk":%s}' % sk
    assert ec.handle_plan_skeleton(host, store, body).status == 200
    blob = store.get("Raum A")
    assert blob == ('{"room":"Raum A","rev":1,"hash":"%s","sk":%s}' % (ec.hex8(ec.fnv1a32(sk)), sk)).encode()
    assert ec.fnv1a32(sk.encode()) == ec.fnv1a32(sk)


def test_skeleton_room_names_count_bytes_and_may_be_unicode():
    host = FakeHost()
    host.rooms[0] = "Käfig/Ü"
    store = ec.SkeletonStore(ec.MemoryStorage())
    assert ec.handle_plan_skeleton(host, store, '{"room":"Käfig/Ü","baseRev":0,"sk":{"a":1}}'.encode()).status == 200
    assert store.find("Käfig/Ü").rev == 1
    assert json.loads(ec.build_skeleton_index_doc(store))["rooms"][0]["room"] == "Käfig/Ü"


def test_timing_helpers():
    assert ec.is_heartbeat_due(10000, 0, 4000)
    assert not ec.is_heartbeat_due(3999, 0, 4000)
    assert ec.is_heartbeat_due(100, 0xFFFFFF00, 300)             # across the wrap
    assert not ec.is_heartbeat_due(100, 0xFFFFFF00, 4000)
    assert ec.is_change_broadcast_due(1000, 0, True)
    assert not ec.is_change_broadcast_due(100, 0, True)
    assert not ec.is_change_broadcast_due(1000, 0, False)
