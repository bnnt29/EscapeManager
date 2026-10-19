"""The strict JSON scanner and the bounded DOM (mirrors test/test_core/test_json.cpp in spirit)."""

from __future__ import annotations

import time

import pytest

import escape_component as ec


def fields(doc, *keys, depth=16):
    return ec.find_fields(doc if isinstance(doc, bytes) else doc.encode(), keys, depth)


# ---- find_field / raw slices -------------------------------------------------------------------------

def test_find_field_returns_raw_bytes_verbatim():
    doc = b'{"room":"R","baseRev":3,"sk":  {"a" : [1, 2.50 ,{"b":"\\u00e4\xc3\xa4"}] ,"z":null}  }'
    f = ec.find_fields(doc, ("room", "baseRev", "sk"))
    assert f["room"] == b'"R"' and f["baseRev"] == b"3"
    assert f["sk"] == b'{"a" : [1, 2.50 ,{"b":"\\u00e4\xc3\xa4"}] ,"z":null}'   # spacing, escapes, number text untouched


def test_find_field_first_duplicate_wins_and_missing():
    assert fields('{"a":1,"a":2}', "a")["a"] == b"1"
    assert fields('{"a":1}', "b") == {}
    assert ec.find_field(b'{"a":1}', "b") == (ec.Scan.MISSING, None)
    assert ec.find_field(b'{"a":1}', "a") == (ec.Scan.FOUND, b"1")
    assert ec.find_field(b"[1]", "a")[0] == ec.Scan.INVALID
    assert ec.find_field(b"", "a")[0] == ec.Scan.INVALID
    assert fields("{}", "a") == {}


def test_find_field_matches_escaped_keys_and_only_top_level():
    assert fields('{"\\u0061":5}', "a")["a"] == b"5"
    assert fields('{"x":{"a":1}}', "a") == {}      # nested members are not top-level members


@pytest.mark.parametrize("doc", [
    '{"a":1,}', '{"a":}', '{"a" 1}', '{a:1}', "{'a':1}", '{"a":1} x', '{"a":01}', '{"a":+1}', '{"a":.5}', '{"a":1.}',
    '{"a":1e}', '{"a":NaN}', '{"a":Infinity}', '{"a":tru}', '{"a":nul}', '{"a":"\\x"}', '{"a":"\\u12"}',
    '{"a":"\\ud800"}', '{"a":"\\udc00"}', '{"a":"\\ud800\\u0041"}', '{"a":"\\u0000"}', '{"a":"tab\there"}',
    '{"a":"line\nbreak"}', '{"a":1e999}', '{"a":-}', '{"a":[1,]}', '{"a":[,1]}', '{"a":{"b":1,}}', '{"a":"x}',
    '{"a":1', '{', '{"a"', '[1]', '"x"', '1', 'null', '{"a":1}\x0c', '\x0b{"a":1}', '{"a":\x0b1}',
])
def test_invalid_documents(doc):
    assert ec.find_fields(doc.encode(), ("a",)) is None, doc
    assert not ec.json_validate(doc.encode()) or doc in ('[1]', '"x"', '1', 'null')


@pytest.mark.parametrize("raw", [
    b'{"a":"\xc0\x80"}', b'{"a":"\xe0\x80\x80"}', b'{"a":"\xed\xa0\x80"}', b'{"a":"\xf4\x90\x80\x80"}',
    b'{"a":"\xff"}', b'{"a":"\xc3"}', b'{"a":"\x80"}', b"\xef\xbb\xbf" + b'{"a":1}',
])
def test_invalid_utf8_is_rejected(raw):
    assert ec.find_fields(raw, ("a",)) is None


@pytest.mark.parametrize("doc", [
    '{"a":"\\ud83d\\ude00"}', '{"a":"Käfig/Ü 😀"}', '{"a":-0}', '{"a":-1.5e+10}', '{"a":0.0}', '{"a":1E5}',
    ' \t\r\n{ \n"a" \t: \r 1 }\n ',
])
def test_valid_documents(doc):
    assert ec.find_fields(doc.encode(), ("a",)) is not None, doc


def test_depth_limit():
    ok = '{"a":' + "[" * 15 + "]" * 15 + "}"        # top object + 15 nested = 16 levels
    too_deep = '{"a":' + "[" * 16 + "]" * 16 + "}"
    assert fields(ok, "a") is not None
    assert fields(too_deep, "a") is None
    assert ec.json_validate(("[" * 16 + "]" * 16).encode())
    assert not ec.json_validate(("[" * 17 + "]" * 17).encode())
    assert ec.find_fields(b'{"a":[[1]]}', ("a",), 3) is not None
    assert ec.find_fields(b'{"a":[[[1]]]}', ("a",), 3) is None


def test_hostile_inputs_are_fast_and_never_raise():
    t0 = time.monotonic()
    for doc in (b"[" * 10_000, b"{" * 10_000, b'{"a":"' + b"a" * 200_000, b'{"a":"' + b"\\" * 100_001,
                b'{"a":' + b"1" * 100_000 + b"}", b'{"a":[' + b"1," * 50_000 + b"1]}", b"\x00" * 1000,
                b'{"a":"' + b"\xc3" * 50_000 + b'"}', b"[" * 5000 + b"]" * 5000):
        assert ec.find_fields(doc, ("a",)) is None or doc.startswith(b'{"a":[')
        assert not ec.json_validate(doc) or doc.startswith(b'{"a":[') or doc.startswith(b"[")
    assert time.monotonic() - t0 < 5.0
    with pytest.raises(ec.JsonError):
        ec.parse_json(b"[" * 10_000)


# ---- slices --------------------------------------------------------------------------------------------------

def test_slice_helpers():
    assert ec.slice_to_string(b'"a\\nb\\u00e4"') == "a\nb\u00e4"
    assert ec.slice_to_string(b'""') == ""
    assert ec.slice_to_string(b'"a" ') is None
    assert ec.slice_to_string(b"5") is None and ec.slice_to_string(None) is None and ec.slice_to_string(b'"') is None
    assert ec.slice_to_uint(b"0", 255) == 0
    assert ec.slice_to_uint(b"255", 255) == 255
    assert ec.slice_to_uint(b"256", 255) is None
    assert ec.slice_to_uint(b"4294967295", 0xFFFFFFFF) == 0xFFFFFFFF
    assert ec.slice_to_uint(b"4294967296", 0xFFFFFFFF) is None
    for bad in (b"", b"-1", b"+1", b"01", b"1.0", b"1e2", b" 1", b"1 ", b'"1"', b"12345678901", b"null", b"true"):
        assert ec.slice_to_uint(bad, 0xFFFFFFFF) is None, bad
    assert ec.slice_is_null(b"null") and not ec.slice_is_null(b"nul") and not ec.slice_is_null(None)
    kinds = {b"{}": "o", b"[1]": "a", b'"x"': "s", b"1": "n", b"-1": "n", b"true": "b", b"false": "b", b"null": "z", b"": ""}
    for raw, kind in kinds.items():
        assert ec.slice_kind(raw) == kind


# ---- DOM -----------------------------------------------------------------------------------------------------

def test_dom_basics():
    v = ec.parse_json('{"a":[1,2.5,"x",true,false,null],"b":{"c":"\\u00e4"},"a":9}')
    assert v["a"] == [1.0, 2.5, "x", True, False, None]     # first duplicate wins
    assert v["b"]["c"] == "\u00e4"
    assert ec.parse_json(" 5 ") == 5.0
    assert ec.parse_json('"x"') == "x"
    assert ec.parse_json(b"[]") == [] and ec.parse_json("{}") == {}


@pytest.mark.parametrize("text", ["", "{", '{"a":1} {', "[1,]", '{"a":01}', "nul", '"\x01"', "{\"a\":\"\\ud800\"}"])
def test_dom_rejects(text):
    with pytest.raises(ec.JsonError):
        ec.parse_json(text)


def test_dom_limits():
    ec.parse_json("[" * 8 + "]" * 8)                         # default depth 8
    with pytest.raises(ec.JsonError):
        ec.parse_json("[" * 9 + "]" * 9)
    ec.parse_json("[" + ",".join(["0"] * 159) + "]")         # 160 nodes including the root
    with pytest.raises(ec.JsonError):
        ec.parse_json("[" + ",".join(["0"] * 160) + "]")
    ec.parse_json("[" + ",".join(["0"] * 4000) + "]", 8, 4001)


def test_json_int_and_text():
    assert ec.json_int(5.0, 0, 255) == 5 and ec.json_int(-0.0, 0, 255) == 0 and ec.json_int(1e1, 0, 255) == 10
    for bad in (1.5, 256.0, -1.0, "1", True, None, float("nan"), float("inf"), [1]):
        assert ec.json_int(bad, 0, 255) is None, bad
    assert ec.json_text_loose("x") == "x" and ec.json_text_loose(70.0) == "70" and ec.json_text_loose(True) == "true"
    assert ec.json_text_loose(None) == "" and ec.json_text_loose([1]) == "" and ec.json_text_loose({}) == ""
    assert ec.json_text_loose(0.1) == "0.1" and ec.json_text_loose(1.5e20) == "1.5e+20"


def test_escape_output_is_always_valid_json():
    nasty = 'q"b\\ \n\r\t\x01\x1f \x7f \u2028 \ud800 é 😀'   # NUL never reaches the output: bounded() cuts at it
    doc = '{"a":%s}' % ec.jstr(nasty)
    assert ec.json_validate(doc)
    back = ec.parse_json(doc)["a"]
    assert back == nasty.replace("\ud800", "\ufffd")
    assert ec.bounded("Käfig" * 20, 32).encode().__len__() <= 32
    assert ec.bounded("a\x00b", 10) == "a"
    assert ec.bounded("x" * 10, 4) == "xxxx" and ec.bounded(None, 4) == ""
    assert ec.bounded("é" * 3, 5) == "éé"                    # never cuts inside a character
