"""Skeleton store and storage (mirrors test/test_core/test_store.cpp)."""

from __future__ import annotations

import os

import escape_component as ec

SK_A = b'{"planId":"p1","layers":[{"id":"L1","lanes":[]}]}'
SK_B = b'{"planId":"p1","layers":[{"id":"L1","lanes":[{"id":"A"}]}]}'


def make_blob(room, rev, sk, hash_override=""):
    return ('{"room":"%s","rev":%d,"hash":"%s","sk":' % (room, rev, hash_override or ec.hex8(ec.fnv1a32(sk)))).encode() + sk + b"}"


def test_put_get_and_blob_format():
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    assert store.load()
    result, rev, digest = store.put("Raum-A", 0, SK_A)
    assert result == ec.SkeletonResult.STORED and rev == 1 and digest == ec.fnv1a32(SK_A)
    blob = store.get("Raum-A")
    found = ec.find_field(blob, "sk")
    assert found == (ec.Scan.FOUND, SK_A)                    # byte-for-byte
    assert ec.json_validate(blob)
    assert blob == make_blob("Raum-A", 1, SK_A)
    assert store.get("Other") is None


def test_revision_rules():
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    store.put("R", 0, SK_A)
    writes = mem.write_count
    # identical content: no write, no revision bump, works with any baseRev (retry-safe)
    assert store.put("R", 0, SK_A)[0] == ec.SkeletonResult.UNCHANGED
    result, rev, _ = store.put("R", 7, SK_A)
    assert result == ec.SkeletonResult.UNCHANGED and rev == 1
    assert mem.write_count == writes
    result, rev, digest = store.put("R", 0, SK_B)            # changed content with a stale baseRev
    assert result == ec.SkeletonResult.CONFLICT and rev == 1 and digest == ec.fnv1a32(SK_A)
    result, rev, _ = store.put("R", 1, SK_B)
    assert result == ec.SkeletonResult.STORED and rev == 2
    assert store.find("R").rev == 2
    assert store.put("R", 5, SK_B)[0] == ec.SkeletonResult.UNCHANGED
    assert store.put("New", 1, SK_B)[0] == ec.SkeletonResult.CONFLICT   # a room without skeleton has revision 0


def test_validation_and_limits():
    store = ec.SkeletonStore(ec.MemoryStorage())
    for bad in (b"", b"[]", b'"x"', b"{", b'{"a":01}', b"null", b"1", b"{} x"):
        assert store.put("R", 0, bad)[0] == ec.SkeletonResult.INVALID, bad
    assert store.put("", 0, SK_A)[0] == ec.SkeletonResult.INVALID
    assert store.put("x" * 33, 0, SK_A)[0] == ec.SkeletonResult.INVALID
    assert store.put("é" * 17, 0, SK_A)[0] == ec.SkeletonResult.INVALID           # 34 bytes
    big = b'{"x":"' + b"a" * ec.EscapeConfig.MAX_PLAN_SKELETON_LEN + b'"}'
    assert store.put("R", 0, big)[0] == ec.SkeletonResult.TOO_LARGE
    exact = b'{"x":"' + b"a" * (ec.EscapeConfig.MAX_PLAN_SKELETON_LEN - 8) + b'"}'
    assert len(exact) == ec.EscapeConfig.MAX_PLAN_SKELETON_LEN
    assert store.put("R", 0, exact)[0] == ec.SkeletonResult.STORED
    assert store.count == 1
    deep = b'{"a":' + b"[" * 16 + b"]" * 16 + b"}"
    assert store.put("D", 0, deep)[0] == ec.SkeletonResult.INVALID                 # depth limit 16 incl. the object


def test_persistence_and_room_limit():
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    for i in range(ec.EscapeConfig.MAX_SKELETON_ROOMS):
        assert store.put("Raum%d" % i, 0, SK_A)[0] == ec.SkeletonResult.STORED
    assert store.put("one-too-many", 0, SK_A)[0] == ec.SkeletonResult.ROOM_LIMIT
    store.put("Raum0", 1, SK_B)
    again = ec.SkeletonStore(mem)
    assert again.load()
    assert again.count == ec.EscapeConfig.MAX_SKELETON_ROOMS
    assert again.find("Raum0").rev == 2
    assert again.get("Raum0") == make_blob("Raum0", 2, SK_B)


def test_storage_failures_keep_state_consistent():
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    store.put("R", 0, SK_A)
    mem.fail_writes = True
    assert store.put("R", 1, SK_B)[0] == ec.SkeletonResult.STORAGE_ERROR
    assert store.find("R").rev == 1                           # RAM index unchanged
    assert store.put("New", 0, SK_B)[0] == ec.SkeletonResult.STORAGE_ERROR
    assert store.find("New") is None
    mem.fail_writes = False
    mem.capacity = 60                                         # smaller than any skeleton blob
    assert store.put("R", 1, SK_B)[0] == ec.SkeletonResult.STORAGE_ERROR
    mem.capacity = 0
    blob = store.get("R")
    assert ec.find_field(blob, "sk") == (ec.Scan.FOUND, SK_A)  # old blob still intact


def test_index_write_failure_rolls_back():
    class FailIndex(ec.MemoryStorage):
        def write(self, key, data):
            return False if key == "skidx" and self.fail_writes else super().write(key, data)

    mem = FailIndex()
    store = ec.SkeletonStore(mem)
    store.put("R", 0, SK_A)
    mem.fail_writes = True
    assert store.put("R", 1, SK_B)[0] == ec.SkeletonResult.STORAGE_ERROR
    assert (store.find("R").rev, store.find("R").hash) == (1, ec.fnv1a32(SK_A))
    assert store.put("N", 0, SK_B)[0] == ec.SkeletonResult.STORAGE_ERROR and store.find("N") is None


def test_adopt_rules():
    store = ec.SkeletonStore(ec.MemoryStorage())
    assert store.adopt(make_blob("R", 3, SK_A), "R") == ec.SkeletonResult.STORED
    assert store.find("R").rev == 3
    assert store.adopt(make_blob("R", 2, SK_B), "R") == ec.SkeletonResult.NOT_NEWER
    assert store.adopt(make_blob("R", 3, SK_A), "R") == ec.SkeletonResult.NOT_NEWER   # equal
    assert store.adopt(make_blob("R", 4, SK_B), "R") == ec.SkeletonResult.STORED
    assert store.find("R").rev == 4
    assert store.adopt(make_blob("R", 5, SK_A, "00000000"), "R") == ec.SkeletonResult.INVALID   # the hash lies
    assert store.adopt(make_blob("Other", 9, SK_A), "R") == ec.SkeletonResult.INVALID           # wrong room
    assert store.adopt(b'{"room":"R"}', "R") == ec.SkeletonResult.INVALID
    assert store.adopt(b"garbage", "R") == ec.SkeletonResult.INVALID
    assert store.adopt(make_blob("R", 0, SK_A), "R") == ec.SkeletonResult.INVALID               # rev 0
    assert store.adopt(make_blob("R", 5, b'["x"]'), "R") == ec.SkeletonResult.INVALID           # sk must be an object
    assert store.adopt(make_blob("R", 5, b"{" + b" " * 7000 + b"}"), "R") == ec.SkeletonResult.TOO_LARGE
    assert store.adopt(make_blob("R", 5, SK_A, "ABCDEF01"), "R") == ec.SkeletonResult.INVALID   # uppercase hex is not canonical
    assert store.find("R").rev == 4
    # the adopted blob is stored byte for byte
    spaced = b'{ "planId" : "p1" ,"x":1.50 }'
    assert store.adopt(make_blob("R", 9, spaced), "R") == ec.SkeletonResult.STORED
    assert ec.find_field(store.get("R"), "sk") == (ec.Scan.FOUND, spaced)


def test_adopt_equal_rev_tiebreak_converges():
    # Two devices wrote different content at the same revision: the larger hash wins on both.
    a_wins = ec.fnv1a32(SK_A) > ec.fnv1a32(SK_B)
    s1, s2 = ec.SkeletonStore(ec.MemoryStorage()), ec.SkeletonStore(ec.MemoryStorage())
    s1.adopt(make_blob("R", 2, SK_A), "R")
    s2.adopt(make_blob("R", 2, SK_B), "R")
    s1.adopt(make_blob("R", 2, SK_B), "R")
    s2.adopt(make_blob("R", 2, SK_A), "R")
    assert s1.find("R").hash == s2.find("R").hash == (ec.fnv1a32(SK_A) if a_wins else ec.fnv1a32(SK_B))
    assert ec.skeleton_is_newer(2, 5, 1, 9) and ec.skeleton_is_newer(2, 6, 2, 5) and not ec.skeleton_is_newer(2, 5, 2, 5)


def test_adopt_room_limit_and_key_collision():
    store = ec.SkeletonStore(ec.MemoryStorage())
    for i in range(ec.EscapeConfig.MAX_SKELETON_ROOMS):
        assert store.adopt(make_blob("R%d" % i, 1, SK_A), "R%d" % i) == ec.SkeletonResult.STORED
    assert store.adopt(make_blob("extra", 1, SK_A), "extra") == ec.SkeletonResult.ROOM_LIMIT


def test_keep_only_and_summary():
    mem = ec.MemoryStorage()
    store = ec.SkeletonStore(mem)
    store.put("A", 0, SK_A)
    store.put("B", 0, SK_B)
    before = store.summary_json()
    assert ec.json_validate(before)
    assert before == '[["%s",1,"%s"],["%s",1,"%s"]]' % (ec.room_key("A"), ec.hex8(ec.fnv1a32(SK_A)),
                                                       ec.room_key("B"), ec.hex8(ec.fnv1a32(SK_B)))
    store.keep_only(["B"])
    assert store.count == 1 and store.find("A") is None
    assert not mem.has("sk_" + ec.room_key("A"))              # blob erased
    assert before != store.summary_json()
    again = ec.SkeletonStore(mem)
    again.load()
    assert again.count == 1 and again.summary_hash() == store.summary_hash()
    assert ec.SkeletonStore(ec.MemoryStorage()).summary_json() == "[]"
    assert ec.SkeletonStore(ec.MemoryStorage()).summary_hash() == ec.fnv1a32("[]")


def test_damaged_index_is_survivable():
    mem = ec.MemoryStorage()
    mem.write("skidx", b'[{"r":"Good","v":2,"h":"0000abcd"},{"r":"","v":1,"h":"0000abcd"},{"r":"X","v":-1,"h":"zz"},5]')
    store = ec.SkeletonStore(mem)
    assert store.load()
    assert store.count == 1 and store.find("Good").rev == 2
    mem.write("skidx", b"not json")
    broken = ec.SkeletonStore(mem)
    assert not broken.load()
    assert broken.count == 0


def test_room_key_is_fnv_of_utf8():
    assert ec.room_key("Raum-A") == "64526e24"
    assert ec.room_key("Käfig/Ü") == "649bc819"


# ---- storage backends ----------------------------------------------------------------------------------------------

def test_file_storage_roundtrip_and_atomic_write(tmp_path, monkeypatch):
    fs = ec.FileStorage(str(tmp_path / "state"))
    assert fs.read("boot") is None
    assert fs.write("boot", b"5") and fs.read("boot") == b"5"
    assert fs.write("boot", b"6") and fs.read("boot") == b"6"
    assert sorted(os.listdir(tmp_path / "state")) == ["boot"]            # no temp files left behind
    # a failing rename must keep the old value and clean up
    def boom(*_a, **_k):
        raise OSError("disk full")
    monkeypatch.setattr(os, "replace", boom)
    assert not fs.write("boot", b"7")
    monkeypatch.undo()
    assert fs.read("boot") == b"6"
    assert sorted(os.listdir(tmp_path / "state")) == ["boot"]
    assert fs.erase("boot") and fs.read("boot") is None and not fs.erase("boot")


def test_file_storage_rejects_path_tricks(tmp_path):
    fs = ec.FileStorage(str(tmp_path))
    for key in ("../x", "a/b", "", ".", "..", "a.b", "x" * 16, "a b"):
        assert fs.read(key) is None
        assert not fs.write(key, b"x")
        assert not fs.erase(key)
    assert os.listdir(tmp_path) == []


def test_file_storage_survives_restart(tmp_path):
    mem_store = ec.SkeletonStore(ec.FileStorage(str(tmp_path)))
    mem_store.put("Raum A", 0, SK_A)
    reloaded = ec.SkeletonStore(ec.FileStorage(str(tmp_path)))
    assert reloaded.load() and reloaded.find("Raum A").rev == 1
    assert reloaded.get("Raum A") == make_blob("Raum A", 1, SK_A)
