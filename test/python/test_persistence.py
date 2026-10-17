"""Boot counter, device id, riddle ids, identity, plan slices and skeletons survive restarts."""

from __future__ import annotations

import re

import escape_component as ec
from helpers import Manager, get, make_component


def start(directory, **kwargs):
    kwargs.setdefault("did", None)
    return make_component(storage=ec.FileStorage(str(directory)), background=False, **kwargs)


def test_boot_counter_increments_once_per_start_and_did_and_riddle_are_stable(tmp_path):
    c1 = start(tmp_path)
    boots, did, riddle = [c1.boot], c1.did, c1.riddle_id(0)
    assert re.fullmatch(r"[0-9a-f]{12}", did)
    assert re.fullmatch(r"riddle-[0-9a-f]{16}", riddle) and len(riddle) <= ec.EscapeConfig.MAX_RIDDLE_ID_LEN   # not a uuid4
    assert c1.uuid(0) == did + "-0"
    c1.close()
    for _ in range(3):
        c = start(tmp_path)
        boots.append(c.boot)
        assert (c.did, c.riddle_id(0)) == (did, riddle)          # generated ONCE and persisted
        c.close()
    assert boots == [1, 2, 3, 4]
    assert (tmp_path / "boot").read_text() == "4"


def test_generated_riddle_ids_differ_between_components_and_devices(tmp_path):
    a = start(tmp_path / "a", components=(("X", "R"), ("Y", "R")))
    b = start(tmp_path / "b", components=(("X", "R"),))
    assert len({a.riddle_id(0), a.riddle_id(1), b.riddle_id(0)}) == 3
    assert a.did != b.did
    a.close(); b.close()


def test_default_riddle_id_is_only_a_first_start_default(tmp_path):
    c = make_component((), storage=ec.FileStorage(str(tmp_path)), background=False, did="aaaaaaaaaaaa")
    c.add_component("Laser", "Raum A", "laser-v1")
    c.close()
    again = make_component((), storage=ec.FileStorage(str(tmp_path)), background=False, did="aaaaaaaaaaaa")
    again.add_component("Laser", "Raum A", "something-else")         # an operator's/first value wins
    assert again.riddle_id(0) == "laser-v1"
    long_default = make_component((), storage=ec.MemoryStorage(), background=False)
    long_default.add_component("L", "R", "x" * 50)
    assert long_default.riddle_id(0) == "x" * 32
    again.close(); long_default.close()


def test_identity_plan_and_skeleton_survive_a_restart(tmp_path):
    c = start(tmp_path, did="abababababab")
    m = Manager(c.listening_port).init()
    assert m.post("/config", {"id": 0, "name": "Neu", "room": "Raum Z", "riddleId": "new-v2"}).status == 200
    assert m.post("/plan", '{"id":0,"plan":{"lane":"A"}}').status == 200
    sk = '{"planId":"p"}'
    assert m.post("/plan-skeleton", '{"room":"Raum Z","baseRev":0,"sk":%s}' % sk).status == 200
    c.close()

    again = start(tmp_path, did="abababababab", components=(("Laser", "Raum A"),))
    assert (again.name(0), again.room(0), again.riddle_id(0)) == ("Neu", "Raum Z", "new-v2")   # operator values beat defaults
    m = Manager(again.listening_port).init()
    comp = m.get_json("/status.json")["components"][0]
    assert comp["plan"] == {"lane": "A"}
    assert m.get_json("/plan-skeleton.json")["rooms"] == [{"room": "Raum Z", "rev": 1, "hash": ec.hex8(ec.fnv1a32(sk))}]
    assert m.get_json("/plan-skeleton.json", "room=Raum%20Z")["sk"] == {"planId": "p"}
    again.close()


def test_skeletons_of_rooms_without_a_local_component_are_dropped_at_start(tmp_path):
    c = start(tmp_path, did="abababababab")
    m = Manager(c.listening_port).init()
    assert m.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":{"a":1}}').status == 200
    c.close()
    other = start(tmp_path, did="abababababab", components=(("Laser", "Raum B"),))
    assert other.store.count == 0
    assert not any(name.startswith("sk_") for name in __import__("os").listdir(tmp_path))
    other.close()


def test_damaged_state_does_not_prevent_starting(tmp_path):
    (tmp_path / "boot").write_text("garbage")
    (tmp_path / "skidx").write_text("not json")
    (tmp_path / "name0").write_bytes(b"\xff\xfe")
    c = start(tmp_path, did="abababababab")
    assert c.boot == 1 and c.store.count == 0 and c.name(0) == "Laser"     # undecodable name: the default
    assert get(c.listening_port, "/status.json").status == 200
    c.close()


def test_failing_storage_gives_a_random_boot_counter_and_still_runs():
    mem = ec.MemoryStorage()
    mem.fail_writes = True
    boots = set()
    for _ in range(4):
        c = make_component(storage=mem, background=False)
        boots.add(c.boot)
        assert get(c.listening_port, "/security.json").status == 200
        c.close()
    assert len(boots) > 1                                                  # random, not a stuck constant


def test_default_state_dir_is_per_port_and_unwritable_dir_falls_back_to_memory(tmp_path, monkeypatch):
    blocked = tmp_path / "file"
    blocked.write_text("x")
    c = ec.EscapeComponent(state_dir=str(blocked / "sub"), local_ip="127.0.0.1", http_port=0, udp_port=0, mdns_enabled=False)
    assert isinstance(c._storage, ec.MemoryStorage)                        # logged, but the device still works
    monkeypatch.setenv("HOME", str(tmp_path))
    assert ec._default_state_dir(8080) == str(tmp_path / ".escape-manager" / "python-8080")
