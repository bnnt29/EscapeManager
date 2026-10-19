"""Two (or more) complete Python devices in one process on loopback: discovery, skeleton sync, mDNS.

They share the discovery port 14210 with whatever else runs on the machine; a random per-run token keeps
foreign announcements out (they fail the MAC check).
"""

from __future__ import annotations

import json
import socket
import struct
import time

import escape_component as ec
from helpers import DISCOVERY_PORT, Manager, wait_for

SK1 = '{"planId":"p1","layers":[{"id":"L1","lanes":[]}]}'
SK2 = '{"planId":"p1","layers":[{"id":"L1","lanes":[{"id":"A"}]}]}'


def pair(component, room_a="Raum A", room_b="Raum A", **kwargs):
    a = component(((("Laser", room_a)),), udp_port=DISCOVERY_PORT, **kwargs)
    b = component(((("Kamera", room_b)),), udp_port=DISCOVERY_PORT, **kwargs)
    return a, b


def test_devices_discover_each_other(component):
    a, b = pair(component)
    assert wait_for(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, 8)
    pa = a.peers()[0]
    assert (pa.did, pa.ip, pa.port) == (b.did, "127.0.0.1", b.listening_port)
    assert pa.proto == 2 and pa.pmin == 2 and pa.boot == b.boot
    ma, mb = Manager(a.listening_port).init(), Manager(b.listening_port).init()
    peers = ma.get_json("/peers.json")
    assert peers["self"]["did"] == a.did and peers["self"]["age"] == 0
    assert [p["did"] for p in peers["peers"]] == [b.did] and peers["peers"][0]["port"] == b.listening_port
    assert 0 <= peers["peers"][0]["age"] < 5000 and peers["peers"][0]["skh"] == ec.hex8(ec.fnv1a32("[]"))
    assert [p["did"] for p in mb.get_json("/peers.json")["peers"]] == [a.did]
    assert a.announcements_sent > 0


def test_peer_with_another_token_is_ignored(component):
    a = component(udp_port=DISCOVERY_PORT)
    b = component(udp_port=DISCOVERY_PORT, auth_token="a-different-venue-token-xyz")
    assert wait_for(lambda: a.announcements_sent > 0 and b.announcements_sent > 0, 5)
    time.sleep(1.0)
    assert a.peers() == [] and b.peers() == []                    # their announcements fail the MAC check


def test_peer_expires_without_announcements(component):
    a, b = pair(component)
    assert wait_for(lambda: len(a.peers()) == 1, 8)
    b.close()                                                  # B falls silent
    last_seen = a.peers()[0].last_seen_ms
    with a._lock:                                              # PEER_TIMEOUT_MS after the last accepted announcement it is gone
        a._peers.expire_stale(last_seen + ec.EscapeConfig.PEER_TIMEOUT_MS)
        assert a._peers.count == 1
        a._peers.expire_stale(last_seen + ec.EscapeConfig.PEER_TIMEOUT_MS + 1)
    assert a.peers() == []


def test_skeleton_written_to_one_device_reaches_the_other_and_back(component):
    a, b = pair(component)
    ma, mb = Manager(a.listening_port).init(), Manager(b.listening_port).init()
    assert wait_for(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, 8)
    r = ma.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1)
    assert r.status == 200 and r.body["rev"] == 1
    assert wait_for(lambda: b.store.find("Raum A") is not None, 10), "B never adopted A's skeleton"
    assert b.store.find("Raum A").rev == 1 and b.store.find("Raum A").hash == a.store.find("Raum A").hash == ec.fnv1a32(SK1)
    assert b.store.get("Raum A") == a.store.get("Raum A")          # byte-identical blobs
    assert ec.find_field(b.store.get("Raum A"), "sk") == (ec.Scan.FOUND, SK1.encode())
    # B updates the plan on top of revision 1; A catches up through the same path
    r = mb.post("/plan-skeleton", '{"room":"Raum A","baseRev":1,"sk":%s}' % SK2)
    assert r.status == 200 and r.body["rev"] == 2
    assert wait_for(lambda: a.store.find("Raum A").rev == 2, 10), "A never adopted B's revision"
    assert a.store.get("Raum A") == b.store.get("Raum A")
    # a stale writer (still on rev 1) is told about the conflict instead of overwriting
    r = ma.post("/plan-skeleton", '{"room":"Raum A","baseRev":1,"sk":{"planId":"other"}}')
    assert r.status == 409 and r.body["code"] == "rev_conflict" and r.body["rev"] == 2
    # the sync shows up in the component log
    comp = ma.get_json("/status.json")["components"][0]
    assert "Raum-Ablaufplan" in comp["evtMsg"]
    # skeleton summaries are announced
    assert wait_for(lambda: {p["skh"] for p in ma.get_json("/peers.json")["peers"]} == {ec.hex8(a.store.summary_hash())}, 8)


def test_skeleton_only_syncs_to_devices_hosting_that_room(component):
    a = component(((("Laser", "Raum A"),)), udp_port=DISCOVERY_PORT)
    b = component(((("Kamera", "Raum B"),)), udp_port=DISCOVERY_PORT)
    ma = Manager(a.listening_port).init()
    assert wait_for(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, 8)
    assert ma.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1).status == 200
    time.sleep(3.0)
    assert b.store.count == 0                                    # B hosts no component in Raum A
    assert not b.sync_in_flight


def test_equal_revision_tiebreak_converges_across_devices(component):
    a, b = pair(component)
    # both write revision 1 with different content before they hear of each other's write
    with a._lock, b._lock:
        a.store.put("Raum A", 0, SK1.encode())
        b.store.put("Raum A", 0, SK2.encode())
        a._bump(); b._bump()
    winner = max(ec.fnv1a32(SK1), ec.fnv1a32(SK2))
    assert wait_for(lambda: a.store.find("Raum A").hash == b.store.find("Raum A").hash == winner, 15)
    assert a.store.get("Raum A") == b.store.get("Raum A")


def test_failed_sync_backs_off_per_peer_and_room(component, monkeypatch):
    a, b = pair(component)
    mb = Manager(b.listening_port).init()
    calls = []
    real = ec.http_get
    def failing(*args, **kwargs):
        calls.append(time.monotonic())
        return None
    monkeypatch.setattr(ec, "http_get", failing)
    assert wait_for(lambda: len(a.peers()) == 1, 8)
    assert mb.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1).status == 200
    assert wait_for(lambda: len(calls) >= 1, 8)
    time.sleep(5.0)                                              # announcements keep coming, but the 10 s back-off holds
    assert len(calls) == 1 and a.store.find("Raum A") is None
    monkeypatch.setattr(ec, "http_get", real)
    # the back-off expires: the next announcement retries and succeeds
    a._sync_failures = {k: v - 11000 for k, v in a._sync_failures.items()}
    assert wait_for(lambda: a.store.find("Raum A") is not None, 10)


def test_sync_rejects_a_peer_that_lies(component, monkeypatch):
    a, b = pair(component)
    mb = Manager(b.listening_port).init()
    assert wait_for(lambda: len(a.peers()) == 1, 8)
    real = ec.http_get
    def lying(ip, port, target, timeout, max_body):
        status, body = real(ip, port, target, timeout, max_body)
        return status, body.replace(b'"layers":[', b'"layers":[1,')       # content no longer matches the framed MAC
    monkeypatch.setattr(ec, "http_get", lying)
    assert mb.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1).status == 200
    time.sleep(3.0)
    assert a.store.find("Raum A") is None


# ---- skeleton sync with an edit token (PROTOCOL.md 3.1; mirrors test_skeleton_sync_with_edit_token_rejects_planted_plans) ----

EDIT_TOKEN = "edit-token-for-the-tests"


def test_skeleton_sync_with_edit_token_rejects_planted_plans(component, monkeypatch):
    # A and B share both tokens. C only knows the normal token (an attacker, or a device that was never given
    # the edit token) and tries to push a newer plan to them through discovery.
    a = component((("Laser", "Raum A"),), udp_port=DISCOVERY_PORT, edit_token=EDIT_TOKEN)
    b = component((("Kamera", "Raum A"),), udp_port=DISCOVERY_PORT, edit_token=EDIT_TOKEN)
    assert wait_for(lambda: len(a.peers()) == 1 and len(b.peers()) == 1, 8)
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    r = editor.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1, role=ec.KeyRole.EDIT)
    assert r.status == 200 and r.body["rev"] == 1
    assert wait_for(lambda: b.store.find("Raum A") is not None, 12), "a signed skeleton must propagate between edit-token devices"
    assert b.store.find("Raum A").rev == 1
    assert b.store.get("Raum A") == a.store.get("Raum A")                   # byte-identical, emac included
    assert ec.find_field(b.store.get("Raum A"), "emac")[0] == ec.Scan.FOUND

    # The rogue device stores a much newer skeleton and announces it.
    c = component((("Rogue", "Raum A"),), udp_port=DISCOVERY_PORT)
    mc = Manager(c.listening_port).init()
    for base, plan in enumerate(("planted", "planted2", "planted3")):
        r = mc.post("/plan-skeleton", '{"room":"Raum A","baseRev":%d,"sk":{"planId":"%s"}}' % (base, plan))
        assert r.status == 200 and r.body["rev"] == base + 1
    assert c.store.find("Raum A").rev == 3 and "emac" not in json.loads(c.store.get("Raum A"))
    hash_a = a.store.find("Raum A").hash

    fetched = []
    real = ec.http_get

    def counting(ip, port, target, timeout, max_body):
        fetched.append(port)
        return real(ip, port, target, timeout, max_body)

    monkeypatch.setattr(ec, "http_get", counting)
    assert wait_for(lambda: len(a.peers()) == 2 and len(b.peers()) == 2, 10)
    assert wait_for(lambda: c.listening_port in fetched, 12), "the planted revision was never even looked at"
    time.sleep(1.0)
    assert a.store.find("Raum A").rev == 1 and a.store.find("Raum A").hash == hash_a      # never adopted
    assert b.store.find("Raum A").rev == 1
    assert a.store.get("Raum A") == b.store.get("Raum A")
    # the failed fetch is backed off per (peer, room) like any other failure
    assert (c.did, int(ec.room_key("Raum A"), 16)) in a._sync_failures


def test_devices_without_an_edit_token_keep_and_pass_on_the_mac(component, monkeypatch):
    a = component((("Laser", "Raum A"),), udp_port=DISCOVERY_PORT, edit_token=EDIT_TOKEN)
    d = component((("Tuer", "Raum A"),), udp_port=DISCOVERY_PORT)                  # no edit token: adopts unverified
    assert wait_for(lambda: len(a.peers()) == 1 and len(d.peers()) == 1, 8)
    editor = Manager(a.listening_port, edit_token=EDIT_TOKEN).init()
    assert editor.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1, role=ec.KeyRole.EDIT).status == 200
    assert wait_for(lambda: d.store.find("Raum A") is not None, 12)
    assert d.store.get("Raum A") == a.store.get("Raum A")                           # the emac travelled with it
    emac = json.loads(d.store.get("Raum A"))["emac"]
    assert a.transport.verify_skeleton("Raum A", 1, ec.fnv1a32(SK1), emac)
    # served by D, a third device with the edit token accepts it (the MAC verifies, whoever hands it over)
    served = Manager(d.listening_port).init().get_json("/plan-skeleton.json", "room=Raum%20A")
    assert served["emac"] == emac
    e_store = ec.SkeletonStore(ec.MemoryStorage())
    e_store.set_signer(a.transport)
    assert e_store.adopt(d.store.get("Raum A"), "Raum A") == ec.SkeletonResult.STORED
    # a plain write on D (no edit token) is unsigned and an edit-token device refuses to adopt it
    fetched = []
    real = ec.http_get
    monkeypatch.setattr(ec, "http_get", lambda ip, port, target, timeout, max_body: fetched.append(port) or real(ip, port, target, timeout, max_body))
    mdev = Manager(d.listening_port).init()
    assert mdev.post("/plan-skeleton", '{"room":"Raum A","baseRev":1,"sk":%s}' % SK2).status == 200
    assert "emac" not in json.loads(d.store.get("Raum A"))
    assert e_store.adopt(d.store.get("Raum A"), "Raum A") == ec.SkeletonResult.UNAUTHORIZED
    assert wait_for(lambda: d.listening_port in fetched, 12), "A never looked at D's newer revision"
    time.sleep(0.5)
    assert a.store.find("Raum A").rev == 1                                          # D's unsigned rev 2 is not adopted by A


# ---- mDNS -----------------------------------------------------------------------------------------------------------------

def test_mdns_answers_unicast_queries_with_the_shared_record(component):
    port = 15353
    a = component(mdns_enabled=True, mdns_port=port)
    assert a._mdns is not None
    query = (struct.pack("!HHHHHH", 0, 0, 1, 0, 0, 0) + bytes([13]) + b"escapemanager" + bytes([5]) + b"local\x00"
             + struct.pack("!HH", 1, 0x8001))                         # QU bit: unicast answer
    asker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    asker.settimeout(3)
    asker.sendto(query, ("127.0.0.1", port))
    data, _ = asker.recvfrom(512)
    assert data[2] == 0x84 and data[3] == 0
    assert data == ec.build_mdns_answer("escapemanager.local", bytes([127, 0, 0, 1]), 15)
    assert struct.unpack_from("!HH", data, len(data) - 14)[1] == 1    # class IN without the cache-flush bit
    # known-answer suppression for a QU query that already lists our address
    suppressed = (struct.pack("!HHHHHH", 0, 0, 1, 1, 0, 0) + bytes([13]) + b"escapemanager" + bytes([5]) + b"local\x00"
                  + struct.pack("!HH", 1, 0x8001) + b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 15, 4) + bytes([127, 0, 0, 1]))
    asker.settimeout(0.6)
    asker.sendto(suppressed, ("127.0.0.1", port))
    try:
        asker.recvfrom(512)
        answered = True
    except socket.timeout:
        answered = False
    assert not answered
    # other names and junk are ignored and never crash the device
    other = query.replace(b"escapemanager", b"somethingelse!"[:13])
    for junk in (other, b"", b"\xff" * 600, bytes(12), query[:20]):
        asker.sendto(junk, ("127.0.0.1", port))
    time.sleep(0.3)
    assert a._background.is_alive()


def test_mdns_name_without_dot_gets_local_suffix(component):
    a = component(mdns_enabled=False, mdns_hostname="foo")
    assert a._mdns_name == "foo.local"
    assert component(mdns_enabled=False, mdns_hostname="Bar.local")._mdns_name == "Bar.local"


def test_sync_frame_is_bound_to_the_announcing_peers_did(component, monkeypatch):
    """The frame MAC binds the RESPONDING device's id: a skeleton served by another device (same token) than the
    one that announced it is not adopted."""
    a = component(((("Laser", "Raum A")),), udp_port=DISCOVERY_PORT)
    b = component(((("Kamera", "Raum A")),), udp_port=0)                # announces nothing; only used as the fetch target
    c = component(((("Tuer", "Raum A")),), udp_port=DISCOVERY_PORT)
    assert wait_for(lambda: len(a.peers()) == 1 and len(c.peers()) == 1, 8)
    mc = Manager(c.listening_port).init()
    real = ec.http_get
    served_by = []

    def redirect(ip, port, target, timeout, max_body):
        served_by.append(port)
        return real(ip, b.listening_port, target, timeout, max_body)   # whoever is asked, device B answers

    b.store.put("Raum A", 0, SK2.encode())
    b.store.put("Raum A", 1, SK2.replace("A", "B").encode())            # rev 2 with other content at B
    monkeypatch.setattr(ec, "http_get", redirect)
    assert mc.post("/plan-skeleton", '{"room":"Raum A","baseRev":0,"sk":%s}' % SK1).status == 200
    assert wait_for(lambda: len(served_by) >= 1, 8)
    time.sleep(1.0)
    assert a.store.find("Raum A") is None                                # B's frame is bound to B's did, A expected C's
    monkeypatch.setattr(ec, "http_get", real)


def test_plan_action_support_can_be_restricted(component):
    c = component()
    c.on_plan_action(0, lambda a: True, supported=[ec.PlanAction.RESET])
    m = Manager(c.listening_port).init()
    assert m.get_json("/status.json")["components"][0]["planActions"] == ["reset"]
    assert m.post("/plan-action", {"id": 0, "action": "reset"}).status == 200
    r = m.post("/plan-action", {"id": 0, "action": "complete"})
    assert (r.status, r.body["code"]) == (422, "unsupported")
