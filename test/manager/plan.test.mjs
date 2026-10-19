// Plan editor tests (manager.html, Chromium + C++ simulators): editor state vs. room progress, dirty
// handling, import validation, orphans/connections, live merge, unknown-field round trip, peer
// changes, room completion, variables, connection drag. HTTP ports 9500-9599 / UDP 14250 through
//   EM_TEST_PORT_BASE=9500 EM_TEST_UDP_PORT=14250 node --test test/manager/plan.test.mjs
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import * as H from "./helpers.mjs";
import { prerequisites, pageKit, startNetwork } from "./pagekit.mjs";

const { chromium, executablePath, skip } = await prerequisites("plan.test.mjs");

describe("manager.html plan editor", { skip }, () => {
  let browser;
  before(async () => { browser = await chromium.launch({ executablePath, headless: true }); });
  after(async () => { await browser?.close(); await H.stopAllSims(); });
  const K = pageKit(() => browser);
  const { openPage, snapshot, planDetail, until, waitForCards, openPlan, enterEditMode, seedSkeleton, seedSlice, noProblems } = K;

  const chip = (page, riddleId) => page.locator(`[id="plan-node-${riddleId}"]`);
  const lane = (page, layerId, laneId) => page.locator(`.planLane[data-layer-id="${layerId}"][data-lane-id="${laneId}"]`);
  const importFile = (page, plan) => page.locator("#viewPlan input[type=file]").setInputFiles({ name: "plan.json", mimeType: "application/json", buffer: Buffer.from(JSON.stringify(plan)) });
  const noticeText = (page) => page.locator('#noticeBar [data-notice="plan"]').innerText().catch(() => "");

  /** Edit mode with a plan imported from a file (= unsaved state), nothing stored on the devices. */
  async function importIntoEditor(p, room, plan) {
    await openPlan(p.page, room);
    await enterEditMode(p.page);
    await importFile(p.page, { planId: "imp-" + Date.now(), room, variables: [], ...plan });
    await until(p.page, "import applied", (n) => Object.keys(window.__em.planDetail().nodes).length >= n, Object.keys(plan.nodes || {}).length);
  }

  test("(1) unsaved edits survive the grid view and back while the tab bar recomputes the progress of two rooms", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, net.rooms.a);
      await enterEditMode(page);
      await page.locator(".planAddLayerBtn").click();
      await until(page, "layer added", () => window.__em.snapshot().plan.layers === 1, null);
      assert.equal((await snapshot(page)).plan.dirty, true, "an edit sets the dirty flag");
      await page.evaluate(() => { location.hash = "#/"; });
      await page.locator("#tabs .tab").nth(2).waitFor();
      // device data of BOTH rooms change -> the tab bar recomputes the progress of both
      H.emClient(net.laser.hostPort, ["action", "0", "next_step"]);
      H.emClient(net.tuer.hostPort, ["action", "0", "next_step"]);
      await until(page, "both cards advanced", (names) => names.every((name) => [...document.querySelectorAll(".card")]
        .some((c) => c.textContent.includes(name) && /1\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || ""))), [net.names.laser, net.names.tuer], 15000);
      await H.sleep(2500); // a few more render cycles
      await page.evaluate(() => { location.hash = "#/plan"; });
      await H.sleep(500);
      const after = (await snapshot(page)).plan;
      assert.equal(after.room, net.rooms.a, "still the room that was being edited");
      assert.equal(after.mode, "edit");
      assert.equal(after.layers, 1, "unsaved layer is still there");
      assert.equal(after.dirty, true);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(2) import: colliding/duplicate ids and orphan nodes are repaired, new ids never collide, a running load cannot overwrite it", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      const plan = {
        layers: [
          { id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }, { id: "A2", name: "b" }] },
          { id: "L2", name: "Zwei", lanes: [{ id: "A1", name: "gleiche Id in anderer Ebene" }, { id: "A3", name: "c" }, { id: "A3", name: "doppelt" }] },
          { id: "L2", name: "doppelte Ebene", lanes: [] },
        ],
        nodes: {
          [net.ids.laser]: { kind: "component", name: net.names.laser, layer: "L1", lane: "A1", connections: [{ step: 1, layer: "L2", lane: "A3" }, { step: 2, layer: "L9", lane: "A1" }] },
          [net.ids.kamera]: { kind: "component", name: net.names.kamera, layer: "L7", lane: "A1", connections: [{ step: 1, layer: "L2", lane: "A1" }] },
          "dummy-x": { kind: "dummy", name: "Orphan-Lane", layer: "L1", lane: "A9", connections: [{ step: 0, layer: "L2", lane: "A3" }] },
          "dummy-y": { kind: "dummy", name: "ok", layer: "L2", lane: "A1", connections: [] },
        },
      };
      await importIntoEditor(p, net.rooms.a, plan);
      const d = await planDetail(page);
      assert.equal(new Set(d.layers.map((l) => l.id)).size, d.layers.length, "layer ids unique: " + JSON.stringify(d.layers.map((l) => l.id)));
      for (const layer of d.layers) assert.equal(new Set(layer.lanes.map((l) => l.id)).size, layer.lanes.length, "lane ids unique within " + layer.id);
      assert.equal(d.nodes[net.ids.laser].layer, "L1");
      assert.deepEqual(d.nodes[net.ids.laser].connections, [{ step: 1, layer: "L2", lane: "A3" }], "the connection into the non-existing layer is dropped");
      for (const orphan of [net.ids.kamera, "dummy-x"]) {
        assert.equal(d.nodes[orphan].layer, null, orphan + " is unassigned");
        assert.equal(d.nodes[orphan].lane, null);
        assert.deepEqual(d.nodes[orphan].connections, [], orphan + " lost its connections");
      }
      assert.equal(d.nodes["dummy-y"].lane, "A1");
      await expectInPool(page, [net.ids.kamera, "dummy-x"]);

      // new layers/lanes: random short ids that collide with nothing (not even a deleted one)
      const before = new Set([...d.layers.map((l) => l.id), ...d.layers.flatMap((l) => l.lanes.map((x) => x.id))]);
      await page.locator(".planAddLayerBtn").click();
      await page.locator(".planAddLaneBtn").first().click();
      await until(page, "layer and lane added", () => window.__em.planDetail().layers.length === 4 || window.__em.planDetail().layers.length === 3, null);
      const d2 = await planDetail(page);
      const fresh = [...d2.layers.map((l) => l.id), ...d2.layers.flatMap((l) => l.lanes.map((x) => x.id))].filter((id) => !before.has(id));
      assert.equal(fresh.length, 2, JSON.stringify(fresh));
      for (const id of fresh) assert.match(id, /^[LA][0-9a-z]{6}$/);
      for (const layer of d2.layers) assert.equal(new Set(layer.lanes.map((l) => l.id)).size, layer.lanes.length);
      assert.equal(new Set(d2.layers.map((l) => l.id)).size, d2.layers.length);

      // a load that is still running when the file is imported must not replace the import
      const layersAfterImport = d2.layers.length;
      await page.route("**/plan-skeleton.json*", async (route) => { await H.sleep(1500); await route.continue().catch(() => {}); });
      await page.locator("#viewPlan").getByRole("button", { name: "Neu laden", exact: true }).click();
      await H.sleep(200);
      await importFile(page, { planId: "second", room: net.rooms.a, layers: [{ id: "X1", name: "Zweiter Import", lanes: [] }], variables: [], nodes: {} });
      await until(page, "second import shown", () => window.__em.planDetail().layers.some((l) => l.id === "X1"), null);
      await H.sleep(2500); // the delayed load answers now
      const d3 = await planDetail(page);
      assert.deepEqual(d3.layers.map((l) => l.id), ["X1"], "the stale load did not overwrite the import (had " + layersAfterImport + " layers before)");
      assert.equal((await snapshot(page)).plan.loading, false);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  async function expectInPool(page, ids) {
    for (const id of ids) assert.equal(await page.locator(`#planPool [id="plan-node-${id}"]`).count(), 1, id + " is shown in the pool");
  }

  test("(3) deleting a lane/moving a node: connections into the lane, of the node and backward ones are removed", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await importIntoEditor(p, net.rooms.a, {
        layers: [
          { id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a1" }, { id: "A2", name: "a2" }] },
          { id: "L2", name: "Zwei", lanes: [{ id: "B1", name: "b1" }] },
          { id: "L3", name: "Drei", lanes: [{ id: "C1", name: "c1" }] },
        ],
        nodes: {
          [net.ids.laser]: { kind: "component", name: net.names.laser, layer: "L1", lane: "A1", connections: [{ step: 1, layer: "L2", lane: "B1" }, { step: 2, layer: "L3", lane: "C1" }] },
          [net.ids.kamera]: { kind: "component", name: net.names.kamera, layer: "L1", lane: "A2", connections: [{ step: 1, layer: "L3", lane: "C1" }] },
          "dummy-d": { kind: "dummy", name: "D", layer: "L2", lane: "B1", connections: [{ step: 0, layer: "L3", lane: "C1" }] },
        },
      });
      let d = await planDetail(page);
      assert.equal(d.nodes[net.ids.laser].connections.length, 2, "valid connections survive the import");

      // (a) delete lane L2/B1: the dummy in it goes to the pool and loses its connection; connections INTO the lane are gone
      await lane(page, "L2", "B1").locator(".laneHead button").click(); // confirm() is auto-accepted
      await until(page, "lane deleted", () => !window.__em.planDetail().layers[1].lanes.length, null);
      d = await planDetail(page);
      assert.equal(d.nodes["dummy-d"].layer, null);
      assert.deepEqual(d.nodes["dummy-d"].connections, [], "the dummy of the deleted lane lost its outgoing connection");
      assert.deepEqual(d.nodes[net.ids.laser].connections, [{ step: 2, layer: "L3", lane: "C1" }], "connections into the deleted lane are removed");
      assert.deepEqual(d.nodes[net.ids.kamera].connections, [{ step: 1, layer: "L3", lane: "C1" }]);
      await expectInPool(page, ["dummy-d"]);

      // (b) drag the camera into L3/C1: its connection would now point into the SAME layer -> removed
      await chip(page, net.ids.kamera).dragTo(lane(page, "L3", "C1"));
      await until(page, "camera moved", (id) => window.__em.planDetail().nodes[id].layer === "L3", net.ids.kamera);
      d = await planDetail(page);
      assert.deepEqual(d.nodes[net.ids.kamera].connections, [], "a connection into the node's own layer is removed");
      assert.deepEqual(d.nodes[net.ids.laser].connections, [{ step: 2, layer: "L3", lane: "C1" }], "other nodes keep valid connections");

      // (c) back to the pool: outgoing connections are cleared
      await chip(page, net.ids.laser).dragTo(page.locator("#planPool"));
      await until(page, "laser in pool", (id) => window.__em.planDetail().nodes[id].layer === null, net.ids.laser);
      d = await planDetail(page);
      assert.deepEqual(d.nodes[net.ids.laser].connections, []);
      assert.equal((await snapshot(page)).plan.dirty, true);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(4) cancelling a room switch resets the dropdown; prompts only when there are unsaved edits", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    const selectRoom = async (room) => {
      for (let i = 0; i < 10; i++) {
        if (await page.locator("#viewPlan .planToolbar select").selectOption(room, { timeout: 1500 }).then(() => true, () => false)) return;
        await H.sleep(300);
      }
    };
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, net.rooms.a);
      await enterEditMode(page);
      // edit mode WITHOUT edits: switching asks nothing
      await selectRoom(net.rooms.b);
      await until(page, "room B loaded", (room) => window.__em.snapshot().plan.room === room && window.__em.snapshot().plan.loaded && !window.__em.snapshot().plan.loading, net.rooms.b);
      assert.deepEqual(p.dialogs.seen, [], "no confirmation without unsaved edits");

      await page.locator(".planAddLayerBtn").click();
      await until(page, "layer added", () => window.__em.snapshot().plan.layers === 1, null);
      p.dialogs.accept = false;
      await selectRoom(net.rooms.a);
      await H.sleep(500);
      assert.equal(p.dialogs.seen.length, 1, "one confirmation: " + p.dialogs.seen);
      assert.equal(await page.locator("#viewPlan .planToolbar select").inputValue(), net.rooms.b, "the dropdown is back on the current room");
      const kept = (await snapshot(page)).plan;
      assert.equal(kept.room, net.rooms.b);
      assert.equal(kept.layers, 1);
      assert.equal(kept.dirty, true);

      p.dialogs.accept = true;
      await selectRoom(net.rooms.a);
      await until(page, "room A loaded", (room) => window.__em.snapshot().plan.room === room && !window.__em.snapshot().plan.loading, net.rooms.a);
      const loaded = (await snapshot(page)).plan;
      assert.equal(loaded.layers, 0);
      assert.equal(loaded.dirty, false, "loading clears the dirty flag");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(5) live data never overwrites an edited placement but keeps runtime fields current", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    seedSkeleton(net.roomA, room, { schema: 1, planId: "p5", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "eins" }, { id: "A2", name: "zwei" }] }], dummies: [], variables: [] });
    seedSlice(net.laser, 0, { planId: "p5", layer: "L1", lane: "A1", connections: [], variables: [] });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, room);
      await until(page, "slice applied", (id) => window.__em.planDetail().nodes[id]?.lane === "A1", net.ids.laser);
      await enterEditMode(page);
      await chip(page, net.ids.laser).dragTo(lane(page, "L1", "A2"));
      await until(page, "moved by the user", (id) => window.__em.planDetail().nodes[id].lane === "A2", net.ids.laser);
      // away and back: the device slice still says A1, the edit wins
      await page.evaluate(() => { location.hash = "#/"; });
      await H.sleep(1500);
      await page.evaluate(() => { location.hash = "#/plan"; });
      await H.sleep(800);
      let d = await planDetail(page);
      assert.equal(d.nodes[net.ids.laser].lane, "A2", "placement survived the view change");
      // the device advances: runtime fields follow, placement stays
      H.emClient(net.laser.hostPort, ["action", "0", "next_step"]);
      await until(page, "runtime field updated", (id) => window.__em.planDetail().nodes[id].currentStep === 1, net.ids.laser);
      d = await planDetail(page);
      assert.equal(d.nodes[net.ids.laser].lane, "A2");
      assert.equal(d.nodes[net.ids.laser].layer, "L1");
      assert.equal(d.dirty, true);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(6) unknown fields of dummies, connections and variable definitions survive save -> reload -> save", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const sk = {
      schema: 1, planId: "p6", room, futureTop: { keep: true },
      layers: [{ id: "L1", name: "Eins", color: "red", lanes: [{ id: "A1", name: "eins", icon: "x" }, { id: "A2", name: "zwei" }] }, { id: "L2", name: "Zwei", lanes: [{ id: "B1", name: "b" }] }],
      dummies: [{ riddleId: "dummy-6", name: "Platzhalter", layer: "L1", lane: "A1", futureDummy: { n: [1, 2] }, connections: [{ step: 0, layer: "L2", lane: "B1", style: "dashed" }] }],
      variables: [
        { riddleId: net.ids.laser, name: "brightness", type: "range", min: 0, max: 100, unit: "%" },
        { riddleId: "gone-component", name: "difficulty", type: "select", options: ["easy", "hard"], note: "offline component" },
      ],
    };
    seedSkeleton(net.roomA, room, sk);
    seedSlice(net.kamera, 0, { planId: "p6", layer: "L1", lane: "A2", connections: [{ step: 1, layer: "L2", lane: "B1", color: "blue" }], variables: [] });
    const p = await openPage(net.laser.base);
    const page = p.page;
    const stored = () => H.emClient(net.laser.hostPort, ["skeleton", room]);
    const check = (blob, label) => {
      assert.deepEqual(blob.sk.futureTop, { keep: true }, label + ": skeleton field");
      assert.equal(blob.sk.layers[0].color, "red", label + ": layer field");
      assert.equal(blob.sk.layers[0].lanes[0].icon, "x", label + ": lane field");
      const dummy = blob.sk.dummies.find((x) => x.riddleId === "dummy-6");
      assert.deepEqual(dummy.futureDummy, { n: [1, 2] }, label + ": dummy field");
      assert.equal(dummy.connections[0].style, "dashed", label + ": connection field of a dummy");
      assert.equal(dummy.connections[0]._extra, undefined, label + ": no internal _extra leaks into the stored data");
      const live = blob.sk.variables.find((x) => x.riddleId === net.ids.laser && x.name === "brightness");
      assert.equal(live.unit, "%", label + ": variable definition field (live component)");
      const gone = blob.sk.variables.find((x) => x.riddleId === "gone-component");
      assert.equal(gone.note, "offline component", label + ": definition of a component that is not live is kept as is");
    };
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, room);
      await enterEditMode(page);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved rev 2", () => window.__em.snapshot().plan.rev === 2 && !window.__em.snapshot().plan.saving, null);
      check(stored(), "after save");
      const status = H.emClient(net.kamera.hostPort, ["status"]);
      assert.equal(status.components[0].plan.connections[0].color, "blue", "unknown field of a slice connection is written back");
      // reload and save again with another change
      assert.equal((await snapshot(page)).plan.dirty, false, "saving clears the dirty flag");
      await page.locator("#viewPlan").getByRole("button", { name: "Neu laden", exact: true }).click();
      await until(page, "reloaded", () => window.__em.snapshot().plan.layers === 3 && !window.__em.snapshot().plan.loading, null);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved rev 3", () => window.__em.snapshot().plan.rev === 3 && !window.__em.snapshot().plan.saving, null);
      check(stored(), "after reload + save");
      assert.equal(stored().rev, 3);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(9) dirty flag: a peer's skeleton change shows a notice, never reloads; own saves raise no notice", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const base = { schema: 1, planId: "p9", room, layers: [{ id: "L1", name: "Eins", lanes: [] }], dummies: [], variables: [] };
    seedSkeleton(net.roomA, room, base);
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, room);
      assert.equal((await snapshot(page)).plan.dirty, false);
      await enterEditMode(page);
      assert.equal((await snapshot(page)).plan.dirty, false, "entering edit mode alone is not an edit");
      await page.locator(".planAddLayerBtn").click();
      await until(page, "layer added", () => window.__em.snapshot().plan.layers === 2, null);
      assert.equal((await snapshot(page)).plan.dirty, true);

      seedSkeleton(net.roomA, room, { ...base, layers: [{ id: "L1", name: "Fremd", lanes: [] }, { id: "L2", name: "Fremd2", lanes: [] }, { id: "L3", name: "Fremd3", lanes: [] }] }, 1);
      await page.locator('#noticeBar [data-notice="plan"]').waitFor({ timeout: 15000 });
      assert.match(await noticeText(page), /Plan wurde auf einem Gerät geändert/);
      await H.sleep(2500);
      const kept = (await snapshot(page)).plan;
      assert.equal(kept.rev, 1, "not reloaded");
      assert.equal(kept.layers, 2, "unsaved edits are kept");
      assert.equal(kept.dirty, true);
      assert.equal(kept.peerChanged, true);

      // the notice's button reloads (after the confirmation for the unsaved edits)
      await page.locator('#noticeBar [data-notice="plan"] button').click();
      await until(page, "reloaded", () => window.__em.snapshot().plan.rev === 2 && !window.__em.snapshot().plan.loading, null);
      const reloaded = (await snapshot(page)).plan;
      assert.equal(reloaded.layers, 3);
      assert.equal(reloaded.dirty, false);
      assert.equal(await page.locator('#noticeBar [data-notice="plan"]').count(), 0, "notice gone after reload");
      assert.ok(p.dialogs.seen.some((m) => /Ungespeicherte/.test(m)), "asked before discarding edits: " + p.dialogs.seen);

      // an own save does not raise the notice (the peers announce the new skeleton hash afterwards)
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved rev 3", () => window.__em.snapshot().plan.rev === 3 && !window.__em.snapshot().plan.saving, null);
      await H.sleep(4000);
      assert.equal(await page.locator('#noticeBar [data-notice="plan"]').count(), 0, "no notice for our own save");
      assert.equal((await snapshot(page)).plan.peerChanged, false);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(9b) view mode: a peer's skeleton change reloads the visible plan automatically", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const base = { schema: 1, planId: "p9b", room, layers: [{ id: "L1", name: "Eins", lanes: [] }], dummies: [], variables: [] };
    seedSkeleton(net.roomA, room, base);
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      await openPlan(p.page, room);
      assert.equal((await snapshot(p.page)).plan.layers, 1);
      seedSkeleton(net.roomA, room, { ...base, layers: [{ id: "L1", name: "a", lanes: [] }, { id: "L2", name: "b", lanes: [] }] }, 1);
      await until(p.page, "auto reload", () => window.__em.snapshot().plan.rev === 2 && window.__em.snapshot().plan.layers === 2, null, 20000);
      assert.equal(await p.page.locator('#noticeBar [data-notice="plan"]').count(), 0);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(P1b) the tab bar reloads no skeleton while only device data changes; a changed skeleton is fetched once, only for its room", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    const sk = { schema: 1, planId: "p1b", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }], dummies: [], variables: [] };
    seedSkeleton(net.roomA, room, sk);
    seedSlice(net.laser, 0, { planId: "p1b", layer: "L1", lane: "A1", connections: [], variables: [] });
    const p = await openPage(net.laser.base);
    const page = p.page;
    const skeletonRequests = (sim, blobOnly = false) => p.network.filter((r) => r.url.startsWith(sim.base + "/plan-skeleton.json") && (!blobOnly || r.url.includes("room="))).length;
    try {
      await waitForCards(page, Object.values(net.names));
      await H.sleep(3500); // first progress computation of both rooms
      const before = { a: skeletonRequests(net.laser) + skeletonRequests(net.kamera), b: skeletonRequests(net.tuer) };
      assert.ok(before.a >= 1 && before.b >= 1, "the initial computation looked at both rooms: " + JSON.stringify(before));
      for (let i = 0; i < 3; i++) {
        for (const sim of [net.laser, net.kamera, net.tuer]) H.emClient(sim.hostPort, ["action", "0", "next_step"]);
        await H.sleep(1500);
      }
      await until(page, "steps advanced", () => [...document.querySelectorAll(".card")].filter((c) => /3\s*\/\s*5/.test(c.querySelector(".steps")?.textContent || "")).length === 3, null);
      await H.sleep(2500);
      assert.deepEqual({ a: skeletonRequests(net.laser) + skeletonRequests(net.kamera), b: skeletonRequests(net.tuer) }, before, "device data changed, skeletons did not: nothing fetched");
      // a new revision of room A: fetched once (index + one blob), room B's device is not asked again
      const blobsBefore = skeletonRequests(net.laser, true) + skeletonRequests(net.kamera, true);
      seedSkeleton(net.roomA, room, { ...sk, layers: [...sk.layers, { id: "L2", name: "Zwei", lanes: [] }] }, 1);
      await H.sleep(5000);
      assert.equal(skeletonRequests(net.laser, true) + skeletonRequests(net.kamera, true) - blobsBefore, 1, "exactly one blob request");
      assert.equal(skeletonRequests(net.tuer), before.b, "the other room is untouched");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(smoke) editor actions: placeholder, lanes, layers, variables (validated on save), plan action, JSON export", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    seedSkeleton(net.roomA, room, { schema: 1, planId: "psm", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }, { id: "L2", name: "Zwei", lanes: [{ id: "B1", name: "b" }] }], dummies: [], variables: [] });
    seedSlice(net.laser, 0, { planId: "psm", layer: "L1", lane: "A1", connections: [], variables: [] });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, room);
      await until(page, "slice applied", (id) => window.__em.planDetail().nodes[id]?.lane === "A1", net.ids.laser);
      // view mode: a layer action goes through the confirmation to the device
      const posts = () => p.network.filter((r) => r.method === "POST" && r.url.endsWith("/plan-action")).length;
      await page.locator(".layerActions button", { hasText: "Zurücksetzen" }).first().click();
      await until(page, "plan action sent", () => /Ablaufplan|zurückgesetzt|ok/.test(document.querySelector("#toastStack")?.textContent || ""), null);
      assert.equal(posts(), 1);

      await enterEditMode(page);
      await page.getByRole("button", { name: "+ Platzhalter hinzufügen" }).click(); // prompt() answered by the test
      await until(page, "placeholder in the pool", () => Object.values(window.__em.planDetail().nodes).some((n) => n.kind === "dummy"), null);
      const dummyId = Object.keys((await planDetail(page)).nodes).find((id) => id.startsWith("dummy-"));
      await chip(page, dummyId).dragTo(lane(page, "L2", "B1"));
      await until(page, "placeholder placed", (id) => window.__em.planDetail().nodes[id].lane === "B1", dummyId);
      await page.locator('.planAddLaneBtn').nth(1).click();
      await until(page, "second lane", () => window.__em.planDetail().layers[1].lanes.length === 2, null);

      // variables: the checkbox selects, an out-of-range value is clamped when saved
      const brightness = page.locator(".planVarRow", { hasText: "brightness" }).first();
      await brightness.locator("input[type=number]").fill("150");
      await until(page, "variable enabled", (id) => window.__em.planDetail().nodes[id].variables.brightness?.enabled === true, net.ids.laser);
      assert.equal(await brightness.locator("input[type=checkbox]").isChecked(), true);

      const download = page.waitForEvent("download");
      await page.getByRole("button", { name: "Als JSON herunterladen" }).click();
      const file = JSON.parse(await (await import("node:fs/promises")).readFile(await (await download).path(), "utf8"));
      assert.ok(file.nodes[dummyId], "the placeholder is exported");
      assert.deepEqual(file.variables.map((v) => [v.riddleId, v.name, v.type]), [[net.ids.laser, "brightness", "range"]], "only the selected variable definitions, not the raw catalog");
      assert.equal(file.nodes[net.ids.laser].variables[0].value, "100", "exported value is validated");

      await page.locator("#planSaveBtn").click();
      await until(page, "saved", () => window.__em.snapshot().plan.rev === 2 && !window.__em.snapshot().plan.saving, null);
      const status = H.emClient(net.laser.hostPort, ["status"]);
      assert.deepEqual(status.components[0].plan.variables, [{ riddleId: net.ids.laser, name: "brightness", value: "100" }]);
      assert.equal(H.emClient(net.laser.hostPort, ["skeleton", room]).sk.dummies.length, 1);

      // removing a layer returns its nodes to the pool and drops their connections
      await page.locator('.planLayer[data-layer-id="L2"] .layerHead button').click();
      await until(page, "layer removed", () => window.__em.planDetail().layers.length === 1, null);
      assert.equal((await planDetail(page)).nodes[dummyId].layer, null);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(A5b) saving the plan is logged once; the devices' echo events of our own save are not logged again", async () => {
    const net = await startNetwork();
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, net.rooms.a);
      await enterEditMode(page);
      await H.sleep(1500);
      await page.locator(".planAddLayerBtn").click();
      await page.locator("#planSaveBtn").click();
      await until(page, "saved", () => window.__em.snapshot().plan.rev === 1 && !window.__em.snapshot().plan.saving, null);
      await H.sleep(4500); // status polls bring the devices' events; the log is flushed once a second
      const log = (await K.readLog(page)).map((e) => e.text);
      assert.equal(log.filter((t) => /Raum-Ablaufplan an .*gespeichert/.test(t)).length, 2, log.join(" | "));
      assert.equal(log.filter((t) => /Raum-Ablaufplan aktualisiert/.test(t)).length, 0, "echo of our own save: " + log.join(" | "));
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  // ---- pure computation (no simulator needed beyond serving the page) ---------------------------
  describe("room progress (pure function)", () => {
    let sim, p;
    before(async () => {
      sim = await H.startSim({ components: ["Pure:PureRoom:pure-1"] });
      p = await openPage(sim.base);
      await p.page.waitForFunction(() => window.__em && typeof window.__em.roomProgressOf === "function");
    });
    after(async () => { await p?.close(); await sim?.stop(); });
    const progress = (sk, devices) => p.page.evaluate(([a, b]) => window.__em.roomProgressOf(a, b, "R"), [sk, devices]);
    const dev = (id, step, totalSteps, extra = {}) => ({ riddleId: id, room: "R", step, totalSteps, ...extra });
    const sk = (layers, dummies = []) => ({ schema: 1, planId: "u", layers, dummies, variables: [] });
    const L = (id, ...lanes) => ({ id, name: id, lanes: lanes.map((l) => ({ id: l, name: l })) });
    const slice = (layer, lane, connections = []) => ({ planId: "u", layer, lane, connections, variables: [] });

    test("(10) completion: totalSteps 0 counts as completed, a blocked dummy is reported and keeps the room unfinished", async () => {
      const layers = [L("L1", "A", "B"), L("L2", "C")];
      // two components, one without steps; both done -> finished
      let r = await progress(sk(layers), [dev("x", 2, 2, { plan: slice("L1", "A") }), dev("z", 0, 0, { plan: slice("L1", "B") })]);
      assert.equal(r.finished, true);
      assert.equal(r.componentCount, 2);
      assert.equal(r.completedComponents, 2);
      assert.equal(r.totalSteps, 2);
      // not finished while the component with steps is not done
      r = await progress(sk(layers), [dev("x", 1, 2, { plan: slice("L1", "A") }), dev("z", 0, 0, { plan: slice("L1", "B") })]);
      assert.equal(r.finished, false);
      // a dummy in layer 2 without any incoming connection is blocked: reported, room cannot finish
      const blocked = sk(layers, [{ riddleId: "d", name: "D", layer: "L2", lane: "C", connections: [] }]);
      r = await progress(blocked, [dev("x", 2, 2, { plan: slice("L1", "A") }), dev("z", 0, 0, { plan: slice("L1", "B") })]);
      assert.equal(r.blocked, 1);
      assert.equal(r.finished, false);
      // the same dummy WITH an incoming connection from a finished component completes
      r = await progress(blocked, [dev("x", 2, 2, { plan: slice("L1", "A", [{ step: 2, layer: "L2", lane: "C" }]) }), dev("z", 0, 0, { plan: slice("L1", "B") })]);
      assert.equal(r.blocked, 0);
      assert.equal(r.finished, true);
      // no plan at all / no assigned component: never finished
      r = await progress(sk([]), [dev("x", 2, 2)]);
      assert.equal(r.finished, false);
      assert.equal(r.componentCount, 0);
      noProblems(p);
    });

    test("orphans: a component placed in a non-existing layer/lane counts as unassigned; unassigned sources feed nothing", async () => {
      const layers = [L("L1", "A"), L("L2", "C")];
      const dummies = [{ riddleId: "d", name: "D", layer: "L2", lane: "C", connections: [] }];
      // component y is placed in a lane that does not exist, its connection must not complete dummy d
      const r = await progress(sk(layers, dummies), [
        dev("x", 1, 2, { plan: slice("L1", "A") }),
        dev("y", 2, 2, { plan: slice("L9", "Z", [{ step: 1, layer: "L2", lane: "C" }]) }),
      ]);
      assert.equal(r.componentCount, 1, "the orphan is not part of the plan");
      assert.equal(r.finished, false);
      assert.equal(r.blocked, 1);
      // a dummy in layer 1 completes by itself; chain: component -> dummy(L2) -> still needs its predecessor
      const chain = sk([L("L1", "A"), L("L2", "B"), L("L3", "C")], [
        { riddleId: "d1", name: "D1", layer: "L2", lane: "B", connections: [{ step: 0, layer: "L3", lane: "C" }] },
        { riddleId: "d2", name: "D2", layer: "L3", lane: "C", connections: [] },
      ]);
      const open = await progress(chain, [dev("x", 1, 2, { plan: slice("L1", "A", [{ step: 2, layer: "L2", lane: "B" }]) })]);
      assert.equal(open.finished, false);
      const done = await progress(chain, [dev("x", 2, 2, { plan: slice("L1", "A", [{ step: 2, layer: "L2", lane: "B" }]) })]);
      assert.equal(done.finished, true, JSON.stringify(done));
      noProblems(p);
    });

    test("(P2/P6) the computation does not depend on or touch the editor state", async () => {
      const before = await p.page.evaluate(() => JSON.stringify(window.__em.planDetail()));
      await progress(sk([L("L1", "A")]), [dev("x", 1, 2, { plan: slice("L1", "A") })]);
      const after = await p.page.evaluate(() => JSON.stringify(window.__em.planDetail()));
      assert.equal(after, before);
    });
  });

  test("(10b) room completion end to end: tab shows a check mark and aria-label; a blocked dummy keeps it open and is labelled", async () => {
    const tag = H.randomTag();
    const done = `EM-${tag}-done`;
    const open = `EM-${tag}-open`;
    const a = await H.startSim({ components: [`Steps-${tag}:${done}:steps-${tag}`], totalSteps: 2 });
    const z = await H.startSim({ components: [`Zero-${tag}:${done}:zero-${tag}`], totalSteps: 0 });
    const c = await H.startSim({ components: [`Open-${tag}:${open}:open-${tag}`], totalSteps: 2 });
    const layers = [{ id: "L1", name: "Eins", lanes: [{ id: "A", name: "a" }, { id: "B", name: "b" }] }, { id: "L2", name: "Zwei", lanes: [{ id: "C", name: "c" }] }];
    seedSkeleton([a, z], done, { schema: 1, planId: "pd", room: done, layers, dummies: [], variables: [] });
    seedSlice(a, 0, { planId: "pd", layer: "L1", lane: "A", connections: [], variables: [] });
    seedSlice(z, 0, { planId: "pd", layer: "L1", lane: "B", connections: [], variables: [] });
    seedSkeleton([c], open, { schema: 1, planId: "po", room: open, layers, dummies: [{ riddleId: "blocked", name: "Haengt", layer: "L2", lane: "C", connections: [] }], variables: [] });
    seedSlice(c, 0, { planId: "po", layer: "L1", lane: "A", connections: [], variables: [] });
    const p = await openPage(a.base);
    const page = p.page;
    try {
      await waitForCards(page, [`Steps-${tag}`, `Zero-${tag}`, `Open-${tag}`]);
      const tab = (room) => page.locator(`#tabs [role=tab][data-room="${room}"]`);
      await tab(done).waitFor();
      await H.sleep(2500);
      assert.equal(await tab(done).evaluate((el) => el.classList.contains("finished")), false, "not finished yet");
      H.emClient(a.hostPort, ["action", "0", "next_step"]);
      H.emClient(a.hostPort, ["action", "0", "next_step"]);
      H.emClient(c.hostPort, ["action", "0", "next_step"]);
      H.emClient(c.hostPort, ["action", "0", "next_step"]);
      await until(page, "room done is finished", (r) => window.__em.snapshot().finishedRooms.includes(r), done, 20000);
      assert.match(await tab(done).innerText(), /✓/, "not colour alone: a visible check mark");
      assert.match(await tab(done).getAttribute("aria-label"), /abgeschlossen/);
      await H.sleep(2500);
      assert.equal((await snapshot(page)).finishedRooms.includes(open), false, "a blocked dummy keeps the room open");
      assert.doesNotMatch(await tab(open).innerText(), /✓/);
      // the plan view names the blocked dummy
      await openPlan(page, open);
      await page.locator("#planPool, .planNode.dummy").first().waitFor();
      assert.match(await page.locator("#viewPlan").innerText(), /blockiert/);
      noProblems(p);
    } finally {
      await p.close();
      await Promise.all([a.stop(), z.stop(), c.stop()]);
    }
  });

  test("(P6) stored variable values are validated against the current definition when merging", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    seedSkeleton(net.roomA, room, { schema: 1, planId: "p6v", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }], dummies: [], variables: [] });
    seedSlice(net.laser, 0, { planId: "p6v", layer: "L1", lane: "A1", connections: [], variables: [
      { riddleId: net.ids.laser, name: "difficulty", value: "extreme" },
      { riddleId: net.ids.laser, name: "brightness", value: "500" },
      { riddleId: net.ids.laser, name: "label", value: "x".repeat(60) },
    ] });
    const p = await openPage(net.laser.base);
    try {
      await waitForCards(p.page, Object.values(net.names));
      await openPlan(p.page, room);
      await until(p.page, "slice merged", (id) => window.__em.planDetail().nodes[id]?.variables?.brightness, net.ids.laser);
      const v = (await planDetail(p.page)).nodes[net.ids.laser].variables;
      assert.equal(v.brightness.value, "100", "range clamped");
      assert.ok(["easy", "medium", "hard"].includes(v.difficulty.value), "select value that is no option any more falls back to the default: " + v.difficulty.value);
      assert.ok(v.label.value.length <= 32, "text clipped to maxLength");
      assert.equal(v.brightness.riddleId, net.ids.laser, "variables carry the riddle id (not a uuid field)");
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(P9) availability changes reach the open plan view (badge, pool, buttons) without a status update", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    seedSkeleton(net.roomA, room, { schema: 1, planId: "p9a", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }, { id: "A2", name: "b" }] }], dummies: [], variables: [] });
    seedSlice(net.laser, 0, { planId: "p9a", layer: "L1", lane: "A1", connections: [], variables: [] });
    seedSlice(net.kamera, 0, { planId: "p9a", layer: "L1", lane: "A2", connections: [], variables: [] });
    const p = await openPage(net.kamera.base, { storage: { "em.offlineMs": "4000" } });
    try {
      await waitForCards(p.page, Object.values(net.names));
      await openPlan(p.page, room);
      await chip(p.page, net.ids.laser).waitFor();
      assert.equal(await chip(p.page, net.ids.laser).getByText("nicht verfügbar").count(), 0);
      assert.equal(await p.page.locator(".layerActions button", { hasText: "Zurücksetzen" }).first().isDisabled(), false);
      await net.laser.stop();
      await until(p.page, "offline badge appears", (id) => document.getElementById("plan-node-" + id)?.textContent.includes("nicht verfügbar"), net.ids.laser, 25000);
      assert.equal((await planDetail(p.page)).nodes[net.ids.laser].available, false);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });

  test("(P8) connection drag: pointer capture, pointercancel cleans up, native dragstart on a dot is prevented", async () => {
    const net = await startNetwork();
    const room = net.rooms.a;
    seedSkeleton(net.roomA, room, { schema: 1, planId: "p8", room, layers: [{ id: "L1", name: "Eins", lanes: [{ id: "A1", name: "a" }] }, { id: "L2", name: "Zwei", lanes: [{ id: "B1", name: "b" }] }], dummies: [], variables: [] });
    seedSlice(net.laser, 0, { planId: "p8", layer: "L1", lane: "A1", connections: [], variables: [] });
    const p = await openPage(net.laser.base);
    const page = p.page;
    try {
      await waitForCards(page, Object.values(net.names));
      await openPlan(page, room);
      await enterEditMode(page);
      const dot = page.locator(`[id="plan-node-${net.ids.laser}"] .planStepDot[data-step="2"]`);
      await dot.waitFor();
      assert.equal(await dot.evaluate((el) => getComputedStyle(el).touchAction), "none");
      // a native drag that starts on a dot is cancelled
      assert.equal(await dot.evaluate((el) => !el.dispatchEvent(new DragEvent("dragstart", { bubbles: true, cancelable: true }))), true);
      const box = await dot.boundingBox();
      // cancelled gesture: the helper line goes away and later pointer moves do nothing
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      await page.mouse.move(box.x + 60, box.y + 40);
      assert.equal(await page.locator("#planSvg line").count(), 1, "helper line while dragging");
      await page.evaluate(() => window.dispatchEvent(new PointerEvent("pointercancel", { pointerId: 1, bubbles: true })));
      assert.equal(await page.locator("#planSvg line").count(), 0, "pointercancel removed the helper line");
      await page.mouse.up();
      assert.equal((await planDetail(page)).nodes[net.ids.laser].connections.length, 0, "a cancelled drag creates no connection");
      // a completed drag onto a lane of the next layer creates the connection and marks the plan dirty
      await page.mouse.move(box.x + box.width / 2, box.y + box.height / 2);
      await page.mouse.down();
      const target = await lane(page, "L2", "B1").boundingBox();
      await page.mouse.move(target.x + target.width / 2, target.y + target.height / 2, { steps: 4 });
      await page.mouse.up();
      await until(page, "connection created", (id) => window.__em.planDetail().nodes[id].connections.length === 1, net.ids.laser);
      assert.deepEqual((await planDetail(page)).nodes[net.ids.laser].connections, [{ step: 2, layer: "L2", lane: "B1" }]);
      assert.equal((await snapshot(page)).plan.dirty, true);
      // the delete handle of the connection is labelled
      await until(page, "connection drawn", () => document.querySelector("#planSvg circle title"), null);
      assert.match(await page.locator("#planSvg circle").first().getAttribute("aria-label"), /Verbindung/);
      noProblems(p);
    } finally { await p.close(); await net.stopAll(); }
  });
});
