import test from "node:test";
import assert from "node:assert/strict";
import { fetchLiveInventory, mapInventoryDevices, sessionTokenFromHash } from "../src/liveInventory.js";

test("maps persistent IDs once and safely bounds hostile labels", () => {
  const hostile = "<img src=x onerror=alert(1)>\u0000";
  const nodes = mapInventoryDevices([
    { id: "persistent-id", displayName: hostile, state: "reachable", addresses: [{ address: "192.0.2.1" }] },
    { id: "persistent-id", displayName: "duplicate" },
  ]);
  assert.equal(nodes.length, 1);
  assert.equal(nodes[0].id, "persistent-id");
  assert.equal(nodes[0].name, "<img src=x onerror=alert(1)> ");
});

test("enforces the live rendering limit", () => {
  const nodes = mapInventoryDevices(Array.from({ length: 1100 }, (_, index) => ({ id: `device-${index}` })));
  assert.equal(nodes.length, 1000);
});

test("accepts only owner-launch session material", () => {
  assert.equal(sessionTokenFromHash("#session=short"), "");
  assert.equal(sessionTokenFromHash(`#session=${"a".repeat(43)}`), "a".repeat(43));
});

test("uses only the authenticated inventory endpoint and deduplicates pages", async () => {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url: String(url), options });
    const second = String(url).includes("cursor=next");
    return { ok: true, status: 200, json: async () => second
      ? { items: [{ id: "one" }, { id: "two" }], nextCursor: null }
      : { items: [{ id: "one" }], nextCursor: "next" } };
  };
  const nodes = await fetchLiveInventory("a".repeat(43), { fetchImpl });
  assert.deepEqual(nodes.map((node) => node.id), ["one", "two"]);
  assert.equal(calls.length, 2);
  assert.ok(calls.every((call) => call.url.startsWith("/api/v1/inventory/devices?")));
  assert.ok(calls.every((call) => call.options.headers["X-Network-Scout-Token"] === "a".repeat(43)));
  assert.ok(calls.every((call) => call.options.method === undefined));
});

test("separates authentication and backend unavailable errors", async () => {
  await assert.rejects(() => fetchLiveInventory(""), { kind: "authentication" });
  await assert.rejects(() => fetchLiveInventory("a".repeat(43), {
    fetchImpl: async () => { throw new TypeError("offline"); },
  }), { kind: "unavailable" });
});
