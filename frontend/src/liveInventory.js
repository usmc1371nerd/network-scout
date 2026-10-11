export const MAX_LIVE_DEVICES = 1000;

const TYPE_MAP = new Map([
  ["computer", "pc"], ["server", "server"], ["router", "router"],
  ["switch", "switch"], ["phone", "phone"], ["printer", "usb-printer"],
  ["iot", "iot-plug"],
]);

export class LiveInventoryError extends Error {
  constructor(kind, message) {
    super(message);
    this.kind = kind;
  }
}

export function sessionTokenFromHash(hash) {
  const token = new URLSearchParams(String(hash || "").replace(/^#/, "")).get("session") || "";
  return token.length >= 43 ? token : "";
}

export function mapInventoryDevices(items, maximum = MAX_LIVE_DEVICES) {
  const result = [];
  const seen = new Set();
  for (const item of Array.isArray(items) ? items : []) {
    const id = typeof item?.id === "string" ? item.id.trim() : "";
    if (!id || id.length > 64 || seen.has(id) || result.length >= maximum) continue;
    seen.add(id);
    const address = Array.isArray(item.addresses) ? item.addresses[0]?.address : "";
    const index = result.length;
    const name = String(item.displayName || "Unknown device").replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, 128);
    const category = String(item.category || "unknown").toLowerCase();
    result.push({
      id,
      name: name || "Unknown device",
      type: TYPE_MAP.get(category) || "pc",
      category,
      status: ["reachable", "unavailable", "unknown"].includes(item.state) ? item.state : "unknown",
      recognition: item.recognition === "recognized" ? "recognized" : "unrecognized",
      ip: typeof address === "string" ? address : "",
      mac: typeof item.primaryMac === "string" ? item.primaryMac : "",
      manufacturer: typeof item.manufacturer === "string" ? item.manufacturer : "",
      x: 36 + (index % 6) * 176,
      y: 36 + Math.floor(index / 6) * 108,
    });
  }
  return result;
}

export async function fetchLiveInventory(token, { fetchImpl = fetch, signal } = {}) {
  if (!token) throw new LiveInventoryError("authentication", "Open Network Scout from its authenticated local launcher.");
  const items = [];
  const cursors = new Set();
  let cursor = null;
  do {
    const query = new URLSearchParams({ limit: "250" });
    if (cursor) query.set("cursor", cursor);
    let response;
    try {
      response = await fetchImpl(`/api/v1/inventory/devices?${query}`, {
        headers: { "X-Network-Scout-Token": token, Accept: "application/json" },
        signal,
      });
    } catch (error) {
      if (error?.name === "AbortError") throw error;
      throw new LiveInventoryError("unavailable", "The local Network Scout backend is unavailable.");
    }
    if (response.status === 401 || response.status === 403) {
      throw new LiveInventoryError("authentication", "The local session is missing or no longer valid.");
    }
    if (!response.ok) throw new LiveInventoryError("unavailable", "The local inventory could not be loaded.");
    const payload = await response.json();
    if (!Array.isArray(payload.items)) throw new LiveInventoryError("unavailable", "The local inventory response was invalid.");
    items.push(...payload.items);
    const nextCursor = typeof payload.nextCursor === "string" ? payload.nextCursor : null;
    if (nextCursor && cursors.has(nextCursor)) {
      throw new LiveInventoryError("unavailable", "The local inventory returned a repeated pagination cursor.");
    }
    if (nextCursor) cursors.add(nextCursor);
    cursor = nextCursor;
  } while (cursor && items.length < MAX_LIVE_DEVICES);
  return mapInventoryDevices(items, MAX_LIVE_DEVICES);
}
