# Proposed Local API v1 Contract

Status: Stage 3 design proposal; routes are not implemented in the migration
foundation.

## Common protocol

- Base path: `/api/v1`; JSON responses use UTF-8.
- Default listener: `127.0.0.1` only. Exact allowed Host validation applies to
  every request. Browser writes additionally require an allowed same-origin
  Origin.
- Every endpoint below requires the owner-controlled local session capability.
  Read capabilities are distinct from write capabilities. Layout writes require
  `topology.layout.write`; inventory and event reads require their corresponding
  read capability.
- The compatibility launch token is supplied in `X-Network-Scout-Token`. The
  header name may change only with a compatibility transition and tests. Tokens
  never appear in query strings, logs, response bodies, or persistent inventory.
- Browser clients use authenticated `fetch()` requests for both JSON and the
  event stream. They must not use native `EventSource`: its constructor cannot
  attach the required capability header. The stream remains SSE on the wire,
  but the client reads and parses `response.body`, reconnects with bounded
  exponential backoff and jitter, and supplies `Last-Event-ID` as a header.
- Collection defaults: `limit=100`, maximum `250`; `cursor` is an opaque stable
  continuation token. Invalid or expired cursors return `400 invalid_cursor`.
- Timestamps are UTC RFC 3339 strings at the API boundary. Stored legacy Unix
  seconds are converted in the adapter.
- `ETag` represents the returned projection version. Mutating requests require
  `If-Match` where documented; stale versions return `409 version_conflict`.
- Unknown response fields must be ignored by clients. Removing/renaming fields
  or changing their meaning requires a new API version.

## Error envelope

```json
{
  "error": {
    "code": "validation_error",
    "message": "The request could not be accepted.",
    "requestId": "opaque-id",
    "fields": [{"path": "positions[0].x", "code": "out_of_range"}]
  }
}
```

Expected statuses: `400` malformed/validation, `401` missing or invalid session,
`403` capability/origin/scope denial, `404` absent resource, `409` version
conflict, `413` body/collection limit, `429` rate limit, and `500` redacted
internal error. No error includes SQL, filesystem paths, commands, tokens, raw
sensor payloads, or stack traces.

## Inventory devices

### `GET /api/v1/inventory/devices`

Capability: `inventory.read`.

Filters: `cursor`, `limit`, `recognition`, `state`, `category`, `updatedAfter`,
and bounded `search` (maximum 128 characters). State is
`reachable|unavailable|unknown`; it is an explicit projection and not inferred
from one failed ping.

```json
{
  "dataVersion": 1,
  "items": [{
    "id": "stable-device-uuid",
    "displayName": "Living-room printer",
    "category": "printer",
    "recognition": "recognized",
    "state": "reachable",
    "identityConfidence": 0.85,
    "addresses": [{"family": 4, "address": "192.0.2.10", "interface": "eth0", "lastObservedAt": "2026-10-10T20:00:00Z"}],
    "firstObservedAt": "2026-10-01T10:00:00Z",
    "lastObservedAt": "2026-10-10T20:00:00Z",
    "revision": 7
  }],
  "nextCursor": null
}
```

### `GET /api/v1/inventory/devices/{id}`

Capability: `inventory.read`. Returns the summary plus hostname/address history,
services, recognition, notes, evidence, identity conflicts, and bounded recent
events. Evidence fields are `type`, `value`, `source`, `confidence`,
`firstObservedAt`, `lastObservedAt`, and sanitized `details`. Raw sensor records
are excluded.

## Topology

### `GET /api/v1/topology/nodes`

Capability: `topology.read`. Same pagination and filters as devices. A node has
`id`, `deviceId`, `label`, `category`, `state`, `identityConfidence`,
`hasConflict`, `lastObservedAt`, and `revision`. One live device maps to at most
one live node; `deviceId` is the uniqueness key.

### `GET /api/v1/topology/edges`

Capability: `topology.read`. Filters: `cursor`, `limit`, `relationshipType`,
`verificationStatus`, `updatedAfter`.

Each edge contains `id`, `sourceDeviceId`, `destinationDeviceId`, `perspective`
(`physical|logical|traffic|inferred|manual`), `relationshipType`,
`evidenceSource`, `confidence`, `firstObservedAt`, `lastObservedAt`,
`verificationStatus` (`verified|observed|inferred|user_defined|unknown`), and
`revision`. Shared subnet membership never creates an edge.

### `GET /api/v1/topology/layout`

Capability: `topology.read`. Returns:

```json
{
  "dataVersion": 1,
  "layoutId": "live-default",
  "revision": 12,
  "viewport": {"x": 0, "y": 0, "zoom": 1},
  "positions": [{"deviceId": "uuid", "x": 120, "y": 80, "pinned": true}]
}
```

### `PUT /api/v1/topology/layout`

Capability: `topology.layout.write`; exact Origin and `If-Match` required. Body
maximum is 256 KiB, at most 1,000 unique positions. Coordinates must be finite
numbers in `[-100000,100000]`; zoom is `[0.1,4]`; unknown keys are rejected.
Writes are transactional and record an authorization decision and audit event.
Returns the new representation and ETag. Layout never changes device identity or
observation evidence.

## Incremental events

### `GET /api/v1/events/stream`

Capability: `events.read`. Response is `text/event-stream`. Clients send
`Last-Event-ID` on reconnect. The server emits a heartbeat at most every 30
seconds and caps each session's buffered events and total connections.

The browser opens this route with same-origin `fetch()` and sends
`X-Network-Scout-Token` plus `Accept: text/event-stream`. It consumes the
response as a `ReadableStream` and implements the SSE field parsing and
reconnection rules. Native `EventSource`, capability-bearing query parameters,
cookies introduced solely for streaming, wildcard CORS, and token-bearing URLs
are prohibited. The server applies the same exact Host, session, capability,
rate, and connection-limit checks used by other sensitive reads. If the client
sends an `Origin` header, it must be the allowed local origin.

Event names: `inventory.device.upserted`, `inventory.device.state_changed`,
`inventory.device.removed`, `topology.edge.upserted`, `topology.edge.removed`,
`topology.layout.changed`, and `stream.resync_required`.

```text
id: 8421
event: inventory.device.upserted
data: {"dataVersion":1,"occurredAt":"2026-10-10T20:00:00Z","deviceId":"uuid","revision":7}
```

Events contain identifiers and revisions, not full sensitive records. The client
fetches authorized projections. If an event cursor is outside retention, the
server sends `stream.resync_required`; the client reloads snapshots. SSE is
preferred because Stage 3 requires server-to-client updates only. No WebSocket
dependency is justified.

## Validation and compatibility

- Path IDs must be canonical UUIDs or the existing opaque persisted IDs during
  migration, maximum 64 characters.
- Search, labels, and notes have explicit length and control-character limits.
- Arrays, nesting depth, body size, and query counts are bounded before database
  or graph work.
- SQL is parameterized; sort/filter names are allowlisted.
- Existing SQLite device IDs remain unchanged. API DTO conversion never rewrites
  inventory during a read.
- Compatibility dashboard routes remain available during Stage 3 and retain
  their authentication. `/api/v1` is not an unauthenticated alias.
- Simulation endpoints use a separate `/api/simulation/v1` namespace when they
  are migrated. Simulation identifiers and DTOs are rejected by live commands.
