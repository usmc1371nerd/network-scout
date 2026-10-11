# Stage 3 Implementation Plan — Interactive Live Network Canvas

Status: proposed; implementation requires separate approval.

## Objective and minimum architecture

Automatically display real devices from the observer inventory on the reusable
React canvas. Add only the service adapter, topology/layout persistence, API
read model, SSE notifications, and UI mode separation needed for that outcome.
Do not rewrite discovery or the canvas and do not invent physical links.

## Reuse, refactor, and new modules

- Reuse `backend/observer/cyber_scout` migrations, IDs, repositories, security
  helpers, discovery, and evidence reports without changing existing IDs.
- Reuse canvas zoom, pan, drag, rendering, and selection primitives from
  `frontend/src/components/NetworkCanvas.jsx`.
- Keep `simulation/backend` and current simulation state isolated.
- Refactor the canvas to accept a mode-specific typed adapter instead of owning
  all simulation mutations directly. Live mode cannot add synthetic devices or
  call the simulator command endpoint.
- Add backend `api_v1` handlers/DTO validation, inventory projection queries,
  topology repositories, layout service, state projector, and bounded event
  stream.
- Add frontend API client, live inventory store, SSE reconnect controller,
  node mapper, accessible mode banner, evidence panel, and layout persistence
  queue.

## Database migrations

Add migration 7; never squash migrations 1–6.

- `topology_edges`: stable ID, source/destination device foreign keys,
  perspective, relationship/evidence types, confidence, verification status,
  first/last observation, expiry, revision, details JSON, unique evidence key.
- `topology_layouts`: layout ID, name, viewport JSON, revision, timestamps.
- `topology_positions`: layout/device foreign keys, finite x/y, pinned flag,
  revision, timestamps, unique layout/device.
- `event_stream_cursor` or an equivalent monotonically ordered event projection
  enabling resumable SSE without storing unbounded payloads.

Migration tests must cover fresh creation, v6 upgrade with backup, rollback on
failure, foreign keys, retained IDs/metadata, and widget compatibility.

## Integration flow

1. Existing passive adapters write normalized observations and evidence.
2. Inventory projection derives an honest state from positive evidence and
   configured age windows; a failed ping alone never means unavailable.
3. Authenticated `/api/v1/topology/nodes` pages existing devices into React.
4. The client keys nodes by persisted `deviceId`, preventing duplicates.
5. New nodes receive a deterministic collision-aware default position only when
   no saved position exists.
6. Drag completion batches a conditional layout update; restart restores saved
   positions and viewport.
7. SSE sends IDs/revisions. The client deduplicates events and fetches changed
   resources; reconnect uses `Last-Event-ID` and falls back to snapshot resync.
8. Edges render only from persisted evidence. An empty/unknown topology is a
   valid and clearly explained state.

The complete proposed wire contract is in `API_V1.md`.

## Security plan

- Preserve loopback bind, owner-private capability, exact Host validation,
  same-origin write checks, and authorization-decision audit records.
- Add capability checks for `inventory.read`, `topology.read`,
  `topology.layout.write`, and `events.read`; never infer authority from CORS.
- Bound request bodies, pagination, filters, layout counts/coordinates, SSE
  clients, buffers, event size, reconnect frequency, and database query time.
- Escape all device-controlled labels. Exclude raw sensor payloads and redact
  secrets/network details from logs and errors.
- Use ETag/If-Match to prevent lost layout writes. Use parameterized SQL and
  allowlisted filters/sorts.
- Simulation DTOs carry an explicit mode discriminator and are rejected by live
  diagnostic, discovery, and layout services.
- Keep tokens out of URLs after bootstrap, local storage, event payloads, export
  files, and telemetry.

Threat regressions must cover missing/wrong token, hostile Host, hostile/missing
Origin on writes, DNS-rebinding shapes, oversized/deep bodies, invalid cursors,
layout coordinate abuse, XSS labels, SSE connection exhaustion, stale ETags,
simulation/live ID confusion, and attempts to form edges from subnet membership.

## Functional test matrix

- Existing devices automatically create exactly one node per stable ID.
- Repeated snapshots and events cannot duplicate nodes.
- Manual positions and viewport survive refresh and application restart.
- New device placement does not overlap pinned nodes within a defined tolerance.
- Disappearance changes state but does not destroy identity or layout;
  reappearance restores the same node and position.
- Incremental updates are ordered/idempotent and cursor gaps force a resync.
- Reachable, unavailable, and unknown states require their documented evidence.
- Detail panels show address/hostname history, source, confidence, conflicts, and
  timestamps without claiming certainty.
- No edge appears without a stored source, type, confidence, timestamps, and
  verification status. Zero edges explains that physical topology is unknown.
- Restart from a v6 database preserves devices and recovers layout after v7.
- Live and Simulation modes have visible persistent banners, separate stores,
  endpoints, controls, and test fixtures.
- Existing Omarchy compatibility tests continue to pass.

## Performance test matrix and budgets

- Benchmark snapshots and canvas interaction at 50, 250, 500, and 1,000 nodes;
  establish measurements before selecting virtualization or a new library.
- Target a responsive interaction loop at the supported default inventory size;
  batch React updates and avoid whole-graph recomputation for one device.
- Verify indexed device, position, edge, and event-cursor queries with query
  plans and bounded page latency on representative databases.
- Test event bursts, slow clients, heartbeat behavior, disconnect cleanup,
  exponential reconnect with jitter, cursor expiry, and memory caps.
- Record server/client idle memory, 1,000-node snapshot memory, and sustained
  event-stream memory. Fail tests on unbounded queue growth.

## Usability and accessibility

- Default labels prefer user name, safe hostname, manufacturer/category, then a
  plain “Unknown device” label.
- Explain states and confidence in plain language with optional technical detail.
- Live/Simulation mode must be conveyed by text and structure, not color alone.
- Canvas nodes and controls require keyboard focus, accessible names, sufficient
  contrast, reduced-motion support, and list/table alternatives.
- Responsive layouts keep core inventory usable without the canvas.
- Advanced evidence, addresses, conflicts, and diagnostics are progressively
  disclosed.

## Canvas library decision gate

Retain the custom canvas for the first integration slice because it already
implements required pan, zoom, drag, and node rendering with no production
dependency. Benchmark and accessibility-test it first. Consider React Flow only
if measured keyboard accessibility, edge rendering, or large-graph maintenance
cost cannot be addressed reasonably. Any adoption requires a new ADR covering
current maintenance activity, license, production dependency audit, bundle-size
delta, migration effort, and measured performance. No new canvas dependency is
approved by this plan.

## Delivery sequence and stop gates

1. Migration 7 and repository/state projector tests.
2. Authenticated read-only inventory/topology API and contract tests.
3. React mode boundary and read-only live node rendering.
4. Persistent layout writes with concurrency controls.
5. Evidence-backed edges and explicit unknown-topology presentation.
6. SSE incremental updates and reconnect/resync behavior.
7. Accessibility, performance, security regression, compatibility, and release
   verification.

Each slice must preserve green observer and simulator tests. No PR is merged
without review, and no later stage begins without approval.
