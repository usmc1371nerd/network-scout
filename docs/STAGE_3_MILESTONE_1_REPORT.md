# Stage 3 Milestone 1 Completion Report

Status: implemented on a feature branch; requires human review before merge.

## Delivered scope

- Added authenticated, Host-validated, read-only
  `GET /api/v1/inventory/devices` over the existing observer database.
- Added strict single-value query parsing, allowlisted filters, page sizes from
  1 to 250, filter-bound opaque cursors, a 1,000-device projection ceiling, and
  stable JSON error envelopes.
- Kept SQLite at schema version 6. Reads preserve stored device IDs and never
  modify inventory or identity evidence.
- Added a distinct Live Network mode. It obtains the owner capability from the
  existing launcher fragment, removes the fragment from browser history, uses
  only the authenticated inventory route, deduplicates by persistent ID, and
  caps rendering at 1,000 devices.
- Added read-only canvas nodes and an accessible inventory list with names,
  status, address, category/manufacturer, and recognition. Labels are rendered
  through React text nodes. No topology edges are created.
- Live mode has no simulator terminal, packets, device/link mutation callbacks,
  active discovery actions, or simulation API calls.

## Verification

- Observer: 55 tests passed, including authentication, exact Host rejection,
  pagination validation, cursor/filter binding, persistent IDs, and hostile
  labels.
- Frontend: 5 tests passed, including duplicate IDs, hostile/control-character
  labels, 1,000-node limit, authenticated endpoint isolation, and distinct
  authentication/backend-unavailable errors.
- Simulator: 4 tests passed unchanged.
- Frontend production build passed.
- Full npm audit reported zero vulnerabilities. Python dependency audit reported
  no known vulnerabilities.
- `git diff --check`, Python compilation, and generated bundle checks passed.

## Baseline measurements

Measured locally against generated schema-6 inventories. These are engineering
baselines, not release service-level objectives.

| Devices | Backend full projection/paging | Frontend mapping |
|---:|---:|---:|
| 50 | 2.79 ms | 0.33 ms |
| 250 | 13.36 ms | 0.43 ms |
| 500 | 60.30 ms | 0.46 ms |
| 1,000 | 227.68 ms | 1.39 ms |

Browser frame-rate and interaction profiling remains a limitation: this slice
uses a deterministic grid and scrollable canvas, but does not claim a measured
1,000-node interaction-frame budget. Virtualization or a canvas-library change
requires measured evidence and a later approved decision.

## Intentional limitations

- Status is `reachable` only when recent positive activity/connectivity exists;
  all other devices are `unknown`. This milestone does not infer
  `unavailable` from silence or a failed probe.
- Inventory is a snapshot loaded at mode entry. Incremental refresh/SSE belongs
  to Milestone 3.4 and is not implemented.
- Positions are deterministic and not persisted. Layout migration 7 and layout
  writes belong to Milestone 3.2.
- The 1,000-device ceiling bounds memory and DOM work. Inventories beyond that
  are intentionally truncated in this milestone.
- The existing owner-private capability remains subject to the documented lack
  of expiry, rotation, and targeted revocation.

## Excluded and unchanged

No migration 7, topology edges, layout writes, SSE, SSH, remote administration,
AI interoperability, generic command execution, simulated-to-live execution,
or active-scanning changes were added.
