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

## Final pre-merge validation

PR #3 was exercised end to end with a disposable schema-6 SQLite inventory and
a non-sensitive test capability. Isolated backend and Vite processes listened
only on `127.0.0.1`. Authenticated paging returned stable, unique persistent
IDs; missing and invalid capabilities returned 401; malformed and
filter-mismatched cursors returned 400; and an invalid Host returned 421.

Headless Chromium verified authenticated Live rendering for 50, 250, 500, and
1,000 synthetic records. Empty and malformed responses produced the intended
empty/backend-unavailable states. A hostile HTML/event-handler label appeared
only as escaped text. The Live DOM exposed no simulator palette, terminal, or
device mutation controls, and its requests were limited to the read-only
inventory endpoint. Browser output and backend logs contained neither the test
capability nor hostile-label execution.

Browser cancellation during development remounts exposed a noisy
`BrokenPipeError` in the local HTTP server. Response writing now treats client
disconnect/reset as a completed, unusable response rather than retrying or
logging a traceback; a regression test covers the behavior.

Post-correction verification: 56 observer tests, 5 frontend tests, and 4
simulator tests passed; the production build, Python compilation,
`git diff --check`, npm audit, and Python dependency audit also passed. The
simulator suite initially could not collect under the system Python because its
Flask dependencies were not installed globally; it passed in the project's
prepared dependency environment.

Manual visual inspection of the 50-record browser capture confirmed readable
Live nodes and a separate Simulation Lab selector. Interactive pointer/keyboard
behavior and browser frame-rate profiling at 1,000 nodes were not manually
tested. Cursor time-expiry was not tested because Milestone 1 cursors are
filter-bound pagination tokens without a TTL; malformed and context-invalid
cursors were covered.

### Pre-merge observation follow-up

The reported five-versus-four discrepancy was a viewport presentation issue,
not a missing record or React rendering failure. The fifth node occupied the
fifth column of the deterministic grid and remained reachable by the existing
Space+Drag panning control, but a narrow initial viewport clipped that column.
Live mode now calculates a transient fit transform after inventory load and
provides a keyboard-accessible **Fit devices** control. The calculation covers
all loaded nodes through the 1,000-node limit. It does not store coordinates,
write inventory, add migration 7, or affect Simulation mode layout.

A 900×700 headless Chromium reproduction with five schema-6 inventory records
showed all five nodes simultaneously in the initial Live viewport. Targeted
geometry tests cover the five-node narrow viewport and the 1,000-node bound;
Space+Drag panning and Ctrl+Scroll zoom remain available.

The observed `BrokenPipeError` is consistent with an expected browser-side
disconnect: navigation, cancellation, or a React development remount can close
an in-flight local response. The response boundary catches only
`BrokenPipeError` and `ConnectionResetError` while emitting headers or writing
the body. It does not retry the response, log request context or capability
material, or suppress unrelated exceptions. Regression coverage exercises both
disconnect types during both header and body writes and proves an unrelated
`RuntimeError` still propagates.

After these checks, 57 observer tests and 7 frontend tests passed, along with
the production build, Python compilation, `git diff --check`, npm audit, and
Python dependency audit. A scoped security diff review found no reportable
security issues in the viewport changes.
