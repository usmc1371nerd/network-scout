# Network Scout Integration Plan

Status: migration foundation established; Stage 3 implementation not started.

## Migration foundation completed

- The official repository is divided into observer, frontend, simulation, and
  optional Omarchy integration boundaries.
- Validated Stage 1/2 working-tree code is preserved under `backend/observer`.
- The React canvas and simulator remain disconnected from live inventory.
- `API_V1.md` defines the proposed transport; `STAGE_3_PLAN.md` defines delivery
  and verification gates.
- Both original repositories remain unchanged reference implementations.

## Integration strategy

Use the LAN Observer as the initial backend substrate and selectively extract Network Lab UI concepts. Do not make either repository a dependency of the other and do not copy their entire directory trees into a combined application.

### Reuse from LAN Observer

- `Observation` normalization and passive adapter protocol.
- Exact-MAC identity behavior and conservative address-only handling.
- SQLite backup/migration mechanics and parameterized repository methods.
- Bounded diagnostic and scan job construction.
- Current-network scope calculation and scheduled-scan gates.
- Zeek/Suricata allowlisted metadata parsers and ingestion budgets.
- Structured rotating logs and user-service hardening templates.
- Existing tests as characterization tests.

### Reuse from Network Lab

- Canvas interaction patterns: drag, zoom, pan, node selection, edge editing.
- Presentational components after accessibility and data-contract review.
- Simulation graph/routing concepts inside a dedicated simulation module.
- Terminal and packet log only as explicitly simulated educational experiences.

### Do not reuse directly

- Global mutable React state as durable inventory.
- Client-supplied graph state as trusted backend state.
- Wildcard Flask CORS or the unauthenticated `/api/run-command` contract.
- Topology-only security heuristics for real-network findings.
- Synthetic MAC, packet, reachability, route, or edge data in observed mode.
- A generic terminal/command endpoint for real devices.

## Migration sequence

### Phase 1 — contracts and characterization

1. Create a new standalone application package without moving either source repository.
2. Record the v1 domain schemas from `ARCHITECTURE.md` as validated Python and JSON contracts.
3. Wrap the current observer database and adapters behind repository/service interfaces.
4. Add characterization tests for existing discovery, identity, jobs, migrations, dashboard reports, and sensors.
5. Define a compatibility adapter for `scanner.py` and QML JSON fields.

Exit: existing observer behavior is reproduced through interfaces; no React integration.

### Phase 2 — secure local application core

1. Implement configuration loading with strict unknown-key and type rejection.
2. Introduce an authorization service and append-only audit records.
3. Implement `/api/v1` read models and typed command requests.
4. Add authenticated local-session bootstrap, host/origin enforcement, body limits, pagination, and rate limits.
5. Add structured errors and SSE event delivery.
6. Keep diagnostics workers unprivileged and reconstruct fixed argv from stored jobs.

Exit: Stage 1 acceptance criteria are met with a minimal non-canvas client or API tests.

### Phase 3 — data migration and compatibility

1. Add additive SQLite migrations for authorization decisions, audit actions, schema-versioned evidence, and later topology/layout records.
2. Preserve v4 data and legacy JSON caches; import only after preview and backup.
3. Maintain `scanner.py` output compatibility for the Omarchy widget.
4. Provide migration verification, rollback instructions, and supported-version checks.

Exit: upgrade and rollback are tested from representative v1-v4 databases.

### Phase 4 — React shell and real inventory

1. Create React inventory/detail/timeline views against read-only `/api/v1` routes.
2. Extract canvas primitives from Network Lab and replace direct object assumptions with DTO adapters.
3. Persist user layout separately from observed identity and evidence.
4. Render devices without edges when relationship evidence is absent.

Exit: real devices can be viewed and arranged without fabricated relationships.

### Phase 5 — isolated simulation mode

1. Port simulator state and algorithms under `/simulation` with a permanent mode banner.
2. Use simulation-specific IDs, DTOs, routes, storage, and event types.
3. Disable all real diagnostics and inventory writes while consuming simulation objects.
4. Label packet logs, terminal sessions, security insights, and links as simulated.

Exit: automated tests prove no simulation record can masquerade as observed evidence.

## Detailed Stage 1 implementation plan

1. Establish package layout for `api`, `core`, `inventory`, `discovery`, `monitoring`, `diagnostics`, and `security`.
2. Define validated configuration and API schemas with explicit bounds.
3. Port/adapt `InventoryStore` behind repository interfaces; add migration and backup tests.
4. Add authorization capability names and decision/audit persistence before adding write routes.
5. Implement secure local-session bootstrap and deny requests with invalid host, origin, session, content type, or body size.
6. Expose inventory, device detail, observations, events, and health through read-only `/api/v1` endpoints.
7. Implement diagnostic job submission using existing device/address ownership and target-scope checks.
8. Add SSE for bounded, replayable event notifications with cursor support.
9. Preserve QML behavior via a compatibility adapter.
10. Add CI for Python/JS tests, lint/static checks, dependency audit, secret scan, and build verification.

## Stage 1 test matrix

- Config: bad types, unknown keys, unsafe paths, public scan ranges, permission failures.
- Identity: DHCP churn, duplicate IPs, randomized/cloned MACs, IPv4/IPv6, address-only evidence.
- API: unauthenticated access, DNS-rebinding host, hostile origin, CSRF, CORS, oversized/deep body, invalid pagination.
- Storage: clean install, each migration, newer schema rejection, interrupted migration, WAL backup/restore, permissions.
- Jobs: wrong device/address, changed interface scope, cancellation, timeout, missing executable, output cap, concurrency.
- Events: deduplication, ordering, replay cursor, backpressure, reconnect.
- Compatibility: stable widget payload and no hidden active scan.

## Dependencies and build plan

- Add exact Python dependency constraints and a resolved lock with hashes for supported Python versions.
- Remove unused `axios` if the React app continues to use `fetch`; otherwise upgrade and justify it.
- Keep the tested Vite 8 lock current through reviewed lock-file refreshes; do
  not use `npm audit fix --force` blindly.
- Pin container base images by digest for releases and run the service as a non-root user.
- Generate an SBOM and run advisory scanning in CI.

## Rollback

- Never mutate the existing repositories during initial extraction.
- Every database migration creates a verified backup and rejects newer unsupported schemas.
- New API routes are additive; keep the QML compatibility adapter until a separately approved deprecation.
- Feature flags default off for active discovery, background services, sensors, AI, and management.
- A failed stage returns to the previous package/database version using documented backup restore.

## Stage gates

- Stage 1 cannot add topology inference, real remote management, AI tools, or privileged capture.
- Stage 2 requires separate approval after Stage 1 evidence is reviewed.
- Canvas work begins only after core identity and API contracts are stable.
