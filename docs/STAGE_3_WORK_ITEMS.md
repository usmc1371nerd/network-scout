# Stage 3 Reviewable Work Items

Status: prepared only; implementation requires explicit human approval.

## Milestone 3.1 — Actual inventory as read-only canvas nodes

Deliver this milestone in small reviewable commits or pull requests:

1. Add a read-only inventory projection over the existing observer repository.
   Preserve stored IDs and migrations 1–6; do not write during reads or add a
   schema migration.
2. Implement authenticated, bounded `GET /api/v1/inventory/devices` with exact
   Host checks, `inventory.read`, stable errors, pagination/filter limits, and
   contract/security tests. Reuse the owner-private local capability; do not add
   query credentials or an unauthenticated bootstrap.
3. Introduce an explicit Live UI mode and adapter. Map one returned device to
   one node keyed by `device.id`; never key by IP, hostname, array index, or a
   simulation identifier.
4. Render actual inventory nodes read-only on the React canvas, with a textual
   Live indicator, safe labels, loading/empty/error states, keyboard-accessible
   inventory alternative, and no simulated mutation controls.
5. Add duplicate-ID, hostile-label, authentication, Host, pagination, empty
   inventory, reload, and compatibility regressions. Measure baseline behavior
   at 50, 250, 500, and 1,000 nodes and document the supported initial budget.

Acceptance requires all existing observer, simulator, frontend build, dependency
audit, and repository-security checks to remain green. It also requires proof
that an existing database opens at schema 6 with unchanged IDs and that Live
mode cannot call simulation or active-discovery endpoints.

Explicitly excluded: SSH, generic commands, remote administration, AI/agent
integration, simulation-to-live execution, active scanning changes, layout
writes, topology edges, SSE, and migration 7.

Stop for human review after Milestone 3.1.

## Later milestones (not authorized)

- **3.2 — Layout persistence:** additive migration 7, conditional layout writes,
  retained IDs, backup/rollback tests, and viewport restoration.
- **3.3 — Evidence-backed edges:** render only persisted, sourced relationships;
  explicitly communicate unknown topology.
- **3.4 — Incremental updates:** authenticated fetch-stream SSE with bounded
  reconnection, `Last-Event-ID`, cursor retention, and snapshot resync.
- **3.5 — Hardening and release:** accessibility/performance gates, SAST,
  reproducible Python locking, SBOM, third-party notices, and packaging checks.

Each milestone starts only after explicit human approval and is reviewed and
merged separately.
