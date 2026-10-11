# Network Scout Architecture Decisions

Status: Stage 0 decision log

## ADR-001 — Preserve source repositories during initial integration

Decision: create a clean standalone application package later; do not merge or relocate the supplied repositories during Stage 0.

Reason: both projects remain useful comparison and rollback points, and their runtime models are materially different.

## ADR-002 — LAN Observer is the source for real observations

Decision: reuse its adapters, reconciliation rules, persistence mechanics, diagnostics, monitoring, and operational controls.

Reason: these paths already encode conservative scope, identity, and evidence semantics with tests.

## ADR-003 — Network Lab remains an explicit simulation domain

Decision: reuse UI primitives and simulation concepts only behind separate types, APIs, storage, and labeling.

Reason: its packets, links, reachability, and findings are synthetic and cannot be represented as observed evidence.

## ADR-004 — Keep Python, React, and SQLite

Decision: retain the existing primary technologies for the initial standalone product.

Reason: they fit the current code, local-first deployment, and interactive topology needs. A framework rewrite has no Stage 0 evidence-based justification.

## ADR-005 — Flask is conditional, not assumed

Decision: Flask may remain if Stage 1 can implement strict validation, local-session security, consistent errors, and SSE cleanly. Otherwise propose a measured migration ADR.

Reason: replacing a framework is not itself a security control; the important properties are explicit middleware and testable boundaries.

## ADR-006 — Use one unprivileged application service and narrow workers

Decision: the application service owns API and domain orchestration; diagnostic workers accept stored typed jobs. Future privileged features require separate helpers.

Reason: this limits command authority and makes authorization and cancellation auditable.

## ADR-007 — Loopback is defense in depth, not authentication

Decision: enforce host/origin/session/capability controls even for the local API.

Reason: browsers and same-user processes can reach loopback; an unauthenticated token endpoint does not prove identity.

## ADR-008 — Server-Sent Events before WebSockets

Decision: use SSE for initial event delivery.

Reason: Stage 1 needs server-to-client updates, not arbitrary bidirectional messaging. SSE has a smaller protocol and authorization surface.

## ADR-009 — Evidence is first-class

Decision: device identities, events, findings, and edges retain source, time, confidence, and evidence references.

Reason: the product must distinguish fact, inference, user input, and simulation and explain every security claim.

## ADR-010 — No subnet-derived physical topology

Decision: common addressing can group devices logically but cannot create a physical edge.

Reason: subnet membership does not establish switch port, radio association, or cable connectivity.

## ADR-011 — Exact MAC is a conservative initial merge key

Decision: retain exact-MAC automatic merging while flagging locally administered/randomized and conflicting observations. Do not merge by IP or hostname alone.

Reason: this preserves existing behavior while avoiding obvious DHCP/IP reuse errors. Later reconciliation can add evidence-backed, reversible rules.

## ADR-012 — API contracts are versioned and bounded

Decision: place production routes under `/api/v1` with strict schemas, pagination, body/collection limits, and stable error codes.

Reason: current ad hoc objects are too permissive for sensitive real-network data and future clients.

## ADR-013 — Active work is policy-gated twice

Decision: authorize scope at job creation and revalidate it when the worker starts.

Reason: interfaces, routes, approved networks, and device addresses can change while a job is queued.

## ADR-014 — No generic remote command or real terminal endpoint

Decision: diagnostics and future management use named typed capabilities only. Network Lab's terminal remains simulated.

Reason: generic command execution is incompatible with least privilege, clear confirmation, and safe AI interoperability.

## ADR-015 — Additive database migrations with verified backups

Decision: extend the observer's `user_version`, integrity-check, SQLite-backup, and newer-schema rejection pattern.

Reason: device history is sensitive and difficult to reconstruct; migrations must be recoverable.

## ADR-016 — Dependency locks and SBOM are release prerequisites

Decision: pin/lock Python and JavaScript dependencies, remove unused packages, audit in CI, and generate an SBOM.

Reason: the current unpinned Python set and vulnerable frontend lock prevent a reproducible security baseline.

## ADR-017 — Boundary-oriented monorepo without a compatibility rewrite

Decision: place the observer in `backend/observer`, React in `frontend`, the
simulator in `simulation`, and optional adapters in `integrations`. Preserve the
internal `cyber_scout` namespace and migrations 1–6 until adapters and packaging
provide a tested transition.

Reason: package renaming during repository migration creates risk unrelated to
the live-canvas objective.

## ADR-018 — Retain the custom canvas for the first live slice

Decision: reuse and measure the existing canvas before adding React Flow or
another dependency. A change requires evidence on accessibility, performance,
maintenance, license, audit, bundle size, and integration effort.

## ADR-019 — Authenticated SSE for incremental updates

Decision: use bounded SSE with `Last-Event-ID`, heartbeat, and snapshot resync.
Stage 3 has no bidirectional streaming requirement that justifies WebSockets.

## ADR-020 — Unified MIT license with explicit provenance

Decision: license the new owner-authorized repository under MIT and retain a
NOTICE identifying both sources and their lack of a declared GitHub-detectable
license at migration time.

## Deferred decisions

- Final Python API framework, pending a Stage 1 proof against the required security and SSE behavior.
- Packaging format (native package, container, bundled desktop shell), pending Linux install/uninstall prototypes.
- Local session bootstrap mechanism, pending desktop integration and threat-focused testing.
- Future capture-helper IPC and privileges; not authorized in early stages.
- Future AI protocol and remote-management adapters; core capability contracts must precede either.
