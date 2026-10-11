# Network Scout Architecture

Status: migration foundation, preserving the Stage 0 design baseline (2026-10-10)

## Unified repository boundary

- `backend/observer`: compatibility-preserving observation service and SQLite
  migrations 1–6. The internal `cyber_scout` name remains to avoid breaking
  imports, services, and installed databases.
- `frontend`: reusable React presentation and existing simulation client.
- `simulation/backend`: synthetic topology and packet behavior only.
- `integrations/omarchy`: optional desktop adapter assets.

Live inventory is intentionally not connected to React in this foundation. See
`API_V1.md` and `STAGE_3_PLAN.md` for the separately approved implementation.

## Scope and conclusions

Cyber Scout should evolve from the two supplied repositories without merging their runtimes wholesale:

- `omarchy-cyber-scout-widget` is the source of truth for real observations, device identity, SQLite history, bounded diagnostics, monitoring, and the existing local dashboard.
- `network-lab` is reusable as a visual and educational component library. Its topology, traffic, terminal, packet, and security behavior is simulated and must remain in an explicitly labeled simulation mode.
- The standalone product should use one Python service boundary, one versioned SQLite store, and a React client. The Omarchy widget remains an optional adapter over stable application APIs.

The current observer already provides more Stage 1 foundation than the original project notes imply. It has schema migrations, conservative identity rules, passive adapters, bounded active jobs, sensor ingestion, user-service templates, and tests. These components should be extracted behind interfaces, not rewritten.

## Current systems

### LAN Observer inventory

| Area | Current implementation | Reuse decision |
|---|---|---|
| Discovery | Linux `ip -j address`, `ip -j neigh`, and `ip monitor neigh` | Reuse behind Linux adapters |
| Identity | Exact normalized MAC merge; address-only observations remain unassigned | Reuse and extend with evidence records |
| Persistence | SQLite schema v6 with inventory, jobs, findings, authorization decisions, identity evidence/conflicts, and cursors | Reuse through repositories and additive migrations |
| Active operations | Fixed argv `ping`/`nmap` jobs, timeouts, cancellation, private current-network scope | Reuse behind policy and authorization services |
| Monitoring | Periodic passive reconciliation and optional Zeek/Suricata JSON ingestion | Reuse as independently testable adapters |
| API/UI | Authenticated standard-library loopback HTTP server plus QML widget | Keep as compatibility surfaces during migration |
| Operations | User services, restrictive permissions, backups, restore validation, bounded logs | Reuse and strengthen |

### Network Lab inventory

| Area | Current implementation | Reuse decision |
|---|---|---|
| Canvas | React draggable nodes, zoom/pan, link editing, device palettes | Extract presentation and interaction primitives |
| Simulator | Client and Flask graph/routing/packet simulation | Preserve in a separate `simulation` domain |
| Terminal | Simulated SSH, ping, traceroute, Bluetooth, packet behavior | Simulation-only; never connect to a real shell |
| Security insights | Topology heuristics over user-created simulated links | Educational simulation-only; do not apply to observed topology |
| Persistence | React memory only | Do not reuse as inventory storage |
| API | One bounded simulation-only Flask command endpoint; it is not an inventory API | Keep isolated; namespace during Stage 3 |

## Target logical architecture

```text
React application ─────── local API / event stream ────── Application service
  ├─ Inventory view                                      ├─ Query services
  ├─ Evidence topology                                   ├─ Command services
  └─ Simulation mode                                     ├─ Authorization/policy
                                                          └─ Audit/event publisher
                                                                    │
                   ┌────────────────────────────────────────────────┼───────────────┐
                   │                                                │               │
           Discovery adapters                               Diagnostics       Simulation
         Linux neighbor/interface                          fixed operations   isolated model
         Zeek/Suricata metadata                            job runner         no real effects
         future OS adapters
                   │                                                │
                   └──────────────────── Inventory repositories ────┘
                                            │
                                      versioned SQLite

Optional Omarchy adapter ── read models / approved commands ── Application service
```

### Modules

- `core`: identifiers, clocks, typed errors, result types, schema versions.
- `inventory`: devices, addresses, observations, services, history, reconciliation.
- `discovery`: passive source adapters and explicit active-discovery requests.
- `topology`: evidence-backed relationships and saved user layout; no subnet-derived physical edges.
- `monitoring`: schedules, state derivation, event deduplication, alert cooldowns.
- `diagnostics`: allowlisted operations and bounded job execution.
- `security`: authentication, authorization, origin protections, policy checks, audit records.
- `simulation`: Network Lab graph and packet model, with separate types and storage namespace.
- `api`: versioned DTOs, validation, pagination, error mapping, event stream.
- `integrations/omarchy`: QML-facing compatibility and launcher behavior.

## Runtime and trust boundaries

1. The browser is untrusted even on loopback. It receives display DTOs and submits typed commands; it never obtains filesystem or subprocess authority.
2. The API runs as the desktop user, binds to loopback by default, validates origin/host/session, and authorizes every command independently of network binding.
3. Discovery adapters parse untrusted OS/tool/sensor output into bounded typed observations.
4. The diagnostics worker accepts only stored job identifiers and allowlisted operation types. It reconstructs argv from validated stored fields.
5. SQLite and configuration are private local assets. The service owns their paths and permissions.
6. Future privileged capture or management helpers are separate processes with narrow IPC contracts. They are not part of Stage 1.
7. Simulation objects can never be passed to a real diagnostics or management operation without an explicit import/reconciliation workflow.

## Data ownership and schemas

All timestamps are UTC Unix milliseconds at API boundaries and UTC Unix seconds only inside a documented legacy adapter. IDs are opaque UUIDs. Every mutable record includes a schema version.

### Device

```json
{
  "id": "uuid",
  "displayName": "string|null",
  "category": "unknown|computer|phone|tablet|server|router|switch|printer|television|iot|other",
  "recognition": "recognized|unrecognized|ignored",
  "identifiers": [{"kind":"mac","value":"AA:BB:CC:DD:EE:FF","confidence":0.85,"source":"neighbor_table"}],
  "firstObservedAt": 0,
  "lastObservedAt": 0,
  "lastActiveAt": null,
  "lastReachableAt": null,
  "identityConfidence": 0.85,
  "notes": "",
  "version": 1
}
```

Invariant: address, hostname, vendor, or subnet alone never automatically merges two devices. Identity merges record their evidence and are reversible.

### Observation

```json
{
  "id": "uuid",
  "deviceId": "uuid|null",
  "observedAt": 0,
  "source": "linux.neighbor|linux.interface|zeek|suricata|diagnostic",
  "sourceInstance": "string",
  "interface": "string|null",
  "address": "ip|null",
  "mac": "mac|null",
  "state": "observed|active|reachable|stale|unknown",
  "confidence": 0.0,
  "facts": {},
  "version": 1
}
```

Invariant: `observed`, `active`, `reachable`, and `offline` are distinct claims. Negative ICMP results do not prove offline state.

### Topology edge

```json
{
  "id": "uuid",
  "sourceDeviceId": "uuid",
  "targetDeviceId": "uuid",
  "perspective": "physical|logical|traffic|simulation",
  "relationshipType": "string",
  "evidenceSource": "lldp|router_api|sensor_flow|user|simulation|other",
  "evidenceIds": ["uuid"],
  "confidence": 0.0,
  "verificationStatus": "verified|observed|inferred|user_defined|simulated|unknown",
  "firstObservedAt": 0,
  "lastObservedAt": 0,
  "expiresAt": null,
  "version": 1
}
```

Invariant: sharing a subnet, gateway, manufacturer, or address range does not create a physical edge. Inferred, user-defined, and simulated edges are visually and structurally distinct.

### Event

```json
{
  "id": "uuid",
  "eventType": "device.first_observed",
  "subjectType": "device|edge|service|sensor|job|system",
  "subjectId": "uuid|null",
  "occurredAt": 0,
  "recordedAt": 0,
  "severity": "info|notice|warning|high",
  "summary": "plain-language string",
  "evidenceIds": ["uuid"],
  "dedupeKey": "string|null",
  "acknowledgedAt": null,
  "dismissedAt": null,
  "details": {},
  "version": 1
}
```

### Authorization decision

```json
{
  "id": "uuid",
  "actor": {"type":"local_user|service|future_ai","id":"string"},
  "capability": "inventory.read|diagnostics.ping|discovery.active",
  "resource": {"type":"device|network|setting","id":"string"},
  "decision": "allow|deny",
  "reason": "policy rule identifier",
  "requestedAt": 0,
  "decidedAt": 0,
  "confirmationId": "uuid|null",
  "requestContext": {"origin":"string|null","sessionId":"string|null"},
  "version": 1
}
```

Read and write capabilities are separate. A browser session token is anti-forgery/session context, not proof of operating-system user identity.

## API principles

- Version all routes under `/api/v1`.
- Use explicit request/response schemas, bounded bodies, bounded collection sizes, pagination, and stable error codes.
- Default bind is loopback. Validate `Host` and `Origin`; do not enable wildcard CORS.
- Use an authenticated local session established through a user-controlled launch flow. Protect writes with same-origin checks and anti-forgery tokens.
- Keep diagnostics asynchronous. A request creates a typed job; workers read the job from trusted storage.
- Use Server-Sent Events initially for one-way inventory/event updates. Do not add WebSockets without a bidirectional requirement.
- Never expose raw sensor records, arbitrary SQL, command strings, generic file paths, or generic shell execution.

## Technology decision

Retain Python and SQLite. Retain Flask only if the Stage 1 implementation adds strict schema validation, production serving, secure local-session middleware, consistent errors, and event streaming without framework contortions. A migration to another Python framework is not justified solely for type hints; it requires an ADR with measured benefits and migration cost. React remains appropriate for the topology interface.

## Operational model

- Run unprivileged user services where persistent operation is enabled explicitly.
- Set umask `0077`; enforce mode `0700` on directories and `0600` on config/database/log files.
- Use SQLite WAL-aware backups and additive, transactional migrations.
- Emit structured, bounded logs with secret and inventory-field redaction.
- No telemetry, cloud account, packet payload capture, remote bind, or privileged helper by default.

## Known limitations after migration foundation

- The unified repository and proposed API contract exist, but `/api/v1` is not implemented.
- Current compatibility timestamps and schemas remain implementation-specific; the API adapter will convert them.
- Topology persistence and evidence-backed edges do not exist.
- Session expiration, revocation, and rotation remain future hardening work.
- The simulator has request limits and tests but remains intentionally separate and is not authorized to receive real inventory.
- Windows and macOS adapters are only interface boundaries, not implementations.
