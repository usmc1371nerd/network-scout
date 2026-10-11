# Network Scout Threat Model

Status: Stage 0 baseline reconciled for the migration foundation

## Migration security disposition

- The observer now uses an owner-private launch capability, authenticates
  sensitive reads and writes, validates exact Host values, and requires an
  allowed same-origin Origin for writes. This protects the browser boundary but
  does not claim to identify processes within the same OS user account.
- External WAN enrichment is disabled unless explicitly configured.
- Simulator CORS is restricted to documented loopback development origins and
  request body, command, device, connection, and object shapes are bounded. It
  still has no user authentication or application rate limiter and therefore
  remains isolated from live inventory.
- Identity evidence and address-reuse conflicts are durable in schema v6;
  shared IP addresses never merge devices.

Residual priorities are session expiry/rotation/revocation, `/api/v1` capability
separation, Python hash-lock/SBOM automation, SSE resource bounds, and strict
live/simulation type separation. Historical
“current state” descriptions below are retained as the Stage 0 evidence that
motivated the implemented controls; `SECURITY_BASELINE.md` is authoritative for
their current disposition.

## Security objectives

1. Network inventory, identifiers, topology, logs, and exports remain private to the local user.
2. Passive observation never silently becomes active probing.
3. Active operations remain within an explicitly approved, currently attached scope.
4. Untrusted web, sensor, tool, and device data cannot trigger code execution or administrative action.
5. Observed, inferred, user-defined, and simulated facts remain distinguishable.
6. The application remains usable under malformed or high-volume local inputs.
7. Every sensitive state change is attributable to an actor, policy decision, and audit event.

## Assets

- Device inventory: MAC/IP/hostname history, recognition, notes, services, presence patterns.
- Network structure and sensor-derived connection metadata.
- Local configuration, approved networks, database, backups, logs, and exports.
- User authority to run network tools.
- Future device credentials and management capability (not present in early stages).
- Integrity of evidence labels and device identity reconciliation.
- Availability of monitoring and local desktop services.

## Actors and capabilities

- Local user: controls the desktop session and authorizes scans.
- Other local process: can connect to loopback and may read same-user files if permissions fail.
- Malicious website: executes browser code and attempts cross-origin requests, DNS rebinding, or CSRF.
- LAN peer: controls packets, hostnames, service banners, MAC/IP behavior, and sensor-visible metadata.
- Sensor/log producer: can emit malformed, misleading, or very large records.
- Supply-chain attacker: compromises a dependency, build input, or update artifact.
- Future enrolled device/AI client: authenticated but potentially compromised and limited to granted capabilities.

## Trust boundaries

| Boundary | Untrusted input | Protected side | Required controls |
|---|---|---|---|
| Browser → local API | URLs, JSON, headers, commands | Inventory and configuration | authenticated launch/session, host/origin validation, anti-forgery, schemas, rate/body limits |
| OS/tools → adapters | command output, interface names, neighbor data | normalized observations | fixed argv, timeouts, parsers, length/type limits |
| Sensor files → ingestion | JSON lines and file metadata | SQLite and UI | regular-file checks, byte/record/line caps, allowlisted fields, safe rotation handling |
| Worker → subprocess | stored job fields | user authority/network | capability policy, scope revalidation, fixed executable and argv, timeout/cancel/output caps |
| API/service → SQLite | typed domain data | private history | parameterized SQL, migrations, permissions, transactions, retention |
| Real mode ↔ simulation | synthetic nodes/edges/packets | truthfulness of observed data | distinct schemas/namespaces, labels, no implicit conversion |
| Core → future helper | typed request | elevated capture/management | separate process, narrow IPC, mutual authentication, least privilege, audit |
| Optional AI → capabilities | prompts/tool arguments | data and actions | opt-in, data minimization, typed tools, authorization, confirmation, prompt-injection resistance |

## Abuse cases and controls

| STRIDE | Scenario | Impact | Current state | Required response |
|---|---|---|---|---|
| Spoofing | LAN peer rotates or clones MAC/IP/hostname to be merged into another device | Incorrect identity/history | Exact MAC is the primary merge key; cloned MAC still collides | retain raw observations, conflict detection, reversible merges, confidence decay |
| Spoofing | Website/local process obtains dashboard token from unauthenticated `/api/session` | Unauthorized settings/event writes | Token endpoint is unauthenticated; same-origin policy is the main browser barrier | authenticated launch session plus host/origin validation; never treat token as identity |
| Tampering | Client submits fabricated Network Lab devices/links to command API | Misleading output | Expected simulation behavior | isolate simulation namespace and label all output simulated |
| Tampering | Sensor log injects markup or oversized fields | UI/database corruption or XSS | Field allowlists/caps and UI escaping exist | preserve caps, central output encoding, add adversarial tests |
| Repudiation | Scan or setting change cannot be tied to a user decision | Unsafe operation lacks accountability | Jobs record trigger but no general authorization record | persist actor, capability, scope, confirmation, decision, outcome |
| Information disclosure | Wildcard CORS/public service exposes submitted topologies or future inventory | Private network data leakage | Network Lab uses `CORS(app)` and public deployment config | remove wildcard CORS; simulation deployment must not share real inventory service |
| Information disclosure | Local inventory/export accessible to any local browser/process | Presence and network metadata leak | Observer GET routes are unauthenticated on loopback | authenticated local session and least-data read scopes |
| Information disclosure | Passive refresh contacts a third-party WAN service | Public address and usage timing leave the device | Current code calls `ipwho.is` without honoring the disabled-by-default setting | remove automatic call; require informed opt-in |
| Denial of service | Large/deep simulation JSON triggers expensive nested graph loops | Public worker exhaustion | No body, shape, node, edge, or rate limits | request-size middleware, schema maxima, complexity budgets, rate limits |
| Denial of service | Malformed/high-volume sensor log consumes resources | Monitoring lag/crash | Strong byte/line/record caps exist | retain caps, backpressure metrics, fuzz parsers |
| Elevation | User-controlled value reaches shell or arbitrary executable | Code execution as desktop user | Observer uses fixed argv and `shell=False`; Network Lab executes no OS commands | retain allowlists; ban generic command endpoints; pin executable resolution if threat warrants |
| Elevation | Future AI or management feature calls privileged action without confirmation | Device compromise/outage | Not implemented | common authorization framework, explicit enrollment, allowlisted actions, protected audit log |

## Highest-priority risks

### TM-01: Local web authorization is not an identity boundary

The observer returns its write token and settings from unauthenticated `GET /api/session`. This blocks basic blind CSRF only because a normal cross-origin page cannot read the response; it does not authenticate the desktop user or another local process, and it is not sufficient against a same-origin compromise or DNS-rebinding-style boundary failure. Before Stage 1 calls the API protected, require a user-controlled launch/session mechanism, validate allowed host/origin values, and authorize capabilities server-side.

### TM-02: Public simulation API lacks resource controls

Network Lab's `/api/run-command` accepts arbitrary client-provided arrays and nested dictionaries, then performs graph and packet computations. The Docker/Render configuration binds publicly, wildcard CORS is enabled, and no authentication, request-size, object-count, nesting, timeout, or rate limit exists. Treat it as an untrusted educational demo only until strict input and resource policies are added.

### TM-03: Real and simulated semantics can be confused

Network Lab generates MACs, packet events, routes, traffic, and security findings. Reusing those models directly with real inventory would violate the product's evidence requirements. Separate packages, database tables, API prefixes, visual banners, and types are mandatory.

### TM-04: Dependency provenance is incomplete

Python dependencies are unpinned. The frontend lock is present, but the audit identifies vulnerable production and build packages. Reproducible lock files, automated advisory checks, SBOM generation, and update policy are required before release.

### TM-05: Passive mode currently has an external side effect

The observer's snapshot path calls a public WAN lookup when its cache is missing or stale, including during passive refresh. This contradicts the local-first boundary and the disabled-by-default configuration field. Stage 1 must make external enrichment an explicit, disclosed opt-in and test that all default workflows remain offline.

## Security assumptions

- The operating-system account and kernel are trusted in early stages.
- Networks are user-owned or explicitly authorized.
- Loopback reduces remote reachability but is not authentication.
- Zeek/Suricata are independently installed and their logs may be adversarial.
- The application has no guarantee of full-LAN visibility from an ordinary endpoint.
- No device-management credential exists in the Stage 0/1 design.

## Out of scope for early stages

- Defending against a fully compromised user account or kernel.
- Real remote administration, arbitrary SSH commands, or device restart.
- Installing capture privileges, firewall changes, sensors, or covert agents.
- Claiming physical topology without authoritative evidence such as LLDP or managed infrastructure data.

## Verification plan

- Unit tests for schema bounds, authorization decisions, target scope, identity conflicts, output encoding, and evidence labels.
- API tests for host/origin rejection, unauthenticated reads/writes, CSRF, oversized/deep JSON, pagination, and rate limits.
- Property/fuzz tests for sensor parsers, tool output parsers, and reconciliation.
- Integration tests proving simulation IDs cannot enter real diagnostic jobs.
- Static checks for shell use, unsafe SQL, secrets, and dependency advisories.
- Service tests for unprivileged execution, filesystem modes, bind addresses, timeouts, and cancellation.

## Residual uncertainty

- Stage 0 did not dynamically expose services to hostile traffic.
- Python advisory status cannot be resolved reproducibly while requirements remain unpinned.
- Future packaging and authentication mechanisms are undecided and require a focused review.
