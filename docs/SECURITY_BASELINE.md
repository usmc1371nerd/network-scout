# Network Scout Security Baseline

Status: Stage 0 review baseline (2026-10-10)

Stage 1 disposition: SB-01, SB-02, and SB-03 were remediated and covered by
regression tests. The unused vulnerable Axios production dependency was
removed; `npm audit --omit=dev` reports zero production vulnerabilities.

Migration disposition: those fixes were copied from the validated working trees
into the unified repository and are mandatory for future integration.

## Remaining risks before Stage 3 implementation

- Session capabilities do not expire, rotate, or support targeted revocation;
  same-user processes remain within the trusted OS-account boundary.
- `/api/v1` capability separation and its uniform validation/error envelope are
  designed but not implemented.
- Raw observations lack a dedicated confidence column although identity evidence
  is source- and confidence-labeled.
- The simulator has no authentication or application rate limiter and remains
  simulation-only. It must never receive live inventory.
- Python lock hashes/advisory automation, SBOMs, dedicated linters/SAST, fuzzing,
  and performance budgets remain release debt.
- The unified frontend toolchain was upgraded to Vite 8.3.4 and React plugin
  6.1.2; full and production-only npm audits report zero vulnerabilities.
- Physical topology/layout storage does not exist. Missing topology must be
  shown as unknown, never filled with invented subnet links.

## Review scope and method

Reviewed the current snapshots of `omarchy-cyber-scout-widget` and `network-lab`, including Python, React/JavaScript, QML, SQL migrations, shell/PowerShell packaging, service templates, manifests, dependency files, and documentation. The review covered subprocess construction, API exposure, CORS, authorization, secrets/configuration, storage permissions, sensor parsing, simulation boundaries, and dependencies.

No credentials or private keys were found in the source snapshot.

## Security findings and engineering risks

### SB-01 — Local dashboard token is not authentication (medium)

`omarchy-cyber-scout-widget/cyber_scout/dashboard.py` creates a strong per-process token, but unauthenticated `GET /api/session` returns that token and sensitive settings. Writes validate only the returned token. Loopback and browser same-origin behavior reduce exposure, but any same-user local process can obtain the token, and the service does not validate `Host` or `Origin` to defend the browser boundary. A token retrievable from the protected service cannot establish user identity.

Required Stage 1 control: authenticated user-controlled launch/session bootstrap, allowlisted host/origin checks, separate read/write capabilities, short-lived anti-forgery value, and security regression tests. Keep loopback binding as defense in depth.

### SB-02 — Network Lab public API has no resource or access controls (medium)

`network-lab/backend/app.py` applies wildcard CORS and accepts arbitrary JSON topology/command input on `/api/run-command`. The Render/Docker path binds Gunicorn to `0.0.0.0`. The handler has no authentication, request body limit, schema, nesting/node/edge limits, per-request complexity budget, or rate limit. It performs repeated graph and packet simulations over client-controlled collections.

Impact is availability and potential future confidentiality if this endpoint is ever connected to real inventory. Keep it isolated as a demo; do not place it in the real service. Any retained simulator API needs explicit size/shape limits and deployment rate limiting.

### SB-03 — Passive snapshots perform an unapproved third-party WAN lookup (medium)

`scanner.py` calls `current_wan()` for both passive and active inventory responses. When its cache is absent, stale, or belongs to another network, it sends an HTTPS request to `ipwho.is` even though validated configuration defines `external_wan_lookup_enabled = false` by default and never consults it. The request does not send LAN inventory, but it discloses the user's public address, timing, and product user-agent to a third party.

Required control: remove WAN lookup from the passive path, honor the validated opt-in setting, explain the external disclosure before consent, and keep the application fully functional without it.

### SB-04 — Network Lab dependencies are stale and Python resolution is unreproducible (high maintenance risk)

`npm audit --omit=dev --json` reported three vulnerable production packages (two high, one moderate) in the lock, led by the direct but currently unused `axios` dependency. Full `npm audit --json` reported eleven vulnerable packages (seven high, three moderate, one low), including the Vite/build chain. Package applicability varies and several advisories concern Node-only adapters or development processing, so the count is not equivalent to eleven exploitable product vulnerabilities.

`requirements.txt` contains unpinned `flask`, `flask-cors`, and `gunicorn`, so a reproducible Python advisory audit is not possible from the repository alone.

Required control: remove unused dependencies, upgrade/test the lock, pin Python dependencies, generate an SBOM, and enforce automated advisory review.

### SB-05 — Simulation and observation models must remain separate (high integrity risk)

Network Lab generates packet events, MAC addresses, routes, topology edges, and topology-only security findings from user-provided state. These are valid educational outputs but are not observed network facts. Directly integrating them would create fabricated evidence.

Required control: distinct schemas, APIs, persistence namespaces, mode banners, visual treatments, and tests that reject simulation IDs in real operations.

### SB-06 — Debug server and deployment defaults differ (low)

Direct execution of Network Lab calls `app.run(debug=True)` and the container uses Gunicorn. Debug mode is development-only and must never be exposed beyond loopback. Deployment configuration should be explicit, non-root, header-aware behind a trusted proxy if used, and environment validated.

## Existing controls worth preserving

- Observer subprocesses use fixed argv lists with `shell=False`, bounded timeouts, cancellation, and output caps.
- Diagnostic jobs accept fixed operation kinds and verify that the address belongs to the stored device.
- Active scans are disabled by default and restricted to current private/link-local ranges with bounded `/24` scope and rate/time limits.
- SQLite statements containing user/domain values are parameterized; the one formatted retention query uses constant table/column allowlists.
- Database/config/runtime directories are tightened to `0700` and files to `0600` where supported.
- Database migrations are versioned, transactional, integrity-checked, and backed up with SQLite's API.
- Sensor ingestion accepts only regular files, caps bytes/records/line length, stores allowlisted metadata, and excludes packet payloads.
- Dashboard output uses JSON serialization or explicit HTML escaping; CSP, `nosniff`, frame denial, and no-store headers are present.
- Dashboard binding is restricted to `127.0.0.1` or `::1` by argument choices.
- No telemetry, cloud upload, remote dashboard bind, generic shell endpoint, or embedded secret is present in the observer.

## Mandatory baseline for Stage 1

### Process and privilege

- Run as the logged-in user; refuse root unless executing a separately designed migration/repair command.
- No ambient capture capabilities, sudo, setuid, Docker socket, or broad device access.
- Resolve external tools from a controlled allowlist and record version/availability without trusting their output.
- Apply worker concurrency, timeout, cancellation, output, CPU, memory, task, and file-descriptor limits.

### Web/API

- Loopback-only default plus explicit allowed-host and allowed-origin enforcement.
- No wildcard CORS. Same-origin is the default; document any exact development origin.
- Authenticated launch/session flow; token values are not user identity.
- Anti-forgery on state changes, secure cookie attributes if cookies are used, and capability authorization on every operation.
- Strict JSON content type, body/nesting/string/array limits, schema validation, pagination, and rate limits.
- Security headers and output encoding; never interpolate untrusted HTML.
- Consistent errors that omit paths, raw tool output, SQL, tokens, and inventory details.

### Data and privacy

- Directories `0700`; database, config, backups, exports, and logs `0600`.
- Retention and deletion cover observations, events, findings, jobs, layouts, exports, and backups with documented exceptions.
- Logs redact addresses, MACs, hostnames, tokens, credentials, and raw request bodies by default.
- Exports require an explicit user action and state their scope.
- No external transmission without separate informed consent.

### Discovery and diagnostics

- Passive by default. Transmitting discovery is labeled active regardless of low impact.
- Revalidate current interface, approved network, target membership, and operation capability when a queued job starts.
- Fixed executables/argv; no shell, command strings, arbitrary flags, or arbitrary paths from clients.
- Negative probe results remain inconclusive unless corroborated by defined evidence.
- Store source, time, confidence, visibility limit, and evidence identifier for every claim.

### Supply chain

- Exact direct constraints and resolved lock files with integrity data.
- CI: unit/integration tests, Python and JS static checks, dependency advisories, secret scanning, license review, and SBOM.
- Reproducible release inputs, checksums, signed provenance when the release pipeline is established.
- No automatic major-version remediation without tests and review.

## Security-sensitive test requirements

- Host-header/DNS-rebinding and cross-origin browser tests.
- Unauthenticated read/write and forged-session tests.
- Oversized/deep JSON and excessive node/edge tests.
- Command-argument and target-scope regression tests.
- Symlink/special-file sensor-path tests and parser fuzz cases.
- Database mode, config mode, backup mode, and log-redaction tests.
- Dependency and secret scan gates.
- Simulation-to-real boundary tests.

## Dependency audit record

- Command: `npm audit --omit=dev --json` — executed 2026-10-10; failed the audit gate with 3 vulnerable packages.
- Command: `npm audit --json` — executed 2026-10-10; failed the audit gate with 11 vulnerable packages.
- Python audit: not executed because no resolved/pinned Python dependency set exists. Creating a lock is a Stage 1 prerequisite.

Advisory results are time-sensitive and must be regenerated in CI rather than copied forward as permanent truth.
