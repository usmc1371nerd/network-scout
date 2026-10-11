# Original Stage 0–2 Reconciliation

Date: 2026-10-10

This matrix uses the original `codex` stage definitions. It does not redefine
completed stages.

## Stage 0 — Codebase review and security architecture

| Requirement | Status | Evidence or gap |
|---|---|---|
| Files, dependencies, functionality, reusable components | Complete and verified | Architecture and integration documents cover both source snapshots. |
| Maintainability and security-sensitive areas | Complete and verified | Security baseline and threat model document API, storage, subprocess, browser, sensor, and simulation boundaries. |
| Subprocess, CORS, authorization, secrets, configuration, dependencies | Complete and verified | Static review plus the three Stage 1 findings; dependency review is reproducible for npm production packages. |
| Simulated versus observed behavior | Complete and verified | Separate domains and trust boundary are documented and retained in repository layout. |
| Proposed architecture and migration strategy | Complete and verified | Architecture and integration plan exist; this migration implements their monorepo boundary. |
| Device, observation, topology-edge, event, authorization schemas | Complete and verified | Canonical conceptual schemas are documented; topology/layout persistence remains Stage 3 implementation. |
| STRIDE-informed threat model | Complete and verified | `THREAT_MODEL.md`. |

Stage 0 acceptance criteria are met. The original work correctly stopped before
large-scale integration.

## Stage 1 — Secure core application

| Requirement | Status | Evidence or gap |
|---|---|---|
| Modular services and strict configuration | Complete and verified | Observer package separates config, discovery, storage, jobs, security, scheduling, sensors, and dashboard. |
| Local-only API and browser-origin protection | Complete and verified for compatibility API | Loopback binding, owner-private launch capability, exact Host checking, same-origin writes, authenticated sensitive reads. |
| Secure filesystem permissions | Complete and verified | Secret/config/database directories and files use owner-private modes with tests. |
| Persistent inventory and migrations | Complete and verified | SQLite migrations 1–6, integrity checks, WAL-aware backup and restore. |
| Structured events and identity reconciliation | Complete and verified | Events, stable exact-MAC reconciliation, evidence and conflict history. |
| Restrictive defaults and subprocess isolation | Complete and verified | Active discovery and external WAN lookup default off; fixed argv, no shell, scope checks, time/output bounds. |
| Consistent API errors | Partially complete | Compatibility API returns JSON errors, but the proposed `/api/v1` stable error envelope is not implemented. |
| Authentication versus local-process access | Partially complete | The launch secret blocks ambient browser access but a same-user local process remains within the OS-account trust boundary; expiration/revocation/rotation are not implemented. |
| Baseline CI: tests, dependency audit, secrets | Complete and verified | Unified CI includes Python tests/compile, pip-audit, frontend build, full npm audit, and credential-pattern rejection. |
| Static analysis | Partially complete | Compilation and syntax checks exist; dedicated Python/JS linters and SAST are not yet configured. |
| Python dependency auditing and reproducibility | Partially complete | Simulation dependencies are exact; automated Python advisory/lock/hash verification remains debt. |

Stage 1 acceptance is substantially met for the compatibility observer API.
The versioned unified API remains a Stage 3 implementation prerequisite.

## Stage 2 — Network discovery and device identification

| Requirement | Status | Evidence or gap |
|---|---|---|
| Local interfaces, routes, ARP/NDP neighbor tables | Complete and verified | Passive adapters normalize all available attached interfaces and neighbor state. |
| Optional explicitly approved Nmap | Complete and verified | Disabled by default; private current-network approval and limits are required. |
| DHCP, mDNS, router integrations, LLDP | Not implemented | These optional sources are availability-dependent and were not guessed or silently enabled. |
| First/last observed, current/history addresses, hostname history, recognition | Complete and verified | Persisted in schema and returned in reports. |
| MAC evidence, classification, source, confidence | Complete and verified | Schema v6 evidence records source/confidence/timestamps; heuristic classifications are labeled. |
| Observation confidence | Partially complete | Identity evidence carries confidence; raw observation rows do not yet have a dedicated confidence column. |
| Randomized MAC and IP reassignment | Complete and verified | Locally administered MACs receive lower confidence; reused IPs generate conflicts. |
| Offline/unavailable state | Partially complete | Last active/connectivity and neighbor states are stored; a canonical reachable/unavailable/unknown state projection remains Stage 3. |
| Duplicate reconciliation and no IP-only merge | Complete and verified | Exact MAC deduplication; address-only observations remain unassigned; shared IPs never merge identities. |

Stage 2 acceptance is met for available passive sources with the documented
partial confidence/state projections. Optional source adapters remain backlog.

## Roadmap deviations and prerequisites

- Work previously labeled as later dashboard/monitoring stages already existed
  in the observer before unification; it is preserved but does not replace the
  original Stage 3 canvas objective.
- Stage 1 and Stage 2 changes existed as uncommitted validated work in the source
  repositories. This migration copies their exact working-tree state while
  preserving the source repositories unchanged.
- The new official repository was empty and had no default branch or license.
- Stage 3 must implement `/api/v1`, topology/layout migrations, and React live
  mode without weakening the compatibility API.
