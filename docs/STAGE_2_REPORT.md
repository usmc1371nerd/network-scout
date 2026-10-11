# Stage 2 Completion Report

Date: 2026-10-10

## Outcome

The observer now preserves the evidence behind device identification and handles
ambiguous address reuse conservatively. Passive discovery continues to use all
attached private IPv4 interfaces without requiring active scanning.

## Implemented

- SQLite schema v6 with durable identity evidence and identity conflict tables.
- Traceable MAC and hostname evidence with source, confidence, and first/last
  observation times.
- Traceable OUI manufacturer and heuristic classification evidence.
- Conservative confidence for locally administered or randomized MAC addresses.
- Explicit address-reuse conflicts when distinct MAC identities share an IP.
- No device merge based solely on a shared address.
- Conflict occurrence tracking and auditable device timeline events.
- Device reports and exports include evidence and conflict history.
- Dashboard device detail shows overall identity confidence, evidence sources,
  and conflicts.
- Passive inventory retains multi-interface neighbor discovery and current
  interface, route, address, hostname, and address-history data.

## Security and Privacy Controls

- No new external network lookup was introduced.
- Active Nmap discovery remains explicit and governed by the existing opt-in
  and approved-network controls.
- Address-only observations remain unassigned instead of being guessed into an
  existing device identity.
- Identity inference is labeled with its source and a bounded confidence value.
- Schema migration uses the existing integrity checks and pre-migration backup.

## Verification

- Python compilation passed.
- Dashboard JavaScript syntax validation passed.
- Observer test suite: 53 passed, 0 failed.
- Git whitespace validation passed.
- Added regression coverage for randomized-MAC evidence, hostname evidence,
  inference sources, IP reuse, conflict recurrence, and non-merging behavior.

## Limitations

- DHCP, mDNS, LLDP, and router-specific sources are not universally available
  and have not been guessed or enabled automatically.
- A randomized MAC is treated as a separate conservative identity; cross-MAC
  correlation requires stronger future evidence or explicit user action.
- Observation confidence is source-specific metadata, not proof of ownership or
  device integrity.
- IPv6 neighbor observations are supported by the normalized model, while the
  current network scoping and legacy widget presentation remain IPv4-focused.

## Breaking Changes

None. Existing databases migrate automatically from schema v5 to v6 after an
automatic consistent backup.

## Recommended Next Stage

Stage 3: device state, recognition, and history workflows.
