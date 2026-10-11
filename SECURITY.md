# Security Policy

Network Scout handles sensitive local network metadata. Please report suspected
vulnerabilities privately through GitHub's security-advisory feature rather
than a public issue. Do not include real credentials, device inventories,
packet captures, public IP addresses, or identifying network data in reports.

## Supported state

Only the latest `main` branch and active pull requests are evaluated during the
pre-release migration period.

## Security invariants

- The inventory API binds to loopback by default and requires an owner-controlled
  session capability; loopback alone is not authentication.
- Browser requests are subject to exact Host checks and write requests require
  an allowed Origin.
- Active probing is disabled by default and restricted to explicitly approved,
  currently attached private networks.
- Commands are fixed, typed operations built as argument arrays with bounds and
  timeouts; no generic shell or remote-command endpoint is permitted.
- Simulation data is never represented as live evidence and cannot invoke real
  diagnostics.
- Runtime databases, tokens, captures, exports, logs, and network-specific
  configuration must never be committed.

See `docs/THREAT_MODEL.md` and `docs/SECURITY_BASELINE.md` for the detailed model.
