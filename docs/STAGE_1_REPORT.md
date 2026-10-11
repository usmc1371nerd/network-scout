# Stage 1 Completion Report

Date: 2026-10-10

## Outcome

The supplied observer backend now has a stronger secure-core boundary without
combining it with Network Lab. Real observation remains in the observer, while
the simulator remains a separate application.

## Implemented

- Owner-private dashboard session secret stored under the user state directory
  with mode `0600` and a `0700` parent.
- Session capability delivered to the launched browser in a URL fragment and
  removed before API access.
- Authentication on all sensitive dashboard API reads and writes.
- Exact loopback `Host` validation and same-origin validation for writes.
- SQLite schema v5 with durable authorization decisions for protected writes.
- External WAN lookup disabled unless the existing configuration opt-in is set.
- Network Lab request body, command, device, connection, and object-shape bounds.
- Network Lab CORS restricted to documented development origins.
- Unused vulnerable Axios dependency removed.
- Exact Python production dependency versions.
- Baseline CI in both repositories for tests, compilation/build, production
  dependency auditing, and common credential-pattern rejection.

## Verification

- Observer: Python compilation and 50 tests passed.
- Network Lab backend: 3 request-boundary tests passed.
- Network Lab frontend: production Vite build passed.
- Production npm dependency audit: 0 vulnerabilities.
- Static JavaScript syntax and Git whitespace checks passed.

## Remaining work

- The session capability launch remains a desktop integration mechanism, not a
  general multi-user web authentication system.
- Development/build-only npm advisories remain and require a separately tested
  toolchain upgrade; production dependencies audit cleanly.
- Python hashes/lock generation and SBOM automation belong in the CI/release
  workstream.
- SSE, the unified `/api/v1` contract, and a standalone React inventory client
  remain future integration work; they are not required to close the validated
  Stage 0 vulnerabilities.
- Stage 2 discovery expansion has not begun.
