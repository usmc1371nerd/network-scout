# PR #1 Stage 3 Readiness Review

Date: 2026-10-10 (US/Eastern)

## Outcome

PR #1 was merged on GitHub at 2026-10-11T01:21:20Z before this review branch
was created. This review did not merge it. The reviewed head was
`9514cc387bbc27a8af8227927beeb5e7f543695a`; GitHub reported all Python,
frontend, and repository-security checks successful for that head.

A full security diff review from the PR base to its head covered all 35
source-bearing review items and produced no validated findings. This does not
remove the known architectural debt listed below.

## Preserved foundation

- Device identity remains the persisted UUID generated at first exact-MAC
  observation. Exact MAC is the automatic merge key; IP or hostname alone does
  not merge devices. Identity evidence, confidence, randomized-MAC treatment,
  and conflict history remain intact.
- SQLite `SCHEMA_VERSION` remains 6. Migrations 1 through 6 are present in order,
  reject newer schemas, back up pre-v6 databases, and preserve device IDs and
  metadata. No migration was squashed or added by this review.
- Security controls remain intact: loopback binding, exact Host validation,
  owner-private capability material, constant-time token comparison,
  same-origin checks for writes, restrictive filesystem modes, fixed-argument
  subprocess execution, active-discovery opt-in and scope checks, bounded
  diagnostics, redacted errors, and audit records.
- The original repositories remain read-only references. Their migrated source
  was not rewritten during this review.

## SSE authentication resolution

The Stage 3 browser client will not use native `EventSource`. It will make a
same-origin authenticated `fetch()` request carrying `X-Network-Scout-Token`,
consume the `text/event-stream` response through `ReadableStream`, and implement
SSE parsing, reconnect/backoff, cancellation, and `Last-Event-ID` itself.

This preserves the existing capability-header boundary. Query-string tokens
would leak through URLs and logs; adding a cookie only for SSE would create a
second session/CSRF lifecycle. Neither is accepted. The server must retain exact
Host checks, validate any supplied Origin, require `events.read`, and bound
connections, queues, event size, and reconnect rate.

## Licensing and provenance

- The root MIT `LICENSE` was reviewed and not changed.
- `NOTICE` identifies both source repositories, destination paths, the owner’s
  migration authorization, and that neither source declared a
  GitHub-detectable license at migration time.
- Repository history attributes the migrated work to James Dumas. No additional
  source author was found in the imported history available for review.
- Direct JavaScript packages are MIT licensed. The resolved development graph
  also contains Apache-2.0, BSD-3-Clause, ISC, and MPL-2.0 components. The pinned
  Python packages are BSD-3-Clause (Flask) and MIT (Flask-Cors and Gunicorn).
  These are compatible with keeping Network Scout under MIT, but distributed
  artifacts must preserve applicable third-party copyright and license notices.
- Before a public binary/source release, automate a complete lockfile-based
  third-party notice/SBOM artifact and verify that copied or bundled dependency
  license texts are included. This is a release blocker, not a blocker to the
  first source-only Stage 3 milestone.

This is an engineering provenance review, not legal advice. The owner’s explicit
authorization recorded in `NOTICE` is the basis for applying MIT to previously
unlicensed source snapshots; any undisclosed contributor agreement or copied
source must be resolved by the repository owner.

## Remaining blockers and debt

- No technical blocker remains for the narrowly scoped first Stage 3 milestone.
- Human approval is required before implementation and again before each later
  major milestone.
- The `/api/v1` session bootstrap, expiry, revocation, and rotation lifecycle is
  still a deferred design decision. The first milestone may reuse the existing
  owner-private launch capability but must not create an unauthenticated token
  endpoint.
- Dedicated Python/JavaScript linting, SAST, reproducible hashed Python locks,
  SBOM generation, and automated third-party notices remain security/release
  debt.
- Canonical reachable/unavailable/unknown projection and observation-level
  confidence remain partially specified. The first milestone must display
  existing truthful fields without inventing certainty.

## Approval boundary

The next authorized unit, once explicitly approved, is only: expose actual
persisted inventory through an authenticated read-only `/api/v1` projection and
render those devices as read-only React canvas nodes keyed by persistent device
ID. It excludes SSH, remote administration, AI agents, simulated-to-live
execution, topology writes, SSE implementation, and active-scanning changes.
