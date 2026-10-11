# Migration Manifest

Date: 2026-10-10

The source repositories were inspected on their `main` branches and were left
unchanged. Their uncommitted working-tree improvements were copied so the
validated Stage 1/2 state was not lost.

## Observer source

Source: `omarchy-cyber-scout-widget` at base commit `0518c5e`, with its existing
uncommitted Stage 1/2 changes.

| Unified path | Migrated content |
|---|---|
| `backend/observer/cyber_scout` | Configuration, models, discovery, scope, SQLite migrations 1–6, diagnostics/jobs, monitoring, sensors, security, compatibility dashboard |
| `backend/observer/scanner.py` | Existing Omarchy-compatible scanner and launcher |
| `backend/observer/tests` | Observer unit, migration, security, API, discovery, monitoring, and evidence tests |
| `backend/observer/packaging` | Monorepo-aware Omarchy release builder plus user-service scripts/templates |
| `backend/observer/OPERATIONS.md`, `SECURITY.md` | Component operational and security guidance |
| `integrations/omarchy` | Canonical optional integration assets; compatibility copies remain beside the observer so the existing plugin and release workflow remain self-contained |

## Network Lab source

Source: `network-lab` at base commit `df4696c`, with its existing uncommitted
Stage 1 hardening.

| Unified path | Migrated content |
|---|---|
| `frontend` | React/Vite canvas, packet visualization, terminal, styling, and lockfile |
| `simulation/backend` | Flask educational simulation engine and request-boundary tests |
| `simulation/requirements.txt` | Exact simulator production dependencies |

Deployment-specific Render/Docker files and project prompts were not migrated;
they described a public simulation deployment rather than the secure local
unified application. Generated dependencies/builds and all runtime data were
excluded.

## Documentation source

Stage 0 architecture/security documents and Stage 1/2 completion reports were
migrated from the parent workspace, then reconciled for Network Scout. New
repository-level documentation records the API proposal, roadmap, migration,
provenance, and Stage 3 plan.
