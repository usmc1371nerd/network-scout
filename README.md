# Network Scout

Network Scout is a local-first network inventory and education application. It
combines the validated Cyber Scout observer foundation with the Network Lab
React canvas while keeping real observations and simulation state strictly
separate.

This repository currently contains the migration foundation. Real inventory is
not yet connected to the canvas; that is the separately approved Stage 3
milestone described in [docs/STAGE_3_PLAN.md](docs/STAGE_3_PLAN.md).

## Repository layout

- `backend/observer`: passive discovery, inventory, diagnostics, monitoring,
  authenticated local dashboard, SQLite migrations 1–6, and tests.
- `frontend`: reusable React canvas and simulation user interface.
- `simulation/backend`: bounded Flask simulation endpoint. It does not receive
  real inventory or invoke operating-system commands.
- `integrations/omarchy`: optional widget assets; Network Scout does not require
  Omarchy.
- `docs`: architecture, threat model, security baseline, API proposal, roadmap,
  decisions, reconciliation, and stage reports.

## Development verification

```bash
cd backend/observer
python3 -B -m pytest -q -p no:cacheprovider tests

cd ../../simulation/backend
python3 -m pytest -q test_app.py

cd ../../frontend
npm ci
npm run build
npm audit --omit=dev --audit-level=high
```

The observer binds only to loopback and its sensitive API requires the
owner-private launch capability plus exact Host and Origin controls. Active
discovery remains disabled until explicitly enabled for an approved, currently
attached private network.

## Data safety

Do not commit databases, logs, exports, captures, configuration containing local
network details, session capabilities, or credentials. See
[SECURITY.md](SECURITY.md) and [docs/SECURITY_BASELINE.md](docs/SECURITY_BASELINE.md).

## License and provenance

New unified-repository work is licensed under the MIT License. Migrated source
origin and the source repositories' prior undeclared license status are recorded
in [NOTICE](NOTICE).
