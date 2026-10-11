# Network Scout Roadmap

## Completed foundations

- Stage 0: architecture review, threat model, shared schemas, and migration plan.
- Stage 1: protected local observer API, authorization audit records, private
  storage, validated configuration, bounded subprocess work, tests, and CI.
- Stage 2: passive multi-interface discovery, stable MAC-based identity,
  traceable evidence, conservative randomized-MAC treatment, and address-conflict
  records without IP-only merging.
- Repository migration foundation: source preservation, monorepo boundaries,
  Stage 0–2 reconciliation, API proposal, security review, and Stage 3 plan.

## Next approval gate — Stage 3

Connect persisted live inventory to the reusable React canvas through the
protected `/api/v1` read model. Add durable layout and evidence-backed topology
tables, incremental SSE updates, explicit Live/Simulation mode labeling, and
tests. Do not infer physical links from subnet membership.

## Later stages

1. Device state, history, alerts, and beginner-friendly explanations.
2. Evidence-backed topology sources such as LLDP, authorized router APIs, and
   sensor flow metadata.
3. Packaging, accessible onboarding, release automation, SBOMs, and expanded OS
   adapters.
4. Optional, separately threat-modeled remote management and AI interoperability.

Remote management, privileged helpers, generic commands, credential storage,
and AI-initiated state changes are explicitly outside the current milestone.
