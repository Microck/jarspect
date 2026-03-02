# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.
**Current focus:** Phase 1 - Bytecode Evidence Core

## Current Position

Phase: 1 of 6 (Bytecode Evidence Core)
Plan: 2 of 3 in current phase
Status: In progress
Last activity: 2026-03-02 - Completed 01-bytecode-evidence-core-02-PLAN.md

Progress: [█░░░░░░░░░] 13%

## Performance Metrics

**Velocity:**
- Total plans completed: 2
- Average duration: 8.5 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-bytecode-evidence-core | 2 | 17 min | 8.5 min |

## Accumulated Context

### Decisions

| Phase | Decision | Rationale |
|-------|----------|-----------|
| 01-bytecode-evidence-core-01 | Kept `ScanResult.bytecode_evidence` optional with serde default/skip semantics. | Preserves compatibility when deserializing legacy persisted scan JSON without the new field. |
| 01-bytecode-evidence-core-01 | Used `cafebabe` for class parsing and explicit constant-pool scanning with `cesu8` decoding. | Ensures all `CONSTANT_Utf8` payloads are extracted while keeping parse fidelity and stable class metadata. |
| 01-bytecode-evidence-core-02 | Added dedicated `invoke_resolved` and `invoke_dynamic` variants in the stable tagged evidence schema. | Keeps invoke evidence additive and machine-readable without changing existing variant semantics. |
| 01-bytecode-evidence-core-02 | Kept `invokedynamic` owner-less and stored bootstrap attribute index instead. | Avoids incorrect owner attribution while preserving data needed for downstream detector interpretation. |

### Pending Todos

- Revisit `scripts/demo_run.sh` startup reliability under cold-build and artifact-lock contention if strict end-to-end verification is required in CI.
- Decide whether to commit a deterministic compiled demo `.jar` fixture so invoke verification does not depend on local `javac/jar` availability.

### Blockers/Concerns

- `scripts/demo_run.sh` auto-start path remains sensitive to cargo artifact-lock timing; pre-starting the API with `JARSPECT_API_URL` worked reliably.
- Local environment still lacks `javac/jar`, so the demo fallback jar does not contain `.class` files for invoke evidence checks.

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 01-bytecode-evidence-core-02-PLAN.md
Resume file: .planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-03-PLAN.md
