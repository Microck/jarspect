# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.
**Current focus:** Phase 1 - Bytecode Evidence Core

## Current Position

Phase: 1 of 6 (Bytecode Evidence Core)
Plan: 3 of 3 in current phase
Status: Phase complete
Last activity: 2026-03-02 - Completed 01-bytecode-evidence-core-03-PLAN.md

Progress: [██░░░░░░░░] 20%

## Performance Metrics

**Velocity:**
- Total plans completed: 3
- Average duration: 9.3 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-bytecode-evidence-core | 3 | 28 min | 9.3 min |

## Accumulated Context

### Decisions

| Phase | Decision | Rationale |
|-------|----------|-----------|
| 01-bytecode-evidence-core-01 | Kept `ScanResult.bytecode_evidence` optional with serde default/skip semantics. | Preserves compatibility when deserializing legacy persisted scan JSON without the new field. |
| 01-bytecode-evidence-core-01 | Used `cafebabe` for class parsing and explicit constant-pool scanning with `cesu8` decoding. | Ensures all `CONSTANT_Utf8` payloads are extracted while keeping parse fidelity and stable class metadata. |
| 01-bytecode-evidence-core-02 | Added dedicated `invoke_resolved` and `invoke_dynamic` variants in the stable tagged evidence schema. | Keeps invoke evidence additive and machine-readable without changing existing variant semantics. |
| 01-bytecode-evidence-core-02 | Kept `invokedynamic` owner-less and stored bootstrap attribute index instead. | Avoids incorrect owner attribution while preserving data needed for downstream detector interpretation. |
| 01-bytecode-evidence-core-03 | Added `reconstructed_string` evidence variant with existing `Location` metadata shape. | Keeps BYTE-03 output additive and stable under the existing serde-tagged contract. |
| 01-bytecode-evidence-core-03 | Implemented a narrow opcode state machine for `new String(new byte[]{...})` reconstruction. | Delivers explainable reconstruction while fail-closing on unknown/control-flow/exception boundaries. |

### Pending Todos

- Harden `scripts/demo_run.sh` auto-start behavior for first-run compile latency (or prebuild binary) to avoid startup timeout in verification flows.
- Decide whether to commit a deterministic compiled demo `.jar` fixture so BYTE-03 verification does not depend on local `javac/jar` availability.

### Blockers/Concerns

- `scripts/demo_run.sh` auto-start path remains sensitive to first-run compile timing; pre-starting the API with `JARSPECT_API_URL` still works reliably.
- Environments without `javac/jar` will still produce a `.java` fallback jar that omits `.class` bytecode evidence unless toolchain/fixture strategy is standardized.

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 01-bytecode-evidence-core-03-PLAN.md
Resume file: .planning/phases/02-archive-yara-fidelity/02-archive-yara-fidelity-01-PLAN.md
