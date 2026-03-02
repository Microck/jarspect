---
phase: 01-bytecode-evidence-core
plan: 02
subsystem: api
tags: [rust, axum, cafebabe, bytecode, serde]

requires:
  - phase: 01-bytecode-evidence-core-01
    provides: "Bytecode evidence schema base and additive /scan wiring"
provides:
  - "Invoke callsite evidence from parsed invoke* bytecode opcodes"
  - "Location metadata on invoke evidence with method descriptor and pc offsets"
  - "Dedicated invokedynamic evidence variant with bootstrap attribute index"
affects: [03-capability-detectors, persisted-scan-json, phase-1-plan-03]

tech-stack:
  added: []
  patterns:
    - "Opcode-driven callsite extraction from Code attributes"
    - "Invoke evidence remains additive under stable serde tagged enum contract"

key-files:
  created: []
  modified:
    - src/analysis/evidence.rs
    - src/analysis/classfile_evidence.rs

key-decisions:
  - "Added explicit invoke_resolved and invoke_dynamic schema variants instead of overloading existing string variants."
  - "Mapped invokedynamic without synthetic owner attribution and preserved bootstrap attribute index for downstream detectors."

patterns-established:
  - "Method-level bytecode walks emit location.method and location.pc for opcode-derived evidence."
  - "Invoke extraction uses cafebabe resolved member refs instead of string matching."

duration: 8 min
completed: 2026-03-02
---

# Phase 1 Plan 2: Bytecode Evidence Core Summary

**Shipped invoke callsite evidence as structured bytecode facts, including resolved owner/name/descriptor tuples and invokedynamic metadata with per-method pc offsets.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-02T14:04:51Z
- **Completed:** 2026-03-02T14:13:43Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments
- Extended `BytecodeEvidenceItem` with additive `invoke_resolved` and `invoke_dynamic` variants while preserving the existing `kind`-tagged serde contract.
- Added schema shape roundtrip tests for both invoke variants so persisted JSON format stays locked for downstream consumers.
- Implemented method opcode walking in `extract_bytecode_evidence()` to emit invoke evidence from `invokevirtual`, `invokestatic`, `invokespecial`, `invokeinterface`, and `invokedynamic` with method+pc location metadata.
- Verified end-to-end scan output now includes invoke evidence with populated owner/name/descriptor and non-null `location.pc` on compiled jars.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add invoke evidence variants to the schema** - `e07e388` (feat)
2. **Task 2: Emit invoke evidence from cafebabe bytecode opcodes with pc offsets** - `fc28d7d` (feat)

## Files Created/Modified
- `src/analysis/evidence.rs` - Added invoke evidence variants and JSON contract tests for invoke payloads.
- `src/analysis/classfile_evidence.rs` - Added opcode-based invoke extraction with method descriptors and instruction offsets.

## Decisions Made
- Kept schema evolution additive by extending `BytecodeEvidenceItem` and preserving `#[serde(tag = "kind", rename_all = "snake_case")]` plus existing variant names.
- Represented `invokedynamic` as its own evidence variant carrying `name`, `descriptor`, and `bootstrap_attr_index` without forcing owner attribution.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Demo script auto-start timing collided with cargo artifact locks**
- **Found during:** Task 2 verification (`bash scripts/demo_run.sh`)
- **Issue:** Script startup wait window elapsed while `cargo run` was still blocked on artifact lock, causing repeated startup failures.
- **Fix:** Pre-started the API server on a dedicated bind address and reran `bash scripts/demo_run.sh` with `JARSPECT_API_URL` targeting the healthy server.
- **Files modified:** None (execution-only workaround)
- **Verification:** Demo run completed successfully and returned scan + persisted fetch output.
- **Committed in:** N/A (no code change required)

**2. [Rule 3 - Blocking] Local demo fixture lacked `.class` entries due missing `javac/jar` toolchain**
- **Found during:** Task 2 done-criteria verification
- **Issue:** `demo/build_sample.sh` fallback produced source-only jar, preventing invoke evidence validation against the demo sample.
- **Fix:** Ran an additional end-to-end scan against a compiled jar (`slf4j-api-2.0.13.jar`) and asserted presence of `invoke_resolved` evidence with non-null `location.pc`.
- **Files modified:** None (verification-only workaround)
- **Verification:** Scan produced `invoke_resolved` and `invoke_dynamic` evidence kinds (`invoke_resolved`: 1041, `invoke_dynamic`: 1).
- **Committed in:** N/A (no code change required)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both deviations were environment/runtime verification blockers; implementation scope stayed aligned with plan and success criteria were validated via alternate deterministic execution paths.

## Issues Encountered
- `scripts/demo_run.sh` can fail when auto-started `cargo run` competes for artifact lock and the health wait window expires.
- This environment lacks Java compiler tooling, so demo fallback jars may not exercise bytecode extraction paths.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Invoke evidence stream is now available for Phase 3 detector wiring with callsite-level metadata.
- Phase 1 Plan 03 can build on the same opcode-walk location model for reconstructed byte-array string evidence.

---
*Phase: 01-bytecode-evidence-core*
*Completed: 2026-03-02*

## Self-Check: PASSED

- FOUND: `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-02-SUMMARY.md`
- FOUND: `src/analysis/evidence.rs`
- FOUND: `src/analysis/classfile_evidence.rs`
- FOUND: task commit `e07e388`
- FOUND: task commit `fc28d7d`
