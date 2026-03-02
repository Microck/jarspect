---
phase: 01-bytecode-evidence-core
plan: 01
subsystem: api
tags: [rust, axum, cafebabe, cesu8, serde]

requires:
  - phase: none
    provides: "Phase bootstrap context"
provides:
  - "Serializable bytecode evidence schema with a stable tagged JSON contract"
  - "Constant-pool Utf8 and String literal extraction from .class entries"
  - "Additive result.bytecode_evidence wiring in /scan results with legacy payload compatibility"
affects: [01-bytecode-evidence-core-02, 03-capability-detectors, persisted-scan-json]

tech-stack:
  added: [cafebabe, cesu8]
  patterns:
    - "analysis module isolates bytecode extraction from HTTP handlers"
    - "persisted JSON schema evolution uses optional additive fields with serde defaults"

key-files:
  created:
    - src/analysis/mod.rs
    - src/analysis/evidence.rs
    - src/analysis/classfile_evidence.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - src/main.rs

key-decisions:
  - "Kept ScanResult.bytecode_evidence optional with serde default/skip semantics to preserve old persisted scan payloads."
  - "Used cafebabe for class parsing plus explicit constant-pool scanning with cesu8 decoding to emit all Utf8 payloads."

patterns-established:
  - "Evidence enums are serde-tagged with fixed `kind` tag and explicit variant renames."
  - "Location.method is a named-field object to avoid tuple-position JSON drift."

duration: 9 min
completed: 2026-03-02
---

# Phase 1 Plan 1: Bytecode Evidence Core Summary

**Shipped a bytecode evidence data contract plus .class constant-pool extraction, then added result.bytecode_evidence to /scan as an additive persisted JSON field.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-02T06:37:12Z
- **Completed:** 2026-03-02T06:47:03Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments
- Added `src/analysis/evidence.rs` with stable serde schema (`kind` tag, pinned variant names, stable `Location` + `LocationMethod`) and serialization/deserialization contract test coverage.
- Added `src/analysis/classfile_evidence.rs` that parses `.class` files, extracts constant-pool Utf8 + String literals, and emits location-aware bytecode evidence items.
- Wired `result.bytecode_evidence` into `/scan` output in `src/main.rs` with `#[serde(default, skip_serializing_if = "Option::is_none")]` to keep legacy scan JSON readable.
- Added backcompat deserialization tests in `src/main.rs` for both new and old persisted scan shapes.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add bytecode evidence schema + classfile string extractor** - `6c4738f` (feat)
2. **Task 2: Wire bytecode_evidence into /scan results (additive + backwards compatible)** - `6770ba4` (feat)

## Files Created/Modified
- `Cargo.toml` - Added `cafebabe` and `cesu8` dependencies for bytecode parsing and JVM string decoding.
- `Cargo.lock` - Locked new dependency graph for bytecode evidence extraction.
- `src/analysis/mod.rs` - Introduced analysis module boundary and re-exports.
- `src/analysis/evidence.rs` - Added persisted bytecode evidence schema and JSON shape lock test.
- `src/analysis/classfile_evidence.rs` - Implemented class parsing and constant-pool evidence extraction.
- `src/main.rs` - Added additive `bytecode_evidence` field population and legacy/new payload deserialization tests.

## Decisions Made
- Kept `bytecode_evidence` additive and optional on `ScanResult` to avoid breaking older `.local-data/scans/*.json` payloads.
- Represented evidence variants with a fixed serde `kind` tag and explicit variant renames to reduce accidental JSON drift across later plans.
- Stored `Location.method` as a named object (`name`, `descriptor`) rather than a tuple to keep persisted shape stable.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered
- `bash scripts/demo_run.sh` failed to auto-start the local API in this environment due startup timing/lock contention (`cargo run` build warm-up and subsequent artifact directory lock). A single focused retry was attempted per instruction; retry still failed before endpoint validation could complete.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness
- Bytecode string evidence primitives and persisted schema contract are in place for invoke evidence expansion in Plan 02.
- No code blockers for Phase 1 Plan 02; only demo script startup robustness should be revisited if end-to-end verification is required in the same environment.

---
*Phase: 01-bytecode-evidence-core*
*Completed: 2026-03-02*

## Self-Check: PASSED

- FOUND: `src/analysis/evidence.rs`
- FOUND: `src/analysis/classfile_evidence.rs`
- FOUND: `src/analysis/mod.rs`
- FOUND: `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-01-SUMMARY.md`
- FOUND: task commit `6c4738f`
- FOUND: task commit `6770ba4`
