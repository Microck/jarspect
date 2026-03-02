---
phase: 06-regression-fixtures
plan: 02
subsystem: testing
tags: [regression, fixtures, bytecode, tokio, tempfile, yara]

requires:
  - phase: 06-regression-fixtures-01
    provides: Library-exported `run_scan(...)` and scan loading helpers for direct integration tests
provides:
  - Committed deterministic compiled fixture jar and checksum for TEST-01/TEST-02
  - Fixture regeneration workflow (`tools/build-regression-fixtures.sh` + `build-regression-fixtures` binary)
  - End-to-end regression tests for compiled fixture coverage and demo-sample signature/YARA continuity
affects: [03-capability-detectors, 04-scoring-behavior-prediction, 05-ui-verdict-rendering, regression-testing]

tech-stack:
  added: []
  patterns:
    - Deterministic jar assembly with `zip::ZipWriter`, `CompressionMethod::Stored`, and `DateTime::default()`
    - Integration tests call `run_scan(...)` directly with tempfile-backed state and fixed artifact IDs

key-files:
  created:
    - tests/fixtures/java-src/AllCapabilities.java
    - tests/fixtures/bytecode/all-capabilities.jar
    - tests/fixtures/bytecode/all-capabilities.sha256
    - tests/fixtures/README.md
    - src/bin/build-regression-fixtures.rs
    - tools/build-regression-fixtures.sh
    - tests/regression-fixtures.rs
  modified: []

key-decisions:
  - Committed generated fixture jar and checksum so `cargo test` does not require Java tooling.
  - Kept regression assertions resilient to current YARA ID formatting by accepting legacy and pack-prefixed forms.

patterns-established:
  - "Fixture pattern: synthetic unreachable Java methods + deterministic committed jar artifact"
  - "Regression pattern: assert indicator ID membership/prefixes and score bounds, not ordering"

duration: 10m
completed: 2026-03-02
---

# Phase 6 Plan 2: Regression Fixtures Summary

**Committed deterministic compiled fixture artifacts and added real-pipeline regression tests that validate detector coverage plus demo signature/YARA continuity without HTTP or local-data writes.**

## Performance

- **Duration:** 10m
- **Started:** 2026-03-02T17:10:24Z
- **Completed:** 2026-03-02T17:20:30Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Added `AllCapabilities.java` plus committed `all-capabilities.jar`/`.sha256` fixture artifacts for deterministic bytecode coverage.
- Added deterministic fixture build tooling (`src/bin/build-regression-fixtures.rs` + `tools/build-regression-fixtures.sh`) with javac-first and Docker fallback.
- Added `tests/regression-fixtures.rs` integration tests that call `run_scan(...)` directly with tempfile-backed uploads/scans and fixed IDs.
- Locked TEST-03 continuity by asserting demo sample still matches stable signature/YARA indicators.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add committed compiled fixture jar + deterministic rebuild script** - `b8d637e` (feat)
2. **Task 2: Add E2E regression tests that call the real scan helper (no HTTP)** - `b39ebd7` (test)

## Files Created/Modified

- `tests/fixtures/java-src/AllCapabilities.java` - Synthetic capability token/invoke fixture source compiled into committed bytecode.
- `tests/fixtures/bytecode/all-capabilities.jar` - Deterministic compiled fixture jar used directly by tests.
- `tests/fixtures/bytecode/all-capabilities.sha256` - Fixture provenance checksum.
- `src/bin/build-regression-fixtures.rs` - Deterministic jar assembler over compiled classes + extra files.
- `tools/build-regression-fixtures.sh` - One-shot fixture regeneration script (javac preferred, Docker fallback).
- `tests/fixtures/README.md` - Safety/regeneration contract and explicit note that tests do not run build tooling.
- `tests/regression-fixtures.rs` - End-to-end regression suite for TEST-01/TEST-02/TEST-03.

## Decisions Made

- Committed generated fixture jar/checksum in-repo instead of building at test-time, keeping CI and local runs independent of JDK/toolchain availability.
- Used `run_scan(...)` directly in integration tests with `tempfile::tempdir()` state to verify real pipeline behavior without HTTP server startup overhead.
- Accepted both legacy (`YARA-*`) and current pack-prefixed (`YARA-DEMO-*`) IDs in regression assertions to preserve resilience across indicator ID formatting drift.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Handled YARA indicator ID format drift in assertions**
- **Found during:** Task 2 (E2E regression test implementation)
- **Issue:** Current scan pipeline emits YARA IDs with rulepack provenance (`YARA-DEMO-*`), while plan examples referenced legacy unprefixed IDs.
- **Fix:** Regression assertions were implemented to accept both legacy and pack-prefixed IDs.
- **Files modified:** `tests/regression-fixtures.rs`
- **Verification:** `cargo test` (including `tests/regression-fixtures.rs`) passes.
- **Committed in:** `b39ebd7`

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** No scope creep; change keeps tests aligned with current indicator contract while preserving backward-compatible intent.

## Auth Gates

None.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 6 requirements TEST-01/TEST-02/TEST-03 now have committed fixtures and automated regression coverage.
- No blockers for roadmap completion; existing non-plan concern about `scripts/demo_run.sh` startup timing remains unchanged.

## Self-Check: PASSED

- Found `.planning/phases/06-regression-fixtures/06-regression-fixtures-02-SUMMARY.md`.
- Found `tests/regression-fixtures.rs` and `tests/fixtures/bytecode/all-capabilities.jar`.
- Verified task commits exist in history: `b8d637e`, `b39ebd7`.

---
*Phase: 06-regression-fixtures*
*Completed: 2026-03-02*
