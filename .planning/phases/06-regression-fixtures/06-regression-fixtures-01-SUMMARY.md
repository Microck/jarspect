---
phase: 06-regression-fixtures
plan: 01
subsystem: testing
tags: [rust, axum, tempfile, regression]

requires:
  - phase: 05-ui-verdict-rendering
    provides: canonical verdict/severity rendering behavior preserved while extracting scan execution
provides:
  - Library scan entrypoint callable from tests (`run_scan`) with optional deterministic `scan_id` override
  - Axum `/scan` handler delegation to shared library pipeline logic
  - Phase 6 roadmap plan list locked to two concrete plans
affects: [06-regression-fixtures-02-PLAN.md, integration-tests]

tech-stack:
  added: [tempfile]
  patterns: [library-first scan pipeline reuse, handler-to-library delegation]

key-files:
  created: [src/lib.rs, .planning/phases/06-regression-fixtures/06-regression-fixtures-01-SUMMARY.md]
  modified: [src/main.rs, Cargo.toml, Cargo.lock, .planning/ROADMAP.md]

key-decisions:
  - "Re-homed scan pipeline types/helpers into `src/lib.rs` and exposed `run_scan` for non-HTTP test execution."
  - "Kept API status semantics by mapping known library scan errors (`invalid id`, `upload missing`) back to existing Axum error JSON statuses."
  - "Added `tempfile` only under `[dev-dependencies]` to keep runtime dependencies unchanged."

patterns-established:
  - "Shared scan logic lives in library API; handlers remain transport wrappers."
  - "Regression-test dependencies are isolated to dev dependencies."

duration: 11m
completed: 2026-03-02
---

# Phase 6 Plan 1: Expose scan helper for regression fixtures Summary

**Reusable `run_scan` library pipeline plus temp-dir-ready test dependency wiring for deterministic Phase 6 regression execution.**

## Performance

- **Duration:** 11m
- **Started:** 2026-03-02T16:55:32Z
- **Completed:** 2026-03-02T17:06:55Z
- **Tasks:** 3
- **Files modified:** 5

## Accomplishments
- Extracted scan execution logic and scan-domain structs into `src/lib.rs`, including the contract entrypoint `pub async fn run_scan(...)`.
- Refactored `src/main.rs` so `/scan` now delegates to the shared library pipeline while retaining existing API error JSON shape.
- Added `tempfile = "3.26.0"` under dev dependencies and locked Phase 6 roadmap plans to concrete filenames/count.

## Task Commits

Each task was committed atomically:

1. **Task 1: Extract scan pipeline into a library helper** - `8b88414` (feat)
2. **Task 2: Add tempfile as a dev-dependency** - `8ae056d` (chore)
3. **Task 3: Lock Phase 6 plan list in the roadmap** - `1c14a60` (chore)

**Plan metadata:** pending final docs commit

## Files Created/Modified
- `src/lib.rs` - Shared scan pipeline types/helpers and exported `run_scan` entrypoint for test and handler reuse.
- `src/main.rs` - HTTP transport layer now calls `jarspect::run_scan(...)` and preserves API error responses.
- `Cargo.toml` - Added `tempfile = "3.26.0"` under `[dev-dependencies]`.
- `Cargo.lock` - Updated lockfile after dependency resolution.
- `.planning/ROADMAP.md` - Phase 6 section now lists two concrete plans and progress row tracks `0/2`.

## Decisions Made
- Kept the scan pipeline reusable from library code so Phase 6 integration tests can exercise real behavior without running an HTTP server.
- Preserved API compatibility by converting library scan errors to the same 400/404/500 JSON response pattern in handlers.
- Left non-Phase-6 roadmap progress edits unstaged/uncommitted to keep this plan scoped to requested roadmap lines only.

## Deviations from Plan

None - plan executed exactly as written.

## Issues Encountered

- First `cargo test` run after adding `tempfile` hit the command timeout during dependency compilation; reran once with a longer timeout and verification passed.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `run_scan` is now callable directly from regression tests with temp upload/scan directories.
- Phase 6 plan inventory is concrete (`01` and `02`), so fixture and E2E test implementation can proceed in Plan 02.

## Self-Check: PASSED

- Verified files: `.planning/phases/06-regression-fixtures/06-regression-fixtures-01-SUMMARY.md`, `src/lib.rs`
- Verified commits: `8b88414`, `8ae056d`, `1c14a60`

---
*Phase: 06-regression-fixtures*
*Completed: 2026-03-02*
