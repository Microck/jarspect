---
phase: 04-scoring-behavior-prediction
plan: 02
subsystem: behavior
tags: [rust, behavior-prediction, evidence-derivation, url-normalization, regression-tests]

requires:
  - phase: 03-capability-detectors
    provides: Detector indicators with extracted URL/command/path evidence and supporting indicator IDs.
  - phase: 04-scoring-behavior-prediction-01
    provides: Existing crate-root module registration pattern for new Phase 4 modules.
provides:
  - Evidence-derived behavior derivation that prefers extracted fields and falls back to bounded regex extraction from indicator evidence/rationale.
  - Structured per-item behavior predictions with pinned confidence constants and rationale strings referencing supporting indicator IDs.
  - Regression tests that lock URL normalization, zero-observable confidence semantics, traceability contract, and placeholder-domain absence.
affects:
  - 04-scoring-behavior-prediction-03
  - 05-ui-verdict-rendering

tech-stack:
  added: [url]
  patterns:
    - Extracted-fields-first observable derivation with regex fallback and deterministic dedup via BTreeMap/BTreeSet.
    - Prediction-level confidence policy (0.9 detector+extracted, 0.8 extracted-only, 0.6 regex) with max-based overall confidence.

key-files:
  created:
    - src/behavior.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - src/main.rs

key-decisions:
  - "Normalized URLs with url::Url into scheme://host[:port]/path and ignored unparsable inputs to keep network predictions stable."
  - "Pinned prediction confidence constants (0.9/0.8/0.6) and empty-observable behavior confidence to exactly 0.0 for deterministic assertions."
  - "Registered `mod behavior;` in crate root during this plan so behavior unit tests compile and run before Plan 04-03 wiring."

patterns-established:
  - "Each `PredictedBehavior` rationale explicitly names evidence source and supporting indicator IDs for traceability."
  - "Legacy placeholder domains are guarded by regression tests to prevent synthetic behavior reintroduction."

duration: 12m
completed: 2026-03-02
---

# Phase 4 Plan 2: Evidence-Derived Behavior Prediction Summary

**Behavior prediction now derives URLs, commands, file writes, and persistence markers directly from indicator evidence with deterministic normalization, confidence, and traceable rationale.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-02T16:11:46Z
- **Completed:** 2026-03-02T16:23:40Z
- **Tasks:** 3
- **Files modified:** 4

## Accomplishments

- Added `url = "2.5.8"` and refreshed lockfile resolution to support stable URL parsing/normalization.
- Implemented `src/behavior.rs` with `derive_behavior`, `DerivedBehavior`, and serializable `PredictedBehavior` outputs sourced from extracted fields first, then bounded regex fallback.
- Added behavior regression tests validating URL normalization, empty-observable confidence semantics, support-ID traceability, and placeholder-domain guardrails.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add `url` dependency for normalization** - `a62f224` (chore)
2. **Task 2: Implement evidence-derived behavior prediction (no placeholders)** - `bd0523a` (feat)
3. **Task 3: Add unit tests that prevent placeholder regressions** - `1c83004` (test)

## Files Created/Modified

- `Cargo.toml` - Added `url` dependency required by behavior URL normalization.
- `Cargo.lock` - Recorded resolved `url` dependency graph.
- `src/behavior.rs` - Added behavior derivation engine, observable extraction/normalization helpers, confidence/rationale generation, and regression tests.
- `src/main.rs` - Added `mod behavior;` so behavior module tests are compiled and executed by `cargo test`.

## Decisions Made

- Kept behavior derivation additive and evidence-only: extracted indicator fields are preferred, regex fallback is bounded to `indicator.evidence` and `indicator.rationale`.
- Chose deterministic data structures (`BTreeMap`, `BTreeSet`) so prediction lists, support IDs, and outputs remain stable across runs.
- Kept overall confidence as max item confidence (clamped to `[0,1]`) with exact `0.0` when no observables are derived.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Registered behavior module for test compilation**
- **Found during:** Task 3 (placeholder regression tests)
- **Issue:** `src/behavior.rs` tests are not compiled in this binary crate unless the module is declared in `src/main.rs`.
- **Fix:** Added `mod behavior;` in crate root.
- **Files modified:** `src/main.rs`
- **Verification:** `cargo test` runs `behavior::tests::*` (57 total tests).
- **Committed in:** `1c83004` (Task 3 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope creep; deviation only enabled planned verification and did not change runtime behavior wiring.

## Auth Gates Encountered

None.

## Issues Encountered

- Initial `cargo test` attempt during Task 2 exceeded the default tool timeout; a single focused retry with a longer timeout completed successfully.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- `src/behavior.rs` is ready for Plan 04-03 wiring into `/scan` response construction.
- Prediction outputs now have normalized observables, per-item confidence, and indicator-linked rationale needed for API embedding/UI rendering.

---

*Phase: 04-scoring-behavior-prediction*
*Completed: 2026-03-02*

## Self-Check: PASSED

- FOUND: `.planning/phases/04-scoring-behavior-prediction/04-scoring-behavior-prediction-02-SUMMARY.md`
- FOUND: `src/behavior.rs`
- FOUND commit: `a62f224`
- FOUND commit: `bd0523a`
- FOUND commit: `1c83004`
