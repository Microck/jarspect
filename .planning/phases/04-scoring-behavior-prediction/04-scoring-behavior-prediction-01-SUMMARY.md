---
phase: 04-scoring-behavior-prediction
plan: 01
subsystem: scoring
tags: [rust, scoring, dedup, synergy, explainability]

requires:
  - phase: 03-capability-detectors
    provides: Detector indicators with structured extracted evidence and location metadata used for scoring fingerprints.
provides:
  - Deduplicated static-indicator scoring with canonical category mapping, diminishing returns, and deterministic integer cap allocation.
  - Deterministic explanation output with indicator count, top contributor lines (+points + evidence), and synergy bonus references.
  - Unit tests that lock CLEAN reachability, anti-inflation behavior, ordering stability, score clamping, and reputation cap semantics.
affects:
  - 04-scoring-behavior-prediction-02
  - 04-scoring-behavior-prediction-03
  - 05-ui-verdict-rendering

tech-stack:
  added: []
  patterns:
    - Integer-only scoring math (weights, multipliers, category caps, synergy caps).
    - Source-agnostic fingerprint dedup keyed by canonical category + observable/location anchors.

key-files:
  created:
    - src/scoring.rs
  modified:
    - src/main.rs

key-decisions:
  - "Normalized detector IDs and freeform category labels into canonical ScoreCategory buckets, including obfuscation -> dynamic_loading and unknown -> other."
  - "Applied per-category cap allocation in deterministic order and reused post-cap effective points in Top contributors lines."
  - "Kept reputation as a separate adjustment with a hard +19 cap so reputation cannot push a scan into HIGH/CRITICAL on its own."

patterns-established:
  - "Top contributor and synergy explanation lines follow deterministic sorting contracts suitable for stable substring assertions."
  - "Synergy bonuses are one-time combo hits with supporting unit-id references and a global +35 cap."

duration: 12m
completed: 2026-03-02
---

# Phase 4 Plan 1: Stable Scoring Pipeline Summary

**Static scoring now deduplicates capability evidence, applies diminishing returns with capped synergy, and emits deterministic contributor/synergy explanations.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-02T16:11:24Z
- **Completed:** 2026-03-02T16:23:17Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Added `score_static_indicators` pipeline in `src/scoring.rs` with category normalization, source-agnostic fingerprint dedup, integer diminishing returns, per-category caps, and synergy bonuses.
- Added `ScoredVerdict` output shape with explicit `raw_score`, clamped `risk_score`, and structured explanation lines (`Indicators`, `Top contributors`, `Synergy bonuses`).
- Added scoring unit tests in `src/scoring.rs` covering CLEAN semantics, dedup anti-inflation, diminishing returns, deterministic tie ordering, synergy explanation behavior, clamp semantics, and reputation cap guardrails.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add score units + dedup + diminishing returns + synergy scoring** - `7c937b4` (feat)
2. **Task 2: Add unit tests that lock scoring stability (no mocks)** - `bedde82` (test)

## Files Created/Modified

- `src/scoring.rs` - New scoring engine (dedup units, severity/category normalization, diminishing returns, synergy, explanation renderer, unit tests).
- `src/main.rs` - Added `mod scoring;` to compile the new module in the binary crate.

## Decisions Made

- Used canonical `ScoreCategory` mapping for detector and non-detector indicators so pattern/signature/yara/detector signals can deduplicate into the same scoring buckets.
- Kept scoring fully integer-based (`1/1`, `1/2`, `1/4` multipliers; floor integer division) to guarantee deterministic scores and contributor points.
- Enforced CLEAN only when deduped static indicator count is zero and reputation contributes zero, preserving explicit no-static-evidence semantics.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Registered scoring module in crate root**
- **Found during:** Task 1 (scoring module implementation)
- **Issue:** A standalone `src/scoring.rs` is not compiled in this binary crate unless declared in `src/main.rs`.
- **Fix:** Added `mod scoring;` in `src/main.rs`.
- **Files modified:** `src/main.rs`
- **Verification:** `cargo test` compiles and runs scoring tests.
- **Committed in:** `7c937b4` (Task 1 commit)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Required for correctness/verification only; no scope creep beyond enabling planned compilation and tests.

## Auth Gates Encountered

None.

## Issues Encountered

None.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Ready for Plan 04-02 behavior prediction work to consume the established scoring categories/fingerprints and explanation conventions.
- Ready for Plan 04-03 verdict wiring to integrate `ScoredVerdict` into API output without reworking scoring internals.

---

*Phase: 04-scoring-behavior-prediction*
*Completed: 2026-03-02*

## Self-Check: PASSED

- FOUND: `.planning/phases/04-scoring-behavior-prediction/04-scoring-behavior-prediction-01-SUMMARY.md`
- FOUND: `src/scoring.rs`
- FOUND commit: `7c937b4`
- FOUND commit: `bedde82`
