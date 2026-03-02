---
phase: 04-scoring-behavior-prediction
plan: 03
subsystem: api
tags: [rust, scan-api, scoring, behavior-prediction, roadmap]

requires:
  - phase: 04-scoring-behavior-prediction-01
    provides: Static scoring engine (`score_static_indicators`) with CLEAN semantics, dedup, diminishing returns, and deterministic explanation lines.
  - phase: 04-scoring-behavior-prediction-02
    provides: Evidence-derived behavior outputs (`derive_behavior`) with normalized observables and confidence/rationale metadata.
provides:
  - `/scan` wiring that maps behavior output from `behavior::derive_behavior` and verdict output from `scoring::score_static_indicators`.
  - Additive `BehaviorPrediction` response fields (`predicted_commands`, `predictions`) with serde defaults for compatibility.
  - A regression test proving verdict scoring ignores behavior-prediction payload differences.
affects:
  - 05-ui-verdict-rendering
  - 06-regression-fixtures

tech-stack:
  added: []
  patterns:
    - Build verdict as a pure static-input mapping (`build_verdict(static_indicators, reputation)`) with no behavior parameter.
    - Keep behavior payload indicators explicitly empty and use only derived observables/predictions for behavior output.

key-files:
  created: []
  modified:
    - src/main.rs
    - .planning/ROADMAP.md

key-decisions:
  - "Mapped `behavior::derive_behavior(...)` into API `BehaviorPrediction` field-by-field and set `indicators` to an explicit empty vector."
  - "Made `build_verdict(...)` accept only static indicators plus optional reputation and delegate all scoring logic to `score_static_indicators(...)`."
  - "Added serde defaults for new behavior fields so legacy persisted scan payloads remain deserializable."

patterns-established:
  - "Behavior prediction remains evidence-derived output only; verdict scoring remains static-evidence based to avoid double counting."
  - "Roadmap plan counts/lists are updated incrementally per completed phase plan."

duration: 7m
completed: 2026-03-02
---

# Phase 4 Plan 3: Scoring + Behavior Wiring Summary

**Scan responses now compose shared scoring and behavior modules, yielding CLEAN-capable verdicts while preventing behavior-derived score feedback.**

## Performance

- **Duration:** 7 min
- **Started:** 2026-03-02T16:28:12Z
- **Completed:** 2026-03-02T16:34:53Z
- **Tasks:** 2
- **Files modified:** 2

## Accomplishments

- Replaced legacy behavior placeholder inference with `behavior::derive_behavior(&static_findings.matches)` and mapped all derived fields into API `BehaviorPrediction`.
- Replaced legacy verdict arithmetic with `scoring::score_static_indicators(&static_findings.matches, reputation.as_ref())`, then mapped its outputs into API verdict fields.
- Added `verdict_ignores_behavior_prediction_outputs` test and removed `infer_behavior()` so behavior data cannot flow back into scoring.

## Task Commits

Each task was committed atomically:

1. **Task 1: Integrate scoring/behavior modules and prevent scoring feedback** - `5bb8589` (feat)
2. **Task 2: Update Phase 4 plan list in roadmap** - `5e2d6ea` (chore)

## Files Created/Modified

- `src/main.rs` - Wired `/scan` to `derive_behavior` + `score_static_indicators`, added additive behavior fields, deleted placeholder behavior helper, and added non-feedback regression test.
- `.planning/ROADMAP.md` - Updated Phase 4 plan count/list from `TBD` to the concrete 01/02/03 plan entries.

## Decisions Made

- Kept `BehaviorPrediction.indicators` as an explicit empty array during response construction to avoid carrying placeholder behavior indicators.
- Kept verdict indicators limited to static findings and reputation indicators; behavior predictions are excluded from `Verdict.indicators` and score input.
- Kept `build_verdict(...)` as a pure helper over static inputs so behavior->score feedback is structurally impossible in the call signature.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Prebuilt binary before demo verification retry**
- **Found during:** Task 1 verification
- **Issue:** First `bash scripts/demo_run.sh` attempt timed out while auto-starting the API and compiling the binary.
- **Fix:** Ran `cargo build` and retried `bash scripts/demo_run.sh` once (focused retry), which completed successfully.
- **Files modified:** None (verification-only operational workaround)
- **Verification:** Retry produced scan output with tier + score.
- **Committed in:** N/A (no file changes)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Deviation was limited to verification workflow reliability; planned code/doc scope remained unchanged.

## Auth Gates Encountered

None.

## Issues Encountered

- Demo script auto-start remains sensitive to first-run compile latency; prebuilding binary avoided timeout and allowed end-to-end verification to finish.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 4 integration is complete: scoring and behavior modules are now wired in `/scan`, and behavior scoring feedback is guarded by test coverage.
- Roadmap Phase 4 is now concretely listed as three plans, so planning context is ready for Phase 5 execution.

---

*Phase: 04-scoring-behavior-prediction*
*Completed: 2026-03-02*

## Self-Check: PASSED

- FOUND: `.planning/phases/04-scoring-behavior-prediction/04-scoring-behavior-prediction-03-SUMMARY.md`
- FOUND: `src/main.rs`
- FOUND: `.planning/ROADMAP.md`
- FOUND commit: `5bb8589`
- FOUND commit: `5e2d6ea`
