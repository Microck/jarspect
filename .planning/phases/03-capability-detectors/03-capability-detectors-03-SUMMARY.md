---
phase: 03-capability-detectors
plan: 03
subsystem: api
tags: [rust, bytecode, detectors, archive, security]

requires:
  - phase: 02-archive-yara-fidelity-01
    provides: recursive archive entry paths for nested jars
  - phase: 03-capability-detectors-02
    provides: detector framework, dedup merging, and DETC-04/05 correlation patterns
provides:
  - DETC-06 unsafe deserialization detector with vulnerability-risk severity handling
  - DETC-07 native loading detector with invoke and embedded native archive evidence
  - DETC-08 credential/token theft detector with token/read/network escalation gates
affects: [04-scoring-behavior-prediction, 06-regression-fixtures, detector-verdicts]

tech-stack:
  added: []
  patterns: [class-scoped correlation gates, capability-level dedup aggregation, archive-entry evidence enrichment]

key-files:
  created:
    - src/detectors/capability_deser.rs
    - src/detectors/capability_native.rs
    - src/detectors/capability_cred_theft.rs
  modified:
    - src/detectors/mod.rs
    - src/detectors/spec.rs
    - demo/build_sample.sh

key-decisions:
  - "Classified DETC-06 as category=vulnerability with fixed med severity to avoid exploitability overstatement."
  - "Escalated DETC-07 to high only when native load invokes correlate with embedded native files or suspicious load paths."
  - "Implemented DETC-08 as token-first detection where med/high require same-class file-read and network correlation."

patterns-established:
  - "Archive resources can be represented as synthetic evidence locations with method/pc unset while preserving nested entry paths."
  - "Credential-theft severity gates are enforced with same-class token + primitive correlation before escalation."

duration: 9 min
completed: 2026-03-02
---

# Phase 3 Plan 3: Capability Detectors Summary

**Unsafe deserialization, native loading, and credential theft detectors now emit explainable, correlation-gated findings from bytecode and archive evidence.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-02T15:51:48Z
- **Completed:** 2026-03-02T16:00:49Z
- **Tasks:** 2
- **Files modified:** 6

## Accomplishments

- Added DETC-06 (`ObjectInputStream.readObject`) as a vulnerability-risk signal with conservative `med` severity and invoke callsite evidence.
- Added DETC-07 native loading detection from `System.load/loadLibrary` plus embedded native archive entries, including extracted native paths.
- Added DETC-08 credential/token theft detection with strict severity gates (`low` token-only, `med` token+read, `high` token+read+network).
- Updated demo jar build flow to always embed `native/dummy.dll`, then validated end-to-end detector output in persisted scan JSON.

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement DETC-06 (unsafe deserialization) and label as vulnerability-risk** - `6f98997` (feat)
2. **Task 2: Implement DETC-07 (native loading) and DETC-08 (credential/token theft) with correlation gates** - `b600f20` (feat)

## Files Created/Modified

- `src/detectors/capability_deser.rs` - DETC-06 detector and unit coverage for vulnerability-risk classification.
- `src/detectors/capability_native.rs` - DETC-07 detector combining invoke evidence with embedded native archive signals.
- `src/detectors/capability_cred_theft.rs` - DETC-08 detector with token/read/network correlation and URL/path extraction.
- `src/detectors/mod.rs` - detector registry wiring for DETC-06/07/08.
- `src/detectors/spec.rs` - shared network primitive matcher list reused for DETC-08 network correlation.
- `demo/build_sample.sh` - deterministic `native/dummy.dll` injection into demo jar for DETC-07 verification.

## Decisions Made

- Treated unsafe deserialization as **vulnerability** category (not malware capability) and pinned DETC-06 severity to `med`.
- Kept DETC-07 conservative by default (`med` for native load primitives) and only escalated to `high` with additional corroborating evidence.
- Kept DETC-08 observable at token-only level while requiring same-class primitive correlation for `med/high` severities.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Prebuilt binary to pass demo verification startup window**
- **Found during:** Task 2 verification
- **Issue:** `scripts/demo_run.sh` timed out on first run while waiting for `cargo run` to finish compilation and serve `/health`.
- **Fix:** Ran `cargo build` before retrying demo verification so server startup fit the script retry window.
- **Files modified:** None (verification workflow adjustment only)
- **Verification:** Re-ran `bash scripts/demo_run.sh` and full Node assertions for DETC-06/07/08 successfully.
- **Committed in:** `b600f20` (task commit includes verified detector/build changes)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope creep; adjustment was needed only to stabilize verification in this environment.

## Authentication Gates

None.

## Issues Encountered

- First demo verification run failed due local compile latency during auto-start; resolved by prebuilding before one focused retry.

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Phase 3 detector coverage is complete through DETC-08 with callsite-backed evidence and conservative severity controls.
- Ready for Phase 4 scoring/behavior work to consume detector outputs and establish stable verdict tiers.
- Remaining concern carried forward: `scripts/demo_run.sh` startup remains sensitive to first-run compile latency without prebuild.

---

*Phase: 03-capability-detectors*
*Completed: 2026-03-02*

## Self-Check: PASSED

- Verified files: `src/detectors/capability_deser.rs`, `src/detectors/capability_native.rs`, `src/detectors/capability_cred_theft.rs`, `.planning/phases/03-capability-detectors/03-capability-detectors-03-SUMMARY.md`.
- Verified commits: `6f98997`, `b600f20`.
