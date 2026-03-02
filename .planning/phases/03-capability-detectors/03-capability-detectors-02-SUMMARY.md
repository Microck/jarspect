---
phase: 03-capability-detectors
plan: 02
subsystem: analysis
tags: [rust, bytecode-detectors, filesystem-modification, persistence-correlation]

requires:
  - phase: 03-capability-detectors-01
    provides: detector framework with EvidenceIndex indexing and additive detector indicator wiring
provides:
  - DETC-04 detector for jar/filesystem modification primitives with class-scoped enrichment gates
  - DETC-05 detector for persistence tokens correlated to same-class exec/write primitives
  - demo-scan verification that DETC-04 and DETC-05 emit source=detector findings with invoke callsite evidence
affects: [03-capability-detectors-03, 04-scoring-behavior-prediction]

tech-stack:
  added: []
  patterns:
    - severity escalation requires same-class correlation between invoke primitives and string evidence
    - detector findings remain one-indicator-per-capability with merged structured evidence

key-files:
  created:
    - src/detectors/capability_fs_modify.rs
    - src/detectors/capability_persistence.rs
  modified:
    - src/detectors/mod.rs
    - src/detectors/spec.rs

key-decisions:
  - "Kept DETC-04 escalation conservative: high only for zip/jar primitives plus same-class traversal or .jar markers; generic writes stay low."
  - "Implemented DETC-05 as token-first detection with same-class invoke correlators so persistence tokens alone remain low severity."
  - "Reused shared token-matching helper for case-insensitive enrichment extraction and deterministic dedup."

patterns-established:
  - "Filesystem and persistence detectors consume invokes + strings from EvidenceIndex without jar-global token correlation."
  - "Invoke-triggered detector tests assert at least one evidence location carries method metadata and pc offset."

duration: 8 min
completed: 2026-03-02
---

# Phase 3 Plan 2: Capability Detectors Summary

**Capability detection now flags jar/filesystem modification and persistence behavior with class-scoped correlation gates, producing DETC-04/05 detector indicators that carry structured invoke callsites and extracted path/command evidence.**

## Performance

- **Duration:** 8 min
- **Started:** 2026-03-02T15:41:04Z
- **Completed:** 2026-03-02T15:48:48Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Implemented DETC-04 (`src/detectors/capability_fs_modify.rs`) to detect zip/jar rewriting and generic file-write primitives with severity modulation (`low`/`med`/`high`) and class-scoped path enrichment.
- Implemented DETC-05 (`src/detectors/capability_persistence.rs`) to detect persistence tokens with required same-class exec/write correlators and conservative high-severity gating.
- Registered both detectors in the shared registry and validated end-to-end output through `cargo test` plus demo scan assertions on persisted scan JSON.

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement DETC-04 (jar/filesystem modification) with enrichment-only escalation** - `5637ae5` (feat)
2. **Task 2: Implement DETC-05 (persistence) as correlation over tokens + exec/write primitives** - `32201f2` (feat)

**Plan metadata:** pending (created after summary/state update)

## Files Created/Modified
- `src/detectors/capability_fs_modify.rs` - DETC-04 primitive matcher, enrichment extraction, severity gates, and unit tests.
- `src/detectors/capability_persistence.rs` - DETC-05 token correlation logic, enrichment extraction, and unit tests.
- `src/detectors/mod.rs` - Detector registry updates to run DETC-04 and DETC-05 in scan pipeline.
- `src/detectors/spec.rs` - Shared case-insensitive token-string extraction helper used by DETC-04/05.

## Decisions Made
- Kept DETC-04 severity conservative by separating generic writes (`low`) from jar/zip rewrite primitives (`med`) and only escalating to `high` with same-class traversal or `.jar` evidence.
- Kept DETC-05 token-only matches reportable at `low`, with `med` requiring same-class exec/write correlators and `high` requiring exec plus concrete path/key tokens.
- Included both string-token and invoke callsite locations in DETC-05 evidence to preserve explainability for correlated and token-only scenarios.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Token dedup helper initially treated case-variants as unique values**
- **Found during:** Task 1 verification (`cargo test`)
- **Issue:** `matching_token_strings` returned both `mods/evil.jar` and `MODS/evil.jar`, failing deterministic case-insensitive dedup expectations.
- **Fix:** Added normalized lowercase dedup tracking in the helper while preserving original matched values.
- **Files modified:** `src/detectors/spec.rs`
- **Verification:** `cargo test` passed after helper fix.
- **Committed in:** `5637ae5`

**2. [Rule 3 - Blocking] Demo verification auto-start timed out on cold compile**
- **Found during:** Task 2 verification (`bash scripts/demo_run.sh` first attempt)
- **Issue:** auto-start health check timed out before initial compile completed, so `scan_id` could not be extracted.
- **Fix:** Prebuilt with `cargo build`, then reran demo verification flow.
- **Files modified:** None
- **Verification:** rerun emitted `scan_id` and Node assertion confirmed DETC-04/05 detector matches with invoke callsites.
- **Committed in:** N/A (verification flow workaround)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking)
**Impact on plan:** Both deviations were required to complete planned verification; implementation scope stayed aligned with DETC-04/05 objectives.

## Issues Encountered
- First demo-run verification attempt failed due cold-start compile latency in `scripts/demo_run.sh`; resolved by prebuilding once before rerun.

## Authentication Gates
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- DETC-04 and DETC-05 now emit `source=detector` findings with non-empty `evidence_locations` and invoke callsites (`method` + `pc`) for invoke-triggered cases.
- Shared detector wiring now covers DETC-01 through DETC-05 with consistent structured enrichment fields.
- Existing demo auto-start compile-latency sensitivity remains a known verification concern and should stay tracked.

---
*Phase: 03-capability-detectors*
*Completed: 2026-03-02*

## Self-Check: PASSED

- Verified summary and DETC-04/05 detector files exist on disk.
- Verified task commits `5637ae5` and `32201f2` exist in git history.
