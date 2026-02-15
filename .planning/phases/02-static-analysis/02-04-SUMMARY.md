---
phase: 02-static-analysis
plan: 04
subsystem: api
tags: [static-agent, scan-endpoint, signatures, integration]
requires:
  - phase: 02-static-analysis
    provides: "Decompiler, pattern matcher, and signature store"
  - phase: 01-foundation
    provides: "Upload + intake endpoints"
provides:
  - "StaticAgent orchestration for uploaded jars"
  - "ScanResult schema with static findings"
  - "`/scan` API integration returning intake + static payloads"
affects: [03-behavior-analysis, 04-reputation-verdict, 05-demo-submit]
tech-stack:
  added: []
  patterns: ["agent artifact handoff", "scan response model composition"]
key-files:
  created:
    [
      "src/mod_sentinel/agents/static_agent.py",
      "src/mod_sentinel/models/scan.py",
      "tests/test_scan_static.py",
    ]
  modified:
    [
      "src/mod_sentinel/api/routes/scan.py",
      "src/mod_sentinel/models/__init__.py",
      "src/mod_sentinel/analysis/decompiler.py",
      "src/mod_sentinel/agents/__init__.py",
    ]
key-decisions:
  - "Return static findings directly from `/scan` to keep API deterministic and demo-friendly."
  - "Expose raw decompiled source list via artifact object, not API payload, for later behavior prompting."
patterns-established:
  - "Each scan stage is represented by a dedicated agent class."
  - "Route layer owns HTTP mapping while agents stay transport-agnostic."
duration: 5min
completed: 2026-02-15
---

# Phase 2 Plan 4: Static Integration Summary

**Integrated static analysis into the scan pipeline so `/scan` now returns intake metadata plus pattern/signature-based indicators for each uploaded jar.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-15T19:40:05Z
- **Completed:** 2026-02-15T19:44:31Z
- **Tasks:** 2
- **Files modified:** 7

## Accomplishments

- Added `StaticAgent` that orchestrates decompilation, pattern matching, and signature search.
- Added typed `ScanRequest`/`ScanResult` models including static findings.
- Updated `POST /scan` and tests to return verifiable static indicators for suspicious jars.

## Task Commits

1. **Task 1: Static Agent implementation** - `1d1e14c` (feat)
2. **Task 2: Extend scan response schema and route to include static findings** - `860196f` (feat)

## Files Created/Modified

- `src/mod_sentinel/agents/static_agent.py` - static scan orchestration and merged findings
- `src/mod_sentinel/models/scan.py` - scan request/result models
- `src/mod_sentinel/api/routes/scan.py` - intake + static endpoint behavior
- `tests/test_scan_static.py` - end-to-end static detection assertion
- `src/mod_sentinel/analysis/decompiler.py` - fallback output enhancement for regex matching reliability

## Decisions Made

- Kept static response deterministic by using rule/signature engines only (no model inference yet).
- Preserved decompiled source output internally for behavior-agent prompt construction in Phase 3.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed static detection miss when fallback decompiler output removed punctuation context**
- **Found during:** Task 2
- **Issue:** Pattern regexes like `java.net.URLConnection` did not match token-only fallback text.
- **Fix:** Included a bounded raw-byte excerpt in fallback decompile output in addition to token extraction.
- **Files modified:** `src/mod_sentinel/analysis/decompiler.py`
- **Verification:** `python3 -m pytest -q` with `tests/test_scan_static.py` detection assertions
- **Committed in:** `860196f`

---

**Total deviations:** 1 auto-fixed (1 bug)
**Impact on plan:** Increased correctness of static pattern matching without expanding scope.

## Issues Encountered

- Initial static integration test failed due fallback formatting mismatch with regex rules; fixed inline.

## User Setup Required

None.

## Next Phase Readiness

- `/scan` now returns the full static context needed by Behavior Agent.
- No blockers for Phase 3 behavior-analysis plans.

## Self-Check: PASSED

- `.planning/phases/02-static-analysis/02-04-SUMMARY.md` exists.
- Commits `1d1e14c` and `860196f` exist in git log.

---

*Phase: 02-static-analysis*
*Completed: 2026-02-15*
