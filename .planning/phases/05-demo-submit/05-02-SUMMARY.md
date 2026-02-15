---
phase: 05-demo-submit
plan: 02
subsystem: demo
tags: [synthetic-sample, demo-script, safe-fixture]
requires:
  - phase: 05-demo-submit
    provides: "Web UI served from FastAPI"
  - phase: 04-reputation-verdict
    provides: "Scan and verdict APIs"
provides:
  - "Safe synthetic suspicious jar source and builder script"
  - "End-to-end demo runner for build/upload/scan/report flow"
  - "Consistent terminal output of verdict tier, score, and top indicators"
affects: [05-03]
tech-stack:
  added: []
  patterns:
    [
      "safe synthetic malware-like fixtures",
      "scripted terminal demo automation with curl+python parsing",
    ]
key-files:
  created:
    [
      "demo/samples/suspicious_mod_src/README.md",
      "demo/samples/suspicious_mod_src/src/main/java/com/modsentinel/demo/DemoMod.java",
      "demo/build_sample.sh",
      "scripts/demo_run.sh",
    ]
  modified: [".gitignore"]
key-decisions:
  - "Keep sample strictly synthetic and benign while embedding suspicious indicators in dead-code strings."
  - "Use one scripted command path for repeatable demos and video capture prep."
patterns-established:
  - "`demo/build_sample.sh` generates `demo/suspicious_sample.jar` locally without external downloads."
  - "`scripts/demo_run.sh` prints final verdict + indicator highlights for live narration."
duration: 5min
completed: 2026-02-15
---

# Phase 5 Plan 2: Synthetic Sample and Demo Script Summary

**Added a safe synthetic suspicious sample plus a single-command demo runner that prints PatchWarden verdicts and top indicators end-to-end.**

## Performance

- **Duration:** 5 min
- **Started:** 2026-02-15T20:36:00Z
- **Completed:** 2026-02-15T20:39:47Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments

- Added synthetic Java sample source that is harmless in execution but intentionally pattern-rich for scanner demos.
- Added `demo/build_sample.sh` to produce `demo/suspicious_sample.jar` locally with no external dependencies.
- Added `scripts/demo_run.sh` to automate build, upload, scan, retrieval, and verdict summary output.
- Ensured demo scripts output stable verdict details (tier, score, indicator highlights).

## Task Commits

1. **Task 1: Add synthetic suspicious-but-benign demo mod source + build script** - `280a643` (feat)
2. **Task 2: End-to-end demo runner script** - `b7d7eea` (feat)

## Files Created/Modified

- `demo/samples/suspicious_mod_src/README.md` - explicit safety and usage documentation for synthetic fixture.
- `demo/samples/suspicious_mod_src/src/main/java/com/modsentinel/demo/DemoMod.java` - safe sample with suspicious-looking dead-code markers.
- `demo/build_sample.sh` - deterministic local sample jar builder.
- `scripts/demo_run.sh` - build/upload/scan/retrieve/print automation script.
- `.gitignore` - ignores generated demo/runtime artifacts.

## Decisions Made

- Prioritized a synthetic fixture path to avoid distributing or requiring real malware samples.
- Kept demo runner script portable by using `curl` and inline Python JSON parsing.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Added no-JDK fallback path in demo/build_sample.sh**
- **Found during:** Task 1 (build script verification)
- **Issue:** Verification environment lacked `javac`/`jar`, so strict compile flow would fail and block demo script execution.
- **Fix:** Added deterministic fallback that packages synthetic `.class` content into the jar when JDK tools are unavailable.
- **Files modified:** demo/build_sample.sh
- **Verification:** `bash demo/build_sample.sh`
- **Committed in:** `280a643`

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** Demo sample build remains local, deterministic, and safe even in minimal environments.

## Issues Encountered

- Local environment did not include Java build tools (`javac`, `jar`).

## User Setup Required

None - no external service configuration required.

## Next Phase Readiness

- Demo artifacts and scripted run flow are ready for README/storyboard/checklist finalization in `05-03`.

## Self-Check: PASSED

- `.planning/phases/05-demo-submit/05-02-SUMMARY.md` exists.
- Commits `280a643` and `b7d7eea` exist in git log.

---

*Phase: 05-demo-submit*
*Completed: 2026-02-15*
