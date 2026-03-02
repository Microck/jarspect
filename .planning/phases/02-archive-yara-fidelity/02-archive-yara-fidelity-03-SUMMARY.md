---
phase: 02-archive-yara-fidelity
plan: 03
subsystem: analysis
tags: [rust, metadata-parsing, manifest-analysis, archive-provenance]

requires:
  - phase: 02-archive-yara-fidelity-02
    provides: flattened archive provenance and per-entry static scanning pipeline
provides:
  - Fabric/Forge/Spigot/manifest metadata parsing over jar-layer grouped entries
  - explicit metadata indicators with nested archive file_path provenance
  - high-severity manifest instrumentation key detection (Premain/Agent/redefine/retransform/boot-class-path)
affects: [03-capability-detectors, 04-scoring-behavior-prediction]

tech-stack:
  added: [toml, serde_yml]
  patterns:
    - metadata analysis isolated in `analysis::metadata` and consumed by static pipeline orchestration
    - jar-layer grouping derived from `!/` path boundaries for same-layer integrity checks

key-files:
  created:
    - src/analysis/metadata.rs
  modified:
    - Cargo.toml
    - Cargo.lock
    - src/analysis/mod.rs
    - src/main.rs

key-decisions:
  - "Grouped archive entries by the last `!/` boundary so metadata integrity checks stay scoped to the owning jar layer."
  - "Emitted metadata findings only for suspicious/inconsistent conditions, keeping severities low/med except high for manifest instrumentation keys."
  - "Mapped metadata findings directly into `result.static.matches[]` with `source=metadata` and full nested `file_path` provenance."

patterns-established:
  - "Metadata indicators are entry-scoped: metadata file path points to exact archive layer and entry."
  - "Manifest instrumentation attributes are modeled as one high-severity finding per key."

duration: 9 min
completed: 2026-03-02
---

# Phase 2 Plan 3: Archive + YARA Fidelity Summary

**Jar-layer metadata integrity checks now emit source=metadata indicators for Fabric/Forge/Spigot/manifest anomalies, including high-confidence manifest agent signals with exact nested provenance.**

## Performance

- **Duration:** 9 min
- **Started:** 2026-03-02T15:04:18Z
- **Completed:** 2026-03-02T15:13:25Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Added `analysis::metadata` with Fabric/Forge/Spigot/manifest parsing that fail-closes into structured low/med findings on malformed or inconsistent metadata.
- Implemented jar-layer grouping and same-layer cross-checks for Fabric entrypoints (`a.b.C` -> `a/b/C.class`) plus declared nested `jars[].file` existence.
- Added explicit high-severity manifest findings for `Premain-Class`, `Agent-Class`, `Can-Redefine-Classes`, `Can-Retransform-Classes`, and `Boot-Class-Path`.
- Wired metadata findings into `run_static_analysis()` so `counts_by_category` and `counts_by_severity` include metadata indicators automatically.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add metadata parsing module (Fabric/Forge/Spigot/Manifest) with jar-layer grouping** - `9a9adb5` (feat)
2. **Task 2: Wire metadata findings into static analysis indicators with nested-provenance file paths** - `1e86807` (feat)

**Plan metadata:** pending (created after summary/state update)

## Files Created/Modified
- `src/analysis/metadata.rs` - Metadata analyzer for Fabric/Forge/Spigot/manifest checks + parser-focused unit tests.
- `src/analysis/mod.rs` - Metadata module export/re-export for orchestration usage.
- `src/main.rs` - Static analysis wiring from `MetadataFinding` -> `Indicator` (`source=metadata`, `category=metadata`, nested `file_path`).
- `Cargo.toml` - Added `toml` and `serde_yml` dependencies required for Forge and Spigot metadata parsing.
- `Cargo.lock` - Recorded resolved dependency graph updates for new metadata parser crates.

## Decisions Made
- Used `rsplit_once("!/")` jar-layer derivation to keep integrity checks scoped to the exact jar boundary that owns each metadata file.
- Kept metadata severity policy conservative (`low|med`) for format/integrity issues and reserved `high` only for instrumentation-centric manifest keys.
- Preserved existing static findings schema by converting metadata output to existing `Indicator` shape rather than introducing a parallel payload.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Prebuilt binary before demo verification run**
- **Found during:** Task 2 verification (`bash scripts/demo_run.sh`)
- **Issue:** Auto-start path timed out on cold compile before health check window elapsed.
- **Fix:** Ran `cargo build` once before retrying `bash scripts/demo_run.sh`.
- **Files modified:** None
- **Verification:** Retry succeeded and emitted metadata indicators including `META-MANIFEST-PREMAIN`.
- **Committed in:** N/A (verification-flow workaround only)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope creep; workaround only stabilized verification flow.

## Issues Encountered
- `scripts/demo_run.sh` remains sensitive to first-run compile latency when no prebuilt binary exists.

## Authentication Gates
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- ARCH-02 criteria are satisfied: metadata findings are explicit, traceable, and entry-scoped in static matches.
- Demo verification confirms metadata indicators are present and manifest findings carry full jar-layer provenance.
- Follow-up concern: demo auto-start timeout behavior should still be hardened in a separate maintenance pass.

---
*Phase: 02-archive-yara-fidelity*
*Completed: 2026-03-02*

## Self-Check: PASSED

- Verified expected summary and implementation files exist on disk.
- Verified task commits `9a9adb5` and `1e86807` exist in git history.
