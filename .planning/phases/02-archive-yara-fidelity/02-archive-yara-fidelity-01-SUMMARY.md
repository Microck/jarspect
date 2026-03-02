---
phase: 02-archive-yara-fidelity
plan: 01
subsystem: api
tags: [rust, zip, nested-jar, yara, demo-fixture]

# Dependency graph
requires:
  - phase: 01-bytecode-evidence-core-03
    provides: Bytecode evidence extraction over ArchiveEntry streams consumed by /scan.
provides:
  - Recursive jar-in-jar traversal with flattened `!/` nested paths and safety budgets.
  - `/scan` wiring to recursive archive entries with optional text scanning safeguards.
  - Demo sample jar that includes embedded jar payload + declared Fabric nested jar metadata.
affects: [02-archive-yara-fidelity-02, 02-archive-yara-fidelity-03, 03-capability-detectors]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Budget-gated archive inflation before memory reads.
    - Flattened recursive archive streams for provenance-stable indicator paths.

key-files:
  created: [src/analysis/archive.rs]
  modified: [src/analysis/mod.rs, src/main.rs, demo/build_sample.sh]

key-decisions:
  - Keep `ArchiveEntry.text` as `Option<String>` and default to empty string for text matchers when payloads exceed text-size budget.
  - Recurse only when entry name ends with `.jar` and bytes begin with ZIP magic `PK\x03\x04`.

patterns-established:
  - "Archive traversal safety first: enforce entry size, ratio, and total-inflation budgets before `read_to_end`."
  - "Nested provenance format is canonicalized as `{root}!/{entry}!/{nested}` for all downstream evidence attribution."

# Metrics
duration: 7m
completed: 2026-03-02
---

# Phase 2 Plan 1: Archive + YARA Fidelity Summary

**Recursive jar-in-jar entry flattening now drives `/scan`, and the demo artifact includes an embedded jar so nested findings are attributed with stable `!/` provenance paths.**

## Performance

- **Duration:** 7m
- **Started:** 2026-03-02T14:36:37Z
- **Completed:** 2026-03-02T14:44:01Z
- **Tasks:** 2
- **Files modified:** 4

## Accomplishments
- Added `analysis::read_archive_entries_recursive` with recursion limits (depth, entry count, entry bytes, total inflated bytes) and compression-ratio guard.
- Switched `/scan` to recursive archive ingestion and adapted static pattern/signature matching to optional text payloads.
- Updated demo fixture build to always include `META-INF/jars/inner-demo.jar`, `fabric.mod.json` nested-jar declaration, and `Premain-Class` manifest attribute.
- Verified nested attribution end-to-end: latest scan indicators include `...jar!/META-INF/jars/inner-demo.jar!/payload.txt`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Implement recursive archive traversal with nested-path rendering + safety limits** - `998b85f` (feat)
2. **Task 2: Update demo sample jar to include an embedded jar and a declared Fabric nested-jar reference** - `91c9e0c` (feat)

## Files Created/Modified
- `src/analysis/archive.rs` - New recursive archive reader with bounded recursion and nested-path rendering.
- `src/analysis/mod.rs` - Exports archive traversal API and `ArchiveEntry` type.
- `src/main.rs` - Routes `/scan` through recursive archive traversal and handles optional text matching.
- `demo/build_sample.sh` - Builds deterministic nested jar fixture with Fabric `jars[]` metadata and suspicious manifest field.

## Decisions Made
- Moved archive traversal into `analysis::archive` and reused a shared `ArchiveEntry` type so Phase 1 bytecode extraction remains compatible.
- Kept traversal fail-open for unreadable embedded jars (skip + debug log) while preserving strict resource budgets.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Demo verification timed out during cold `cargo run` startup**
- **Found during:** Task 1 verification (`bash scripts/demo_run.sh`)
- **Issue:** Auto-start health check timed out while the first compile was still in progress.
- **Fix:** Performed one focused retry after prebuilding (`cargo build && bash scripts/demo_run.sh`).
- **Files modified:** None (verification-only runtime handling)
- **Verification:** Retry completed successfully and returned a valid scan result.
- **Committed in:** None (no code delta)

---

**Total deviations:** 1 auto-fixed (1 blocking)
**Impact on plan:** No scope creep; retry only improved verification reliability.

## Issues Encountered
- `scripts/demo_run.sh` auto-start can race with first-run compile latency; prebuilding once resolved it for this run.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Recursive entry stream with nested provenance is in place for per-entry YARA severity work.
- Demo fixture now exercises nested-jar attribution, enabling ARCH-01 regression checks in later plans.

## Self-Check: PASSED
- Verified files: `src/analysis/archive.rs`, `demo/build_sample.sh`, `.planning/phases/02-archive-yara-fidelity/02-archive-yara-fidelity-01-SUMMARY.md`.
- Verified commits: `998b85f`, `91c9e0c`.
