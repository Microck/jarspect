---
phase: 02-archive-yara-fidelity
plan: 02
subsystem: analysis
tags: [rust, yara-x, archive-scanning, rulepacks]

requires:
  - phase: 02-archive-yara-fidelity-01
    provides: recursive archive entry traversal with stable nested paths
provides:
  - pack-separated demo/prod signature and YARA corpora
  - per-entry YARA scanning with metadata-derived severity
  - pack-prefixed YARA indicator ids with entry-scoped provenance
affects: [03-capability-detectors, 04-scoring-behavior-prediction]

tech-stack:
  added: []
  patterns:
    - env-driven rulepack selection via JARSPECT_RULEPACKS
    - dedicated analysis::yara module for scanning and severity mapping

key-files:
  created:
    - data/signatures/demo/rules.yar
    - data/signatures/demo/signatures.json
    - data/signatures/prod/rules.yar
    - data/signatures/prod/signatures.json
    - src/analysis/yara.rs
  modified:
    - data/signatures/rules.yar
    - src/main.rs
    - src/analysis/mod.rs

key-decisions:
  - "Represent active YARA corpora as typed RulepackKind values selected from JARSPECT_RULEPACKS (default demo)."
  - "Derive YARA severity with ordered fallbacks: meta.severity -> meta.threat_level -> tags -> pack default."
  - "Keep data/signatures/rules.yar as a compatibility mirror of demo rules while startup loads from data/signatures/<pack>/ by default."

patterns-established:
  - "YARA ids are always pack-scoped: YARA-DEMO-* or YARA-PROD-*"
  - "YARA findings are generated from inflated archive entries and carry entry path provenance"

duration: 12 min
completed: 2026-03-02
---

# Phase 2 Plan 2: Archive + YARA Fidelity Summary

**Per-entry YARA scanning now derives severity from rule metadata and emits pack-scoped indicator ids tied to exact archive entry paths.**

## Performance

- **Duration:** 12 min
- **Started:** 2026-03-02T14:47:58Z
- **Completed:** 2026-03-02T15:00:37Z
- **Tasks:** 2
- **Files modified:** 8

## Accomplishments
- Split signature/YARA assets into `demo` and `prod` directories with stable compatibility stubs at legacy paths.
- Added `JARSPECT_RULEPACKS` support (`demo`, `prod`, `demo,prod`) with default demo startup behavior.
- Implemented `analysis::yara::scan_yara_rulepacks` to scan every inflated entry, map severities from metadata fallbacks, and preserve entry path provenance.
- Updated YARA indicator IDs to always include pack provenance (`YARA-DEMO-*` / `YARA-PROD-*`) and ensured demo rules carry explicit severity metadata.

## Task Commits

Each task was committed atomically:

1. **Task 1: Separate demo vs prod signature + YARA packs with a stable on-disk layout** - `12de8f3` (feat)
2. **Task 2: Implement per-entry YARA scanning with severity-from-metadata and pack-aware indicator ids** - `7dc20d8` (feat)

**Plan metadata:** pending (created after summary/state update)

## Files Created/Modified
- `data/signatures/demo/rules.yar` - Demo YARA ruleset now carries explicit severity metadata.
- `data/signatures/demo/signatures.json` - Demo signature corpus moved to pack-specific path.
- `data/signatures/prod/rules.yar` - Production placeholder YARA ruleset (valid syntax, no hits).
- `data/signatures/prod/signatures.json` - Production placeholder signature corpus (`[]`).
- `data/signatures/rules.yar` - Legacy demo compatibility mirror kept in sync.
- `src/analysis/yara.rs` - New rulepack-aware YARA scanning + severity derivation module with tests.
- `src/analysis/mod.rs` - Exposed YARA analysis module and exports.
- `src/main.rs` - Startup rulepack loading, static analysis YARA wiring, and pack-prefixed indicator emission.

## Decisions Made
- Used typed `RulepackKind` selection in startup configuration to avoid ambiguous string-based branching and to keep IDs deterministic.
- Kept signature corpora merged at runtime while keeping YARA rulepacks separate so match IDs can preserve pack provenance.
- Set demo pack default severity fallback to `high` and prod fallback to `med` when metadata/tags are absent.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Fixed moved-path borrow errors in rulepack file loading**
- **Found during:** Task 2 verification (`cargo test`)
- **Issue:** `PathBuf` values were moved into `read_to_string`, then referenced again in `with_context` closures.
- **Fix:** Borrowed paths (`&path`) for file reads and kept `path.display()` available for error context.
- **Files modified:** `src/main.rs`, `src/analysis/mod.rs`
- **Verification:** `cargo test`
- **Committed in:** `7dc20d8`

**2. [Rule 3 - Blocking] Prebuilt binary before demo verification runs**
- **Found during:** Task 1 and Task 2 verification (`bash scripts/demo_run.sh`)
- **Issue:** demo auto-start timed out during first-run compile latency in `scripts/demo_run.sh`.
- **Fix:** Ran `cargo build` before demo verification commands so startup checks had a ready binary.
- **Files modified:** None
- **Verification:** all demo verification commands completed successfully after prebuild.
- **Committed in:** N/A (verification-flow workaround only)

---

**Total deviations:** 2 auto-fixed (1 bug, 1 blocking)
**Impact on plan:** Both deviations were required to finish verification reliably; no scope creep.

## Issues Encountered
- `scripts/demo_run.sh` startup health check still races with cold compile in this environment. Prebuilding keeps verification stable.

## Authentication Gates
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- YARA-01/YARA-02/YARA-03 acceptance criteria are satisfied and committed.
- Phase 2 Plan 3 can build on deterministic entry path provenance and pack-separated rule loading.
- Carry-forward concern: demo auto-start timeout on cold builds remains and should be hardened separately.

---
*Phase: 02-archive-yara-fidelity*
*Completed: 2026-03-02*

## Self-Check: PASSED

- Verified expected files exist on disk.
- Verified task commits `12de8f3` and `7dc20d8` exist in git history.
