---
phase: 03-capability-detectors
plan: 01
subsystem: analysis
tags: [rust, bytecode-detectors, capability-analysis, java-fixtures]

requires:
  - phase: 01-bytecode-evidence-core
    provides: invoke/string bytecode evidence with location metadata
  - phase: 02-archive-yara-fidelity
    provides: archive entry provenance and static pipeline integration points
provides:
  - detector framework with EvidenceIndex + merged DetectorFinding outputs
  - DETC-01/02/03 capability detectors using invoke evidence and class-scoped correlation
  - additive Indicator enrichment fields for structured callsite and extraction metadata
affects: [03-capability-detectors-02, 04-scoring-behavior-prediction]

tech-stack:
  added: []
  patterns:
    - capability detectors run as pure functions over BytecodeEvidence via EvidenceIndex lookups
    - detector severity escalation is correlation-gated to reduce false positives

key-files:
  created:
    - src/detectors/index.rs
    - src/detectors/spec.rs
    - src/detectors/capability_exec.rs
    - src/detectors/capability_network.rs
    - src/detectors/capability_dynamic_load.rs
  modified:
    - src/detectors/mod.rs
    - src/main.rs
    - demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
    - demo/build_sample.sh

key-decisions:
  - "Merged detector outputs by ID and accumulated location/extraction evidence instead of emitting one indicator per callsite."
  - "Applied class-scoped string correlation to severity gates so single primitive hits do not escalate to critical/high by default."
  - "Extended Indicator with optional structured evidence fields to keep API changes additive and backward compatible."

patterns-established:
  - "Detector modules expose `detect(&EvidenceIndex) -> Vec<DetectorFinding>` and are composed by a registry entrypoint."
  - "Scan pipeline converts detector findings into `source=detector` static matches before category/severity count aggregation."

duration: 13 min
completed: 2026-03-02
---

# Phase 3 Plan 1: Capability Detectors Summary

**Capability-layer detection now emits DETC-01/02/03 indicators from resolved bytecode invokes with structured callsite evidence and correlation-gated severity, backed by compiled demo bytecode fixtures.**

## Performance

- **Duration:** 13 min
- **Started:** 2026-03-02T15:22:53Z
- **Completed:** 2026-03-02T15:36:45Z
- **Tasks:** 2
- **Files modified:** 9

## Accomplishments
- Added `src/detectors` framework primitives (index/spec/registry) with deterministic finding dedup and merge behavior.
- Implemented DETC-01 (exec), DETC-02 (network), and DETC-03 (dynamic loading) using resolved invoke evidence and class-scoped string correlation.
- Wired detector output into static scan results as additive `Indicator` fields (`evidence_locations`, extracted URLs/commands/paths).
- Expanded `DemoMod.java` with never-invoked fixture methods for DETC-01..08 and ensured `demo/build_sample.sh` emits compiled `.class` files when JDK tools are available.

## Task Commits

Each task was committed atomically:

1. **Task 1: Create EvidenceIndex + detector plumbing (pure functions + unit-testable)** - `83739f0` (feat)
2. **Task 2: Implement DETC-01/02/03 + wire into scan output with additive Indicator fields** - `4aeaae9` (feat)

**Plan metadata:** pending (created after summary/state update)

## Files Created/Modified
- `src/detectors/index.rs` - Bytecode evidence index keyed by invoke owner/name and class-scoped string lookups.
- `src/detectors/spec.rs` - Shared conservative URL extraction + token matching helpers.
- `src/detectors/mod.rs` - DetectorFinding model, registry entrypoint, and finding dedup/merge logic.
- `src/detectors/capability_exec.rs` - DETC-01 execution detector + severity-correlation tests.
- `src/detectors/capability_network.rs` - DETC-02 networking detector + class-scoped URL correlation tests.
- `src/detectors/capability_dynamic_load.rs` - DETC-03 dynamic-loading detector + sensitive-token correlation tests.
- `src/main.rs` - Additive Indicator fields and detector wiring into static analysis output/count aggregation.
- `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java` - Never-invoked bytecode fixtures for DETC-01..08 primitives and string markers.
- `demo/build_sample.sh` - Compile `DemoMod.java` with `javac` before jar packaging so demo artifacts include `.class` bytecode.

## Decisions Made
- Kept detector findings normalized as one indicator per capability ID to avoid per-callsite noise while preserving all callsite locations.
- Used correlated class-level strings (not jar-global strings) for severity escalation and enrichment extraction.
- Kept all new indicator metadata optional and default-skipped in serde to preserve legacy payload compatibility.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Demo build script did not compile Java source into bytecode**
- **Found during:** Task 2 verification (`jar tf demo/suspicious_sample.jar | grep -q '\.class$'`)
- **Issue:** `demo/build_sample.sh` only packaged `DemoMod.java`, so planned bytecode detector verification could not pass.
- **Fix:** Added `javac -d ... DemoMod.java` before `jar cfm` packaging when `javac`/`jar` are available.
- **Files modified:** `demo/build_sample.sh`
- **Verification:** `bash demo/build_sample.sh` followed by class-entry check succeeded.
- **Committed in:** `4aeaae9`

**2. [Rule 3 - Blocking] Demo auto-start verification timed out on cold compile**
- **Found during:** Task 2 verification (`bash scripts/demo_run.sh` first attempt)
- **Issue:** Auto-start health-check window expired before initial compile finished, so no `scan_id` was emitted.
- **Fix:** Prebuilt once with `cargo build`, then reran demo verification flow.
- **Files modified:** None
- **Verification:** Rerun emitted scan output and detector assertion script passed.
- **Committed in:** N/A (verification-flow workaround only)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both deviations were necessary to complete bytecode-based detector verification; no scope creep beyond plan goals.

## Issues Encountered
- Initial `scripts/demo_run.sh` run failed to emit `scan_id` because local API startup timed out on first compile; rerun after `cargo build` succeeded.

## Authentication Gates
None.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- DETC-01/02/03 are now emitted as `source=detector` indicators with non-empty structured invoke locations.
- Detector modules and fixture methods for DETC-04..08 are in place for the next capability-detector plans.
- Follow-up concern carried forward: demo auto-start remains sensitive to cold compile latency unless prebuilt.

---
*Phase: 03-capability-detectors*
*Completed: 2026-03-02*

## Self-Check: PASSED

- Verified summary and detector implementation files exist on disk.
- Verified task commits `83739f0` and `4aeaae9` exist in git history.
