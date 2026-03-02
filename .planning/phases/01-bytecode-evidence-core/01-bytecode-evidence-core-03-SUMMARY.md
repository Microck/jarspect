---
phase: 01-bytecode-evidence-core
plan: 03
subsystem: api
tags: [rust, bytecode, cafebabe, java, evidence]

# Dependency graph
requires:
  - phase: 01-bytecode-evidence-core-02
    provides: invoke evidence variants and method-level pc locations
provides:
  - Deterministic demo bytecode pattern for new String(new byte[]{...})
  - Narrow byte-array string reconstructor for String.<init>([B)V
  - Additive reconstructed_string evidence items with location metadata
affects: [02-archive-yara-fidelity, 03-capability-detectors, scan-response-schema]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - Opcode-limited abstract interpreter with reset-on-unknown semantics
    - Additive serde-tagged evidence variants for bytecode extraction

key-files:
  created: [src/analysis/byte_array_strings.rs]
  modified:
    - demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
    - src/analysis/evidence.rs
    - src/analysis/classfile_evidence.rs
    - src/analysis/mod.rs

key-decisions:
  - "Added reconstructed_string as an additive BytecodeEvidenceItem variant using existing Location shape."
  - "Implemented a narrow reconstructor for immediate byte-array construction and reset state on control-flow and exception boundaries."

patterns-established:
  - "Reconstruction helpers live in dedicated analysis modules and are wired from classfile_evidence extraction."
  - "Never-invoked demo methods are valid fixtures as long as they compile into .class bytecode."

# Metrics
duration: 11m
completed: 2026-03-02
---

# Phase 1 Plan 3: Bytecode Evidence Core Summary

**Narrow JVM bytecode reconstruction now emits `reconstructed_string` evidence for `new String(new byte[]{...})` callsites with class/method/pc metadata from compiled demo bytecode.**

## Performance

- **Duration:** 10m 48s
- **Started:** 2026-03-02T14:17:02Z
- **Completed:** 2026-03-02T14:27:50Z
- **Tasks:** 2
- **Files modified:** 5

## Accomplishments
- Added a deterministic fixture method in `DemoMod.java` that compiles the exact BYTE-03 pattern without altering `main()` behavior.
- Implemented `src/analysis/byte_array_strings.rs`, a minimal state machine that reconstructs strings from byte-array initialization and `String.<init>([B)V`.
- Wired reconstructed output into `extract_bytecode_evidence()` and extended the stable serde evidence schema with `kind: "reconstructed_string"`.

## Task Commits

Each task was committed atomically:

1. **Task 1: Add a deterministic demo pattern for new String(new byte[]{...})** - `7cc1155` (feat)
2. **Task 2: Reconstruct byte-array strings from bytecode and emit as evidence** - `256b1d3` (feat)

**Plan metadata:** pending

## Files Created/Modified
- `src/analysis/byte_array_strings.rs` - Implements a narrow opcode interpreter and reconstruction tests.
- `src/analysis/classfile_evidence.rs` - Collects reconstructed strings per method and emits `reconstructed_string` evidence.
- `src/analysis/evidence.rs` - Extends stable tagged evidence enum and adds serde shape tests.
- `src/analysis/mod.rs` - Registers the new reconstruction module.
- `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java` - Adds deterministic never-invoked fixture method.

## Decisions Made
- Added `BytecodeEvidenceItem::ReconstructedString` rather than overloading existing constant-pool variants to keep evidence semantics explicit and additive.
- Kept reconstruction intentionally narrow (constants/newarray/dup/bastore/String ctor only) and fail-closed on unknown/control-flow/handler boundaries for correctness.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Installed local Java toolchain to produce compiled demo bytecode**
- **Found during:** Task 1 (demo fixture verification)
- **Issue:** `demo/build_sample.sh` fell back to a `.java`-only jar because `javac`/`jar` were missing, blocking BYTE-03 verification.
- **Fix:** Installed `openjdk-21-jdk-headless`, rebuilt the sample jar, and verified `.class` output.
- **Files modified:** None (execution environment dependency only)
- **Verification:** `bash demo/build_sample.sh` and `unzip -l demo/suspicious_sample.jar` showed `com/jarspect/demo/DemoMod.class`.
- **Committed in:** N/A (environment-only fix)

**2. [Rule 3 - Blocking] Prestarted API server to avoid cold-build timeout in demo verification**
- **Found during:** Task 2 (`bash scripts/demo_run.sh` verification)
- **Issue:** Auto-start path timed out while `cargo run` compiled on first launch.
- **Fix:** Started API explicitly with `JARSPECT_BIND` and reran verification via `JARSPECT_API_URL`.
- **Files modified:** None (verification runtime flow only)
- **Verification:** Demo scan succeeded and follow-up JSON check confirmed `cp_*`, `invoke_resolved`, and `reconstructed_string` evidence, with value `Hello` and populated location.
- **Committed in:** N/A (execution-only fix)

---

**Total deviations:** 2 auto-fixed (2 blocking)
**Impact on plan:** Both deviations were required to complete deterministic verification; implementation scope remained within BYTE-03.

## Issues Encountered
- `scripts/demo_run.sh` cold-start retries were insufficient for first compile latency in this environment; prestarting the API made verification deterministic.

## User Setup Required
None - no external service configuration required.

## Next Phase Readiness
- Phase 1 plan set is complete with additive bytecode evidence for constant-pool strings, invoke evidence, and reconstructed byte-array strings.
- Next phase can begin archive/YARA fidelity work with stable upstream evidence contracts now in place.

---
*Phase: 01-bytecode-evidence-core*
*Completed: 2026-03-02*

## Self-Check: PASSED
- FOUND: `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-03-SUMMARY.md`
- FOUND: `src/analysis/byte_array_strings.rs`
- FOUND commit: `7cc1155`
- FOUND commit: `256b1d3`
