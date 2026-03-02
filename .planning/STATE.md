# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.
**Current focus:** Phase 3 - Capability Detectors

## Current Position

Phase: 3 of 6 (Capability Detectors)
Plan: 1 of 3 in current phase
Status: In progress
Last activity: 2026-03-02 - Completed 03-capability-detectors-01-PLAN.md

Progress: [█████░░░░░] 47%

## Performance Metrics

**Velocity:**
- Total plans completed: 7
- Average duration: 9.9 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-bytecode-evidence-core | 3 | 28 min | 9.3 min |
| 02-archive-yara-fidelity | 3 | 28 min | 9.3 min |
| 03-capability-detectors | 1 | 13 min | 13.0 min |

## Accumulated Context

### Decisions

| Phase | Decision | Rationale |
|-------|----------|-----------|
| 01-bytecode-evidence-core-01 | Kept `ScanResult.bytecode_evidence` optional with serde default/skip semantics. | Preserves compatibility when deserializing legacy persisted scan JSON without the new field. |
| 01-bytecode-evidence-core-01 | Used `cafebabe` for class parsing and explicit constant-pool scanning with `cesu8` decoding. | Ensures all `CONSTANT_Utf8` payloads are extracted while keeping parse fidelity and stable class metadata. |
| 01-bytecode-evidence-core-02 | Added dedicated `invoke_resolved` and `invoke_dynamic` variants in the stable tagged evidence schema. | Keeps invoke evidence additive and machine-readable without changing existing variant semantics. |
| 01-bytecode-evidence-core-02 | Kept `invokedynamic` owner-less and stored bootstrap attribute index instead. | Avoids incorrect owner attribution while preserving data needed for downstream detector interpretation. |
| 01-bytecode-evidence-core-03 | Added `reconstructed_string` evidence variant with existing `Location` metadata shape. | Keeps BYTE-03 output additive and stable under the existing serde-tagged contract. |
| 01-bytecode-evidence-core-03 | Implemented a narrow opcode state machine for `new String(new byte[]{...})` reconstruction. | Delivers explainable reconstruction while fail-closing on unknown/control-flow/exception boundaries. |
| 02-archive-yara-fidelity-01 | Canonicalized nested archive provenance as `{root}!/{entry}!/{nested}` using a flattened recursive stream. | Gives YARA/signature/bytecode indicators stable, grep-able nested paths for ARCH-01 attribution. |
| 02-archive-yara-fidelity-01 | Kept `ArchiveEntry.text` optional with empty-string fallback for text matchers. | Preserves binary scanning and avoids large-entry lossy text expansion while keeping existing matchers compatible. |
| 02-archive-yara-fidelity-02 | Introduced typed `RulepackKind` selection from `JARSPECT_RULEPACKS` with default `demo`. | Keeps demo/prod corpora explicit and deterministic while preserving backward-compatible startup behavior. |
| 02-archive-yara-fidelity-02 | Mapped YARA severity using ordered fallbacks: `meta.severity` -> `meta.threat_level` -> tags -> pack default. | Ensures severities are rule-authored when available and still deterministic when metadata is absent. |
| 02-archive-yara-fidelity-02 | Prefixed YARA indicators with pack provenance (`YARA-DEMO-*`/`YARA-PROD-*`) and retained entry-scoped `file_path`. | Prevents demo/prod mixing in reporting and keeps YARA-01 path attribution intact. |
| 02-archive-yara-fidelity-03 | Grouped metadata checks by jar layer using the last `!/` boundary in archive entry paths. | Keeps Fabric/Forge/Spigot integrity checks scoped to the owning jar, including nested jar layers. |
| 02-archive-yara-fidelity-03 | Reserved `high` metadata severity for manifest instrumentation keys and kept malformed/inconsistent metadata findings in `low|med`. | Preserves conservative signal quality while still flagging clear Java agent risk attributes. |
| 02-archive-yara-fidelity-03 | Converted metadata findings directly into `result.static.matches[]` indicators with `source=metadata` and full nested `file_path` provenance. | Makes ARCH-02 findings additive, traceable, and immediately consumable by existing scoring/behavior stages. |
| 03-capability-detectors-01 | Consolidated detector output by capability ID while merging all callsite locations and extracted evidence vectors. | Keeps capability signals readable and explainable without emitting one indicator per invoke instruction. |
| 03-capability-detectors-01 | Applied class-scoped string correlation gates for DETC-01/02/03 severity escalation. | Reduces false positives by requiring related string context in the same class before escalation. |
| 03-capability-detectors-01 | Extended `Indicator` with optional structured detector fields (`evidence_locations`, `extracted_urls`, `extracted_commands`, `extracted_file_paths`). | Preserves backward compatibility while enabling machine-readable detector provenance. |

### Pending Todos

- Harden `scripts/demo_run.sh` auto-start behavior for first-run compile latency (or prebuild binary) to avoid startup timeout in verification flows.
- Decide whether to commit deterministic precompiled `.class` fixture bytes as fallback for environments without local JDK tooling.

### Blockers/Concerns

- `scripts/demo_run.sh` auto-start path remains sensitive to first-run compile timing; prebuilding with `cargo build` avoids timeout in verification flows.
- Demo fixture now compiles `DemoMod.class` when JDK tools are present, but fallback environments without `javac` still produce source-only jars.
- Java fixture compilation emits deprecation warnings from JDK tooling; non-blocking for scan behavior.

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 03-capability-detectors-01-PLAN.md
Resume file: .planning/phases/03-capability-detectors/03-capability-detectors-02-PLAN.md
