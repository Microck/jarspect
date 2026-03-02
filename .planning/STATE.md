# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.
**Current focus:** Phase 3 - Capability Detectors

## Current Position

Phase: 2 of 6 (Archive + YARA Fidelity)
Plan: 3 of 3 in current phase
Status: Phase complete
Last activity: 2026-03-02 - Completed 02-archive-yara-fidelity-03-PLAN.md

Progress: [████░░░░░░] 40%

## Performance Metrics

**Velocity:**
- Total plans completed: 6
- Average duration: 9.3 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-bytecode-evidence-core | 3 | 28 min | 9.3 min |
| 02-archive-yara-fidelity | 3 | 28 min | 9.3 min |

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

### Pending Todos

- Harden `scripts/demo_run.sh` auto-start behavior for first-run compile latency (or prebuild binary) to avoid startup timeout in verification flows.
- Decide whether to reintroduce deterministic `.class` fixture bytes in `demo/build_sample.sh` so bytecode evidence demos stay consistent without local JDK tooling.

### Blockers/Concerns

- `scripts/demo_run.sh` auto-start path remains sensitive to first-run compile timing; pre-starting the API with `JARSPECT_API_URL` still works reliably.
- Nested-jar demo attribution is now deterministic across build modes, but `.class` bytecode-specific demo evidence is still absent without a committed compiled fixture.
- Metadata demo scans may raise `META-FABRIC-ENTRYPOINT-MISSING` in zip-fallback builds when `DemoMod.class` is not present; this is expected until deterministic compiled fixtures are committed.

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 02-archive-yara-fidelity-03-PLAN.md
Resume file: .planning/phases/03-capability-detectors/03-capability-detectors-01-PLAN.md
