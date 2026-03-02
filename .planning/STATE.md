# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-03-02)

**Core value:** Upload a `.jar`, get a risk verdict with explainable indicators before you install.
**Current focus:** Phase 6 - Regression Fixtures

## Current Position

Phase: 5 of 6 (UI Verdict Rendering)
Plan: 1 of 1 in current phase
Status: Phase complete
Last activity: 2026-03-02 - Completed 05-ui-verdict-rendering-01-PLAN.md

Progress: [█████████░] 87%

## Performance Metrics

**Velocity:**
- Total plans completed: 13
- Average duration: 9.3 min

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 01-bytecode-evidence-core | 3 | 28 min | 9.3 min |
| 02-archive-yara-fidelity | 3 | 28 min | 9.3 min |
| 03-capability-detectors | 3 | 30 min | 10.0 min |
| 04-scoring-behavior-prediction | 3 | 31 min | 10.3 min |
| 05-ui-verdict-rendering | 1 | 4 min | 4.0 min |

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
| 03-capability-detectors-02 | Kept DETC-04 escalation conservative: zip/jar primitives baseline at `med`, generic writes remain `low`, and escalation to `high` requires same-class traversal or `.jar` markers. | Prevents common write primitives from over-escalating while still highlighting suspicious archive rewrite behavior. |
| 03-capability-detectors-02 | Implemented DETC-05 as token-first detection with same-class exec/write correlators and explicit high gate requiring concrete path/key markers. | Ensures persistence tokens remain reportable without inflating severity unless corroborated by stronger behavior signals. |
| 03-capability-detectors-02 | Reused case-insensitive token extraction helper to keep enrichment output deterministic and deduplicated across detector modules. | Preserves explainable, machine-stable extracted evidence for downstream scoring and behavior prediction. |
| 03-capability-detectors-03 | Classified DETC-06 as `category=vulnerability` with fixed `med` severity. | Keeps unsafe deserialization signal as vulnerability-risk without overstating exploitability from static evidence alone. |
| 03-capability-detectors-03 | Escalated DETC-07 to `high` only with native-load invoke plus embedded native entry or suspicious path markers. | Maintains conservative defaults while still surfacing stronger JNI/native loading risk when corroborated by archive/string evidence. |
| 03-capability-detectors-03 | Implemented DETC-08 with strict same-class correlation gates (`token-only=low`, `token+read=med`, `token+read+network=high`). | Preserves observability for token markers while reducing false positives from standalone strings or unrelated network usage. |
| 04-scoring-behavior-prediction-01 | Normalized detector IDs and freeform categories into canonical scoring buckets, including `obfuscation -> dynamic_loading`. | Enables source-agnostic dedup and stable scoring across detector/pattern/signature evidence. |
| 04-scoring-behavior-prediction-01 | Applied integer post-cap category allocation and reused post-cap points in `Top contributors` lines. | Keeps explanation math exactly aligned with score computation and deterministic under ties/caps. |
| 04-scoring-behavior-prediction-01 | Capped reputation adjustment at +19 and kept CLEAN gated on zero deduped static indicators plus zero reputation points. | Prevents reputation-only escalation to HIGH/CRITICAL while preserving explicit CLEAN semantics. |
| 04-scoring-behavior-prediction-02 | Normalized behavior URLs with `url::Url` into `scheme://host[:port]/path`, ignoring unparsable values. | Keeps derived network observables deterministic and deduplicable for BEHV-01 outputs. |
| 04-scoring-behavior-prediction-02 | Pinned prediction confidence constants to `0.9`/`0.8`/`0.6` and empty-observable confidence to exact `0.0`. | Makes BEHV-02 behavior explainable and testable with exact-value assertions. |
| 04-scoring-behavior-prediction-02 | Registered `mod behavior;` in crate root during execution. | Ensures `src/behavior.rs` unit tests compile and run before full `/scan` wiring in Plan 04-03. |
| 04-scoring-behavior-prediction-03 | Mapped `behavior::derive_behavior(...)` directly into API `BehaviorPrediction` fields and set `behavior.indicators` explicitly empty. | Replaces synthetic placeholder behavior indicators with evidence-derived outputs while keeping behavior non-scoring. |
| 04-scoring-behavior-prediction-03 | Refactored `build_verdict(...)` to accept only static indicators plus optional reputation and delegate scoring to `score_static_indicators(...)`. | Structurally prevents behavior->score feedback and aligns verdict math/explanations with the shared scoring engine. |
| 04-scoring-behavior-prediction-03 | Added serde-default additive fields `predicted_commands` and `predictions` to `BehaviorPrediction`. | Preserves backward-compatible scan JSON deserialization while exposing BEHV-02 structured prediction data. |
| 05-ui-verdict-rendering-01 | Normalized UI tier tokens before applying `data-tier` and rendering headlines. | Keeps verdict theming stable for mixed-case/backend variant tiers and prevents CSS token mismatch. |
| 05-ui-verdict-rendering-01 | Rendered CLEAN headline as `CLEAN · score/100` while preserving explicit UNKNOWN risk wording. | Removes contradictory "CLEAN risk" wording without changing non-CLEAN semantics. |
| 05-ui-verdict-rendering-01 | Canonicalized indicator severity display labels from normalized tokens (`med` -> `MEDIUM`) while keeping normalized `data-sev`. | Ensures styling and visible severity text stay consistent even with backend shorthand values. |

### Pending Todos

- Harden `scripts/demo_run.sh` auto-start behavior for first-run compile latency (or prebuild binary) to avoid startup timeout in verification flows.
- Decide whether to commit deterministic precompiled `.class` fixture bytes as fallback for environments without local JDK tooling.

### Blockers/Concerns

- `scripts/demo_run.sh` auto-start path remains sensitive to first-run compile timing; prebuilding with `cargo build` avoids timeout in verification flows.
- Demo fixture now compiles `DemoMod.class` when JDK tools are present, but fallback environments without `javac` still produce source-only jars.
- Java fixture compilation emits deprecation warnings from JDK tooling; non-blocking for scan behavior.
- Local verification environments may have occupied bind ports (`127.0.0.1:18000/18001`); prefer explicit `JARSPECT_BIND` or reuse active local instance for UI/browser checks.

## Session Continuity

Last session: 2026-03-02
Stopped at: Completed 05-ui-verdict-rendering-01-PLAN.md
Resume file: .planning/phases/06-regression-fixtures/06-regression-fixtures-01-PLAN.md
