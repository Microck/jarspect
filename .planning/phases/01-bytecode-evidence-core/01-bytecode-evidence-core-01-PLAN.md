---
phase: 01-bytecode-evidence-core
plan: 01
type: execute
wave: 1
depends_on: []
files_modified:
  - Cargo.toml
  - src/main.rs
  - src/analysis/mod.rs
  - src/analysis/evidence.rs
  - src/analysis/classfile_evidence.rs
autonomous: true

must_haves:
  truths:
    - "/scan responses include bytecode-derived string evidence extracted from .class files"
    - "Bytecode evidence includes location metadata (entry path + class name at minimum)"
    - "Existing endpoints remain and the response shape changes are additive only"
  artifacts:
    - path: "src/analysis/evidence.rs"
      provides: "Serializable bytecode evidence schema (Location + evidence enum)"
    - path: "src/analysis/classfile_evidence.rs"
      provides: "Classfile parsing and constant-pool string extraction"
    - path: "src/main.rs"
      provides: "scan handler includes bytecode_evidence field in ScanResult"
  key_links:
    - from: "src/main.rs"
      to: "src/analysis/classfile_evidence.rs"
      via: "extract_bytecode_evidence(&entries)"
      pattern: "extract_bytecode_evidence"
    - from: "src/analysis/classfile_evidence.rs"
      to: "cafebabe"
      via: "parse_class_with_options"
      pattern: "parse_class"
---

<objective>
Add a stable bytecode evidence schema and emit constant-pool string evidence from .class files as an additive field in the existing /scan response.

Purpose: Satisfy BYTE-01 and EVID-01 foundations without changing existing endpoints or breaking persisted scans.
Output: A new `result.bytecode_evidence` field containing cp-derived string evidence with location metadata.
</objective>

<execution_context>
@/home/ubuntu/.config/opencode/get-shit-done/workflows/execute-plan.md
@/home/ubuntu/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/01-bytecode-evidence-core/01-RESEARCH.md

@Cargo.toml
@src/main.rs
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add bytecode evidence schema + classfile string extractor</name>
  <files>
Cargo.toml
src/analysis/mod.rs
src/analysis/evidence.rs
src/analysis/classfile_evidence.rs
  </files>
  <action>
- Add dependencies per Phase 1 research: `cafebabe = "0.9.0"`, `cesu8 = "1.1.0"`.
- Add dependencies per Phase 1 research: `cafebabe = "0.9.0"`, `cesu8 = "1.1.0"`.
- Create `src/analysis/evidence.rs` defining a JSON-serializable schema and treat its serde JSON shape as a persisted compatibility contract (scans are stored as JSON under `.local-data/scans/*.json`). Pin these invariants explicitly:
  - `BytecodeEvidenceItem` MUST be `#[serde(tag = "kind", rename_all = "snake_case")]`.
    - The tag field name is locked to `kind` (do not change to `tag`, `type`, etc in later plans).
    - Variant names are snake_case. Prefer explicitly pinning variant names with `#[serde(rename = "...")]` on each variant to avoid accidental rename drift.
  - `Location` uses a stable, named-field representation:
    - `Location { entry_path: String, class_name: String, method: Option<LocationMethod>, pc: Option<u32> }`.
    - `Location.method` MUST be a struct (NOT a tuple) to prevent positional JSON drift:
      - `LocationMethod { name: String, descriptor: String }`.
  - Add a small unit test in `src/analysis/evidence.rs` that locks the JSON shape (both serialize + deserialize) for:
    - one `BytecodeEvidenceItem::cp_utf8` value (must use `kind`, not an externally-tagged enum shape)
    - one `Location` value with `method` populated (must be an object with `name` + `descriptor`, not a 2-tuple array)
  - `BytecodeEvidence { items: Vec<BytecodeEvidenceItem> }`.
  - Initial variants (do not remove/rename later):
    - `cp_utf8 { value, location }`
    - `cp_string_literal { value, location }`
- Create `src/analysis/classfile_evidence.rs` exposing `pub fn extract_bytecode_evidence(entries: &[ArchiveEntry]) -> BytecodeEvidence`.
  - Iterate only entries whose `path.ends_with(".class")`.
  - Parse class bytes using `cafebabe` with bytecode parsing enabled (even if Plan 01 only emits strings).
  - Extract constant-pool strings:
    - Emit ALL `CONSTANT_Utf8` payloads as `cp_utf8` evidence.
    - Emit ALL `CONSTANT_String` literals as `cp_string_literal` evidence.
  - Ensure decoding is NOT `from_utf8_lossy` over raw class bytes; prefer `cafebabe`'s parsed values and/or decode raw CP bytes via `cesu8` when needed.
  - Set `location.entry_path` to the jar entry path, `location.class_name` to the internal class name (`a/b/C`). Leave `method` and `pc` as `None` for CP items.
- Create `src/analysis/mod.rs` and re-export the extractor + schema.
  </action>
  <verify>
 cargo test
  </verify>
  <done>
- Code compiles with new dependencies and modules.
- Serde JSON shape for `BytecodeEvidenceItem` and `Location.method` is pinned by unit tests (tag field name, rename rules, and method representation).
  </done>
</task>

<task type="auto">
  <name>Task 2: Wire bytecode_evidence into /scan results (additive + backwards compatible)</name>
  <files>
src/main.rs
  </files>
  <action>
- Update `ScanResult` to include an additive field:
  - `bytecode_evidence: Option<analysis::BytecodeEvidence>`
  - Annotate with `#[serde(default, skip_serializing_if = "Option::is_none")]` so older persisted scans still deserialize.
- In `scan()` handler, after `entries` are loaded, compute `let bytecode_evidence = Some(analysis::extract_bytecode_evidence(&entries));` and attach to `ScanResult`.
- Do not remove or change existing fields (`intake`, `static`, `behavior`, `reputation`, `verdict`).
- Add backcompat deserialization tests in `src/main.rs` covering BOTH persisted shapes:
  - New shape: deserializes a representative persisted scan JSON payload containing `result.bytecode_evidence`.
  - Old shape: deserializes a representative persisted scan JSON payload that omits `result.bytecode_evidence` entirely, and assert the parsed `ScanResult.bytecode_evidence == None`.
  - The JSON MUST use `kind` for bytecode evidence items.
  - It MUST include a `Location` with `method: {"name":..., "descriptor":...}` (object form) to lock the method representation.
  - Assert `serde_json::from_str::<ScanRunResponse>(...)` succeeds for both payloads.
  </action>
  <verify>
  cargo test
  bash scripts/demo_run.sh
  # Note: scripts/demo_run.sh performs `GET /scans/{scan_id}` after `POST /scan` and exits non-zero on scan_id mismatch.
  </verify>
  <done>
- `bash scripts/demo_run.sh` succeeds.
- `POST /scan` response includes `result.bytecode_evidence.items` and contains cp-derived string evidence with entry_path + class_name.
- `GET /scans/{scan_id}` still works: `scripts/demo_run.sh` performs the GET and fails if the fetched `scan_id` does not match the POST response.
- `result.bytecode_evidence.items` is non-empty for the demo jar (jar contains `.class` files).
  </done>
</task>

</tasks>

<verification>
- Run `bash scripts/demo_run.sh` and confirm the returned JSON has `result.bytecode_evidence.items`.
- Note: `scripts/demo_run.sh` exercises `/upload` (multipart) before `/scan`, so it also demonstrates endpoint preservation for `/upload`.
- Note: `scripts/demo_run.sh` also performs `GET /scans/{scan_id}` and exits non-zero if the fetched `scan_id` mismatches.
- Spot-check one evidence item: it includes `location.entry_path` and `location.class_name`.
</verification>

<success_criteria>
- BYTE-01 foundation: constant-pool string evidence exists in scan output with location metadata.
- API-01 honored: endpoints unchanged; response changes additive only.
</success_criteria>

<output>
After completion, create `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-01-SUMMARY.md`
</output>
