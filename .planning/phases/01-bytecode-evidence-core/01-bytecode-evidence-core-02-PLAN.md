---
phase: 01-bytecode-evidence-core
plan: 02
type: execute
wave: 2
depends_on:
  - 01-bytecode-evidence-core-01
files_modified:
  - src/main.rs
  - src/analysis/evidence.rs
  - src/analysis/classfile_evidence.rs
autonomous: true

must_haves:
  truths:
    - "/scan responses include resolved invoke* evidence as (owner, name, descriptor)"
    - "Invoke evidence includes location metadata (entry path, class, method, pc offset when available)"
    - "Existing endpoints remain and the response shape changes are additive only"
  artifacts:
    - path: "src/analysis/evidence.rs"
      provides: "Invoke evidence variants (invoke + invokedynamic)"
    - path: "src/analysis/classfile_evidence.rs"
      provides: "Bytecode opcode walk emitting invoke evidence with pc"
  key_links:
    - from: "src/analysis/classfile_evidence.rs"
      to: "cafebabe::bytecode::Opcode"
      via: "match invoke opcodes"
      pattern: "Opcode::Invoke"
---

<objective>
Extend bytecode evidence to include resolved invoke* references with location metadata, using parsed bytecode opcodes (no string scanning).

Purpose: Satisfy BYTE-02 and EVID-01 for invoke callsites so Phase 3 detectors can consume a reliable invoke stream.
Output: `result.bytecode_evidence.items` contains invoke evidence items with owner/name/descriptor and method+pc.
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

@src/main.rs
@src/analysis/evidence.rs
@src/analysis/classfile_evidence.rs
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add invoke evidence variants to the schema</name>
  <files>
src/analysis/evidence.rs
  </files>
  <action>
- Extend `BytecodeEvidenceItem` with variants:
- Extend `BytecodeEvidenceItem` with variants (additive only):
  - `invoke_resolved { owner: String, name: String, descriptor: String, location: Location }`
  - `invoke_dynamic { name: String, descriptor: String, bootstrap_attr_index: u16, location: Location }`
- Treat the Plan 01 serde contract as an invariant:
  - `BytecodeEvidenceItem` MUST remain `#[serde(tag = "kind", rename_all = "snake_case")]` (tag field locked to `kind`).
  - Do not rename any existing variants.
  - Do not change `Location.method` representation; it remains `Option<LocationMethod { name, descriptor }>` (NOT a tuple).
  </action>
  <verify>
 cargo test
  </verify>
  <done>
- Schema compiles and serializes with the two new invoke variants.
- Backcompat tests from Plan 01 still pass, proving persisted scan JSON from Plan 01 remains deserializable after this schema extension.
  </done>
</task>

<task type="auto">
  <name>Task 2: Emit invoke evidence from cafebabe bytecode opcodes with pc offsets</name>
  <files>
src/analysis/classfile_evidence.rs
  </files>
  <action>
- In `extract_bytecode_evidence()`, for each parsed class method with a `Code` attribute containing parsed bytecode opcodes:
  - Iterate `(pc, opcode)` pairs.
  - For each of:
    - `invokevirtual`, `invokestatic`, `invokespecial`, `invokeinterface`
    emit `invoke_resolved` with:
    - `owner` = member.class_name
    - `name` and `descriptor` = member.name_and_type
    - `location.method` = `Some(LocationMethod { name: current_method_name, descriptor: current_method_descriptor })`
    - `location.pc` = `Some(pc)`
  - For `invokedynamic`, emit `invoke_dynamic` with name+descriptor and the bootstrap attribute index.
- Location rules:
  - Always set `entry_path` and `class_name`.
  - For invoke evidence, set `method` and `pc`.
- Do not attempt to force an owner for invokedynamic.
  </action>
  <verify>
  cargo test
  bash scripts/demo_run.sh
  </verify>
  <done>
- Demo run succeeds.
- The scan JSON includes at least one `kind: "invoke_resolved"` item with non-empty owner/name/descriptor and a `location.pc` value.
  </done>
</task>

</tasks>

<verification>
- Run `bash scripts/demo_run.sh`.
- Note: `scripts/demo_run.sh` exercises `/upload` before `/scan`.
- Confirm the scan payload includes `result.bytecode_evidence.items` entries with `kind: invoke_resolved` and `location.method` + `location.pc`.
</verification>

<success_criteria>
- BYTE-02 satisfied: invoke* instructions are represented as (owner, name, descriptor) with location metadata.
- Changes remain additive; existing endpoints and fields are unchanged.
</success_criteria>

<output>
After completion, create `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-02-SUMMARY.md`
</output>
