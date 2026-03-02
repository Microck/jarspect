---
phase: 01-bytecode-evidence-core
plan: 03
type: execute
wave: 3
depends_on:
  - 01-bytecode-evidence-core-02
files_modified:
  - demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
  - src/analysis/evidence.rs
  - src/analysis/classfile_evidence.rs
  - src/analysis/byte_array_strings.rs
autonomous: true

must_haves:
  truths:
    - "Strings built via new String(new byte[]{...}) appear as reconstructed string evidence"
    - "Reconstructed string evidence includes location metadata (class, method, pc offset when available)"
    - "Phase 1 bytecode evidence includes strings + invokes and is additive to existing scan output"
  artifacts:
    - path: "src/analysis/byte_array_strings.rs"
      provides: "Minimal byte-array -> String reconstructor for a narrow opcode pattern"
    - path: "demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java"
      provides: "Deterministic fixture containing new String(new byte[]{...}) pattern"
  key_links:
    - from: "src/analysis/classfile_evidence.rs"
      to: "src/analysis/byte_array_strings.rs"
      via: "reconstruct_byte_array_strings(opcodes)"
      pattern: "reconstruct"
---

<objective>
Implement narrow reconstruction of `new String(new byte[]{...})` strings from bytecode, and ensure the demo fixture contains that pattern for deterministic verification.

Purpose: Satisfy BYTE-03 in a controlled, explainable way without building a full bytecode interpreter.
Output: `result.bytecode_evidence.items` contains reconstructed_string evidence items for the demo jar.
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

@src/analysis/evidence.rs
@src/analysis/classfile_evidence.rs
@demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
@scripts/demo_run.sh
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add a deterministic demo pattern for new String(new byte[]{...})</name>
  <files>
demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
  </files>
  <action>
- Update `DemoMod.java` to include a never-invoked method that contains the exact pattern required by BYTE-03:
  - Example shape (keep it simple and compiler-friendly):
    - `return new String(new byte[] { 72, 101, 108, 108, 111 });` // "Hello"
  - Keep it inside the class so it compiles into bytecode in the demo jar.
- Do not change the runtime behavior of `main()`.
  </action>
  <verify>
bash demo/build_sample.sh
  </verify>
  <done>
- `demo/suspicious_sample.jar` is rebuilt successfully and contains updated compiled bytecode.
  </done>
</task>

<task type="auto">
  <name>Task 2: Reconstruct byte-array strings from bytecode and emit as evidence</name>
  <files>
src/analysis/byte_array_strings.rs
src/analysis/evidence.rs
src/analysis/classfile_evidence.rs
  </files>
  <action>
- Extend `BytecodeEvidenceItem` with `reconstructed_string { value: String, location: Location }` (additive only).
  - Preserve the Plan 01 serde contract: enum remains `#[serde(tag = "kind", rename_all = "snake_case")]`, and `Location.method` remains the struct representation.
  - Do not rename any existing `kind` values.
- Add `src/analysis/byte_array_strings.rs` implementing a minimal reconstructor over a single straight-line pattern:
  - Target pattern: `new String(new byte[]{ <immediate constants> })` compiled as:
    - create byte array (`newarray byte`), push index/byte constants, `bastore` (possibly with `dup`), then call `java/lang/String.<init>([B)V`.
  - Implement a tiny state machine / abstract interpreter limited to:
    - integer/byte constants (`iconst_*`, `bipush`, `sipush`), `newarray`, `dup`, `bastore`, and the `invokespecial` for `String.<init>([B)V`.
  - Reset state on unknown opcodes and on control-flow boundaries (jumps, returns, exception handlers); correctness over completeness.
- In `extract_bytecode_evidence()` when iterating a method's `(pc, opcode)` stream:
  - Feed opcodes into the reconstructor and collect reconstructed strings with their callsite `pc`.
  - Emit each as `reconstructed_string` evidence with `location.method` + `location.pc`.
  </action>
  <verify>
 cargo test
  bash scripts/demo_run.sh
  </verify>
  <done>
- Demo run succeeds.
- The scan JSON includes at least one `kind: "reconstructed_string"` item with `value` equal to the string embedded in `DemoMod.java` and a populated `location`.
  </done>
</task>

</tasks>

<verification>
- Run `bash scripts/demo_run.sh`.
- Confirm that `result.bytecode_evidence.items` includes:
  - at least one `cp_utf8` or `cp_string_literal`
  - at least one `invoke_resolved`
  - at least one `reconstructed_string`
</verification>

<success_criteria>
- Phase 1 success criteria are all demonstrably true via the demo runner:
  - bytecode strings present
  - resolved invoke* present
  - reconstructed new String(byte[]) present
  - endpoints unchanged and response changes additive only
</success_criteria>

<output>
After completion, create `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-03-SUMMARY.md`
</output>
