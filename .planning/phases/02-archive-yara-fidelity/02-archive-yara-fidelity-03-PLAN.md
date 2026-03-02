---
phase: 02-archive-yara-fidelity
plan: 03
type: execute
wave: 3
depends_on:
  - 02-archive-yara-fidelity-02
files_modified:
  - Cargo.toml
  - src/main.rs
  - src/analysis/mod.rs
  - src/analysis/metadata.rs
autonomous: true

must_haves:
  truths:
    - "Scan output includes parsed mod metadata + manifest signals and flags inconsistencies / suspicious attributes"
    - "Metadata indicators include enough evidence to trace to the exact jar layer and metadata file"
  artifacts:
    - path: "src/analysis/metadata.rs"
      provides: "Fabric/Forge/Spigot/Manifest parsing + integrity checks"
  key_links:
    - from: "src/main.rs"
      to: "src/analysis/metadata.rs"
      via: "analyze_metadata(entries) -> metadata findings"
      pattern: "metadata"
---

<objective>
Parse mod metadata and manifest signals (Fabric/Forge/Spigot + MANIFEST.MF), and emit explicit indicators when metadata is inconsistent or suspicious.

Purpose: Satisfy ARCH-02 so archive structure and mod identity signals are reflected in scan results with traceable evidence.
Output: `result.static.matches[]` includes `source=metadata` indicators with `file_path` pointing at the metadata entry path and evidence describing what was suspicious/inconsistent.
</objective>

<execution_context>
@/home/ubuntu/.config/opencode/get-shit-done/workflows/execute-plan.md
@/home/ubuntu/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/phases/02-archive-yara-fidelity/02-RESEARCH.md

@Cargo.toml
@src/main.rs
@src/analysis/archive.rs
@demo/build_sample.sh
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add metadata parsing module (Fabric/Forge/Spigot/Manifest) with jar-layer grouping</name>
  <files>
Cargo.toml
src/analysis/metadata.rs
src/analysis/mod.rs
  </files>
  <action>
- Add dependencies required by Phase 2 research:
  - `toml = "1"`
  - `yaml_serde = "0.10"`
- Create `src/analysis/metadata.rs` implementing metadata analysis over the flattened entry stream.
  - Input: `entries: &[crate::analysis::ArchiveEntry]`.
  - Group entries by jar layer using the `!/` delimiter in `ArchiveEntry.path`:
    - Define a helper that computes:
      - `jar_key`: the nested jar prefix (everything up to the last `.jar` layer), e.g. `root.jar` or `root.jar!/META-INF/jars/inner-demo.jar`.
      - `rel_path`: path within that jar layer.
    - Build a map `{jar_key -> Vec<(rel_path, entry)>}`.
  - For each jar layer, parse the following when present and emit findings only for suspicious/inconsistent cases:
    1) Fabric: `fabric.mod.json`
       - Parse with `serde_json`.
       - Validate `id` format and entrypoints.
       - Cross-check that `entrypoints.*` classes exist as `.class` entries within the SAME jar layer (dotted `a.b.C` -> `a/b/C.class`).
       - If `jars[]` exists, cross-check the referenced nested jar entry exists in the same layer.
    2) Forge: `META-INF/mods.toml`
       - Parse with `toml`.
       - Validate `[[mods]].modId` format.
    3) Spigot/Bukkit: `plugin.yml`
       - Parse with `yaml_serde`.
       - Validate required fields and cross-check `main` class exists.
    4) Manifest: `META-INF/MANIFEST.MF`
       - Parse as text and look for suspicious keys:
         `Premain-Class`, `Agent-Class`, `Can-Redefine-Classes`, `Can-Retransform-Classes`, `Boot-Class-Path`.
       - Emit a high-severity finding per suspicious key.
  - Output format:
    - Export `pub struct MetadataFinding { pub id: String, pub title: String, pub severity: String, pub file_path: String, pub evidence: String, pub rationale: String }`.
    - Use stable ids like:
      - `META-MANIFEST-PREMAIN`
      - `META-FABRIC-ENTRYPOINT-MISSING`
      - `META-FABRIC-NESTEDJAR-MISSING`
  - IMPORTANT: Treat missing/invalid metadata as `low|med` unless it is an agent/instrumentation manifest key (those are `high`).
- Update `src/analysis/mod.rs` to `pub mod metadata;` and re-export `metadata::analyze_metadata` (or similarly named) and `MetadataFinding`.
  </action>
  <verify>
cargo test
  </verify>
  <done>
- Code compiles with the new deps.
- `src/analysis/metadata.rs` can analyze entries and produce structured findings without panicking on malformed inputs.
  </done>
</task>

<task type="auto">
  <name>Task 2: Wire metadata findings into static analysis indicators with nested-provenance file paths</name>
  <files>
src/main.rs
  </files>
  <action>
- In `src/main.rs`, integrate metadata analysis into `run_static_analysis()`:
  - Call the metadata analyzer early (before patterns/signatures is fine).
  - Convert each `MetadataFinding` into an `Indicator`:
    - `source`: `"metadata"`
    - `category`: `"metadata"`
    - `severity`: from finding
    - `file_path`: `Some(finding.file_path.clone())` (MUST be the fully qualified nested path including `!/` when applicable)
    - `evidence` and `rationale`: from finding
- Ensure `counts_by_category` and `counts_by_severity` include metadata indicators.
- Verify the demo sample (from Plan 01) triggers at least one metadata finding:
  - The demo manifest includes `Premain-Class`, so `META-MANIFEST-PREMAIN` should appear.
  </action>
  <verify>
cargo test
bash scripts/demo_run.sh
  </verify>
  <done>
- Demo scan output contains at least one `source=metadata` indicator.
- That indicator has `file_path` ending in `META-INF/MANIFEST.MF` and includes the correct jar layer prefix (`root.jar!/` ...).
  </done>
</task>

</tasks>

<verification>
- Run `bash scripts/demo_run.sh`.
- Inspect the newest scan JSON and confirm:
  - at least one `result.static.matches[]` item has `source == "metadata"`.
  - the `file_path` shows the correct jar layer (outer or inner) and uses `!/` separators.
</verification>

<success_criteria>
- ARCH-02: Mod metadata + manifest signals are parsed and inconsistencies/suspicious attributes are reported as explicit findings with traceable evidence.
</success_criteria>

<output>
After completion, create `.planning/phases/02-archive-yara-fidelity/02-archive-yara-fidelity-03-SUMMARY.md`
</output>
