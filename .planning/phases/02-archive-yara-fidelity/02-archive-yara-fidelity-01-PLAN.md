---
phase: 02-archive-yara-fidelity
plan: 01
type: execute
wave: 1
depends_on:
  - 01-bytecode-evidence-core-03
files_modified:
  - src/main.rs
  - src/analysis/mod.rs
  - src/analysis/archive.rs
  - demo/build_sample.sh
autonomous: true

must_haves:
  truths:
    - "Scanning a jar with an embedded jar produces findings attributed to nested paths (e.g. contains '!/')"
    - "Archive traversal is recursive with explicit safety limits (depth/entry-count/bytes)"
  artifacts:
    - path: "src/analysis/archive.rs"
      provides: "Recursive JAR traversal producing a flattened entry stream with stable nested paths"
    - path: "demo/build_sample.sh"
      provides: "Demo jar includes a deterministic embedded jar for verification"
  key_links:
    - from: "src/main.rs"
      to: "src/analysis/archive.rs"
      via: "read_archive_entries_recursive(root_label, bytes)"
      pattern: "read_archive_entries_recursive"
---

<objective>
Add a safe, recursive JAR reader that emits a flattened stream of inflated entries with stable nested paths, and update the demo fixture so nested-jar scanning is verifiable.

Purpose: Satisfy ARCH-01 foundation so YARA and bytecode evidence can attribute findings to the correct nested entry path.
Output: `ArchiveEntry` list includes nested paths like `...jar!/inner.jar!/path` and scan output contains at least one finding whose `file_path` includes `!/`.
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

@src/main.rs
@src/analysis/mod.rs
@src/analysis/evidence.rs
@src/analysis/classfile_evidence.rs
@demo/build_sample.sh
@scripts/demo_run.sh
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement recursive archive traversal with nested-path rendering + safety limits</name>
  <files>
src/analysis/archive.rs
src/analysis/mod.rs
src/main.rs
  </files>
  <action>
- Create `src/analysis/archive.rs` implementing a flattened recursive archive reader:
  - Public API:
    - `pub struct ArchiveEntry { pub path: String, pub bytes: Vec<u8>, pub text: Option<String> }`
      - `path` MUST be the fully qualified nested path string using `!/` between archive layers.
      - `text` is optional and is only populated for entries below a small threshold (ex: <= 256 KiB) to keep lossy text scanning from becoming a zip-bomb vector.
    - `pub fn read_archive_entries_recursive(root_label: &str, jar_bytes: &[u8]) -> anyhow::Result<Vec<ArchiveEntry>>`
  - Nested path rules:
    - Render outer entries as: `{root_label}!/{entry_path}`.
    - Render inner entries as: `{root_label}!/{outer_entry_path}!/{inner_entry_path}`.
    - Use `!/` exactly (not `::`, `>`, `:`) so evidence strings are stable and grep-able.
  - Recursion rules:
    - Treat an entry as an embedded jar if:
      - `entry_path.to_ascii_lowercase().ends_with(".jar")` AND
      - bytes start with ZIP magic `PK\x03\x04`.
    - Recurse into embedded jars up to a hard limit (recommended defaults):
      - max depth: 3
      - max total entries across recursion: 50_000
      - max per-entry uncompressed size: 16 MiB
      - max total inflated bytes: 256 MiB
      - compression ratio guard using `ZipFile::compressed_size()` + `ZipFile::size()`; if ratio is extreme, skip entry and record a debug log.
  - IMPORTANT: enforce the above limits BEFORE reading the entry into memory.
- Update `src/analysis/mod.rs` to `pub mod archive;` and re-export the entry type + reader:
  - `pub use archive::{ArchiveEntry, read_archive_entries_recursive};`
  - Keep Phase 1 exports intact.
- Update `src/main.rs` scan pipeline to call the new reader:
  - Replace `read_archive_entries(&bytes)?` with `analysis::read_archive_entries_recursive(&format!("{}.jar", request.upload_id), &bytes)?`.
  - Remove or leave the old `read_archive_entries` function, but ensure the code path used by `/scan` is the new recursive one.
  - Update `run_static_analysis()` signature (and callers) to accept the new `analysis::ArchiveEntry` (or `analysis::archive::ArchiveEntry`) and handle `text: Option<String>`:
    - For pattern/signature matching that currently uses `entry.text`, use `entry.text.as_deref().unwrap_or("")`.
  </action>
  <verify>
cargo test
bash scripts/demo_run.sh
  </verify>
  <done>
- `/scan` uses the recursive entry reader and does not read archive entries without enforcing size/ratio budgets.
- `ArchiveEntry.path` uses `!/` separators and includes nested jar layers when present.
- Demo scan completes successfully after code changes.
  </done>
</task>

<task type="auto">
  <name>Task 2: Update demo sample jar to include an embedded jar and a declared Fabric nested-jar reference</name>
  <files>
demo/build_sample.sh
  </files>
  <action>
- Modify `demo/build_sample.sh` so the built `demo/suspicious_sample.jar` always contains:
  1) An embedded jar at `META-INF/jars/inner-demo.jar` (any name is fine, keep deterministic).
     - Build the inner jar as a tiny zip/jar containing a single small file like `payload.txt` with a string that will trigger an existing signature mechanism (YARA or token signatures). Recommended payload string: `c2.jarspect.example.invalid` (matches existing demo YARA rule `synthetic_c2_domain`).
  2) A `fabric.mod.json` in the outer jar that declares the embedded jar via the `jars[]` array:
     - `{"schemaVersion":1,"id":"jarspect-demo","version":"1.0.0","entrypoints":{"main":["com.jarspect.demo.DemoMod"]},"jars":[{"file":"META-INF/jars/inner-demo.jar"}]}`
     - Keep JSON minimal and valid.
  3) A deterministic `META-INF/MANIFEST.MF` in the outer jar containing at least one suspicious manifest attribute to support Phase 2 metadata checks later:
     - Include `Premain-Class: com.jarspect.demo.DemoMod` (safe; does not execute).
- Ensure both code paths (javac+jar present, and fallback zip-based) embed the same files in the same locations.
  </action>
  <verify>
bash demo/build_sample.sh
bash scripts/demo_run.sh
  </verify>
  <done>
- Built demo jar contains `META-INF/jars/inner-demo.jar`.
- A scan over the demo jar produces at least one indicator with `file_path` containing `!/META-INF/jars/inner-demo.jar!/` (nested evidence attribution).
  </done>
</task>

</tasks>

<verification>
- Run `bash scripts/demo_run.sh`.
- After the run, inspect the newest scan JSON under `.local-data/scans/` and confirm at least one `result.verdict.indicators[].file_path` contains `!/`.
</verification>

<success_criteria>
- ARCH-01: The scanner recursively inflates and scans embedded jars within strict budgets, and findings can attribute nested provenance via `!/` paths.
</success_criteria>

<output>
After completion, create `.planning/phases/02-archive-yara-fidelity/02-archive-yara-fidelity-01-SUMMARY.md`
</output>
