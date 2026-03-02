---
phase: 03-capability-detectors
plan: 02
type: execute
wave: 3
depends_on:
  - 03-capability-detectors-01
files_modified:
  - src/detectors/mod.rs
  - src/detectors/spec.rs
  - src/detectors/capability_fs_modify.rs
  - src/detectors/capability_persistence.rs
autonomous: true

must_haves:
  truths:
    - "Scan flags jar/filesystem modification primitives with bytecode callsite evidence"
    - "Scan flags persistence indicators only when correlated with exec or file-write primitives (FP controls)"
    - "Demo scan proves DETC-04/05 end-to-end against compiled bytecode (source=detector matches exist with evidence_locations)"
  artifacts:
    - path: "src/detectors/capability_fs_modify.rs"
      provides: "DETC-04 detector (zip/jar output + file writes)"
    - path: "src/detectors/capability_persistence.rs"
      provides: "DETC-05 detector (persistence tokens correlated with exec/write primitives)"
  key_links:
    - from: "src/detectors/capability_persistence.rs"
      to: "src/detectors/index.rs"
      via: "strings_in_class correlation"
      pattern: "strings_in_class"
---

<objective>
Implement DETC-04 and DETC-05 with correlation-based FP controls so common mod patterns don't automatically become high severity.

Purpose: Expand capability coverage to filesystem/jar modification and persistence while keeping signals usable and explainable.
Output: New `source="detector"` indicators for DETC-04/05, deduped and carrying evidence locations + extracted file/path tokens when present.
</objective>

<execution_context>
@/home/ubuntu/.config/opencode/get-shit-done/workflows/execute-plan.md
@/home/ubuntu/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/REQUIREMENTS.md
@.planning/phases/03-capability-detectors/03-RESEARCH.md

@src/detectors/index.rs
@src/detectors/spec.rs
@src/detectors/mod.rs
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement DETC-04 (jar/filesystem modification) with enrichment-only escalation</name>
  <files>
src/detectors/capability_fs_modify.rs
src/detectors/spec.rs
src/detectors/mod.rs
  </files>
  <action>
- Add `src/detectors/capability_fs_modify.rs` implementing DETC-04.
- Evidence sources (bytecode invokes):
  - File writes:
    - `java/io/FileOutputStream.<init>` and `write`
    - `java/nio/file/Files.write|newOutputStream|move|copy|delete`
  - Jar/zip rewriting:
    - `java/util/zip/ZipOutputStream.putNextEntry|write|closeEntry`
    - `java/util/jar/JarOutputStream.<init>`
- Extract file/path enrichment from correlated strings in the SAME class (use `strings_in_class(entry_path, class_name)`; do not use global strings across the jar):
  - traversal markers: `../`, `..\\`
  - write targets like `.jar`, `mods/`, `META-INF/`, `.service`
- FP controls:
  - Base severity: `med` when jar/zip output primitives are present.
  - If only generic file writes exist (FileOutputStream / Files.write) without zip/jar primitives: severity `low`.
- Escalate to `high` only when enrichment suggests jar rewriting or traversal within the same class (zip/jar primitive + correlated `.jar` or traversal marker tokens).
  - Never emit `critical` here.
- Register the detector in `src/detectors/mod.rs`.
- Add unit tests (no mocks) constructing `BytecodeEvidence`:
  - `ZipOutputStream.putNextEntry` alone -> `med`.
  - `ZipOutputStream.putNextEntry` + string containing `"../"` or `".jar"` -> `high`.
  - `FileOutputStream.write` alone -> `low`.
  - For invoke-triggered cases, assert at least one emitted `evidence_locations[]` entry has `method` populated and `pc` set.
  </action>
  <verify>
cargo test
  </verify>
  <done>
- DETC-04 emits a single deduped indicator with merged locations and optional extracted file/path tokens.
- Tests demonstrate severity modulation and avoid critical escalation for generic primitives.
  </done>
</task>

<task type="auto">
  <name>Task 2: Implement DETC-05 (persistence) as correlation over tokens + exec/write primitives</name>
  <files>
src/detectors/capability_persistence.rs
src/detectors/mod.rs
  </files>
  <action>
- Add `src/detectors/capability_persistence.rs` implementing DETC-05.
- Evidence sources:
- Persistence tokens from bytecode-derived strings (cp + reconstructed) correlated to the same class as the correlators (use `strings_in_class(entry_path, class_name)`, not global strings):
    - Windows Run key fragments: `Software\\Microsoft\\Windows\\CurrentVersion\\Run` (and HKCU/HKLM prefixes)
    - scheduler: `schtasks`
    - cron: `crontab`, `/etc/cron`, `cron.d`
    - systemd: `/etc/systemd/system`, `systemctl`, `.service`
  - Correlators:
    - DETC-01 exec primitives (Runtime.exec / ProcessBuilder.start) via invokes index.
    - DETC-04 write primitives (Files.write / FileOutputStream / ZipOutputStream) via invokes index.
- FP controls (required):
  - Do NOT emit `high` severity for tokens alone.
  - Emit `low` when persistence tokens exist without correlators (still report, but low).
  - Emit `med` when tokens + (exec OR write) exist in the same class.
  - Emit `high` only when tokens + exec primitive exist (stronger signal) AND at least one token is a concrete path/key (e.g. full Run key fragment or `/etc/systemd/system`).
  - Never emit `critical`.
- Extract `extracted_file_paths` by collecting matching persistence path tokens; extract `extracted_commands` if `schtasks` or `systemctl` present.
- Register the detector in `src/detectors/mod.rs`.
- Add unit tests proving the correlation gates:
  - token-only -> `low`.
  - token + write -> `med`.
  - token + exec -> `high`.
  - For invoke-triggered cases, assert at least one emitted `evidence_locations[]` entry has `method` populated and `pc` set.
  </action>
  <verify>
 cargo test

 # Run demo scan + assert DETC-04/05 exist end-to-end against compiled bytecode.
 bash scripts/demo_run.sh | tee .local-data/demo-run.out
 SCAN_ID="$(node -e 'const fs = require("fs"); const out = fs.readFileSync(".local-data/demo-run.out", "utf8"); const m = out.match(/scan_id:\s*([a-f0-9]{32})/i); if (!m) { console.error("scan_id not found in demo output"); process.exit(1); } process.stdout.write(m[1]);')"

 SCAN_ID="${SCAN_ID}" node -e '
 const fs = require("fs");
 const scanId = process.env.SCAN_ID;
 if (!scanId) {
   console.error("SCAN_ID env var missing");
   process.exit(1);
 }

 const scanPath = `.local-data/scans/${scanId}.json`;
 const payload = JSON.parse(fs.readFileSync(scanPath, "utf8"));
 const matches = (payload && payload.result && payload.result.static && Array.isArray(payload.result.static.matches))
   ? payload.result.static.matches
   : [];

 const detectorMatches = matches.filter((m) => m && m.source === "detector");
 if (!detectorMatches.length) {
   throw new Error("expected at least one source=detector match in result.static.matches");
 }

 const requiredPrefixes = ["DETC-04", "DETC-05"];
 for (const prefix of requiredPrefixes) {
   const byPrefix = detectorMatches.filter((m) => typeof m.id === "string" && m.id.startsWith(prefix));
   if (!byPrefix.length) {
     throw new Error(`missing detector match for prefix ${prefix}`);
   }

    for (const m of byPrefix) {
      const locs = m.evidence_locations;
      if (!Array.isArray(locs) || !locs.length) {
        throw new Error(`${m.id}: expected non-empty evidence_locations`);
      }

      const hasCallsite = locs.some((l) => l && l.method && typeof l.method.name === "string" && typeof l.method.descriptor === "string" && typeof l.pc === "number");
      if (!hasCallsite) {
        throw new Error(`${m.id}: expected at least one callsite location with method+pc`);
      }
    }
 }

 console.log("detector assertions (DETC-04/05): ok");
 '
  </verify>
  <done>
- DETC-05 only escalates severity when correlation is present; tests cover gates.
- DETC-04 and DETC-05 exist end-to-end in `.local-data/scans/${scan_id}.json` as `source="detector"` matches with evidence locations that include at least one invoke callsite (`method` + `pc`).
  </done>
</task>

</tasks>

<verification>
- `cargo test` proves DETC-04/05 FP controls and location wiring.
- `bash scripts/demo_run.sh` + Node assertions prove `.local-data/scans/${scan_id}.json` contains `source="detector"` matches for DETC-04 and DETC-05 with at least one invoke callsite location (`method` + `pc`).
</verification>

<success_criteria>
- DETC-04/05 are implemented with evidence sources explicitly tied to invoke evidence + bytecode strings.
- Persistence does not become high severity based on tokens alone.
</success_criteria>

<output>
After completion, create `.planning/phases/03-capability-detectors/03-capability-detectors-02-SUMMARY.md`
</output>
