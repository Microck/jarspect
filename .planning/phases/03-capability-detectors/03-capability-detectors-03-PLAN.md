---
phase: 03-capability-detectors
plan: 03
type: execute
wave: 4
depends_on:
  - 02-archive-yara-fidelity-01
  - 03-capability-detectors-02
files_modified:
  - src/detectors/mod.rs
  - src/detectors/spec.rs
  - src/detectors/capability_deser.rs
  - src/detectors/capability_native.rs
  - src/detectors/capability_cred_theft.rs
  - demo/build_sample.sh
autonomous: true

must_haves:
  truths:
    - "Unsafe deserialization sinks are flagged as vulnerability-risk with callsite evidence"
    - "JNI/native loading is detected from both invoke evidence and archive entry signals (embedded native libs)"
    - "DETC-08 severity gates: token-only => low; token+file-read => med; token+file-read+network => high"
    - "Demo scan proves DETC-06/07/08 end-to-end against compiled bytecode (and DETC-07 carries embedded native entry evidence)"
  artifacts:
    - path: "src/detectors/capability_deser.rs"
      provides: "DETC-06 detector (ObjectInputStream.readObject)"
    - path: "src/detectors/capability_native.rs"
      provides: "DETC-07 detector (System.load/loadLibrary + embedded native files)"
    - path: "src/detectors/capability_cred_theft.rs"
      provides: "DETC-08 detector (token-only low; med/high require file-read/network correlation gates)"
  key_links:
    - from: "src/detectors/capability_native.rs"
      to: "src/analysis/archive.rs"
      via: "entries list for embedded native file extensions"
      pattern: '\\.(dll|so|dylib|jnilib)$'
---

<objective>
Finish DETC-06/07/08 with evidence-driven, explainable outputs and correlation-based FP controls.

Purpose: Complete Phase 3 detector coverage so the scan can reliably surface high-risk capabilities while separating malware-like behavior from vulnerability-risk signals.
Output: Detector indicators for unsafe deserialization, native loading, and credential/token theft, each with traceable evidence and conservative severity.
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
@src/analysis/archive.rs
</context>

<tasks>

<task type="auto">
  <name>Task 1: Implement DETC-06 (unsafe deserialization) and label as vulnerability-risk</name>
  <files>
src/detectors/capability_deser.rs
src/detectors/mod.rs
  </files>
  <action>
- Add `src/detectors/capability_deser.rs` implementing DETC-06.
- Evidence source: resolved invoke:
  - `("java/io/ObjectInputStream", "readObject")` (any descriptor)
- Output behavior:
  - Category: `"vulnerability"` (not a malware capability category).
  - Severity: `med` by default.
  - Never emit `high|critical` without additional context (Phase 3 does not infer exploitability).
- Register the detector in `src/detectors/mod.rs`.
- Add unit test ensuring:
  - A single `readObject` invoke yields one indicator with `severity == "med"` and callsite `Location.method` + `pc` present.
  </action>
  <verify>
cargo test
  </verify>
  <done>
- DETC-06 exists, is explainable, and is treated as vulnerability-risk (severity stays conservative).
  </done>
</task>

<task type="auto">
  <name>Task 2: Implement DETC-07 (native loading) and DETC-08 (credential/token theft) with correlation gates</name>
  <files>
 src/detectors/capability_native.rs
 src/detectors/capability_cred_theft.rs
 src/detectors/spec.rs
 src/detectors/mod.rs
 demo/build_sample.sh
  </files>
  <action>
- Ensure the compiled demo jar includes an embedded native entry so DETC-07 can be proven end-to-end:
  - Update `demo/build_sample.sh` so that after the jar is built it contains a dummy `.dll` entry (no execution).
  - Recommended implementation: create a small placeholder file and `jar uf` it into the output jar under a nested path like `native/dummy.dll`.
  - Verify locally during execution with: `jar tf demo/suspicious_sample.jar | grep -Ei '\.(dll|so|dylib|jnilib)$'`.

- Add `src/detectors/capability_native.rs` implementing DETC-07.
  - Evidence sources:
    - invokes: `("java/lang/System", "load")` and `("java/lang/System", "loadLibrary")`.
    - archive entry signals: any `entries[].path` ending with `.dll|.so|.dylib|.jnilib` (case-insensitive) across nested jars.
  - FP controls:
    - Base: `med` when System.load/loadLibrary is present.
    - Escalate to `high` only when an embedded native file is present OR when strings in the same class look like an absolute/temporary path (e.g. `/tmp/`, `C:\\Users\\`).
    - Never emit `critical`.
  - Extract `extracted_file_paths` with embedded native entry paths (use the fully qualified nested path string).
- Add `src/detectors/capability_cred_theft.rs` implementing DETC-08.
  - Sensitive token sources: bytecode-derived strings for:
    - Discord stores: `discord`, `Local Storage`, `leveldb`, `token`
    - Browser stores: `Login Data`, `Cookies`, `Local State`, `User Data`, `Default`
    - Minecraft/session: `.minecraft`, `launcher_profiles.json`, `accounts.json`, `session`
  - Correlators:
    - File read primitives (invokes):
      - `java/nio/file/Files.readAllBytes|newInputStream`
      - `java/io/FileInputStream.<init>`
    - Optional exfil correlator: network primitives from DETC-02 invoke list.
  - FP controls:
    - Token-only -> `low` indicator (always emit so the signal is observable).
    - Token + file read -> `med`.
    - Token + file read + network primitive -> `high`.
    - Never emit `critical`.
  - Extract `extracted_file_paths` using matched sensitive path tokens.
  - Extract `extracted_urls` by reusing `extract_urls()` over all strings (if present).
- Register both detectors in `src/detectors/mod.rs`.
- Add unit tests that prove:
  - Native load escalates only with embedded native file signal.
  - Cred theft escalates only with read + tokens (+ optional network).
  - For invoke-triggered cases, assert at least one emitted `evidence_locations[]` entry has `method` populated and `pc` set.
- Ensure the detectors continue to produce a SINGLE indicator per capability id with merged locations (dedup).
  </action>
  <verify>
 cargo test

 # Build compiled demo jar with embedded native entry + run scan.
 bash demo/build_sample.sh
 jar tf demo/suspicious_sample.jar | grep -Ei '\.(dll|so|dylib|jnilib)$'

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

 const requiredPrefixes = ["DETC-06", "DETC-07", "DETC-08"];
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

 const detc07 = detectorMatches.filter((m) => typeof m.id === "string" && m.id.startsWith("DETC-07"));
 const hasEmbeddedNativePath = detc07.some((m) => Array.isArray(m.extracted_file_paths) && m.extracted_file_paths.some((p) => typeof p === "string" && /\.(dll|so|dylib|jnilib)$/i.test(p)));
 if (!hasEmbeddedNativePath) {
   throw new Error("DETC-07: expected at least one extracted_file_paths entry ending with .dll/.so/.dylib/.jnilib");
 }

 console.log("detector assertions (DETC-06/07/08): ok");
 '
  </verify>
  <done>
- DETC-07 uses both invoke evidence and archive entry signals and carries extracted embedded-native paths when present.
- DETC-08 severity gates are consistent and test-enforced: token-only => `low`; `med/high` require file-read correlation (and `high` also requires a network primitive).
- DETC-06/07/08 exist end-to-end in `.local-data/scans/${scan_id}.json` as `source="detector"` matches with evidence locations that include at least one invoke callsite (`method` + `pc`).
  </done>
</task>

</tasks>

<verification>
- `cargo test` covers DETC-06/07/08 behavior and FP gates.
- `bash demo/build_sample.sh` + `bash scripts/demo_run.sh` + Node assertions prove `.local-data/scans/${scan_id}.json` contains `source="detector"` matches for DETC-06/07/08 with at least one invoke callsite location (`method` + `pc`), and DETC-07 includes at least one embedded native path.
</verification>

<success_criteria>
- DETC-01..DETC-08 are all implemented as bytecode-evidence consumers with structured, traceable callsite evidence.
- FP controls prevent single generic primitives from becoming CRITICAL.
</success_criteria>

<output>
After completion, create `.planning/phases/03-capability-detectors/03-capability-detectors-03-SUMMARY.md`
</output>
