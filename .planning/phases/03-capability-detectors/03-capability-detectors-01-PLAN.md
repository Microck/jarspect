---
phase: 03-capability-detectors
plan: 01
type: execute
wave: 2
depends_on:
  - 01-bytecode-evidence-core-01
  - 01-bytecode-evidence-core-02
  - 01-bytecode-evidence-core-03
  - 02-archive-yara-fidelity-01
files_modified:
  - src/main.rs
  - src/detectors/mod.rs
  - src/detectors/index.rs
  - src/detectors/spec.rs
  - src/detectors/capability_exec.rs
  - src/detectors/capability_network.rs
  - src/detectors/capability_dynamic_load.rs
  - demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
autonomous: true

must_haves:
  truths:
    - "Scan emits detector-sourced capability indicators with callsite locations derived from bytecode evidence"
    - "Execution/network/dynamic-loading primitives are detected from resolved invoke evidence (not lossy string scanning)"
    - "Detectors apply false-positive controls (severity modulation + correlation) and do not mark single primitives as CRITICAL"
    - "Demo scan proves DETC-01..03 against compiled bytecode (detector matches exist and carry method+pc evidence_locations)"
  artifacts:
    - path: "src/detectors/index.rs"
      provides: "EvidenceIndex over Phase 1 bytecode evidence (invokes + strings)"
    - path: "src/detectors/capability_exec.rs"
      provides: "DETC-01 detector with command-string correlation"
    - path: "src/detectors/capability_network.rs"
      provides: "DETC-02 detector with URL enrichment"
    - path: "src/detectors/capability_dynamic_load.rs"
      provides: "DETC-03 detector with reflection/string correlation"
    - path: "demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java"
      provides: "Compiled demo jar bytecode contains invoke primitives/strings for DETC-01..08 (later plans assert end-to-end)"
  key_links:
    - from: "src/main.rs"
      to: "src/detectors/mod.rs"
      via: "run_capability_detectors(bytecode_evidence, entries)"
      pattern: "run_capability_detectors"
    - from: "src/detectors/index.rs"
      to: "src/analysis/evidence.rs"
      via: "BytecodeEvidence + Location"
      pattern: "BytecodeEvidence"
---

<objective>
Add a detector framework (EvidenceIndex + detector outputs) and implement DETC-01/02/03 using Phase 1 bytecode evidence with FP controls and traceable callsite locations.

Purpose: Establish the capability-detector layer on top of bytecode-derived evidence so higher-level behaviors can be detected reliably and explained.
Output: New `source="detector"` indicators in `result.static.matches[]` for execution, networking, and dynamic loading, each carrying callsite `Location` evidence.
</objective>

<execution_context>
@/home/ubuntu/.config/opencode/get-shit-done/workflows/execute-plan.md
@/home/ubuntu/.config/opencode/get-shit-done/templates/summary.md
</execution_context>

<context>
@.planning/PROJECT.md
@.planning/ROADMAP.md
@.planning/STATE.md
@.planning/REQUIREMENTS.md
@.planning/phases/03-capability-detectors/03-RESEARCH.md

@src/main.rs
@src/analysis/evidence.rs
</context>

<tasks>

<task type="auto">
  <name>Task 1: Create EvidenceIndex + detector plumbing (pure functions + unit-testable)</name>
  <files>
src/detectors/mod.rs
src/detectors/index.rs
src/detectors/spec.rs
  </files>
  <action>
- Create `src/detectors/index.rs` implementing an index over Phase 1 bytecode evidence:
  - Input: `&crate::analysis::BytecodeEvidence`.
  - Build lookups keyed by resolved invoke tuples and location context:
    - `invokes_by_owner_name: HashMap<(String, String), Vec<InvokeHit>>` where `InvokeHit` includes `descriptor` and `Location`.
    - `strings_by_entry_class: HashMap<(String, String), Vec<StringHit>>` where `StringHit` includes `value` and `Location` (for reconstructed strings) OR a best-effort location for CP strings (method/pc may be None).
  - Provide helpers used by detectors:
    - `invokes(owner, name) -> &[InvokeHit]`.
    - `strings_in_class(entry_path, class_name) -> &[StringHit]`.
    - `all_strings() -> impl Iterator<Item=&StringHit>`.
- Create `src/detectors/spec.rs` with small, explainable match helpers (avoid massive regex suites):
  - `extract_urls(strings: impl Iterator<Item=&str>) -> Vec<String>` using a conservative regex (per Phase 3 research) and dedup/sort.
  - `contains_any_token(haystack: &str, tokens: &[&str]) -> bool` for token lists.
  - A small `COMMAND_TOKENS` list for DETC-01 enrichment (e.g. `"powershell"`, `"cmd.exe"`, `"/bin/sh"`, `"curl"`, `"wget"`).
- Create `src/detectors/mod.rs` defining detector output types and a registry surface:
  - Define a detector output struct (do NOT depend on `Indicator`):
    - `DetectorFinding { id, title, category, severity, rationale, evidence_locations: Vec<Location>, extracted_urls: Vec<String>, extracted_commands: Vec<String>, extracted_file_paths: Vec<String> }`.
  - Define `pub fn run_capability_detectors(evidence: &crate::analysis::BytecodeEvidence, entries: &[crate::analysis::ArchiveEntry]) -> Vec<DetectorFinding>` but in Plan 01 it can ignore `entries` for these detectors.
  - `run_capability_detectors` MUST dedup findings by `id` and merge locations (do not emit one finding per callsite).
  </action>
  <verify>
cargo test
  </verify>
  <done>
- `src/detectors/*` compiles and is callable as a pure function over `BytecodeEvidence`.
- The helper index supports correlation checks (strings in same class) needed for FP controls.
  </done>
</task>

<task type="auto">
  <name>Task 2: Implement DETC-01/02/03 + wire into scan output with additive Indicator fields</name>
  <files>
src/main.rs
src/detectors/mod.rs
src/detectors/capability_exec.rs
src/detectors/capability_network.rs
src/detectors/capability_dynamic_load.rs
demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java
  </files>
  <action>
- Update the compiled demo sample jar to contain REAL bytecode invokes (and correlated string constants) for DETC-01..08 while keeping the demo safe:
  - Edit `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java`.
  - Add private static methods that are NEVER invoked from `main()` (or any reachable method). These exist only so javac emits the invoke instructions.
  - Add at least these never-invoked fixtures (names flexible):
    - DETC-01 fixture: contains both `Runtime.getRuntime().exec(...)` and `new ProcessBuilder(...).start()` plus at least one correlated command-like string token (e.g. `"powershell"`).
    - DETC-02 fixture: contains at least one hardcoded URL string in code (e.g. `new URL("https://example.invalid/..."))` plus a network primitive invoke such as `URLConnection.connect()` and/or `new Socket(host, port)`.
    - DETC-03 fixture: contains dynamic-loading primitives such as `new URLClassLoader(new URL[]{...})`, `Class.forName(...)`, and `Method.invoke(...)`.
    - DETC-04 fixture: contains jar/zip output primitives like `new ZipOutputStream(...)` + `putNextEntry(...)` and `new JarOutputStream(...)`, and at least one correlated string like `"../"` or `"mods/"` or `".jar"`.
    - DETC-05 fixture: contains persistence tokens as string constants (e.g. `"Software\\Microsoft\\Windows\\CurrentVersion\\Run"`, `"schtasks"`, `"/etc/systemd/system"`) plus an exec OR file-write primitive in the same class (so later detector correlation can be proven end-to-end).
    - DETC-06 fixture: contains `new ObjectInputStream(...).readObject()` (wrap in try/catch; safe + never invoked).
    - DETC-07 fixture: contains `System.loadLibrary("demo")` and/or `System.load("/tmp/demo.so")` (never invoked).
    - DETC-08 fixture: contains sensitive token/path strings (e.g. `"Login Data"`, `"Cookies"`, `"Local State"`, `".minecraft"`) plus `Files.readAllBytes(...)` and at least one network primitive invoke (e.g. `new URL("https://example.invalid/").openConnection().connect()`).
  - Keep these methods uncalled so the demo run remains safe.

- Add detectors:
  - `src/detectors/capability_exec.rs` (DETC-01)
    - Evidence source: `BytecodeEvidenceItem::invoke_resolved` with `(owner,name)`:
      - `("java/lang/Runtime", "exec")` (any descriptor)
      - `("java/lang/ProcessBuilder", "start")`
    - FP control: severity modulation
      - Base: `med` when primitive present.
      - Escalate to `high` only when a command-like token is present in correlated strings from the same `(entry_path,class_name)` OR any reconstructed string in the class matches command tokens.
    - Extract `extracted_commands` by collecting any string hits containing command tokens (dedup).
  - `src/detectors/capability_network.rs` (DETC-02)
    - Evidence source: resolved invokes:
       - URL: `java/net/URL.<init>` (invoke name is `"<init>"`) and/or `openConnection`
      - URLConnection: `connect`
      - Socket: `java/net/Socket.<init>` and/or `connect`
      - DatagramSocket: `send`
      - (Optional) Java 11+: `java/net/http/HttpClient.send|sendAsync`
    - URL evidence: ONLY attach URLs that correlate to the class that triggered networking primitives:
      - For each `(entry_path, class_name)` that contains a networking invoke, run `extract_urls()` over `strings_in_class(entry_path, class_name)` (all evidence kinds), and attach those URLs to the DETC-02 finding.
      - Severity escalation (`low` -> `med`) is based on correlated URLs (not global URLs across the jar).
    - FP control:
      - Base: `low` if primitive present.
      - Escalate to `med` if at least one URL was extracted.
      - Never emit `critical` here.
  - `src/detectors/capability_dynamic_load.rs` (DETC-03)
    - Evidence source: resolved invokes:
      - `java/net/URLClassLoader.<init>` / `newInstance`
      - `java/lang/Class.forName`
      - `java/lang/reflect/Method.invoke`
      - `java/lang/reflect/Constructor.newInstance`
      - (Optional) `java/lang/ClassLoader.defineClass`, `java/lang/invoke/MethodHandles$Lookup.defineClass`
    - FP control:
      - Base: `med` when any primitive present.
      - Escalate to `high` only when correlated strings in the same class contain sensitive class/method tokens like `java/lang/Runtime`, `exec`, `defineClass`, `loadLibrary`.
      - Never emit `critical` for reflection alone.
- Integrate these detectors into `run_capability_detectors` registry in `src/detectors/mod.rs`.
- Wire detectors into scan output (additive only):
  - Update `Indicator` in `src/main.rs` by adding OPTIONAL fields:
    - `evidence_locations: Option<Vec<crate::analysis::Location>>`
    - `extracted_urls: Option<Vec<String>>`
    - `extracted_commands: Option<Vec<String>>`
    - `extracted_file_paths: Option<Vec<String>>`
    - Each MUST be annotated with `#[serde(default, skip_serializing_if = "Option::is_none")]`.
  - Update all existing Indicator constructors in `src/main.rs` to set these fields to `None` (no behavior change).
  - In the scan pipeline (inside `run_static_analysis()` or immediately after it but before counts are finalized):
    - If `result.bytecode_evidence` is present, call `detectors::run_capability_detectors(bytecode_evidence, &entries)`.
    - Convert each `DetectorFinding` into an `Indicator` with:
      - `source`: `"detector"`
      - `category`: `"capability"`
      - `id`: the detector id (e.g. `DETC-01.RUNTIME_EXEC`)
      - `severity`: from the detector finding
      - `file_path`: `Some(first_location.entry_path.clone())` when available (keep legacy `file_path` for UI compatibility)
      - `evidence`: a short human string referencing the primitive matched and counts (do NOT attempt to embed full location detail here; locations are structured)
      - `evidence_locations`: `Some(finding.evidence_locations.clone())`
      - extracted fields: `Some(...)` only when the vectors are non-empty
  - Ensure detector indicators are included in `counts_by_category` and `counts_by_severity`.
- Add unit tests (no mocks) for each detector module proving:
  - A single primitive produces at most `low|med`.
  - Adding correlated strings escalates severity per rules.
  - Output includes at least one `Location` with `method` + `pc` populated when the trigger is an invoke.
    - Construct `BytecodeEvidence` test fixtures directly using Phase 1 schema types.
  </action>
  <verify>
cargo test

# Prove the demo jar is compiled to .class (not the non-bytecode fallback).
command -v javac >/dev/null
command -v jar >/dev/null
bash demo/build_sample.sh
jar tf demo/suspicious_sample.jar | grep -q '\.class$'

# Run demo scan + assert detector indicators are emitted and carry invoke locations.
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

const requiredPrefixes = ["DETC-01", "DETC-02", "DETC-03"];
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
    const hasInvokeLocation = locs.some(
      (l) =>
        l &&
        l.method &&
        typeof l.method.name === "string" &&
        typeof l.method.descriptor === "string" &&
        typeof l.pc === "number",
    );
    if (!hasInvokeLocation) {
      throw new Error(`${m.id}: expected at least one evidence_locations item with method + pc`);
    }
  }
}

console.log("detector assertions: ok");
'
  </verify>
  <done>
- DETC-01/02/03 indicators are emitted when their primitives exist in bytecode evidence, each with `source="detector"` and non-empty `evidence_locations`.
- Detectors enforce FP controls (tests cover severity modulation + correlation).
- Existing endpoints and existing response fields remain unchanged; Indicator changes are additive and backwards-compatible.
  </done>
</task>

</tasks>

<verification>
- Run `cargo test` (detector unit tests cover FP controls and evidence location behavior).
- Run `bash scripts/demo_run.sh`, capture `scan_id` from its output, then assert `.local-data/scans/${scan_id}.json` contains `source="detector"` matches for DETC-01..03 and each has at least one `evidence_locations[]` entry with `method` + `pc`.
</verification>

<success_criteria>
- DETC-01/02/03 are implemented using Phase 1 invoke evidence, not regex over lossy class bytes.
- Detector indicators carry structured callsite evidence and do not mark single primitives as CRITICAL.
</success_criteria>

<output>
After completion, create `.planning/phases/03-capability-detectors/03-capability-detectors-01-SUMMARY.md`
</output>
