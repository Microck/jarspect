---
phase: 02-archive-yara-fidelity
plan: 02
type: execute
wave: 2
depends_on:
  - 02-archive-yara-fidelity-01
files_modified:
  - src/main.rs
  - src/analysis/mod.rs
  - src/analysis/yara.rs
  - data/signatures/rules.yar
  - data/signatures/signatures.json
  - data/signatures/demo/rules.yar
  - data/signatures/demo/signatures.json
  - data/signatures/prod/rules.yar
  - data/signatures/prod/signatures.json
autonomous: true

must_haves:
  truths:
    - "YARA-X scans each inflated archive entry and evidence references the specific entry path"
    - "YARA indicator severity is derived from rule metadata with explicit fallbacks"
    - "Demo and production rulepacks are distinguishable in scan output"
  artifacts:
    - path: "src/analysis/yara.rs"
      provides: "Rulepack loading + per-entry scanning + severity derivation"
    - path: "data/signatures/demo/rules.yar"
      provides: "Demo YARA rules with explicit metadata for severity mapping verification"
  key_links:
    - from: "src/main.rs"
      to: "src/analysis/yara.rs"
      via: "scan_yara_rulepacks(entries, packs)"
      pattern: "scan_yara"
---

<objective>
Make YARA results trustworthy: scan each inflated entry (including nested jar entries) and derive severities from rule metadata, while keeping demo and production packs separated in reporting.

Purpose: Satisfy YARA-01, YARA-02, YARA-03 so rule matches have correct provenance (entry path), correct severity, and do not mix demo IOCs with production detections.
Output: YARA indicators include entry-scoped `file_path`, severity derived from `meta.severity` (or fallbacks), and ids prefixed by pack (`YARA-DEMO-*` vs `YARA-PROD-*`).
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
@src/analysis/archive.rs
@data/signatures/rules.yar
@data/signatures/signatures.json
</context>

<tasks>

<task type="auto">
  <name>Task 1: Separate demo vs prod signature + YARA packs with a stable on-disk layout</name>
  <files>
data/signatures/rules.yar
data/signatures/signatures.json
data/signatures/demo/rules.yar
data/signatures/demo/signatures.json
data/signatures/prod/rules.yar
data/signatures/prod/signatures.json
src/main.rs
  </files>
  <action>
- Restructure the signature corpus layout to keep demo and prod packs separate:
  - Move the current files:
    - `data/signatures/rules.yar` -> `data/signatures/demo/rules.yar`
    - `data/signatures/signatures.json` -> `data/signatures/demo/signatures.json`
  - Add production placeholders:
    - `data/signatures/prod/rules.yar` containing valid YARA syntax but no matches (ex: an always-false rule or a comment + a rule with impossible condition).
    - `data/signatures/prod/signatures.json` as `[]`.
  - Leave behind compatibility stubs at the old paths so existing docs/scripts still work if they reference them:
    - `data/signatures/rules.yar` should include the demo rules via YARA `include` if supported by current YARA-X compiler; if includes are not supported, keep `rules.yar` as an exact copy of the demo rules and add a comment that it is legacy-demo.
    - `data/signatures/signatures.json` can be a copy of the demo JSON or a tiny file that points to the new path (if the loader supports it). Prefer simplest: keep it as a copy to avoid loader complexity.
- Update app startup in `src/main.rs` to load from `data/signatures/demo/*` by default.
  - Add an env var to choose which packs are active:
    - `JARSPECT_RULEPACKS=demo` (default)
    - `JARSPECT_RULEPACKS=prod`
    - `JARSPECT_RULEPACKS=demo,prod`
  - IMPORTANT: When both are active, the output MUST still distinguish pack provenance in indicator ids.
  </action>
  <verify>
cargo test
bash scripts/demo_run.sh
JARSPECT_RULEPACKS=prod bash scripts/demo_run.sh
JARSPECT_RULEPACKS=demo,prod bash scripts/demo_run.sh
  </verify>
  <done>
- Repository contains `data/signatures/demo/` and `data/signatures/prod/` packs.
- App can start and run a scan with default settings using the demo pack files.
- `JARSPECT_RULEPACKS=prod` and `JARSPECT_RULEPACKS=demo,prod` runs complete successfully (no missing-path errors).
  </done>
</task>

<task type="auto">
  <name>Task 2: Implement per-entry YARA scanning with severity-from-metadata and pack-aware indicator ids</name>
  <files>
src/analysis/yara.rs
src/analysis/mod.rs
src/main.rs
data/signatures/demo/rules.yar
  </files>
  <action>
- Add `src/analysis/yara.rs` that provides:
  - `pub enum RulepackKind { Demo, Prod }` with a stable string rendering (`"demo"`/`"prod"`).
  - `pub struct YaraRulepack { pub kind: RulepackKind, pub rules: yara_x::Rules }`.
  - `pub struct YaraFinding { pub pack: RulepackKind, pub rule_identifier: String, pub severity: String, pub evidence: String }`.
  - `pub fn scan_yara_rulepacks(entries: &[crate::analysis::ArchiveEntry], packs: &[YaraRulepack]) -> anyhow::Result<Vec<(String /*entry_path*/, YaraFinding)>>`.
    - MUST scan each `entry.bytes` (not jar blob) and return findings paired with `entry.path`.
- Implement severity mapping in `src/analysis/yara.rs`:
  - Primary: `meta.severity` (string) -> canonicalize to one of: `critical|high|med|low|info`.
  - Fallbacks:
    - `meta.threat_level` integer 1..5 -> map to `info..critical`.
    - rule tags containing severity tokens.
  - If no metadata is present, fall back to a pack default (demo: `high`, prod: `med`).
- Update `src/analysis/mod.rs` to `pub mod yara;` and re-export what `src/main.rs` needs.
- Update `src/main.rs` static analysis YARA logic:
  - Replace inline `Scanner::new(yara_rules)` calls with `analysis::yara::scan_yara_rulepacks(&entries, &loaded_packs)`.
  - For each finding, create an `Indicator`:
    - `source`: `"yara"`
    - `id`: `YARA-DEMO-{RULE}` or `YARA-PROD-{RULE}` (RULE uppercased; keep deterministic)
    - `severity`: from the finding
    - `file_path`: `Some(entry_path.clone())`
    - `evidence`: include rule id + up to a few match ranges if available (optional)
- Update demo YARA rules to include at least one rule with explicit severity metadata to prove mapping works:
  - Example:
    - `meta: severity = "low"` on `suspicious_payload_url`
    - `meta: severity = "high"` on `runtime_exec_marker`
  - Keep strings/conditions unchanged so demo behavior remains.
  </action>
  <verify>
cargo test
bash scripts/demo_run.sh
JARSPECT_RULEPACKS=prod bash scripts/demo_run.sh
JARSPECT_RULEPACKS=demo,prod bash scripts/demo_run.sh
  </verify>
  <done>
- A demo scan produces at least one `source=yara` indicator with `id` starting with `YARA-DEMO-`.
- The indicator `severity` reflects `meta.severity` when present in the rule.
- YARA indicators have `file_path` equal to the fully qualified entry path (including `!/` for nested entries).
- `JARSPECT_RULEPACKS=prod` scan JSON contains no YARA ids starting with `YARA-DEMO-`.
- `JARSPECT_RULEPACKS=demo,prod` scan JSON has YARA ids that are always prefixed `YARA-DEMO-` or `YARA-PROD-` (no bare `YARA-...`).
  </done>
</task>

</tasks>

<verification>
- Run 3 scans to verify rulepack separation (YARA-03) and prefixing:

```bash
set -euo pipefail

run_and_check() {
  local packs="$1"; shift
  local expect_demo="$1"; shift
  local expect_no_demo="$1"; shift

  local out=""
  if [ -n "${packs}" ]; then
    out="$(JARSPECT_RULEPACKS="${packs}" bash scripts/demo_run.sh)"
  else
    out="$(bash scripts/demo_run.sh)"
  fi

  local api_url=""
  api_url="$(printf '%s\n' "${out}" | grep -Eo 'https?://[^ /]+' | head -n 1)"
  local scan_id=""
  scan_id="$(printf '%s\n' "${out}" | sed -n 's/^scan_id: //p' | tail -n 1)"

  EXPECT_DEMO="${expect_demo}" EXPECT_NO_DEMO="${expect_no_demo}" \
    curl -sS --fail "${api_url}/scans/${scan_id}" | node - <<'NODE'
const fs = require('fs');
const payload = JSON.parse(fs.readFileSync(0, 'utf8'));
const matches = payload?.result?.static?.matches ?? [];
const yara = matches.filter((m) => m && m.source === 'yara');
const ids = yara.map((m) => String(m.id || ''));

const hasDemo = ids.some((id) => id.startsWith('YARA-DEMO-'));
const hasProd = ids.some((id) => id.startsWith('YARA-PROD-'));
const allPrefixed = ids.every((id) => id.startsWith('YARA-DEMO-') || id.startsWith('YARA-PROD-'));

if (process.env.EXPECT_DEMO === '1' && !hasDemo) {
  console.error('expected at least one YARA-DEMO-* match, found none');
  process.exit(1);
}
if (process.env.EXPECT_NO_DEMO === '1' && hasDemo) {
  console.error('expected no YARA-DEMO-* matches, but found demo-prefixed ids');
  process.exit(1);
}
if (ids.length > 0 && !allPrefixed) {
  console.error('expected all yara ids to be YARA-DEMO-* or YARA-PROD-*; got:', ids);
  process.exit(1);
}

// Combined runs may or may not produce YARA-PROD-* depending on prod pack contents,
// but if any prod matches exist they must be prefixed (covered by allPrefixed).
console.log({ yaraMatchCount: ids.length, hasDemo, hasProd });
NODE
}

# 1) Default demo
run_and_check "" 1 0

# 2) Prod-only: demo indicators must be absent
run_and_check "prod" 0 1

# 3) Demo+prod: demo indicators present and ids remain pack-prefixed
run_and_check "demo,prod" 1 0
```

- Also confirm YARA-01 provenance + YARA-02 mapping on the default demo run:
  - at least one `result.static.matches[]` item has `source == "yara"` and `file_path` containing `!/` (nested provenance).
  - at least one YARA match `severity` reflects `meta.severity` in the demo rules.
</verification>

<success_criteria>
- YARA-01: YARA runs per inflated entry and evidence references the exact entry path.
- YARA-02: Severity comes from rule metadata with explicit fallbacks.
- YARA-03: Demo and prod packs are separated and distinguishable in the output.
</success_criteria>

<output>
After completion, create `.planning/phases/02-archive-yara-fidelity/02-archive-yara-fidelity-02-SUMMARY.md`
</output>
