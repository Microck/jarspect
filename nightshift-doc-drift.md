# Nightshift: Doc Drift Analysis — Jarspect

**Task:** doc-drift (Documentation Drift Detector)
**Category:** analysis
**Date:** 2026-04-03
**Agent:** Nightshift v3 (GLM 5.1)

---

## Executive Summary

15 documentation drift findings identified across severity levels P0–P3 in the jarspect codebase. Two P0 findings describe actively misleading documentation: removed detector triggers still referenced, and a false AI-dependency claim.

| Severity | Count |
|----------|-------|
| P0 (Critical — Misleading) | 2 |
| P1 (High — Incorrect) | 3 |
| P2 (Medium — Outdated) | 4 |
| P3 (Low — Minor) | 6 |

---

## Findings

### Finding 1: P0 — `DETC-03.DYNAMIC_LOAD` Static Override Removal Not Reflected in Docs

- **File:** `docs/corpus-calibration.md`, lines 49, 81
- **What docs say:** Static override layer includes `DETC-03.DYNAMIC_LOAD` at high/critical severity.
- **What code does:** `src/scan.rs:360-394` (`high_confidence_static_reason()`) only checks `DETC-03.BASE64_STAGER` and `DETC-02.DISCORD_WEBHOOK`. Test at line 502 explicitly confirms `DETC-03.DYNAMIC_LOAD` was removed.
- **Recommended fix:** Replace `DETC-03.DYNAMIC_LOAD` with `DETC-03.BASE64_STAGER` and `DETC-02.DISCORD_WEBHOOK` in docs/corpus-calibration.md lines 49 and 81.

---

### Finding 2: P0 — AI-Dependency Claim is False

- **File:** `README.md`, line 608
- **What docs say:** "Production verdicts require a working Azure OpenAI endpoint. Without AI configuration, scans will fail with an error."
- **What code does:** `src/scan.rs:275-300` — when `ai_config` is `None`, the code calls `verdict::heuristic_verdict()` with method `"heuristic_fallback"` and returns a successful response.
- **Recommended fix:** Change to: "Production verdicts prefer a working Azure OpenAI endpoint. Without AI configuration, scans fall back to a heuristic verdict with method `heuristic_fallback`."

---

### Finding 3: P1 — `/health` Response Example Doesn't Match API

- **File:** `README.md`, lines 461-472
- **What docs say:**
  ```json
  { "rulepacks": "prod", "signature_count": 12, "yara_rule_count": 6, "mb_hash_match_enabled": true }
  ```
- **What code does** (`src/main.rs:177-188`):
  ```json
  { "rulepacks": ["demo"], "signatures_loaded": 6, "yara_rulepacks_loaded": 1, "malwarebazaar_hash_match_enabled": true, "malwarebazaar_match_continue_analysis": false }
  ```
- Key differences: `signature_count` → `signatures_loaded`, `yara_rule_count` → `yara_rulepacks_loaded`, `rulepacks` is array not string, `mb_hash_match_enabled` → `malwarebazaar_hash_match_enabled`, two additional fields.
- **Recommended fix:** Update README example JSON to match actual field names and types.

---

### Finding 4: P1 — demo_run.sh Uses Wrong Default Port

- **File:** `scripts/demo_run.sh`, line 5
- **What code says:** `API_BASE_URL="${JARSPECT_API_URL:-http://localhost:8000}"`
- **What it should be:** Actual server default (`src/main.rs:130`) is `127.0.0.1:18000`.
- **Recommended fix:** Change default to `http://localhost:18000`.

---

### Finding 5: P1 — Verdict Method Values Incomplete

- **File:** `README.md`, line 600
- **What docs say:** method values are `ai_verdict`, `malwarebazaar_hash`, `static_override(ai_verdict)`, or `heuristic_fallback`
- **What code does:** `src/scan.rs` also produces `archive_fallback_static_override` and `archive_validation_failure` methods.
- **Recommended fix:** Add `archive_fallback_static_override` and `archive_validation_failure` to documented method values.

---

### Finding 6: P2 — Missing Configuration Documentation

- **File:** `README.md`, Configuration section (lines 364-401)
- **Missing items:**
  - `JARSPECT_WEB_DIR` env var (exists in `.env.example` and `src/main.rs:88-90`)
  - `JARSPECT_MB_MATCH_CONTINUE_ANALYSIS` env var (exists in `.env.example` and `src/scan.rs:20`)
  - `/health` endpoint missing `malwarebazaar_match_continue_analysis` and `yara_rulepacks_loaded` response fields
- **Recommended fix:** Add missing env vars to config table. Add missing `/health` response fields.

---

### Finding 7: P2 — Azure OpenAI `deployment` Described as Required

- **File:** `README.md`, lines 375-382
- **What docs say:** `AZURE_OPENAI_DEPLOYMENT` listed under "AI Verdict (required for production)" with no indication it's optional.
- **What code does:** `src/verdict.rs:18` — `deployment: Option<String>`. If `None`, entire AI config returns `None` (disabling AI).
- **Recommended fix:** Add note that `AZURE_OPENAI_DEPLOYMENT` is required for AI verdicts. Without it, AI is disabled even if endpoint and key are set.

---

### Finding 8: P2 — Data Model Missing `sha256` Field

- **File:** `README.md`, lines 580-591
- **What docs say:** `ScanRunResponse` data model table does not include `sha256`.
- **What code does:** `src/lib.rs:51` — `sha256: Option<String>` is a top-level field on `ScanRunResponse`. README text at line 70 mentions it, but the formal Data Model table omits it.
- **Recommended fix:** Add `sha256 | string or null | SHA-256 hash of the uploaded JAR` to the Data Model table.

---

### Finding 9: P2 — Rust Edition Requirement Misleading

- **File:** `README.md`, line 282
- **What docs say:** "Prerequisites: Rust stable toolchain"
- **What code does:** `Cargo.toml:4` — `edition = "2024"`, which requires Rust 1.85+ (2024 edition).
- **Recommended fix:** Change to "Rust 1.85+ toolchain (2024 edition)".

---

### Finding 10: P3 — Incorrect Function Name in Pipeline Pseudocode

- **File:** `README.md`, line 557
- **What docs say:** `analysis::run_yara_scan()`
- **What code does:** `src/analysis/mod.rs:12` — the function is `scan_yara_rulepacks()`
- **Recommended fix:** Update to `analysis::scan_yara_rulepacks()`.

---

### Finding 11: P3 — Dead Code: `fallback_verdict()` Never Called

- **File:** `src/verdict.rs`, line 523
- **Description:** `pub fn fallback_verdict()` is exported but never called from anywhere in the codebase. The actual fallback path uses `heuristic_verdict()`.
- **Recommended fix:** Remove `fallback_verdict()` or document it as utility for external consumers.

---

### Finding 12: P3 — Detector Count Misleading

- **File:** `README.md`, lines 51, 75, 95
- **What docs say:** "8 capability detectors"
- **What code does:** `src/detectors/mod.rs:32-49` — `run_capability_detectors()` calls 11 functions (8 base + 3 compound: discord_webhook, base64_stager, remote_code_load).
- **Recommended fix:** Update to "8 base capability detectors plus 3 compound detectors" or "11 capability detectors".

---

### Finding 13: P3 — Data Model Missing `static_findings` Field

- **File:** `README.md`, lines 580-591
- **What docs say:** Data Model table does not include `static_findings`.
- **What code does:** `src/lib.rs:56` — `static_findings: Option<StaticFindings>` is a top-level field on `ScanRunResponse`.
- **Recommended fix:** Add `static_findings` row to the Data Model table.

---

### Finding 14: P3 — Demo JAR Referenced as "Bundled" but is Build Artifact

- **File:** `README.md`, line 610
- **What docs say:** "The bundled demo rulepack matches strings from `demo/suspicious_sample.jar`"
- **What exists:** `demo/suspicious_sample.jar` is NOT in the repository; it's generated by `demo/build_sample.sh`.
- **Recommended fix:** Change to "The demo rulepack matches strings from `demo/suspicious_sample.jar` (built by `demo/build_sample.sh`)"

---

### Finding 15: P3 — `upload_id` Description Imprecise

- **File:** `README.md`, line 427
- **What docs say:** "upload_id is a 32-character lowercase hex string (UUID v4, simple form)"
- **What code does:** `src/main.rs:226` — `Uuid::new_v4().simple().to_string()` produces exactly this.
- **Recommended fix:** No change needed — technically correct.

---

## Prioritized Recommendations

### Immediate (P0)
1. Update `docs/corpus-calibration.md` — Replace `DETC-03.DYNAMIC_LOAD` with `DETC-03.BASE64_STAGER` and `DETC-02.DISCORD_WEBHOOK` (lines 49, 81).
2. Fix README AI-dependency claim — Line 608 should state scans degrade to `heuristic_fallback`, not "fail with an error."

### High Priority (P1)
3. Fix `/health` response example — Update README to use actual field names.
4. Fix `demo_run.sh` default port — Change `localhost:8000` to `localhost:18000`.
5. Document all verdict methods — Add `archive_fallback_static_override` and `archive_validation_failure`.

### Medium Priority (P2)
6. Add missing config vars to README: `JARSPECT_WEB_DIR`, `JARSPECT_MB_MATCH_CONTINUE_ANALYSIS`.
7. Add `sha256` and `static_findings` to the Data Model table.
8. Update Rust prerequisite to "Rust 1.85+ (2024 edition)."
9. Clarify Azure OpenAI deployment requirement.

### Low Priority (P3)
10. Fix function name in pipeline pseudocode.
11. Remove or document dead `fallback_verdict()` code.
12. Update detector count to reflect 11 total detectors.
13. Fix demo JAR description.
