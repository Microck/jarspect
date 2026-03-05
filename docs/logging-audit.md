# Logging Quality Audit

## Overview

This audit evaluates the logging infrastructure and practices in the Jarspect codebase as of commit `<current>`.

## Current Logging Setup

### Infrastructure
- **Framework**: `tracing` crate for structured logging
- **Initialization**: `tracing_subscriber` in `src/main.rs:79-83`
- **Default Log Level**: `jarspect=info,tower_http=info` (configurable via `RUST_LOG` env var)

### Existing Log Statements by Module

#### `src/main.rs` (HTTP server)
- Line 102: `info!` - Loaded signature and YARA rulepacks (with rulepack names)
- Line 116: `info!` - Configured upload limits (upload_max_bytes, body_max_bytes)
- Line 143: `info!` - Server listening address

#### `src/scan.rs` (Core scan orchestrator)
- Line 114: `warn!` - Archive parsing failed, attempting raw fallback scan (with error)
- Line 286: `warn!` - AI verdict failed, falling back to heuristic verdict (with error)
- Line 410: `warn!` - MalwareBazaar lookup failed, continuing with local analysis (with error)

#### `src/verdict.rs` (AI verdict generation)
- Lines 409-415: `tracing::warn!` - AI request failed (with api_calls, transient_attempts, backoff, error)
- Lines 437-443: `tracing::warn!` - Failed to decode AI response payload (with api_calls, transient_attempts, backoff, error)
- Lines 457-463: `tracing::warn!` - AI rate limited for too long (with api_calls, waited_secs, wait_secs, body)
- Line 468: `tracing::warn!` - AI rate limited (429), waiting then retrying (with api_calls, wait_secs, body)
- Line 474: `tracing::warn!` - AI API returned non-200 status (with status, body)

## Critical Gaps

### 1. Scan Lifecycle Logging (HIGH PRIORITY)
**Location**: `src/scan.rs:run_scan()`

**Missing**:
- Scan initiation: Log when a scan starts (upload_id, scan_id)
- SHA256 hash computation: Log hash for correlation
- MalwareBazaar check result: Log whether hash matched or not found
- Static analysis summary: Log number of files analyzed, class files, patterns matched, YARA hits
- Verdict determination: Log final verdict (CLEAN/SUSPICIOUS/MALICIOUS), method, confidence
- Scan completion: Log total scan duration

**Impact**: No visibility into scan progress or results in production logs. Cannot correlate scans with outcomes.

---

### 2. External Service Call Logging (HIGH PRIORITY)
**Location**: `src/malwarebazaar.rs`

**Missing**:
- MalwareBazaar API call initiation: Log hash being checked
- MalwareBazaar response: Log result (found/not found), family if available
- HTTP request/response timing: Add timing metrics for API calls

**Impact**: Cannot diagnose API issues or performance problems.

---

### 3. Detector Execution Logging (MEDIUM PRIORITY)
**Location**: `src/detectors/mod.rs:run_capability_detectors()`

**Missing**:
- Detector execution summary: Log total findings count by category and severity
- Individual detector results (debug level): Which detectors found evidence

**Impact**: Hard to debug detection behavior or understand which capabilities contributed to verdicts.

---

### 4. YARA Scan Logging (MEDIUM PRIORITY)
**Location**: `src/analysis/yara.rs` (module exists but not read)

**Missing**:
- YARA scan initiation: Log scanning entries with YARA rules
- YARA scan summary: Log number of rule hits by severity and pack (demo/prod)

**Impact**: Cannot verify YARA rule execution or correlate YARA hits with verdicts.

---

### 5. Profile Building Logging (MEDIUM PRIORITY)
**Location**: `src/profile.rs:build_profile()`

**Missing**:
- Mod metadata extraction result: Log which loader detected (fabric/forge/neoforge/spigot), mod_id, name, version
- Capability summary: Log which capabilities were detected as present

**Impact**: Cannot verify mod metadata parsing or understand capability profiling behavior.

---

### 6. Archive Parsing Logging (MEDIUM PRIORITY)
**Location**: `src/analysis/archive.rs` (module exists but not read)

**Missing**:
- Archive structure: Log number of entries, class files detected
- Archive parsing errors: More detailed error context when parsing fails

**Impact**: Limited visibility into archive analysis.

---

### 7. Error Context Logging (LOW-MEDIUM PRIORITY)
**General Issue**: Many error returns use `anyhow::Error` without structured logging before bubbling up.

**Examples**:
- File read errors
- Serialization/deserialization errors
- YARA compilation errors

**Impact**: When errors occur at top level, root cause context may be lost.

## Logging Quality Issues

### 1. Inconsistent Structured Field Usage
- Some logs use field syntax: `warn!(error = %error, ...)`
- Some logs use positional: `warn!("AI request failed; retrying")` (later lines in verdict.rs)
- Missing correlation IDs (scan_id) across most logs

**Recommendation**: Use consistent structured logging with scan_id/upload_id as trace correlation.

### 2. No Request/Response Correlation
- HTTP endpoints in `main.rs` don't log incoming request IDs
- No way to correlate scan initiation with scan completion logs

**Recommendation**: Generate request ID at HTTP handler entry and propagate through scan.

### 3. No Performance Metrics
- No timing metrics for scan phases (intake, static analysis, YARA scan, AI verdict)
- No timing for external API calls

**Recommendation**: Use `tracing::Instrument` span durations or manual timing logs.

### 4. Severity Level Concerns
- Some potentially actionable conditions use `warn!` when `info!` or `debug!` might be appropriate
- No `debug!` level logs for detailed tracing during troubleshooting

**Recommendation**: 
- `info!`: Key business events (scan started/finished, verdict produced)
- `warn!`: Recoverable errors and fallbacks (already well-used)
- `debug!`: Detailed detector findings, YARA rule execution, file-by-file analysis
- `error!`: Unrecoverable errors that require intervention

## Recommendations

### Priority 1: Add Scan Lifecycle Logging

Add to `src/scan.rs`:

```rust
use tracing::{info, instrument};

#[instrument(skip_all, fields(upload_id = %request.upload_id))]
pub async fn run_scan(
    state: &AppState,
    request: ScanRequest,
    scan_id_override: Option<&str>,
) -> Result<ScanRunResponse> {
    let scan_id = build_scan_id(scan_id_override)?;
    tracing::Span::current().record("scan_id", &scan_id);
    
    info!("scan initiated");
    
    // ... existing code ...
    
    info!(
        sha256 = %sha256_hash,
        file_count = entries.len(),
        class_file_count = intake.class_file_count,
        pattern_matches = static_findings.matched_pattern_ids.len(),
        signature_matches = static_findings.matched_signature_ids.len(),
        yara_hits = static_findings.matches.iter().filter(|i| i.source == "yara").count(),
        "static analysis completed"
    );
    
    // ... verdict logic ...
    
    info!(
        verdict = %ai_verdict.result,
        confidence = ai_verdict.confidence,
        risk_score = ai_verdict.risk_score,
        method = %method,
        duration_ms = started_at.elapsed().as_millis(),
        "scan completed"
    );
    
    Ok(response)
}
```

### Priority 2: Add External Service Call Logging

Add to `src/malwarebazaar.rs`:

```rust
use tracing::{info, instrument};

#[instrument(skip_all, fields(sha256))]
pub async fn check_hash(sha256: &str, api_key: &str) -> Result<Option<MalwareBazaarResult>> {
    // ... existing API call code ...
    
    match result {
        Some(ref malware) => {
            info!(
                family = ?malware.family.as_deref(),
                tags = malware.tags.len(),
                "malwarebazaar hash match found"
            );
        }
        None => {
            info!("malwarebazaar hash not found");
        }
    }
    
    Ok(result)
}
```

### Priority 3: Add Detector Execution Summary

Add to `src/detectors/mod.rs`:

```rust
use tracing::debug;

pub fn run_capability_detectors(
    evidence: &BytecodeEvidence,
    entries: &[ArchiveEntry],
) -> Vec<DetectorFinding> {
    // ... existing code ...
    
    let findings = dedup_findings(findings);
    
    debug!(
        total_findings = findings.len(),
        by_category = %format!("{:?}", summarize_by_category(&findings)),
        "detector execution completed"
    );
    
    findings
}
```

### Priority 4: Establish Logging Convention

Create `src/logging.rs` with helpers:

```rust
use tracing::{info, warn, error};

/// Scan lifecycle events
pub fn log_scan_start(scan_id: &str, upload_id: &str) {
    info!(scan_id, upload_id, "scan initiated");
}

pub fn log_scan_complete(scan_id: &str, verdict: &str, confidence: f64, duration_ms: u64) {
    info!(
        scan_id,
        verdict,
        confidence,
        duration_ms,
        "scan completed"
    );
}

/// External service events
pub fn log_malwarebazaar_check(sha256: &str) {
    info!(sha256, "checking malwarebazaar");
}

pub fn log_malwarebazaar_result(sha256: &str, found: bool, family: Option<&str>) {
    if found {
        info!(sha256, family, "malwarebazaar match found");
    } else {
        info!(sha256, "malwarebazaar no match");
    }
}

/// AI service events
pub fn log_ai_verdict_request(scan_id: &str) {
    info!(scan_id, "requesting AI verdict");
}

pub fn log_ai_verdict_result(scan_id: &str, verdict: &str, confidence: f64) {
    info!(scan_id, verdict, confidence, "AI verdict received");
}
```

## Summary Statistics

| Metric | Count |
|--------|-------|
| Total source files | ~25 |
| Files with logging | 3 (main.rs, scan.rs, verdict.rs) |
| Total log statements | ~11 |
| Info-level logs | 3 |
| Warn-level logs | 7+ |
| Error-level logs | 0 (explicit) |
| Debug-level logs | 0 |
| Logs with structured fields | ~8 |
| Logs with trace correlation (scan_id) | 0 |

## Action Items

1. **HIGH**: Add scan lifecycle logging (init, static analysis complete, verdict, complete)
2. **HIGH**: Add MalwareBazaar API call logging (request initiated, result)
3. **MEDIUM**: Add detector execution summary logs
4. **MEDIUM**: Add YARA scan logging (initiation, summary)
5. **MEDIUM**: Add profile building logs (metadata extraction, capability summary)
6. **LOW**: Create logging convention helpers in dedicated module
7. **LOW**: Add debug-level logs for detailed troubleshooting
8. **LOW**: Add request/response correlation IDs to HTTP handlers

## Notes

- This audit is based on static analysis. Runtime verification of log output was not performed.
- The project already uses structured logging with `tracing`, which is excellent for observability.
- Current logging focuses on error/warning conditions. Adding info/debug logs would significantly improve operational visibility.
- Consider adding log sampling or rate limiting for high-volume debug logs in production.
