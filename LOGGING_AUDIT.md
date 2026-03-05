# Logging Audit Report

## Executive Summary

This report audits the logging quality and completeness across the Jarspect codebase.

## Current State

### Files with Logging
- `src/main.rs` - Uses `tracing::info!` (4 occurrences)
- `src/scan.rs` - Uses `tracing::warn!` (4 occurrences)
- `src/verdict.rs` - Uses `tracing::warn!` (7 occurrences)
- `src/analysis/archive.rs` - Uses `tracing::debug!` (6 occurrences)

### Files WITHOUT Logging
- `src/malwarebazaar.rs` - CRITICAL: HTTP operations unlogged
- `src/lib.rs` - CRITICAL: Config loading unlogged
- `src/analysis/yara.rs` - HIGH: Scans and matches unlogged
- `src/profile.rs` - MEDIUM: Profile building unlogged
- `src/detectors/*` (all) - MEDIUM: Detector execution unlogged

## Findings

### 1. MalwareBazaar Integration (CRITICAL)
**Issue**: No logging for external HTTP operations
**Impact**: Cannot debug hash lookup failures, API errors, or rate limits
**Recommendation**: Add structured logging for:
- Hash lookup attempts (info)
- API responses (debug)
- Failures (warn)
- Rate limiting events (warn)

### 2. Configuration Loading (CRITICAL)
**Issue**: No logging for signature and YARA rule loading
**Impact**: Cannot diagnose startup failures or misconfigurations
**Recommendation**: Add logging for:
- Signature files being loaded (info)
- Signature counts (info)
- YARA rule compilation (debug)
- Validation failures (warn)

### 3. YARA Scanning (HIGH)
**Issue**: No logging of scan operations or matches
**Impact**: Cannot track which rules are being evaluated
**Recommendation**: Add logging for:
- Scan start/end (debug)
- Matched rules (debug with rule ID, severity, file path)

### 4. Profile Building (MEDIUM)
**Issue**: No logging of metadata extraction
**Impact**: Cannot verify which mod format was detected
**Recommendation**: Add logging for:
- Detected loader (info)
- Metadata fields extracted (debug)
- Parsing failures (warn)

### 5. Detector Execution (MEDIUM)
**Issue**: No logging of detector runs
**Impact**: Cannot see which detectors found evidence
**Recommendation**: Add logging for:
- Detector start/end (debug)
- Evidence found counts (debug)
- Skip reasons (trace)

### 6. Scan Pipeline (HIGH)
**Issue**: Missing progress logging between scan stages
**Impact**: Cannot track where in the pipeline a scan is
**Recommendation**: Add logging for:
- Intake completion (info with file/class counts)
- Static analysis start (info)
- YARA scan start (info)
- Detector run start (info)
- Verdict determination (info)
- Scan completion (info with result)

### 7. Archive Analysis (LOW - GOOD)
**Current state**: Uses debug logging for budget limits
**Status**: Adequate for current needs
**No changes required**

## Logging Level Guidelines

### info
- Scan start/end with identifiers
- High-level stage transitions
- Configuration loading results
- External service calls (MalwareBazaar, AI API)
- Errors affecting scan outcome

### warn
- Retryable failures (with backoff details)
- Graceful degradation scenarios
- Non-critical parsing failures with fallbacks
- Rate limiting

### debug
- Detailed operation progress
- File/class counts
- Detector evidence found
- YARA rule matches
- Individual detector runs

### trace
- Very detailed diagnostics
- Skip reasons for optimization
- Individual record processing

## Structured Logging Fields

Use structured fields for consistency:

### Common fields
- `scan_id`: UUID for the scan operation
- `upload_id`: Upload identifier
- `file_count`: Number of files processed
- `class_count`: Number of .class files
- `jar_size_bytes`: Size of the JAR file
- `duration_ms`: Operation duration
- `error`: Error details
- `retry_count`: Number of retry attempts
- `backoff_ms`: Backoff duration

### MalwareBazaar-specific
- `sha256_hash`: Hash being looked up
- `family`: Malware family name (if found)
- `tags_count`: Number of tags
- `api_call_count`: Number of API calls made

### YARA-specific
- `rule_id`: YARA rule identifier
- `severity`: Rule severity
- `file_path`: Matched file path
- `rulepack`: rulepack kind (demo/prod)

### Detector-specific
- `detector_id`: Detector identifier
- `evidence_count`: Number of evidence items found
- `severity`: Finding severity
