# Nightshift: Doc Drift Analysis — Jarspect

**Date:** 2026-04-05
**Task:** doc-drift
**Verdict:** Docs are in excellent shape. No actionable drift found.

## Findings

### P3 — Minor: "8 capability detectors" claim is underselling

The README header and several sections reference "8 capability detectors." The codebase has 11 detector files: 8 base detectors (DETC-01 through DETC-08) and 3 compound detectors (base64_stager, discord_webhook, remote_code_load). The project layout section in the README correctly lists all 11, but the "8 detectors" phrasing in the pipeline description and Detection Engine sections is technically incomplete.

**Impact:** Low. The compound detectors are mentioned separately in their own sections. The "8" refers specifically to the base capability detectors, which is accurate.

**Recommendation:** Consider updating to "8 base + 3 compound detectors" for precision.

### No other drift detected

- All API routes documented in README match src/main.rs exactly
- Configuration env vars documented match the code
- Cargo.toml dependencies match README references
- Project layout section accurately reflects actual file structure
- Detection table (DETC-01 through DETC-08) matches detector files one-to-one
- Benchmark figures and methodology are self-consistent
- Version (0.1.0) matches Cargo.toml

## Summary

| Severity | Count | Details |
|----------|-------|---------|
| P0       | 0     | —       |
| P1       | 0     | —       |
| P2       | 0     | —       |
| P3       | 1     | "8 detectors" undersells the 11 total |

This is one of the best-documented repos in the Microck org. No meaningful drift.
