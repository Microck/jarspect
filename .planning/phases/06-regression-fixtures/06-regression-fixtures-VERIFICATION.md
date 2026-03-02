---
phase: 06-regression-fixtures
verified: 2026-03-02T17:26:44Z
status: passed
score: 5/5 must-haves verified
---

# Phase 6: Regression Fixtures Verification Report

**Phase Goal:** The new bytecode-first logic is protected by safe fixtures and end-to-end tests, and the existing demo flow still works.
**Verified:** 2026-03-02T17:26:44Z
**Status:** passed
**Re-verification:** No - initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Tests can run the real scan pipeline without HTTP by calling a reusable helper | VERIFIED | `src/lib.rs:141` exports `run_scan`; `tests/regression-fixtures.rs:128` calls `run_scan(...)`; no HTTP client usage found in `tests/regression-fixtures.rs` |
| 2 | Scan tests can write artifacts into a temp directory (not `.local-data/`) | VERIFIED | `tests/regression-fixtures.rs:103` uses `tempdir()`; `tests/regression-fixtures.rs:104` and `tests/regression-fixtures.rs:105` create temp `uploads`/`scans` dirs |
| 3 | Safe, compiled fixtures exist and are committed in-repo | VERIFIED | `tests/fixtures/bytecode/all-capabilities.jar` and `tests/fixtures/bytecode/all-capabilities.sha256` exist; jar contains `com/jarspect/fixtures/AllCapabilities.class` and `native/demo.so`; safety contract documented in `tests/fixtures/README.md` |
| 4 | E2E scan tests run the real scan pipeline (no mocks, no HTTP) using temp dirs | VERIFIED | `tests/regression-fixtures.rs:15` and `tests/regression-fixtures.rs:88` define tokio integration tests; test helper calls `run_scan` directly and loads signatures/YARA via library APIs |
| 5 | Demo jar regression test asserts demo signature ids and YARA rule ids still hit | VERIFIED | `tests/regression-fixtures.rs:90` scans `demo/suspicious_sample.jar`; `tests/regression-fixtures.rs:93` and `tests/regression-fixtures.rs:94` assert signature + YARA IDs |

**Score:** 5/5 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `src/lib.rs` | Library API callable from integration tests | VERIFIED | Exists; substantive (750 lines); exports include `pub async fn run_scan`; wired via `src/main.rs` and `tests/regression-fixtures.rs` |
| `src/main.rs` | Axum handlers call shared scan helper | VERIFIED | Exists; substantive (223 lines); `/scan` handler delegates to `jarspect::run_scan(...)` and wraps response in JSON |
| `Cargo.toml` | `tempfile` available to tests under dev dependencies | VERIFIED | Exists; `tempfile = "3.26.0"` present under `[dev-dependencies]`; used by `tests/regression-fixtures.rs` |
| `.planning/ROADMAP.md` | Phase 6 plan list/count are concrete | VERIFIED | Exists; Phase 6 lists `06-regression-fixtures-01-PLAN.md` and `06-regression-fixtures-02-PLAN.md`; progress row shows `0/2` |
| `tests/fixtures/bytecode/all-capabilities.jar` | Committed compiled fixture jar | VERIFIED | Exists (zip/JAR, stored entries, fixed timestamp metadata); includes class payload and `native/demo.so` |
| `tests/regression-fixtures.rs` | Regression tests covering TEST-01/02/03 | VERIFIED | Exists; substantive (185 lines); contains two `#[tokio::test]` cases and resilient indicator assertions |
| `tools/build-regression-fixtures.sh` | One-shot fixture regeneration script | VERIFIED | Exists; substantive (49 lines); javac-first, Docker fallback, deterministic jar build + SHA256 generation |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `src/main.rs` | `src/lib.rs` | handler calls shared scan helper | WIRED | `scan` handler calls `jarspect::run_scan(&state, request, None).await` and uses returned payload in `Json(...)` |
| `src/main.rs` | `src/lib.rs` | main constructs `AppState` from library type | WIRED | `use jarspect::{AppState, ...}` plus `let state = AppState { ... }` in server setup |
| `tests/regression-fixtures.rs` | `src/lib.rs` | direct call to `run_scan` | WIRED | Imports `run_scan` and invokes it with fixed `scan_id_override`, then asserts over serialized result |
| `tests/regression-fixtures.rs` | `tests/fixtures/bytecode/all-capabilities.jar` | fixture bytes read into temp upload | WIRED | Test uses fixture path and calls `fs::read(...)`, writes bytes to temp upload jar |
| `tests/regression-fixtures.rs` | `demo/suspicious_sample.jar` | demo regression scan | WIRED | Second test scans demo jar path and validates signature/YARA continuity |

### Requirements Coverage

| Requirement | Status | Blocking Issue |
| --- | --- | --- |
| TEST-01: safe fixtures proving each detector fires | SATISFIED | None |
| TEST-02: end-to-end scan test for indicators and tier outcomes | SATISFIED | None |
| TEST-03: demo sample still triggers demo signatures/rules | SATISFIED | None |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| None | - | No TODO/FIXME/placeholder stubs, empty implementations, or console-log-only handlers found in phase files | - | No blocker anti-patterns detected |

### Human Verification Required

None required for this code-level phase verification.

### Gaps Summary

No gaps found. Must-haves from both Phase 6 plans are implemented and wired, and the phase goal is achieved at code level.

---

_Verified: 2026-03-02T17:26:44Z_
_Verifier: Claude (gsd-verifier)_
