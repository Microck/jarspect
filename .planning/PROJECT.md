# Jarspect

## What This Is

Jarspect is a security scanner for Minecraft mods. It unpacks a `.jar`, runs layered static analysis, and returns a 0-100 risk score with explainable indicators so users can audit before installing.
Today it is demo-grade: most detection logic scans lossy UTF-8 text rather than compiled bytecode, so real malware techniques often evade detection.

## Core Value

Upload a `.jar`, get a risk verdict with explainable indicators before you install.

## Current Milestone: v2.0 Logic rework

**Goal:** Make detection reliable by moving from demo-only string scanning to bytecode-native analysis and production-grade scoring.

**Target features:**
- Parse `.class` files (constant pool + method code) to extract structured indicators
- Detect real-world capability patterns (dynamic loading, exec, persistence, jar rewriting, credential theft, unsafe deserialization)
- Rebuild scoring/tiering so `CLEAN` is reachable and high-risk combos land in `HIGH`/`CRITICAL`
- Replace synthetic behavior evidence with evidence derived from extracted findings
- Add regression tests + safe fixtures that prove key techniques are detected

## Requirements

### Validated

- ✓ Upload `.jar` and persist it to `.local-data/uploads/` — existing
- ✓ Run scan pipeline (`/scan`) and persist results to `.local-data/scans/` — existing
- ✓ Web UI to upload+scan and inspect indicators — existing
- ✓ Signature corpus + YARA-X rulepack loaded at startup — existing (demo fixtures)

### Active

- [ ] Bytecode-native detection engine (v2.0)
- [ ] Production-grade scoring + tiering (v2.0)
- [ ] Regression test suite + fixtures for key detectors (v2.0)

### Out of Scope

- Dynamic/sandboxed execution of untrusted code — safety + complexity
- Cloud / hosted scanning service — keep single local binary for now
- Threat intel feeds / online reputation lookups — defer until core detection is solid

## Context

- Current backend is a single-file Axum server (`src/main.rs`) with a static web UI under `web/`.
- Current static analysis mostly searches `String::from_utf8_lossy()` over binary `.class` bytes, which misses constant-pool and bytecode-encoded signals.
- `PLAN.md` contains the research-backed overhaul approach and specific malware technique families to target.

## Constraints

- **Safety**: No real malware samples in-repo; use safe synthetic fixtures for tests/demos
- **Testing**: No mocks in tests
- **Architecture**: Prefer incremental modularization; avoid a big-bang rewrite that breaks the existing API
- **Explainability**: Every detection provides concrete evidence (class/method/file + snippet or resolved symbol)

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Bytecode-native analysis (constant pool + invoke resolution) | Real malware indicators live in compiled bytecode | — Pending |
| Keep scanning per-entry (inflate ZIP members) | YARA and detectors need uncompressed bytes | — Pending |

---
*Last updated: 2026-03-02 after starting milestone v2.0 Logic rework*
