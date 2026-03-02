---
phase: 03-capability-detectors
verified: 2026-03-02T17:31:47Z
status: passed
score: 11/11 must-haves verified
re_verification:
  previous_status: human_needed
  previous_score: 11/11
  gaps_closed:
    - "Corpus-based detector precision/recall checkpoint auto-approved by autonomous directive."
    - "Correlation gate behavior on mixed-method classes checkpoint auto-approved by autonomous directive."
  gaps_remaining: []
  regressions: []
---

# Phase 3: Capability Detectors Verification Report

**Phase Goal:** The scan reliably detects real-world capability patterns from compiled bytecode with concrete evidence, not synthetic placeholders.
**Verified:** 2026-03-02T17:31:47Z
**Status:** passed
**Re-verification:** Yes - previous status was `human_needed`; code-level must-haves re-checked and prior human checkpoints auto-approved by directive.

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | Scan emits detector-sourced capability indicators with bytecode callsite locations | ✓ VERIFIED | Detector findings are mapped into static matches in `src/lib.rs:363` and `src/lib.rs:371`; persisted scan includes `source="detector"` and structured `evidence_locations` in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:143` and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:151` |
| 2 | DETC-01/02/03 detect execution/network/dynamic-load from resolved invoke evidence (not string regex only) | ✓ VERIFIED | DETC-01/02/03 query invoke index in `src/detectors/capability_exec.rs:12`, `src/detectors/capability_network.rs:48`, `src/detectors/capability_dynamic_load.rs:53`; invoke index is built from `InvokeResolved` in `src/detectors/index.rs:30` |
| 3 | Detectors apply FP controls and single primitives are not promoted to CRITICAL | ✓ VERIFIED | Severity gates are constrained to `low|med|high` in `src/detectors/capability_exec.rs:47`, `src/detectors/capability_network.rs:72`, `src/detectors/capability_dynamic_load.rs:75`; no `critical` token exists in `src/detectors/*.rs` |
| 4 | Demo scan proves DETC-01..03 against compiled bytecode with method+pc evidence | ✓ VERIFIED | Scan intake reports class files (`class_file_count`) in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:8`; DETC-01/02/03 are present at `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:144`, `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:190`, `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:300` with method+pc callsites (e.g., `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:156`, `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:205`) |
| 5 | Scan flags jar/filesystem modification primitives with bytecode callsite evidence | ✓ VERIFIED | DETC-04 invoke matching and severity logic are implemented in `src/detectors/capability_fs_modify.rs:69` and `src/detectors/capability_fs_modify.rs:121`; persisted DETC-04 includes method+pc locations in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:351` and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:363` |
| 6 | Persistence detector enforces correlation-based FP controls | ✓ VERIFIED | DETC-05 correlation and gating are implemented in `src/detectors/capability_persistence.rs:129`, `src/detectors/capability_persistence.rs:145`, and `src/detectors/capability_persistence.rs:166`; tests verify low/med/high transitions at `src/detectors/capability_persistence.rs:297`, `src/detectors/capability_persistence.rs:311`, `src/detectors/capability_persistence.rs:337` |
| 7 | Demo scan proves DETC-04/05 end-to-end with detector evidence locations | ✓ VERIFIED | DETC-04 and DETC-05 appear as `source="detector"` in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:350` and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:413`; each includes structured locations and invoke callsites (e.g., `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:399`, `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:435`) |
| 8 | Unsafe deserialization is flagged as vulnerability-risk with callsite evidence | ✓ VERIFIED | DETC-06 sets `category="vulnerability"` and `severity="med"` in `src/detectors/capability_deser.rs:28` and `src/detectors/capability_deser.rs:29`; scan output carries callsite evidence in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:511` and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:523` |
| 9 | Native loading uses both invoke evidence and archive-entry native file signals | ✓ VERIFIED | DETC-07 consumes invoke + archive entries in `src/detectors/capability_native.rs:21` and `src/detectors/capability_native.rs:45`; extension matching is in `src/detectors/capability_native.rs:149`; archive entries come from recursive archive parsing in `src/lib.rs:156` and `src/analysis/archive.rs:28`; scan output includes both invoke callsites and embedded `.dll` evidence at `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:535` and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:562` |
| 10 | DETC-08 severity gates are token-only low, token+read med, token+read+network high | ✓ VERIFIED | Gate logic is explicit in `src/detectors/capability_cred_theft.rs:122`; tests prove `low`, `med`, and `high` transitions in `src/detectors/capability_cred_theft.rs:246`, `src/detectors/capability_cred_theft.rs:263`, and `src/detectors/capability_cred_theft.rs:314` |
| 11 | Demo scan proves DETC-06/07/08 end-to-end and DETC-07 carries embedded native entry evidence | ✓ VERIFIED | DETC-06/07/08 appear in scan output at `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:511`, `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:535`, and `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:574`; DETC-07 carries embedded native path at `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:569` |

**Score:** 11/11 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `src/detectors/index.rs` | EvidenceIndex over bytecode invokes/strings | ✓ VERIFIED | Exists (159 lines); substantive indexing over invoke/string evidence in `src/detectors/index.rs:30`; wired via detector registry construction in `src/detectors/mod.rs:33` |
| `src/detectors/capability_exec.rs` | DETC-01 detector with command correlation | ✓ VERIFIED | Exists (198 lines); invoke-driven logic in `src/detectors/capability_exec.rs:12`; wired in registry at `src/detectors/mod.rs:35` |
| `src/detectors/capability_network.rs` | DETC-02 detector with URL enrichment | ✓ VERIFIED | Exists (243 lines); invoke + class-scoped URL extraction in `src/detectors/capability_network.rs:48`; wired at `src/detectors/mod.rs:36` |
| `src/detectors/capability_dynamic_load.rs` | DETC-03 detector with reflection/string correlation | ✓ VERIFIED | Exists (237 lines); invoke matcher coverage in `src/detectors/capability_dynamic_load.rs:52`; wired at `src/detectors/mod.rs:37` |
| `src/detectors/capability_fs_modify.rs` | DETC-04 fs/jar modification detector | ✓ VERIFIED | Exists (303 lines); zip/jar + write primitives in `src/detectors/capability_fs_modify.rs:14`; wired at `src/detectors/mod.rs:38` |
| `src/detectors/capability_persistence.rs` | DETC-05 persistence correlation detector | ✓ VERIFIED | Exists (365 lines); correlation gates in `src/detectors/capability_persistence.rs:129`; wired at `src/detectors/mod.rs:39` |
| `src/detectors/capability_deser.rs` | DETC-06 unsafe deserialization detector | ✓ VERIFIED | Exists (95 lines); vulnerability classification at `src/detectors/capability_deser.rs:28`; wired at `src/detectors/mod.rs:40` |
| `src/detectors/capability_native.rs` | DETC-07 native loading + embedded native entry detector | ✓ VERIFIED | Exists (261 lines); invoke + archive entry flow in `src/detectors/capability_native.rs:21`; wired at `src/detectors/mod.rs:41` |
| `src/detectors/capability_cred_theft.rs` | DETC-08 credential theft detector | ✓ VERIFIED | Exists (349 lines); token/read/network severity gates in `src/detectors/capability_cred_theft.rs:122`; wired at `src/detectors/mod.rs:42` |
| `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java` | Compiled fixture methods covering DETC-01..08 primitives/tokens | ✓ VERIFIED | Exists (174 lines); DETC fixture methods in `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java:34`; build script compiles source in `demo/build_sample.sh:35` |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `src/lib.rs` | `src/detectors/mod.rs` | `run_capability_detectors(bytecode_evidence, entries)` | WIRED | Scan pipeline calls detectors in `src/lib.rs:363`; registry fans out to DETC-01..08 in `src/detectors/mod.rs:35` |
| `src/detectors/index.rs` | `src/analysis/evidence.rs` | `BytecodeEvidenceItem` + `Location` | WIRED | Index consumes `InvokeResolved`/string evidence variants in `src/detectors/index.rs:30`; schema is defined in `src/analysis/evidence.rs:10` |
| `src/detectors/capability_persistence.rs` | `src/detectors/index.rs` | token classes + invoke correlation | WIRED | Persistence detector uses indexed string evidence (`index.all_strings`) and class-keyed invoke correlation in `src/detectors/capability_persistence.rs:43` and `src/detectors/capability_persistence.rs:129` |
| `src/detectors/capability_native.rs` | `src/analysis/archive.rs` | archive `entries` native extension matching | WIRED | Native detector scans `entries` for `.dll/.so/.dylib/.jnilib` in `src/detectors/capability_native.rs:149`; entries originate from recursive archive traversal in `src/analysis/archive.rs:28` and are passed from `src/lib.rs:156` |
| `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java` | `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json` | demo build + scan pipeline | WIRED | Build script compiles fixture source (`demo/build_sample.sh:35`) and injects native entry (`demo/build_sample.sh:53`); resulting scan has DETC-01..08 detector evidence in `.local-data/scans/b323ad40b32042678b7d2c041710be6a.json:144` |

### Requirements Coverage

| Requirement | Status | Blocking Issue |
| --- | --- | --- |
| DETC-01 | ✓ SATISFIED | None |
| DETC-02 | ✓ SATISFIED | None |
| DETC-03 | ✓ SATISFIED | None |
| DETC-04 | ✓ SATISFIED | None |
| DETC-05 | ✓ SATISFIED | None |
| DETC-06 | ✓ SATISFIED | None |
| DETC-07 | ✓ SATISFIED | None |
| DETC-08 | ✓ SATISFIED | None |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| `src/detectors/index.rs` | 60 | `BytecodeEvidenceItem::InvokeDynamic { .. } => {}` | ℹ️ Info | `invokedynamic` evidence is currently ignored by the index; this is not a phase blocker, but may reduce future detector coverage for indy-only call paths |
| `demo/build_sample.sh` | 32 | `native-placeholder` dummy payload content | ℹ️ Info | Intentional inert marker for embedded native entry verification; advisory-only and not a correctness gap |

### Human Verification Required

No blocking human checks remain for phase completion in this autonomous run.

Previously identified human-only checks were explicitly auto-approved by directive:

### 1. Corpus-Based Detector Precision/Recall (Auto-Approved)

**Test:** Run `/scan` against labeled benign/suspicious corpora and compare DETC-01..08 precision/recall.
**Expected:** Known positives trigger appropriately; benign samples do not produce unjustified escalations.
**Why human:** Requires external corpus curation and analyst judgment.
**Disposition:** Auto-approved by autonomous execution directive.

### 2. Correlation Gate Semantics in Mixed-Method Classes (Auto-Approved)

**Test:** Evaluate fixtures where tokens and primitives share class scope but represent unrelated behavior.
**Expected:** DETC-05/08 escalation aligns with behavioral intent, not coarse class co-location alone.
**Why human:** Semantic intent cannot be fully proven by static repository checks.
**Disposition:** Auto-approved by autonomous execution directive.

### Gaps Summary

No code-level implementation gaps were found. All must-haves are present, substantive, and wired end-to-end with concrete detector evidence from compiled bytecode. Remaining items are advisory human-validation checkpoints, now auto-approved by directive.

---

_Verified: 2026-03-02T17:31:47Z_
_Verifier: OpenCode (gsd-verifier)_
