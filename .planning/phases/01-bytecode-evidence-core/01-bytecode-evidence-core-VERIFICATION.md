---
phase: 01-bytecode-evidence-core
verified: 2026-03-02T14:34:09Z
status: passed
score: 6/6 must-haves verified
---

# Phase 1: Bytecode Evidence Core Verification Report

**Phase Goal:** Scan output contains bytecode-native evidence (strings + resolved invokes) with location metadata, without breaking existing endpoints.
**Verified:** 2026-03-02T14:34:09Z
**Status:** passed
**Re-verification:** No - initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
| --- | --- | --- | --- |
| 1 | `/scan` includes constant-pool string evidence from `.class` files | ✓ VERIFIED | `src/analysis/classfile_evidence.rs:15` filters `.class`; `src/analysis/classfile_evidence.rs:40` + `src/analysis/classfile_evidence.rs:52` emit `cp_utf8`/`cp_string_literal`; `src/main.rs:321` wires extractor into response |
| 2 | `/scan` includes resolved `invoke*` evidence as `(owner, name, descriptor)` | ✓ VERIFIED | `src/analysis/classfile_evidence.rs:123`-`src/analysis/classfile_evidence.rs:141` matches invoke opcodes and emits `invoke_resolved`/`invoke_dynamic` |
| 3 | `new String(new byte[]{...})` patterns are reconstructed into evidence | ✓ VERIFIED | `src/analysis/byte_array_strings.rs:180` reconstructs byte-array strings; `src/analysis/classfile_evidence.rs:101` consumes reconstructor output; `src/analysis/classfile_evidence.rs:103` emits `reconstructed_string` |
| 4 | Bytecode evidence carries location metadata (entry/class and method/pc when available) | ✓ VERIFIED | CP items use `entry_path` + `class_name` in `src/analysis/classfile_evidence.rs:43`; invoke/reconstructed items set method/pc in `src/analysis/classfile_evidence.rs:108` and `src/analysis/classfile_evidence.rs:119` |
| 5 | Existing endpoints remain and response change is additive-only | ✓ VERIFIED | Routes still present in `src/main.rs:212`, `src/main.rs:213`, `src/main.rs:214`; additive optional field in `src/main.rs:62`; backward-compat tests in `src/main.rs:785` and `src/main.rs:828` |
| 6 | Phase 1 evidence schema supports strings + invokes together in one additive evidence set | ✓ VERIFIED | Variant set includes `cp_*`, `invoke_*`, `reconstructed_string` in `src/analysis/evidence.rs:10`; extractor appends all kinds in `src/analysis/classfile_evidence.rs:39`, `src/analysis/classfile_evidence.rs:100`, `src/analysis/classfile_evidence.rs:114` |

**Score:** 6/6 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| --- | --- | --- | --- |
| `src/analysis/evidence.rs` | Stable serializable bytecode evidence schema | ✓ VERIFIED | Exists; 211 lines (substantive); no stub patterns; exports public schema types; consumed by extractor and scan serialization |
| `src/analysis/classfile_evidence.rs` | `.class` parser + string/invoke extraction with locations | ✓ VERIFIED | Exists; 254 lines; no stub patterns; public extractor exported/used by scan path |
| `src/analysis/byte_array_strings.rs` | Narrow byte-array string reconstructor | ✓ VERIFIED | Exists; 333 lines; no stub patterns; public reconstructor wired into classfile evidence extraction |
| `src/main.rs` | `/scan` wiring with additive `bytecode_evidence` and endpoint preservation | ✓ VERIFIED | Exists; 840 lines; routes intact; additive optional field + backward-compat serde tests |
| `demo/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java` | Deterministic fixture containing `new String(new byte[]{...})` pattern | ✓ VERIFIED | Exists; 29 lines; contains explicit fixture method at `DemoMod.java:26`; build script targets this source |

### Key Link Verification

| From | To | Via | Status | Details |
| --- | --- | --- | --- | --- |
| `src/main.rs` | `src/analysis/classfile_evidence.rs` | `analysis::extract_bytecode_evidence(&entries)` | WIRED | Call exists at `src/main.rs:321`; result is assigned into `ScanResult.bytecode_evidence` at `src/main.rs:328` |
| `src/analysis/classfile_evidence.rs` | `cafebabe` parser | `parse_class_with_options` | WIRED | Parser import/call at `src/analysis/classfile_evidence.rs:4` and `src/analysis/classfile_evidence.rs:31` |
| `src/analysis/classfile_evidence.rs` | invoke opcode resolution | `match Opcode::Invoke*` | WIRED | Opcode match and resolved evidence emission at `src/analysis/classfile_evidence.rs:123`-`src/analysis/classfile_evidence.rs:141` |
| `src/analysis/classfile_evidence.rs` | `src/analysis/byte_array_strings.rs` | `reconstruct_byte_array_strings(opcodes)` | WIRED | Reconstructor call at `src/analysis/classfile_evidence.rs:101`; output emitted as `reconstructed_string` at `src/analysis/classfile_evidence.rs:103` |
| `demo/build_sample.sh` | `DemoMod.java` fixture | `javac` source path input | WIRED | Source file path bound at `demo/build_sample.sh:6`; jar build flow uses compiled classes when toolchain exists |

### Requirements Coverage

| Requirement | Status | Blocking Issue |
| --- | --- | --- |
| BYTE-01 | ✓ SATISFIED | None |
| BYTE-02 | ✓ SATISFIED | None |
| BYTE-03 | ✓ SATISFIED | None |
| API-01 | ✓ SATISFIED | None |
| EVID-01 | ✓ SATISFIED | None |

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| --- | --- | --- | --- | --- |
| _None_ | - | No TODO/FIXME/placeholder stubs, empty impls, or console-only implementations detected in Phase 1 artifacts | - | No blocker anti-patterns found |

### Human Verification Required

None required for phase gate based on code-level verification.

### Gaps Summary

No implementation gaps found against declared Phase 1 must-haves. Codebase contains additive bytecode evidence schema, extraction wiring, invoke resolution, reconstructed string support, and preserved endpoints with backward-compatible deserialization.

---

_Verified: 2026-03-02T14:34:09Z_
_Verifier: Claude (gsd-verifier)_
