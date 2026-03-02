# Phase 1: Bytecode Evidence Core - Research

**Researched:** 2026-03-02
**Domain:** JVM classfile parsing + bytecode evidence extraction (Rust)
**Confidence:** HIGH

<user_constraints>
## User Constraints

No phase `CONTEXT.md` was provided for Phase 1.
</user_constraints>

## Summary

Phase 1 is a data-extraction problem, not a detector/scoring problem: produce a stable evidence set from `.class` files (constant-pool strings, resolved invokes, and a narrow reconstruction of `new String(new byte[]{...})`) while keeping existing HTTP endpoints unchanged and response changes additive.

The biggest reliability jump comes from stopping the current lossy text scan (`String::from_utf8_lossy`) over `.class` bytes and instead parsing classfile structures. For Rust, `cafebabe` is the most complete off-the-shelf classfile parser reviewed here: it supports Java 21 classfile structure, validates format, and (optionally) disassembles `Code` bytecode into typed opcodes with byte offsets and already-resolved constant-pool references for invoke instructions.

**Primary recommendation:** Use `cafebabe` for class + bytecode parsing, and add a small, purpose-built constant-pool string extractor (Utf8 + String literals) plus a minimal byte-array-to-string reconstructor over the parsed opcode stream.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `cafebabe` | 0.9.0 | Parse `.class` + decode bytecode opcodes with offsets and resolved member refs | Broad classfile coverage (Java 21), typed API, supports parsing `Code` and opcodes including invoke* (HIGH confidence from crate source) |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `cesu8` | 1.1.0 | Decode Java CESU-8 / modified-UTF8 style constant-pool bytes to Rust strings | For an explicit constant-pool Utf8 scanner to avoid `from_utf8_lossy` on structured data |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `cafebabe` | `classfile-parser` (0.3.8) | Provides constant pool + `code_parser` that returns `(offset, Instruction)` pairs, but its classfile support is documented against older JVMS (SE10) and requires manual constant-pool resolution for invoke refs |
| Any crate | Hand-rolled minimal parser | Lowest dependency surface, but easy to get constant-pool skipping, modified UTF-8, and bytecode operand sizing wrong; higher bug risk for Phase 1 |

**Cargo install (recommended):**
```toml
[dependencies]
cafebabe = "0.9.0"
cesu8 = "1.1.0"
```

## Architecture Patterns

### Recommended Project Structure
Keep Phase 1 changes isolated and additive; the planner can decide how far to modularize in this phase, but the evidence core benefits from a clear boundary.

```
src/
├── analysis/
│   ├── mod.rs
│   ├── classfile_evidence.rs   # parse .class, extract evidence
│   ├── cp_strings.rs           # Utf8 + CONSTANT_String extraction
│   └── byte_array_strings.rs   # new String(new byte[]{...}) reconstructor
└── main.rs                     # HTTP + orchestration
```

### Pattern 1: Evidence-First Extraction Pipeline
**What:** Build a per-class `EvidenceBundle` from raw `.class` bytes, then union bundles across archive entries. Evidence is pure data (strings + invokes + reconstructed strings) with location metadata.
**When to use:** Always for `.class` entries (detectors come later in Phase 3).
**Example (shape):**
```rust
// Pseudocode for Phase 1 planning.
struct Location {
    entry_path: String,   // jar entry path
    class_name: String,   // internal name: a/b/C
    method: Option<(String, String)>, // (name, descriptor)
    pc: Option<u32>,      // bytecode offset within Code
}

enum EvidenceKind {
    CpUtf8,
    CpStringLiteral,
    InvokeResolved,
    ReconstructedString,
}

struct Evidence {
    kind: EvidenceKind,
    value: String,        // string value OR a formatted invoke tuple
    location: Location,
    // optional extra fields: owner/name/descriptor for invokes, cp_index, etc.
}
```

### Pattern 2: Invoke Resolution as Data, Not Matching
**What:** Iterate `Code` bytecode opcodes and record every invoke as `(owner, name, descriptor)` at `(class, method, pc)`.
**When to use:** Phase 1 extraction; Phase 3 detectors consume this stream.
**Implementation note:** With `cafebabe`, `Opcode::{Invokevirtual,Invokestatic,Invokespecial,Invokeinterface}` already carry a resolved `MemberRef` (class name + name-and-type) so no custom constant-pool graph walking is needed for these.

### Anti-Patterns to Avoid
- **Treating `.class` as text:** Any `from_utf8_lossy`-based scan over class bytes will keep producing false negatives due to structured, length-prefixed data.
- **Full decompiler/VM:** Phase 1 only needs constant pool, invoke tuples, and one narrow string reconstruction pattern; do not implement general stack maps, verification, or full control-flow interpretation.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Classfile structure parsing | A custom JVM classfile parser for all versions | `cafebabe` | Already supports Java 21 structure + validation; avoids subtle constant-pool and attribute bugs |
| Bytecode instruction sizing/alignment | A from-scratch disassembler | `cafebabe::bytecode::ByteCode` | Handles `tableswitch`/`lookupswitch` padding, `wide`, validated jumps |
| Modified UTF-8 corner cases | Ad-hoc lossy decoding | `cesu8` (or `cafebabe` internal decoding) | JVM constant-pool strings are not plain UTF-8; lossy decoding hides evidence |

**Key insight:** For Phase 1, reliability comes from parsing the classfile correctly more than from clever heuristics.

## Common Pitfalls

### Pitfall 1: Modified UTF-8 ("Java UTF-8") decoding
**What goes wrong:** Constant-pool Utf8 entries are not guaranteed to be standard UTF-8; naive decoding produces replacement characters and breaks string evidence.
**Why it happens:** Classfile uses a modified encoding (commonly referred to as Java CESU-8 / modified UTF-8) for constant-pool Utf8 bytes.
**How to avoid:** Decode with a Java-aware decoder (`cesu8::from_java_cesu8`), and only fall back to a lossy strategy for display (never for matching).
**Warning signs:** Evidence strings include lots of `\uFFFD` replacement characters or unexpectedly empty strings.

### Pitfall 2: Constant-pool indexing and "double slot" entries
**What goes wrong:** Off-by-one errors, or mis-parsing after `Long`/`Double` entries causes later indices to be wrong.
**Why it happens:** Constant pool is 1-based; `CONSTANT_Long` and `CONSTANT_Double` occupy two indices.
**How to avoid:** If implementing any manual CP scan, explicitly advance an extra slot for tags 5/6.
**Warning signs:** Invoke resolution points to garbage owners/names, or parsing fails mid-file.

### Pitfall 3: `invokedynamic` is not a normal `(owner, name, desc)`
**What goes wrong:** Treating `invokedynamic` like other invokes and claiming an owner.
**Why it happens:** `invokedynamic` references a bootstrap method + a name-and-type; the "owner" is indirect.
**How to avoid:** For Phase 1, record `invokedynamic` evidence as `(name, descriptor, bootstrap_attr_index)` and keep `owner = None` (or a dedicated variant).
**Warning signs:** Incorrectly attributing lambdas to arbitrary owners.

### Pitfall 4: Byte-array string reconstruction requires some stack modeling
**What goes wrong:** Backtracking by bytes without understanding stack shape misses real patterns or reconstructs wrong bytes.
**Why it happens:** The array is typically built via `newarray` + `dup` + `{i}const/bipush` + `bastore` and then consumed by `String.<init>`; ordering depends on compiler.
**How to avoid:** Implement a tiny abstract interpreter for a limited opcode set (ints + byte arrays + `dup` + `bastore`) and reset to "unknown" on control-flow boundaries.
**Warning signs:** Reconstructed strings have swapped bytes, missing prefixes, or fail whenever code uses locals.

## Code Examples

Verified patterns from primary sources (crate code inspected locally under `opensrc/`).

### Parse `.class` and iterate bytecode opcodes with offsets (`cafebabe`)
```rust
use cafebabe::{parse_class, ParseOptions};
use cafebabe::attributes::{AttributeData, CodeData};
use cafebabe::bytecode::Opcode;

let mut opts = ParseOptions::default();
opts.parse_bytecode(true);
let class = cafebabe::parse_class_with_options(class_bytes, &opts)?;

for m in &class.methods {
    for attr in &m.attributes {
        let AttributeData::Code(CodeData { bytecode: Some(bc), .. }) = &attr.data else {
            continue;
        };

        for (pc, op) in &bc.opcodes {
            match op {
                Opcode::Invokevirtual(member)
                | Opcode::Invokestatic(member)
                | Opcode::Invokespecial(member)
                | Opcode::Invokeinterface(member, _) => {
                    // member.class_name + member.name_and_type.{name,descriptor}
                    // pc is the instruction offset within this Code attribute
                }
                Opcode::Invokedynamic(indy) => {
                    // indy.name_and_type.{name,descriptor} + indy.attr_index
                }
                _ => {}
            }
        }
    }
}
```
Source: `cafebabe` crate (`opensrc/cafebabe-0.9.0/src/bytecode.rs`, `opensrc/cafebabe-0.9.0/src/attributes.rs`, `opensrc/cafebabe-0.9.0/src/lib.rs`).

### Decode classfile "Utf8" bytes using a Java-aware CESU-8 decoder
```rust
let s = cesu8::from_java_cesu8(raw_bytes)
    .unwrap_or_else(|_| String::from_utf8_lossy(raw_bytes));
```
Source: `classfile-parser` crate (`opensrc/classfile-parser-0.3.8/src/constant_info/parser.rs`).

## Minimal Viable Parsing Scope (Phase 1)

Implement ONLY what the success criteria requires:

- Parse `.class` entries (magic `0xCAFEBABE`) and extract:
  - **Constant-pool strings:** all `CONSTANT_Utf8` payloads, plus `CONSTANT_String` literals as a distinct evidence kind.
  - **Invoke evidence:** `invokevirtual`, `invokestatic`, `invokespecial`, `invokeinterface` resolved to `(owner, name, descriptor)` with `(class, method, pc)`.
  - **Reconstructed strings:** only the pattern `new String(new byte[]{<constant bytes>})` where bytes are immediate constants in the same straight-line sequence.

Explicitly NOT in Phase 1:

- No nested-jar recursion (Phase 2).
- No detector/scoring rewrite (Phase 3+).
- No full deobfuscation (XOR/Base64 decode loops), no reflection call graph resolution.
- No line-number mapping, no debug attribute dependency.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Regex over `String::from_utf8_lossy()` of archive entries | Parse classfiles and emit evidence (strings + invokes) | Phase 1 | Enables reliable detection against compiled bytecode and avoids lossy decoding false negatives |

## Open Questions

1. **Evidence schema placement in API response**
   - What we know: endpoints must stay and response changes must be additive.
   - What's unclear: whether evidence should live under `result.static_findings` or a new top-level `result.bytecode_evidence`.
   - Recommendation: add a new optional field (e.g. `bytecode_evidence`) to avoid mixing with existing indicators and keep Phase 1 purely additive.

2. **How to represent `invokedynamic`**
   - What we know: `cafebabe` surfaces `Opcode::Invokedynamic` with name+descriptor and bootstrap attribute index.
   - What's unclear: whether Phase 1 must force an `(owner, name, descriptor)` triple for all invokes.
   - Recommendation: treat invokedynamic as a dedicated evidence variant with `owner=None` to avoid incorrect attribution.

## Sources

### Primary (HIGH confidence)
- `cafebabe` README (Java 21 support, Chapter 4 coverage): https://github.com/staktrace/cafebabe
- JVM Specification, Class File Format (Chapter 4): https://docs.oracle.com/javase/specs/jvms/se21/html/jvms-4.html
- crates.io metadata (exact versions):
  - https://crates.io/crates/cafebabe
  - https://crates.io/crates/cesu8
  - https://crates.io/crates/classfile-parser

### Secondary (MEDIUM confidence)
- `classfile-parser` repository (nom-based classfile parser): https://github.com/Palmr/classfile-parser

### Tertiary (LOW confidence)
- Perplexity MCP lookup attempted but tool returned an error in this environment (could not cross-verify via Perplexity).

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - validated by inspecting downloaded crate sources and crates.io versions.
- Architecture: HIGH - direct fit to Phase 1 success criteria (evidence extraction only).
- Pitfalls: MEDIUM-HIGH - grounded in JVM classfile rules; some reconstruction heuristics remain implementation-dependent.

**Research date:** 2026-03-02
**Valid until:** 2026-04-01
