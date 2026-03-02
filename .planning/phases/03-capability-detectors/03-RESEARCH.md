# Phase 3: Capability Detectors - Research

**Researched:** 2026-03-02
**Domain:** JVM bytecode capability detection (Rust) over Phase 1 evidence + Phase 2 archive metadata
**Confidence:** MEDIUM-HIGH

## User Constraints

No phase `CONTEXT.md` was provided for Phase 3.

Constraints inferred from `.planning/ROADMAP.md` and the Phase 3 prompt:

- Implementation language/runtime remains Rust (Axum server) and existing endpoints (`/upload`, `/scan`, `/scans/{scan_id}`) must remain; response changes must be additive.
- Phase 3 detectors MUST consume Phase 1 evidence (constant-pool strings + resolved invokes with location metadata + limited reconstructed strings) and Phase 2 archive fidelity (nested jar paths, metadata parsing, YARA per entry) instead of lossy text/regex over `.class` bytes.
- Detectors must emit concrete, traceable evidence (class/method/pc + archive entry path) and avoid synthetic placeholders.

## Summary

Phase 3 is best planned as an evidence-indexing + rule evaluation layer: build fast indexes over the Phase 1 `BytecodeEvidence` stream (invokes and strings) plus Phase 2 archive metadata (entry paths, nested jar paths, resource types), then run a suite of capability detectors that each (1) match a small set of bytecode primitives, (2) collect the best evidence locations, and (3) apply false-positive controls via simple gating and correlation.

The practical planning risk is scope creep into deobfuscation / call-graph reconstruction. To keep Phase 3 shippable and reliable, treat detectors as pattern matchers over already-extracted facts, not a general JVM interpreter. Reflection/dynamic loading and outbound networking are extremely common in legitimate mods; the plan should explicitly build in severity modulation and correlation (e.g., reflection + strings naming `java/lang/Runtime` + exec primitive) rather than firing high-severity alerts for single generic signals.

**Primary recommendation:** Implement detectors as data-driven `DetectorSpec` rules evaluated against an `EvidenceIndex` (invokes + strings + archive signals), producing `Indicator` outputs that carry 1..N `Location` callsites and (when present) extracted URL/path/command evidence.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `cafebabe` | 0.9.0 | Parse `.class` and extract invoke tuples with bytecode offsets (Phase 1) | Phase 1 research already standardized on it; detectors depend on its extracted evidence | 
| `serde` / `serde_json` | (repo-pinned) | Persist scan JSON and additive schema evolution | Scan payloads are persisted under `.local-data/scans/*.json` |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `regex` | 1.11 (repo) | URL extraction + small sets of structured token matches | Use for URL parsing and a few patterns; prefer `contains()` for large token lists |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| Large regex suites for everything | Token/substring matching over CP strings | Much lower FP/maintenance cost; faster and easier to explain than complex regexes |

## Architecture Patterns

### Recommended Project Structure

Keep detectors isolated from transport/API code; treat them as a pure function from evidence + archive signals to indicators.

```
src/
├── analysis/
│   ├── evidence.rs                 # Phase 1 schema (Location + BytecodeEvidenceItem)
│   └── classfile_evidence.rs       # Phase 1 extractor
├── detectors/
│   ├── mod.rs                      # registry + shared types
│   ├── index.rs                    # EvidenceIndex builder
│   ├── spec.rs                     # DetectorSpec + matchers (data-driven)
│   ├── capability_exec.rs          # DETC-01
│   ├── capability_network.rs       # DETC-02
│   ├── capability_dynamic_load.rs  # DETC-03
│   ├── capability_fs_modify.rs     # DETC-04
│   ├── capability_persistence.rs   # DETC-05
│   ├── capability_deser.rs         # DETC-06
│   ├── capability_native.rs        # DETC-07
│   └── capability_cred_theft.rs    # DETC-08
└── main.rs                         # HTTP + scan orchestration
```

### Pattern 1: EvidenceIndex + Data-Driven Specs

**What:** Convert raw evidence items into lookup tables, then evaluate declarative detector specs.

**When to use:** Always; it keeps the detector logic simple, testable, and stable as the evidence schema grows.

**Example (index + spec shape):**
```rust
use std::collections::HashMap;

use crate::analysis::evidence::{BytecodeEvidence, BytecodeEvidenceItem, Location};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct InvokeKey {
    pub owner: String,      // internal name, e.g. "java/lang/Runtime"
    pub name: String,       // e.g. "exec"
    pub descriptor: String, // e.g. "(Ljava/lang/String;)Ljava/lang/Process;"
}

pub struct EvidenceIndex<'a> {
    pub invokes: HashMap<InvokeKey, Vec<&'a Location>>,
    pub invokedynamic: Vec<(&'a Location, &'a str, &'a str /* desc */)>,
    pub strings: Vec<(&'a Location, &'a str)>,
}

pub fn build_index(evd: &'_ BytecodeEvidence) -> EvidenceIndex<'_> {
    let mut invokes: HashMap<InvokeKey, Vec<&Location>> = HashMap::new();
    let mut invokedynamic = Vec::new();
    let mut strings = Vec::new();

    for item in &evd.items {
        match item {
            BytecodeEvidenceItem::InvokeResolved { owner, name, descriptor, location } => {
                invokes
                    .entry(InvokeKey {
                        owner: owner.clone(),
                        name: name.clone(),
                        descriptor: descriptor.clone(),
                    })
                    .or_default()
                    .push(location);
            }
            BytecodeEvidenceItem::InvokeDynamic { name, descriptor, location, .. } => {
                invokedynamic.push((location, name.as_str(), descriptor.as_str()));
            }
            BytecodeEvidenceItem::CpUtf8 { value, location }
            | BytecodeEvidenceItem::CpStringLiteral { value, location }
            | BytecodeEvidenceItem::ReconstructedString { value, location } => {
                strings.push((location, value.as_str()));
            }
        }
    }

    EvidenceIndex {
        invokes,
        invokedynamic,
        strings,
    }
}
```

### Pattern 2: Indicator Output Must Reference Locations

**What:** For each capability match, emit an `Indicator` that includes callsite location(s) and the matched primitive(s).

**When to use:** Always; explainability is a Phase 3 success criterion.

**Implementation note:** The current `Indicator` struct in `src/main.rs` only has `file_path: Option<String>` and free-form `evidence: String`. Phase 3 planning should add an additive, structured evidence field (e.g. `evidence_locations`) rather than trying to encode `class/method/pc` into a single string.

### Anti-Patterns to Avoid

- **Hardcoded if/else detector soup:** It becomes untestable and impossible to extend once Phase 4 synergy/scoring wants structured inputs.
- **High-severity for single generic signals:** Reflection and networking are common; build in gating/correlation.
- **Trying to infer “actual owner” behind reflection:** Treat reflection as an indicator primitive and correlate with string evidence; do not attempt full call-graph recovery.

## Evidence to Consume (Inputs)

Phase 3 detector planning should explicitly enumerate the evidence sources and which detectors use them.

### Phase 1: Bytecode evidence

Expected `BytecodeEvidenceItem` variants (per Phase 1 plans):

- `cp_utf8 { value, location(entry_path, class_name, method=None, pc=None) }`
- `cp_string_literal { value, location(...) }`
- `reconstructed_string { value, location(entry_path, class_name, method, pc) }`
- `invoke_resolved { owner, name, descriptor, location(entry_path, class_name, method, pc) }`
- `invoke_dynamic { name, descriptor, bootstrap_attr_index, location(...) }`

Use cases:

- **Primary match keys:** `invoke_resolved` owner/name/descriptor + location.
- **Evidence enrichment:** strings (all string kinds) for URLs, file paths, commands, registry keys, class names.
- **Fallback matching:** reflect/dynamic-load detectors use `Method.invoke` + strings naming sensitive classes/methods.

### Phase 2: Archive/metadata signals

Phase 3 planning should expect these additional inputs (even if Phase 2 names differ in implementation):

- `entry_path` that preserves nested jar paths (e.g. `outer.jar!/lib/inner.jar!/a/b/C.class`).
- parsed manifest + mod metadata fields (names, versions, entrypoints, mixins) to help triage and reduce FP.
- per-entry YARA results already scoped to an entry path.
- raw entry list for resource inspection (e.g. embedded `.dll/.so/.dylib`, `.ps1`, `.bat`, `.sh`, `.service`).

## Detector Catalog (DETC-01..DETC-08)

These are the minimum primitives to cover for Phase 3 planning. The plan should implement at least the JDK primitives first; library-specific coverage can be additive later.

### DETC-01: Process execution primitives

**Invoke primitives (high confidence):**

- `java/lang/Runtime.exec` (multiple overloads)
- `java/lang/ProcessBuilder.start`

**Evidence enrichment:** nearby strings that look like commands (`cmd.exe`, `powershell`, `/bin/sh`, `curl`, `wget`, `java -jar`, etc.) and file paths.

**False-positive control:** default to `high` only when (a) execution primitive exists AND (b) there is at least one command-like string in the same class or method; otherwise mark as `med` (still report; do not suppress).

**Source (API docs):**
- `Runtime`: https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html
- `ProcessBuilder`: https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html

### DETC-02: Outbound networking primitives (+ URL evidence)

**Invoke primitives (high confidence):**

- `java/net/URL.<init>` and `openConnection`
- `java/net/URLConnection.connect`
- `java/net/Socket.<init>` / `connect`
- `java/net/DatagramSocket.send`

**Invoke primitives (medium confidence, newer JDKs):**

- `java/net/http/HttpClient.send` / `sendAsync` (Java 11+)

**URL evidence extraction:** scan bytecode string evidence for:

- `https?://...` URLs
- domains (`example.com`) and IP literals
- suspicious endpoints (`/gate.php`, `/panel`, `/api/`, `/payload`, etc.) should be treated as enrichment only (avoid hardcoding malware-specific endpoints).

**False-positive control:**

- Emit a low/med indicator for network primitives even without a URL string.
- Escalate when URLs/domains exist, or when combined with exec/dynamic load/credential indicators.

**Sources (API docs):**
- `URL`: https://docs.oracle.com/javase/8/docs/api/java/net/URL.html
- `URLConnection`: https://docs.oracle.com/javase/8/docs/api/java/net/URLConnection.html
- `Socket`: https://docs.oracle.com/javase/8/docs/api/java/net/Socket.html

### DETC-03: Dynamic code loading

**Invoke primitives (high confidence):**

- `java/net/URLClassLoader` constructors / `newInstance`
- `java/lang/Class.forName`
- `java/lang/reflect/Method.invoke`
- `java/lang/reflect/Constructor.newInstance`

**Invoke primitives (medium confidence):**

- `java/lang/ClassLoader.defineClass` (direct calls may be rare; common via subclass or method handles)
- `java/lang/invoke/MethodHandles$Lookup.defineClass` (Java 9+)

**Reflection hiding owners:** treat `Method.invoke` as a primitive; then look for string evidence naming:

- class names (`java/lang/Runtime`, `javax/crypto/`, `java/net/URLClassLoader`)
- method names (`exec`, `defineClass`, `loadLibrary`)

**False-positive control:** require correlation for high severity:

- reflection/dynamic-load primitive + sensitive class/method strings, OR
- dynamic-load primitive + network/download evidence.

**Sources (API docs):**
- `URLClassLoader`: https://docs.oracle.com/javase/8/docs/api/java/net/URLClassLoader.html
- `Class`: https://docs.oracle.com/javase/8/docs/api/java/lang/Class.html
- `Method`: https://docs.oracle.com/javase/8/docs/api/java/lang/reflect/Method.html

### DETC-04: Jar/filesystem modification

**Invoke primitives (high confidence):**

- `java/io/FileOutputStream.<init>` / `write`
- `java/nio/file/Files.write` / `newOutputStream` / `move` / `copy` / `delete`
- `java/util/zip/ZipOutputStream.putNextEntry` / `write` / `closeEntry`
- `java/util/jar/JarOutputStream` constructors

**Evidence enrichment:** string evidence for file paths, relative traversal markers (`../`, `..\\`), and suspicious write targets (`.jar`, `mods/`, startup locations).

**False-positive control:** emitting this capability is expected for some packers/updaters; escalate when combined with exec/persistence/native.

**Source (API docs):**
- `ZipOutputStream`: https://docs.oracle.com/javase/8/docs/api/java/util/zip/ZipOutputStream.html
- `Files`: https://docs.oracle.com/javase/8/docs/api/java/nio/file/Files.html
- `FileOutputStream`: https://docs.oracle.com/javase/8/docs/api/java/io/FileOutputStream.html

### DETC-05: Persistence indicators (strings + correlated primitives)

**Primary strategy:** this is mostly string- and path-driven; correlate with exec and/or file write primitives.

**String indicators (high confidence tokens):**

- Windows Run key: `\\Software\\Microsoft\\Windows\\CurrentVersion\\Run` (and HKCU/HKLM prefixes)
- Task scheduler: `schtasks`
- cron markers: `crontab`, `/etc/cron`, `cron.d`
- systemd markers: `/etc/systemd/system`, `systemctl`, `.service`

**False-positive control:** do not emit high severity for tokens alone; require one of:

- exec primitive present in same class/method, OR
- file write primitive present + matching path token.

### DETC-06: Unsafe deserialization sink (vuln-risk)

**Invoke primitive (high confidence):**

- `java/io/ObjectInputStream.readObject`

**Labeling:** treat as a vulnerability risk indicator (not “malware behavior”), since exploitability depends on input sources.

**Source (API docs):**
- `ObjectInputStream`: https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html

### DETC-07: JNI/native library loading

**Invoke primitives (high confidence):**

- `java/lang/System.load`
- `java/lang/System.loadLibrary`

**Archive signals (high confidence):**

- embedded native files: `.dll`, `.so`, `.dylib` (and optionally `.jnilib`)

**False-positive control:**

- `System.loadLibrary` alone is common in legitimate mods with LWJGL; escalate when (a) embedded native lib present OR (b) load path looks user-profile/system directory.

**Source (API docs):**
- `System`: https://docs.oracle.com/javase/8/docs/api/java/lang/System.html

### DETC-08: Credential/token theft indicators

**Strategy:** combine sensitive-path tokens + file read primitives + exfil primitives.

**Sensitive string tokens (medium confidence; validate with fixtures):**

- Discord: `discord`, `Local Storage`, `leveldb`, `tokens`
- Browser stores: `Login Data`, `Cookies`, `Local State`, `User Data`, `Default`
- Minecraft: `.minecraft`, `launcher_profiles.json`, `accounts.json`, `session`

**File read primitives:**

- `java/nio/file/Files.readAllBytes` / `newInputStream`
- `java/io/FileInputStream.<init>`

**False-positive control:** emit low severity for tokens alone; require read primitive + token, and escalate if also network primitive present.

## False-Positive Controls (Planning Checklist)

Build these controls into the detector specs up front; they are the difference between “detects primitives” and “usable signal”.

- **Severity modulation:** split each capability into `primitive_present` (low/med) vs `primitive+enrichment` (med/high).
- **Correlation gates:** persistence requires exec or file-write correlation; credential theft requires read + sensitive token + (optional) network.
- **Result dedup:** merge multiple hits of the same capability into one indicator with multiple locations (cap count + evidence list), rather than spamming many indicators.

## Indicator Schema Fields Needed for Explainability

Current `Indicator` schema is insufficient for Phase 3 explainability (it cannot represent class/method/pc cleanly). Planning should add an additive structure, for example:

- `evidence_locations: Vec<Location>` (Phase 1 `Location` reused directly)
- `evidence_kinds: Vec<String>` or `evidence_refs: Vec<BytecodeEvidenceRef>` where:
  - `BytecodeEvidenceRef { kind: String, owner: Option<String>, name: Option<String>, descriptor: Option<String>, value: Option<String>, location: Location }`
- `extracted: { urls?: Vec<String>, file_paths?: Vec<String>, commands?: Vec<String> }` (optional)

Minimum for Phase 3 success criteria:

- a capability indicator must cite at least one callsite `Location` with `entry_path`, `class_name`, `method`, and `pc` when the trigger is an invoke.

## Common Pitfalls

### Pitfall 1: Reflection/network are ubiquitous (FP explosion)
**What goes wrong:** Every mod gets flagged as “dynamic loading” or “exfiltration”.
**Why it happens:** Primitive APIs are used legitimately; the maliciousness is in correlation and target evidence.
**How to avoid:** Use severity modulation + correlation gates; require sensitive string evidence for high severity.

### Pitfall 2: URLs are often not string literals
**What goes wrong:** You detect network primitives but never surface URL evidence.
**Why it happens:** URLs may be reconstructed, concatenated, or decoded.
**How to avoid:**
- scan all string evidence kinds (Utf8 + String + reconstructed) for URLs/domains
- treat “no URL found” as expected and still emit the primitive capability

### Pitfall 3: `invokedynamic` misinterpretation
**What goes wrong:** Mis-attributing owners for lambdas, or treating `invokedynamic` as a normal invoke.
**Why it happens:** `invokedynamic` has a bootstrap method indirection.
**How to avoid:**
- ignore `invokedynamic` for capability matching unless you have an explicit rule for its name/descriptor
- rely on resolved invokes + strings for most capability signals

### Pitfall 4: Nested jar paths get lost
**What goes wrong:** Evidence points to `a/b/C.class` but not which nested jar it came from.
**Why it happens:** Archive scanners frequently flatten paths.
**How to avoid:** treat nested path preservation as a contract for Phase 2 and propagate `entry_path` into `Location` for all evidence.

## Code Examples

Verified patterns to reference during planning/implementation.

### Match an invoke primitive and emit an indicator with locations
```rust
fn detect_process_exec(index: &EvidenceIndex<'_>) -> Vec<(String /* id */, Vec<&Location>)> {
    let mut out = Vec::new();

    // Match by owner+name; in practice include all overload descriptors for Runtime.exec.
    for (key, locs) in &index.invokes {
        if key.owner == "java/lang/Runtime" && key.name == "exec" {
            out.push(("DETC-01.RUNTIME_EXEC".to_string(), locs.clone()));
        }
        if key.owner == "java/lang/ProcessBuilder" && key.name == "start" {
            out.push(("DETC-01.PROCESSBUILDER_START".to_string(), locs.clone()));
        }
    }

    out
}
```

### Extract URL evidence from bytecode-derived strings
```rust
use regex::Regex;

fn extract_urls(strings: &[(&Location, &str)]) -> Vec<String> {
    // Keep this intentionally conservative to reduce FP.
    let re = Regex::new(r"(?i)https?://[a-z0-9][a-z0-9._-]*\.[a-z]{2,}[^\s\"'<>]*").unwrap();

    let mut urls = Vec::new();
    for (_loc, s) in strings {
        for m in re.find_iter(s) {
            urls.push(m.as_str().to_string());
        }
    }

    urls.sort();
    urls.dedup();
    urls
}
```

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Full bytecode interpreter | A general JVM abstract interpreter or decompiler | Phase 1 evidence + simple pattern matchers | High complexity; Phase 3 only needs primitive detection and evidence correlation |
| Reflection call resolution | Custom reflective call-graph recovery | Reflection primitive + string correlation | Real-world obfuscation makes it unreliable; false certainty is worse than partial signal |
| Complex URL parsing | RFC-grade URL parsing/normalization | Conservative regex + raw URL evidence | Phase 3 requirement is “include URL evidence when present”, not normalization |

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Regex over lossy `.class` bytes | Detectors over bytecode-derived evidence (invokes + strings + locations) | Phase 3 | Evidence is explainable and resilient to classfile structure |

## Open Questions

1. **Where do Phase 3 indicators live in the response?**
   - What we know: response changes must be additive only.
   - What's unclear: whether Phase 3 capabilities should replace existing `static_findings.matches` or be added alongside (e.g. `capability_findings`).
   - Recommendation: add capabilities as additional `Indicator` entries with `source="detector"` and keep existing demo-grade patterns until Phase 4 reworks scoring.

2. **What exact Phase 2 metadata shape is guaranteed?**
   - What we know: nested jar recursion + per-entry YARA + metadata parsing are Phase 2 goals.
   - What's unclear: the exact structs available to Phase 3 detectors.
   - Recommendation: plan Phase 3 against a minimal contract: stable `entry_path` (including nested path) + entry bytes + (optional) metadata map.

## Sources

### Primary (HIGH confidence)
- JVM Specification (classfile + descriptors): https://docs.oracle.com/javase/specs/jvms/se21/html/
- Phase 1 research (repo-local): `.planning/phases/01-bytecode-evidence-core/01-RESEARCH.md`
- Phase 1 plans (repo-local): `.planning/phases/01-bytecode-evidence-core/01-bytecode-evidence-core-01-PLAN.md`, `02-PLAN.md`, `03-PLAN.md`

### Secondary (MEDIUM confidence)
- Oracle Java SE 8 API docs (used for method names/owners):
  - `Runtime`: https://docs.oracle.com/javase/8/docs/api/java/lang/Runtime.html
  - `ProcessBuilder`: https://docs.oracle.com/javase/8/docs/api/java/lang/ProcessBuilder.html
  - `URLClassLoader`: https://docs.oracle.com/javase/8/docs/api/java/net/URLClassLoader.html
  - `ObjectInputStream`: https://docs.oracle.com/javase/8/docs/api/java/io/ObjectInputStream.html
  - `ZipOutputStream`: https://docs.oracle.com/javase/8/docs/api/java/util/zip/ZipOutputStream.html

### Tertiary (LOW confidence)
- Perplexity WebUI MCP failed in this environment (tool returned an error), so no cross-verification from that channel was possible.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - Phase 1 already standardized parsing + evidence schema via `cafebabe`.
- Architecture: HIGH - evidence-index + detector specs directly support explainable detectors and future Phase 4 scoring.
- Pitfalls/FP controls: MEDIUM - grounded in common JVM/mod patterns, but will need validation against fixtures in Phase 6.

**Research date:** 2026-03-02
**Valid until:** 2026-04-01
