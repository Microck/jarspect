# Phase 2: Archive + YARA Fidelity - Research

**Researched:** 2026-03-02
**Domain:** Recursive JAR (ZIP) traversal + mod metadata parsing + YARA-X per-entry evidence + severity mapping (Rust)
**Confidence:** HIGH

<user_constraints>
## User Constraints

No phase `CONTEXT.md` was provided for Phase 2.

Constraints derived from the phase goal/requirements and success criteria:

- **Goal:** The scan pipeline accurately understands archive structure (including nested jars) and produces entry-scoped YARA evidence with trustworthy severities.
- **Requirements:** ARCH-01, ARCH-02, YARA-01, YARA-02, YARA-03
- **Success criteria:**
  - Embedded jar scanning produces findings from nested jar (evidence shows nested path).
  - Scan output includes parsed mod metadata + manifest signals and flags inconsistencies / high-suspicion attributes.
  - YARA-X runs per inflated archive entry (classes/resources), evidence references the entry path.
  - YARA severities come from rule metadata (or defined conventions) and demo vs production rulepacks are separated.
</user_constraints>

## Summary

Phase 2 is mainly about **trustworthy location and provenance**: every static finding (especially YARA) must point at the exact inflated entry it matched, even when that entry lives inside an embedded jar. The simplest planning model is: treat a jar as a tree of jars, but **emit a flattened stream of entries** where each entry has a *fully qualified nested path* (e.g. `outer.jar!/META-INF/jars/inner.jar!/com/acme/A.class`). YARA, token signatures, regex patterns, and Phase-1 bytecode evidence can then run against the same flattened stream without special casing.

YARA-X already exposes rule metadata via `Rule::metadata()` in the Rust API (inspected locally in the `yara-x` crate source). Severity should be derived from `meta.severity` when present; otherwise fall back to a small, explicitly-defined convention (e.g., `meta.threat_level` int or severity tags), and only then a default.

**Primary recommendation:** Implement `read_archive_entries_recursive()` that (1) enforces strict archive limits (zip-bomb/size/depth), (2) tracks nested paths as a structured type with a stable string rendering, (3) parses a minimal set of metadata files (Fabric/Forge/Spigot + MANIFEST.MF) into explicit “metadata indicators”, and (4) maps YARA severity from rule metadata with clear fallbacks and rulepack separation.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `zip` | 2.4.2 | Read JARs as ZIPs and inflate entries | Existing implementation uses `zip::ZipArchive`; provides per-entry `compressed_size()` and `size()` to implement zip-bomb guards (HIGH confidence from crate source) |
| `yara-x` | 1.13.0 | Compile and scan YARA rules in Rust | Existing code uses `yara_x::{Compiler, Rules, Scanner}`; matching rules expose `Rule::metadata()`, `Rule::tags()`, and match ranges for evidence (HIGH confidence from crate source) |
| `serde_json` | (existing) | Parse `fabric.mod.json` | Already in repo; required for Fabric metadata parsing |

### Supporting
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `toml` | 1.0.3+spec-1.1.0 | Parse `META-INF/mods.toml` | Needed for Forge mod metadata (ARCH-02) |
| `yaml_serde` | 0.10.3 | Parse `plugin.yml` | Prefer a maintained YAML+Serde crate; `serde_yaml` is published as `0.9.34+deprecated` in crates.io |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| YAML crate | Hand-parse plugin.yml | Not recommended: YAML edge cases (quoting, lists) are easy to mis-handle; plugin.yml is “simple” but YAML is not |
| Nested-jar detection | Only scan `fabric.mod.json` `jars[]` entries | Misses embedded jars in non-Fabric layouts or payload jars not declared in metadata; use declared jars as a strong hint, but keep a heuristic fallback |

## Architecture Patterns

### Recommended Project Structure
Phase 2 introduces recursion + metadata parsing + YARA mapping; keep it behind obvious boundaries so Phase 3+ can reuse the same archive model.

```
src/
├── analysis/
│   ├── mod.rs
│   ├── archive.rs          # recursive jar reading + limits + nested path
│   ├── metadata.rs         # fabric/mods.toml/plugin.yml/MANIFEST.MF parsing
│   └── yara.rs             # rule loading, pack separation, severity extraction
└── main.rs                 # HTTP + orchestration
```

### Pattern 1: Flattened Entry Stream With Structured Nested Paths
**What:** Recursively traverse nested jars but emit a single `Vec<ArchiveEntry>` where each entry has a stable, nested path string.
**When to use:** Always before running any matchers (patterns/signatures/YARA/bytecode). This ensures YARA-01 and the nested-jar success criterion.
**Key design choice (nested path rendering):** Use the common jar URL delimiter `!/` between archive layers.

Example nested path string:

- `outer.jar!/META-INF/jars/inner.jar!/com/acme/A.class`

**Recursion boundaries (recommended defaults):**

- Max recursion depth: 3
- Max number of total entries traversed (across all jars): 50_000
- Max per-entry uncompressed size: 16 MiB (lower for “text” entries if needed)
- Max total inflated bytes (across all entries): 256 MiB
- Compression ratio guard: if `uncompressed_size / compressed_size` is extremely high, fail/skip (zip bomb heuristic)

Source for uncompressed vs compressed sizes: `ZipFile::size()` and `ZipFile::compressed_size()` in `zip` crate (`zip-2.4.2/src/read.rs`).

### Pattern 2: “Jar Unit” Metadata Parsing (ARCH-02)
**What:** Parse metadata files at each jar boundary, generate explicit “metadata indicators”, and cross-check referenced entrypoints/classes exist *within that jar*.
**When to use:** On the outer jar and any embedded jar that appears to be a mod/plugin jar (metadata file present).

Minimum set to implement (per quality gate):

- `fabric.mod.json` (Fabric/Quilt ecosystem)
- `META-INF/mods.toml` (Forge)
- `plugin.yml` (Spigot/Bukkit)
- `META-INF/MANIFEST.MF` (JAR manifest)

### Pattern 3: YARA Per-Entry With Rule-Metadata Severity (YARA-02)
**What:** For each matching YARA rule, derive severity from rule metadata, and include nested entry path in evidence.
**When to use:** For every inflated entry (classes/resources), including nested jar entries.

Relevant YARA-X API (crate source):

- `scan_results.matching_rules()` yields `Rule`
- `Rule::identifier()` yields rule name
- `Rule::metadata()` yields iterator of `(ident, MetaValue)`
- `Rule::tags()` yields tags
- `Rule::patterns()` + `Pattern::matches()` yields match ranges and bytes for richer evidence

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| YAML parsing | Custom plugin.yml parser | `yaml_serde` | YAML quoting/lists/escaping are deceptively complex |
| TOML parsing | Custom mods.toml parser | `toml` | TOML tables/arrays-of-tables should be parsed correctly for `[[mods]]` and dependency blocks |
| Zip-bomb safety | “Just read_to_end everything” | Enforced archive limits using `ZipFile::size()` and `compressed_size()` | ZIP inflation can exceed upload size by orders of magnitude; must guard |
| YARA severity mapping | Hardcode `high` | Rule metadata (`meta.severity`) + explicit fallback conventions | Makes severities trustworthy and testable |

**Key insight:** The archive layer is a *security boundary*. Limits and provenance must be designed first; detector logic should not be forced to care about ZIP/JAR edge cases.

## Common Pitfalls

### Pitfall 1: Zip bombs and “inflation surprises”
**What goes wrong:** A small upload inflates to huge memory usage because every entry is read into a `Vec<u8>`.
**Why it happens:** ZIP/JAR compression ratio can be extreme; nested jars compound the expansion.
**How to avoid:** Enforce hard caps using `ZipFile::size()` (uncompressed) and `ZipFile::compressed_size()` before reading. Cap total inflated bytes across recursion.
**Warning signs:** OOM / very slow scans on small uploads; scan time grows superlinearly with nesting.

### Pitfall 2: Unbounded recursion / cycles via nested jar references
**What goes wrong:** Recursion never terminates (or hits stack/memory limits) on maliciously crafted jar-in-jar layouts.
**Why it happens:** “Scan any *.jar you see” without depth/entry-count limits.
**How to avoid:** Max depth + max nested jar count + global budget (entries + inflated bytes). Optionally, hash nested jar bytes to deduplicate repeat payloads.
**Warning signs:** Many repeated embedded jars, deep `META-INF/jars/.../jars/...` structures.

### Pitfall 3: Trusting metadata without verifying referenced classes exist
**What goes wrong:** Metadata claims safe entrypoints but points to missing classes (or points to a tiny stub while payload lives elsewhere).
**Why it happens:** Metadata parsing is treated as informational only.
**How to avoid:** Always cross-check entrypoint class names against jar entries. Flag missing classes as a metadata integrity finding.
**Warning signs:** `fabric.mod.json` entrypoint values that do not map to any `.class` entry; `plugin.yml` `main` class missing.

### Pitfall 4: Severity drift between rulepacks and UI
**What goes wrong:** Rules emit `medium` but the system expects `med`; UI normalizer fails or scoring misweights.
**Why it happens:** Severity mapping isn’t canonicalized at ingestion.
**How to avoid:** Canonicalize to the backend’s known set (`critical|high|med|low|info`) and treat unknowns as `med` (or explicitly “unknown”).
**Warning signs:** Counts by severity show unexpected buckets; UI shows “unknown” badges.

## Code Examples

### Extract severity from YARA rule metadata (yara-x)
```rust
use yara_x::{MetaValue, Rule};

fn canonical_severity(s: &str) -> Option<&'static str> {
    match s.to_ascii_lowercase().as_str() {
        "critical" => Some("critical"),
        "high" => Some("high"),
        "medium" | "med" => Some("med"),
        "low" => Some("low"),
        "info" | "informational" => Some("info"),
        _ => None,
    }
}

fn yara_severity(rule: &Rule<'_, '_>) -> Option<&'static str> {
    // Primary: meta.severity = "high" (string)
    for (k, v) in rule.metadata() {
        if k.eq_ignore_ascii_case("severity") {
            if let MetaValue::String(s) = v {
                if let Some(sev) = canonical_severity(s) {
                    return Some(sev);
                }
            }
        }
    }

    // Fallback: meta.threat_level = 1..5 (int) if the rulepack uses it.
    for (k, v) in rule.metadata() {
        if k.eq_ignore_ascii_case("threat_level") {
            if let MetaValue::Integer(n) = v {
                return Some(match n {
                    5 => "critical",
                    4 => "high",
                    3 => "med",
                    2 => "low",
                    _ => "info",
                });
            }
        }
    }

    // Optional fallback: tags can encode severity (rule : high)
    for tag in rule.tags() {
        if let Some(sev) = canonical_severity(tag.identifier()) {
            return Some(sev);
        }
    }

    None
}
```
Source: `yara-x` crate API inspected locally (`yara-x-1.13.0/src/models.rs`, `yara-x-1.13.0/src/scanner/mod.rs`).

### Include entry-scoped YARA evidence with offsets (optional richer evidence)
```rust
use yara_x::Rule;

fn yara_match_evidence(rule: &Rule<'_, '_>) -> String {
    let mut parts = Vec::new();
    for pat in rule.patterns() {
        for m in pat.matches().take(3) {
            parts.push(format!(
                "{}@{}..{}",
                pat.identifier(),
                m.range().start,
                m.range().end
            ));
        }
    }
    if parts.is_empty() {
        format!("Matched rule {}", rule.identifier())
    } else {
        format!("Matched rule {} ({})", rule.identifier(), parts.join(", "))
    }
}
```
Source: `yara-x` crate API inspected locally (`yara-x-1.13.0/src/models.rs`).

## Metadata Parsing: Minimal Checks + Suspicious Flags

### Fabric (`fabric.mod.json`)
Verified from Fabric Wiki spec:

- Mandatory: `id` matches `^[a-z][a-z0-9-_]{1,63}$`, `version` string.
- Entry points: `entrypoints` object; keys include `main`, `client`, `server`; values are strings or objects with a `value` string (format `my.package.MyClass` or `my.package.MyClass::thing`).
- Nested jars: `jars` is an array of objects where `file` is mandatory and points to the nested jar path.

Flag as suspicious / inconsistent:

- `entrypoints.*` references a class that does not exist as an entry (convert dotted `a.b.C` to `a/b/C.class`).
- `jars[].file` points to a missing entry, or points to a non-jar (does not look like ZIP magic).
- No metadata file exists in the outer jar but the jar contains lots of `.class` and/or known mod APIs (this is heuristic; keep severity low unless corroborated).

Source: https://wiki.fabricmc.net/documentation:fabric_mod_json_spec

### Forge (`META-INF/mods.toml`)
Verified from Forge docs:

- File location: `src/main/resources/META-INF/mods.toml` in a typical project; in the jar it lives under `META-INF/mods.toml`.
- Non-mod-specific mandatory properties: `modLoader`, `loaderVersion`, `license`.
- Mod section: `[[mods]]` array of tables; per-mod mandatory `modId` with pattern `^[a-z][a-z0-9_]{1,63}$`.

Flag as suspicious / inconsistent:

- `[[mods]].modId` exists but is invalid format.
- Multiple `[[mods]]` entries with surprising `modId` mismatches vs jar name or vs package namespace frequency.
- If a mod declares `version = "${file.jarVersion}"`, cross-check `Implementation-Version` exists in MANIFEST.MF (else it displays as `0.0NONE` in some contexts per docs).

Source: https://docs.minecraftforge.net/en/latest/gettingstarted/modfiles/

### Spigot/Bukkit (`plugin.yml`)
Verified from Spigot wiki:

- Required attributes: `main`, `name`, `version`.
- `main` must be the fully qualified class name of the plugin class.
- `name` must be alphanumeric + underscore.

Flag as suspicious / inconsistent:

- `main` class does not exist in the jar.
- `name` is invalid or differs wildly from jar base name.

Source: https://www.spigotmc.org/wiki/plugin-yml/

### JAR Manifest (`META-INF/MANIFEST.MF`)
Flag as high-suspicion (mod context) if any of these attributes exist:

- `Premain-Class`
- `Agent-Class`
- `Can-Redefine-Classes`
- `Can-Retransform-Classes`
- `Boot-Class-Path`

Rationale: These are typical for Java agents/instrumentation; uncommon for Minecraft mods/plugins and worth an explicit indicator.

## Rulepack Separation (YARA-03)

Current repo state:

- Demo-only rules live at `data/signatures/rules.yar` and signatures at `data/signatures/signatures.json`.

Recommended separation that preserves demo flow:

- Keep demo pack as the default to avoid breaking existing demo UX.
- Add a parallel production pack in a different folder (or filename), and load it optionally via an env var/config.
- Ensure scan output can *distinguish* which pack fired without requiring schema changes.

Prescriptive approach:

- File layout:
  - `data/signatures/demo/rules.yar`
  - `data/signatures/demo/signatures.json`
  - `data/signatures/prod/rules.yar`
  - `data/signatures/prod/signatures.json`

- Output ID conventions:
  - Demo YARA: `YARA-DEMO-<RULE_IDENTIFIER>`
  - Prod YARA: `YARA-PROD-<RULE_IDENTIFIER>`
  - Demo signatures: `SIG-DEMO-...`
  - Prod signatures: `SIG-PROD-...`

This keeps the current `Indicator` schema stable while ensuring demo IOCs never get mistaken for production detections.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| Scan whole jar blob with YARA | Scan each inflated entry with YARA | (Phase 2) | Required to hit patterns inside compressed ZIP members and produce entry-scoped evidence |
| Hardcoded YARA severity | Severity from rule metadata (`meta.severity`) | (Phase 2) | Makes severity trustworthy and rulepack-controlled |

## Open Questions

1. **What are the exact archive safety limits for production?**
   - What we know: upload cap is 50 MB; zip inflation can exceed this.
   - What’s unclear: acceptable max inflated bytes / recursion depth / entry count.
   - Recommendation: set conservative defaults (as above) and expose as constants; add metrics/logging for limit hits.

2. **Should nested jar detection prioritize declared Fabric `jars[]` entries?**
   - What we know: Fabric spec defines `jars` with mandatory `file` pointing to nested jars.
   - What’s unclear: whether scanning *all* embedded jars is too expensive/noisy.
   - Recommendation: prefer declared `jars[]` first, but still scan other `*.jar` entries within budget.

3. **What is the production severity convention for YARA rules?**
   - What we know: YARA-X supports arbitrary meta; `Rule::metadata()` exposes it.
   - What’s unclear: whether production pack will use `severity` strings, `threat_level` ints, or tags.
   - Recommendation: implement `severity` string first, then support `threat_level` and tags as fallbacks.

## Sources

### Primary (HIGH confidence)
- Local crate source: `yara-x-1.13.0/src/models.rs` (rule metadata + pattern matches)
- Local crate source: `yara-x-1.13.0/src/scanner/mod.rs` (matching rule iterator)
- Local crate source: `zip-2.4.2/src/read.rs` (`ZipFile::size()` and `ZipFile::compressed_size()`)
- Repo implementation: `src/main.rs` (`read_archive_entries`, per-entry YARA scan, current hardcoded severity)

### Secondary (MEDIUM confidence)
- Fabric mod JSON spec: https://wiki.fabricmc.net/documentation:fabric_mod_json_spec
- Forge `mods.toml` docs: https://docs.minecraftforge.net/en/latest/gettingstarted/modfiles/
- Spigot `plugin.yml` docs: https://www.spigotmc.org/wiki/plugin-yml/

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH - versions verified via `Cargo.lock` and local crate source inspection
- Architecture: HIGH - derived from current repo pipeline and well-bounded recursion/limit patterns
- Pitfalls: HIGH - zip inflation/recursion/severity canonicalization are concrete failure modes for this domain

**Research date:** 2026-03-02
**Valid until:** 2026-04-01 (re-check crate versions and docs monthly)
