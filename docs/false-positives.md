# False Positives: Case Studies And Fixes

This doc captures a couple real false-positive classes seen during benchmarking, and the concrete prompt/detector changes that reduced them.

## Case Study: OptiFine

### Why it was flagged

OptiFine contains signals that look scary out of context:

- Network access (version checks, capes, crash reporting URLs)
- Process execution (opening links / shader pack folders on some platforms)

Those are exactly the kinds of primitives malware uses too, so naive scoring tends to label it high risk.

### What fixed it

Prompt changes in `src/verdict.rs`:

- Added an explicit list of legitimate patterns (hardware probing, URL openers, plugin systems)
- Strengthened the rule that single primitives are usually benign and that MALICIOUS requires combinations (credential theft + network, persistence + execution, etc.)
- Required the explanation to cite concrete evidence and use extracted artifacts (URLs/domains/commands/paths) to justify benign vs malicious

Net effect:

- OptiFine can still show `execution` + `network`, but if extracted artifacts are consistent with update checks / optifine.net endpoints and there is no credential theft / persistence, the AI should output CLEAN (or at worst SUSPICIOUS).

## Case Study: ModernFix

### Why it was flagged

ModernFix is a performance + compatibility mod and commonly triggers:

- Dynamic loading / reflection (compat layers)
- Filesystem access (configs, caches)

### What fixed it

Detector/prompt framing changes:

- Capability presence is only set by medium/high detector signals (low-only detector hits get routed to `low_signal_indicators`) (see `src/profile.rs`)
- The AI prompt explicitly marks filesystem access for config/caches and dynamic loading for compatibility as not inherently malicious (see `src/verdict.rs`)

Net effect:

- The scan still records the evidence, but the AI verdict should downgrade it to CLEAN unless paired with clear malicious indicators (credential theft, persistence, high/critical YARA hits).

## Case Study: Entity Texture Features (ETF)

### Why it was flagged

ETF (and related rendering mods) often contain:

- Reflection / dynamic class usage
- Optional network interactions (update checks, external links)

### What fixed it

Prompt changes in `src/verdict.rs`:

- Whitelisted common rendering-mod behaviors (reflection for compatibility, exec for GPU probing / desktop integration)
- Made MALICIOUS depend on combinations + malware-specific indicators (YARA high/critical, credential theft strings/paths)

## Case Study: FancyMenu

### Why it was flagged

FancyMenu contains error message strings that reference PowerShell/cmd.exe syntax (e.g. stack traces, diagnostic messages). The exec detector (`DETC-01`) was treating these strings as evidence of shell command execution, escalating to `high` severity.

### What fixed it

The `is_command_like_string()` filter in `src/detectors/capability_exec.rs` was added to distinguish real command strings from incidental mentions:

- Rejects strings that look like error messages (contain `Exception`, `Error`, stack trace markers)
- Rejects strings that look like class names or package paths (mostly dots/slashes with no whitespace)
- Requires the string to have a command-like structure (begins with a known shell/binary name followed by arguments)

This eliminated the false positive without weakening detection of actual `Runtime.exec()` calls with real shell commands.

## Case Study: tr7zw Mods (3DSkinLayers, EntityCulling, NotEnoughAnimations)

### Why they were flagged

tr7zw's mods (notably 3DSkinLayers, EntityCulling, NotEnoughAnimations) triggered multiple signals:

- **Unsafe deserialization** (`DETC-06`): `ObjectInputStream.readObject()` present in utility code
- **Network I/O** (`DETC-02`): update checks and external URLs

The AI was treating the combination of deserialization + network as suspicious, leaning toward SUSPICIOUS or even MALICIOUS.

### What fixed it

Two changes:

1. **AI prompt tuning** in `src/verdict.rs`: explicitly instructs the AI that deserialization is a *vulnerability risk* (BleedingPipe-style), not a malware indicator by itself. It should not contribute to a MALICIOUS verdict unless combined with credential theft, persistence, or other exfiltration signals.

2. **NeoForge metadata parsing** in `src/profile.rs`: several tr7zw mods use `META-INF/neoforge.mods.toml`. Without NeoForge support, metadata was missing, making the AI less confident the jar was a legitimate mod. Adding NeoForge parsing provided the mod identity context the AI needed.

## How to Keep This Under Control

- Prefer dataset-driven regression: keep the Modrinth top-50 benign corpus and re-scan when changing detectors/prompts.
- Watch for drift: if a detector tweak increases `execution` or `network` prevalence, verify the AI still explains why it is benign on known-good mods.
- The benign benchmark (50/50 CLEAN) should be re-run after any detector or prompt change.
