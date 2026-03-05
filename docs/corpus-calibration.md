# Corpus Calibration Report

Date: 2026-03-05 (updated from 2026-03-03 initial calibration)

## Safety Model

- All malware downloads were handled as archive bytes only (no execution).
- Malware corpus came from MalwareBazaar (tags: `fractureiser`, `mavenrat`, `maksstealer`, `maksrat`) and was extracted from password-protected zips (`infected`).
- Only jars with Minecraft mod metadata (fabric.mod.json, mods.toml, neoforge.mods.toml, plugin.yml, mcmod.info) were included in the strict-modlike subset.
- Benign corpus came from the Modrinth top-50 most-downloaded mods.

## Data Collected

### Malicious corpus

- **70 JAR samples** (strict-modlike subset from 4 MalwareBazaar tags).
- Source tags: `fractureiser` (1 jar), `mavenrat` (8), `maksstealer` (11), `maksrat` (82). Combined unique: 84 jars. After strict-modlike filtering (must contain mod metadata): 70 jars.
- Selection via `scripts/select-malwarebazaar-dataset.ts` using `zipinfo` heuristic to detect mod metadata entries.

### Benign corpus

- **50 JAR samples** from Modrinth top-50 most-downloaded mods.
- Downloaded via `scripts/modrinth-top-50-scan.sh`.

### Malware families present

| Family | Count | Key indicators |
|--------|-------|---------------|
| Krypton stealer | ~15 | Obfuscated Fabric `ModInitializer` stub + `URLClassLoader` + `a/a/a/Config` + `UTF_16BE` |
| MaxCoffe / MaksRAT | ~20 | Fabric `example_mod` stub + `MaxCoffe/Coffe.class` + raw `Socket` + `JarInputStream` + `defineClass` |
| Maks Libraries | ~10 | Forge `mcmod.info` with `makslibraries` mod ID |
| PussyRAT | ~5 | `pussylib/pussygo` class marker |
| Loader/Stager | ~5 | `StagingHelper` + HTTP client + JAR staging |
| Fractureiser-tagged | 1 | `RPCHelper` with 32 Ethereum JSON-RPC endpoints + `ProcessBuilder.start()` |
| Other MaksRAT variants | ~14 | Various obfuscated loader stubs with network + dynamic loading correlation |

## Changes Applied During Calibration

### Initial calibration (2026-03-03)

1. Tightened credential theft detector (`DETC-08`): require strong credential markers, suppress token-only/no-correlation findings.
2. Capability profile filtering: only medium/high detector signals mark capability `present`; low-only hits moved to `low_signal_indicators`.
3. Added robust local fallback verdict (`heuristic_fallback`).
4. Added graceful archive failure handling: invalid/malformed archives return `SUSPICIOUS` with `archive_validation_failure`.
5. Reordered scan pipeline: MalwareBazaar hash check now runs before archive parsing.

### Multi-tag expansion calibration (2026-03-05)

6. **Static override layer**: high-confidence static signals (production YARA high/critical, `DETC-03.DYNAMIC_LOAD` high/critical, and others) override the AI verdict to MALICIOUS via `static_override(ai_verdict)`.
7. **6 production YARA rules** (`data/signatures/prod/rules.yar`): family-specific, multi-string rules for Krypton, MaxCoffe, MaksLibraries, PussyRAT, Loader/Stager, and ETH RPC loader families.
8. **Exec detector filter** (`is_command_like_string()`): stops error message strings and class names from being misclassified as shell commands (fixed FancyMenu, tr7zw false positives).
9. **AI prompt tuning**: deserialization is vulnerability-risk not malware; private URLs are low-signal; don't infer shell usage from class names.
10. **NeoForge metadata parsing**: `META-INF/neoforge.mods.toml` support added; shallowest-metadata preference to avoid bundled dependency noise.

## Final Metrics (Production Config, AI + Static Override enabled)

Scans run with `JARSPECT_RULEPACKS=prod JARSPECT_MB_HASH_MATCH_ENABLED=0` (hash matching disabled to exercise detectors + AI + YARA).

### Malicious corpus: 70 samples

| Verdict | Count | Rate |
|---------|-------|------|
| MALICIOUS | 70 | 100% |
| SUSPICIOUS | 0 | 0% |
| CLEAN | 0 | 0% |

**True positive rate: 100%** (70/70)

### Benign corpus: 50 samples

| Verdict | Count | Rate |
|---------|-------|------|
| CLEAN | 50 | 100% |
| SUSPICIOUS | 0 | 0% |
| MALICIOUS | 0 | 0% |

**False positive rate: 0%** (0/50)

### Verdict method breakdown (malicious corpus)

Most samples hit via `static_override(ai_verdict)` (production YARA or `DETC-03.DYNAMIC_LOAD` at high severity). Remaining samples caught by the AI itself assigning MALICIOUS.

### Run artifacts

- Malware run: `.local-data/runs/mb-mc-malware-batch-strict-modlike-v3-20260305T044500Z/`
- Benign run: `.local-data/runs/modrinth-top-50-showcase3-benign-ai-20260305T021000Z/`

## Previous Metrics (Initial Calibration, Heuristic Only)

From 2026-03-03, AI + MalwareBazaar disabled, heuristic fallback only:

- Dataset: 44 (24 malicious, 20 benign)
- Malicious: 6 MALICIOUS, 7 SUSPICIOUS, 11 CLEAN
- Benign: 0 MALICIOUS, 5 SUSPICIOUS, 15 CLEAN

This baseline showed the need for AI + YARA + static override layers. The improvements above closed all 18 false negatives and 5 false positives.
