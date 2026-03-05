# Benchmarking And Reporting

This doc describes how to:

- Run Modrinth top-N scans with per-run artifacts under `.local-data/`
- Run local directory scans (benign + malicious)
- Aggregate a run into `aggregate.csv` + `summary.json` for graphing

## Safety

- Treat all malware jars as inert bytes. Never execute them.
- Keep downloaded malware under `.local-data/` only.

## 1) Modrinth Top-N Scan

Prereqs:

- Start the server: `cargo run`
- Ensure `.env` is configured for your desired rulepacks/AI.

Run:

```bash
LIMIT=200 bash scripts/modrinth-top-50-scan.sh
```

Outputs (example):

- `.local-data/runs/modrinth-top-200-<timestamp>/run.json`
- `.local-data/runs/modrinth-top-200-<timestamp>/results.csv`
- `.local-data/runs/modrinth-top-200-<timestamp>/json/*-scan.json`
- `.local-data/runs/modrinth-top-200-<timestamp>/jars/*.jar`

Notes:

- `results.csv` is intended as the primary index for graphs.
- Per-sample `*-scan.json` contains the persisted scan payload used by aggregation.

## 2) Local Directory Scan Runner

Use this when you already have jars (for example `corpus/benign` or a downloaded malware set).

```bash
bash scripts/scan-local-dir.sh benign corpus/benign
```

Output run directory:

- `.local-data/runs/benign-<timestamp>/run.json`
- `.local-data/runs/benign-<timestamp>/results.csv`
- `.local-data/runs/benign-<timestamp>/json/<sha256>-scan.json`
- `.local-data/runs/benign-<timestamp>/jars/<sha256>--<filename>.jar`

## 3) MalwareBazaar Corpus Acquisition

### Single-tag download

Downloads password-protected zips (password: `infected`) and extracts jars for a single MalwareBazaar tag.

```bash
TAG=minecraft TARGET_TOTAL=50 bash scripts/fetch-malwarebazaar-minecraft.sh
```

Outputs:

- `.local-data/malwarebazaar/queries/*.json` (API query payloads)
- `.local-data/malwarebazaar/zips/*.zip` (downloaded archives)
- `.local-data/malwarebazaar/extracted/<sha256>/...` (temporary extraction)
- `.local-data/malwarebazaar/jars/*.jar` (extracted jars)

### Multi-tag download (recommended for larger corpus)

The `tag=minecraft` query only returns ~24 jar samples. To build a meaningful malware corpus, download from multiple related tags:

```bash
# Download each tag into its own directory
for TAG in fractureiser mavenrat maksstealer maksrat; do
  TAG=$TAG bash scripts/malwarebazaar-download.sh
done
```

This creates per-tag directories:

- `.local-data/malwarebazaar/fractureiser/` (1 jar)
- `.local-data/malwarebazaar/mavenrat/` (8 jars)
- `.local-data/malwarebazaar/maksstealer/` (11 jars)
- `.local-data/malwarebazaar/maksrat/` (82 jars)

### Strict mod-like subset selection

Not all MalwareBazaar jars are actual Minecraft mods (some are generic Java malware). Use the selection script to filter to jars that contain mod metadata files:

```bash
bun scripts/select-malwarebazaar-dataset.ts \
  .local-data/malwarebazaar/fractureiser \
  .local-data/malwarebazaar/mavenrat \
  .local-data/malwarebazaar/maksstealer \
  .local-data/malwarebazaar/maksrat \
  --output .local-data/malwarebazaar/mc-malware-batch-strict-modlike-jars
```

The script uses `zipinfo` to check each jar for mod metadata entries (`fabric.mod.json`, `mods.toml`, `neoforge.mods.toml`, `plugin.yml`, `mcmod.info`) and creates symlinks for matching jars. From 84 total jars, this typically produces ~70 strict mod-like samples.

### Scanning the malware corpus

```bash
JARSPECT_MB_HASH_MATCH_ENABLED=0 \
  bash scripts/scan-local-dir.sh malwarebazaar .local-data/malwarebazaar/mc-malware-batch-strict-modlike-jars
```

Setting `JARSPECT_MB_HASH_MATCH_ENABLED=0` is critical for benchmarking -- it disables the MalwareBazaar hash short-circuit so the detection layers (bytecode detectors, YARA rules, AI verdict, static override) are actually exercised instead of trivially matching by hash.

## 4) Aggregation

Given a run directory containing:

- `run.json`
- `results.csv`
- per-sample `*-scan.json`

Run:

```bash
bun scripts/aggregate-run.ts .local-data/runs/<your-run-dir>
```

Outputs in the same run directory:

- `aggregate.csv`
- `summary.json`

`aggregate.csv` includes:

- Core identity: `run_id`, `dataset`, `sample`, `sha256`
- Verdict: `verdict`, `confidence`, `risk_score`, `method`
- Profile: `loader`, `class_count`, `jar_size_bytes`, 8 capability flags
- YARA hit counts by severity
- Extracted artifact counts (URLs/domains/commands/paths)

## 5) Suggested Graphs

All of these can be built from `aggregate.csv`:

- Verdict distribution: counts of CLEAN/SUSPICIOUS/MALICIOUS per dataset
- Capability prevalence: fraction of samples with each capability present
- Risk score histogram: distribution of `risk_score` across datasets
- YARA severity bars: per-run `yara_high + yara_critical` totals
- Extracted artifacts: box plot / histogram of `extracted_url_count` and `extracted_domain_count`

## MalwareBazaar Matches And Reporting Artifacts

By default, a MalwareBazaar hash match short-circuits and returns a final MALICIOUS verdict.

If you want capability/profile artifacts for graphs even for known-malware samples, set:

```bash
export JARSPECT_MB_MATCH_CONTINUE_ANALYSIS=1
```

The final verdict stays `MALICIOUS` with method `malwarebazaar_hash`.
