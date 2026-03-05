<picture>
  <img alt="Jarspect" src="docs/brand/logo-horizontal.svg" width="640">
</picture>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Upload a `.jar`, get a risk verdict with explainable indicators before you install.**

The name **Jarspect** is a portmanteau of **JAR** (Java Archive) and **Inspect**, reflecting its mission to provide deep, automated inspection of game mods for hidden threats.

Jarspect is an AI-first security scanner for Minecraft mods. It runs a 3-layer pipeline -- MalwareBazaar threat intel, bytecode capability extraction, and Azure OpenAI verdict -- to classify `.jar` files as **CLEAN**, **SUSPICIOUS**, or **MALICIOUS** with full explanations. The bytecode layer parses compiled `.class` files at the constant-pool and instruction level, reconstructs obfuscated strings, resolves method invocations, runs YARA rules per archive entry, and feeds 8 capability detectors into a structured profile that the AI analyzes to produce its verdict.

---

## Why This Exists

In June 2023, **fractureiser** compromised dozens of Minecraft mods on CurseForge and Bukkit. Stage 0 hid a URL inside `new String(new byte[]{...})` to evade string-based scanners, then loaded a remote class via `URLClassLoader` reflection chain. Stages 1-3 added persistence (Windows Run keys, Linux systemd units), credential theft (MSA tokens, Discord tokens, browser cookies, crypto wallets), and self-replication into other installed mods.

**BleedingPipe** exploited unsafe `ObjectInputStream.readObject()` calls in popular server-side mods, allowing remote code execution on Minecraft servers. **PussyRAT** used reflection to hijack Minecraft session tokens. The **Stargazers Ghost Network** distributed trojanized mods through fake GitHub stars, delivering multi-stage Java-to-.NET info-stealers.

Traditional antivirus and text-based scanners score these threats 0/100 because real malware lives in **compiled bytecode** -- API references exist as structured constant-pool entries, not grep-able plain text. A scanner that doesn't parse `.class` files is blind to all of it. And rule-based scoring alone can't distinguish a rendering mod that calls `Runtime.exec()` for GPU probing from a RAT that calls it to run shell commands.

Jarspect was built to fix both problems. Every detection technique in the bytecode layer traces back to a real-world malware sample or documented attack vector. The AI verdict layer understands context -- it knows that `sodium` calling `glxinfo` is legitimate GPU detection, not process execution abuse.

---

## How It Works

Jarspect uses a **3-layer pipeline** where each layer can short-circuit to a final verdict:

```
POST /upload  (multipart .jar)
        |
        v
   upload_id stored at .local-data/uploads/{upload_id}.jar
        |
POST /scan  (upload_id)
        |
  Layer 1: MalwareBazaar Threat Intel
        |   SHA-256 hash lookup against abuse.ch database
        |   Match? -> MALICIOUS (confidence 1.0, method: malwarebazaar_hash)
        |            Optional: set JARSPECT_MB_MATCH_CONTINUE_ANALYSIS=1 to still run
        |            archive traversal + static analysis for reporting artifacts (verdict unchanged)
        |
  Layer 2: Bytecode Capability Extraction
        +-- Archive traversal     recursive jar-in-jar extraction with budget gates
        +-- Bytecode evidence     cafebabe class parsing -> constant pool + invoke resolution
        +-- Byte-array strings    reconstruct new String(new byte[]{...}) hidden values
        +-- YARA per-entry        inflate each entry, scan individually, severity from metadata
        +-- Metadata checks       fabric.mod.json / mods.toml / neoforge.mods.toml / plugin.yml / MANIFEST.MF
        +-- Capability detectors  8 detectors (exec, network, dynamic load, fs/jar modify,
        |                         persistence, deserialization, native/JNI, credential theft)
        +-- Profile builder       structured capability profile with extracted artifacts
        |
  Layer 3: AI Verdict (Azure OpenAI)
        |   Receives capability profile + extracted URLs, domains, commands, file paths
        |   Returns: CLEAN / SUSPICIOUS / MALICIOUS with confidence, explanation,
        |   and per-capability rationale
                |
                v
   scan_id persisted at .local-data/scans/{scan_id}.json
        |
GET /scans/{scan_id}  -> fetch full result at any time
```

**Key properties:**
- **AI-first** -- Azure OpenAI (gpt-4o) analyzes the full capability profile and decides the verdict; no rule-based scoring fallback
- **Static override layer** -- high-confidence static signals (production YARA rules, high-severity detector correlations like `DETC-03.DYNAMIC_LOAD`) override the AI verdict to MALICIOUS via `static_override(ai_verdict)`, preventing the AI from downgrading obvious malware
- **Known-malware guaranteed** -- MalwareBazaar hash match short-circuits to MALICIOUS before any other analysis (verdict always uses method `malwarebazaar_hash`)
- **Reporting-friendly artifacts** -- scan JSON includes top-level `sha256` and (when available) `static_findings` for extracted URLs/domains/paths/commands
- **Bytecode-native** -- parses `.class` constant pools and resolves `invoke*` instructions instead of running regex over lossy UTF-8
- **Reconstructs hidden strings** -- recovers `new String(new byte[]{...})` values that fractureiser Stage 0 used to hide URLs and class names
- **Recursive archive scanning** -- follows jar-in-jar nesting with `!/` path provenance and budget-gated inflation
- **Per-entry YARA** -- scans each inflated archive entry individually (not the compressed jar blob) with severity from rule metadata
- **8 capability detectors** -- each uses an evidence index with class-scoped correlation gates for severity escalation
- **Artifact extraction** -- URLs, domains, shell commands, and file paths extracted from bytecode evidence and fed to the AI
- **Fully explainable** -- the AI provides per-capability rationale explaining what it found and why it matters (or doesn't)
- **Single binary** -- `cargo run` starts the HTTP server and the web UI on the same port
---

## Detection Engine

### Bytecode Evidence Extraction

Every `.class` entry (identified by `0xCAFEBABE` magic) is parsed using the `cafebabe` crate:

1. **Constant-pool strings** -- all `CONSTANT_Utf8` and `CONSTANT_String` entries are extracted and deduplicated. These contain class names (`java/lang/Runtime`), method names (`exec`), descriptors (`(Ljava/lang/String;)Ljava/lang/Process;`), and string literals.

2. **Invoke resolution** -- every `invokevirtual`, `invokestatic`, `invokespecial`, `invokeinterface`, and `invokedynamic` instruction is resolved through the constant-pool reference chain into `(owner, name, descriptor)` tuples with method name and program-counter location metadata.

3. **Byte-array string reconstruction** -- a narrow opcode state machine walks method bytecode looking for the `newarray T_BYTE` + `dup/bipush/sipush/bastore` + `String.<init>([B)V` pattern. When found, the byte values are assembled into the hidden string. This is how fractureiser Stage 0 concealed `java.net.URLClassLoader` and the remote class name -- these strings never appear in the constant pool.

### Capability Detectors

Eight detectors run against an `EvidenceIndex` built from the extracted bytecode evidence. Each detector uses class-scoped correlation gates: a method call alone may be `low` severity, but the same call in a class that also references suspicious strings or complementary APIs escalates to `high`.

| ID | Capability | What it catches |
|----|-----------|----------------|
| DETC-01 | Process execution | `Runtime.exec()`, `ProcessBuilder.start()`, shell command strings |
| DETC-02 | Network I/O | `URL`, `HttpURLConnection`, `HttpClient`, socket APIs, extracted URLs |
| DETC-03 | Dynamic class loading | `URLClassLoader`, `ClassLoader.defineClass`, `Class.forName`, reflection chains |
| DETC-04 | Filesystem/JAR modification | `ZipOutputStream`, `JarFile`, `Files.walk`, directory traversal + `.jar` markers |
| DETC-05 | Persistence | Windows Run keys, systemd unit paths, startup folders, `schtasks`/`crontab` |
| DETC-06 | Unsafe deserialization | `ObjectInputStream.readObject()` (BleedingPipe-style vulnerability risk) |
| DETC-07 | Native/JNI loading | `System.load`/`loadLibrary`, embedded `.dll`/`.so`/`.dylib` entries |
| DETC-08 | Credential theft | Discord token paths, browser cookie/login databases, `.minecraft` session files |

### YARA Rules

YARA rules run on each **inflated** archive entry individually -- not the compressed jar blob. This is critical because YARA over the whole JAR won't reliably match inside deflated entries.

Severities come from rule metadata (`meta.severity`) with fallback chain to `meta.threat_level`, tags, then pack default. Rule IDs are prefixed by pack provenance (`YARA-DEMO-*` for demo rules, `YARA-PROD-*` for production rules).

Demo and production rulepacks are separated via the `JARSPECT_RULEPACKS` environment variable.

#### Production YARA Rules

The `prod` rulepack (`data/signatures/prod/rules.yar`) contains 6 high-precision rules targeting known Minecraft mod malware families:

| Rule | Family / Campaign | What it matches |
|------|------------------|-----------------|
| `minecraft_makslibraries_mcmod_info` | Maks Libraries | Forge `mcmod.info` with `makslibraries` mod ID |
| `minecraft_pussylib_pussygo_class` | PussyRAT | `pussylib/pussygo` class marker |
| `minecraft_loaderclient_staging_helper` | Loader/Stager | `StagingHelper` + JAR staging + HTTP client |
| `minecraft_krypton_loader_stub` | Krypton stealer | Obfuscated Fabric stub with `URLClassLoader` + `a/a/a/Config` + `UTF_16BE` + `Error in hash` |
| `minecraft_maxcoffe_socket_loader_stub` | MaxCoffe / MaksRAT | Socket I/O + JAR staging + `defineClass` + `nothing_to_see_here` marker |
| `minecraft_eth_rpc_endpoint_list` | Fractureiser-tagged | `RPCHelper` class with 6+ hardcoded Ethereum JSON-RPC endpoints |

All production rules use `severity = "high"` and require multiple corroborating strings (no single-string rules) to maintain high precision. A production YARA hit at high/critical severity triggers the `static_override` layer, guaranteeing a MALICIOUS verdict regardless of the AI's assessment.

### Metadata Checks

Jarspect parses mod metadata files and cross-references them against archive contents:

- **Fabric/Quilt** -- `fabric.mod.json`: validates entrypoint classes exist in the JAR
- **Forge** -- `META-INF/mods.toml`: checks mod ID, version, loader constraints
- **NeoForge** -- `META-INF/neoforge.mods.toml`: checks mod ID, version, NeoForge-specific fields
- **Spigot/Bukkit** -- `plugin.yml`: validates main class exists
- **MANIFEST.MF** -- flags high-risk Java agent attributes (`Premain-Class`, `Agent-Class`, `Can-Redefine-Classes`, etc.)

When multiple metadata files are present, Jarspect picks the shallowest (most likely to be the main mod) to avoid noise from bundled dependencies.

### Recursive Archive Scanning

Jars can contain jars (Fabric nested jars under `META-INF/jars/`, or malware embedding payload archives). Jarspect recursively extracts nested archives with:

- `!/` delimited path provenance (e.g. `outer.jar!/META-INF/jars/inner.jar!/com/Evil.class`)
- Budget gates: per-entry size limit, compression ratio limit, total inflated bytes cap
- Configurable depth limit
---

## Verdict Pipeline

Jarspect uses a 3-layer verdict pipeline. Each layer can produce a final verdict:

### Layer 1: MalwareBazaar Threat Intel

Before any static analysis, the jar's SHA-256 hash is checked against [MalwareBazaar](https://bazaar.abuse.ch/) (abuse.ch). If the hash matches a known malware sample, the scan immediately returns **MALICIOUS** with `confidence: 1.0` and `method: malwarebazaar_hash`.

By default, MalwareBazaar matches short-circuit (no further analysis). If you need static-analysis artifacts for reporting/graphs even on known-malware samples, set `JARSPECT_MB_MATCH_CONTINUE_ANALYSIS=1`. The final verdict still stays MalwareBazaar-based.

### Layer 2: Bytecode Capability Extraction

If no threat intel match is found, the full bytecode analysis runs: archive traversal, class parsing, YARA scanning, and 8 capability detectors. The results are assembled into a `CapabilityProfile` containing:

- Which capabilities are present (network, execution, persistence, etc.) with evidence
- YARA rule matches with severity
- Mod metadata (loader, mod ID, version, authors, entrypoints)
- Reconstructed hidden strings
- Suspicious manifest entries
- Extracted artifacts: URLs, domains, shell commands, file paths found in bytecode evidence

### Layer 3: AI Verdict (Azure OpenAI)

The capability profile is sent to Azure OpenAI (gpt-4o) with a specialized system prompt. The AI analyzes the profile in context -- understanding that `Runtime.exec()` in a rendering mod calling `glxinfo` is legitimate GPU probing, not malicious process execution. It returns:

- **Verdict**: `CLEAN`, `SUSPICIOUS`, or `MALICIOUS`
- **Confidence**: 0.0 to 1.0
- **Risk score**: 0 to 100
- **Explanation**: prose description of findings and reasoning
- **Capabilities assessment**: per-capability rationale explaining what was found and why it matters (or doesn't)

The AI is instructed to cite concrete evidence (class paths, extracted URLs) and to explain what would upgrade/downgrade a SUSPICIOUS verdict.

### Static Override Layer

After the AI (or heuristic fallback) produces its verdict, a final guard runs: if any high-confidence static signal is present, the verdict is overridden to **MALICIOUS** regardless of what the AI said. This prevents the AI from downgrading obvious malware.

Signals that trigger the override:
- Any production YARA rule match (`YARA-PROD-*`) at high/critical severity
- `DETC-03.DYNAMIC_LOAD` at high/critical (URLClassLoader + correlated network in the same class)
- `DETC-03.BASE64_STAGER`, `DETC-02.REMOTE_CODE_FETCH`, `DETC-04.REMOTE_CODE_WRITE`, `DETC-03.REMOTE_CODE_LOAD` at high/critical
- `DETC-02.DISCORD_WEBHOOK` at high/critical
- `NET-DISCORD-WEBHOOK` signature match at high/critical

When triggered, the verdict method becomes `static_override(ai_verdict)` (or `static_override(heuristic_fallback)`).

### Verdict Categories

| Verdict | Meaning |
|---------|---------|
| `CLEAN` | No malicious indicators; capabilities are consistent with legitimate mod behavior |
| `SUSPICIOUS` | Some concerning signals but insufficient evidence for a definitive malicious classification |
| `MALICIOUS` | Strong evidence of malicious intent -- known malware hash, or AI-confirmed coordinated malicious behavior |
---

## Quickstart

**Prerequisites:** Rust stable toolchain ([rustup.rs](https://rustup.rs))

```bash
git clone https://github.com/Microck/jarspect.git
cd jarspect
cargo run
```

The server starts on `http://127.0.0.1:18000` by default.

- **Web UI** -- [http://localhost:18000/](http://localhost:18000/)
- **Health check** -- [http://localhost:18000/health](http://localhost:18000/health)

To run the end-to-end demo (builds a synthetic suspicious `.jar` and exercises the full API):

```bash
bash scripts/demo_run.sh
```

---

## Installation

Jarspect ships as a single Rust binary. No external runtime or database required.

```bash
# 1. Install Rust (if you don't have it)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# 2. Clone and build
git clone https://github.com/Microck/jarspect.git
cd jarspect
cargo build --release

# 3. Run
./target/release/jarspect
```

All persistent data lands in `.local-data/` relative to the working directory (auto-created on first run).
---

## Usage

The full flow is three HTTP calls:

**Step 1: Upload the `.jar`**

```bash
curl -X POST http://localhost:18000/upload \
  -F "file=@/path/to/yourmod.jar"
```

```json
{
  "upload_id": "a3f9c1d2e4b56789...",
  "filename": "yourmod.jar",
  "size_bytes": 204800,
  "storage_url": ".local-data/uploads/a3f9c1d2e4b56789....jar"
}
```

**Step 2: Run the scan**

```bash
curl -X POST http://localhost:18000/scan \
  -H "Content-Type: application/json" \
  -d '{"upload_id": "a3f9c1d2e4b56789..."}'
```

The response contains the full `ScanRunResponse` (see [Data Model](#data-model)) including the `scan_id`.

**Step 3: Fetch results**

```bash
curl http://localhost:18000/scans/<scan_id>
```

---

## Configuration

### Server

| Variable | Default | Description |
|----------|---------|-------------|
| `JARSPECT_BIND` | `127.0.0.1:18000` | Host and port the HTTP server binds to |
| `JARSPECT_RULEPACKS` | `demo` | Which YARA/signature rulepacks to load: `demo`, `prod`, or `demo,prod` |
| `JARSPECT_AI_ENABLED` | `1` | Enable/disable AI verdict even if Azure OpenAI env vars are set (`0`/`false` to disable) |
| `JARSPECT_UPLOAD_MAX_BYTES` | `52428800` | Maximum accepted upload size in bytes (default 50 MiB) |
| `JARSPECT_MB_HASH_MATCH_ENABLED` | `1` | Enable/disable MalwareBazaar hash matching (`0`/`false` to disable; useful for benchmarking static/AI detectors) |
| `RUST_LOG` | `jarspect=info,tower_http=info` | Log verbosity (uses `tracing-subscriber` env-filter syntax) |

### AI Verdict (required for production)

| Variable | Description |
|----------|-------------|
| `AZURE_OPENAI_ENDPOINT` | Azure OpenAI endpoint URL (e.g. `https://your-resource.openai.azure.com`) |
| `AZURE_OPENAI_API_KEY` | Azure OpenAI API key |
| `AZURE_OPENAI_DEPLOYMENT` | Deployment name (e.g. `gpt-4o`) |
| `AZURE_OPENAI_API_VERSION` | API version (default: `2024-10-21`) |

### Threat Intelligence

| Variable | Description |
|----------|-------------|
| `MALWAREBAZAAR_API_KEY` | MalwareBazaar API key for hash lookups (optional but recommended) |

Example: full production configuration:

```bash
JARSPECT_BIND=0.0.0.0:18000 \
JARSPECT_RULEPACKS=prod \
AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com \
AZURE_OPENAI_API_KEY=your-key \
AZURE_OPENAI_DEPLOYMENT=gpt-4o \
MALWAREBAZAAR_API_KEY=your-mb-key \
RUST_LOG=jarspect=info \
cargo run --release
```
---

## API Reference

All responses are JSON. Error responses use `{"detail": "<message>"}`.

---

### `POST /upload`

Upload a `.jar` file for later scanning. Accepts `multipart/form-data` with a field named `file`.

**Constraints:** `.jar` extension required; max 50 MB.

**Response `200`:**

```json
{
  "upload_id": "a3f9c1d2e4b56789abcdef0123456789",
  "filename": "suspicious-mod.jar",
  "size_bytes": 18432,
  "storage_url": ".local-data/uploads/a3f9c1d2e4b56789abcdef0123456789.jar"
}
```

`upload_id` is a 32-character lowercase hex string (UUID v4, simple form).

---

### `POST /scan`

Run the 3-layer scan pipeline (MalwareBazaar -> bytecode extraction -> AI verdict) on a previously uploaded `.jar`.

**Request body:**

```json
{
  "upload_id": "a3f9c1d2e4b56789abcdef0123456789"
}
```

**Response `200`:** Full `ScanRunResponse` (see [Data Model](#data-model)).

---

### `GET /scans/{scan_id}`

Retrieve a previously persisted scan result. `scan_id` must be a 32-character hex string.

**Response `404`:** `{"detail": "Scan not found"}`

---

### `GET /health`

Liveness check. Reports AI status, loaded rulepacks, signature/YARA rule counts, and feature flags.

**Response `200`:**

```json
{
  "status": "ok",
  "service": "jarspect",
  "version": "0.1.0",
  "ai_enabled": true,
  "rulepacks": "prod",
  "signature_count": 12,
  "yara_rule_count": 6,
  "mb_hash_match_enabled": true,
  "upload_max_bytes": 52428800
}
```
---

## Web UI

Open [http://localhost:18000/](http://localhost:18000/) after starting the server.

The single-page console lets you:

1. **Drop a `.jar` file** onto the upload zone or use the file picker
2. **Click "Run scan"** -- the UI calls `/upload` then `/scan` and streams status messages
3. **Inspect the verdict** -- displays the AI verdict (CLEAN / SUSPICIOUS / MALICIOUS), confidence score, detection method, and the AI's full explanation
4. **Review AI reasoning** -- per-capability rationale from the AI explaining why each detected capability is or isn't concerning
5. **Browse indicators** -- filterable list with severity badges, evidence text, and rationale from both bytecode detectors and threat intelligence

---

## Architecture

![Architecture diagram](docs/architecture.svg)

> Mermaid source at `docs/architecture.mmd`

The scan pipeline lives in `src/scan.rs` as an orchestrator that runs the 3-layer pipeline. `src/main.rs` is the Axum transport layer.

```
POST /scan
  |
  +- SHA-256 hash                 sha2::Sha256::digest()
  +- MalwareBazaar lookup         malwarebazaar::check_hash()  - match? -> MALICIOUS
  |
  +- Archive traversal            analysis::read_archive_entries_recursive()
  +- Bytecode extraction          analysis::extract_bytecode_evidence()
  +- YARA per-entry               analysis::run_yara_scan()
  +- Capability detectors         detectors::run_detectors()  - 8 detectors against EvidenceIndex
  +- Profile builder              profile::build_profile()  - structured capability summary
  |
  +- AI verdict                   verdict::ai_verdict()  - Azure OpenAI gpt-4o analysis
                                  returns CLEAN / SUSPICIOUS / MALICIOUS + explanation
```

**Signature loading** happens once at startup:
- `data/signatures/{demo,prod}/signatures.json` -- loaded per rulepack
- `data/signatures/{demo,prod}/rules.yar` -- compiled via `yara_x::Compiler`, stored as `Arc<Rules>`

Both are held in `AppState` and shared across requests via `Arc`.
---

## Data Model

Scan results are persisted as pretty-printed JSON at:

```
.local-data/scans/{scan_id}.json
```

Top-level shape (`ScanRunResponse`):

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | `string` | 32-character hex UUID for this scan run |
| `verdict` | object | AI verdict: `result`, `confidence`, `risk_score`, `method`, `explanation`, `capabilities_assessment` |
| `malwarebazaar` | object or null | MalwareBazaar match details (if Layer 1 matched): `sha256_hash`, `family`, `tags`, `first_seen` |
| `capabilities` | object or null | Capability signals per detector: `{ name: { present, evidence[] } }` |
| `yara_hits` | array or null | YARA rule matches: `[{ id, severity, file_path, evidence }]` |
| `metadata` | object or null | Mod metadata from fabric.mod.json / mods.toml / plugin.yml |
| `profile` | object or null | Full `CapabilityProfile` sent to the AI for analysis |
| `intake` | object | Upload metadata: `upload_id`, `storage_path`, `file_count`, `class_file_count` |

Verdict object:

| Field | Type | Description |
|-------|------|-------------|
| `result` | `string` | `CLEAN`, `SUSPICIOUS`, or `MALICIOUS` |
| `confidence` | `f64` | 0.0 to 1.0 confidence in the verdict |
| `risk_score` | `u8` | 0 to 100 risk score |
| `method` | `string` | How the verdict was determined: `ai_verdict`, `malwarebazaar_hash`, `static_override(ai_verdict)`, or `heuristic_fallback` |
| `explanation` | `string` | Full prose explanation of findings and reasoning |
| `capabilities_assessment` | `map<string, string>` | Per-capability rationale from the AI (e.g. `{ "execution": "Runtime.exec used for GPU probing, not malicious" }`) |
---

## Safety and Limitations

- **No sandbox.** Jarspect does not execute or load any `.class` files. All analysis is purely static (bytecode-level constant-pool and instruction parsing).
- **AI-dependent.** Production verdicts require a working Azure OpenAI endpoint. Without AI configuration, scans will fail with an error. The AI model's judgment is the final authority on ambiguous cases.
- **Rate limiting.** Azure OpenAI endpoints may be rate-limited (429 responses). Jarspect retries with exponential backoff but will fail if rate-limited for too long.
- **Synthetic demo fixtures.** The bundled demo rulepack matches strings from `demo/suspicious_sample.jar` -- a synthetic artifact built by `demo/build_sample.sh`. No real malware samples are included in the repository.
- **Static analysis only.** The bytecode layer extracts capabilities and artifacts deterministically from bytecode evidence, but does not execute code.
- **50 MB upload cap.** Enforced server-side; configurable via `JARSPECT_UPLOAD_MAX_BYTES`.
- **`.jar` only.** Other archive types are rejected at the upload handler.
- **Budget-gated extraction.** Recursive archive scanning has per-entry size, compression ratio, total inflated bytes, and depth limits to prevent zip-bomb denial of service.

---

## Development

```bash
# Check for compile errors
cargo check

# Run tests (70 unit + 3 integration)
cargo test

# Build optimized binary
cargo build --release

# Run with verbose logging
RUST_LOG=debug cargo run

# Run with production YARA rules
JARSPECT_RULEPACKS=prod cargo run
```

**Project layout:**

```
src/
  main.rs                               Axum HTTP transport layer
  lib.rs                                core types, static analysis, run_scan() delegation
  scan.rs                               3-layer scan pipeline orchestrator
  verdict.rs                            AI verdict via Azure OpenAI (prompt, retry, rate-limit handling)
  profile.rs                            capability profile builder (structured AI input)
  malwarebazaar.rs                      MalwareBazaar hash lookup (abuse.ch)
  analysis/
    mod.rs                              analysis module exports and shared types
    archive.rs                          recursive jar-in-jar traversal with budget gates
    classfile_evidence.rs               cafebabe class parsing, constant-pool + invoke resolution
    byte_array_strings.rs               new String(new byte[]{...}) reconstruction state machine
    evidence.rs                         EvidenceIndex for detector lookups
    metadata.rs                         fabric.mod.json / mods.toml / neoforge.mods.toml / plugin.yml / MANIFEST.MF
    yara.rs                             per-entry YARA scanning with rulepack separation
  detectors/
    mod.rs                              detector runner and exports
    spec.rs                             detector specification types
    index.rs                            EvidenceIndex builder
    capability_exec.rs                  DETC-01: process execution
    capability_network.rs               DETC-02: network I/O
    capability_dynamic_load.rs          DETC-03: dynamic class loading
    capability_fs_modify.rs             DETC-04: filesystem/JAR modification
    capability_persistence.rs           DETC-05: persistence mechanisms
    capability_deser.rs                 DETC-06: unsafe deserialization
    capability_native.rs                DETC-07: native/JNI loading
    capability_cred_theft.rs            DETC-08: credential theft
    capability_base64_stager.rs         compound: base64-encoded stager detection
    capability_discord_webhook.rs       compound: Discord webhook exfiltration
    capability_remote_code_load.rs      compound: remote code fetch + load correlation
data/signatures/
  demo/                                 demo rulepack (matches synthetic fixtures)
  prod/                                 production rulepack (real bytecode-aware rules)
web/
  index.html                            single-page browser UI
  app.js                                UI logic with verdict rendering
  styles.css                            UI styles (Geist + JetBrains Mono)
docs/
  architecture.mmd                      Mermaid architecture diagram source
  architecture.svg                      rendered architecture diagram
  corpus-calibration.md                 calibration report from corpus testing
  benchmarking.md                       benchmark workflows and aggregation
  false-positives.md                    FP case studies and fixes
  brand/                                logo assets
scripts/
  demo_run.sh                           end-to-end demo (build sample + scan)
  modrinth-top-50-scan.sh               benign benchmark: download + scan Modrinth top mods
  scan-local-dir.sh                     batch scan a local directory of jars
  malwarebazaar-download.sh             download MalwareBazaar samples by tag
  select-malwarebazaar-dataset.ts       filter downloaded jars to mod-like subset
  aggregate-run.ts                      aggregate a run into CSV + summary JSON
.local-data/                            runtime data (gitignored)
  uploads/{upload_id}.jar               uploaded .jar files
  scans/{scan_id}.json                  persisted scan results
```

To add new YARA rules, append rules to the appropriate rulepack under `data/signatures/{demo,prod}/rules.yar`. Include `meta.severity` in your rules for automatic severity mapping. The compiler runs at startup and will report any syntax errors.

---

## Contributing

Issues and pull requests are welcome at [github.com/Microck/jarspect](https://github.com/Microck/jarspect).

For bug reports, include the `scan_id` and the anonymized `.jar` that triggered the issue (or a minimal reproduction). For new detection rules, include the rationale and a safe synthetic fixture that demonstrates the match.

---

## License

Apache-2.0. See [`LICENSE`](LICENSE).

---

## Origin

Built at the **Microsoft AI Dev Days Hackathon 2026**.
