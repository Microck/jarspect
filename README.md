<picture>
  <img alt="Jarspect" src="docs/brand/logo-horizontal.svg" width="640">
</picture>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Upload a `.jar`, get a risk verdict with explainable indicators before you install.**

The name **Jarspect** is a portmanteau of **JAR** (Java Archive) and **Inspect**, reflecting its mission to provide deep, automated inspection of game mods for hidden threats.

Jarspect is a bytecode-native security scanner for Minecraft mods. It parses compiled `.class` files at the constant-pool and instruction level, reconstructs obfuscated strings, resolves method invocations, runs YARA rules per archive entry, and correlates findings through 8 capability detectors to produce a risk tier, 0-100 score, and a list of concrete indicators you can audit.

---

## Why This Exists

In June 2023, **fractureiser** compromised dozens of Minecraft mods on CurseForge and Bukkit. Stage 0 hid a URL inside `new String(new byte[]{...})` to evade string-based scanners, then loaded a remote class via `URLClassLoader` reflection chain. Stages 1-3 added persistence (Windows Run keys, Linux systemd units), credential theft (MSA tokens, Discord tokens, browser cookies, crypto wallets), and self-replication into other installed mods.

**BleedingPipe** exploited unsafe `ObjectInputStream.readObject()` calls in popular server-side mods, allowing remote code execution on Minecraft servers. **PussyRAT** used reflection to hijack Minecraft session tokens. The **Stargazers Ghost Network** distributed trojanized mods through fake GitHub stars, delivering multi-stage Java-to-.NET info-stealers.

Traditional antivirus and text-based scanners score these threats 0/100 because real malware lives in **compiled bytecode** -- API references exist as structured constant-pool entries, not grep-able plain text. A scanner that doesn't parse `.class` files is blind to all of it.

Jarspect was built to fix this. Every detection technique in the engine traces back to a real-world malware sample or documented attack vector.

---

## How It Works

```
POST /upload  (multipart .jar)
        |
        v
   upload_id stored at .local-data/uploads/{upload_id}.jar
        |
POST /scan  (upload_id + optional author metadata)
        |
        +-- Archive traversal     recursive jar-in-jar extraction with budget gates
        +-- Bytecode evidence     cafebabe class parsing -> constant pool + invoke resolution
        +-- Byte-array strings    reconstruct new String(new byte[]{...}) hidden values
        +-- YARA per-entry        inflate each entry, scan individually, severity from metadata
        +-- Metadata checks       fabric.mod.json / mods.toml / plugin.yml / MANIFEST.MF
        +-- Capability detectors  8 detectors (exec, network, dynamic load, fs/jar modify,
        |                         persistence, deserialization, native/JNI, credential theft)
        +-- Scoring engine        dedup + diminishing returns + synergy bonuses -> 0-100
        +-- Behavior prediction   evidence-derived URLs, commands, file paths, persistence
        +-- Reputation            optional author trust score
                |
                v
           Verdict synthesis
           risk_tier . risk_score . summary . explanation . indicators[]
                |
                v
   scan_id persisted at .local-data/scans/{scan_id}.json
        |
GET /scans/{scan_id}  -> fetch full result at any time
```

**Key properties:**
- **Bytecode-native** -- parses `.class` constant pools and resolves `invoke*` instructions instead of running regex over lossy UTF-8
- **Reconstructs hidden strings** -- recovers `new String(new byte[]{...})` values that fractureiser Stage 0 used to hide URLs and class names
- **Recursive archive scanning** -- follows jar-in-jar nesting with `!/` path provenance and budget-gated inflation
- **Per-entry YARA** -- scans each inflated archive entry individually (not the compressed jar blob) with severity from rule metadata
- **8 capability detectors** -- each uses an evidence index with class-scoped correlation gates for severity escalation
- **Evidence-derived behavior** -- predicted URLs, commands, and file paths come from actual findings, not synthetic placeholders
- **Fully explainable** -- every indicator carries `source`, `id`, `severity`, `file_path`, `evidence`, and `rationale`
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

### Metadata Checks

Jarspect parses mod metadata files and cross-references them against archive contents:

- **Fabric/Quilt** -- `fabric.mod.json`: validates entrypoint classes exist in the JAR
- **Forge** -- `META-INF/mods.toml`: checks mod ID, version, loader constraints
- **Spigot/Bukkit** -- `plugin.yml`: validates main class exists
- **MANIFEST.MF** -- flags high-risk Java agent attributes (`Premain-Class`, `Agent-Class`, `Can-Redefine-Classes`, etc.)

### Recursive Archive Scanning

Jars can contain jars (Fabric nested jars under `META-INF/jars/`, or malware embedding payload archives). Jarspect recursively extracts nested archives with:

- `!/` delimited path provenance (e.g. `outer.jar!/META-INF/jars/inner.jar!/com/Evil.class`)
- Budget gates: per-entry size limit, compression ratio limit, total inflated bytes cap
- Configurable depth limit
---

## Scoring

The scoring engine deduplicates indicators by fingerprint, applies diminishing returns per category, and adds synergy bonuses when dangerous capability combinations appear together.

**Deduplication:** Same indicator from multiple sources keeps `max(points)` across layers. Repeated hits within a category yield full value for the first few, then diminishing returns.

**Synergy bonuses:** Capability combinations that indicate coordinated malicious behavior receive additive bonuses:
- Execution + Network (download-and-execute pattern)
- Dynamic loading + Network (remote code loading)
- Credential theft + Network (data exfiltration)
- Persistence + Execution (persistent backdoor)

**Reputation cap:** Author reputation adjustments are capped at +19 points, preventing reputation-only escalation to HIGH or CRITICAL.

**CLEAN gate:** Score 0 requires zero static indicators and zero reputation points.

### Risk Tiers

| Tier | Score range | Meaning |
|------|-------------|---------|
| `CLEAN` | 0 | No indicators detected across any analysis layer |
| `LOW` | 1-39 | Minor signals; unlikely to be malicious but worth noting |
| `MEDIUM` | 40-64 | Multiple corroborating signals; review carefully before installing |
| `HIGH` | 65-84 | Strong evidence of suspicious behavior across two or more capabilities |
| `CRITICAL` | 85-100 | High-confidence malware markers; do not install |

### Behavior Prediction

Behavior predictions are **evidence-derived**, not synthetic. The engine extracts:

- **URLs** from constant-pool strings and reconstructed byte-array strings
- **Commands** from shell command markers near process-execution invocations
- **File paths** from filesystem API arguments and known sensitive paths
- **Persistence indicators** from registry key paths, systemd unit paths, startup folder references

Each prediction carries a confidence score and rationale linking back to specific detector findings.
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
  -d '{
    "upload_id": "a3f9c1d2e4b56789...",
    "author": {
      "author_id": "new_creator",
      "mod_id": "demo-suspicious",
      "account_age_days": 7,
      "prior_mod_count": 0,
      "report_count": 3
    }
  }'
```

The response contains the full `ScanRunResponse` (see [Data Model](#data-model)) including the `scan_id`.

**Step 3: Fetch results**

```bash
curl http://localhost:18000/scans/<scan_id>
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JARSPECT_BIND` | `127.0.0.1:18000` | Host and port the HTTP server binds to |
| `JARSPECT_RULEPACKS` | `demo` | Which YARA/signature rulepacks to load: `demo`, `prod`, or `demo,prod` |
| `RUST_LOG` | `jarspect=info,tower_http=info` | Log verbosity (uses `tracing-subscriber` env-filter syntax) |

Example: bind to all interfaces on port 9000 with production rules and debug logging:

```bash
JARSPECT_BIND=0.0.0.0:9000 JARSPECT_RULEPACKS=prod RUST_LOG=debug cargo run
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

Run the full scan pipeline on a previously uploaded `.jar`. Author metadata is optional but enables the reputation layer.

**Request body:**

```json
{
  "upload_id": "a3f9c1d2e4b56789abcdef0123456789",
  "author": {
    "author_id": "new_creator",
    "mod_id": "demo-suspicious",
    "account_age_days": 7,
    "prior_mod_count": 0,
    "report_count": 3
  }
}
```

**Response `200`:** Full `ScanRunResponse` (see [Data Model](#data-model)).

---

### `GET /scans/{scan_id}`

Retrieve a previously persisted scan result. `scan_id` must be a 32-character hex string.

**Response `404`:** `{"detail": "Scan not found"}`

---

### `GET /health`

Liveness check.

**Response `200`:**

```json
{
  "status": "ok",
  "service": "jarspect",
  "version": "0.1.0"
}
```
---

## Web UI

Open [http://localhost:18000/](http://localhost:18000/) after starting the server.

The single-page console lets you:

1. **Pick a `.jar` file** from disk using the file picker
2. **Fill in optional author metadata** (Author ID, Mod ID, account age, prior mod count, report count) -- useful for exercising the reputation layer in demos
3. **Click "Upload and Scan"** -- the UI calls `/upload` then `/scan` and streams status messages
4. **Inspect the verdict panel** -- displays risk tier, risk score, summary, explanation prose, and a scrollable indicator list with severity badges and evidence text

The `scan_id` is shown in the results header so you can re-fetch results later with `GET /scans/{scan_id}`.

---

## Architecture

![Architecture diagram](docs/architecture.svg)

> Mermaid source at `docs/architecture.mmd`

The scan pipeline lives in `src/lib.rs` as a library function `run_scan()`, callable without HTTP. `src/main.rs` is the Axum transport layer.

```
POST /scan
  |
  +- Archive traversal       read_archive_entries()  - recursive jar-in-jar with budget gates
  +- Bytecode extraction     extract_bytecode_evidence()  - cafebabe class parse + invoke resolve
  +- Byte-array strings      reconstruct_byte_array_strings()  - opcode state machine
  +- YARA per-entry          run_yara_scan()  - inflate each entry, scan individually
  +- Metadata checks         check_metadata()  - fabric/forge/spigot/manifest validation
  +- Capability detectors    run_detectors()  - 8 detectors against EvidenceIndex
  +- Scoring                 score_static_indicators()  - dedup + diminishing + synergy -> 0-100
  +- Behavior prediction     derive_behavior()  - evidence-derived URLs/commands/paths
  +- Reputation              score_author()  - optional composite trust score
  +- Verdict                 build_verdict()  - tier + score + explanation + all indicators
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

Top-level shape:

| Field | Type | Description |
|-------|------|-------------|
| `scan_id` | `string` | 32-character hex UUID for this scan run |
| `result.intake` | object | Upload metadata: `upload_id`, `storage_path`, `file_count`, `class_file_count` |
| `result.static` | object | All detector/YARA/metadata matches, deduplicated IDs, per-category/severity counts |
| `result.behavior` | object | Evidence-derived `predicted_network_urls`, `predicted_file_writes`, `predicted_persistence`, `predicted_commands`, `predictions[]` |
| `result.reputation` | object or null | `author_score` (0-1), raw metadata fields, `indicators[]`; null if no author provided |
| `result.bytecode_evidence` | object or null | Raw extracted constant-pool strings, invoke tuples, reconstructed byte-array strings (omitted when empty) |
| `result.verdict` | object | `risk_tier`, `risk_score` (0-100), `summary`, `explanation`, all `indicators[]` |

Each `Indicator` object:

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | `detector`, `yara`, `metadata`, `pattern`, `signature`, `behavior`, or `reputation` |
| `id` | `string` | Stable identifier (e.g. `DETC-01`, `YARA-PROD-JAVA-EXEC-001`, `META-MISSING-ENTRYPOINT`) |
| `title` | `string` | Human-readable label |
| `category` | `string` | `execution`, `network`, `dynamic_loading`, `filesystem`, `persistence`, `vulnerability`, `native`, `credential_theft`, `mod_integrity`, `obfuscation`, `reputation` |
| `severity` | `string` | `critical`, `high`, `med`, or `low` |
| `file_path` | `string` or null | Archive entry where the match was found (with `!/` nesting for jar-in-jar) |
| `evidence` | `string` | Extracted text snippet or structured evidence |
| `rationale` | `string` | Why this indicator is suspicious |

Detector indicators may also carry:

| Field | Type | Description |
|-------|------|-------------|
| `evidence_locations` | `array` or null | `[{class, method, pc}]` callsite locations |
| `extracted_urls` | `array` or null | URLs found in the same class context |
| `extracted_commands` | `array` or null | Shell commands found in the same class context |
| `extracted_file_paths` | `array` or null | Sensitive file paths found in the same class context |
---

## Safety and Limitations

- **No sandbox.** Jarspect does not execute or load any `.class` files. All analysis is purely static (bytecode-level constant-pool and instruction parsing).
- **Synthetic demo fixtures.** The bundled demo rulepack matches strings from `demo/suspicious_sample.jar` -- a synthetic artifact built by `demo/build_sample.sh`. No real malware samples are included.
- **Static analysis only.** The behavior layer is deterministic heuristics derived from bytecode evidence, not dynamic analysis. It predicts plausible activity from static signals but does not execute code.
- **Reputation is demo-grade.** The reputation layer scores author metadata using a simple linear formula. It is not connected to a real registry or threat intelligence feed.
- **50 MB upload cap.** Enforced server-side; configurable in source (`upload_max_bytes`).
- **`.jar` only.** Other archive types are rejected at the upload handler.
- **Budget-gated extraction.** Recursive archive scanning has per-entry size, compression ratio, total inflated bytes, and depth limits to prevent zip-bomb denial of service.

---

## Development

```bash
# Check for compile errors
cargo check

# Run tests (58 unit + 2 integration)
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
  lib.rs                                scan pipeline, types, run_scan() entry point (750 lines)
  main.rs                               Axum HTTP transport layer (223 lines)
  scoring.rs                            scoring engine: dedup, diminishing returns, synergy (1130 lines)
  behavior.rs                           evidence-derived behavior prediction (503 lines)
  analysis/
    mod.rs                              analysis module exports and shared types
    archive.rs                          recursive jar-in-jar traversal with budget gates
    classfile_evidence.rs               cafebabe class parsing, constant-pool + invoke resolution
    byte_array_strings.rs               new String(new byte[]{...}) reconstruction state machine
    evidence.rs                         EvidenceIndex for detector lookups
    metadata.rs                         fabric.mod.json / mods.toml / plugin.yml / MANIFEST.MF
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
data/signatures/
  demo/                                 demo rulepack (matches synthetic fixtures)
    signatures.json                     JSON signature corpus
    rules.yar                           YARA rules
  prod/                                 production rulepack (real bytecode-aware rules)
    signatures.json                     JSON signature corpus
    rules.yar                           YARA rules
  signatures.json                       legacy signatures (kept for backward compat)
  rules.yar                             legacy YARA rules
tests/
  regression-fixtures.rs                integration tests via run_scan()
  fixtures/                             committed compiled test fixtures
web/
  index.html                            single-page browser UI
  app.js                                UI logic with tier/severity normalization
  styles.css                            UI styles
demo/
  build_sample.sh                       builds synthetic suspicious_sample.jar
  suspicious_sample.jar                 pre-built synthetic fixture
  voiceover.md                          demo TTS voiceover script
scripts/
  demo_run.sh                           end-to-end demo runner
docs/
  architecture.mmd                      Mermaid architecture diagram source
  architecture.svg                      rendered architecture diagram
  brand/                                logo assets
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
