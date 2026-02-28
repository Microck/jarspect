<picture>
  <img alt="Jarspect" src="docs/brand/logo-horizontal.svg" width="640">
</picture>

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

**Upload a `.jar`, get a risk verdict with explainable indicators before you install.**

Jarspect is a security scanner for Minecraft mods. It unpacks a `.jar`, runs layered deterministic static analysis (regex patterns + a JSON signature corpus + YARA-X rules), infers likely runtime behavior, and optionally folds in author reputation, producing a final risk tier, 0–100 score, and a list of concrete indicators you can audit.

---

## How It Works

```
POST /upload  (multipart .jar)
        │
        ▼
   upload_id stored at .local-data/uploads/{upload_id}.jar
        │
POST /scan  (upload_id + optional author metadata)
        │
        ├── Intake          unzip archive, enumerate entries + class count
        ├── Static analysis regex patterns + signature corpus + YARA-X rules
        ├── Behavior        infer predicted URLs / file writes / persistence
        └── Reputation      score author trust from account age / mods / reports
                │
                ▼
           Verdict synthesis
           risk_tier · risk_score · summary · explanation · indicators[]
                │
                ▼
   scan_id persisted at .local-data/scans/{scan_id}.json
        │
GET /scans/{scan_id}  → fetch full result at any time
```

**Key properties:**
- **No live malware needed** - ships with synthetic fixtures safe for demos
- **Layered signals** - patterns, signatures, YARA-X, behavior inference, and reputation are all independent and additive
- **Fully explainable** - every indicator carries `source`, `id`, `severity`, `file_path`, `evidence`, and `rationale`
- **Single binary** - `cargo run` starts the HTTP server and the web UI on the same port

---

## Features

- Upload `.jar` files up to 50 MB via multipart form or the web UI
- Static analysis with four built-in regex patterns (process exec, outbound URL, base64 blob, reflective loading)
- Extensible JSON signature corpus (`data/signatures/signatures.json`) supporting `token` and `regex` kinds
- YARA-X rule matching (`data/signatures/rules.yar`) compiled once at startup
- Behavior inference: predicts outbound network activity, file-system writes, and persistence from static findings
- Reputation scoring: composite author trust score from account age, prior mod count, and report activity
- Verdict synthesis: weighted severity scoring across all layers → risk tier + 0–100 score
- Persisted scan results - re-fetch any scan by `scan_id` without re-running analysis
- Browser UI with real-time status, indicator list, and scan-ID display
- Demo runner (`scripts/demo_run.sh`) that builds a synthetic suspicious sample and exercises all endpoints

---

## Risk Tiers

| Tier | Score range | Meaning |
|------|-------------|---------|
| `CLEAN` | 0 | No indicators detected across any layer |
| `LOW` | 1–39 | Minor signals; unlikely to be malicious but worth noting |
| `MEDIUM` | 40–64 | Multiple corroborating signals; review carefully before installing |
| `HIGH` | 65–84 | Strong evidence of suspicious behavior across two or more layers |
| `CRITICAL` | 85–100 | High-confidence malware markers; do not install |

---

## Quickstart

**Prerequisites:** Rust stable toolchain ([rustup.rs](https://rustup.rs))

```bash
git clone https://github.com/Microck/jarspect.git
cd jarspect
cargo run
```

The server starts on `http://127.0.0.1:8000` by default.

- **Web UI** → [http://localhost:8000/](http://localhost:8000/)
- **Health check** → [http://localhost:8000/health](http://localhost:8000/health)

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
curl -X POST http://localhost:8000/upload \
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
curl -X POST http://localhost:8000/scan \
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
curl http://localhost:8000/scans/<scan_id>
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `JARSPECT_BIND` | `127.0.0.1:8000` | Host and port the HTTP server binds to |
| `RUST_LOG` | `jarspect=info,tower_http=info` | Log verbosity (uses `tracing-subscriber` env-filter syntax) |

Example: bind to all interfaces on port 9000 with debug logging:

```bash
JARSPECT_BIND=0.0.0.0:9000 RUST_LOG=debug cargo run
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

**Response `200` example:**

```json
{
  "scan_id": "b7e2a0f1c3d456789abcdef012345678",
  "result": {
    "intake": {
      "upload_id": "a3f9c1d2e4b56789abcdef0123456789",
      "storage_path": ".local-data/uploads/a3f9c1d2e4b56789abcdef0123456789.jar",
      "file_count": 12,
      "class_file_count": 8
    },
    "static": {
      "matches": [
        {
          "source": "pattern",
          "id": "EXEC-RUNTIME",
          "title": "Runtime process execution",
          "category": "execution",
          "severity": "high",
          "file_path": "com/example/Loader.class",
          "evidence": "...Runtime.getRuntime().exec(new String[]{...",
          "rationale": "Detected process execution primitive commonly used in malware droppers."
        }
      ],
      "counts_by_category": { "execution": 1, "network": 1 },
      "counts_by_severity": { "high": 2 },
      "matched_pattern_ids": ["EXEC-RUNTIME", "NET-URL"],
      "matched_signature_ids": ["SIG-TOKEN-RUNTIME-EXEC", "YARA-RUNTIME_EXEC_MARKER"],
      "analyzed_files": 12
    },
    "behavior": {
      "predicted_network_urls": ["https://payload.example.invalid/bootstrap"],
      "predicted_file_writes": ["mods/cache.bin"],
      "predicted_persistence": ["startup task registration (predicted)"],
      "confidence": 0.82,
      "indicators": [...]
    },
    "reputation": {
      "author_id": "new_creator",
      "author_score": 0.17,
      "account_age_days": 7,
      "prior_mod_count": 0,
      "report_count": 3,
      "indicators": [...]
    },
    "verdict": {
      "risk_tier": "CRITICAL",
      "risk_score": 91,
      "summary": "Jarspect assessed this mod as CRITICAL risk (91/100) from layered static, YARA-X, behavior, and reputation signals.",
      "explanation": "Upload is assessed as CRITICAL risk (91/100) based on weighted indicator severity.\nIndicators considered: 7\n- [EXEC-RUNTIME] Runtime process execution (high) :: ...\n...",
      "indicators": [...]
    }
  }
}
```

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

Open [http://localhost:8000/](http://localhost:8000/) after starting the server.

The single-page console lets you:

1. **Pick a `.jar` file** from disk using the file picker
2. **Fill in optional author metadata** (Author ID, Mod ID, account age, prior mod count, report count) - useful for exercising the reputation layer in demos
3. **Click "Upload and Scan"** - the UI calls `/upload` then `/scan` and streams status messages
4. **Inspect the verdict panel** - displays risk tier, risk score, summary, explanation prose, and a scrollable indicator list with severity badges and evidence text

The `scan_id` is shown in the results header so you can re-fetch results later with `GET /scans/{scan_id}`.

---

## Architecture

![Architecture diagram](docs/architecture.svg)

> Mermaid source at `docs/architecture.mmd`

The scan pipeline runs entirely in a single Axum request handler:

```
POST /scan
  │
  ├─ Intake        read_archive_entries()  - unzip .jar, decode text, count .class files
  ├─ Static        run_static_analysis()   - regex patterns + JSON signatures + YARA-X per entry
  ├─ Behavior      infer_behavior()        - derive predicted URLs / writes / persistence from static matches
  ├─ Reputation    score_author()          - composite trust score (optional; only when author supplied)
  └─ Verdict       build_verdict()         - weighted severity sum → risk_score clamped 0–100 → risk_tier
```

**Signature loading** happens once at startup:
- `data/signatures/signatures.json` - loaded via `load_signatures()`
- `data/signatures/rules.yar` - compiled via `yara_x::Compiler` in `load_yara_rules()`, stored as `Arc<Rules>`

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
| `result.static` | object | All pattern/signature/YARA matches, deduplicated IDs, per-category/severity counts, `analyzed_files` |
| `result.behavior` | object | Predicted `network_urls`, `file_writes`, `persistence`; `confidence` float; `indicators[]` |
| `result.reputation` | object or null | `author_score` (0–1), raw metadata fields, `indicators[]`; null if no author provided |
| `result.verdict` | object | `risk_tier`, `risk_score` (0–100), `summary`, `explanation`, all `indicators[]` |

Each `Indicator` object:

| Field | Type | Description |
|-------|------|-------------|
| `source` | `string` | `pattern`, `signature`, `yara`, `behavior`, or `reputation` |
| `id` | `string` | Stable identifier (e.g. `EXEC-RUNTIME`, `SIG-TOKEN-RUNTIME-EXEC`, `YARA-RUNTIME_EXEC_MARKER`) |
| `title` | `string` | Human-readable label |
| `category` | `string` | `execution`, `network`, `obfuscation`, `signature`, `filesystem`, `persistence`, `reputation` |
| `severity` | `string` | `critical`, `high`, `med`, or `low` |
| `file_path` | `string` or null | Archive entry where the match was found |
| `evidence` | `string` | Extracted text snippet (±80 chars of context) |
| `rationale` | `string` | Why this indicator is suspicious |

---

## Safety and Limitations

- **Synthetic fixtures only.** The bundled signatures and YARA rules match strings from `demo/suspicious_sample.jar` - a synthetic artifact built by `demo/build_sample.sh`. No real malware samples are included.
- **Demo-grade behavior inference.** The behavior layer is deterministic heuristics, not dynamic analysis. It predicts plausible activity from static signals but does not execute code.
- **Demo-grade reputation scoring.** The reputation layer scores author metadata using a simple linear formula. It is not connected to a real registry or threat intelligence feed.
- **No sandbox.** Jarspect does not execute or load any `.class` files. All analysis is purely static (byte/text level).
- **50 MB upload cap.** Enforced server-side; configurable in source (`upload_max_bytes`).
- **`.jar` only.** Other archive types are rejected at the upload handler.

---

## Development

```bash
# Check for compile errors
cargo check

# Run tests
cargo test

# Build optimized binary
cargo build --release

# Run with verbose logging
RUST_LOG=debug cargo run
```

**Project layout:**

```
src/main.rs                         single-file Axum server + full scan pipeline
data/signatures/signatures.json     JSON signature corpus (token + regex kinds)
data/signatures/rules.yar           YARA-X rules (compiled at startup)
web/index.html                      single-page browser UI
web/app.js                          UI logic (upload + scan + render)
web/styles.css                      UI styles
scripts/demo_run.sh                 end-to-end demo runner
demo/build_sample.sh                builds synthetic suspicious_sample.jar
demo/suspicious_sample.jar          pre-built synthetic fixture
docs/architecture.mmd               Mermaid architecture diagram source
docs/architecture.svg               rendered architecture diagram
docs/brand/                         logo assets
.local-data/                        runtime data (gitignored)
  uploads/{upload_id}.jar           uploaded .jar files
  scans/{scan_id}.json              persisted scan results
```

To add new signatures, append entries to `data/signatures/signatures.json`. To add YARA rules, append rules to `data/signatures/rules.yar`. The compiler runs at startup and will report any syntax errors.

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
