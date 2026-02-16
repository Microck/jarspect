# Jarspect

Jarspect is a multi-agent security scanner for Minecraft mods (`.jar`) that helps players and communities detect suspicious behavior before installation.

Built for: Microsoft AI Dev Days Hackathon 2026
Categories: AI Apps and Agents, Best Enterprise Solution
Demo video: <paste hosted link>

## Quickstart

Prereqs:
- Rust (stable toolchain)

1. Run the API + web UI:

```bash
cargo run
```

2. Open:
- `http://localhost:8000/` for upload + verdict UI
- `http://localhost:8000/docs` for API docs

3. Run the demo script (in another terminal, with the server still running):

```bash
bash scripts/demo_run.sh
```

Expected: prints `scan_id`, `risk_tier`, `risk_score`, and top indicators.

## What It Does

Jarspect combines deterministic static analysis, YARA-X signature matching, behavior prediction, author reputation scoring, and verdict synthesis.

Pipeline:

```text
Upload (.jar)
  -> Intake Agent (loader + manifest inspection)
  -> Static Agent (archive inspection + heuristics + YARA-X signature matches)
  -> Behavior Agent (predicted file/network/persistence behavior)
  -> Reputation Agent (optional author metadata + fixture history)
  -> Verdict Agent (risk tier + score + explanation + indicators)
  -> Persisted Scan Result (scan_id; GET /scans/{scan_id})
```

## API Surface (Minimal)

- `POST /upload` (multipart file upload)
- `POST /scan` (scan an upload_id + metadata)
- `GET /scans/{scan_id}` (fetch persisted results)

Interactive docs: `http://localhost:8000/docs`

## Verification

```bash
cargo check
cargo test
```

## Safety Note

Jarspect includes synthetic demo fixtures only.

- `demo/samples/suspicious_mod_src/` is intentionally benign source code.
- `demo/suspicious_sample.jar` is generated locally for demonstrations.
- No real malware samples are downloaded, bundled, or distributed.

## Demo Recording

Follow `demo/recording-checklist.md`.

## License

Apache-2.0 (see `LICENSE`).
