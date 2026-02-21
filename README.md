# Jarspect

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Jarspect is a security scanner for Minecraft mods (`.jar`) that flags suspicious behavior before installation.

It combines deterministic static analysis (patterns + signatures + YARA-X), fixture-backed reputation scoring, and a final verdict synthesis that produces a risk tier, score, and explainable indicators.

## Quickstart

Prereqs:
- Rust (stable toolchain)

```bash
cargo run
```

Open:
- http://localhost:8000/ (UI)
- http://localhost:8000/health

## Installation

TODO: document Rust toolchain setup if needed.

## Usage

High-level flow:
1. Upload a `.jar` -> get `upload_id`
2. Scan the upload -> get `scan_id`
3. Fetch results by `scan_id`

## Configuration

- `JARSPECT_BIND` (default `127.0.0.1:8000`)
- `RUST_LOG` (default `jarspect=info,tower_http=info`)

## API Reference

TODO: add request/response examples.

- `POST /upload`
- `POST /scan`
- `GET /scans/{scan_id}`
- `GET /health`

## Web UI

TODO: describe what the UI shows and where verdicts/indicators appear.

## Architecture

TODO: add a short flow describing: intake -> static -> behavior -> reputation -> verdict.

## Data Model

Persisted results:
- `.local-data/scans/{scan_id}.json`

TODO: document the top-level JSON fields.

## Safety & Limitations

- Synthetic demo fixtures only; no real malware samples
- Behavior/reputation layers are deterministic demo logic (hackathon scope)

## Development

```bash
cargo check
cargo test
```

## Testing

```bash
cargo test
```

## Contributing

Issues and pull requests are welcome.

## Support

TODO: add Issues/Discussions link.

## Security

TODO: add security policy (or add `SECURITY.md` and link it).

## License

Apache-2.0 (see `LICENSE`).

## Changelog / Releases

TODO: link to GitHub Releases or add `CHANGELOG.md`.

## Roadmap

- `.planning/ROADMAP.md`
