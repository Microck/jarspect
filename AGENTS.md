# AGENTS.md

Instructions for AI coding agents working with this codebase.

## Architecture

Jarspect is a 3-layer security scanner for Minecraft `.jar` mods, written in Rust:

1. **Layer 1** (`src/malwarebazaar.rs`): MalwareBazaar SHA-256 hash lookup
2. **Layer 2** (`src/analysis/`, `src/detectors/`): bytecode capability extraction + YARA
3. **Layer 3** (`src/verdict.rs`): Azure OpenAI AI verdict
4. **Static override** (`src/scan.rs`): high-confidence static signals override AI verdict to MALICIOUS

Pipeline orchestrator: `src/scan.rs`. HTTP transport: `src/main.rs`. Profile builder: `src/profile.rs`.

## Key conventions

- All tests are in-crate (`#[cfg(test)]`) or in `tests/`. Run with `cargo test`.
- No mocks. Tests use real fixtures under `tests/fixtures/`.
- YARA rules live in `data/signatures/{demo,prod}/rules.yar`. Production rules require multiple corroborating strings.
- Runtime data goes in `.local-data/` (gitignored).
- Environment configuration: see `.env.example` for all variables.

## Detector pattern

Each capability detector (`src/detectors/capability_*.rs`) follows the same shape:
- Takes `&EvidenceIndex` (from `src/detectors/index.rs`)
- Returns `Vec<Indicator>` with `id`, `severity`, `evidence`, `source: "detector"`
- Uses class-scoped correlation gates for severity escalation
