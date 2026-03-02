# Regression Fixtures

This directory contains synthetic fixture artifacts used by integration tests.

## Safety guarantees

- The fixture source (`java-src/AllCapabilities.java`) is intentionally synthetic.
- Capability-like code paths are guarded behind an unreachable runtime condition.
- The fixture exists only to exercise static scan logic and detector coverage.
- No real malware payloads or active C2 infrastructure are included.

## Regenerating fixtures

Run:

```bash
tools/build-regression-fixtures.sh
```

The script:

- Compiles `AllCapabilities.java` using local `javac` when available.
- Falls back to Docker (`eclipse-temurin:17-jdk`) if `javac` is unavailable.
- Adds `native/demo.so` with deterministic bytes (`DEMO`) into the classes tree.
- Calls `cargo run --quiet --bin build-regression-fixtures -- <classes-dir> <out-jar>`
  to produce a deterministic jar (stored entries, fixed timestamps).
- Writes `bytecode/all-capabilities.sha256` for provenance.

## Test behavior

- Tests consume the committed `bytecode/all-capabilities.jar` directly.
- Tests do **not** invoke the build script.
- Running `cargo test` does not require `javac`, `jar`, or Docker.
