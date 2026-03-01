# Jarspect - Test & Smoke Checklist

Goal: run the exact checks needed before recording the submission video and submitting.

## 0) Repo sanity

```bash
cd projects/jarspect
git status --porcelain
```

Expected: no output.

## 1) Tooling sanity

```bash
cargo --version
curl --version
node --version
```

Note: `scripts/demo_run.sh` uses Node.js to parse JSON output.

## 2) Automated tests (Rust)

```bash
cd projects/jarspect
cargo check
cargo test
```

## 3) Local smoke (API + UI)

Terminal 1:

```bash
cd projects/jarspect
cargo run
```

Terminal 2:

```bash
curl -sS http://localhost:8000/health
```

UI:
- http://localhost:8000/

## 4) Demo smoke (scripted)

```bash
cd projects/jarspect
bash scripts/demo_run.sh
```

Expected: prints `scan_id`, `risk_tier`, `risk_score`, and a `top_indicators` list.

## 5) Submission artifacts

- README: `README.md`
- Architecture diagram: `docs/architecture.svg` (source: `docs/architecture.mmd`)
- Recording checklist: `demo/recording-checklist.md`
- Optional local video artifact: `demo/video.mp4`
