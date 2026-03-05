# Jarspect - Test & Smoke Checklist

Goal: run the exact checks needed before recording the submission video and submitting.

## 0) Repo sanity

```bash
cd projects/jarspect
git status --porcelain
```

Expected: no output (clean working tree).

## 1) Tooling sanity

```bash
cargo --version
curl --version
```

## 2) Automated tests (Rust)

```bash
cargo check
cargo test
```

Expected: 70 unit + 3 integration tests pass.

## 3) Local smoke (API + UI)

Terminal 1 -- start server with production YARA rules:

```bash
JARSPECT_RULEPACKS=prod cargo run
```

Terminal 2 -- health check:

```bash
curl -sS http://localhost:18000/health | python3 -m json.tool
```

Expected: `status: ok`, `ai_enabled: true` (if Azure env vars set), `rulepacks: ["prod"]`.

UI: open http://localhost:18000/ -- verify health dot is green, upload zone is visible.

## 4) E2E scan smoke

Upload + scan a benign jar:

```bash
UPLOAD=$(curl -s -X POST http://localhost:18000/upload -F "file=@path/to/benign.jar")
UPLOAD_ID=$(echo "$UPLOAD" | python3 -c "import sys,json; print(json.load(sys.stdin)['upload_id'])")
curl -s -X POST http://localhost:18000/scan \
  -H "Content-Type: application/json" \
  -d "{\"upload_id\": \"$UPLOAD_ID\"}" | python3 -m json.tool
```

Expected: verdict `CLEAN`, method `ai_verdict`.

## 5) Demo smoke (scripted)

```bash
bash scripts/demo_run.sh
```

Expected: prints scan results with verdict, confidence, and explanation.

## 6) Submission artifacts

- README: `README.md`
- Architecture diagram: `docs/architecture.svg` (source: `docs/architecture.mmd`)
- Voiceover script: `demo/voiceover.md`
- Docs: `docs/corpus-calibration.md`, `docs/benchmarking.md`, `docs/false-positives.md`
