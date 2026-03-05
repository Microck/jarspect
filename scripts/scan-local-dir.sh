#!/usr/bin/env bash
set -euo pipefail

SERVER_URL=${SERVER_URL:-"http://127.0.0.1:18000"}
RUN_ID=${RUN_ID:-"$(date -u +%Y%m%dT%H%M%SZ)"}

IN_DIR=${1:-${IN_DIR:-""}}
if [[ -z "$IN_DIR" ]]; then
  echo "Usage: bash scripts/scan-local-dir.sh /path/to/jars" >&2
  echo "Env: SERVER_URL, DATASET, RUN_ID, OUT_DIR" >&2
  exit 2
fi
if [[ ! -d "$IN_DIR" ]]; then
  echo "ERROR: not a directory: $IN_DIR" >&2
  exit 2
fi

base=$(basename "$IN_DIR")
DATASET=${DATASET:-"local-dir-${base}"}
OUT_DIR=${OUT_DIR:-".local-data/runs/${DATASET}-${RUN_ID}"}

mkdir -p "$OUT_DIR/json"

RUN_JSON="$OUT_DIR/run.json"
RESULTS_CSV="$OUT_DIR/results.csv"

if [[ ! -f "$RUN_JSON" ]]; then
  git_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
  ai_deployment=$(rg -N --no-filename '^AZURE_OPENAI_DEPLOYMENT=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)
  rulepacks=$(rg -N --no-filename '^JARSPECT_RULEPACKS=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)
  server_health=$(curl -fsS "$SERVER_URL/health" 2>/dev/null | jq -c . 2>/dev/null || echo "null")

  cat > "$RUN_JSON" <<EOF
{
  "run_id": "${RUN_ID}",
  "dataset": "${DATASET}",
  "server_url": "${SERVER_URL}",
  "server_health": ${server_health},
  "input_dir": "${IN_DIR}",
  "git_commit": "${git_commit}",
  "azure_openai_deployment": "${ai_deployment}",
  "rulepacks": "${rulepacks}"
}
EOF
fi

if [[ ! -f "$RESULTS_CSV" ]]; then
  echo "file_path,file_name,size_bytes,sha256,scan_id,verdict,confidence,risk_score,method,error" > "$RESULTS_CSV"
fi

shopt -s nullglob
files=("$IN_DIR"/*.jar)
if [[ ${#files[@]} -eq 0 ]]; then
  echo "No .jar files found in: $IN_DIR" >&2
  exit 0
fi

echo "Scanning ${#files[@]} jar(s) from $IN_DIR"

for jar_path in "${files[@]}"; do
  file_name=$(basename "$jar_path")
  size_bytes=$(wc -c < "$jar_path" | tr -d ' ')
  sha256=$(sha256sum "$jar_path" | awk '{print $1}')

  upload_json="$OUT_DIR/json/${sha256}-upload.json"
  scan_json="$OUT_DIR/json/${sha256}-scan.json"

  err=""
  scan_id=""
  verdict=""
  confidence=""
  risk_score=""
  method=""

  if ! curl -fsS -X POST "$SERVER_URL/upload" -F "file=@${jar_path}" -o "$upload_json"; then
    err="upload_failed"
    echo "$jar_path,$file_name,$size_bytes,$sha256,$scan_id,$verdict,$confidence,$risk_score,$method,$err" >> "$RESULTS_CSV"
    continue
  fi

  upload_id=$(jq -r '.upload_id // empty' "$upload_json" 2>/dev/null || true)
  if [[ -z "$upload_id" ]]; then
    err="upload_missing_upload_id"
    echo "$jar_path,$file_name,$size_bytes,$sha256,$scan_id,$verdict,$confidence,$risk_score,$method,$err" >> "$RESULTS_CSV"
    continue
  fi

  if ! curl -fsS -X POST "$SERVER_URL/scan" -H "Content-Type: application/json" \
    -d "{\"upload_id\":\"$upload_id\"}" -o "$scan_json"; then
    err="scan_failed"
    echo "$jar_path,$file_name,$size_bytes,$sha256,$scan_id,$verdict,$confidence,$risk_score,$method,$err" >> "$RESULTS_CSV"
    continue
  fi

  scan_id=$(jq -r '.scan_id // empty' "$scan_json" 2>/dev/null || true)
  verdict=$(jq -r '.verdict.result // empty' "$scan_json" 2>/dev/null || true)
  confidence=$(jq -r '.verdict.confidence // empty' "$scan_json" 2>/dev/null || true)
  risk_score=$(jq -r '.verdict.risk_score // empty' "$scan_json" 2>/dev/null || true)
  method=$(jq -r '.verdict.method // empty' "$scan_json" 2>/dev/null || true)

  echo "$jar_path,$file_name,$size_bytes,$sha256,$scan_id,$verdict,$confidence,$risk_score,$method,$err" >> "$RESULTS_CSV"
done

echo "Done. Results: $RESULTS_CSV"
