#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${JARSPECT_API_URL:-http://localhost:8000}"
JAR_PATH="${ROOT_DIR}/demo/suspicious_sample.jar"
SERVER_PID=""
SERVER_LOG=""

cleanup() {
  if [ -n "${SERVER_PID}" ] && kill -0 "${SERVER_PID}" 2>/dev/null; then
    kill "${SERVER_PID}" 2>/dev/null || true
    wait "${SERVER_PID}" 2>/dev/null || true
  fi
}

trap cleanup EXIT

is_jarspect_api() {
  local base_url="$1"
  local health_response=""

  if ! health_response="$(curl -sS --max-time 2 "${base_url}/health" 2>/dev/null)"; then
    return 1
  fi

  HEALTH_JSON="${health_response}" node -e '
const payload = JSON.parse(process.env.HEALTH_JSON || "{}");
process.exit(payload.service === "jarspect" ? 0 : 1);
' >/dev/null 2>&1
}

wait_for_jarspect_api() {
  local base_url="$1"
  local retries="$2"
  local attempt=0

  until is_jarspect_api "${base_url}"; do
    attempt=$((attempt + 1))
    if [ "${attempt}" -ge "${retries}" ]; then
      return 1
    fi
    sleep 0.2
  done

  return 0
}

pick_free_port() {
  local port=""
  for port in $(seq 18000 18100); do
    if ! ss -ltn "sport = :${port}" | grep -q LISTEN; then
      printf '%s' "${port}"
      return 0
    fi
  done

  return 1
}

start_local_server() {
  local port=""
  port="$(pick_free_port)" || {
    echo "[demo] Unable to find a free local port in 18000-18100" >&2
    exit 1
  }

  mkdir -p "${ROOT_DIR}/.local-data"
  SERVER_LOG="${ROOT_DIR}/.local-data/demo-server.log"
  API_BASE_URL="http://127.0.0.1:${port}"

  echo "[demo] Starting local Jarspect API at ${API_BASE_URL} ..."
  (
    cd "${ROOT_DIR}"
    JARSPECT_BIND="127.0.0.1:${port}" cargo run >"${SERVER_LOG}" 2>&1
  ) &
  SERVER_PID=$!

  if ! wait_for_jarspect_api "${API_BASE_URL}" 60; then
    echo "[demo] Failed to start Jarspect API. Last server log lines:" >&2
    if [ -f "${SERVER_LOG}" ]; then
      tail -n 40 "${SERVER_LOG}" >&2 || true
    fi
    exit 1
  fi
}

if is_jarspect_api "${API_BASE_URL}"; then
  echo "[demo] Using existing Jarspect API at ${API_BASE_URL}"
elif [ -n "${JARSPECT_API_URL:-}" ]; then
  echo "[demo] JARSPECT_API_URL points to a non-Jarspect service: ${API_BASE_URL}" >&2
  echo "[demo] Expected GET /health to return JSON with {\"service\":\"jarspect\"}." >&2
  exit 1
else
  echo "[demo] No Jarspect API detected at ${API_BASE_URL}; auto-starting one."
  start_local_server
fi

echo "[demo] Building synthetic sample jar..."
bash "${ROOT_DIR}/demo/build_sample.sh" >/dev/null

echo "[demo] Uploading sample to ${API_BASE_URL}/upload ..."
UPLOAD_RESPONSE="$(curl -sS --fail -X POST "${API_BASE_URL}/upload" -F "file=@${JAR_PATH};type=application/java-archive")"
UPLOAD_ID="$(UPLOAD_JSON="${UPLOAD_RESPONSE}" node -e 'const payload = JSON.parse(process.env.UPLOAD_JSON); process.stdout.write(payload.upload_id);')"

SCAN_REQUEST='{"author":{"author_id":"new_creator","mod_id":"demo-suspicious","account_age_days":7,"prior_mod_count":0,"report_count":3}}'

SCAN_REQUEST="$(SCAN_REQUEST_JSON="${SCAN_REQUEST}" UPLOAD_ID_VALUE="${UPLOAD_ID}" node -e 'const payload = JSON.parse(process.env.SCAN_REQUEST_JSON); payload.upload_id = process.env.UPLOAD_ID_VALUE; process.stdout.write(JSON.stringify(payload));')"

echo "[demo] Running full scan..."
SCAN_RESPONSE="$(curl -sS --fail -X POST "${API_BASE_URL}/scan" -H "Content-Type: application/json" -d "${SCAN_REQUEST}")"

SCAN_ID="$(SCAN_JSON="${SCAN_RESPONSE}" node -e 'const payload = JSON.parse(process.env.SCAN_JSON); process.stdout.write(payload.scan_id);')"

FETCH_RESPONSE="$(curl -sS --fail "${API_BASE_URL}/scans/${SCAN_ID}")"

echo "[demo] Scan complete."
SCAN_JSON="${SCAN_RESPONSE}" FETCH_JSON="${FETCH_RESPONSE}" node - <<'NODE'
const scanPayload = JSON.parse(process.env.SCAN_JSON || "{}");
const fetchPayload = JSON.parse(process.env.FETCH_JSON || "{}");
const result = scanPayload.result || {};
const verdict = result.verdict || {};
const indicators = Array.isArray(verdict.indicators) ? verdict.indicators : [];

console.log("");
console.log(`scan_id: ${scanPayload.scan_id || "unknown"}`);
console.log(`risk_tier: ${verdict.risk_tier || "UNKNOWN"}`);
console.log(`risk_score: ${verdict.risk_score ?? "?"}`);
console.log("");
console.log("top_indicators:");
for (const indicator of indicators.slice(0, 5)) {
  console.log(`- [${indicator.severity || "unknown"}] ${indicator.id || "unknown"} (${indicator.source || "unknown"}) ${indicator.title || ""}`);
}
if (!indicators.length) {
  console.log("- none");
}
if (fetchPayload.scan_id !== scanPayload.scan_id) {
  console.error("fetched scan_id mismatch");
  process.exit(1);
}
NODE
