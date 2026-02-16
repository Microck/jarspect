#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${JARSPECT_API_URL:-http://localhost:8000}"
JAR_PATH="${ROOT_DIR}/demo/suspicious_sample.jar"

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
