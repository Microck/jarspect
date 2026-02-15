#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_BASE_URL="${PATCHWARDEN_API_URL:-http://localhost:8000}"
JAR_PATH="${ROOT_DIR}/demo/suspicious_sample.jar"

echo "[demo] Building synthetic sample jar..."
bash "${ROOT_DIR}/demo/build_sample.sh" >/dev/null

echo "[demo] Uploading sample to ${API_BASE_URL}/upload ..."
UPLOAD_RESPONSE="$(curl -sS --fail -X POST "${API_BASE_URL}/upload" -F "file=@${JAR_PATH};type=application/java-archive")"
UPLOAD_ID="$(UPLOAD_JSON="${UPLOAD_RESPONSE}" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["UPLOAD_JSON"])
print(payload["upload_id"])
PY
)"

SCAN_REQUEST="$(python3 - <<'PY'
import json

payload = {
    "author": {
        "author_id": "new_creator",
        "mod_id": "demo-suspicious",
        "account_age_days": 7,
        "prior_mod_count": 0,
        "report_count": 3,
    }
}
print(json.dumps(payload))
PY
)"

SCAN_REQUEST="$(SCAN_REQUEST_JSON="${SCAN_REQUEST}" UPLOAD_ID_VALUE="${UPLOAD_ID}" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["SCAN_REQUEST_JSON"])
payload["upload_id"] = os.environ["UPLOAD_ID_VALUE"]
print(json.dumps(payload))
PY
)"

echo "[demo] Running full scan..."
SCAN_RESPONSE="$(curl -sS --fail -X POST "${API_BASE_URL}/scan" -H "Content-Type: application/json" -d "${SCAN_REQUEST}")"

SCAN_ID="$(SCAN_JSON="${SCAN_RESPONSE}" python3 - <<'PY'
import json
import os

payload = json.loads(os.environ["SCAN_JSON"])
print(payload["scan_id"])
PY
)"

FETCH_RESPONSE="$(curl -sS --fail "${API_BASE_URL}/scans/${SCAN_ID}")"

echo "[demo] Scan complete."
SCAN_JSON="${SCAN_RESPONSE}" FETCH_JSON="${FETCH_RESPONSE}" python3 - <<'PY'
import json
import os

scan_payload = json.loads(os.environ["SCAN_JSON"])
fetch_payload = json.loads(os.environ["FETCH_JSON"])

result = scan_payload.get("result", {})
verdict = result.get("verdict", {})
indicators = verdict.get("indicators", [])

print("")
print(f"scan_id: {scan_payload.get('scan_id', 'unknown')}")
print(f"risk_tier: {verdict.get('risk_tier', 'UNKNOWN')}")
print(f"risk_score: {verdict.get('risk_score', '?')}")
print("")
print("top_indicators:")
for indicator in indicators[:5]:
    indicator_id = indicator.get("id", "unknown")
    severity = indicator.get("severity", "unknown")
    source = indicator.get("source", "unknown")
    title = indicator.get("title", "")
    print(f"- [{severity}] {indicator_id} ({source}) {title}")

if not indicators:
    print("- none")

fetched_scan_id = fetch_payload.get("scan_id")
if fetched_scan_id != scan_payload.get("scan_id"):
    raise SystemExit("fetched scan_id mismatch")
PY
