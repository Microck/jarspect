#!/usr/bin/env bash
set -euo pipefail

SERVER_URL=${SERVER_URL:-"http://127.0.0.1:18000"}
LIMIT=${LIMIT:-50}
RUN_ID=${RUN_ID:-"$(date -u +%Y%m%dT%H%M%SZ)"}
OUT_DIR=${OUT_DIR:-".local-data/runs/modrinth-top-${LIMIT}-${RUN_ID}"}

SEARCH_PAGES_DIR="$OUT_DIR/search-pages"
mkdir -p "$OUT_DIR/jars" "$OUT_DIR/json" "$SEARCH_PAGES_DIR"

SEARCH_BASE_URL="https://api.modrinth.com/v2/search?index=downloads&facets=%5B%5B%22project_type:mod%22%5D%5D"
SEARCH_URL="${SEARCH_BASE_URL}&limit=${LIMIT}&offset=0"
SEARCH_JSON="$OUT_DIR/search.json"
RESULTS_CSV="$OUT_DIR/results.csv"
RUN_JSON="$OUT_DIR/run.json"

if [[ ! -f "$RUN_JSON" ]]; then
  git_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
  ai_deployment=$(rg -N --no-filename '^AZURE_OPENAI_DEPLOYMENT=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)
  rulepacks=$(rg -N --no-filename '^JARSPECT_RULEPACKS=' .env 2>/dev/null | head -1 | cut -d= -f2- || true)
  server_health=$(curl -fsS "$SERVER_URL/health" 2>/dev/null | jq -c . 2>/dev/null || echo "null")

  cat > "$RUN_JSON" <<EOF
{
  "run_id": "${RUN_ID}",
  "dataset": "modrinth-top-${LIMIT}",
  "server_url": "${SERVER_URL}",
  "server_health": ${server_health},
  "limit": ${LIMIT},
  "search_url": "${SEARCH_URL}",
  "git_commit": "${git_commit}",
  "azure_openai_deployment": "${ai_deployment}",
  "rulepacks": "${rulepacks}"
}
EOF
fi

need_fetch=1
if [[ -f "$SEARCH_JSON" ]]; then
  existing_hits=$(jq -r '.hits | length' "$SEARCH_JSON" 2>/dev/null || echo "0")
  if [[ "$existing_hits" -ge "$LIMIT" ]]; then
    need_fetch=0
  fi
fi

if [[ "$need_fetch" -eq 1 ]]; then
  echo "Fetching Modrinth top mods (limit=$LIMIT)..."

  page_files=()
  remaining=$LIMIT
  offset=0
  while [[ "$remaining" -gt 0 ]]; do
    page_limit=100
    if [[ "$remaining" -lt 100 ]]; then
      page_limit=$remaining
    fi

    page_json="$SEARCH_PAGES_DIR/offset-${offset}.json"
    page_url="${SEARCH_BASE_URL}&limit=${page_limit}&offset=${offset}"

    if [[ ! -f "$page_json" ]]; then
      curl -fsS -H "User-Agent: jarspect/0.1.0 (batch scan)" "$page_url" -o "$page_json"
    fi

    if ! jq -e '.hits and (.hits | type=="array")' "$page_json" >/dev/null 2>&1; then
      echo "ERROR: invalid Modrinth search response JSON: $page_json" >&2
      exit 1
    fi

    hits_len=$(jq -r '.hits | length' "$page_json")
    if [[ "$hits_len" -eq 0 ]]; then
      break
    fi

    page_files+=("$page_json")
    remaining=$((remaining - hits_len))
    offset=$((offset + hits_len))

    if [[ "$hits_len" -lt "$page_limit" ]]; then
      break
    fi
  done

  if [[ ${#page_files[@]} -eq 0 ]]; then
    echo "ERROR: no Modrinth results fetched" >&2
    exit 1
  fi

  jq -s --argjson limit "$LIMIT" '{hits:(map(.hits) | add), offset:0, limit:$limit, total_hits:(.[0].total_hits // 0)}' \
    "${page_files[@]}" > "$SEARCH_JSON.tmp"
  mv "$SEARCH_JSON.tmp" "$SEARCH_JSON"
fi

if [[ ! -f "$RESULTS_CSV" ]]; then
  echo "rank,project_id,slug,title,downloads,version,filename,sha256,scan_id,verdict,confidence,risk_score,method" > "$RESULTS_CSV"
fi

declare -A done
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  [[ "$line" == rank,* ]] && continue
  pid=$(printf '%s' "$line" | cut -d, -f2)
  [[ -n "$pid" ]] && done["$pid"]=1
done < "$RESULTS_CSV"

rank=0

if ! jq -e '.hits and (.hits | type=="array")' "$SEARCH_JSON" >/dev/null 2>&1; then
  echo "ERROR: invalid Modrinth search response JSON: $SEARCH_JSON" >&2
  exit 1
fi

project_ids=$(jq -r '.hits[].project_id' "$SEARCH_JSON")

for project_id in $project_ids; do
  rank=$((rank+1))

  if [[ -n "${done[$project_id]:-}" ]]; then
    echo "[$rank/$LIMIT] $project_id (already scanned)"
    continue
  fi
  slug=$(jq -r --arg id "$project_id" '.hits[] | select(.project_id==$id) | .slug' "$SEARCH_JSON")
  title=$(jq -r --arg id "$project_id" '.hits[] | select(.project_id==$id) | .title' "$SEARCH_JSON")
  downloads=$(jq -r --arg id "$project_id" '.hits[] | select(.project_id==$id) | .downloads' "$SEARCH_JSON")

  echo "[$rank/$LIMIT] $slug"

  versions_json="$OUT_DIR/json/${slug}-${project_id}-versions.json"
  if [[ ! -f "$versions_json" ]]; then
    curl -fsS -H "User-Agent: jarspect/0.1.0 (batch scan)" "https://api.modrinth.com/v2/project/${project_id}/version" -o "$versions_json" || {
      echo "WARN: failed to fetch versions for $slug" >&2
      continue
    }
  fi

  if ! jq -e 'type=="array" and length>0' "$versions_json" >/dev/null 2>&1; then
    echo "WARN: invalid versions JSON for $slug" >&2
    continue
  fi

  # Take the newest version and its primary jar file.
  version=$(jq -r '.[0].version_number // empty' "$versions_json" 2>/dev/null || true)
  file_url=$(jq -r '.[0].files[] | select(.primary==true) | .url' "$versions_json" 2>/dev/null | head -1 || true)
  filename=$(jq -r '.[0].files[] | select(.primary==true) | .filename' "$versions_json" 2>/dev/null | head -1 || true)

  if [[ -z "${version}" || -z "${file_url}" || -z "${filename}" ]]; then
    echo "WARN: missing primary file for $slug" >&2
    continue
  fi
  if [[ "${filename,,}" != *.jar ]]; then
    echo "WARN: primary file is not a .jar for $slug ($filename)" >&2
    continue
  fi

  jar_path="$OUT_DIR/jars/${slug}-${version}.jar"
  if [[ ! -f "$jar_path" ]]; then
    curl -fsS -L -H "User-Agent: jarspect/0.1.0 (batch scan)" "$file_url" -o "$jar_path" || {
      echo "WARN: download failed for $slug" >&2
      rm -f "$jar_path"
      continue
    }
  fi

  if [[ ! -s "$jar_path" ]]; then
    echo "WARN: downloaded jar is empty for $slug" >&2
    rm -f "$jar_path"
    continue
  fi

  sha256=$(sha256sum "$jar_path" | awk '{print $1}')

  upload_json="$OUT_DIR/json/${slug}-${version}-upload.json"
  scan_json="$OUT_DIR/json/${slug}-${version}-scan.json"

  curl -fsS -X POST "$SERVER_URL/upload" -F "file=@${jar_path}" -o "$upload_json" || {
    echo "WARN: upload failed for $slug" >&2
    continue
  }
  upload_id=$(jq -r '.upload_id // empty' "$upload_json")
  if [[ -z "$upload_id" ]]; then
    echo "WARN: upload response missing upload_id for $slug" >&2
    continue
  fi

  curl -fsS -X POST "$SERVER_URL/scan" -H "Content-Type: application/json" \
    -d "{\"upload_id\":\"$upload_id\"}" -o "$scan_json" || {
    echo "WARN: scan failed for $slug" >&2
    continue
  }

  scan_id=$(jq -r '.scan_id // empty' "$scan_json")
  verdict=$(jq -r '.verdict.result // empty' "$scan_json")
  confidence=$(jq -r '.verdict.confidence // empty' "$scan_json")
  risk_score=$(jq -r '.verdict.risk_score // empty' "$scan_json")
  method=$(jq -r '.verdict.method // empty' "$scan_json")

  # CSV escape quotes in title
  safe_title=$(printf '%s' "$title" | sed 's/"/""/g')
  echo "$rank,$project_id,$slug,\"$safe_title\",$downloads,$version,$filename,$sha256,$scan_id,$verdict,$confidence,$risk_score,$method" >> "$RESULTS_CSV"

  done["$project_id"]=1
done

echo "Done. Results: $RESULTS_CSV"
