#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${ROOT_DIR}/demo"
SOURCE_FILE="${DEMO_DIR}/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java"
OUTPUT_JAR="${DEMO_DIR}/suspicious_sample.jar"
BUILD_DIR="${DEMO_DIR}/.build"

mkdir -p "${BUILD_DIR}" "${DEMO_DIR}"
rm -f "${OUTPUT_JAR}"

if command -v javac >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
  CLASSES_DIR="${BUILD_DIR}/classes"
  rm -rf "${CLASSES_DIR}"
  mkdir -p "${CLASSES_DIR}"

  javac -d "${CLASSES_DIR}" "${SOURCE_FILE}"
  (
    cd "${CLASSES_DIR}"
    jar cf "${OUTPUT_JAR}" .
  )
else
  echo "[build_sample] javac/jar not found; creating deterministic synthetic jar fallback" >&2
  STAGE_DIR="${BUILD_DIR}/fallback"
  rm -rf "${STAGE_DIR}"
  mkdir -p "${STAGE_DIR}/META-INF" "${STAGE_DIR}/com/jarspect/demo"
  printf 'Manifest-Version: 1.0\nCreated-By: Jarspect Demo\n\n' > "${STAGE_DIR}/META-INF/MANIFEST.MF"
  cp "${SOURCE_FILE}" "${STAGE_DIR}/com/jarspect/demo/DemoMod.java"
  (
    cd "${STAGE_DIR}"
    zip -qr "${OUTPUT_JAR}" .
  )
fi

echo "Built synthetic sample jar: ${OUTPUT_JAR}"
