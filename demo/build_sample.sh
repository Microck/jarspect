#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DEMO_DIR="${ROOT_DIR}/demo"
SOURCE_FILE="${DEMO_DIR}/samples/suspicious_mod_src/src/main/java/com/jarspect/demo/DemoMod.java"
OUTPUT_JAR="${DEMO_DIR}/suspicious_sample.jar"
BUILD_DIR="${DEMO_DIR}/.build"
OUTER_STAGE_DIR="${BUILD_DIR}/outer"
INNER_STAGE_DIR="${BUILD_DIR}/inner"
INNER_JAR="${BUILD_DIR}/inner-demo.jar"
NATIVE_STAGE_DIR="${BUILD_DIR}/native"

mkdir -p "${BUILD_DIR}" "${DEMO_DIR}"
rm -f "${OUTPUT_JAR}"
rm -rf "${OUTER_STAGE_DIR}" "${INNER_STAGE_DIR}" "${NATIVE_STAGE_DIR}"
mkdir -p "${OUTER_STAGE_DIR}/META-INF/jars" "${OUTER_STAGE_DIR}/META-INF" "${OUTER_STAGE_DIR}/com/jarspect/demo"
mkdir -p "${INNER_STAGE_DIR}"
mkdir -p "${NATIVE_STAGE_DIR}"

cp "${SOURCE_FILE}" "${OUTER_STAGE_DIR}/com/jarspect/demo/DemoMod.java"

printf '%s\n' '{"schemaVersion":1,"id":"jarspect-demo","version":"1.0.0","entrypoints":{"main":["com.jarspect.demo.DemoMod"]},"jars":[{"file":"META-INF/jars/inner-demo.jar"}]}' > "${OUTER_STAGE_DIR}/fabric.mod.json"
printf 'Manifest-Version: 1.0\nCreated-By: Jarspect Demo\nPremain-Class: com.jarspect.demo.DemoMod\n\n' > "${OUTER_STAGE_DIR}/META-INF/MANIFEST.MF"

printf 'c2.jarspect.example.invalid\n' > "${INNER_STAGE_DIR}/payload.txt"
(
  cd "${INNER_STAGE_DIR}"
  zip -X -q "${INNER_JAR}" payload.txt
)
cp "${INNER_JAR}" "${OUTER_STAGE_DIR}/META-INF/jars/inner-demo.jar"
printf 'native-placeholder\n' > "${NATIVE_STAGE_DIR}/dummy.dll"

if command -v javac >/dev/null 2>&1 && command -v jar >/dev/null 2>&1; then
  javac -d "${OUTER_STAGE_DIR}" "${OUTER_STAGE_DIR}/com/jarspect/demo/DemoMod.java"

  # Keep output layout identical to fallback mode while using the JDK jar tool.
  (
    cd "${OUTER_STAGE_DIR}"
    jar cfm "${OUTPUT_JAR}" META-INF/MANIFEST.MF .
  )
else
  echo "[build_sample] javac/jar not found; creating deterministic zip-based fallback" >&2
  (
    cd "${OUTER_STAGE_DIR}"
    zip -X -q -r "${OUTPUT_JAR}" .
  )
fi

if command -v jar >/dev/null 2>&1; then
  (
    cd "${BUILD_DIR}"
    jar uf "${OUTPUT_JAR}" native/dummy.dll
  )
elif command -v zip >/dev/null 2>&1; then
  (
    cd "${BUILD_DIR}"
    zip -X -q "${OUTPUT_JAR}" native/dummy.dll
  )
else
  echo "[build_sample] neither jar nor zip is available to add native/dummy.dll" >&2
  exit 1
fi

echo "Built synthetic sample jar: ${OUTPUT_JAR}"
