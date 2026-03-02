#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="${ROOT_DIR}/tests/fixtures/java-src"
OUT_DIR="${ROOT_DIR}/tests/fixtures/bytecode"
OUT_JAR="${OUT_DIR}/all-capabilities.jar"
OUT_SHA256="${OUT_DIR}/all-capabilities.sha256"
BUILD_ROOT="${ROOT_DIR}/target/regression-fixtures"
CLASSES_DIR="${BUILD_ROOT}/classes"

CONTAINER_WORKDIR="/work"
CONTAINER_SRC_DIR="${CONTAINER_WORKDIR}/src"
CONTAINER_CLASSES_DIR="${CONTAINER_WORKDIR}/classes"

JAVA_SOURCES=("${SRC_DIR}/AllCapabilities.java")

rm -rf "${BUILD_ROOT}"
mkdir -p "${CLASSES_DIR}" "${OUT_DIR}"

if command -v javac >/dev/null 2>&1; then
  javac --release 17 -d "${CLASSES_DIR}" "${JAVA_SOURCES[@]}"
else
  if ! command -v docker >/dev/null 2>&1; then
    echo "[build-regression-fixtures] missing javac and docker" >&2
    exit 1
  fi

  docker run --rm \
    -v "${SRC_DIR}:${CONTAINER_SRC_DIR}:ro" \
    -v "${CLASSES_DIR}:${CONTAINER_CLASSES_DIR}" \
    -w "${CONTAINER_WORKDIR}" \
    eclipse-temurin:17-jdk \
    javac --release 17 -d "${CONTAINER_CLASSES_DIR}" "${CONTAINER_SRC_DIR}/AllCapabilities.java"
fi

mkdir -p "${CLASSES_DIR}/native"
printf 'DEMO' > "${CLASSES_DIR}/native/demo.so"

cargo run --quiet --bin build-regression-fixtures -- "${CLASSES_DIR}" "${OUT_JAR}"

if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${OUT_JAR}" | cut -d ' ' -f1 > "${OUT_SHA256}"
else
  shasum -a 256 "${OUT_JAR}" | cut -d ' ' -f1 > "${OUT_SHA256}"
fi

echo "[build-regression-fixtures] wrote ${OUT_JAR}"
echo "[build-regression-fixtures] wrote ${OUT_SHA256}"
