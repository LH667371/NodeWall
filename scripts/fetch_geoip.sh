#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET_DIR="${NODEWALL_GEOIP_DIR:-${ROOT_DIR}/third_party/geoip}"
MONTH_TAG="${1:-$(date +%Y-%m)}"
FILE_NAME="dbip-country-lite-${MONTH_TAG}.csv.gz"
URL="https://download.db-ip.com/free/${FILE_NAME}"

mkdir -p "${TARGET_DIR}"
curl -fL "${URL}" -o "${TARGET_DIR}/${FILE_NAME}"
cp "${TARGET_DIR}/${FILE_NAME}" "${TARGET_DIR}/dbip-country-lite.csv.gz"
printf '[geoip] downloaded %s\n' "${TARGET_DIR}/${FILE_NAME}"
printf '[geoip] active database %s\n' "${TARGET_DIR}/dbip-country-lite.csv.gz"
