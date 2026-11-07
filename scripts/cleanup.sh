#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "${ROOT_DIR}/bin/nodewall" ]]; then
  make -C "${ROOT_DIR}" build
fi

exec "${ROOT_DIR}/bin/nodewall" cleanup "$@"
