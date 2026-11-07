#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if [[ ! -x "${ROOT_DIR}/bin/nodewall" ]]; then
  make -C "${ROOT_DIR}" build
fi

if [[ $# -gt 0 ]]; then
  exec "${ROOT_DIR}/bin/nodewall" set-password "$@"
fi

read -r -s -p "New NodeWall password: " password
printf '\n'
read -r -s -p "Confirm password: " confirm_password
printf '\n'

if [[ "${password}" != "${confirm_password}" ]]; then
  printf '[set-password] error: passwords do not match\n' >&2
  exit 1
fi

NODEWALL_ADMIN_PASSWORD="${password}" exec "${ROOT_DIR}/bin/nodewall" set-password
