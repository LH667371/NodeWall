#!/usr/bin/env bash
set -euo pipefail

export COPYFILE_DISABLE=1
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${NODEWALL_DIST_DIR:-${ROOT_DIR}/dist}"
VERSION_FILE="${ROOT_DIR}/VERSION"
if [[ ! -r "${VERSION_FILE}" ]]; then
  echo "[package] error: cannot read ${VERSION_FILE}" >&2
  exit 1
fi
RELEASE_VERSION="$(sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "${VERSION_FILE}")"
if [[ -z "${RELEASE_VERSION}" || "${RELEASE_VERSION}" == *[[:space:]]* ]]; then
  echo "[package] error: VERSION must contain one release version" >&2
  exit 1
fi
# Keep the version shown by the console and reported by agents short and
# stable. Release automation can still provide a traceable revision explicitly
# without coupling every local build to a timestamp and Git commit.
PACKAGE_REVISION="${NODEWALL_PACKAGE_REVISION:-${NODEWALL_VERSION:-${RELEASE_VERSION}}}"
PACKAGE_LABEL="${NODEWALL_PACKAGE_LABEL:-${PACKAGE_REVISION}}"
PACKAGE_TARGETS="${NODEWALL_PACKAGE_TARGETS:-linux/amd64 linux/arm64}"
PACKAGE_FORMAT="${NODEWALL_PACKAGE_FORMAT:-archive}"
# Preserve the existing archive default for callers of this script; the make
# targets select the contents explicitly and use distinct archive names.
PACKAGE_CONTENT="${NODEWALL_PACKAGE_CONTENT:-offline}"

log() {
  printf '[package] %s\n' "$*"
}

has_compatible_web_node() {
  command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1 && node -e '
    const [major, minor] = process.versions.node.split(".").map(Number);
    const supported = (major === 20 && minor >= 19) ||
      (major === 22 && minor >= 12) || major > 22;
    process.exit(supported ? 0 : 1);
  '
}

select_web_node() {
  if ! has_compatible_web_node; then
    local nvm_script="${NVM_DIR:-${HOME:-}/.nvm}/nvm.sh"
    if [[ -s "${nvm_script}" ]]; then
      # Sourcing nvm lets npm and its Vite subprocess use the same Node.
      set +u
      if source "${nvm_script}" --no-use; then
        nvm use --silent "$(<"${ROOT_DIR}/.nvmrc")" >/dev/null 2>&1 || true
      fi
      set -u
    fi
  fi
  if ! has_compatible_web_node; then
    local node_version
    node_version="$(node --version 2>/dev/null || printf 'not found')"
    echo "[package] error: web builds require npm and Node.js ^20.19.0 or >=22.12.0 (found ${node_version})" >&2
    echo "[package] run 'nvm install' from the repository root or put a compatible Node.js and npm on PATH" >&2
    exit 1
  fi
  log "using Node.js $(node --version) for the web build"
}

build_web_dist() {
  # Keep packaging a one-command operation while avoiding an unnecessary
  # registry access when the locked dependencies are already installed.
  if [[ ! -x "${ROOT_DIR}/web/node_modules/.bin/vite" ]]; then
    log "installing web dependencies"
    npm --prefix "${ROOT_DIR}/web" ci
  fi

  log "building web assets"
  npm --prefix "${ROOT_DIR}/web" run build

  if [[ ! -f "${ROOT_DIR}/web/dist/index.html" ]]; then
    echo "[package] error: web build did not produce web/dist/index.html" >&2
    exit 1
  fi
}

build_binary() {
  local goos="$1"
  local goarch="$2"
  local binary_path="$3"
  mkdir -p "$(dirname "${binary_path}")"
  log "building ${goos}/${goarch}"
  # AppVersion is embedded from VERSION by Go. Only the package label is injected.
  local ldflags="-X nodewall/internal/version.PackageVersion=${PACKAGE_REVISION}"
  env GOCACHE="${ROOT_DIR}/.gocache" GOPATH="${ROOT_DIR}/.gopath" GOENV=off \
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -ldflags "${ldflags}" -o "${binary_path}" "${ROOT_DIR}/cmd/nodewall"
}

package_target() {
  local target="$1"
  local goos="${target%/*}"
  local goarch="${target#*/}"
  local package_name="nodewall_${PACKAGE_LABEL}_${PACKAGE_CONTENT}_${goos}_${goarch}"
  local stage_dir="${DIST_DIR}/${package_name}"
  local archive_path="${DIST_DIR}/${package_name}.tar.gz"

  if [[ "${PACKAGE_FORMAT}" == "binary" ]]; then
    local binary_path="${DIST_DIR}/nodewall_${PACKAGE_LABEL}_${goos}_${goarch}"
    build_binary "${goos}" "${goarch}" "${binary_path}"
    chmod +x "${binary_path}"
    return
  fi

  rm -rf "${stage_dir}"
  mkdir -p "${stage_dir}" "${DIST_DIR}"

  build_binary "${goos}" "${goarch}" "${stage_dir}/bin/nodewall"

  cp "${ROOT_DIR}/packaging/README.package.md" "${stage_dir}/README.md"
  cp "${ROOT_DIR}/packaging/README.package.zh-CN.md" "${stage_dir}/README.zh-CN.md"
  if [[ "${PACKAGE_CONTENT}" == "offline" ]]; then
    cp -R "${CLAMAV_BUNDLE}" "${stage_dir}/clamav"
  fi
  find "${stage_dir}" -name '._*' -delete

  log "packing ${archive_path}"
  if [[ "${PACKAGE_CONTENT}" == "offline" ]]; then
    # Most of the offline payload is already compressed (CVDs, engines,
    # and corresponding source). A lower gzip level avoids re-compressing it.
    tar --format ustar -C "${DIST_DIR}" -cf - "${package_name}" | gzip -1 > "${archive_path}"
  else
    tar --format ustar -C "${DIST_DIR}" -czf "${archive_path}" "${package_name}"
  fi
}

case "${PACKAGE_FORMAT}" in
  archive|binary) ;;
  *) echo "[package] error: unsupported package format: ${PACKAGE_FORMAT}" >&2; exit 1 ;;
esac
case "${PACKAGE_CONTENT}" in
  offline|update) ;;
  *) echo "[package] error: unsupported package content: ${PACKAGE_CONTENT}" >&2; exit 1 ;;
esac

[[ -f "${ROOT_DIR}/bpf/gen/xdpacl_bpfel.o" ]] || {
  echo "[package] error: missing bpf/gen/xdpacl_bpfel.o; run 'make generate' first" >&2
  exit 1
}
select_web_node
mkdir -p "${DIST_DIR}"
if [[ "${PACKAGE_FORMAT}" == "archive" && "${PACKAGE_CONTENT}" == "offline" ]]; then
  clamav_stage="$(mktemp -d "${DIST_DIR}/.clamav.XXXXXX")"
  trap 'rm -rf "${clamav_stage}"' EXIT
  # Both architecture archives must use the same verified database snapshot.
  CLAMAV_BUNDLE="${clamav_stage}/clamav"
  log "checking for current ClamAV databases"
  bash "${ROOT_DIR}/scripts/prepare-clamav.sh" "${CLAMAV_BUNDLE}"
fi
build_web_dist
for target in ${PACKAGE_TARGETS}; do
  package_target "${target}"
done

log "packages ready under ${DIST_DIR}"
