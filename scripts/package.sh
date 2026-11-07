#!/usr/bin/env bash
set -euo pipefail

export COPYFILE_DISABLE=1
export COPY_EXTENDED_ATTRIBUTES_DISABLE=1

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DIST_DIR="${NODEWALL_DIST_DIR:-${ROOT_DIR}/dist}"
DEFAULT_VERSION="0.1.0"
if [[ -f "${ROOT_DIR}/VERSION" ]]; then
  DEFAULT_VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
fi
PACKAGE_VERSION="${NODEWALL_VERSION:-${DEFAULT_VERSION}}"
PACKAGE_BUILD="${NODEWALL_PACKAGE_BUILD:-$(date +%Y%m%d%H%M%S)}"
PACKAGE_REVISION="${NODEWALL_PACKAGE_REVISION:-${PACKAGE_VERSION}+build.${PACKAGE_BUILD}}"
PACKAGE_TARGETS="${NODEWALL_PACKAGE_TARGETS:-linux/amd64 linux/arm64}"
PACKAGE_FORMAT="${NODEWALL_PACKAGE_FORMAT:-archive}"

log() {
  printf '[package] %s\n' "$*"
}

build_web_dist() {
  if ! command -v npm >/dev/null 2>&1; then
    echo "[package] error: npm is required to build the web assets" >&2
    exit 1
  fi

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
  local out_dir="$3"
  mkdir -p "${out_dir}/bin"
  log "building ${goos}/${goarch}"
  local ldflags="-X nodewall/internal/version.AppVersion=${DEFAULT_VERSION} -X nodewall/internal/version.PackageVersion=${PACKAGE_REVISION}"
  env GOCACHE="${ROOT_DIR}/.gocache" GOPATH="${ROOT_DIR}/.gopath" GOENV=off \
    CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
    go build -ldflags "${ldflags}" -o "${out_dir}/bin/nodewall" "${ROOT_DIR}/cmd/nodewall"
}

package_target() {
  local target="$1"
  local goos="${target%/*}"
  local goarch="${target#*/}"
  local package_name="nodewall_${PACKAGE_VERSION}_${goos}_${goarch}"
  local stage_dir="${DIST_DIR}/${package_name}"
  local archive_path="${DIST_DIR}/${package_name}.tar.gz"

  if [[ "${PACKAGE_FORMAT}" == "binary" ]]; then
    mkdir -p "${DIST_DIR}"
    local binary_path="${DIST_DIR}/nodewall_${PACKAGE_VERSION}_${goos}_${goarch}"
    rm -f "${binary_path}"
    log "building single binary ${goos}/${goarch}"
    local ldflags="-X nodewall/internal/version.AppVersion=${DEFAULT_VERSION} -X nodewall/internal/version.PackageVersion=${PACKAGE_REVISION}"
    env GOCACHE="${ROOT_DIR}/.gocache" GOPATH="${ROOT_DIR}/.gopath" GOENV=off \
      CGO_ENABLED=0 GOOS="${goos}" GOARCH="${goarch}" \
      go build -ldflags "${ldflags}" -o "${binary_path}" "${ROOT_DIR}/cmd/nodewall"
    chmod +x "${binary_path}"
    return
  fi

  rm -rf "${stage_dir}"
  mkdir -p "${stage_dir}" "${DIST_DIR}"

  build_binary "${goos}" "${goarch}" "${stage_dir}"

  cp "${ROOT_DIR}/packaging/README.package.md" "${stage_dir}/README.md"
  cp "${ROOT_DIR}/packaging/README.package.zh-CN.md" "${stage_dir}/README.zh-CN.md"
  find "${stage_dir}" -name '._*' -delete

  log "packing ${archive_path}"
  tar --format ustar -C "${DIST_DIR}" -czf "${archive_path}" "${package_name}"
}

[[ -f "${ROOT_DIR}/bpf/gen/xdpacl_bpfel.o" ]] || {
  echo "[package] error: missing bpf/gen/xdpacl_bpfel.o; run 'make generate' first" >&2
  exit 1
}
mkdir -p "${DIST_DIR}"
build_web_dist
for target in ${PACKAGE_TARGETS}; do
  package_target "${target}"
done

log "packages ready under ${DIST_DIR}"
