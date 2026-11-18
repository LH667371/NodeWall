#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ASSETS_DIR="${NODEWALL_CLAMAV_ASSETS_DIR:-${ROOT_DIR}/tmp/clamav-assets}"
DATABASE_DIR="${NODEWALL_CLAMAV_DATABASE_DIR:-${ASSETS_DIR}/database}"
DATABASE_URL="${NODEWALL_CLAMAV_DATABASE_URL:-https://database.clamav.net}"
DATABASE_URL="${DATABASE_URL%/}"
BUNDLE_DESTINATION="${1:-}"
# The digest pins the multi-platform Alpine image, while apk verifies its
# signed package indexes and packages. The resulting musl runtime is private
# to NodeWall and does not replace the host's glibc.
ALPINE_IMAGE="alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf"
CLAMAV_VERSION="1.4.6"
APORTS_COMMIT="c84b05967ca68847882204bc14ab80ecc7b38c57"
CLAMAV_SOURCE_SHA256="06dbc7adf96e2f6a27c548a841ce83c95360d1e121b106a6f7cf56f282a3c61b"

fail() {
  printf '[clamav] error: %s\n' "$*" >&2
  exit 1
}

checksum() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi
}

# Rename on the destination filesystem so a failed copy cannot replace a
# usable cache file. The bundle itself is built from a private snapshot.
publish_file() {
  if cmp -s "$1" "$2"; then
    return
  fi
  publish_tmp="$(mktemp "$(dirname "$2")/.incoming.XXXXXX")"
  cp -p "$1" "${publish_tmp}"
  mv -f "${publish_tmp}" "$2"
  publish_tmp=""
}

command -v docker >/dev/null 2>&1 || fail 'Docker is required to check offline databases'
case "${DATABASE_URL}" in
  *[[:space:]]*) fail 'NODEWALL_CLAMAV_DATABASE_URL must not contain whitespace' ;;
  http://?*|https://?*) ;;
  *) fail 'NODEWALL_CLAMAV_DATABASE_URL must be an HTTP(S) mirror URL' ;;
esac

mkdir -p "${ASSETS_DIR}/database" "${DATABASE_DIR}"
ASSETS_DIR="$(cd "${ASSETS_DIR}" && pwd -P)"
DATABASE_DIR="$(cd "${DATABASE_DIR}" && pwd -P)"

assets_lock="${ASSETS_DIR}/.prepare-lock"
mkdir "${assets_lock}" || fail "cannot lock the ClamAV assets cache at ${assets_lock}"
database_lock=""
work_dir=""
publish_tmp=""
cleanup() {
  if [[ -n "${publish_tmp}" ]]; then rm -f "${publish_tmp}"; fi
  if [[ -n "${work_dir}" ]]; then rm -rf "${work_dir}"; fi
  if [[ -n "${database_lock}" ]]; then rmdir "${database_lock}"; fi
  rmdir "${assets_lock}"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [[ "${DATABASE_DIR}" != "${ASSETS_DIR}" ]]; then
  mkdir "${DATABASE_DIR}/.prepare-lock" || fail "cannot lock the database cache at ${DATABASE_DIR}/.prepare-lock"
  database_lock="${DATABASE_DIR}/.prepare-lock"
fi

work_dir="$(mktemp -d "${ASSETS_DIR}/.prepare.XXXXXX")"
bundle="${work_dir}/bundle"
mkdir -p "${bundle}/engines" "${bundle}/database" "${bundle}/source/alpine"
source_archive="source/clamav-${CLAMAV_VERSION}.tar.gz"
recipe_files=(APKBUILD clamd.confd clamd.initd clamd.logrotate clamd_freshclam_conf_alpine.patch freshclam.confd freshclam.initd freshclam.logrotate link-fts.patch)
static_assets=(engines/amd64.tar.gz engines/arm64.tar.gz "${source_archive}")
for file in "${recipe_files[@]}"; do
  static_assets+=("source/alpine/${file}")
done

# Distribute the corresponding source and the exact Alpine packaging recipe
# with the binary. Check the cached release independently of mutable CVDs.
cached=true
for file in MANIFEST.sha256 "${static_assets[@]}"; do
  if [[ ! -s "${ASSETS_DIR}/${file}" ]]; then
    cached=false
    break
  fi
done
if "${cached}"; then
  for file in "${static_assets[@]}"; do
    awk -v file="${file}" '$2 == file { print; count++ } END { if (count != 1) exit 1 }' \
      "${ASSETS_DIR}/MANIFEST.sha256" || fail "missing or duplicate checksum for ${file}"
    cp -p "${ASSETS_DIR}/${file}" "${bundle}/${file}"
  done > "${work_dir}/static.sha256"
  (cd "${bundle}" && checksum -c "${work_dir}/static.sha256")
else
  for arch in amd64 arm64; do
    echo "[clamav] preparing ${arch} engine"
    docker run --rm --platform "linux/${arch}" -v "${bundle}:/output" "${ALPINE_IMAGE}" sh -ec '
      apk_version="$1"
      apk add --no-cache "clamav-daemon=$apk_version" "clamav-scanner=$apk_version" "freshclam=$apk_version" "clamav-libs=$apk_version" "clamav-libunrar=$apk_version" ca-certificates
      stage=$(mktemp -d)
      mkdir -p "$stage/lib" "$stage/usr/lib" "$stage/usr/bin" "$stage/usr/sbin" "$stage/etc/ssl"
      for file in /lib/*.so*; do [ ! -e "$file" ] || cp -L "$file" "$stage/lib/"; done
      for file in /usr/lib/*.so*; do [ ! -e "$file" ] || cp -L "$file" "$stage/usr/lib/"; done
      cp /usr/sbin/clamd "$stage/usr/sbin/"
      cp /usr/bin/clamscan /usr/bin/sigtool /usr/bin/freshclam "$stage/usr/bin/"
      cp -L /etc/ssl/certs/ca-certificates.crt "$stage/etc/ssl/cert.pem"
      apk info -vv > "$stage/PACKAGES.txt"
      tar -czf "/output/engines/$2.tar.gz" -C "$stage" .
    ' sh "${CLAMAV_VERSION}-r0" "${arch}"
  done
  if [[ -s "${ASSETS_DIR}/${source_archive}" ]]; then
    cp -p "${ASSETS_DIR}/${source_archive}" "${bundle}/${source_archive}"
  else
    curl -fL --retry 3 --connect-timeout 15 --max-time 600 \
      "https://github.com/Cisco-Talos/clamav/releases/download/clamav-${CLAMAV_VERSION}/clamav-${CLAMAV_VERSION}.tar.gz" \
      -o "${bundle}/${source_archive}"
  fi
  for file in "${recipe_files[@]}"; do
    curl -fsSL --retry 3 --connect-timeout 15 --max-time 120 \
      "https://raw.githubusercontent.com/alpinelinux/aports/${APORTS_COMMIT}/community/clamav/${file}" \
      -o "${bundle}/source/alpine/${file}"
  done
fi
(cd "${bundle}" && printf '%s  %s\n' "${CLAMAV_SOURCE_SHA256}" "${source_archive}" | checksum -c -)

databases=(main.cvd daily.cvd bytecode.cvd)
for file in "${databases[@]}"; do
  if [[ -s "${DATABASE_DIR}/${file}" ]]; then
    cp -p "${DATABASE_DIR}/${file}" "${bundle}/database/${file}"
  fi
done

# Keep FreshClam's mirror cooldown across runs, outside the distributable bundle.
mirror_key="$(printf '%s' "${DATABASE_URL}" | checksum | awk '{print $1}')"
freshclam_state="${ASSETS_DIR}/.freshclam-${mirror_key}.dat"
if [[ -f "${freshclam_state}" ]]; then
  cp "${freshclam_state}" "${bundle}/database/freshclam.dat"
fi

update_status=0
docker run --rm -i -v "${work_dir}:/stage" "${ALPINE_IMAGE}" \
  sh -es -- "${DATABASE_URL}" <<'SH' || update_status=$?
  # Return staged files to the bind mount's owner, using container UID mapping.
  owner=$(stat -c '%u:%g' /stage)
  if [ "$owner" != 0:0 ]; then
    trap 'chown -R "$owner" /stage' EXIT
  fi
  case "$(uname -m)" in
    aarch64) arch=arm64; loader=ld-musl-aarch64.so.1 ;;
    x86_64) arch=amd64; loader=ld-musl-x86_64.so.1 ;;
    *) echo '[clamav] error: unsupported Docker architecture' >&2; exit 1 ;;
  esac
  engine=$(mktemp -d)
  tar -xzf "/stage/bundle/engines/${arch}.tar.gz" -C "$engine"
  export LC_ALL=C CURL_CA_BUNDLE="$engine/etc/ssl/cert.pem"
  run_engine() {
    tool=$1
    shift
    "$engine/lib/$loader" --library-path "$engine/lib:$engine/usr/lib" "$engine/usr/bin/$tool" "$@"
  }
  cd /stage/bundle/database
  for file in main.cvd daily.cvd bytecode.cvd; do
    if [ -f "$file" ] && ! run_engine sigtool --info "$file" | grep -Fxq 'Verification OK.'; then
      echo "[clamav] discarding invalid staged copy of $file"
      rm "$file"
    fi
  done
  mirror=$1
  printf '%s\n' \
    'DatabaseDirectory /stage/bundle/database' 'DatabaseOwner root' \
    "DatabaseMirror $mirror" 'ScriptedUpdates no' 'TestDatabases yes' > /stage/freshclam.conf
  set -- --config-file=/stage/freshclam.conf --update-db=main --update-db=daily --update-db=bytecode
  case "$mirror" in
    https://database.clamav.net|http://database.clamav.net) ;;
    *) set -- "$@" --no-dns ;;
  esac
  status=0
  run_engine freshclam "$@" >/stage/freshclam.log 2>&1 || status=$?
  cat /stage/freshclam.log
  [ "$status" -eq 0 ] || exit "$status"

  # FreshClam may exit zero during a CDN cooldown or after receiving an older
  # signed CVD than advertised. Require a positive check and current version.
  for file in main.cvd daily.cvd bytecode.cvd; do
    if ! info=$(run_engine sigtool --info "$file") || ! printf '%s\n' "$info" | grep -Fxq 'Verification OK.'; then
      echo "[clamav] error: signature verification failed for $file" >&2
      exit 1
    fi
    version=$(printf '%s\n' "$info" | awk '$1 == "Version:" { print $2 }')
    if ! awk -v name="${file%.cvd}" -v version="$version" '
      $0 ~ "^" name "[.]cvd (database is up-to-date|updated) [(]version: " version "," { checked = 1 }
      $1 == name && /remote version: [0-9]+[)]/ {
        sub(/^.*remote version: /, "")
        if ($0 + 0 > version + 0) behind = 1
      }
      END { exit !(checked && !behind) }
    ' /stage/freshclam.log; then
      echo "[clamav] error: could not confirm that $file (version $version) is current" >&2
      exit 1
    fi
  done
SH

if [[ -f "${bundle}/database/freshclam.dat" ]]; then
  publish_file "${bundle}/database/freshclam.dat" "${freshclam_state}"
  rm "${bundle}/database/freshclam.dat"
fi
[[ "${update_status}" -eq 0 ]] || fail 'database refresh failed; previous cached databases were kept'

cp "${ROOT_DIR}/packaging/CLAMAV-NOTICE.md" "${bundle}/NOTICE.md"
bundle_files=("${static_assets[@]}" database/main.cvd database/daily.cvd database/bytecode.cvd NOTICE.md)
(cd "${bundle}" && checksum "${bundle_files[@]}" > MANIFEST.sha256)

if [[ "${DATABASE_DIR}" != "${ASSETS_DIR}/database" ]]; then
  for file in "${databases[@]}"; do
    publish_file "${bundle}/database/${file}" "${DATABASE_DIR}/${file}"
  done
fi
mkdir -p "${ASSETS_DIR}/engines" "${ASSETS_DIR}/source/alpine"
for file in "${bundle_files[@]}" MANIFEST.sha256; do
  publish_file "${bundle}/${file}" "${ASSETS_DIR}/${file}"
done
if [[ -n "${BUNDLE_DESTINATION}" ]]; then
  mv "${bundle}" "${BUNDLE_DESTINATION}"
fi
echo "[clamav] verified offline assets ready: ${ASSETS_DIR}"
