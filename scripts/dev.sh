#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODE="${NODEWALL_DEV_MODE:-demo}"
GO_BIN="${GO:-go}"
AIR_BIN="${AIR_BIN:-air}"
NPM_BIN="${NPM_BIN:-npm}"
SERVER_ADDR="${NODEWALL_SERVER_ADDR:-127.0.0.1:8080}"
AGENT_ADDR="${NODEWALL_AGENT_ADDR:-127.0.0.1:9080}"
AGENT_URL="${NODEWALL_AGENT_URL:-http://${AGENT_ADDR}}"
STATE_DIR="${NODEWALL_STATE_DIR:-${ROOT_DIR}/tmp}"
export NODEWALL_MONITORING_HISTORY_DIR="${NODEWALL_MONITORING_HISTORY_DIR:-${STATE_DIR}/monitoring-history}"
export NODEWALL_SCAN_REPORT_DIR="${NODEWALL_SCAN_REPORT_DIR:-${STATE_DIR}/scan-reports}"
DROP_LOG_DIR="${NODEWALL_LOG_DIR:-${STATE_DIR}/logs}"
DROP_LOG_STATE_FILE="${NODEWALL_DROP_LOG_STATE:-${STATE_DIR}/drop-log-state.json}"
GEOIP_DB="${NODEWALL_GEOIP_DB:-${ROOT_DIR}/third_party/geoip/dbip-country-lite.csv.gz}"
DEMO_STATE_FILE="${NODEWALL_AGENT_STATE_DEMO:-${STATE_DIR}/agent-demo-state.json}"
REAL_STATE_FILE="${NODEWALL_AGENT_STATE_REAL:-${STATE_DIR}/agent-real-state.json}"
STATE_FILE="$DEMO_STATE_FILE"
DATAPLANE_MODE="${NODEWALL_DATAPLANE:-mock}"
PID_AGENT=""
PID_SERVER=""
USE_AIR="${NODEWALL_USE_AIR:-auto}"

mkdir -p "${STATE_DIR}"
mkdir -p "${DROP_LOG_DIR}"

log() {
  printf '[dev] %s\n' "$*"
}

fail() {
  printf '[dev] error: %s\n' "$*" >&2
  exit 1
}

cleanup() {
  local exit_code=$?
  trap - EXIT INT TERM

  if [[ -n "${PID_SERVER}" ]] && kill -0 "${PID_SERVER}" >/dev/null 2>&1; then
    kill "${PID_SERVER}" >/dev/null 2>&1 || true
    wait "${PID_SERVER}" 2>/dev/null || true
  fi

  if [[ -n "${PID_AGENT}" ]] && kill -0 "${PID_AGENT}" >/dev/null 2>&1; then
    kill "${PID_AGENT}" >/dev/null 2>&1 || true
    wait "${PID_AGENT}" 2>/dev/null || true
  fi

  exit "${exit_code}"
}

trap cleanup EXIT INT TERM

check_prereqs() {
  command -v "${GO_BIN}" >/dev/null 2>&1 || fail "go not found"
  command -v "${NPM_BIN}" >/dev/null 2>&1 || fail "npm not found"

  if [[ "${MODE}" == "real" ]]; then
    [[ "$(uname -s)" == "Linux" ]] || fail "real mode requires Linux"
    [[ -f "${ROOT_DIR}/bpf/gen/xdpacl_bpfel.o" ]] || fail "missing BPF object, run 'make generate' first"

    if [[ "${EUID}" -ne 0 ]]; then
      log "warning: real mode usually requires root or CAP_NET_ADMIN/CAP_BPF"
    fi

    DATAPLANE_MODE="real"
    STATE_FILE="${REAL_STATE_FILE}"
  else
    DATAPLANE_MODE="mock"
    STATE_FILE="${DEMO_STATE_FILE}"
  fi

  if [[ "${USE_AIR}" == "auto" ]]; then
    if command -v "${AIR_BIN}" >/dev/null 2>&1; then
      USE_AIR="true"
    else
      USE_AIR="false"
    fi
  fi
}

build_web() {
  log "building Vue console"
  (
    cd "${ROOT_DIR}"
    "${NPM_BIN}" --prefix web run build >/dev/null
  )
}

start_agent() {
  log "starting agent in ${MODE} mode on ${AGENT_ADDR}"
  (
    cd "${ROOT_DIR}"
    if [[ "${USE_AIR}" == "true" ]]; then
      env \
        GOCACHE="${ROOT_DIR}/.gocache" \
        GOPATH="${ROOT_DIR}/.gopath" \
        GOENV=off \
        NODEWALL_DEV_MODE="${MODE}" \
        NODEWALL_DATAPLANE="${DATAPLANE_MODE}" \
        NODEWALL_AGENT_ADDR="${AGENT_ADDR}" \
        NODEWALL_AGENT_URL="${AGENT_URL}" \
        NODEWALL_SERVER_ADDR="${SERVER_ADDR}" \
        NODEWALL_AGENT_STATE="${STATE_FILE}" \
        NODEWALL_LOG_DIR="${DROP_LOG_DIR}" \
        NODEWALL_DROP_LOG_STATE="${DROP_LOG_STATE_FILE}" \
        NODEWALL_GEOIP_DB="${GEOIP_DB}" \
        "${AIR_BIN}" -c "${ROOT_DIR}/.air.agent.toml" 2>&1 | sed 's/^/[agent] /'
    else
      env \
        GOCACHE="${ROOT_DIR}/.gocache" \
        GOPATH="${ROOT_DIR}/.gopath" \
        GOENV=off \
        NODEWALL_DEV_MODE="${MODE}" \
        NODEWALL_DATAPLANE="${DATAPLANE_MODE}" \
        NODEWALL_AGENT_ADDR="${AGENT_ADDR}" \
        NODEWALL_AGENT_URL="${AGENT_URL}" \
        NODEWALL_SERVER_ADDR="${SERVER_ADDR}" \
        NODEWALL_AGENT_STATE="${STATE_FILE}" \
        NODEWALL_LOG_DIR="${DROP_LOG_DIR}" \
        NODEWALL_DROP_LOG_STATE="${DROP_LOG_STATE_FILE}" \
        NODEWALL_GEOIP_DB="${GEOIP_DB}" \
        "${GO_BIN}" run ./cmd/agent 2>&1 | sed 's/^/[agent] /'
    fi
  ) &
  PID_AGENT=$!
}

wait_for_agent() {
  log "waiting for agent health on ${AGENT_URL}/health"
  local attempt
  for attempt in $(seq 1 40); do
    if [[ -n "${PID_AGENT}" ]] && ! kill -0 "${PID_AGENT}" >/dev/null 2>&1; then
      fail "agent exited before becoming healthy"
    fi
    if curl -fsS "${AGENT_URL}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.5
  done
  fail "agent health check did not succeed in time"
}

start_server() {
  log "starting server on ${SERVER_ADDR}"
  (
    cd "${ROOT_DIR}"
    if [[ "${USE_AIR}" == "true" ]]; then
      env \
        GOCACHE="${ROOT_DIR}/.gocache" \
        GOPATH="${ROOT_DIR}/.gopath" \
        GOENV=off \
        NODEWALL_DEV_MODE="${MODE}" \
        NODEWALL_AUTH_ENABLED=false \
        NODEWALL_AGENT_URL="${AGENT_URL}" \
        NODEWALL_SERVER_ADDR="${SERVER_ADDR}" \
        NODEWALL_WEB_DIR="${ROOT_DIR}/web/dist" \
        "${AIR_BIN}" -c "${ROOT_DIR}/.air.server.toml" 2>&1 | sed 's/^/[server] /'
    else
      env \
        GOCACHE="${ROOT_DIR}/.gocache" \
        GOPATH="${ROOT_DIR}/.gopath" \
        GOENV=off \
        NODEWALL_DEV_MODE="${MODE}" \
        NODEWALL_AUTH_ENABLED=false \
        NODEWALL_AGENT_URL="${AGENT_URL}" \
        NODEWALL_SERVER_ADDR="${SERVER_ADDR}" \
        NODEWALL_WEB_DIR="${ROOT_DIR}/web/dist" \
        "${GO_BIN}" run ./cmd/server 2>&1 | sed 's/^/[server] /'
    fi
  ) &
  PID_SERVER=$!
}

print_summary() {
  cat <<EOF
[dev] NodeWall is ready
[dev] mode: ${MODE}
[dev] hot reload: ${USE_AIR}
[dev] UI: http://${SERVER_ADDR}
[dev] agent health: ${AGENT_URL}/health
[dev] server nodes: http://${SERVER_ADDR}/nodes
[dev] state file: ${STATE_FILE}
[dev] drop log dir: ${DROP_LOG_DIR}
[dev] drop log state: ${DROP_LOG_STATE_FILE}
EOF
}

check_prereqs
build_web
start_agent
wait_for_agent
start_server
print_summary

wait "${PID_AGENT}" "${PID_SERVER}"
