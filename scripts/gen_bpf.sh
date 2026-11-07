#!/usr/bin/env bash
set -euo pipefail

mkdir -p bpf/gen

export GOCACHE="${GOCACHE:-$PWD/.gocache}"
export GOPATH="${GOPATH:-$PWD/.gopath}"
export GOENV="${GOENV:-off}"

host_os="$(uname -s)"
image="${NODEWALL_BPF_IMAGE:-nodewall-bpf-gen:go1.27.3}"
runtime="${CONTAINER_RUNTIME:-}"

if [[ "$host_os" == "Linux" ]]; then
  exec make generate-hostlinux
fi

if [[ -z "$runtime" ]]; then
  if command -v docker >/dev/null 2>&1; then
    runtime="docker"
  elif command -v podman >/dev/null 2>&1; then
    runtime="podman"
  fi
fi

if [[ -z "$runtime" ]]; then
  echo "NodeWall BPF generation requires Linux or a container runtime (docker/podman)." >&2
  echo "Current host: $host_os." >&2
  exit 1
fi

echo "NodeWall: generating BPF objects in a Linux container via $runtime"
"$runtime" build -f build/bpf-generator.Dockerfile -t "$image" .
"$runtime" run --rm \
  -v "$PWD":/workspace \
  -w /workspace \
  -e GOCACHE=/workspace/.gocache \
  -e GOPATH=/workspace/.gopath \
  -e GOENV=off \
  "$image" \
  make generate-hostlinux
