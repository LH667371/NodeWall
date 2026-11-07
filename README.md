# NodeWall

NodeWall is a host-level firewall system for Kubernetes nodes.

## Languages

- English: `README.md`
- 简体中文: [`README.zh-CN.md`](README.zh-CN.md)
- Architecture (EN): [`docs/architecture.md`](docs/architecture.md)
- 架构设计 (ZH-CN): [`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md)
- Agent guidelines (EN): [`AGENTS.md`](AGENTS.md)
- Agent 指南 (ZH-CN): [`AGENTS.zh-CN.md`](AGENTS.zh-CN.md)

It protects host NICs with XDP/eBPF while leaving Kubernetes-managed
networking rules untouched.

## Goals

- Use Go for the node agent and control plane
- Use XDP/eBPF for early packet filtering
- Manage per-interface host allowlists
- Avoid modifying kube-proxy, CNI, iptables, or nftables rules
- Preserve a clear rollback path for risky operations

## v1 Scope

- IPv4 allowlists only
- XDP attach/detach on selected interfaces
- LPM trie-backed source CIDR allowlist
- Non-IPv4 default action configurable as `pass` or `drop`
- Local agent HTTP API
- Lightweight central server
- Health checks, counters, and rollback scaffolding
- Minimal web UI for single-node workflows

## Repository Layout

- `cmd/agent`: local NodeWall agent
- `cmd/server`: control-plane API server
- `internal/xdp`: eBPF loading, attach, map management
- `internal/api`: HTTP handlers for agent and server
- `internal/health`: health probes and reporting
- `internal/rollback`: rollback coordination
- `internal/store`: in-memory storage
- `bpf/`: XDP program and generation helpers
- `web/`: minimal browser UI

## Quick Start

1. Generate the eBPF object:

   ```sh
   make generate
   ```

2. Build binaries:

   ```sh
   make build
   ```

3. Start the full local dev stack:

   ```sh
   make dev
   ```

4. Run the local agent only:

   ```sh
   make run-agent
   ```

5. Run the server only:

   ```sh
   make run-server
   ```

The generated XDP object is expected at `bpf/gen/xdpacl_bpfel.o`.

## Build Notes

The project targets host Go `1.27.3`.

`make generate` now supports two paths:

- On Linux: generate the BPF object directly on the host
- On macOS or other non-Linux hosts: build a Linux helper image and run the
  generation step inside Docker automatically

The generated XDP object still requires a Linux eBPF toolchain inside that
environment (`clang`, kernel headers, and libbpf-compatible headers), which the
container image provides.

If you want to override the container image or runtime:

```sh
NODEWALL_BPF_IMAGE=my-nodewall-bpf CONTAINER_RUNTIME=docker make generate
```

## Local Dev Modes

`make dev` and `make dev-demo` run the agent in `mock` dataplane mode. This is
the default for macOS, non-Linux hosts, and general UI/API iteration. The
server continues to serve the built-in static UI from `web/`.

`make dev-real` runs the real dataplane path and is intended for Linux hosts
with the generated BPF object available and sufficient privileges for XDP
attach/detach.

Useful commands:

```sh
make dev
make dev-real
make run-agent
make run-server
```

Environment examples for both modes live in `examples/dev.env.example`.

## Install preflight

Run the preflight before installation to check the Ubuntu release, root
privileges, kernel, systemd, service ports, the selected NIC, BPF/XDP, and
iptables:

```sh
sudo ./bin/nodewall preflight --default-interface ens18
```

The command prints one result per check and exits unsuccessfully when a hard
failure is found. Ubuntu 18.04 is the minimum release checked by the installer;
non-Ubuntu distributions receive a warning while their kernel and dataplane
dependencies are still checked. SSH protection uses `/var/log/auth.log`,
`/var/log/secure`, or journald when the traditional files are absent.
`nodewall install` runs the same preflight
before writing installation files or systemd units. `--enable-services=false`
skips only the live systemd check.

## Packaging

NodeWall now supports multi-architecture release packaging for distribution to
target hosts without copying the whole source repository.

Default package targets:

- `linux/amd64`
- `linux/arm64`

Build packages:

```sh
make generate
make package-archive
```

`make package-archive` builds the web assets automatically, then compiles the
current Go sources and writes the archives. If the locked web dependencies are
not installed, the packaging script runs `npm ci` first.

Build one target only:

```sh
make package-one TARGET=linux/amd64
```

Artifacts are written under `dist/` as `.tar.gz` archives. Each archive
contains:

- prebuilt `nodewall`
- README and operations notes

On the target Linux host:

```sh
tar -xzf nodewall_<version>_linux_amd64.tar.gz
cd nodewall_<version>_linux_amd64
sudo ./bin/nodewall install --password 'change-me'
sudo ./bin/nodewall cleanup
```

If `0.0.0.0:8080` or `127.0.0.1:9080` is already in use, install with custom
ports:

```sh
sudo ./bin/nodewall install \
  --server-addr 127.0.0.1:18080 \
  --agent-addr 127.0.0.1:19080 \
  --agent-url http://127.0.0.1:19080 \
  --password 'change-me'
```

Notes:

- `nodewall install` extracts the embedded runtime assets and does not require
  the source repo
- Installation deploys services and the UI without automatically attaching the
  default interface; enable protection explicitly from the console
- `nodewall cleanup` removes installed services and files
- install performs a port availability check before writing
  `/etc/nodewall/nodewall.env`
- after installation, adjust `/etc/nodewall/nodewall.env` and restart the
  services if you need to move ports later
- packaging requires `bpf/gen/xdpacl_bpfel.o`, so run `make generate` first

## Smart Interface Discovery

The agent can now discover available network interfaces and return a
recommended candidate based on interface state, loopback detection, address
presence, and common physical NIC naming patterns.

- Agent API: `GET /interfaces`
- Server proxy: `GET /nodes/{node}/interfaces`
- Web UI: detect interfaces and apply the recommended NIC with one click

This keeps manual override available while making first-time setup faster.

## Restart Recovery

The agent now persists interface runtime state and reconciles it on startup.

- Persisted state is stored in `NODEWALL_AGENT_STATE`
- Installed Linux deployments default to `/etc/nodewall/agent-state.json`
- On restart, the agent reloads attached interfaces, reapplies allowlists, and
  restores the non-IPv4 action
- Pending publish sessions are conservatively marked as failed instead of being
  resumed without their original rollback window

This means a reboot or agent crash no longer leaves NodeWall with only saved
metadata and no dataplane reconciliation.

## Traffic Analytics

NodeWall now exposes per-source traffic insight data for top passed and top
dropped IPs.

- XDP data plane records source IP pass/drop counters in `source_stats`
- Agent API: `GET /interfaces/{iface}/insights`
- Server proxy: `GET /nodes/{node}/interfaces/{iface}/insights`
- Web UI: shows simple charts for top attackers and top passed sources

The current attack signal is heuristic-based and intended as an operational aid:
high drop counts or very high drop ratios are surfaced as higher risk sources.

The UI also keeps a rolling trend of recent pass/drop snapshots and surfaces a
small set of suggested `/32` blocks for the highest-risk dropped sources.

## Deployment And Cleanup

NodeWall now includes Linux-oriented operational helpers:

- `make deploy`: build binaries, install files, write a default env file, and
  enable both `nodewall-agent.service` and `nodewall-server.service`
- `make cleanup`: stop and disable installed services when run as root on
  Linux, remove installed files, and clean local build artifacts

The systemd units live under `deployments/systemd/` and use
`/etc/nodewall/nodewall.env` as an optional environment file for user
overrides. If the default `0.0.0.0:8080` or `127.0.0.1:9080` ports are busy,
set `NODEWALL_SERVER_ADDR`, `NODEWALL_AGENT_ADDR`, and `NODEWALL_AGENT_URL`
there before restarting the services.

## Access Control And Password Login

Production-style deployments can now protect the web console with:

- password-based login on the server UI
- CIDR-based allowlists via `NODEWALL_ALLOWED_CIDRS`
- plain IP allowlists via `NODEWALL_ALLOWED_IPS`
- MAC-based allowlists via `NODEWALL_ALLOWED_MACS` when the remote MAC can be
  resolved on the host
- `NODEWALL_WEB_ACCESS=public` (the default) keeps the console externally
  reachable while still requiring login. The source allowlists are enforced
  only when `NODEWALL_WEB_ACCESS=restricted` or `allowlist` is selected.
- `NODEWALL_WEB_ACCESS=drop` allows only loopback access for maintenance.

The cluster baseline always preserves the manager's TCP `8082` entry point. On
enrollment and server restart, the manager adds the current interconnect
addresses and control port to existing node policies. Observe-only policies are
updated in durable state without starting enforcement. The UI can enable the
baseline permanently or run it for `1` to `120` seconds first; without an
explicit confirmation, the agent restores the state from before the trial when
the timer expires. This keeps ZStack management paths recoverable during a
connectivity check.

For a single host, you can now write:

```sh
NODEWALL_ALLOWED_IPS=192.168.1.10,192.168.1.11
```

instead of manually converting each entry to `/32`.

`make dev` disables login by default so local iteration stays frictionless.

Password storage:

- default file: `/etc/nodewall/auth.json`
- created during deploy
- updated later with:

```sh
/opt/nodewall/bin/nodewall set-password --file /etc/nodewall/auth.json
```

## Safety

NodeWall is intentionally conservative:

- risky policy changes are wrapped in rollback sessions
- non-IPv4 behavior is explicit
- health checks run after apply
- manual rollback remains available
