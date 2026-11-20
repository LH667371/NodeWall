# NodeWall

NodeWall is a host-level firewall system for Kubernetes nodes.

## Languages

- English: `README.md`
- 简体中文: [`README.zh-CN.md`](README.zh-CN.md)
- Architecture (EN): [`docs/architecture.md`](docs/architecture.md)
- 架构设计 (ZH-CN): [`docs/architecture.zh-CN.md`](docs/architecture.zh-CN.md)
- Agent guidelines (EN): [`AGENTS.md`](AGENTS.md)
- Agent 指南 (ZH-CN): [`AGENTS.zh-CN.md`](AGENTS.zh-CN.md)

It protects host NICs with XDP/eBPF at ingress and TC/eBPF at egress while
leaving Kubernetes-managed networking rules untouched.

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

The project uses the Go toolchain declared in `go.mod`.

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
with the generated BPF object available and sufficient privileges for XDP and
TC attach/detach. The agent selects native or generic XDP for ingress using the
kernel and driver capabilities. The same BPF object handles TC egress.

Useful commands:

```sh
make dev
make dev-real
make run-agent
make run-server
```

Environment examples for both modes live in `examples/dev.env.example`.

## Install preflight

Run the preflight before installation to check root privileges, the running
Linux kernel, systemd, service ports, the selected NIC, BPF/XDP, and
iptables:

```sh
sudo ./bin/nodewall preflight --default-interface ens18
```

The command prints one result per check and exits unsuccessfully when a hard
failure is found. Dataplane compatibility is checked against the running kernel
and the selected backend's requirements. SSH protection uses `/var/log/auth.log`,
`/var/log/secure`, or journald when the traditional files are absent.
`nodewall install` runs the same preflight
before writing installation files or systemd units. `--enable-services=false`
skips only the live systemd check.

Linux 4.18 is the minimum version checked for XDP/TC. The running kernel must
also be able to load the packaged BPF object and attach it to the selected
interface. During boot, the agent restores the saved policy for each configured
interface and retries if its network device has yet to appear. The health
endpoint reports incomplete restorations while the management API is available.

## Packaging

NodeWall now supports multi-architecture release packaging for distribution to
target hosts without copying the whole source repository.

Default package targets:

- `linux/amd64`
- `linux/arm64`

Choose a package for the intended use:

```sh
# Only needed if the BPF object has not been generated yet.
make generate

# Offline installation, including the ClamAV engine and full databases.
make package-offline

# Routine update, without ClamAV assets.
make package-update
```

Both commands build the web assets and compile the current Go sources. If the
locked web dependencies are missing, the script runs `npm ci` first.
Packaging checks Node.js before preparing ClamAV assets. It uses Node.js
`^20.19.0` or `>=22.12.0` from PATH, or selects the installed nvm version from
`.nvmrc`. To install that version, run `nvm install` from the repository root.
`make package-offline` uses Docker and network access to check the `main`,
`daily`, and `bytecode` databases on every run. It downloads available updates,
verifies all three CVD signatures, and reuses the verified engine and source
cache. If the database refresh or verification fails, packaging stops and the
previous database cache is preserved.
Completed engine builds are cached independently from database refreshes. On
a new builder, set `NODEWALL_CLAMAV_ENGINE_SEED_DIR` to the verified `clamav/`
directory from an offline archive with the same engine version to reuse it.
`make package-archive` remains an alias for `make package-offline`;
`make package` still produces standalone binaries without ClamAV assets.

Build one target only:

```sh
NODEWALL_PACKAGE_TARGETS=linux/amd64 make package-update
```

Archives are written under `dist/`, with `_offline_linux_amd64.tar.gz` or
`_update_linux_amd64.tar.gz` in the filename (and corresponding names for
other architectures). Both include the prebuilt binary and operations notes;
the offline archive also includes the ClamAV engines, databases, and source.

An update archive preserves any ClamAV engine and databases already installed
on the target. Use the offline archive to provision a standalone manager for
the first time. Any enrolled node with an offline bundle can supply the other
nodes, including an original manager that has no assets. Nodes check at startup
and every two minutes, synchronizing missing or newer engines and databases in
the background after enrollment. Follow progress with
`journalctl -u nodewall-agent -f`; scan reports also expose engine/update status.
Engine releases and individual database versions never downgrade; an engine
upgrade restarts the private clamd. Transfers use enrolled credentials and pinned
TLS, followed by SHA-256, CVD signature, and full database loading checks. Failed
updates retain the working version. An update archive alone cannot provision
these assets on an isolated host without another source.

On the target Linux host:

```sh
tar -xzf nodewall_<version>_offline_linux_amd64.tar.gz
cd nodewall_<version>_offline_linux_amd64
sudo ./bin/nodewall install --password 'change-me'
```

To update an existing node, extract the update archive for its architecture
and run `sudo ./bin/nodewall update` from the extracted directory.

If the default web port `8086` or agent port `9080` is already in use, install
with custom ports:

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
- A new secure all-in-one installation listens on `0.0.0.0:9080` and advertises
  its usable IPv4 address when one is detected. Explicit bind settings, disabled
  TLS, and installations without a usable address retain their configured
  behavior. An explicit loopback bind prevents other managers from reaching the agent.
- Installation deploys services and the UI without automatically attaching the
  default interface; enable protection explicitly from the console
- `nodewall cleanup` must run as root. It stops NodeWall processes, restores the SSH configuration, SFTP subsystem, and root console key before removing runtime files. If SSH validation or reload fails, cleanup stops with the recovery files intact so it can be retried from a local console.
- install performs a port availability check before writing
  `/etc/nodewall/nodewall.env`; all NodeWall management services use the 8086+
  port range. Upgrades and re-enrollment migrate legacy values from 8080
  through 8085 before reporting the selected management address in node
  heartbeats
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
overrides. If the default `0.0.0.0:8086` or `127.0.0.1:9080` ports are busy,
set `NODEWALL_SERVER_ADDR`, `NODEWALL_AGENT_ADDR`, and `NODEWALL_AGENT_URL`
there before restarting the services.

## Off-host Monitoring History

Each manager collects node metrics every 15 seconds and writes them to
`NODEWALL_MONITORING_HISTORY_DIR`. History is kept for up to seven days within
the default 512 MiB quota, configurable through `NODEWALL_MONITORING_HISTORY_MIB`.
Resource Monitoring → History keeps retired nodes selectable until their archive
expires and can replay the hour ending at their last archived sample.

For history access after the primary Web host fails, enable a standby manager on
another host. The standby collects its own samples and copies the primary's two
most recent minutes of completed samples during its regular sync.

## Access Control And Password Login

Administrators can issue a single-use enrollment command from Node Management.
New nodes enroll as agents by default. Grant standby manager access only to
nodes trusted to hold the cluster encryption key and credential snapshot.
Previously enrolled standby managers continue syncing through their node credentials.

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

Node management now exposes a per-node “Update Agent” action. It uses the
node credential to ask the selected agent to download and install the current
manager package immediately, then restart its services; regular heartbeats
still check for version drift after enrollment. Removing a node sends a forced
cleanup marker, so a reachable agent is detached and asked to uninstall itself
even when its last heartbeat is stale, before the manager revokes its credential
and removes local policy state.

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
