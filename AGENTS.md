# AGENTS.md

## Project Goal

Build a production-oriented single-node MVP for a host-level firewall system
for Kubernetes nodes.

## Core Constraints

- Go for control plane and node agent
- XDP/eBPF in C for the data plane
- Keep eBPF code minimal and auditable
- Only manage host NIC interface allowlists
- Do not touch Kubernetes-managed iptables, nftables, kube-proxy, or CNI rules

## v1 Scope

- IPv4 allowlist on a per-interface basis
- Default deny for unmatched IPv4 packets
- Configurable non-IPv4 action
- Attach/detach XDP on demand
- Hot updates through BPF maps
- Counters, health checks, rollback, and a simple web UI

## Coding Rules

- Prefer standard library packages where practical
- Keep package boundaries explicit and small
- Return actionable errors for risky operations
- Add focused tests for parsing, rollback, and handlers
- Preserve a recovery path at every stage of policy apply
- Write Git commit subjects and bodies in English
- Set the product release number in the root `VERSION` file. Packaging and
  running binaries derive their default versions from it.
- Keep design drafts and review screenshots outside the repository.

## Install, Update, and Uninstall Invariants

- Every persisted file or directory introduced under `NODEWALL_CONFIG_DIR` must
  be added to `nodewallOwnedConfigEntries` in `internal/cli/cleanup.go`, or be
  referenced by a `NODEWALL_*` path in `nodewall.env`. Add a cleanup regression
  test whenever a new setting, cache, journal, key, or certificate is added.
- `install`, `update`, and `cleanup` must be safe to run repeatedly. Updates
  must migrate legacy state before writing new state, and cleanup must remove
  all NodeWall-owned state while refusing unrelated administrator files.
- The reserved SSH comment `nodewall-console` is owned by NodeWall. Key APIs
  must identify the active console key by its fingerprint derived from the
  configured private key; never generate a key while listing keys. Uninstall
  must remove legacy and duplicate reserved console entries, while preserving
  administrator entries with other comments.
- Any new public state field used to distinguish current, historical, or
  externally managed credentials must be covered by agent, proxy, and UI tests.
- Legacy iptables backend changes must keep host INPUT/OUTPUT separate from
  VM/container FORWARD traffic, preserve stateful replies after explicit denies,
  and test migration and repeated cleanup of historical NodeWall chains. Never
  flush an entire table or rewrite platform-owned rules or persistence files.
- XDP/TC changes must preserve bridge/CNI forwarding while enforcing the host's
  own traffic. Test guest unicast, broadcast/multicast host copies, multiple
  uplinks, and coexistence with platform TC filters. Keep inbound and outbound
  reply authorization separate and record flow state only after acceptance.
- Firewall audit logs must distinguish packet sources from CIDR rule counters
  and observe-only matches from actual rejections. Never invent a packet source
  of `0.0.0.0` from an all-address rule or infer DHCP from its port/address alone.
  Cover audit map ABI compatibility, persisted deltas, proxy/event snapshots,
  and per-IP action eligibility when these semantics change.
- Dataplane compatibility must distinguish kernel attach APIs, NIC driver
  capabilities, network topology, and existing attachments; never generalize
  one product's workaround to every host. Cover modern/legacy XDP APIs,
  native/generic mode, known driver quirks, standalone/bond/bridge interfaces,
  and first/repeated trial recovery. Only unsupported capabilities may trigger
  a fallback. Permission, ownership, device, and transport errors must preserve
  their cause; never replay an uncertain attach request or silently use iptables.
- Cluster presence and a particular Web's Agent reachability are separate
  signals. Test multiple Webs with asymmetric host firewall paths; a recent
  authenticated heartbeat must not become an offline node solely because one
  Web cannot query its Agent. Relay fallback must pin enrolled peer TLS, allow
  only one hop, propagate cancellation, and never replay an uncertain mutation.
- Event-center records, overview event feeds, and notification counts must use
  explicit event snapshots, never the security workspace's selected node,
  feature, NIC, or direction. Cluster filters must not shrink the node inventory.
  Preserve per-node provenance and scan history; collect bounded metadata rather
  than full findings or unrelated security settings. Cover unvisited nodes,
  identical scan IDs on different hosts, stale HTTP/SSE responses, node removal,
  and failed triage writes. A transport or authorization failure must never be
  reported as a successfully ignored event.
- HTTP summaries and page streams must share manager-side collectors and caches.
  Call only routes registered by the Agent; verify the HTTP/SSE contract with
  `AgentHandler.Routes()` and a mock dataplane so fixtures cannot invent Agent
  summary endpoints. Isolate cache keys by node, NIC, and direction.
- Optional GPU/vendor probes must run outside the main resource collection lock,
  with bounded timeouts, one in-flight sample, and a shared cache. Test slow
  driver initialization, caller cancellation, real zero readings, missing
  sensors, and PCI identity changes without enabling driver persistence modes.

## Delivery Order

1. Repository skeleton and docs
2. Minimal XDP program
3. Go loader and map management
4. Local node agent APIs
5. Rollback and health checks
6. Central server
7. Minimal web UI
