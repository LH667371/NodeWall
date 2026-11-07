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

## Delivery Order

1. Repository skeleton and docs
2. Minimal XDP program
3. Go loader and map management
4. Local node agent APIs
5. Rollback and health checks
6. Central server
7. Minimal web UI
