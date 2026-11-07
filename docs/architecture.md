# NodeWall Architecture

## Overview

NodeWall is a host-level firewall system for Kubernetes nodes.

It filters packets at host NIC ingress with XDP/eBPF and avoids changes to
Kubernetes-managed netfilter state.

## Main Components

- Web UI
- Go API Server
- Go Node Agent
- XDP program on the target interface
- BPF maps for allowlist, counters, and config

## Packet Flow

```text
NIC -> XDP -> kernel networking stack -> kube-proxy / CNI / netfilter
```

NodeWall only acts at the XDP layer.

## Data Plane Logic

The v1 XDP program:

1. Parses the Ethernet header
2. Detects IPv4 traffic
3. Applies configurable behavior to non-IPv4 traffic
4. Reads the IPv4 source address
5. Looks it up in an LPM trie allowlist
6. Passes matched traffic and drops unmatched traffic
7. Updates pass/drop counters

## Control Plane

### Node Agent

Responsible for:

- Loading the XDP object
- Attaching and detaching programs
- Updating BPF maps
- Reporting counters
- Running local health checks
- Managing rollback sessions

### API Server

Responsible for:

- Storing interface policies
- Tracking publish history
- Driving single-node publish and rollback
- Serving the minimal web UI

## Rollback Model

Apply flow:

1. Snapshot current state
2. Apply requested policy
3. Run health checks
4. Open a confirmation window
5. Commit or roll back automatically

## Safety Defaults

- IPv4 traffic is allowlist-based
- Non-IPv4 action is explicit
- Health checks gate completion
- Manual recovery remains possible
