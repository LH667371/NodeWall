`go test ./test/integration` starts real manager/agent subprocesses with a mock
dataplane. It checks production authentication, enrollment, independently pinned
self-signed certificates, and authenticated QUIC reporting without attaching NICs.
It also scans an isolated fixture, restarts the remote agent process, and verifies
historical JSON/HTML reports remain downloadable through the authenticated proxy.
`ssh_guard_test.go` additionally negotiates an encrypted SSH subsystem with
ephemeral keys, runs the actual SFTP CLI helper process, and checks upload rejection,
original-file preservation, successful publication, and per-file audit records.

For actual Linux BPF packet execution, run:

```sh
NODEWALL_BPF_TEST=1 go test -v ./internal/xdp -run TestXDPVLANEnforcement
NODEWALL_BPF_TEST=1 go test -v ./internal/xdp -run TestXDPReplyFlowDirections
NODEWALL_BPF_TEST=1 go test -v ./internal/xdp -run '^TestXDP(DHCPBroadcastAudit|ObservationAudit)$'
```

This packet test uses BPF_PROG_TEST_RUN and needs BPF privileges, but never
attaches a program to a host interface.
The reply-flow test checks both directions, rejected requests, DNS fallback,
outbound rule revocation, and service replies while ingress is observing.
These tests reexec in a disposable network namespace with explicit local test
addresses so the surrounding host's default route cannot bypass host checks.
The audit tests distinguish validated DHCP client broadcasts from arbitrary
port-67 traffic without changing the deny verdict, and keep observe-only matches
separate from actual rejections in both ingress and egress maps.

For the physical-uplink/bridge packet path, run:

```sh
NODEWALL_BPF_TEST=1 go test -v ./internal/xdp -run '^TestBridgeGuestForwarding$'
```

It needs root, `unshare`, `ip`, `tc`, and mount/network namespace privileges.
It creates disposable bridge/veth devices and a namespace-specific sysfs mount,
without changing a host NIC, live firewall, VM disk, or VM service. It verifies
guest unicast and IPv6 multicast, separate host/guest broadcast copies, host
default deny and port allows, independent uplink policies, and preservation of
another owner's TC filter across attach/detach.

For a routed container uplink that is not a bridge slave, run:

```sh
NODEWALL_BPF_TEST=1 go test -v ./internal/xdp -run '^TestRoutedContainerIngress$'
```

The isolated FIB/veth fixture verifies that a forwarded pod request reaches the
existing routing stack while the same ingress interface still denies a request
to an unallowed host port. No production CNI, iptables, or sysctl is changed.

The explicit legacy iptables backend has an opt-in real packet test as well:

```sh
NODEWALL_IPTABLES_TEST=1 go test -v ./internal/xdp -run '^TestIPTablesHostConnections$'
```

Run it on Linux as root with `ip`, `iptables`, and network namespace privileges.
It creates two disposable network namespaces and refuses to modify the original
host network namespace. It covers TCP/UDP replies, inbound service responses,
default deny, explicit revocation, observe mode, legacy hook migration, and
repeatable cleanup while preserving unrelated rules. It also empties, deletes,
reorders, and bypasses private chains, verifies degraded runtime status, and
checks that reconciliation restores real inbound and outbound blocking.

On a ZStack host, set `NODEWALL_ZSTACK_RESTORE_PYTHON` to its KVM agent virtualenv
Python executable to exercise the installed `zstacklib` save/parse/restore code
three times inside the disposable namespace. This does not invoke the live
security-group plugin or change the host's firewall or VM settings.
