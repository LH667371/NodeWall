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
```

The packet test uses BPF_PROG_TEST_RUN and needs BPF privileges, but never
attaches a program to a host interface.
