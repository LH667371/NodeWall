package xdp

import (
	"fmt"
	"strings"
	"testing"

	"nodewall/internal/models"
)

type fakeIPTablesRunner struct {
	calls   [][]string
	outputs map[string]string
}

func (r *fakeIPTablesRunner) Run(args ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	key := strings.Join(args, " ")
	if output, ok := r.outputs[key]; ok {
		return output, nil
	}
	if strings.Contains(key, " -N ") {
		return "Chain already exists.", fmt.Errorf("exists")
	}
	return "", nil
}

func TestIPTablesManagerKeepsZStackTrafficAndOwnsFirstJump(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n-A PREROUTING ! -p 253 -j ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.Attach("em1", AttachModeNative); err != nil {
		t.Fatalf("attach legacy dataplane: %v", err)
	}
	if err := manager.ReplaceBlockedCIDRs("em1", []string{"203.0.113.9/32"}); err != nil {
		t.Fatalf("replace blocks: %v", err)
	}
	if err := manager.ReplaceDeniedPortRules("em1", []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 8080}}); err != nil {
		t.Fatalf("replace denied ports: %v", err)
	}
	if err := manager.WriteConfig("em1", Config{PolicyEnforced: true}); err != nil {
		t.Fatalf("write config: %v", err)
	}

	joined := commandLog(runner.calls)
	for _, want := range []string{
		"-t raw -I PREROUTING 1 -i br_em1 -j NWRAW_EM1",
		"-t raw -A NWRAW_EM1 -p 253 -j RETURN",
		"-t raw -A NWRAW_EM1 -s 203.0.113.9/32 -m comment --comment nodewall:blocked_source -j DROP",
		"-t raw -A NWRAW_EM1 -p tcp --dport 8080 -m comment --comment nodewall:denied_port -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing command %q in:\n%s", want, joined)
		}
	}
}

func TestIPTablesCountersProduceDropRecords(t *testing.T) {
	chain := iptablesChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -L " + chain + " -v -x -n": "pkts bytes target prot opt in out source destination\n9 720 DROP tcp -- * * 198.51.100.8/32 0.0.0.0/0 tcp dpt:443 /* nodewall:blocked_source */\n4 320 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0\n",
	}}
	manager := newIPTablesManager(runner, nil)
	logs, err := manager.ReadDropLogs("em1", 10)
	if err != nil {
		t.Fatalf("read drop logs: %v", err)
	}
	if len(logs) != 1 || logs[0].SourceIP != "198.51.100.8" || logs[0].Port != 443 || logs[0].Drops != 9 {
		t.Fatalf("unexpected logs: %#v", logs)
	}
	stats, err := manager.ReadStats("em1")
	if err != nil {
		t.Fatalf("read stats: %v", err)
	}
	if stats.Passed != 4 || stats.Dropped != 9 {
		t.Fatalf("unexpected stats: %#v", stats)
	}
}

func TestIPTablesObserveOnlyDoesNotCompileDropRules(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatalf("attach legacy dataplane: %v", err)
	}
	if err := manager.ReplaceBlockedCIDRs("em1", []string{"203.0.113.9/32"}); err != nil {
		t.Fatalf("replace blocks: %v", err)
	}
	if err := manager.WriteConfig("em1", Config{PolicyEnforced: true, ObserveOnly: true}); err != nil {
		t.Fatalf("write observe-only config: %v", err)
	}

	joined := commandLog(runner.calls)
	if strings.Contains(joined, "nodewall:blocked_source -j DROP") {
		t.Fatalf("observe-only policy unexpectedly compiled a drop rule:\n%s", joined)
	}
	if !strings.Contains(joined, "-t raw -A NWRAW_EM1 -j RETURN") {
		t.Fatalf("observe-only policy did not compile a terminal return:\n%s", joined)
	}
}

func TestIPTablesObserveOnlyReportsWouldBeDrops(t *testing.T) {
	chain := iptablesChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -L " + chain + " -v -x -n": "pkts bytes target prot opt in out source destination\n7 560 RETURN tcp -- * * 203.0.113.9 0.0.0.0/0 tcp dpt:22 /* nodewall:denied_port */\n",
	}}
	manager := newIPTablesManager(runner, nil)
	logs, err := manager.ReadDropLogs("em1", 10)
	if err != nil {
		t.Fatalf("read observed drop logs: %v", err)
	}
	if len(logs) != 1 || logs[0].SourceIP != "203.0.113.9" || logs[0].Port != 22 || logs[0].Drops != 7 {
		t.Fatalf("unexpected observed logs: %#v", logs)
	}
}

func TestIPTablesEgressStatsAndLogsAreReadable(t *testing.T) {
	chain := iptablesEgressChainName("em1")
	forwardChain := iptablesForwardEgressChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -L " + chain + " -v -x -n":           "pkts bytes target prot opt in out source destination\n5 400 RETURN tcp -- * * 0.0.0.0/0 198.51.100.8 tcp dpt:443 /* nodewall:denied_port */\n2 160 RETURN tcp -- * * 0.0.0.0/0 203.0.113.8 tcp dpt:443\n",
		"-t mangle -L " + forwardChain + " -v -x -n": "pkts bytes target prot opt in out source destination\n3 240 DROP tcp -- * * 10.10.0.9 198.51.100.9 tcp dpt:443 /* nodewall:blocked_source */\n",
	}}
	manager := newIPTablesManager(runner, nil)
	stats, err := manager.ReadDirectionStats("em1", models.DirectionEgress)
	if err != nil {
		t.Fatalf("read egress stats: %v", err)
	}
	if stats.Direction != models.DirectionEgress || stats.Dropped != 8 || stats.Passed != 2 {
		t.Fatalf("unexpected egress stats: %#v", stats)
	}
	logs, err := manager.ReadDirectionDropLogs("em1", models.DirectionEgress, 10)
	if err != nil {
		t.Fatalf("read egress logs: %v", err)
	}
	if len(logs) != 2 || logs[0].Direction != models.DirectionEgress || logs[0].SourceIP != "198.51.100.8" || logs[0].Port != 443 {
		t.Fatalf("unexpected egress logs: %#v", logs)
	}
	sources, err := manager.ReadDirectionSourceStats("em1", models.DirectionEgress, 10)
	if err != nil {
		t.Fatalf("read egress sources: %v", err)
	}
	if len(sources) != 3 || sources[0].SourceIP != "198.51.100.8" || sources[0].Dropped != 5 {
		t.Fatalf("unexpected egress sources: %#v", sources)
	}
}

func TestIPTablesEgressLogsMergeOutputAndForwardCounters(t *testing.T) {
	logs := dropLogsFromCounters([]iptablesCounter{
		{packets: 2, target: "DROP", source: "10.10.0.5", destination: "198.51.100.8", port: 443, reason: "nodewall:blocked_source", wouldDrop: true},
		{packets: 3, target: "DROP", source: "10.10.0.6", destination: "198.51.100.8", port: 443, reason: "nodewall:blocked_source", wouldDrop: true},
	}, models.DirectionEgress, 10)
	if len(logs) != 1 || logs[0].SourceIP != "198.51.100.8" || logs[0].Drops != 5 || logs[0].Count != 5 {
		t.Fatalf("unexpected merged egress logs: %#v", logs)
	}
}

func TestEnsureJumpIgnoresChainPolicy(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n-A PREROUTING -i br_em1 -j NWRAW_EM1\n-A PREROUTING ! -p 253 -j ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.ensureJumpFirst(iptablesTable, iptablesParent, "-i", "br_em1", "NWRAW_EM1"); err != nil {
		t.Fatalf("ensure first jump: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("policy line caused an unnecessary rewrite: %#v", runner.calls)
	}
}

func TestIPTablesEgressPolicyUsesPrivateOutputChain(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatalf("attach legacy dataplane: %v", err)
	}
	if err := manager.ApplyDirectionPolicy("em1", models.DirectionEgress, DirectionPolicy{
		BlockedCIDRs:   []string{"198.51.100.0/24"},
		PolicyEnforced: true,
	}); err != nil {
		t.Fatalf("apply egress policy: %v", err)
	}
	joined := commandLog(runner.calls)
	if !strings.Contains(joined, "-t raw -A NWRAW_OUT_EM1 -d 198.51.100.0/24 -m comment --comment nodewall:blocked_source -j DROP") {
		t.Fatalf("egress destination rule missing:\n%s", joined)
	}
	if !strings.Contains(joined, "-t raw -I OUTPUT 1 -o em1 -j NWRAW_OUT_EM1") {
		t.Fatalf("egress output jump missing:\n%s", joined)
	}
	if !strings.Contains(joined, "-t mangle -I FORWARD 1 -o em1 -j NWFW_OUT_EM1") {
		t.Fatalf("egress forwarded-traffic jump missing:\n%s", joined)
	}
}

func TestIPTablesEgressRateLimitTargetsRemoteDestination(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, nil)
	if err := manager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatalf("attach legacy dataplane: %v", err)
	}
	if err := manager.ApplyDirectionPolicy("em1", models.DirectionEgress, DirectionPolicy{
		RateLimitRules: []models.RateLimitRule{{
			ID:                "remote-rate",
			SourceIP:          "198.51.100.8",
			Protocol:          models.PortProtocolTCP,
			Port:              443,
			RequestsPerMinute: 120,
			Burst:             20,
		}},
		PolicyEnforced: true,
	}); err != nil {
		t.Fatalf("apply egress rate limit: %v", err)
	}

	joined := commandLog(runner.calls)
	for _, want := range []string{
		"-t raw -A NWRAW_OUT_EM1 -d 198.51.100.8 -p tcp --dport 443",
		"-t mangle -A NWFW_OUT_EM1 -d 198.51.100.8 -p tcp --dport 443",
		"--hashlimit-mode dstip",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing egress rate-limit command %q in:\n%s", want, joined)
		}
	}
}

func TestIPTablesCompileFailureLeavesFailOpenChain(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S PREROUTING": "-P PREROUTING ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, nil)
	if err := manager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatalf("attach legacy dataplane: %v", err)
	}
	err := manager.replaceDirectionChain(iptablesTable, iptablesChainName("em1"), DirectionPolicy{
		DeniedPortRules: []models.PortRule{{Protocol: models.PortProtocol("sctp"), Port: 443}},
		PolicyEnforced:  true,
	}, "-s")
	if err == nil {
		t.Fatal("expected invalid protocol to fail policy compilation")
	}
	joined := commandLog(runner.calls)
	if !strings.Contains(joined, "-t raw -F NWRAW_EM1") || !strings.Contains(joined, "-t raw -A NWRAW_EM1 -j RETURN") {
		t.Fatalf("compile failure did not leave a fail-open chain:\n%s", joined)
	}
}

func commandLog(calls [][]string) string {
	lines := make([]string, 0, len(calls))
	for _, call := range calls {
		lines = append(lines, strings.Join(call, " "))
	}
	return strings.Join(lines, "\n")
}
