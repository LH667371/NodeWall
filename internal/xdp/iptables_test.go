package xdp

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"nodewall/internal/models"
)

func TestIPTablesNFTIncompatibleChainNeedsConfirmedAbsence(t *testing.T) {
	const message = "iptables v1.8.9 (nf_tables): chain `NWRAW_EM1' in table `raw' is incompatible, use 'nft' tool."
	for _, tc := range []struct {
		name, listing    string
		readErr, wantErr bool
	}{
		{"absent", "-P PREROUTING ACCEPT\n-A PREROUTING -m comment --comment \"NWRAW_EM1\" -j RETURN\n", false, false},
		{"still-present", "-N NWRAW_EM1\n", false, true},
		{"still-referenced", "-A PREROUTING -j NWRAW_EM1\n", false, true},
		{"read-denied", "", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fakeIPTablesRunner{outputs: map[string]string{"-t raw -S NWRAW_EM1": message, "-t raw -S": tc.listing}, errors: map[string]error{"-t raw -S NWRAW_EM1": errors.New(message)}}
			if tc.readErr {
				runner.errors["-t raw -S"] = errors.New("permission denied")
			}
			manager := newIPTablesManager(runner, nil)
			var errs []error
			manager.removeOwnedChain("raw", "NWRAW_EM1", &errs)
			if (len(errs) > 0) != tc.wantErr {
				t.Fatalf("errors=%v wantErr=%t", errs, tc.wantErr)
			}
			for _, call := range runner.calls {
				if len(call) < 3 || call[2] != "-S" {
					t.Fatalf("unexpected mutation on failed inspection: %v", call)
				}
			}
		})
	}
}

type fakeIPTablesRunner struct {
	calls   [][]string
	outputs map[string]string
	errors  map[string]error
	rules   map[string][][]string
}

func (r *fakeIPTablesRunner) Run(args ...string) (string, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	key := strings.Join(args, " ")
	if err := r.errors[key]; err != nil {
		return r.outputs[key], err
	}
	if output, ok := r.outputs[key]; ok {
		return output, nil
	}
	if len(args) >= 4 && args[0] == "-t" {
		if r.rules == nil {
			r.rules = make(map[string][][]string)
		}
		chain := args[1] + "/" + args[3]
		switch args[2] {
		case "-N":
			if _, exists := r.rules[chain]; exists {
				return "Chain already exists.", fmt.Errorf("exists")
			}
			r.rules[chain] = nil
		case "-F":
			r.rules[chain] = nil
		case "-A":
			r.rules[chain] = append(r.rules[chain], append([]string(nil), args[4:]...))
		case "-S":
			if rules, ok := r.rules[chain]; ok {
				lines := []string{"-N " + args[3]}
				for _, rule := range rules {
					lines = append(lines, "-A "+args[3]+" "+strings.Join(rule, " "))
				}
				return strings.Join(lines, "\n") + "\n", nil
			}
		}
	}
	return "", nil
}

func TestIPTablesManagerKeepsZStackTrafficAndOwnsFirstJump(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n-A INPUT ! -p 253 -j ACCEPT\n",
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
		"-t filter -I INPUT 1 -i br_em1 -j NWRAW_EM1",
		"-t filter -A NWRAW_EM1 -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment nodewall:reply_flow -j RETURN",
		"-t filter -A NWRAW_EM1 -p 253 -j RETURN",
		"-t filter -A NWRAW_EM1 -s 203.0.113.9/32 -m comment --comment nodewall:blocked_source -j DROP",
		"-t filter -A NWRAW_EM1 -p tcp --dport 8080 -m comment --comment nodewall:denied_port -j DROP",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing command %q in:\n%s", want, joined)
		}
	}
}

func TestIPTablesCountersProduceDropRecords(t *testing.T) {
	chain := iptablesChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -L " + chain + " -v -x -n": "pkts bytes target prot opt in out source destination\n9 720 DROP tcp -- * * 198.51.100.8/32 0.0.0.0/0 tcp dpt:443 /* nodewall:blocked_source */\n4 320 RETURN all -- * * 0.0.0.0/0 0.0.0.0/0\n",
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

func TestIPTablesAggregateCountersNeverInventPacketSources(t *testing.T) {
	output := "pkts bytes target prot opt in out source destination\n" +
		"3 240 DROP udp -- * * 0.0.0.0/0 0.0.0.0/0 udp dpt:67 /* nodewall:default_deny */\n" +
		"5 400 DROP tcp -- * * 10.42.0.0/16 0.0.0.0/0 tcp dpt:443 /* nodewall:denied_port */\n" +
		"7 560 RETURN tcp -- * * 10.42.0.0/16 0.0.0.0/0 tcp dpt:443 /* nodewall:denied_port */\n" +
		"2 160 DROP udp -- * * 0.0.0.0/32 0.0.0.0/0 udp dpt:67 /* nodewall:denied_port */\n"
	logs := dropLogsFromCounters(parseIPTablesListCounters(output), models.DirectionIngress, 20)
	if len(logs) != 4 {
		t.Fatalf("lost distinct observed/enforced counters: %+v", logs)
	}
	seen := map[string]bool{}
	for _, entry := range logs {
		switch {
		case entry.SourceIP == "0.0.0.0":
			if entry.SourceCIDR != "" || entry.Drops != 2 {
				t.Fatalf("real unspecified source lost: %+v", entry)
			}
			seen["packet"] = true
		case entry.SourceCIDR == "0.0.0.0/0":
			if entry.SourceIP != "" || entry.Drops != 3 {
				t.Fatalf("invented all-address source: %+v", entry)
			}
			seen["all"] = true
		case entry.SourceCIDR == "10.42.0.0/16":
			if entry.SourceIP != "" {
				t.Fatalf("CIDR became a packet source: %+v", entry)
			}
			if entry.Count == 7 && entry.Drops == 0 {
				seen["observed"] = true
			}
			if entry.Count == 5 && entry.Drops == 5 {
				seen["enforced"] = true
			}
		default:
			t.Fatalf("unknown counter: %+v", entry)
		}
	}
	if len(seen) != 4 {
		t.Fatalf("missing counter classes: %+v", seen)
	}
	stats := sourceStatsFromCounters(parseIPTablesListCounters(output), models.DirectionIngress, 20)
	if len(stats) != 0 {
		t.Fatalf("aggregate counters became individual attackers: %+v", stats)
	}
}

func TestIPTablesObserveOnlyDoesNotCompileDropRules(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n",
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
	if !strings.Contains(joined, "-t filter -A NWRAW_EM1 -j RETURN") {
		t.Fatalf("observe-only policy did not compile a terminal return:\n%s", joined)
	}
}

func TestIPTablesObserveOnlyReportsWouldBeDrops(t *testing.T) {
	chain := iptablesChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -L " + chain + " -v -x -n": "pkts bytes target prot opt in out source destination\n7 560 RETURN tcp -- * * 203.0.113.9 0.0.0.0/0 tcp dpt:22 /* nodewall:denied_port */\n",
	}}
	manager := newIPTablesManager(runner, nil)
	logs, err := manager.ReadDropLogs("em1", 10)
	if err != nil {
		t.Fatalf("read observed drop logs: %v", err)
	}
	if len(logs) != 1 || logs[0].SourceIP != "203.0.113.9" || logs[0].Port != 22 || logs[0].Drops != 0 || logs[0].Count != 7 {
		t.Fatalf("unexpected observed logs: %#v", logs)
	}
}

func TestIPTablesEgressStatsAndLogsAreReadable(t *testing.T) {
	chain := iptablesEgressChainName("em1")
	forwardChain := iptablesForwardEgressChainName("em1")
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -L " + chain + " -v -x -n":        "pkts bytes target prot opt in out source destination\n5 400 RETURN tcp -- * * 0.0.0.0/0 198.51.100.8 tcp dpt:443 /* nodewall:denied_port */\n2 160 RETURN tcp -- * * 0.0.0.0/0 203.0.113.8 tcp dpt:443\n",
		"-t mangle -L " + forwardChain + " -v -x -n": "pkts bytes target prot opt in out source destination\n3 240 DROP tcp -- * * 10.10.0.9 198.51.100.9 tcp dpt:443 /* nodewall:blocked_source */\n",
	}}
	manager := newIPTablesManager(runner, nil)
	stats, err := manager.ReadDirectionStats("em1", models.DirectionEgress)
	if err != nil {
		t.Fatalf("read egress stats: %v", err)
	}
	if stats.Direction != models.DirectionEgress || stats.Dropped != 5 || stats.Passed != 2 {
		t.Fatalf("unexpected egress stats: %#v", stats)
	}
	logs, err := manager.ReadDirectionDropLogs("em1", models.DirectionEgress, 10)
	if err != nil {
		t.Fatalf("read egress logs: %v", err)
	}
	if len(logs) != 1 || logs[0].Direction != models.DirectionEgress || logs[0].SourceIP != "198.51.100.8" || logs[0].Port != 443 {
		t.Fatalf("unexpected egress logs: %#v", logs)
	}
	sources, err := manager.ReadDirectionSourceStats("em1", models.DirectionEgress, 10)
	if err != nil {
		t.Fatalf("read egress sources: %v", err)
	}
	if len(sources) != 2 || sources[0].SourceIP != "198.51.100.8" || sources[0].Dropped != 5 {
		t.Fatalf("unexpected egress sources: %#v", sources)
	}
}

func TestIPTablesEgressLogsMergeDuplicateDispositions(t *testing.T) {
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
		"-t filter -S INPUT": "-P INPUT ACCEPT\n-A INPUT -i br_em1 -j NWRAW_EM1\n-A INPUT ! -p 253 -j ACCEPT\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.ensureJumpFirst(iptablesTable, iptablesParent, "-i", "br_em1", "NWRAW_EM1"); err != nil {
		t.Fatalf("ensure first jump: %v", err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("policy line caused an unnecessary rewrite: %#v", runner.calls)
	}
}

func TestDetachRemovesReferencesFromEveryParentChain(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n-A INPUT -i br_em1 -j NWRAW_EM1\n",
		"-t filter -S":       "-P INPUT ACCEPT\n-A INPUT -i br_em1 -j NWRAW_EM1\n-A OUTPUT -o em1 -j NWRAW_EM1\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.MockManager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatal(err)
	}
	if err := manager.Detach("em1"); err != nil {
		t.Fatalf("detach: %v", err)
	}
	joined := commandLog(runner.calls)
	if !strings.Contains(joined, "-t filter -D OUTPUT -o em1 -j NWRAW_EM1") {
		t.Fatalf("detach did not remove the stale reference in OUTPUT:\n%s", joined)
	}
	if !strings.Contains(joined, "-t filter -X NWRAW_EM1") {
		t.Fatalf("detach did not delete the private chain:\n%s", joined)
	}
}

func TestIPTablesEgressPolicyUsesPrivateOutputChain(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n",
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
	if !strings.Contains(joined, "-t filter -A NWRAW_OUT_EM1 -d 198.51.100.0/24 -m comment --comment nodewall:blocked_source -j DROP") {
		t.Fatalf("egress destination rule missing:\n%s", joined)
	}
	if !strings.Contains(joined, "-t filter -I OUTPUT 1 -o em1 -j NWRAW_OUT_EM1") {
		t.Fatalf("egress output jump missing:\n%s", joined)
	}
	if strings.Contains(joined, "-I FORWARD") || strings.Contains(joined, "-A NWFW_OUT_EM1") {
		t.Fatalf("host policy must not install VM forwarding rules:\n%s", joined)
	}
	if strings.Contains(joined, "-t filter -A NWRAW_OUT_EM1 -m physdev --physdev-is-bridged") {
		t.Fatalf("host-originated OUTPUT chain unexpectedly received a bridge-only match:\n%s", joined)
	}
}

func TestIPTablesEgressRateLimitTargetsRemoteDestination(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n",
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
		"-t filter -A NWRAW_OUT_EM1 -d 198.51.100.8 -p tcp --dport 443",
		"--hashlimit-mode dstip",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing egress rate-limit command %q in:\n%s", want, joined)
		}
	}
}

func TestIPTablesCompileFailureLeavesFailOpenChain(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t filter -S INPUT": "-P INPUT ACCEPT\n",
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
	if !strings.Contains(joined, "-t filter -F NWRAW_EM1") || !strings.Contains(joined, "-t filter -A NWRAW_EM1 -j RETURN") {
		t.Fatalf("compile failure did not leave a fail-open chain:\n%s", joined)
	}
}

func TestIPTablesReplyStateComesAfterRevocationsAndBeforeDefaultDeny(t *testing.T) {
	for _, direction := range []string{"-s", "-d"} {
		t.Run(direction, func(t *testing.T) {
			runner := &fakeIPTablesRunner{}
			manager := newIPTablesManager(runner, nil)
			if err := manager.replaceDirectionChain(iptablesTable, "NWRAW_TEST", DirectionPolicy{
				BlockedCIDRs:    []string{"192.0.2.1/32"},
				DeniedPortRules: []models.PortRule{{Protocol: models.PortProtocolTCP, Port: 443}},
				Allowlist:       []string{"198.51.100.0/24"},
				PolicyEnforced:  true,
			}, direction); err != nil {
				t.Fatal(err)
			}
			joined := commandLog(runner.calls)
			reply := strings.Index(joined, "--ctstate ESTABLISHED,RELATED")
			block := strings.Index(joined, "nodewall:blocked_source")
			deny := strings.Index(joined, "nodewall:denied_port")
			fallback := strings.Index(joined, "nodewall:default_deny")
			if block < 0 || deny < 0 || reply < deny || reply < block || fallback < reply {
				t.Fatalf("unsafe reply-state priority:\n%s", joined)
			}
		})
	}
}

func TestIPTablesMigrationRetiresOnlyOwnedLegacyHooks(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S":          "-P PREROUTING ACCEPT\n-A PREROUTING -i br_em1 -j NWRAW_EM1\n-A OUTPUT -o br_em1 -j NWRAW_OUT_EM1\n-A PREROUTING -p 253 -m comment --comment zstack-network -j NFLOG\n",
		"-t mangle -S":       "-P FORWARD ACCEPT\n-A FORWARD -o br_em1 -j NWFW_OUT_EM1\n-A FORWARD -j ZSTACK_FORWARD\n",
		"-t filter -S INPUT": "-P INPUT ACCEPT\n-A INPUT -i br_em1 -j NWRAW_EM1\n",
	}}
	manager := newIPTablesManager(runner, func(string) string { return "br_em1" })
	if err := manager.Attach("em1", AttachModeIPTables); err != nil {
		t.Fatal(err)
	}
	joined := commandLog(runner.calls)
	for _, want := range []string{
		"-t raw -D PREROUTING -i br_em1 -j NWRAW_EM1",
		"-t raw -D OUTPUT -o br_em1 -j NWRAW_OUT_EM1",
		"-t mangle -D FORWARD -o br_em1 -j NWFW_OUT_EM1",
		"-t raw -X NWRAW_EM1", "-t raw -X NWRAW_OUT_EM1", "-t mangle -X NWFW_OUT_EM1",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("migration omitted %q:\n%s", want, joined)
		}
	}
	for _, call := range runner.calls {
		if len(call) < 4 || call[2] == "-S" || call[1] == "filter" {
			continue
		}
		if !strings.HasPrefix(call[len(call)-1], "NW") {
			t.Fatalf("migration changed a foreign rule: %v", call)
		}
	}
	if strings.Index(joined, "-t filter -A NWRAW_EM1 -j RETURN") > strings.Index(joined, "-t raw -D PREROUTING") {
		t.Fatalf("legacy hooks removed before replacement chain was ready:\n%s", joined)
	}
	runner.calls = nil
	if err := manager.Reconcile(); err != nil {
		t.Fatal(err)
	}
	for _, call := range runner.calls {
		if len(call) > 2 && call[2] != "-S" {
			t.Fatalf("reconcile rewrote healthy hooks/counters: %v", call)
		}
	}
}

func TestIPTablesMissingConntrackFailsOpen(t *testing.T) {
	runner := &fakeIPTablesRunner{errors: map[string]error{
		"-t filter -A NWRAW_TEST -m conntrack --ctstate ESTABLISHED,RELATED -m comment --comment nodewall:reply_flow -j RETURN": fmt.Errorf("conntrack match unavailable"),
	}}
	manager := newIPTablesManager(runner, nil)
	if err := manager.replaceDirectionChain(iptablesTable, "NWRAW_TEST", DirectionPolicy{PolicyEnforced: true, Allowlist: []string{"192.0.2.1/32"}}, "-s"); err == nil {
		t.Fatal("missing conntrack must prevent enabling stateless enforcement")
	}
	joined := commandLog(runner.calls)
	if strings.Contains(joined, "nodewall:default_deny") || !strings.HasSuffix(joined, "-t filter -A NWRAW_TEST -j RETURN") {
		t.Fatalf("missing conntrack did not retain recovery access:\n%s", joined)
	}
}

func TestLegacyCleanupParsesQuotedCommentsWithoutChangingForeignRules(t *testing.T) {
	runner := &fakeIPTablesRunner{outputs: map[string]string{
		"-t raw -S": "-A PREROUTING -m comment --comment \"keep -j NWRAW_EM1 inside this comment\" -j ACCEPT\n-A OUTPUT -m comment --comment \"old NodeWall hook\" -j NWRAW_EM1\n",
	}}
	manager := newIPTablesManager(runner, nil)
	var errs []error
	manager.removeAllChainReferences("raw", "NWRAW_EM1", &errs)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := []string{"-t", "raw", "-D", "OUTPUT", "-m", "comment", "--comment", "old NodeWall hook", "-j", "NWRAW_EM1"}
	if len(runner.calls) != 2 || !reflect.DeepEqual(runner.calls[1], want) {
		t.Fatalf("cleanup touched a foreign rule or split a quoted argument: %#v", runner.calls)
	}
	for _, text := range []string{`-A INPUT --comment "broken`, "-A INPUT \\"} {
		if _, err := splitIPTablesArgs(text); err == nil {
			t.Errorf("malformed quoted rule accepted: %q", text)
		}
	}
}

func TestIPTablesReconcilesChangedRuleBodiesAndReportsDrift(t *testing.T) {
	for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
		for _, mutation := range []string{"empty", "bypass", "reordered"} {
			t.Run(string(direction)+"/"+mutation, func(t *testing.T) {
				runner := &fakeIPTablesRunner{outputs: map[string]string{
					"-t filter -S INPUT":  "-P INPUT ACCEPT\n-A INPUT -i em1 -j NWRAW_EM1\n",
					"-t filter -S OUTPUT": "-P OUTPUT ACCEPT\n-A OUTPUT -o em1 -j NWRAW_OUT_EM1\n",
				}}
				manager := newIPTablesManager(runner, nil)
				if err := manager.Attach("em1", AttachModeIPTables); err != nil {
					t.Fatal(err)
				}
				if err := manager.ApplyDirectionPolicy("em1", models.DirectionEgress, DirectionPolicy{PolicyEnforced: true, Allowlist: []string{"192.0.2.1/32"}}); err != nil {
					t.Fatal(err)
				}
				chain := iptablesChainName("em1")
				if direction == models.DirectionEgress {
					chain = iptablesEgressChainName("em1")
				}
				key := "filter/" + chain
				expected := manager.chainDigests[chain]
				switch mutation {
				case "empty":
					runner.rules[key] = nil
				case "bypass":
					runner.rules[key] = append([][]string{{"-j", "RETURN"}}, runner.rules[key]...)
				case "reordered":
					rules := runner.rules[key]
					runner.rules[key] = append(append([][]string(nil), rules[1:]...), rules[0])
				}
				if runtime, err := manager.Runtime("em1"); err == nil || runtime.ProgramLoaded {
					t.Fatal("changed rules were reported as active protection")
				}
				if err := manager.Reconcile(); err != nil {
					t.Fatal(err)
				}
				if !manager.chainMatches(chain) || manager.chainDigests[chain] != expected {
					t.Fatal("reconciler did not restore the configured rule body")
				}
				if _, err := manager.Runtime("em1"); err != nil {
					t.Fatalf("restored protection remained degraded: %v", err)
				}
				runner.calls = nil
				if err := manager.Reconcile(); err != nil {
					t.Fatal(err)
				}
				for _, call := range runner.calls {
					if len(call) >= 3 && call[2] != "-S" {
						t.Fatalf("healthy rule counters were reset: %v", call)
					}
				}
			})
		}
	}
}

func commandLog(calls [][]string) string {
	lines := make([]string, 0, len(calls))
	for _, call := range calls {
		lines = append(lines, strings.Join(call, " "))
	}
	return strings.Join(lines, "\n")
}
