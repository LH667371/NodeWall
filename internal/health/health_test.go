package health

import (
	"context"
	"testing"

	"nodewall/internal/xdp"
)

func TestCheckReportsRuleAndEnforcementMismatch(t *testing.T) {
	dataplane := xdp.NewMockManager()
	if err := dataplane.Attach("eth0", xdp.AttachModeGeneric); err != nil {
		t.Fatalf("attach mock dataplane: %v", err)
	}
	if err := dataplane.UpsertCIDR("eth0", "10.0.0.0/8"); err != nil {
		t.Fatalf("add allowlist: %v", err)
	}

	status := (Probe{NodeID: "node-01", XDP: dataplane}).Check(context.Background())
	if status.Status != "degraded" {
		t.Fatalf("expected degraded status, got %#v", status)
	}
	if len(status.Interfaces) != 1 || status.Interfaces[0].EnforcementOK {
		t.Fatalf("expected enforcement mismatch to be reported, got %#v", status.Interfaces)
	}

	cfg, err := dataplane.ReadConfig("eth0")
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfg.PolicyEnforced = true
	if err := dataplane.WriteConfig("eth0", cfg); err != nil {
		t.Fatalf("enable policy enforcement: %v", err)
	}

	status = (Probe{NodeID: "node-01", XDP: dataplane}).Check(context.Background())
	if status.Status != "ok" || len(status.Interfaces) != 1 || !status.Interfaces[0].EnforcementOK {
		t.Fatalf("expected healthy enforcement after config update, got %#v", status)
	}
}

func TestCheckReportsUnattachedHostAsDegraded(t *testing.T) {
	dataplane := xdp.NewMockManager()

	status := (Probe{NodeID: "node-01", XDP: dataplane}).Check(context.Background())
	if status.Status != "degraded" {
		t.Fatalf("expected unattached host to be degraded, got %#v", status)
	}
	for _, iface := range status.Interfaces {
		if iface.XDPAttached || iface.MapOK || iface.StatsOK {
			t.Fatalf("unattached interface was reported healthy: %#v", iface)
		}
	}
}

func TestCheckDoesNotReportObserveOnlyRulesAsEnforced(t *testing.T) {
	dataplane := xdp.NewMockManager()
	if err := dataplane.Attach("eth0", xdp.AttachModeGeneric); err != nil {
		t.Fatalf("attach mock dataplane: %v", err)
	}
	if err := dataplane.UpsertCIDR("eth0", "10.0.0.0/8"); err != nil {
		t.Fatalf("add allowlist: %v", err)
	}
	cfg, err := dataplane.ReadConfig("eth0")
	if err != nil {
		t.Fatal(err)
	}
	cfg.PolicyEnforced = true
	cfg.ObserveOnly = true
	if err := dataplane.WriteConfig("eth0", cfg); err != nil {
		t.Fatal(err)
	}
	status := (Probe{NodeID: "node-01", XDP: dataplane}).Check(context.Background())
	if len(status.Interfaces) != 1 || !status.Interfaces[0].ObserveOnly || status.Interfaces[0].PolicyEnforced {
		t.Fatalf("observe-only dataplane was reported as enforced: %#v", status.Interfaces)
	}
}
