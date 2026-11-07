package config

import (
	"testing"
	"time"
)

func TestLoadAgentConfigReadsDataplaneMode(t *testing.T) {
	t.Setenv("NODEWALL_DATAPLANE", "mock")
	t.Setenv("NODEWALL_IPTABLES_RECONCILE_INTERVAL", "9s")
	t.Setenv("NODEWALL_DEV_MODE", "demo")
	t.Setenv("NODEWALL_DEFAULT_INTERFACE", "eth0")
	t.Setenv("NODEWALL_ALLOWED_CIDRS", "127.0.0.1/32,10.0.0.0/8")

	cfg := LoadAgentConfig()
	if cfg.DataplaneMode != "mock" {
		t.Fatalf("unexpected dataplane mode: %s", cfg.DataplaneMode)
	}
	if cfg.IPTablesReconcileEvery != 9*time.Second {
		t.Fatalf("unexpected iptables reconcile interval: %s", cfg.IPTablesReconcileEvery)
	}
	if cfg.DevMode != "demo" {
		t.Fatalf("unexpected dev mode: %s", cfg.DevMode)
	}
	if cfg.DefaultInterface != "eth0" {
		t.Fatalf("unexpected default interface: %s", cfg.DefaultInterface)
	}
}

func TestLoadServerConfigSecurity(t *testing.T) {
	t.Setenv("NODEWALL_ALLOWED_CIDRS", "127.0.0.1/32,10.0.0.0/8")
	t.Setenv("NODEWALL_ALLOWED_IPS", "192.168.1.10,192.168.1.11")
	t.Setenv("NODEWALL_ALLOWED_MACS", "aa:bb:cc:dd:ee:ff")
	t.Setenv("NODEWALL_AUTH_FILE", "/tmp/nodewall-auth.json")
	t.Setenv("NODEWALL_AUTH_ENABLED", "true")

	cfg := LoadServerConfig()
	if !cfg.AuthEnabled {
		t.Fatalf("expected auth enabled")
	}
	if cfg.AuthFile != "/tmp/nodewall-auth.json" {
		t.Fatalf("unexpected auth file: %s", cfg.AuthFile)
	}
	if len(cfg.AllowedCIDRs) != 2 || len(cfg.AllowedIPs) != 2 || len(cfg.AllowedMACs) != 1 {
		t.Fatalf("unexpected allowlists: %+v %+v %+v", cfg.AllowedCIDRs, cfg.AllowedIPs, cfg.AllowedMACs)
	}
}

func TestLoadServerConfigDefaultsToExternalManagementListener(t *testing.T) {
	t.Setenv("NODEWALL_SERVER_ADDR", "")
	cfg := LoadServerConfig()
	if cfg.ListenAddr != "0.0.0.0:8080" {
		t.Fatalf("expected external management listener by default, got %q", cfg.ListenAddr)
	}
}

func TestHistoryStorageConfiguration(t *testing.T) {
	t.Setenv("NODEWALL_SCAN_REPORT_DIR", "/tmp/nodewall-test-reports")
	t.Setenv("NODEWALL_MONITORING_HISTORY_DIR", "/tmp/nodewall-test-history")
	t.Setenv("NODEWALL_MONITORING_HISTORY_MIB", "64")
	if LoadAgentConfig().ScanReportDir != "/tmp/nodewall-test-reports" {
		t.Fatal("scan report directory not configured")
	}
	server := LoadServerConfig()
	if server.MonitoringHistoryDir != "/tmp/nodewall-test-history" || server.MonitoringHistoryBytes != 64<<20 {
		t.Fatal("monitoring storage configuration ignored")
	}
}
