//go:build linux

package securityscan

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestSystemdCommandFieldsSkipsWrappersAndKeepsPayload(t *testing.T) {
	paths := systemdRelatedPaths([]byte("[Service]\nExecStart=/usr/bin/env MINER_MODE=1 /bin/sh /tmp/loader.sh --config /var/tmp/payload.conf\n"))
	want := map[string]bool{"/tmp/loader.sh": true}
	if len(paths) != len(want) {
		t.Fatalf("systemdRelatedPaths() = %#v, want %#v", paths, want)
	}
	for _, path := range paths {
		if !want[path] {
			t.Errorf("wrapper or unexpected command was retained: %s", path)
		}
	}
}

func TestRandomStartupNamesDoNotDependOnObservedUnit(t *testing.T) {
	for _, path := range []string{
		"/etc/systemd/system/31b06da8.service",
		"/etc/systemd/system/q7m2x91k.service",
		"/usr/lib/systemd/system/31b06da81846f30e.service",
	} {
		if !isRandomSystemdUnitPath(path) {
			t.Errorf("random unit was not recognized: %s", path)
		}
	}
	for _, path := range []string{
		"/etc/systemd/system/ssh.service",
		"/etc/systemd/system/network-online.target",
		"/etc/systemd/system/nodewall-agent.service",
	} {
		if isRandomSystemdUnitPath(path) {
			t.Errorf("ordinary unit was treated as random: %s", path)
		}
	}
}

func TestRelatedPersistenceFindingOnlyPromotesRiskyPayloadReferences(t *testing.T) {
	root := t.TempDir()
	payload := filepath.Join(root, "payload")
	if err := os.WriteFile(payload, []byte("#!/bin/sh\necho payload\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	// Use a /tmp path because the collector treats temporary startup targets as
	// actionable evidence even when the payload itself has no signature.
	tmpPayload := filepath.Join("/tmp", "nodewall-scan-payload-"+filepath.Base(root))
	if err := os.Link(payload, tmpPayload); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(tmpPayload) })
	finding, ok := relatedPersistenceFinding(context.Background(), New(), tmpPayload, "f-unit", "random.service")
	if !ok || finding.Rule != "startup-payload" || finding.RelatedTo != "f-unit" {
		t.Fatalf("temporary payload was not linked: %#v, %t", finding, ok)
	}
	ordinary, ok := relatedPersistenceFinding(context.Background(), New(), "/usr/bin/mysqld", "f-unit", "random.service")
	if ok || ordinary.ID != "" {
		t.Fatalf("ordinary system executable became a payload finding: %#v, %t", ordinary, ok)
	}
}

func TestStartupWriterReferencesUnit(t *testing.T) {
	data := []byte("#!/bin/sh\ninstall -m 644 /tmp/payload.service /etc/systemd/system/q7m2x91k.service\nsystemctl enable q7m2x91k.service\n")
	if !startupWriterReferencesUnit(data, "q7m2x91k.service") {
		t.Fatal("unit writer was not associated with the service")
	}
	if startupWriterReferencesUnit([]byte("echo q7m2x91k.service"), "q7m2x91k.service") {
		t.Fatal("ordinary text mentioning a unit was treated as a writer")
	}
}
