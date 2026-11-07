//go:build linux

package securityscan

import (
	"os"
	"testing"
)

func TestInspectExecutableFileDetectsCryptominerIndicators(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "deleted-miner-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	// This is inert test data. It has an ELF signature and the independent
	// miner markers required by the detector; it is never executed.
	sample := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("XMRig 6.24.0 randomx cryptonight stratum+ssl")...)
	if _, err := file.Write(sample); err != nil {
		t.Fatal(err)
	}
	if err := file.Sync(); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}

	threat, ok := inspectExecutableFile(file, file.Name()+" (deleted)", info)
	if !ok {
		t.Fatal("expected miner indicators in an open executable to be detected")
	}
	if threat.rule != "cryptominer" || threat.severity != SeverityHigh {
		t.Fatalf("unexpected threat: %#v", threat)
	}
	if threat.sha256 == "" || threat.size != int64(len(sample)) {
		t.Fatalf("expected evidence metadata, got %#v", threat)
	}
}

func TestInspectExecutableFileIgnoresSingleMinerName(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "normal-tool-*")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	sample := append([]byte{0x7f, 'E', 'L', 'F'}, []byte("tool documentation mentions xmrig")...)
	if _, err := file.Write(sample); err != nil {
		t.Fatal(err)
	}
	info, err := file.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if threat, ok := inspectExecutableFile(file, file.Name(), info); ok {
		t.Fatalf("single miner name should not be enough: %#v", threat)
	}
}
