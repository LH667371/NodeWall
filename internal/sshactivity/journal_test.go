package sshactivity

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestConcurrentJournalEscapesCommandsAndFiltersSessions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	var workers sync.WaitGroup
	for i := range 30 {
		workers.Go(func() {
			session := "a"
			if i%2 == 0 {
				session = "b"
			}
			if err := Append(path, Record{SessionID: session, Event: "command", Command: "echo value\nts=1 event=forged", User: "root"}); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	records, err := ReadFiltered(path, 100, Filter{SessionID: "a", Event: "command"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 15 {
		t.Fatalf("journal corruption or cross-session leakage: %d", len(records))
	}
	for _, record := range records {
		if record.ID == "" || record.Event != "command" || !strings.Contains(record.Command, "event=forged") {
			t.Fatal("invalid journal record")
		}
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("audit journal is not private")
	}
}

func TestJournalRotationAndLegacyRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit")
	legacy := "ts=1700000000 event=session_close session=legacy user=root exit_code=7\n"
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(journalLimit); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := Append(path, Record{SessionID: "new", Event: "command", Command: "echo new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".1"); err != nil {
		t.Fatal("journal was not rotated")
	}
	// Put a legacy fixture at the tail of the rotated segment to exercise the
	// same bounded-tail path used by older installations.
	file, err = os.OpenFile(path+".1", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = file.WriteString("\n" + legacy)
	file.Close()
	records, err := ReadFiltered(path, 10, Filter{SessionID: "legacy"})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ExitCode == nil || *records[0].ExitCode != 7 {
		t.Fatalf("legacy/rotated record lost: %#v", records)
	}
}
