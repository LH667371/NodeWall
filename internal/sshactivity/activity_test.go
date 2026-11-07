package sshactivity

import "testing"

func TestParseLine(t *testing.T) {
	record, ok := ParseLine("ts=1700000000 event=command user=root source=192.0.2.5 source_port=4122 transfer=none action=executed scan= findings=0 command_b64=ZWNobyBoaQ== path_b64=")
	if !ok {
		t.Fatal("expected activity record")
	}
	if record.Event != "command" || record.Command != "echo hi" || record.SourcePort != 4122 {
		t.Fatalf("unexpected record: %#v", record)
	}
}

func TestParseLineRejectsInvalidTimestamp(t *testing.T) {
	if _, ok := ParseLine("event=command"); ok {
		t.Fatal("expected invalid activity line to be ignored")
	}
}
