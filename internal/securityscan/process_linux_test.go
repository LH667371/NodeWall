//go:build linux

package securityscan

import (
	"fmt"
	"strings"
	"testing"
)

func syntheticProcStat(user, system uint64) []byte {
	// After the command name, field 1 is state; utime and stime are fields 14
	// and 15 in the full /proc/[pid]/stat record, indexes 11 and 12 here.
	fields := make([]string, 13)
	fields[0] = "S"
	fields[11] = fmt.Sprint(user)
	fields[12] = fmt.Sprint(system)
	return []byte("123 (worker thread) " + strings.Join(fields, " "))
}

func TestParseProcStatCPUTime(t *testing.T) {
	got, err := parseProcStatCPUTime(syntheticProcStat(17, 5), "/proc/123/task/123/stat")
	if err != nil {
		t.Fatalf("parseProcStatCPUTime returned error: %v", err)
	}
	if got != 22 {
		t.Fatalf("parseProcStatCPUTime = %d, want 22", got)
	}
}

func TestParseProcStatCPUTimeHandlesCommandParenthesis(t *testing.T) {
	data := syntheticProcStat(3, 9)
	data = []byte(strings.Replace(string(data), "(worker thread)", "(worker ) thread)", 1))
	got, err := parseProcStatCPUTime(data, "/proc/123/task/123/stat")
	if err != nil {
		t.Fatalf("parseProcStatCPUTime returned error: %v", err)
	}
	if got != 12 {
		t.Fatalf("parseProcStatCPUTime = %d, want 12", got)
	}
}

func TestParseProcStatCPUTimeRejectsShortRecord(t *testing.T) {
	if _, err := parseProcStatCPUTime([]byte("123 (worker) S 0"), "/proc/123/task/123/stat"); err == nil {
		t.Fatal("parseProcStatCPUTime accepted a short record")
	}
}

func TestSortedPIDDifferenceIsDeterministic(t *testing.T) {
	got := sortedPIDDifference(map[int]struct{}{9: {}, 2: {}, 7: {}}, map[int]struct{}{7: {}})
	want := []int{2, 9}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("sortedPIDDifference = %#v, want %#v", got, want)
	}
}

func TestKernelDeletedExecutableIsIgnored(t *testing.T) {
	if !isKernelHelper("bpfilter_umh", "", "/ (deleted)") {
		t.Fatal("expected bpfilter helper to be ignored")
	}
	if isKernelHelper("xmrig", "xmrig --algo", "/ (deleted)") {
		t.Fatal("did not expect a user process to be treated as a kernel helper")
	}
}
