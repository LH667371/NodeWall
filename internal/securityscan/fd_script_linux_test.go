//go:build linux

package securityscan

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestFDScriptScanDoesNotConsumePipe(t *testing.T) {
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer readEnd.Close()
	defer writeEnd.Close()
	cmd := exec.Command("/bin/bash", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{readEnd}
	var output bytes.Buffer
	cmd.Stdout = &output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	procCmdline := filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "cmdline")
	ready := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		if fd, ok := scriptFDFromArgs(strings.Split(readProcTextLimited(procCmdline, maxProcMetadataBytes), "\x00")); ok && fd == 3 {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("test shell did not open the pipe descriptor")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	findings, err := collectFDScriptFindings(ctx, New(), 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, finding := range findings {
		if finding.PID == cmd.Process.Pid {
			t.Fatalf("pipe was treated as a readable regular script: %#v", finding)
		}
	}
	if _, err := writeEnd.WriteString("printf pipe-preserved\n"); err != nil {
		t.Fatal(err)
	}
	_ = writeEnd.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if output.String() != "pipe-preserved" {
		t.Fatalf("shell received different pipe data: %q", output.String())
	}
}

func TestFDScriptRequiresDirectShellArgumentAndCombinedEvidence(t *testing.T) {
	if _, ok := scriptFDFromArgs([]string{"bash", "-c", "echo /dev/fd/3"}); ok {
		t.Fatal("a descriptor mentioned inside a command is not a script argument")
	}
	if isMaliciousFDScript([]byte("# graphic_card.ko\n# journalctl --vacuum-time=1s\n")) {
		t.Fatal("comment-only examples must not trigger containment")
	}
	if isMaliciousFDScript([]byte("printf graphic_card.ko\n")) {
		t.Fatal("one indicator must not trigger containment")
	}
}

func TestFDScriptUsesSignatureAndPreservesVerifiedSample(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sample.sh")
	script := []byte("#!/bin/bash\n# harmless signature fixture\nsleep 30 &\nwait\n")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command("/bin/bash", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})
	socket := fakeClamAV(t, func(content string) string {
		if content == string(script) {
			return "stream: Mock.FDScript FOUND"
		}
		return "stream: OK"
	})
	scanner := New()
	scanner.signatures = newClamAVEngine(context.Background(), socket)
	var found Finding
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
		findings, err := collectFDScriptFindings(context.Background(), scanner, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, item := range findings {
			if item.PID == cmd.Process.Pid && item.Rule == "clamav-fd-script" {
				found = item
			}
		}
		if found.ID != "" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if found.ID == "" || !strings.Contains(found.Detail, "Mock.FDScript") {
		t.Fatalf("signature match missing: %#v", found)
	}
	if sample, err := ReadFDScriptSample(found); err != nil || string(sample) != string(script) {
		t.Fatalf("verified sample: %q %v", sample, err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFDScriptSample(found); err == nil {
		t.Fatal("a changed descriptor was accepted")
	}
}

func TestFDScriptFindsRegularDescriptorAndRejectsChanges(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test-script.sh")
	script := []byte("#!/bin/bash\ninsmod() { :; }\njournalctl() { :; }\ninsmod /tmp/a/renamed-driver.ko\njournalctl --vacuum-time=1s\nsleep 30 &\nwait\n")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	cmd := exec.Command("/bin/bash", "/dev/fd/3")
	cmd.ExtraFiles = []*os.File{file}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})
	var found Finding
	var source Finding
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		findings, scanErr := collectFDScriptFindings(context.Background(), New(), 100)
		if scanErr != nil {
			t.Fatal(scanErr)
		}
		for _, item := range findings {
			if item.Source == "fd-script" && item.PID == cmd.Process.Pid {
				found = item
			}
			if item.Source == "file" && item.Path == path {
				source = item
			}
		}
		if found.ID != "" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if found.ID == "" {
		t.Fatal("running descriptor-backed script was not detected")
	}
	if source.ID == "" || !source.Quarantinable || source.RelatedTo != found.ID || source.SHA256 != found.SHA256 {
		t.Fatalf("on-disk script was not linked for isolation: %#v", source)
	}
	if sample, err := ReadFDScriptSample(found); err != nil || string(sample) != string(script) {
		t.Fatalf("sample verification: %q %v", sample, err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadFDScriptSample(found); err == nil {
		t.Fatal("changed descriptor content was accepted")
	}
}

func TestQuickScanFindsOpenPathScriptWithoutHighCPU(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ordinary-name.sh")
	script := []byte("#!/bin/bash\ninsmod() { :; }\njournalctl() { :; }\ninsmod /dev/shm/other.ko\njournalctl --vacuum-time=1s\nsleep 30 &\nwait\n")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		findings, err := collectFDScriptFindings(context.Background(), New(), 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, finding := range findings {
			if finding.PID == cmd.Process.Pid && finding.Source == "fd-script" {
				if finding.ScriptArgument != path || finding.ScriptFDTarget != path {
					t.Fatalf("script provenance missing: %#v", finding)
				}
				if _, err := ReadFDScriptSample(finding); err != nil {
					t.Fatalf("script identity could not be verified: %v", err)
				}
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("open pathname script was not linked to its interpreter")
}

func TestQuickScanPublishesRunningScriptBeforeLaterPhases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "probe.sh")
	script := []byte("#!/bin/bash\ninsmod() { :; }\njournalctl() { :; }\ninsmod /tmp/another.ko\njournalctl --vacuum-time=1s\nsleep 30 &\nwait\n")
	if err := os.WriteFile(path, script, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/bash", path)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); _, _ = cmd.Process.Wait() })
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		args := strings.Split(readProcTextLimited(filepath.Join("/proc", strconv.Itoa(cmd.Process.Pid), "cmdline"), maxProcMetadataBytes), "\x00")
		if _, _, ok := shellScriptDescriptor(cmd.Process.Pid, args); ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	published := false
	_, _ = New().ScanProcesses(ctx, func(progress Progress) {
		for _, finding := range progress.ProcessFindings {
			if finding.Source == "fd-script" && finding.PID == cmd.Process.Pid {
				published = true
				cancel()
				return
			}
		}
	})
	if !published {
		t.Fatal("running script was not published before the remaining scan phases")
	}
}
