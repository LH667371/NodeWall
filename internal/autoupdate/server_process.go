package autoupdate

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// managementServerOutdated detects an interrupted update in which the agent
// and version marker are already current but the local web process still has
// an older executable inode open. An agent-only host is not treated as stale.
func managementServerOutdated(procRoot, installDir string) bool {
	binDir := filepath.Join(installDir, "bin")
	installed, err := os.Stat(filepath.Join(binDir, "nodewall"))
	if err != nil {
		return false
	}
	entries, err := os.ReadDir(procRoot)
	if err != nil {
		return false
	}
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || !entry.IsDir() {
			continue
		}
		procDir := filepath.Join(procRoot, entry.Name())
		command, err := os.ReadFile(filepath.Join(procDir, "cmdline"))
		if err != nil {
			continue
		}
		args := strings.Split(string(command), "\x00")
		if len(args) < 2 || args[1] != "server" {
			continue
		}
		exe := filepath.Join(procDir, "exe")
		target, err := os.Readlink(exe)
		if err != nil {
			continue
		}
		target = strings.TrimSuffix(target, " (deleted)")
		if filepath.Dir(target) != binDir || !strings.HasPrefix(filepath.Base(target), "nodewall") {
			continue
		}
		running, err := os.Stat(exe)
		if err == nil && !os.SameFile(installed, running) {
			return true
		}
	}
	return false
}
