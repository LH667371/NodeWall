package xdp

import (
	"encoding/base64"
	"strconv"
	"strings"

	"nodewall/internal/models"
)

// A dedicated NFLOG group keeps the sampler independent of other loggers.
// It is only used after the agent has successfully bound the group.
const firewallAuditGroup = 49173

func defaultDenyAuditRule(iface string, direction models.PolicyDirection, observeOnly bool) []string {
	verdict := "drop"
	if observeOnly {
		verdict = "observe"
	}
	prefix := strings.Join([]string{"nodewall", base64.RawURLEncoding.EncodeToString([]byte(iface)), string(direction), verdict}, ":")
	return []string{"-m", "limit", "--limit", "5/second", "--limit-burst", "10", "-j", "NFLOG", "--nflog-group", strconv.Itoa(firewallAuditGroup), "--nflog-prefix", prefix, "--nflog-threshold", "1"}
}
