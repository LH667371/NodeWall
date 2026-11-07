package xdp

import (
	"fmt"

	"nodewall/internal/models"
)

// ApplyDirectionPolicy makes the native backend's egress boundary explicit.
// The tc program records reply flows, but it is not an egress firewall. An
// observe-only policy is safe to accept; an enforced one must use iptables
// compatibility mode until a tc egress enforcement program is introduced.
func (m *Manager) ApplyDirectionPolicy(_ string, direction models.PolicyDirection, policy DirectionPolicy) error {
	if direction != models.DirectionEgress {
		return nil
	}
	if policy.ObserveOnly || !policy.PolicyEnforced {
		return nil
	}
	return fmt.Errorf("native xdp dataplane cannot enforce egress policy; use NODEWALL_DATAPLANE=iptables")
}

// MockManager accepts both directions so API and rollback tests can exercise
// the same control flow without requiring a Linux firewall.
func (m *MockManager) ApplyDirectionPolicy(_ string, _ models.PolicyDirection, _ DirectionPolicy) error {
	return nil
}
