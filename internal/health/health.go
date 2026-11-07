package health

import (
	"context"
	"fmt"
	"time"

	"nodewall/internal/models"
	"nodewall/internal/xdp"
)

type Probe struct {
	NodeID string
	XDP    xdp.Dataplane
}

func (p Probe) Check(_ context.Context) models.HealthStatus {
	now := time.Now().UTC()
	status := models.HealthStatus{
		NodeID:      p.NodeID,
		Status:      "ok",
		AgentOK:     true,
		LastCheckAt: now,
	}

	interfaces := p.XDP.Interfaces()
	if len(interfaces) == 0 {
		// An empty runtime list means the agent is alive, but no dataplane has
		// been loaded yet. Reporting "ok" here is dangerous because the UI
		// would present an unprotected host as healthy. Include physical
		// interfaces when discovery is available so the operator can see what
		// still needs to be attached.
		status.Status = "degraded"
		if inventory, err := p.XDP.DiscoverInterfaces(); err == nil {
			for _, item := range inventory.Interfaces {
				if !item.IsPhysical || item.IsLoopback {
					continue
				}
				status.Interfaces = append(status.Interfaces, models.InterfaceHealth{
					Interface:   item.Name,
					LastCheckAt: now,
					LastError:   "dataplane is not attached; host traffic is not being enforced",
				})
			}
		}
		return status
	}

	for _, iface := range interfaces {
		runtime, runtimeErr := p.XDP.Runtime(iface)
		health := models.InterfaceHealth{
			Interface:   iface,
			XDPAttached: runtime.Attached,
			MapOK:       runtime.ProgramLoaded,
			StatsOK:     false,
			LastCheckAt: now,
		}
		if runtimeErr != nil {
			health.MapOK = false
			health.LastError = runtimeErr.Error()
			status.Status = "degraded"
			status.Interfaces = append(status.Interfaces, health)
			continue
		}

		cfg, err := p.XDP.ReadConfig(iface)
		if err != nil {
			health.MapOK = false
			health.LastError = err.Error()
			status.Status = "degraded"
		} else {
			health.ObserveOnly = cfg.ObserveOnly
			health.RateLimitEnforced = cfg.RateLimitEnabled
			// Observe-only rules are intentionally loaded for visibility but do
			// not block traffic. Expose that distinction to the manager so the UI
			// cannot report a trial or a staged policy as enforced.
			health.PolicyEnforced = cfg.PolicyEnforced && !cfg.ObserveOnly
			health.EgressPolicyEnforced = cfg.EgressPolicyEnforced
			// Runtime exposes ingress rule maps. Egress currently uses a TC
			// tracker for reply-flow discovery, so there is no equivalent
			// egress rule set here from which to infer an expected gate value.
			health.EnforcementOK = expectedPolicyEnforced(runtime) == cfg.PolicyEnforced &&
				(len(runtime.RateLimitRules) > 0) == cfg.RateLimitEnabled
			if !health.EnforcementOK {
				health.LastError = fmt.Sprintf(
					"policy enforcement mismatch: ingress expected=%t actual=%t, rate limit expected=%t actual=%t",
					expectedPolicyEnforced(runtime),
					cfg.PolicyEnforced,
					len(runtime.RateLimitRules) > 0,
					cfg.RateLimitEnabled,
				)
				status.Status = "degraded"
			}
		}

		if _, err := p.XDP.ReadStats(iface); err == nil {
			health.StatsOK = true
		} else {
			health.LastError = err.Error()
			status.Status = "degraded"
		}

		status.Interfaces = append(status.Interfaces, health)
	}

	return status
}

func expectedPolicyEnforced(runtime xdp.Runtime) bool {
	return hasRules(runtime.BypassCIDRs, runtime.BlockedCIDRs, runtime.ICMPAllowCIDRs, runtime.ICMPBlockedCIDRs, runtime.Allowlist, runtime.PublicPorts, runtime.DeniedPorts, runtime.AllowedPorts)
}

func hasRules(bypass, blocked, icmpAllow, icmpBlocked, allowlist []string, publicPorts, deniedPorts, allowedPorts []uint16) bool {
	return len(bypass) > 0 || len(blocked) > 0 || len(icmpAllow) > 0 || len(icmpBlocked) > 0 ||
		len(allowlist) > 0 || len(publicPorts) > 0 || len(deniedPorts) > 0 || len(allowedPorts) > 0
}
