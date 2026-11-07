package service

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
)

// RecoverPendingPolicies resolves transactions left by a manager crash. It
// reads each record again under the same per-interface lock used for updates,
// so a background check cannot roll back a live, successfully completed edit.
func (s *PolicyService) RecoverPendingPolicies(ctx context.Context) error {
	var failures []error
	for _, item := range s.store.PendingPolicyUpdates() {
		lock, _ := s.applyLocks.LoadOrStore(item.NodeID+"/"+item.Interface, &sync.Mutex{})
		lock.(*sync.Mutex).Lock()
		func() {
			defer lock.(*sync.Mutex).Unlock()
			recovery, exists := s.store.PendingPolicyUpdate(item.NodeID, item.Interface)
			if !exists {
				return
			}
			// An intentional page-triggered trial is owned by the agent's
			// safety timer. Do not treat it as a manager crash and roll it back
			// on the next ten-second recovery tick.
			if recovery.TrialExpiresAt.After(time.Now()) {
				return
			}
			node, found := FindNode(s.ListNodes(ctx), recovery.NodeID)
			if !found {
				failures = append(failures, fmt.Errorf("recover policy: node %s is missing", recovery.NodeID))
				return
			}
			attempt, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			if recovery.Previous == nil {
				if err := s.postJSON(attempt, node.AgentURL+"/interfaces/"+recovery.Interface+"/detach", map[string]any{}, nil); err != nil {
					failures = append(failures, err)
					return
				}
			} else if !recovery.TrialExpiresAt.IsZero() {
				for _, direction := range []models.PolicyDirection{models.DirectionEgress, models.DirectionIngress} {
					publishID := recovery.TrialPublishIDs[direction]
					if publishID == "" {
						continue
					}
					err := s.postJSON(attempt, node.AgentURL+"/interfaces/"+recovery.Interface+"/rollback", map[string]any{
						"publish_id": publishID, "direction": direction,
					}, nil)
					if err != nil && !strings.Contains(err.Error(), "404") {
						failures = append(failures, err)
						return
					}
				}
				attached, err := s.agentInterfaceAttached(attempt, node, recovery.Interface)
				if err != nil {
					failures = append(failures, err)
					return
				}
				// A timed-out trial is normally already detached by the agent's
				// own snapshot restore. Reapplying an observe-only previous policy
				// would silently reattach it and defeat the requested closed state.
				if attached {
					for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
						if err := s.applyPolicy(attempt, node, *recovery.Previous, direction); err != nil {
							failures = append(failures, err)
							return
						}
					}
				}
			} else {
				for _, direction := range []models.PolicyDirection{models.DirectionIngress, models.DirectionEgress} {
					if err := s.applyPolicy(attempt, node, *recovery.Previous, direction); err != nil {
						failures = append(failures, err)
						return
					}
				}
			}
			if err := s.store.FinishPolicyUpdate(attempt, recovery.NodeID, recovery.Interface, true); err != nil {
				failures = append(failures, err)
			}
		}()
	}
	return errors.Join(failures...)
}

func (s *PolicyService) RunPolicyRecovery(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		if err := s.RecoverPendingPolicies(ctx); err != nil {
			log.Printf("warning: policy recovery pending: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
