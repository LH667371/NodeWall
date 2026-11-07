package store

import (
	"context"
	"errors"
	"maps"
	"time"

	"nodewall/internal/models"
)

type PolicyRecovery struct {
	NodeID          string                            `json:"node_id"`
	Interface       string                            `json:"interface"`
	Previous        *models.InterfacePolicy           `json:"previous,omitempty"`
	StartedAt       time.Time                         `json:"started_at"`
	TrialExpiresAt  time.Time                         `json:"trial_expires_at,omitempty"`
	TrialPublishIDs map[models.PolicyDirection]string `json:"trial_publish_ids,omitempty"`
}

// BeginPolicyUpdate durably records the previous policy before a remote map
// changes. An interrupted manager must resolve this record before another edit.
func (s *Store) BeginPolicyUpdate(_ context.Context, nodeID, iface string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := policyKey(nodeID, iface)
	if _, exists := s.recoveries[key]; exists {
		return errors.New("previous policy update is still recovering; retry after node connectivity is restored")
	}
	recovery := PolicyRecovery{NodeID: nodeID, Interface: iface, StartedAt: time.Now().UTC()}
	if previous, exists := s.policies[key]; exists {
		recovery.Previous = &previous
	}
	s.recoveries[key] = recovery
	if err := s.saveLocked(); err != nil {
		delete(s.recoveries, key)
		return err
	}
	return nil
}

func (s *Store) PendingPolicyUpdates() []PolicyRecovery {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]PolicyRecovery, 0, len(s.recoveries))
	for _, recovery := range s.recoveries {
		result = append(result, recovery)
	}
	return result
}

func (s *Store) PendingPolicyUpdate(nodeID, iface string) (PolicyRecovery, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	recovery, exists := s.recoveries[policyKey(nodeID, iface)]
	if recovery.TrialPublishIDs != nil {
		recovery.TrialPublishIDs = maps.Clone(recovery.TrialPublishIDs)
	}
	return recovery, exists
}

// MarkPolicyTrial makes an in-flight policy update intentional until the
// agent's safety timer expires. The durable previous policy remains available
// so a manager restart can still finish the rollback safely.
func (s *Store) MarkPolicyTrial(_ context.Context, nodeID, iface string, expiresAt time.Time, publishIDs map[models.PolicyDirection]string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := policyKey(nodeID, iface)
	recovery, exists := s.recoveries[key]
	if !exists {
		return errors.New("policy update recovery record not found")
	}
	previous := recovery
	recovery.TrialExpiresAt = expiresAt.UTC()
	recovery.TrialPublishIDs = maps.Clone(publishIDs)
	s.recoveries[key] = recovery
	if err := s.saveLocked(); err != nil {
		s.recoveries[key] = previous
		return err
	}
	return nil
}

func (s *Store) FinishPolicyUpdate(_ context.Context, nodeID, iface string, restore bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := policyKey(nodeID, iface)
	recovery, exists := s.recoveries[key]
	if !exists {
		return nil
	}
	current, hadCurrent := s.policies[key]
	if restore {
		if recovery.Previous == nil {
			delete(s.policies, key)
		} else {
			s.policies[key] = *recovery.Previous
		}
	}
	delete(s.recoveries, key)
	if err := s.saveLocked(); err != nil {
		s.recoveries[key] = recovery
		if hadCurrent {
			s.policies[key] = current
		} else {
			delete(s.policies, key)
		}
		return err
	}
	return nil
}
