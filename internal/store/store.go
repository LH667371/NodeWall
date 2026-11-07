package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nodewall/internal/models"
)

var errPolicyNotFound = errors.New("policy not found")
var ErrNodeNotFound = errors.New("node not found")

type Store struct {
	mu         sync.RWMutex
	nodes      map[string]models.Node
	policies   map[string]models.InterfacePolicy
	recoveries map[string]PolicyRecovery
	history    map[string][]models.PublishRecord
	path       string
}

func New() *Store {
	return &Store{
		nodes:      make(map[string]models.Node),
		policies:   make(map[string]models.InterfacePolicy),
		recoveries: make(map[string]PolicyRecovery),
		history:    make(map[string][]models.PublishRecord),
	}
}

func NewPersistent(path string) (*Store, error) {
	st := New()
	st.path = path
	if err := st.load(); err != nil {
		return nil, err
	}
	return st, nil
}

func policyKey(nodeID, iface string) string {
	return nodeID + ":" + iface
}

func (s *Store) UpsertNode(_ context.Context, node models.Node) {
	_ = s.UpsertNodeChecked(context.Background(), node)
}

func (s *Store) UpsertNodeChecked(_ context.Context, node models.Node) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	previous, existed := s.nodes[node.ID]

	if existing, ok := s.nodes[node.ID]; ok {
		if existing.NameCustomized {
			node.Name = existing.Name
			node.NameCustomized = true
		} else if strings.TrimSpace(node.Name) == "" {
			node.Name = existing.Name
		}
		if strings.TrimSpace(node.AgentURL) == "" {
			node.AgentURL = existing.AgentURL
		}
		if strings.TrimSpace(node.AdvertiseIP) == "" {
			node.AdvertiseIP = existing.AdvertiseIP
		}
		if strings.TrimSpace(node.AgentHTTPAddr) == "" {
			node.AgentHTTPAddr = existing.AgentHTTPAddr
		}
		if node.SSH == nil {
			node.SSH = existing.SSH
		}
		if node.LastSeenAt.IsZero() {
			node.LastSeenAt = existing.LastSeenAt
		}
	}

	s.nodes[node.ID] = node
	if err := s.saveLocked(); err != nil {
		if existed {
			s.nodes[node.ID] = previous
		} else {
			delete(s.nodes, node.ID)
		}
		return err
	}
	return nil
}

func (s *Store) UpdateNodeName(_ context.Context, nodeID, name string) (models.Node, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeID = strings.TrimSpace(nodeID)
	name = strings.TrimSpace(name)
	if nodeID == "" || name == "" {
		return models.Node{}, errors.New("node id and name are required")
	}
	node, ok := s.nodes[nodeID]
	if !ok {
		return models.Node{}, ErrNodeNotFound
	}
	node.Name = name
	node.NameCustomized = true
	s.nodes[nodeID] = node
	if err := s.saveLocked(); err != nil {
		return models.Node{}, err
	}
	return node, nil
}

func (s *Store) DeleteNode(_ context.Context, nodeID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	nodeID = strings.TrimSpace(nodeID)
	if nodeID == "" {
		return false
	}
	if _, ok := s.nodes[nodeID]; !ok {
		return false
	}
	delete(s.nodes, nodeID)
	for key, item := range s.recoveries {
		if item.NodeID == nodeID {
			delete(s.recoveries, key)
		}
	}
	for key := range s.policies {
		if strings.HasPrefix(key, nodeID+":") {
			delete(s.policies, key)
		}
	}
	for key := range s.history {
		if strings.HasPrefix(key, nodeID+":") {
			delete(s.history, key)
		}
	}
	_ = s.saveLocked()
	return true
}

func (s *Store) ListNodes(_ context.Context) []models.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]models.Node, 0, len(s.nodes))
	for _, node := range s.nodes {
		out = append(out, node)
	}
	sort.SliceStable(out, func(i, j int) bool {
		leftName := strings.ToLower(strings.TrimSpace(out[i].Name))
		rightName := strings.ToLower(strings.TrimSpace(out[j].Name))
		if leftName == "" {
			leftName = strings.ToLower(strings.TrimSpace(out[i].ID))
		}
		if rightName == "" {
			rightName = strings.ToLower(strings.TrimSpace(out[j].ID))
		}
		if leftName == rightName {
			return strings.ToLower(strings.TrimSpace(out[i].ID)) < strings.ToLower(strings.TrimSpace(out[j].ID))
		}
		return leftName < rightName
	})
	return out
}

func (s *Store) PutPolicy(_ context.Context, policy models.InterfacePolicy) models.InterfacePolicy {
	updated, _ := s.PutPolicyChecked(context.Background(), policy)
	return updated
}

// PutPolicyChecked keeps the last durable policy visible if the disk write
// fails, allowing callers to roll the dataplane back instead of claiming success.
func (s *Store) PutPolicyChecked(_ context.Context, policy models.InterfacePolicy) (models.InterfacePolicy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	policy.UpdatedAt = time.Now().UTC()
	key := policyKey(policy.NodeID, policy.Interface)
	previous, existed := s.policies[key]
	s.policies[key] = policy
	if err := s.saveLocked(); err != nil {
		if existed {
			s.policies[key] = previous
		} else {
			delete(s.policies, key)
		}
		return previous, err
	}
	return policy, nil
}

func (s *Store) GetPolicy(_ context.Context, nodeID, iface string) (models.InterfacePolicy, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policy, ok := s.policies[policyKey(nodeID, iface)]
	if !ok {
		return models.InterfacePolicy{}, errPolicyNotFound
	}

	return policy, nil
}

func (s *Store) AddPublishRecord(_ context.Context, record models.PublishRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := policyKey(record.NodeID, record.Interface)
	s.history[key] = append([]models.PublishRecord{record}, s.history[key]...)

	policy, ok := s.policies[key]
	if ok {
		next := record
		policy.PendingPublish = &next
		if record.Direction == models.DirectionEgress {
			policy.Egress.PendingPublish = &next
		} else {
			policy.Ingress.PendingPublish = &next
		}
		s.policies[key] = policy
	}
	_ = s.saveLocked()
}

func (s *Store) UpdatePublishStatus(_ context.Context, nodeID, iface, publishID string, status models.PublishStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := policyKey(nodeID, iface)
	records := s.history[key]
	for i := range records {
		if records[i].PublishID == publishID {
			records[i].Status = status
			if status == models.PublishConfirmed {
				now := time.Now().UTC()
				records[i].ConfirmedAt = &now
			}
			break
		}
	}
	s.history[key] = records

	if policy, ok := s.policies[key]; ok {
		if policy.PendingPublish != nil && policy.PendingPublish.PublishID == publishID {
			policy.PendingPublish.Status = status
			if status != models.PublishPendingConfirm {
				policy.PendingPublish = nil
			}
		}
		if policy.Ingress.PendingPublish != nil && policy.Ingress.PendingPublish.PublishID == publishID {
			policy.Ingress.PendingPublish.Status = status
			if status != models.PublishPendingConfirm {
				policy.Ingress.PendingPublish = nil
			}
		}
		if policy.Egress.PendingPublish != nil && policy.Egress.PendingPublish.PublishID == publishID {
			policy.Egress.PendingPublish.Status = status
			if status != models.PublishPendingConfirm {
				policy.Egress.PendingPublish = nil
			}
		}
		s.policies[key] = policy
	}
	_ = s.saveLocked()
}

func (s *Store) History(_ context.Context, nodeID, iface string) []models.PublishRecord {
	s.mu.RLock()
	defer s.mu.RUnlock()

	records := s.history[policyKey(nodeID, iface)]
	out := make([]models.PublishRecord, len(records))
	copy(out, records)
	return out
}

func (s *Store) ListPolicyInterfaces(_ context.Context, nodeID string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	seen := map[string]struct{}{}
	out := make([]string, 0)
	for _, policy := range s.policies {
		if policy.NodeID != nodeID {
			continue
		}
		iface := strings.TrimSpace(policy.Interface)
		if iface == "" {
			continue
		}
		if _, ok := seen[iface]; ok {
			continue
		}
		seen[iface] = struct{}{}
		out = append(out, iface)
	}
	sort.Strings(out)
	return out
}

type persistedState struct {
	Recoveries map[string]PolicyRecovery         `json:"policy_recoveries,omitempty"`
	Nodes      map[string]models.Node            `json:"nodes"`
	Policies   map[string]models.InterfacePolicy `json:"policies"`
	History    map[string][]models.PublishRecord `json:"history"`
}

func (s *Store) load() error {
	if s.path == "" {
		return nil
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if state.Nodes != nil {
		s.nodes = state.Nodes
	}
	if state.Policies != nil {
		s.policies = state.Policies
	}
	if state.History != nil {
		s.history = state.History
	}
	if state.Recoveries != nil {
		s.recoveries = state.Recoveries
	}
	return nil
}

func (s *Store) saveLocked() error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(persistedState{
		Recoveries: s.recoveries,
		Nodes:      s.nodes,
		Policies:   s.policies,
		History:    s.history,
	}, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), filepath.Base(s.path)+".tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(0o644); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return err
	}
	cleanup = false
	return nil
}
