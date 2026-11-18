package xdp

import (
	"fmt"
	"sort"

	"nodewall/internal/models"
)

// The native egress hook keeps its own counters because the ingress XDP hook
// and TC egress hook observe different packet directions. Combining them would
// make the UI report an apparently healthy ingress policy while hiding outbound
// drops.
func (m *Manager) ReadDirectionStats(ifaceName string, direction models.PolicyDirection) (models.InterfaceStats, error) {
	if direction != models.DirectionEgress {
		return models.InterfaceStats{}, fmt.Errorf("native directional stats support only egress")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return models.InterfaceStats{}, errNotAttached
	}
	statsMap := state.collection.Maps["egress_stats_map"]
	if statsMap == nil {
		return models.InterfaceStats{}, fmt.Errorf("egress_stats_map not loaded")
	}
	var value statsValue
	if err := statsMap.Lookup(uint32(0), &value); err != nil {
		return models.InterfaceStats{}, fmt.Errorf("lookup egress stats: %w", err)
	}
	return models.InterfaceStats{Direction: direction, Passed: value.Passed, Dropped: value.Dropped}, nil
}

func (m *Manager) ReadDirectionSourceStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.SourceStat, error) {
	if direction != models.DirectionEgress {
		return nil, fmt.Errorf("native directional stats support only egress")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}
	statsMap := state.collection.Maps["egress_source_stats"]
	if statsMap == nil {
		return nil, fmt.Errorf("egress_source_stats not loaded")
	}
	var (
		key   uint32
		value sourceStatsValue
		out   []models.SourceStat
	)
	iter := statsMap.Iterate()
	for iter.Next(&key, &value) {
		total := value.Passed + value.Dropped
		if total == 0 {
			continue
		}
		out = append(out, models.SourceStat{
			SourceIP:  sourceIPFromUint32(key),
			Passed:    value.Passed,
			Dropped:   value.Dropped,
			Total:     total,
			DropRatio: float64(value.Dropped) / float64(total),
			Risk:      classifyRisk(value.Passed, value.Dropped),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dropped == out[j].Dropped {
			return out[i].Passed > out[j].Passed
		}
		return out[i].Dropped > out[j].Dropped
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) ReadDirectionPortStats(ifaceName string, direction models.PolicyDirection, limit int) ([]models.PortStat, error) {
	if direction != models.DirectionEgress {
		return nil, fmt.Errorf("native directional stats support only egress")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}
	statsMap := state.collection.Maps["egress_port_stats"]
	if statsMap == nil {
		return nil, fmt.Errorf("egress_port_stats not loaded")
	}
	var (
		key   uint16
		value portStatsValue
		out   []models.PortStat
	)
	iter := statsMap.Iterate()
	for iter.Next(&key, &value) {
		total := value.Passed + value.Dropped
		if total == 0 {
			continue
		}
		out = append(out, models.PortStat{
			Port:    key,
			Passed:  value.Passed,
			Dropped: value.Dropped,
			Total:   total,
			Risk:    classifyRisk(value.Passed, value.Dropped),
		})
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dropped == out[j].Dropped {
			return out[i].Passed > out[j].Passed
		}
		return out[i].Dropped > out[j].Dropped
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Manager) ReadDirectionDropLogs(ifaceName string, direction models.PolicyDirection, limit int) ([]models.InterceptLogEntry, error) {
	if direction != models.DirectionEgress {
		return nil, fmt.Errorf("native directional stats support only egress")
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	state, ok := m.states[ifaceName]
	if !ok || state.collection == nil {
		return nil, errNotAttached
	}
	logMap := state.collection.Maps["egress_drop_logs"]
	if logMap == nil {
		return nil, fmt.Errorf("egress_drop_logs not loaded")
	}
	var (
		key   dropLogKey
		value dropLogValue
		out   []models.InterceptLogEntry
	)
	iter := logMap.Iterate()
	for iter.Next(&key, &value) {
		if value.Drops == 0 {
			continue
		}
		out = append(out, interceptLogFromMap(key, value, direction))
	}
	if err := iter.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Drops == out[j].Drops {
			if out[i].SourceIP == out[j].SourceIP {
				return out[i].Port > out[j].Port
			}
			return out[i].SourceIP < out[j].SourceIP
		}
		return out[i].Drops > out[j].Drops
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

var _ DirectionalStats = (*Manager)(nil)
