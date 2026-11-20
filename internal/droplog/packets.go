package droplog

import (
	"path/filepath"
	"time"

	"nodewall/internal/models"
)

type packetAuditKey struct {
	iface, peer, reason string
	direction           models.PolicyDirection
	port                uint16
	traffic             models.FirewallTraffic
	dropped             bool
}

// RecordPacketAudit batches a bounded set of packet-header samples until the
// normal log flush. The iptables rule totals are recorded independently.
func (r *Recorder) RecordPacketAudit(sample models.DropLogRecord) {
	if sample.Traffic == nil || sample.Traffic.Evidence != models.FirewallPacketSample {
		return
	}
	r.packetMu.Lock()
	defer r.packetMu.Unlock()
	if !r.auditOn {
		return
	}
	if r.packets == nil {
		r.packets = make(map[packetAuditKey]models.DropLogRecord)
	}
	key := packetAuditKey{sample.Interface, sample.SourceIP, sample.Reason, sample.Direction, sample.Port, *sample.Traffic, sample.Drops != 0}
	previous, exists := r.packets[key]
	if !exists && len(r.packets) >= 256 {
		return
	}
	sample.Count += previous.Count
	sample.Drops += previous.Drops
	r.packets[key] = sample
}

func (r *Recorder) flushPackets(now time.Time) error {
	r.packetMu.Lock()
	defer r.packetMu.Unlock()
	path := filepath.Join(r.logDir, fileNameFor(now))
	for key, sample := range r.packets {
		if err := appendJSONL(path, sample); err != nil {
			return err
		}
		delete(r.packets, key)
	}
	return nil
}
