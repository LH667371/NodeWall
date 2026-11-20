//go:build !linux

package xdp

import (
	"context"
	"errors"

	"nodewall/internal/models"
)

func (m *IPTablesManager) StartPacketAudit(context.Context, func(models.DropLogRecord)) error {
	return errors.New("packet audit requires Linux")
}
