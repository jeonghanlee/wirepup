//go:build !linux && !darwin

package networkcfg

import (
	"context"
	"errors"
	"os"
)

func (m *Manager) lock(ctx context.Context) (*os.File, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, errors.New("networkcfg: session locking is unsupported on this platform")
}
