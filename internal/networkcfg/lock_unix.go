//go:build linux || darwin

package networkcfg

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// lock uses a persistent inode shared by all session-file writers. Closing
// the descriptor releases flock, including after process death; unlinking
// the lock file would let another writer lock a different inode concurrently.
func (m *Manager) lock(ctx context.Context) (*os.File, error) {
	ctx, cancel := context.WithTimeout(ctx, lockTimeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(m.Path), sessionDirMode); err != nil {
		return nil, fmt.Errorf("networkcfg: lock: %w", err)
	}
	f, err := os.OpenFile(m.Path+".lock", os.O_CREATE|os.O_RDWR, sessionFileMode)
	if err != nil {
		return nil, fmt.Errorf("networkcfg: lock: %w", err)
	}
	for {
		if err = ctx.Err(); err != nil {
			break
		}
		err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return f, nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EINTR) {
			break
		}
		if err = waitContext(ctx); err != nil {
			break
		}
	}
	f.Close()
	return nil, fmt.Errorf("networkcfg: lock: %w", err)
}
