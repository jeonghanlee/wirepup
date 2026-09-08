package networkcfg

import (
	"context"
	"time"
)

// waitContext bounds a retry without a worker goroutine or a blocking lock.
func waitContext(ctx context.Context) error {
	timer := time.NewTimer(waitInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
