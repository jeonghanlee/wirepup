//go:build !linux

package active

import (
	"context"
	"errors"
	"net/netip"
)

var errUnsupported = errors.New("active: implemented for Linux only")

// ErrPrivilege is unused off Linux.
var ErrPrivilege = errors.New("active: transmitting requires CAP_NET_RAW")

// ProbeResult is the outcome of a probe sequence.
type ProbeResult struct {
	Plan     Plan
	Sent     int
	Conflict *Reply
}

// SweepResult is the outcome of a sweep.
type SweepResult struct {
	Plan    Plan
	Sent    int
	Replies []Reply
}

// Probe is unsupported off Linux.
func Probe(ctx context.Context, iface string, target netip.Addr) (ProbeResult, error) {
	return ProbeResult{}, errUnsupported
}

// Sweep is unsupported off Linux.
func Sweep(ctx context.Context, iface string, prefix netip.Prefix) (SweepResult, error) {
	return SweepResult{}, errUnsupported
}
