//go:build !linux

package afpacket

import (
	"context"
	"errors"

	"github.com/jeonghanlee/wirepup/internal/capture"
)

var errUnsupported = errors.New("live capture is implemented for Linux only")

// Source is a placeholder on platforms without AF_PACKET.
type Source struct{}

// Open always fails on non-Linux platforms.
func Open(opts Options) (*Source, error) { return nil, errUnsupported }

// Name returns an empty name.
func (s *Source) Name() string { return "" }

// Packets yields nothing.
func (s *Source) Packets(ctx context.Context) (<-chan capture.Packet, <-chan error) {
	out := make(chan capture.Packet)
	errc := make(chan error, 1)
	errc <- errUnsupported
	close(out)
	close(errc)
	return out, errc
}

// Stats reports zero counters.
func (s *Source) Stats() capture.Stats { return capture.Stats{} }

// Close does nothing.
func (s *Source) Close() error { return nil }
