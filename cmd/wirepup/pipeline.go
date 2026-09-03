package main

import (
	"context"
	"fmt"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/capture/afpacket"
	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
	"github.com/jeonghanlee/wirepup/internal/decode"
	"github.com/jeonghanlee/wirepup/internal/observation"
)

// sink receives the observations of one packet.
type sink func(obs []observation.Observation)

// openLive opens the AF_PACKET source for the selected interface.
func openLive(g *globalFlags, prog []bpf.Instruction) (capture.Source, error) {
	if g.iface == "" {
		return nil, fmt.Errorf("%w: an interface is required (-i)", errUsage)
	}
	src, err := afpacket.Open(afpacket.Options{Interface: g.iface, Promiscuous: !g.noPromisc, Filter: prog})
	if err != nil {
		return nil, err
	}
	return src, nil
}

// runSource drains a source through the decode pipeline into the sink
// until the context ends or the source is exhausted. It returns the
// decoder counters and the source counters.
func runSource(ctx context.Context, src capture.Source, s sink) (decode.Stats, capture.Stats, error) {
	if ctx.Err() != nil {
		return decode.Stats{}, src.Stats(), nil
	}
	dec := decode.New(src.Name())
	packets, errc := src.Packets(ctx)
	for pkt := range packets {
		s(dec.Decode(pkt))
	}
	var err error
	if e, ok := <-errc; ok && e != nil {
		err = fmt.Errorf("%w: %v", errCapture, e)
	}
	return dec.Stats(), src.Stats(), err
}

// reportStats prints the closing counters unless quiet.
func reportStats(e *env, g *globalFlags, ds decode.Stats, cs capture.Stats) {
	if g.quiet {
		return
	}
	fmt.Fprintf(e.stderr, "%d packets processed (%d decoded, %d malformed), %d received by kernel, %d dropped\n",
		ds.Packets, ds.Decoded, ds.Malformed, cs.Received, cs.Dropped)
}

// withTimeout applies the --timeout flag.
func withTimeout(ctx context.Context, g *globalFlags) (context.Context, context.CancelFunc) {
	if g.timeout > 0 {
		return context.WithTimeout(ctx, g.timeout)
	}
	return context.WithCancel(ctx)
}
