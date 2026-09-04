package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/capture/afpacket"
	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
	"github.com/jeonghanlee/wirepup/internal/capture/pcapfile"
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

// openSource picks the capture file when --pcap is given and the live
// interface otherwise. Kernel filters apply to live capture only; the
// display filter covers files.
func openSource(g *globalFlags, prog []bpf.Instruction) (capture.Source, error) {
	if g.pcap != "" {
		if g.iface != "" {
			return nil, fmt.Errorf("%w: use either --pcap or -i, not both", errUsage)
		}
		return pcapfile.Open(g.pcap)
	}
	return openLive(g, prog)
}

// openSources opens every comma-separated interface or capture file so
// that diagnosis can compare sources. Kernel filters apply to live
// sources only.
func openSources(g *globalFlags, prog []bpf.Instruction) ([]capture.Source, error) {
	var names []string
	live := g.pcap == ""
	spec := g.pcap
	if live {
		spec = g.iface
	}
	for _, n := range strings.Split(spec, ",") {
		if n = strings.TrimSpace(n); n != "" {
			names = append(names, n)
		}
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("%w: an interface (-i) or a capture file (--pcap) is required", errUsage)
	}
	if !live && g.iface != "" {
		return nil, fmt.Errorf("%w: use either --pcap or -i, not both", errUsage)
	}
	var out []capture.Source
	for _, n := range names {
		var src capture.Source
		var err error
		if live {
			src, err = afpacket.Open(afpacket.Options{Interface: n, Promiscuous: !g.noPromisc, Filter: prog})
		} else {
			src, err = pcapfile.Open(n)
		}
		if err != nil {
			for _, s := range out {
				s.Close()
			}
			return nil, err
		}
		out = append(out, src)
	}
	return out, nil
}

// runSources drains several sources concurrently into one sink; the
// sink must be safe for concurrent use. Files replay sequentially so
// that packet order within a file is preserved per source.
func runSources(ctx context.Context, srcs []capture.Source, s sink) (decode.Stats, capture.Stats, error) {
	var mu sync.Mutex
	var total decode.Stats
	var ctotal capture.Stats
	var firstErr error
	var wg sync.WaitGroup
	for _, src := range srcs {
		wg.Add(1)
		go func(src capture.Source) {
			defer wg.Done()
			ds, cs, err := runSource(ctx, src, s)
			mu.Lock()
			defer mu.Unlock()
			total.Packets += ds.Packets
			total.Decoded += ds.Decoded
			total.Malformed += ds.Malformed
			total.Skipped += ds.Skipped
			ctotal.Received += cs.Received
			ctotal.Dropped += cs.Dropped
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}(src)
	}
	wg.Wait()
	return total, ctotal, firstErr
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

// reportTime is the generation time of a report: the last packet time
// of a capture file, so that replays reproduce, and the clock otherwise.
func reportTime(g *globalFlags, last time.Time) time.Time {
	if g.pcap != "" && !last.IsZero() {
		return last
	}
	return time.Now()
}

// withTimeout applies the --timeout flag.
func withTimeout(ctx context.Context, g *globalFlags) (context.Context, context.CancelFunc) {
	if g.timeout > 0 {
		return context.WithTimeout(ctx, g.timeout)
	}
	return context.WithCancel(ctx)
}
