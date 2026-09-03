package main

import (
	"context"
	"fmt"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/capture/pcapfile"
)

// runCapture writes every received frame to a PCAP or PCAPNG file
// (passive). Nothing is decoded on the way.
func runCapture(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var out string
	var snapLen int
	fs := newFlagSet("capture", e)
	g.register(fs)
	fs.StringVar(&out, "o", "", "output file (.pcap or .pcapng)")
	fs.StringVar(&out, "output", "", "output file (.pcap or .pcapng)")
	fs.IntVar(&snapLen, "snaplen", 0, "bytes to keep per frame (0 = whole frame)")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if out == "" {
		fmt.Fprintf(e.stderr, "wirepup: %v: an output file is required (-o)\n", errUsage)
		return exitUsage
	}
	prog, _, err := filterFor(g.protocols)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	src, err := openLive(&g, prog)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	defer src.Close()
	w, err := pcapfile.Create(out, src.Name(), snapLen)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitError
	}
	if !g.quiet {
		fmt.Fprintf(e.stderr, "Capturing on %s to %s (passive: nothing is transmitted)...\n", src.Name(), out)
	}
	ctx, cancel := withTimeout(ctx, &g)
	defer cancel()
	packets, errc := src.Packets(ctx)
	var writeErr error
	for pkt := range packets {
		if snapLen > 0 && len(pkt.Data) > snapLen {
			pkt.Data = pkt.Data[:snapLen]
		}
		if err := w.Write(pkt); err != nil {
			writeErr = err
			cancel()
			break
		}
	}
	var runErr error
	if err, ok := <-errc; ok && err != nil {
		runErr = fmt.Errorf("%w: %v", errCapture, err)
	}
	if err := w.Close(); err != nil && writeErr == nil {
		writeErr = err
	}
	cs := src.Stats()
	if !g.quiet {
		fmt.Fprintf(e.stderr, "%d packets written to %s, %d received by kernel, %d dropped\n", w.Count(), out, cs.Received, cs.Dropped)
	}
	switch {
	case writeErr != nil:
		fmt.Fprintf(e.stderr, "wirepup: %v\n", writeErr)
		return exitError
	case runErr != nil:
		fmt.Fprintf(e.stderr, "wirepup: %v\n", runErr)
		return exitCodeFor(runErr)
	}
	return exitOK
}

var _ capture.Source = (*pcapfile.Reader)(nil)
