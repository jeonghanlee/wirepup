package main

import (
	"context"
	"fmt"

	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

// runObserve prints every observation as it is decoded (passive).
func runObserve(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("observe", e)
	g.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	return observeWith(ctx, e, &g)
}

// observeWith runs the event stream over the selected source.
func observeWith(ctx context.Context, e *env, g *globalFlags) int {
	prog, display, err := filterFor(g.protocols)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	src, err := openSource(g, prog)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	defer src.Close()
	if !g.quiet && g.pcap == "" {
		fmt.Fprintf(e.stderr, "Listening on %s (passive: nothing is transmitted)...\n", src.Name())
	}
	ctx, cancel := withTimeout(ctx, g)
	defer cancel()
	show := func(obs []observation.Observation) {
		for _, o := range obs {
			if !wantObservation(o, display, g.verbose) {
				continue
			}
			ev := output.EventFrom(o)
			if g.json {
				jsonout.Line(e.stdout, ev)
			} else {
				text.Event(e.stdout, ev)
			}
		}
	}
	ds, cs, err := runSource(ctx, src, show)
	reportStats(e, g, ds, cs)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	return exitOK
}

// wantObservation applies the display filter: frame-level observations
// appear only when asked for explicitly or in verbose mode.
func wantObservation(o observation.Observation, display map[string]bool, verbose bool) bool {
	proto := o.Ref().Protocol
	if display != nil {
		return display[proto]
	}
	if hiddenProtocols[proto] {
		return verbose
	}
	return true
}
