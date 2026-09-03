package main

import (
	"context"
	"fmt"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

// runDiscover streams device events and prints the device table at the
// end (passive).
func runDiscover(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("discover", e)
	g.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
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
	local, _ := interfaces.LocalMACs()
	table := device.New(device.Options{LocalMACs: local})
	if !g.quiet {
		fmt.Fprintf(e.stderr, "Listening on %s (passive: nothing is transmitted)...\n", src.Name())
	}
	ctx, cancel := withTimeout(ctx, &g)
	defer cancel()
	show := func(obs []observation.Observation) {
		for _, ev := range table.Apply(obs) {
			de := output.DeviceEventFrom(ev)
			if g.json {
				jsonout.Line(e.stdout, de)
			} else {
				text.DeviceEvent(e.stdout, de)
			}
		}
	}
	ds, cs, runErr := runSource(ctx, src, show)
	reportStats(e, &g, ds, cs)
	doc := output.DevicesFrom(src.Name(), time.Now(), table.Devices())
	if g.json {
		jsonout.Document(e.stdout, doc)
	} else if len(doc.Devices) > 0 {
		fmt.Fprintln(e.stdout)
		text.Devices(e.stdout, doc)
	}
	if runErr != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", runErr)
		return exitCodeFor(runErr)
	}
	return exitOK
}
