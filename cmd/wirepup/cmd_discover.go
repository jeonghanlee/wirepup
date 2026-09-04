package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/oui"
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
	return discoverWith(ctx, e, &g)
}

// discoverWith runs device discovery over the selected source.
func discoverWith(ctx context.Context, e *env, g *globalFlags) int {
	prog, display, err := filterFor(g.protocols)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	vendors, ouiPath, err := loadOUI(e, g)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	src, err := openSource(g, prog)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	defer src.Close()
	var local []string
	if g.pcap == "" {
		local, _ = interfaces.LocalMACs()
	}
	table := device.New(device.Options{LocalMACs: local, Vendor: vendors.Lookup})
	if !g.quiet && g.pcap == "" {
		fmt.Fprintf(e.stderr, "Listening on %s (passive: nothing is transmitted)...\n", src.Name())
	}
	ctx, cancel := withTimeout(ctx, g)
	defer cancel()
	var last time.Time
	show := func(obs []observation.Observation) {
		if len(obs) > 0 {
			last = obs[0].Ref().Timestamp
		}
		if !wantPacket(obs, display) {
			return
		}
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
	reportStats(e, g, ds, cs)
	at := reportTime(g, last)
	doc := output.DevicesFrom(src.Name(), at, ouiPath, table)
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

// loadOUI opens the vendor registry. A missing default file is a notice,
// not an error; a missing explicit --oui-file is an error.
func loadOUI(e *env, g *globalFlags) (*oui.Table, string, error) {
	t, err := oui.Load(g.ouiFile, oui.DefaultPaths)
	if err != nil {
		if g.ouiFile != "" || !errors.Is(err, oui.ErrNotFound) {
			return nil, "", err
		}
		if !g.quiet {
			fmt.Fprintf(e.stderr, "wirepup: vendor hints disabled: %v\n", err)
		}
		return nil, "", nil
	}
	return t, t.Path(), nil
}
