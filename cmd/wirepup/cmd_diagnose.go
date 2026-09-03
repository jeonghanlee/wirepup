package main

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

// defaultDiagnoseWindow bounds a live diagnosis when no --timeout is
// given, so the command ends on its own.
const defaultDiagnoseWindow = 10 * time.Second

// runDiagnose observes for a window, then applies the diagnosis rules.
// It is passive: nothing is transmitted and nothing is changed.
func runDiagnose(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var epicsOnly bool
	fs := newFlagSet("diagnose", e)
	g.register(fs)
	fs.BoolVar(&epicsOnly, "epics", false, "report only the EPICS CA/PVA rules")
	targetArg, rest, err := positional(fs, args)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	if ok, code := parse(fs, rest); !ok {
		return code
	}
	var target netip.Addr
	if targetArg != "" {
		target, err = netip.ParseAddr(targetArg)
		if err != nil || !target.Is4() {
			fmt.Fprintf(e.stderr, "wirepup: %v: target must be an IPv4 address, got %q\n", errUsage, targetArg)
			return exitUsage
		}
	}
	dctx, err := diagnosisContext(&g)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	vendors, _, err := loadOUI(e, &g)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	prog, _, err := filterFor(g.protocols)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	src, err := openSource(&g, prog)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	defer src.Close()
	var local []string
	if g.pcap == "" {
		local, _ = interfaces.LocalMACs()
		if g.timeout == 0 {
			g.timeout = defaultDiagnoseWindow
		}
		if !g.quiet {
			fmt.Fprintf(e.stderr, "Observing %s for %s (passive: nothing is transmitted)...\n", src.Name(), g.timeout)
		}
	}
	table := device.New(device.Options{LocalMACs: local, Vendor: vendors.Lookup})
	ctx, cancel := withTimeout(ctx, &g)
	defer cancel()
	var last time.Time
	ds, cs, runErr := runSource(ctx, src, func(obs []observation.Observation) {
		if len(obs) > 0 {
			last = obs[0].Ref().Timestamp
		}
		table.Apply(obs)
	})
	reportStats(e, &g, ds, cs)
	if runErr != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", runErr)
		return exitCodeFor(runErr)
	}
	report := diagnose.Run(dctx, table, target)
	_ = epicsOnly
	at := time.Now()
	if g.pcap != "" && !last.IsZero() {
		at = last
	}
	doc := output.DiagnosisFrom(src.Name(), at, report)
	if g.json {
		jsonout.Document(e.stdout, doc)
	} else {
		text.Diagnosis(e.stdout, doc)
	}
	if target.IsValid() && !report.TargetSeen {
		return exitNotObserved
	}
	return exitOK
}

// diagnosisContext takes the local context from the host for live runs
// and from --local for capture files.
func diagnosisContext(g *globalFlags) (diagnose.Context, error) {
	if g.pcap == "" {
		if g.iface == "" {
			return diagnose.Context{}, fmt.Errorf("%w: an interface is required (-i)", errUsage)
		}
		return diagnose.ContextFor(g.iface)
	}
	var prefixes []netip.Prefix
	for _, s := range strings.Split(g.local, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return diagnose.Context{}, fmt.Errorf("%w: --local %q: %v", errUsage, s, err)
		}
		prefixes = append(prefixes, p)
	}
	name := g.iface
	if name == "" {
		name = "capture"
	}
	return diagnose.ContextFromPrefixes(name, prefixes), nil
}
