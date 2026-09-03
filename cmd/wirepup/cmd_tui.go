package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	"github.com/jeonghanlee/wirepup/internal/tui"
)

// TUI timing.
const (
	tuiRedraw    = 500 * time.Millisecond
	tuiDiagnosis = 3 * time.Second
)

// runTUI shows the live views over a passive source. It is a renderer:
// the same pipeline, table, and rules feed it as feed the text output.
func runTUI(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("tui", e)
	g.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	out, ok := e.stdout.(*os.File)
	if !ok || !term.IsTerminal(int(out.Fd())) || !term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprintf(e.stderr, "wirepup: %v: tui needs a terminal on stdin and stdout\n", errUsage)
		return exitUsage
	}
	dctx, err := diagnosisContext(&g)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	vendors, ouiPath, err := loadOUI(e, &g)
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
	}
	table := device.New(device.Options{LocalMACs: local, Vendor: vendors.Lookup})
	model := tui.New(src.Name())
	if ifs, err := interfaces.List(); err == nil {
		model.SetInterfaces(output.InterfacesFrom(ifs))
	}
	ctx, cancel := withTimeout(ctx, &g)
	defer cancel()
	go func() {
		ds, cs, _ := runSource(ctx, src, func(obs []observation.Observation) {
			table.Apply(obs)
			for _, o := range obs {
				if hiddenProtocols[o.Ref().Protocol] && !g.verbose {
					continue
				}
				model.AddEvent(output.EventFrom(o))
			}
		})
		model.SetStats(fmt.Sprintf("%d packets, %d dropped (source ended)", ds.Packets, cs.Dropped))
	}()
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: terminal: %v\n", err)
		return exitError
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Fprint(out, tui.Enter)
	defer fmt.Fprint(out, tui.Leave)
	keys := make(chan byte, 16)
	go func() {
		buf := make([]byte, 1)
		for {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return
			}
			if n == 1 {
				keys <- buf[0]
			}
		}
	}()
	redraw := time.NewTicker(tuiRedraw)
	defer redraw.Stop()
	rules := time.NewTicker(tuiDiagnosis)
	defer rules.Stop()
	refresh := func() {
		model.SetDevices(output.DevicesFrom(src.Name(), time.Now(), ouiPath, table))
		if g.pcap == "" {
			model.SetStats(fmt.Sprintf("%d received, %d dropped", src.Stats().Received, src.Stats().Dropped))
		}
	}
	draw := func() {
		w, h, err := term.GetSize(int(out.Fd()))
		if err != nil {
			w, h = 80, 24
		}
		tui.Screen(out, model.Render(w, h))
	}
	refresh()
	model.SetDiagnosis(output.DiagnosisFrom(src.Name(), time.Now(), diagnose.RunAll(dctx, table, nilAddr, diagnose.Options{End: time.Now()})))
	draw()
	for !model.Quit() {
		select {
		case <-ctx.Done():
			return exitOK
		case k := <-keys:
			if model.HandleKey(k) {
				draw()
			}
		case <-redraw.C:
			refresh()
			draw()
		case <-rules.C:
			model.SetDiagnosis(output.DiagnosisFrom(src.Name(), time.Now(), diagnose.RunAll(dctx, table, nilAddr, diagnose.Options{End: time.Now()})))
		}
	}
	return exitOK
}
