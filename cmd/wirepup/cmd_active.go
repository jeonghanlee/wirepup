package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/jeonghanlee/wirepup/internal/active"
	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/networkcfg"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

// Active command defaults.
const (
	defaultConnectWindow = 5 * time.Second
	confirmPrompt        = "Proceed? [y/N] "
)

// activeFlags are shared by the commands that transmit or change the host.
type activeFlags struct {
	yes bool
}

func (a *activeFlags) register(fs interface {
	BoolVar(*bool, string, bool, string)
}) {
	fs.BoolVar(&a.yes, "yes", false, "do not ask for confirmation before acting")
}

// confirm asks on the terminal unless --yes was given. Without a
// terminal the action is refused so that a script cannot change the
// host by accident.
func confirm(e *env, a *activeFlags, stdin io.Reader) error {
	if a.yes {
		return nil
	}
	f, ok := stdin.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return fmt.Errorf("%w: no terminal to confirm on; pass --yes to proceed", errUsage)
	}
	fmt.Fprint(e.stderr, confirmPrompt)
	line, _ := bufio.NewReader(stdin).ReadString('\n')
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return nil
	}
	return errAborted
}

var errAborted = errors.New("aborted by user")

func activeExit(err error) int {
	switch {
	case errors.Is(err, active.ErrPrivilege), errors.Is(err, networkcfg.ErrPrivilege):
		return exitPrivilege
	case errors.Is(err, errUnsafe):
		return exitUnsafe
	case errors.Is(err, errAborted):
		return exitError
	default:
		return exitCodeFor(err)
	}
}

var errUnsafe = errors.New("unsafe or conflicting network change")

// runProbe sends a bounded ARP sweep (active).
func runProbe(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var a activeFlags
	var arpPrefix string
	fs := newFlagSet("probe", e)
	g.register(fs)
	a.register(fs)
	fs.StringVar(&arpPrefix, "arp", "", "IPv4 prefix to sweep with ARP requests (/24 or smaller)")
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if g.iface == "" || arpPrefix == "" {
		fmt.Fprintf(e.stderr, "wirepup: %v: probe needs -i <interface> and --arp <prefix>\n", errUsage)
		return exitUsage
	}
	prefix, err := netip.ParsePrefix(arpPrefix)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v: --arp %q: %v\n", errUsage, arpPrefix, err)
		return exitUsage
	}
	hosts, err := active.Hosts(prefix)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	plan := active.Plan{Interface: g.iface, Protocol: "ARP request", Targets: hosts, Count: len(hosts), Rate: active.RatePerSecond}
	fmt.Fprintf(e.stderr, "ACTIVE: will %s\n", plan)
	if err := confirm(e, &a, os.Stdin); err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	res, err := active.Sweep(ctx, g.iface, prefix)
	report := diagnose.Report{Interface: g.iface}
	report.Executed = append(report.Executed, diagnose.Finding{Code: "arp-sweep", Text: fmt.Sprintf("sent %d ARP requests on %s to %s at %d/s", res.Sent, g.iface, prefix, active.RatePerSecond), Data: map[string]string{"prefix": prefix.String(), "sent": fmt.Sprint(res.Sent)}})
	for _, r := range res.Replies {
		report.Observed = append(report.Observed, diagnose.Finding{Code: "arp-reply", Text: fmt.Sprintf("%s is-at %s", r.IP, r.MAC), Data: map[string]string{"ip": r.IP.String(), "mac": r.MAC.String()}})
	}
	renderReport(e, &g, activeSourceName(&g), report)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	return exitOK
}

// runConnect adds a temporary secondary IPv4 address after passive
// observation, a diagnosis, an explicit confirmation, and an ARP probe.
func runConnect(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var a activeFlags
	var addrFlag string
	fs := newFlagSet("connect", e)
	g.register(fs)
	a.register(fs)
	fs.StringVar(&addrFlag, "address", "", "temporary address with prefix to add (default: recommended candidate)")
	targetArg, rest, err := positional(fs, args)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	if ok, code := parse(fs, rest); !ok {
		return code
	}
	if g.iface == "" {
		fmt.Fprintf(e.stderr, "wirepup: %v: connect needs -i <interface>\n", errUsage)
		return exitUsage
	}
	var target netip.Addr
	if targetArg != "" {
		target, err = netip.ParseAddr(targetArg)
		if err != nil || !target.Is4() {
			fmt.Fprintf(e.stderr, "wirepup: %v: target must be an IPv4 address, got %q\n", errUsage, targetArg)
			return exitUsage
		}
	}
	var requested netip.Prefix
	if addrFlag != "" {
		requested, err = netip.ParsePrefix(addrFlag)
		if err != nil || !requested.Addr().Is4() {
			fmt.Fprintf(e.stderr, "wirepup: %v: --address must be an IPv4 prefix such as 192.168.1.254/24\n", errUsage)
			return exitUsage
		}
	}
	if !target.IsValid() && !requested.IsValid() {
		fmt.Fprintf(e.stderr, "wirepup: %v: connect needs a target address or --address\n", errUsage)
		return exitUsage
	}
	dctx, err := diagnose.ContextFor(g.iface)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitError
	}
	report := diagnose.Report{Interface: g.iface}
	if target.IsValid() {
		if g.timeout == 0 {
			g.timeout = defaultConnectWindow
		}
		table, code := observeWindow(ctx, e, &g)
		if code != exitOK {
			return code
		}
		report = diagnose.Run(dctx, table, target)
		if !report.TargetSeen && !requested.IsValid() {
			renderReport(e, &g, activeSourceName(&g), report)
			fmt.Fprintf(e.stderr, "wirepup: %v; pass --address to add one anyway\n", errNotObserved)
			return exitNotObserved
		}
		if report.TargetSeen && !requested.IsValid() && len(report.Recommended) == 0 {
			renderReport(e, &g, activeSourceName(&g), report)
			fmt.Fprintln(e.stderr, "wirepup: nothing to do: the target is inside a local subnet")
			return exitOK
		}
	}
	if !requested.IsValid() {
		cand := ""
		for _, f := range report.Recommended {
			if f.Code == diagnose.CodeTemporaryAddress {
				cand = f.Data["candidate"]
			}
		}
		if cand == "" {
			renderReport(e, &g, activeSourceName(&g), report)
			fmt.Fprintf(e.stderr, "wirepup: %v: no free candidate address; pass --address\n", errUnsafe)
			return exitUnsafe
		}
		requested = netip.PrefixFrom(netip.MustParseAddr(cand), diagnose.AssumedPrefixBits)
	}
	if err := refuseIfConfigured(dctx, requested); err != nil {
		renderReport(e, &g, activeSourceName(&g), report)
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUnsafe
	}
	mgr := networkcfg.New(version)
	argv := append([]string{mgr.IPPath}, networkcfg.AddArgv(g.iface, requested)...)
	report.Recommended = append(report.Recommended, diagnose.Finding{Code: "requested-action", Text: fmt.Sprintf("add %s to %s after an ARP probe: %s", requested, g.iface, strings.Join(argv, " ")), Data: map[string]string{"argv": strings.Join(argv, " ")}})
	renderReport(e, &g, activeSourceName(&g), report)
	fmt.Fprintf(e.stderr, "ACTIVE: will send %d ARP probes for %s on %s, then run: %s\n", active.ProbeCount, requested.Addr(), g.iface, strings.Join(argv, " "))
	if err := confirm(e, &a, os.Stdin); err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	probe, err := active.Probe(ctx, g.iface, requested.Addr())
	executed := []diagnose.Finding{{Code: "arp-probe", Text: fmt.Sprintf("sent %d ARP probes for %s on %s", probe.Sent, requested.Addr(), g.iface), Data: map[string]string{"sent": fmt.Sprint(probe.Sent), "address": requested.Addr().String()}}}
	if err != nil {
		renderExecuted(e, &g, executed)
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	if probe.Conflict != nil {
		executed = append(executed, diagnose.Finding{Code: "address-in-use", Text: fmt.Sprintf("%s answered for %s (%s); address not added", probe.Conflict.MAC, requested.Addr(), probe.Conflict.Kind), Data: map[string]string{"mac": probe.Conflict.MAC.String(), "kind": string(probe.Conflict.Kind)}})
		renderExecuted(e, &g, executed)
		fmt.Fprintf(e.stderr, "wirepup: %v: %s is already in use by %s\n", errUnsafe, requested.Addr(), probe.Conflict.MAC)
		return exitUnsafe
	}
	entry, err := mgr.Add(g.iface, requested)
	if err != nil {
		renderExecuted(e, &g, executed)
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	executed = append(executed, diagnose.Finding{Code: "address-added", Text: fmt.Sprintf("added %s to %s (label %s), recorded in %s: %s", entry.Address, entry.Interface, dashIfEmpty(entry.Label), mgr.Path, strings.Join(entry.Argv, " ")), Data: map[string]string{"address": entry.Address.String(), "interface": entry.Interface, "label": entry.Label, "argv": strings.Join(entry.Argv, " "), "session": mgr.Path}})
	renderExecuted(e, &g, executed)
	fmt.Fprintf(e.stderr, "Remove it later with: wirepup disconnect -i %s %s\n", entry.Interface, entry.Address)
	return exitOK
}

// runDisconnect removes addresses WirePup recorded, and only those.
func runDisconnect(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("disconnect", e)
	g.register(fs)
	addrArg, rest, err := positional(fs, args)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	if ok, code := parse(fs, rest); !ok {
		return code
	}
	var only netip.Prefix
	if addrArg != "" {
		only, err = netip.ParsePrefix(addrArg)
		if err != nil {
			if a, aerr := netip.ParseAddr(addrArg); aerr == nil {
				only = netip.PrefixFrom(a, diagnose.AssumedPrefixBits)
			} else {
				fmt.Fprintf(e.stderr, "wirepup: %v: address %q\n", errUsage, addrArg)
				return exitUsage
			}
		}
	}
	mgr := networkcfg.New(version)
	session, err := mgr.Load()
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitError
	}
	var executed []diagnose.Finding
	matched := 0
	code := exitOK
	for _, entry := range session.Entries {
		if g.iface != "" && entry.Interface != g.iface {
			continue
		}
		if only.IsValid() && entry.Address.Addr() != only.Addr() {
			continue
		}
		matched++
		ran, err := mgr.Remove(entry)
		switch {
		case err != nil:
			executed = append(executed, diagnose.Finding{Code: "remove-failed", Text: fmt.Sprintf("could not remove %s from %s: %v", entry.Address, entry.Interface, err)})
			code = activeExit(err)
		case ran:
			executed = append(executed, diagnose.Finding{Code: "address-removed", Text: fmt.Sprintf("removed %s from %s: %s %s", entry.Address, entry.Interface, mgr.IPPath, strings.Join(networkcfg.DelArgv(entry), " ")), Data: map[string]string{"address": entry.Address.String(), "interface": entry.Interface}})
		default:
			executed = append(executed, diagnose.Finding{Code: "record-dropped", Text: fmt.Sprintf("%s was no longer on %s; dropped the stale record", entry.Address, entry.Interface)})
		}
	}
	if matched == 0 {
		fmt.Fprintf(e.stderr, "wirepup: nothing to remove: no WirePup-created address recorded in %s\n", mgr.Path)
		if g.json {
			renderExecuted(e, &g, executed)
		}
		return code
	}
	renderExecuted(e, &g, executed)
	return code
}

// observeWindow runs passive discovery for the timeout and returns the
// table; it uses the same decode pipeline as diagnose, without the
// --protocol ingest gate, so an active command takes a broad picture.
func observeWindow(ctx context.Context, e *env, g *globalFlags) (*device.Table, int) {
	src, err := openLive(g, nil)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return nil, exitCodeFor(err)
	}
	defer src.Close()
	local, _ := interfaces.LocalMACs()
	table := device.New(device.Options{LocalMACs: local})
	if !g.quiet {
		fmt.Fprintf(e.stderr, "Observing %s for %s (passive) before any change...\n", src.Name(), g.timeout)
	}
	wctx, cancel := withTimeout(ctx, g)
	defer cancel()
	_, _, err = runSource(wctx, src, func(obs []observation.Observation) { table.Apply(obs) })
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return nil, exitCodeFor(err)
	}
	return table, exitOK
}

func refuseIfConfigured(ctx diagnose.Context, p netip.Prefix) error {
	for _, l := range ctx.LocalIPv4 {
		if l.Addr() == p.Addr() {
			return fmt.Errorf("%w: %s is already configured on %s", errUnsafe, p.Addr(), ctx.Interface)
		}
	}
	if p.Bits() < 31 {
		if p.Addr() == p.Masked().Addr() {
			return fmt.Errorf("%w: %s is the network address", errUnsafe, p.Addr())
		}
		if p.Addr() == broadcastOf(p) {
			return fmt.Errorf("%w: %s is the broadcast address", errUnsafe, p.Addr())
		}
	}
	return nil
}

// broadcastOf returns the last address of an IPv4 prefix.
func broadcastOf(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	v |= uint32(0xffffffff) >> p.Bits()
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

func renderReport(e *env, g *globalFlags, source string, r diagnose.Report) {
	renderReportAt(e, g, source, r, time.Now())
}

// renderReportAt renders with an explicit generation time, which file
// replay sets to the last packet so that output is reproducible.
func renderReportAt(e *env, g *globalFlags, source string, r diagnose.Report, at time.Time) {
	doc := output.DiagnosisFrom(source, at, r)
	if g.json {
		jsonout.Document(e.stdout, doc)
		return
	}
	text.Diagnosis(e.stdout, doc)
}

// activeSourceName is the source of an active command's report: the
// interface it ran on, or the literal "active" when it ran without one.
// A capture file is never the source of a transmission, so --pcap is
// not consulted.
func activeSourceName(g *globalFlags) string {
	if g.iface != "" {
		return g.iface
	}
	return "active"
}

// renderExecuted renders the findings of an executed action; the
// interface field stays the interface name, empty when none was given.
func renderExecuted(e *env, g *globalFlags, executed []diagnose.Finding) {
	renderReport(e, g, activeSourceName(g), diagnose.Report{Interface: g.iface, Executed: executed})
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
