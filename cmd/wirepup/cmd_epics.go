package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/jeonghanlee/wirepup/internal/active"
	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/output"
	jsonout "github.com/jeonghanlee/wirepup/internal/output/json"
	"github.com/jeonghanlee/wirepup/internal/output/text"
)

// EPICS command defaults.
const (
	epicsProtocols    = "ca,pva"
	defaultFindWindow = 5 * time.Second
	activeSearchID    = 0x77697265 // "wire"
	activeInstanceID  = 1
	searchBoth        = "ca,pva"
)

// runEPICS dispatches the epics subcommands.
func runEPICS(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(e.stderr, "usage: wirepup epics <observe|find|diagnose> [flags]")
		return exitUsage
	}
	switch args[0] {
	case "observe":
		return runEPICSObserve(ctx, e, args[1:])
	case "find":
		return runEPICSFind(ctx, e, args[1:])
	case "diagnose":
		return runEPICSDiagnose(ctx, e, args[1:])
	}
	fmt.Fprintf(e.stderr, "wirepup: unknown epics subcommand %q\n", args[0])
	return exitUsage
}

// runEPICSObserve is observe restricted to the EPICS protocols, printed
// as labelled blocks.
func runEPICSObserve(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	fs := newFlagSet("epics observe", e)
	g.register(fs)
	if ok, code := parse(fs, args); !ok {
		return code
	}
	if g.protocols == "" {
		g.protocols = epicsProtocols
	}
	prog, display, err := filterFor(g.protocols)
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
	if !g.quiet && g.pcap == "" {
		fmt.Fprintf(e.stderr, "Listening on %s for EPICS traffic (passive: nothing is transmitted)...\n", src.Name())
	}
	ctx, cancel := withTimeout(ctx, &g)
	defer cancel()
	show := func(obs []observation.Observation) {
		for _, o := range obs {
			if !display[o.Ref().Protocol] {
				continue
			}
			ev := output.EventFrom(o)
			if g.json {
				jsonout.Line(e.stdout, ev)
			} else {
				text.EPICSEvent(e.stdout, ev)
			}
		}
	}
	ds, cs, err := runSource(ctx, src, show)
	reportStats(e, &g, ds, cs)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitCodeFor(err)
	}
	return exitOK
}

// runEPICSFind reports what the wire shows about one PV. Passive by
// default; --active sends one CA search per destination and is
// reported as executed.
func runEPICSFind(ctx context.Context, e *env, args []string) int {
	var g globalFlags
	var a activeFlags
	var activeSearch bool
	var to, search string
	fs := newFlagSet("epics find", e)
	g.register(fs)
	a.register(fs)
	fs.BoolVar(&activeSearch, "active", false, "send searches (ACTIVE: transmits one datagram per destination and protocol)")
	fs.StringVar(&to, "to", "", "comma-separated search destinations host[:port] for --active (default: directed broadcasts of the interface; CA and PVA use their own default ports)")
	fs.StringVar(&search, "search", searchBoth, "protocols to search with --active: ca, pva, or ca,pva")
	pv, rest, err := positional(fs, args)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	if ok, code := parse(fs, rest); !ok {
		return code
	}
	if pv == "" {
		fmt.Fprintf(e.stderr, "wirepup: %v: a PV name is required\n", errUsage)
		return exitUsage
	}
	report := diagnose.Report{Interface: g.iface}
	at := time.Now()
	if g.pcap != "" || g.iface != "" {
		table, last, code := findWindow(ctx, e, &g)
		if code != exitOK {
			return code
		}
		if g.pcap != "" && !last.IsZero() {
			at = last
		}
		report = passiveFindReport(table, pv, g.iface)
	} else if !activeSearch {
		fmt.Fprintf(e.stderr, "wirepup: %v: epics find needs -i, --pcap, or --active\n", errUsage)
		return exitUsage
	}
	if !activeSearch {
		renderReportAt(e, &g, sourceName(&g), report, at)
		if len(report.Observed) == 0 {
			return exitNotObserved
		}
		return exitOK
	}
	protos := protocolSet(search)
	if len(protos) == 0 || (!protos["ca"] && !protos["pva"]) {
		fmt.Fprintf(e.stderr, "wirepup: %v: --search must name ca, pva, or ca,pva\n", errUsage)
		return exitUsage
	}
	caDests, pvaDests, err := searchDestinations(&g, to, protos)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return exitUsage
	}
	var plan []string
	if len(caDests) > 0 {
		plan = append(plan, fmt.Sprintf("one CA search to %s", joinDests(caDests)))
	}
	if len(pvaDests) > 0 {
		plan = append(plan, fmt.Sprintf("one PVA search to %s", joinDests(pvaDests)))
	}
	fmt.Fprintf(e.stderr, "ACTIVE: will send for %s: %s\n", pv, strings.Join(plan, "; "))
	if err := confirm(e, &a, os.Stdin); err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return activeExit(err)
	}
	wait := g.timeout
	if wait == 0 {
		wait = active.CADefaultWait
	}
	answers := 0
	var firstErr error
	if len(caDests) > 0 {
		res, err := active.CASearch(ctx, pv, caDests, activeSearchID, true, wait)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		report.Executed = append(report.Executed, diagnose.Finding{Code: "ca-search-sent", Text: fmt.Sprintf("sent %d CA search datagram(s) for %s to %s (reply requested)", len(res.Sent), pv, joinDests(caDests)), Data: map[string]string{"pv": pv, "destinations": joinDests(caDests)}})
		for _, r := range res.Responses {
			answers++
			report.Observed = append(report.Observed, diagnose.Finding{Code: "ca-search-answer", Text: fmt.Sprintf("CA server %s answered for %s: TCP port %d (datagram from %s)", r.ServerIP, pv, r.TCPPort, r.From), Data: map[string]string{"server": r.ServerIP.String(), "tcp_port": fmt.Sprint(r.TCPPort), "pv": pv}})
		}
		for _, r := range res.NotFound {
			report.Observed = append(report.Observed, diagnose.Finding{Code: "ca-not-found", Text: fmt.Sprintf("CA %s replied not found for %s", r.From, pv)})
		}
		if len(res.Responses) > 1 {
			report.Inferred = append(report.Inferred, diagnose.Finding{Code: "ca-multiple-servers", Text: fmt.Sprintf("%d CA servers claim %s; a client would connect to whichever answered first", len(res.Responses), pv)})
		}
	}
	if len(pvaDests) > 0 {
		res, err := active.PVASearch(ctx, pv, pvaDests, activeSearchID, activeInstanceID, wait)
		if err != nil && firstErr == nil {
			firstErr = err
		}
		report.Executed = append(report.Executed, diagnose.Finding{Code: "pva-search-sent", Text: fmt.Sprintf("sent %d PVA search datagram(s) for %s to %s (reply required)", len(res.Sent), pv, joinDests(pvaDests)), Data: map[string]string{"pv": pv, "destinations": joinDests(pvaDests)}})
		for _, r := range res.Responses {
			answers++
			report.Observed = append(report.Observed, diagnose.Finding{Code: "pva-search-answer", Text: fmt.Sprintf("PVA server %s answered for %s: TCP port %d guid %s (datagram from %s)", r.ServerAddr, pv, r.ServerPort, r.GUID, r.From), Data: map[string]string{"server": r.ServerAddr.String(), "tcp_port": fmt.Sprint(r.ServerPort), "guid": r.GUID, "pv": pv}})
		}
		for _, r := range res.NotFound {
			report.Observed = append(report.Observed, diagnose.Finding{Code: "pva-not-found", Text: fmt.Sprintf("PVA %s (guid %s) replied not found for %s", r.From, r.GUID, pv)})
		}
		if len(res.Responses) > 1 {
			report.Inferred = append(report.Inferred, diagnose.Finding{Code: "pva-multiple-servers", Text: fmt.Sprintf("%d PVA servers claim %s", len(res.Responses), pv)})
		}
	}
	if answers == 0 {
		report.Inferred = append(report.Inferred, diagnose.Finding{Code: "no-answer", Text: fmt.Sprintf("no server answered for %s within %s from the destinations tried; the PV may still exist on a server not reached by these searches", pv, wait)})
	}
	renderReport(e, &g, sourceName(&g), report)
	if firstErr != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", firstErr)
		return activeExit(firstErr)
	}
	if answers == 0 {
		return exitNotObserved
	}
	return exitOK
}

func joinDests(ds []netip.AddrPort) string {
	var names []string
	for _, d := range ds {
		names = append(names, d.String())
	}
	return strings.Join(names, ", ")
}

// runEPICSDiagnose is diagnose restricted to the EPICS rules.
func runEPICSDiagnose(ctx context.Context, e *env, args []string) int {
	return runDiagnose(ctx, e, append([]string{"--epics"}, args...))
}

func findWindow(ctx context.Context, e *env, g *globalFlags) (*device.Table, time.Time, int) {
	var last time.Time
	if g.pcap == "" && g.timeout == 0 {
		g.timeout = defaultFindWindow
	}
	src, err := openSource(g, nil)
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return nil, last, exitCodeFor(err)
	}
	defer src.Close()
	var local []string
	if g.pcap == "" {
		local, _ = interfaces.LocalMACs()
		if !g.quiet {
			fmt.Fprintf(e.stderr, "Observing %s for %s (passive: nothing is transmitted)...\n", src.Name(), g.timeout)
		}
	}
	table := device.New(device.Options{LocalMACs: local})
	wctx, cancel := withTimeout(ctx, g)
	defer cancel()
	_, _, err = runSource(wctx, src, func(obs []observation.Observation) {
		if len(obs) > 0 {
			last = obs[0].Ref().Timestamp
		}
		table.Apply(obs)
	})
	if err != nil {
		fmt.Fprintf(e.stderr, "wirepup: %v\n", err)
		return nil, last, exitCodeFor(err)
	}
	return table, last, exitOK
}

// passiveFindReport lists what was seen for one PV name.
func passiveFindReport(table *device.Table, pv, iface string) diagnose.Report {
	r := diagnose.Report{Interface: iface}
	answered := 0
	for _, s := range table.CASearches() {
		if s.PV != pv {
			continue
		}
		r.Observed = append(r.Observed, diagnose.Finding{Code: "ca-search-seen", Text: fmt.Sprintf("CA search for %s from %s:%d (x%d, id %d)", pv, s.ClientIP, s.ClientPort, s.Count, s.ID), Evidence: []diagnose.Ref{s.Ref}, Data: map[string]string{"client": s.ClientIP.String(), "count": fmt.Sprint(s.Count)}})
		for _, a := range s.Responses {
			answered++
			r.Observed = append(r.Observed, diagnose.Finding{Code: "ca-search-answer", Text: fmt.Sprintf("server %s answered for %s: TCP port %d", a.ServerIP, pv, a.TCPPort), Evidence: []diagnose.Ref{a.Ref}, Data: map[string]string{"server": a.ServerIP.String(), "tcp_port": fmt.Sprint(a.TCPPort)}})
		}
		if len(s.Responses) == 0 {
			r.Inferred = append(r.Inferred, diagnose.Finding{Code: "ca-no-answer", Text: fmt.Sprintf("no response observed for the search from %s; the PV may still exist on a server whose reply did not cross this interface", s.ClientIP), Evidence: []diagnose.Ref{s.Ref}})
		}
		if len(s.Responses) > 1 {
			r.Inferred = append(r.Inferred, diagnose.Finding{Code: "ca-multiple-servers", Text: fmt.Sprintf("%d servers answered for %s", len(s.Responses), pv), Evidence: []diagnose.Ref{s.Ref}})
		}
	}
	for _, srv := range table.CAServers() {
		for _, name := range srv.PVs {
			if name == pv {
				r.Inferred = append(r.Inferred, diagnose.Finding{Code: "ca-server-claims", Text: fmt.Sprintf("CA server %s (TCP %d) claims %s", srv.Addr, srv.TCPPort, pv), Evidence: []diagnose.Ref{srv.Ref}})
			}
		}
	}
	for _, s := range table.PVASearches() {
		if s.PV != pv {
			continue
		}
		r.Observed = append(r.Observed, diagnose.Finding{Code: "pva-search-seen", Text: fmt.Sprintf("PVA search for %s from %s:%d (x%d, seq %d)", pv, s.ClientIP, s.ClientPort, s.Count, s.SequenceID), Evidence: []diagnose.Ref{s.Ref}, Data: map[string]string{"client": s.ClientIP.String(), "count": fmt.Sprint(s.Count)}})
		for _, a := range s.Responses {
			answered++
			r.Observed = append(r.Observed, diagnose.Finding{Code: "pva-search-answer", Text: fmt.Sprintf("PVA server %s answered for %s: TCP port %d guid %s", a.ServerAddr, pv, a.ServerPort, a.GUID), Evidence: []diagnose.Ref{a.Ref}, Data: map[string]string{"server": a.ServerAddr.String(), "tcp_port": fmt.Sprint(a.ServerPort), "guid": a.GUID}})
		}
		if len(s.Responses) == 0 {
			r.Inferred = append(r.Inferred, diagnose.Finding{Code: "pva-no-answer", Text: fmt.Sprintf("no PVA response observed for the search from %s; the PV may still exist on a server whose reply did not cross this interface", s.ClientIP), Evidence: []diagnose.Ref{s.Ref}})
		}
		if len(s.Responses) > 1 {
			r.Inferred = append(r.Inferred, diagnose.Finding{Code: "pva-multiple-servers", Text: fmt.Sprintf("%d PVA servers answered for %s", len(s.Responses), pv), Evidence: []diagnose.Ref{s.Ref}})
		}
	}
	for _, srv := range table.PVAServers() {
		for _, name := range srv.PVs {
			if name == pv {
				r.Inferred = append(r.Inferred, diagnose.Finding{Code: "pva-server-claims", Text: fmt.Sprintf("PVA server %s (TCP %d, guid %s) claims %s", srv.Addr, srv.TCPPort, srv.GUID, pv), Evidence: []diagnose.Ref{srv.Ref}})
			}
		}
	}
	if len(r.Observed) == 0 {
		r.Inferred = append(r.Inferred, diagnose.Finding{Code: "nothing-seen", Text: fmt.Sprintf("nothing about %s crossed this interface during the window; nothing can be said about the PV from passive observation alone", pv)})
	}
	_ = answered
	return r
}

// searchDestinations resolves --to into per-protocol destination lists.
// An address without a port gets each protocol's default port; an
// explicit port is used as given for every selected protocol.
func searchDestinations(g *globalFlags, to string, protos map[string]bool) (caDests, pvaDests []netip.AddrPort, err error) {
	var addrs []netip.Addr
	var explicit []netip.AddrPort
	for _, s := range strings.Split(to, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if ap, err := netip.ParseAddrPort(s); err == nil {
			explicit = append(explicit, ap)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: --to %q: not an address or address:port", errUsage, s)
		}
		addrs = append(addrs, a)
	}
	if len(addrs) == 0 && len(explicit) == 0 {
		if g.iface == "" {
			return nil, nil, fmt.Errorf("%w: --active needs --to <host[:port],...> or -i <interface> for its broadcast addresses", errUsage)
		}
		ifc, err := interfaces.ByName(g.iface)
		if err != nil {
			return nil, nil, err
		}
		for _, ap := range active.BroadcastDestinations(ifc.IPv4, 0) {
			addrs = append(addrs, ap.Addr())
		}
		if len(addrs) == 0 {
			return nil, nil, fmt.Errorf("%w: %s has no IPv4 subnet to broadcast on; use --to", errUsage, g.iface)
		}
	}
	if protos["ca"] {
		caDests = append(caDests, explicit...)
		for _, a := range addrs {
			caDests = append(caDests, netip.AddrPortFrom(a, ca.DefaultServerPort))
		}
	}
	if protos["pva"] {
		pvaDests = append(pvaDests, explicit...)
		for _, a := range addrs {
			pvaDests = append(pvaDests, netip.AddrPortFrom(a, pva.DefaultUDPPort))
		}
	}
	return caDests, pvaDests, nil
}

func sourceName(g *globalFlags) string {
	if g.pcap != "" {
		return g.pcap
	}
	if g.iface != "" {
		return g.iface
	}
	return "active"
}
