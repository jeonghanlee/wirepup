package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/networkcfg"
)

const guideCleanupTimeout = 5 * time.Second

var (
	errGuideBack = errors.New("back")
	errGuideQuit = errors.New("quit")
)

// guide retains only the selected source, the last real operation result,
// and entries returned by its own successful address adds.
type guide struct {
	ctx        context.Context
	env        *env
	source     globalFlags
	localAsked bool
	pv         string
	args       []string
	result     operationResult
	entries    []networkcfg.Entry
	status     int
}

func runGuide(ctx context.Context, e *env) (code int) {
	ctx, cancel := context.WithCancel(ctx)
	call := *e
	call.input = newPromptInput(ctx, e.stdin, cancel)
	call.guided = true
	call.stderr = e.stdout
	g := &guide{ctx: ctx, env: &call}
	defer func() {
		cancel()
		<-call.input.done
		if c := g.cleanup(); c != exitOK {
			code = c
		}
	}()
	fmt.Fprintln(e.stdout, "WirePup guide")
	fmt.Fprintln(e.stdout, "Start with passive observation. Active actions require a separate confirmation.")
	for {
		choice, err := g.menu("Purpose", "Find devices", "Diagnose EPICS connectivity", "Analyze a capture file")
		if err != nil {
			if errors.Is(err, errGuideBack) {
				continue
			}
			return g.exit(err)
		}
		g.source, g.pv, g.localAsked = globalFlags{quiet: true}, "", false
		window := defaultDiagnoseWindow
		if err = g.chooseSource(choice == 3, window); err == nil {
			switch choice {
			case 1:
				if err = g.duration(defaultDiagnoseWindow); err == nil {
					g.execute(g.deviceArgs())
				}
			case 2:
				err = g.findPV()
			case 3:
				err = g.captureView()
			}
		}
		if err == nil {
			err = g.next(choice)
		}
		if errors.Is(err, errGuideBack) {
			continue
		}
		if err != nil {
			return g.exit(err)
		}
	}
}

func (g *guide) exit(err error) int {
	if errors.Is(err, errGuideQuit) && g.ctx.Err() == nil {
		return g.status
	}
	if errors.Is(err, errPromptTooLong) || (!errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled)) {
		fmt.Fprintf(g.env.stdout, "Guide stopped: %v\n", err)
	}
	return exitError
}

func (g *guide) menu(title string, choices ...string) (int, error) {
	for {
		fmt.Fprintf(g.env.stdout, "\n%s\n", title)
		for i, c := range choices {
			fmt.Fprintf(g.env.stdout, "  %d  %s\n", i+1, c)
		}
		fmt.Fprintln(g.env.stdout, "  b  Back    q  Quit")
		line, err := g.env.input.line(g.ctx, func() { fmt.Fprint(g.env.stdout, "Choice: ") })
		if err != nil {
			return 0, err
		}
		switch strings.TrimSpace(line) {
		case "b":
			return 0, errGuideBack
		case "q":
			return 0, errGuideQuit
		}
		n, err := strconv.Atoi(strings.TrimSpace(line))
		if err == nil && n >= 1 && n <= len(choices) {
			return n, nil
		}
		fmt.Fprintln(g.env.stdout, "Choose a listed number, b, or q.")
	}
}

// Free-text controls have an escape so literal PV/path names remain usable.
func (g *guide) ask(label string) (string, error) {
	for {
		line, err := g.env.input.line(g.ctx, func() { fmt.Fprintf(g.env.stdout, "%s (/back, /quit; use // for a literal leading /): ", label) })
		if err != nil {
			return "", err
		}
		switch line {
		case "/back":
			return "", errGuideBack
		case "/quit":
			return "", errGuideQuit
		}
		if strings.HasPrefix(line, "//") {
			line = line[1:]
		}
		if strings.IndexFunc(line, unicode.IsControl) >= 0 {
			fmt.Fprintln(g.env.stdout, "Control characters are not accepted.")
			continue
		}
		return line, nil
	}
}

func (g *guide) chooseSource(fileOnly bool, window time.Duration) error {
	choice := 2
	if !fileOnly {
		var err error
		choice, err = g.menu("Source", "Live interface", "Capture file")
		if err != nil {
			return err
		}
	}
	if choice == 2 {
		for {
			name, err := g.ask("Capture file")
			if err != nil {
				return err
			}
			if name == "" {
				fmt.Fprintln(g.env.stdout, "Enter a PCAP or PCAPNG path.")
				continue
			}
			if strings.Contains(name, ",") || strings.TrimSpace(name) != name {
				fmt.Fprintln(g.env.stdout, "The direct diagnosis command splits commas and trims outer spaces. Choose a path without those ambiguities.")
				continue
			}
			if strings.HasPrefix(name, "-") {
				name = "." + string(filepath.Separator) + name
			}
			st, err := os.Stat(name)
			if err != nil || !st.Mode().IsRegular() {
				fmt.Fprintf(g.env.stdout, "Cannot read a regular capture file at %q.\n", name)
				continue
			}
			g.source.pcap = name
			fmt.Fprintln(g.env.stdout, "Offline analysis: no traffic is transmitted; this host's prefixes are not used.")
			return nil
		}
	}
	ifs, err := interfaces.List()
	if err != nil {
		return err
	}
	var choices []string
	for _, i := range ifs {
		state := i.OperState
		if !i.Up {
			state = "administratively down"
		}
		prefixes := append(append([]netip.Prefix{}, i.IPv4...), i.IPv6...)
		choices = append(choices, fmt.Sprintf("%s (link %s; addresses %v)", i.Name, state, prefixes))
	}
	fmt.Fprintln(g.env.stdout, "Interfaces are read locally. Selecting one does not enable or configure it.")
	n, err := g.menu("Interface", choices...)
	if err != nil {
		return err
	}
	g.source.iface = ifs[n-1].Name
	if strings.Contains(g.source.iface, ",") {
		return fmt.Errorf("interface name cannot round-trip through the direct command's comma-separated source grammar")
	}
	g.source.timeout = window
	return nil
}

func (g *guide) duration(window time.Duration) error {
	if g.source.pcap != "" {
		return nil
	}
	for {
		value, err := g.ask(fmt.Sprintf("Observation duration [%s]", window))
		if err != nil {
			return err
		}
		if value == "" {
			g.source.timeout = window
			return nil
		}
		duration, err := time.ParseDuration(value)
		if err == nil && duration > 0 {
			g.source.timeout = duration
			return nil
		}
		fmt.Fprintln(g.env.stdout, "Enter a positive duration, for example 5s or 1m.")
	}
}

func (g *guide) sourceArgs() []string {
	args := []string{"--quiet"}
	if g.source.pcap != "" {
		return append(args, "--pcap", g.source.pcap)
	}
	return append(args, "-i", g.source.iface, "--timeout", g.source.timeout.String())
}

func (g *guide) deviceArgs() []string {
	if g.source.pcap != "" {
		return []string{"read", g.source.pcap, "--devices", "--quiet"}
	}
	return append([]string{"discover"}, g.sourceArgs()...)
}

func (g *guide) originalContext() error {
	if g.source.pcap == "" || g.localAsked {
		return nil
	}
	for {
		value, err := g.ask("Original capture-host prefixes, comma-separated [unknown]")
		if err != nil {
			return err
		}
		flags := g.source
		flags.local = value
		if _, err := diagnosisContext(&flags); err != nil {
			fmt.Fprintf(g.env.stdout, "%v\n", err)
			continue
		}
		g.source.local, g.localAsked = value, true
		if value == "" {
			fmt.Fprintln(g.env.stdout, "Original prefixes are unknown; local-subnet conclusions cannot be established.")
		}
		return nil
	}
}

func (g *guide) diagnosis(target string, epicsOnly bool) error {
	if !epicsOnly {
		if err := g.originalContext(); err != nil {
			return err
		}
	}
	args := []string{"diagnose"}
	if epicsOnly {
		args = []string{"epics", "diagnose"}
	}
	if target != "" {
		args = append(args, target)
	}
	args = append(args, g.sourceArgs()...)
	if !epicsOnly && g.source.local != "" {
		args = append(args, "--local", g.source.local)
	}
	g.execute(args)
	return nil
}

func (g *guide) findPV() error {
	for {
		pv, err := g.ask("PV name [all EPICS activity]")
		if err != nil {
			return err
		}
		if len(pv) > 1 && strings.HasPrefix(pv, "-") {
			fmt.Fprintln(g.env.stdout, "The direct find command cannot represent a PV beginning with a dash. Enter another name.")
			continue
		}
		g.pv = pv
		window := defaultFindWindow
		if pv == "" {
			window = defaultDiagnoseWindow
		}
		if err := g.duration(window); err != nil {
			return err
		}
		if pv == "" {
			return g.diagnosis("", true)
		}
		g.execute(append([]string{"epics", "find", pv}, g.sourceArgs()...))
		return nil
	}
}

func (g *guide) captureView() error {
	n, err := g.menu("Capture view", "Events", "Devices", "General diagnosis", "EPICS diagnosis", "Find a PV")
	if err != nil {
		return err
	}
	switch n {
	case 1:
		g.execute([]string{"read", g.source.pcap, "--quiet"})
	case 2:
		g.execute(g.deviceArgs())
	case 3:
		return g.diagnosis("", false)
	case 4:
		return g.diagnosis("", true)
	case 5:
		return g.findPV()
	}
	return nil
}

func (g *guide) execute(args []string) {
	if g.ctx.Err() != nil {
		g.status = exitError
		return
	}
	g.args = append([]string{}, args...)
	fmt.Fprintf(g.env.stdout, "\nCommand: %s\n", directCommand(args))
	g.result = executeOperation(g.ctx, g.env, args)
	g.status = g.result.Code
	g.entries = append(g.entries, g.result.Added...)
	fmt.Fprintf(g.env.stdout, "Operation finished (exit %d).\n", g.status)
	if g.status == exitPrivilege {
		fmt.Fprintln(g.env.stdout, "Permission is insufficient. Run the displayed command with suitable privileges, or choose a capture file. This guide does not invoke sudo.")
	}
	if g.result.Devices != nil && len(g.result.Devices.Devices) == 0 {
		fmt.Fprintln(g.env.stdout, "No devices were observed; a silent device or traffic outside this capture can still exist.")
	}
	if g.hasCode(diagnose.CodeDuplicateAddress, diagnose.CodeCAMultipleServers, diagnose.CodePVAMultipleServers) {
		fmt.Fprintln(g.env.stdout, "Multiple claims need inspection. The guide does not repair device or server configuration.")
	}
}

func (g *guide) hasCode(codes ...string) bool {
	r := g.result.Report
	if r == nil {
		return false
	}
	for _, list := range [][]diagnose.Finding{r.Observed, r.Inferred, r.Recommended} {
		for _, f := range list {
			for _, c := range codes {
				if f.Code == c {
					return true
				}
			}
		}
	}
	return false
}

func (g *guide) observedAddresses() []string {
	var addresses []string
	seen := map[string]bool{}
	if g.result.Devices != nil {
		for _, d := range g.result.Devices.Devices {
			for _, a := range d.IPv4 {
				if !seen[a.Address] {
					addresses = append(addresses, a.Address)
					seen[a.Address] = true
				}
			}
		}
	}
	sort.Strings(addresses)
	return addresses
}

func (g *guide) connectionTargets() []string {
	var targets []string
	if g.source.pcap != "" || g.hasCode(diagnose.CodeDuplicateAddress) || g.result.Report == nil {
		return targets
	}
	for _, f := range g.result.Report.Recommended {
		if f.Code == diagnose.CodeTemporaryAddress && f.Data["candidate"] != "" && f.Data["target"] != "" {
			targets = append(targets, f.Data["target"])
		}
	}
	return targets
}

func (g *guide) next(purpose int) error {
	for {
		if err := g.ctx.Err(); err != nil {
			return err
		}
		choices := []string{"Repeat the displayed operation", "Change source or purpose", "Finish"}
		actions := []string{"repeat", "source", "quit"}
		add := func(text, action string) { choices = append(choices, text); actions = append(actions, action) }
		addresses := g.observedAddresses()
		targets := g.connectionTargets()
		if len(addresses) > 0 {
			add("Diagnose an observed IPv4 address", "diagnose")
		}
		if purpose == 2 {
			add("Inspect another PV or all EPICS activity", "pv")
		}
		if g.source.pcap != "" {
			add("Choose another capture view", "view")
		}
		if len(targets) > 0 {
			add("Connect temporarily to a recommended target (active)", "connect")
		}
		if g.source.pcap == "" {
			if purpose == 1 {
				add("Send bounded ARP requests (active)", "arp")
			}
			if g.pv != "" && g.hasCode("nothing-seen", diagnose.CodeCASearchUnanswered, diagnose.CodePVASearchUnanswered, "no-answer") {
				add("Send an explicit PV search (active)", "search")
			}
		}
		choice, err := g.menu("Next action", choices...)
		if err != nil {
			return err
		}
		switch actions[choice-1] {
		case "repeat":
			// Repetition re-enters the real command, including its confirmation.
			g.execute(g.args)
		case "source":
			return errGuideBack
		case "quit":
			return errGuideQuit
		case "pv":
			err = g.findPV()
		case "view":
			err = g.captureView()
		case "diagnose":
			var n int
			n, err = g.menu("Observed IPv4 address", addresses...)
			if err == nil {
				err = g.diagnosis(addresses[n-1], false)
			}
		case "connect":
			var n int
			n, err = g.menu("Target for temporary connection", targets...)
			if err == nil {
				g.execute(append([]string{"connect", targets[n-1]}, g.sourceArgs()...))
			}
		case "arp":
			err = g.arp()
		case "search":
			err = g.search()
		}
		if errors.Is(err, errGuideBack) {
			continue
		}
		if err != nil {
			return err
		}
	}
}

func (g *guide) arp() error {
	prefix, err := g.ask("Explicit IPv4 address or prefix (/24 or smaller)")
	if err != nil {
		return err
	}
	if a, err := netip.ParseAddr(prefix); err == nil && a.Is4() {
		prefix += "/32"
	}
	g.execute([]string{"probe", "-i", g.source.iface, "--arp", prefix})
	return nil
}

func (g *guide) search() error {
	protocol, err := g.menu("Search protocols", "CA and PVA", "CA", "PVA")
	if err != nil {
		return err
	}
	to, err := g.ask("Explicit destinations host[:port], comma-separated [interface broadcasts]")
	if err != nil {
		return err
	}
	fmt.Fprintln(g.env.stdout, "The interface supplies capture and broadcast context; UDP searches follow OS routing and are not bound to that interface.")
	args := append([]string{"epics", "find", g.pv, "--active", "--search", []string{"ca,pva", "ca", "pva"}[protocol-1]}, g.sourceArgs()...)
	if to != "" {
		args = append(args, "--to", to)
	}
	g.execute(args)
	return nil
}

func (g *guide) cleanup() int {
	if len(g.entries) == 0 {
		return exitOK
	}
	ctx, cancel := context.WithTimeout(context.Background(), guideCleanupTimeout)
	defer cancel()
	mgr := networkcfg.New(version)
	code := exitOK
	for i := len(g.entries) - 1; i >= 0; i-- {
		entry := g.entries[i]
		ran, err := mgr.RemoveOwned(ctx, entry)
		if err != nil {
			code = activeExit(err)
			fmt.Fprintf(g.env.stdout, "Cleanup failed for %s on %s: %v\n", entry.Address, entry.Interface, err)
			fmt.Fprintf(g.env.stdout, "Inspect %s and the interface before selective recovery: %s\n", mgr.Path, directCommand([]string{"disconnect", "-i", entry.Interface, entry.Address.String()}))
			fmt.Fprintln(g.env.stdout, "Selective disconnect does not check this guide's full ownership or shared-subnet dependencies. Resolve the reported condition before running it; primary deletion can also remove manual secondary addresses.")
			continue
		}
		if ran {
			fmt.Fprintf(g.env.stdout, "Removed this guide's temporary address %s from %s.\n", entry.Address, entry.Interface)
		} else {
			fmt.Fprintf(g.env.stdout, "This guide's address %s was already absent; its record was removed.\n", entry.Address)
		}
	}
	return code
}

// directCommand quotes each literal argument for Bash. No displayed
// command is executed by a shell; the dispatcher receives the original argv.
func directCommand(args []string) string {
	executable, err := os.Executable()
	if err != nil {
		executable = "wirepup"
	}
	words := append([]string{executable}, args...)
	quoted := make([]string, len(words))
	for i, word := range words {
		quoted[i] = "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
	}
	return strings.Join(quoted, " ")
}
