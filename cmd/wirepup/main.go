// Command wirepup is the CLI entry point. It parses the subcommand and
// its flags, runs it, and maps errors to the exit codes documented in
// docs/cli-design.md. Passive commands never reach the active or
// network-configuration packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture/afpacket"
)

// version is set by the build (see Makefile).
var version = "dev"

// Exit codes from docs/cli-design.md.
const (
	exitOK          = 0
	exitError       = 1
	exitUsage       = 2
	exitPrivilege   = 3
	exitCapture     = 4
	exitNotObserved = 5
	exitUnsafe      = 6
)

// globalFlags are accepted by every command that captures or renders.
type globalFlags struct {
	iface     string
	json      bool
	quiet     bool
	verbose   bool
	timeout   time.Duration
	noPromisc bool
	ouiFile   string
	protocols string
	pcap      string
	local     string
}

func (g *globalFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&g.iface, "i", "", "interface to capture on")
	fs.StringVar(&g.iface, "interface", "", "interface to capture on")
	fs.BoolVar(&g.json, "json", false, "machine-readable JSON output")
	fs.BoolVar(&g.quiet, "quiet", false, "suppress progress messages")
	fs.BoolVar(&g.verbose, "verbose", false, "show frame-level observations")
	fs.DurationVar(&g.timeout, "timeout", 0, "stop after this duration (0 = until interrupted)")
	fs.BoolVar(&g.noPromisc, "no-promisc", false, "do not enable promiscuous mode")
	fs.StringVar(&g.ouiFile, "oui-file", "", "IEEE oui.txt to use for vendor hints")
	fs.StringVar(&g.protocols, "protocol", "", "comma-separated protocol filter (for example arp,lldp)")
	fs.StringVar(&g.pcap, "pcap", "", "read from a capture file instead of an interface")
	fs.StringVar(&g.local, "local", "", "local IPv4/IPv6 prefixes of the capture host (comma-separated), for --pcap")
}

// command is one subcommand.
type command struct {
	name  string
	brief string
	run   func(ctx context.Context, env *env, args []string) int
}

// env carries the writers so that tests can capture output.
type env struct {
	stdout io.Writer
	stderr io.Writer
}

var commands = []command{
	{"interfaces", "list local interfaces (passive)", runInterfaces},
	{"observe", "print a passive event stream", runObserve},
	{"discover", "passive device discovery", runDiscover},
	{"capture", "write frames to a PCAP/PCAPNG file (passive)", runCapture},
	{"read", "replay a capture file offline", runRead},
	{"diagnose", "rule-based diagnosis (passive)", runDiagnose},
	{"epics", "EPICS CA/PVA tools: observe, find, diagnose", runEPICS},
	{"probe", "bounded ARP sweep (ACTIVE: transmits)", runProbe},
	{"connect", "add a temporary secondary IPv4 address (ACTIVE: changes host)", runConnect},
	{"disconnect", "remove WirePup-created temporary addresses (ACTIVE: changes host)", runDisconnect},
	{"version", "print the version", runVersion},
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, &env{stdout: os.Stdout, stderr: os.Stderr}, os.Args[1:]))
}

func run(ctx context.Context, e *env, args []string) int {
	if len(args) == 0 {
		usage(e.stderr)
		return exitUsage
	}
	name := args[0]
	if name == "-h" || name == "--help" || name == "help" {
		usage(e.stdout)
		return exitOK
	}
	for _, c := range commands {
		if c.name == name {
			return c.run(ctx, e, args[1:])
		}
	}
	fmt.Fprintf(e.stderr, "wirepup: unknown command %q\n\n", name)
	usage(e.stderr)
	return exitUsage
}

func usage(w io.Writer) {
	fmt.Fprintln(w, "usage: wirepup <command> [flags]")
	fmt.Fprintln(w)
	names := make([]string, 0, len(commands))
	for _, c := range commands {
		names = append(names, c.name)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, c := range commands {
			if c.name == n {
				fmt.Fprintf(w, "  %-12s %s\n", c.name, c.brief)
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Passive commands transmit nothing and change no host configuration.")
	fmt.Fprintln(w, "probe, connect, and disconnect are the only commands that transmit or change the host.")
}

// newFlagSet returns a flag set that reports usage errors without exiting.
func newFlagSet(name string, e *env) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(e.stderr)
	return fs
}

// parse handles the flag errors uniformly; ok is false when the caller
// must return the given exit code.
func parse(fs *flag.FlagSet, args []string) (ok bool, code int) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return false, exitOK
		}
		return false, exitUsage
	}
	return true, exitOK
}

// exitCodeFor maps an error to the documented exit code.
func exitCodeFor(err error) int {
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, afpacket.ErrPrivilege):
		return exitPrivilege
	case errors.Is(err, errCapture):
		return exitCapture
	case errors.Is(err, errUsage):
		return exitUsage
	case errors.Is(err, errNotObserved):
		return exitNotObserved
	default:
		return exitError
	}
}

var (
	errUsage       = errors.New("invalid arguments")
	errCapture     = errors.New("capture failed")
	errNotObserved = errors.New("requested target not observed")
)

func runVersion(ctx context.Context, e *env, args []string) int {
	fmt.Fprintf(e.stdout, "wirepup %s\n", version)
	return exitOK
}

// protocolSet parses the --protocol flag into a set of names.
func protocolSet(spec string) map[string]bool {
	set := map[string]bool{}
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(strings.ToLower(p))
		if p != "" {
			set[p] = true
		}
	}
	return set
}
