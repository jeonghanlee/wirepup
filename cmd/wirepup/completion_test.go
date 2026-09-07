package main

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

// Run the shipped Bash handler and executable. The outer filesystem supplies
// path candidates; no CLI handler, parser, or completion function is replaced.
func TestBashCompletion(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("Linux Bash completion")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	binary := filepath.Join(dir, "wirepup")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	completion := filepath.Join(root, "completions", "wirepup.bash")
	complete := func(words ...string) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		script := `set -eu; source "$1"; shift; COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]}-1)); _wirepup; if ((${#COMPREPLY[@]})); then printf '%s\0' "${COMPREPLY[@]}"; fi`
		args := append([]string{"--noprofile", "--norc", "-c", script, "_", completion, binary}, words...)
		cmd := exec.CommandContext(ctx, "bash", args...)
		cmd.Dir = dir
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("complete %q: %v", words, err)
		}
		if len(out) == 0 {
			return nil
		}
		return strings.Split(string(bytes.TrimSuffix(out, []byte{0})), "\x00")
	}
	expect := func(name string, words, want []string) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			got := complete(words...)
			sort.Strings(got)
			sort.Strings(want)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("%q: got %q; want %q", words, got, want)
			}
		})
	}
	var commandNames []string
	for _, c := range commands {
		commandNames = append(commandNames, c.name)
	}
	commandNames = append(commandNames, "help", "-h", "--help")
	expect("command contract", []string{""}, commandNames)
	expect("command prefix", []string{"cap"}, []string{"capture"})
	expect("EPICS children", []string{"epics", ""}, []string{"observe", "find", "diagnose"})
	expect("unknown command", []string{"no-such-command", "--"}, nil)
	expect("unknown EPICS child", []string{"epics", "no-such-command", "--"}, nil)
	expect("capture option", []string{"capture", "--out"}, []string{"--output"})
	expect("single dash long option", []string{"capture", "-out"}, []string{"-output"})
	expect("invalid option omitted", []string{"observe", "--out"}, nil)
	expect("version options", []string{"version", "--"}, nil)
	expect("ARP takes a value", []string{"probe", "--arp", ""}, nil)
	expect("timeout takes a value", []string{"observe", "--timeout", "--"}, nil)
	expect("boolean does not take a value", []string{"capture", "--json", "--out"}, []string{"--output"})
	expect("boolean assigned", []string{"observe", "--json", "=", "f"}, []string{"false"})
	expect("quoted boolean assignment", []string{"observe", "'--json=f"}, []string{"--json=false"})
	expect("find flags after PV", []string{"epics", "find", "read", "--act"}, []string{"--active"})
	expect("colon in PV", []string{"epics", "find", "DEMO", ":", "PV", "--act"}, []string{"--active"})
	expect("diagnose target before flags", []string{"diagnose", "192.0.2.1", "--ep"}, []string{"--epics"})
	expect("extra positional stops parsing", []string{"observe", "unexpected", "--"}, nil)
	expect("unknown value flag", []string{"capture", "--unknown", "=", ""}, nil)
	expect("option subscript stays data", []string{"capture", "--x[$(touch injected)]", "=", ""}, nil)
	var protocols []string
	for name := range protocolFilters {
		protocols = append(protocols, name)
	}
	expect("protocol contract", []string{"observe", "--protocol", ""}, protocols)
	expect("protocol comma list", []string{"observe", "--protocol", "arp,ll"}, []string{"arp,lldp"})
	expect("protocol equals", []string{"observe", "--protocol", "=", "ll"}, []string{"lldp"})
	expect("search comma list", []string{"epics", "find", "PV", "--search", "ca,"}, []string{"ca,pva"})
	expect("search duplicate omitted", []string{"epics", "find", "PV", "--search", "ca,ca"}, nil)
	expect("destination is not queried", []string{"epics", "find", "PV", "--active", "--yes", "--to", ""}, nil)
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, ifc := range interfaces {
		names = append(names, ifc.Name)
	}
	expect("local interfaces", []string{"observe", "-i", ""}, names)
	expect("interface comma list", []string{"diagnose", "--interface", "made-up,l"}, []string{"made-up,lo"})
	expect("single interface only", []string{"observe", "-i", "made-up,l"}, nil)
	for _, name := range []string{"a capture.pcap", "a:colon.pcap", "a=equal.pcap", "-input.pcap", "-input:colon.pcap", "-input=equals.pcap", "oui file.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(dir, "a directory"), 0700); err != nil {
		t.Fatal(err)
	}
	expect("file with spaces", []string{"read", "a c"}, []string{"a capture.pcap"})
	expect("file after terminator", []string{"read", "--", "a c"}, []string{"a capture.pcap"})
	expect("dash file after terminator", []string{"read", "--", "-input.p"}, []string{"./-input.pcap"})
	expect("dash file with split colon needs relative prefix", []string{"read", "--", "-input", ":", "co"}, nil)
	expect("dash file with split equals needs relative prefix", []string{"read", "--", "-input", "=", "eq"}, nil)
	expect("dash file as flag value", []string{"observe", "--pcap", "-input.p"}, []string{"-input.pcap"})
	expect("no options after terminator", []string{"observe", "--", "--pro"}, nil)
	expect("one positional after terminator", []string{"read", "--", "file.pcap", "a c"}, nil)
	expect("quoted file", []string{"read", "'a c"}, []string{"a capture.pcap"})
	expect("double quoted file", []string{"read", `"a c`}, []string{"a capture.pcap"})
	expect("escaped file", []string{"read", `a\ c`}, []string{"a capture.pcap"})
	expect("directory", []string{"read", "a d"}, []string{"a directory/"})
	expect("file option", []string{"observe", "--pcap", "a c"}, []string{"a capture.pcap"})
	expect("output alias", []string{"capture", "-o", "a c"}, []string{"a capture.pcap"})
	expect("OUI file", []string{"discover", "--oui-file", "oui f"}, []string{"oui file.txt"})
	expect("file list", []string{"diagnose", "--pcap", "first.pcap,a c"}, []string{"first.pcap,a capture.pcap"})
	expect("colon file", []string{"read", "a", ":", "co"}, []string{"colon.pcap"})
	expect("quoted colon file", []string{"read", "'a:co"}, []string{"a:colon.pcap"})
	expect("escaped colon file", []string{"read", `a\:co`}, []string{"a:colon.pcap"})
	expect("equals file", []string{"read", "a", "=", "eq"}, []string{"equal.pcap"})
	expect("quoted equals file", []string{"read", `"a=eq`}, []string{"a=equal.pcap"})
	expect("escaped assignment", []string{"observe", `--protocol\=ll`}, []string{"--protocol=lldp"})
	expect("quoted assignment", []string{"observe", `"--protocol=ll`}, []string{"--protocol=lldp"})
	expect("value named command", []string{"read", "--oui-file", "capture", "a c"}, []string{"a capture.pcap"})
	expect("value beginning dash", []string{"read", "--oui-file", "-input.pcap", "--dev"}, []string{"--devices"})
	expect("file substitution stays data", []string{"read", "$(touch injected)"}, nil)
	if _, err := os.Stat(filepath.Join(dir, "injected")); !os.IsNotExist(err) {
		t.Fatal("completion evaluated shell input")
	}
	t.Run("completed dash paths replay a real capture", func(t *testing.T) {
		capture, err := os.ReadFile(filepath.Join(root, "testdata", "pcap", "ca-beacon.pcap"))
		if err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"-input.pcap", "-input:colon.pcap", "-input=equals.pcap"} {
			if err := os.WriteFile(filepath.Join(dir, name), capture, 0600); err != nil {
				t.Fatal(err)
			}
		}
		for _, input := range []string{"-input.p", "'-input:co", `"-input=eq`, "./-input.p", "./-input:co"} {
			got := complete("read", "--json", "--", input)
			if len(got) != 1 {
				t.Fatalf("complete %q: got %q", input, got)
			}
			cmd := exec.CommandContext(ctx, binary, "read", "--json", "--", got[0])
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil || bytes.Count(out, []byte(`"kind":"ca.beacon"`)) != 2 {
				t.Fatalf("replay completed path %q: %v\n%s", got[0], err, out)
			}
		}
	})
}
