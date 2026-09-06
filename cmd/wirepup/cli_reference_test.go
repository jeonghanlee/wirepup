package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Help is produced by the real flag registrations, so a newly introduced
// public flag must acquire a reference entry before this check can pass.
func TestCLIReferenceCoversCommandHelp(t *testing.T) {
	doc, err := os.ReadFile("../../docs/cli-reference.md")
	if err != nil {
		t.Fatal(err)
	}
	flagLine := regexp.MustCompile(`(?m)^  -([a-z][a-z-]*)\b`)
	optionEntries := strings.Join(regexp.MustCompile(`(?m)^### .+$`).FindAllString(string(doc), -1), "\n")
	for _, c := range commands {
		paths := [][]string{{c.name}}
		if c.name == "epics" {
			paths = [][]string{{"epics", "observe"}, {"epics", "find"}, {"epics", "diagnose"}}
		}
		for _, path := range paths {
			t.Run(strings.Join(path, "/"), func(t *testing.T) {
				if !bytes.Contains(doc, []byte("`"+strings.Join(path, " "))) {
					t.Fatal("command missing from reference")
				}
				if c.name == "version" {
					return
				}
				code, _, help := runCLI(t, append(path, "--help")...)
				if code != exitOK {
					t.Fatalf("help exit %d: %s", code, help)
				}
				flags := flagLine.FindAllStringSubmatch(help, -1)
				if len(flags) == 0 {
					t.Fatalf("no registered options in help: %s", help)
				}
				for _, flag := range flags {
					prefix := "--"
					if len(flag[1]) == 1 {
						prefix = "-"
					}
					if !strings.Contains(optionEntries, "`"+prefix+flag[1]+"`") {
						t.Errorf("option %s has no reference entry", flag[1])
					}
				}
			})
		}
	}
}

// Execute the built command entry path with stdin closed. This protects
// scripts when terminal-only guidance is introduced alongside direct dispatch.
func TestDirectInvocationNonTerminal(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "wirepup")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	build := exec.CommandContext(ctx, "go", "build", "-o", binary, ".")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	cases := []struct {
		name string
		args []string
		code int
		err  string
	}{
		{"no arguments", nil, exitUsage, "usage:"},
		{"help", []string{"--help"}, exitOK, ""},
		{"unknown command", []string{"not-a-command"}, exitUsage, "unknown command"},
		{"leaf help", []string{"epics", "find", "--help"}, exitOK, "Usage of"},
		{"missing input", []string{"read"}, exitUsage, "capture file is required"},
		{"source conflict", []string{"observe", "--pcap", filepath.Join(fixtureDir, "ca-search-response.pcap"), "-i", "lo"}, exitUsage, "not both"},
		{"unknown protocol", []string{"epics", "find", "PV", "--protocol", "bogus"}, exitUsage, "unknown protocol"},
		{"confirmation refused", []string{"probe", "-i", "lo", "--arp", "192.0.2.1/32"}, exitUsage, "no terminal to confirm"},
		{"unobserved PV", []string{"epics", "find", "NOPE:PV", "--pcap", filepath.Join(fixtureDir, "ca-search-response.pcap"), "--quiet"}, exitNotObserved, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, tc.args...)
			var out, errs bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &errs
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("non-terminal invocation did not finish: %v", ctx.Err())
			}
			if cmd.ProcessState == nil || cmd.ProcessState.ExitCode() != tc.code {
				t.Fatalf("exit: %v; want %d; stderr: %s", err, tc.code, errs.String())
			}
			if !strings.Contains(errs.String(), tc.err) {
				t.Fatalf("stderr missing %q: %s", tc.err, errs.String())
			}
		})
	}
	for _, name := range []string{"dhcp-success.events", "same-l2-different-subnet.target", "ca-duplicate-servers.find"} {
		found := false
		for _, c := range goldenCases {
			if c.name != name {
				continue
			}
			found = true
			t.Run(name, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				out, err := exec.CommandContext(ctx, binary, c.args...).Output()
				if err != nil {
					t.Fatalf("direct CLI: %v", err)
				}
				want, err := os.ReadFile(filepath.Join(goldenDir, c.name+".jsonl"))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(out, want) {
					t.Fatalf("direct CLI output differs from %s", c.name)
				}
			})
		}
		if !found {
			t.Fatalf("required golden case %s is missing", name)
		}
	}
}
