package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// These packets came from real Linux, DHCP, and EPICS actors in the VM.
// Replay the stored bytes through the CLI without requiring root or a VM.
func TestRecordedVMCaptures(t *testing.T) {
	dir := "../../tests/vm/pcap"
	cases := []struct {
		capture string
		args    []string
		codes   []string
	}{
		{"epics-reads", []string{"epics", "find", "WP:VALUE"}, []string{"ca-search-answer", "pva-search-answer"}},
		{"active-ca", []string{"epics", "find", "WP:VALUE"}, []string{"ca-search-answer"}},
		{"active-pva", []string{"epics", "find", "WP:VALUE"}, []string{"pva-search-answer"}},
		{"duplicate-ca", []string{"epics", "find", "WP:VALUE"}, []string{"ca-multiple-servers"}},
		{"duplicate-pva", []string{"epics", "find", "WP:VALUE"}, []string{"pva-multiple-servers"}},
		{"missing-pv", []string{"diagnose", "--epics"}, []string{"ca-search-no-response"}},
		{"dhcp-no-offer", []string{"diagnose", "--local", "192.0.2.1/24"}, []string{"dhcp-discover-no-offer"}},
	}
	for _, c := range cases {
		t.Run(c.capture, func(t *testing.T) {
			args := append(c.args, "--pcap", filepath.Join(dir, c.capture+".pcap"), "--json", "--quiet")
			code, out, errs := runCLI(t, args...)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errs)
			}
			var report map[string]json.RawMessage
			if err := json.Unmarshal([]byte(out), &report); err != nil {
				t.Fatal(err)
			}
			found := make(map[string]bool)
			for _, section := range []string{"observed", "inferred"} {
				var findings []struct{ Code string }
				if err := json.Unmarshal(report[section], &findings); err != nil {
					t.Fatal(err)
				}
				for _, finding := range findings {
					found[finding.Code] = true
				}
			}
			for _, want := range c.codes {
				if !found[want] {
					t.Errorf("missing %s: %s", want, out)
				}
			}
		})
	}
	code, out, errs := runCLI(t, "read", filepath.Join(dir, "dhcp-success.pcap"), "--json", "--quiet")
	if code != exitOK {
		t.Fatalf("DHCP replay exit %d: %s", code, errs)
	}
	ack := false
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var event struct {
			Fields map[string]any
		}
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatal(err)
		}
		ack = ack || event.Fields["message_type"] == "ack"
	}
	if !ack {
		t.Fatal("real DHCP lease capture lost its ACK")
	}
}
