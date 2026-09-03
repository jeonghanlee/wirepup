package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureDir = "../../testdata/pcap"
	goldenDir  = "../../testdata/golden"
	ouiFixture = "../../testdata/fixtures/oui/oui.txt"
	updateEnv  = "WIREPUP_UPDATE_GOLDEN"
)

// goldenCases replay committed fixtures through the real CLI and compare
// the JSON Lines output byte for byte with the committed golden files.
// Set WIREPUP_UPDATE_GOLDEN=1 to regenerate after a deliberate change.
var goldenCases = []struct {
	name string
	args []string
}{
	{"arp-autoip-selection.events", []string{"read", "--json", "--quiet", filepath.Join(fixtureDir, "arp-autoip-selection.pcap")}},
	{"dhcp-success.events", []string{"read", "--json", "--quiet", "--verbose", filepath.Join(fixtureDir, "dhcp-success.pcap")}},
	{"dhcp-success.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "dhcp-success.pcap")}},
	{"dhcp-no-offer.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "dhcp-no-offer.pcap")}},
	{"lldp-single-neighbor.events", []string{"read", "--json", "--quiet", filepath.Join(fixtureDir, "lldp-single-neighbor.pcapng")}},
	{"lldp-single-neighbor.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "lldp-single-neighbor.pcap")}},
	{"ipv6-dad.events", []string{"read", "--json", "--quiet", "--verbose", filepath.Join(fixtureDir, "ipv6-dad.pcap")}},
	{"ipv6-dad.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "ipv6-dad.pcap")}},
	{"vlan-tagged-arp.events", []string{"read", "--json", "--quiet", "--verbose", filepath.Join(fixtureDir, "vlan-tagged-arp.pcap")}},
	{"same-l2-different-subnet.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "same-l2-different-subnet.pcap")}},
	{"same-l2-different-subnet.diagnosis", []string{"diagnose", "--pcap", filepath.Join(fixtureDir, "same-l2-different-subnet.pcap"), "--local", "10.20.30.51/24", "--json", "--quiet", "--oui-file", ouiFixture}},
	{"same-l2-different-subnet.target", []string{"diagnose", "192.168.1.100", "--pcap", filepath.Join(fixtureDir, "same-l2-different-subnet.pcap"), "--local", "10.20.30.51/24", "--json", "--quiet", "--oui-file", ouiFixture}},
}

func TestGoldenJSON(t *testing.T) {
	update := os.Getenv(updateEnv) != ""
	for _, c := range goldenCases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			code := run(context.Background(), &env{stdout: &out, stderr: &errb}, c.args)
			if code != exitOK {
				t.Fatalf("exit %d: %s", code, errb.String())
			}
			path := filepath.Join(goldenDir, c.name+".jsonl")
			if update {
				if err := os.WriteFile(path, out.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file %s (set %s=1 to create): %v", path, updateEnv, err)
			}
			if !bytes.Equal(want, out.Bytes()) {
				t.Fatalf("output differs from %s\n--- got ---\n%s\n--- want ---\n%s", path, out.String(), want)
			}
			if !strings.Contains(out.String(), `"schema":`) {
				t.Fatal("no schema field in output")
			}
		})
	}
}

func TestReadTextAndErrors(t *testing.T) {
	code, out, _ := runCLI(t, "read", "--quiet", filepath.Join(fixtureDir, "dhcp-success.pcap"))
	if code != exitOK || !strings.Contains(out, "dhcp discover from 00:80:f4:12:34:56 (ioc-pc)") || !strings.Contains(out, "arp announcement 10.20.30.42") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if code, _, errs := runCLI(t, "read"); code != exitUsage || !strings.Contains(errs, "capture file") {
		t.Fatalf("no file: %d %s", code, errs)
	}
	if code, _, _ := runCLI(t, "read", "--quiet", "/nonexistent.pcap"); code != exitError {
		t.Fatalf("missing file exit %d", code)
	}
	if code, _, errs := runCLI(t, "read", "a.pcap", "b.pcap"); code != exitUsage || !strings.Contains(errs, "unexpected") {
		t.Fatalf("two files: %d %s", code, errs)
	}
	code, out, _ = runCLI(t, "read", "--protocol", "arp", "--quiet", filepath.Join(fixtureDir, "dhcp-success.pcap"))
	if code != exitOK || strings.Contains(out, "dhcp") || !strings.Contains(out, "arp announcement") {
		t.Fatalf("protocol filter:\n%s", out)
	}
	if code, _, errs := runCLI(t, "observe", "--pcap", "x.pcap", "-i", "lo"); code != exitUsage || !strings.Contains(errs, "not both") {
		t.Fatalf("pcap and iface: %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "capture", "-i", "lo"); code != exitUsage || !strings.Contains(errs, "output file") {
		t.Fatalf("capture without output: %d %s", code, errs)
	}
}

func TestDiagnoseTextAndExitCodes(t *testing.T) {
	pcap := filepath.Join(fixtureDir, "same-l2-different-subnet.pcap")
	code, out, _ := runCLI(t, "diagnose", "--pcap", pcap, "--local", "10.20.30.51/24", "--quiet", "--oui-file", ouiFixture)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"Observed", "local capture IPv4 = 10.20.30.51/24", "Inferred", "outside every configured local IPv4 subnet", "Recommended", "192.168.1.254", "Executed", "(none", "explicit connect"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	if code, out, _ := runCLI(t, "diagnose", "10.99.99.99", "--pcap", pcap, "--local", "10.20.30.51/24", "--quiet"); code != exitNotObserved || !strings.Contains(out, "not observed") {
		t.Fatalf("unseen target: exit %d\n%s", code, out)
	}
	if code, _, errs := runCLI(t, "diagnose", "not-an-ip", "--pcap", pcap, "--quiet"); code != exitUsage || !strings.Contains(errs, "IPv4 address") {
		t.Fatalf("bad target: %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "diagnose", "--pcap", pcap, "--local", "junk", "--quiet"); code != exitUsage || !strings.Contains(errs, "--local") {
		t.Fatalf("bad local: %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "diagnose", "--quiet"); code != exitUsage || !strings.Contains(errs, "interface") {
		t.Fatalf("no source: %d %s", code, errs)
	}
}
