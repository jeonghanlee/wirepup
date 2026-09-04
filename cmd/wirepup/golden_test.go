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
	{"ca-search-response.events", []string{"epics", "observe", "--pcap", filepath.Join(fixtureDir, "ca-search-response.pcap"), "--json", "--quiet"}},
	{"ca-search-response.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "ca-search-response.pcap")}},
	{"ca-beacon.events", []string{"epics", "observe", "--pcap", filepath.Join(fixtureDir, "ca-beacon.pcap"), "--json", "--quiet"}},
	{"ca-duplicate-servers.find", []string{"epics", "find", "DUP:PV", "--pcap", filepath.Join(fixtureDir, "ca-duplicate-servers.pcap"), "--json", "--quiet"}},
	{"ca-search-no-response.find", []string{"epics", "find", "MISSING:PV", "--pcap", filepath.Join(fixtureDir, "ca-search-no-response.pcap"), "--json", "--quiet"}},
	{"pva-search-response.events", []string{"epics", "observe", "--pcap", filepath.Join(fixtureDir, "pva-search-response.pcap"), "--json", "--quiet"}},
	{"pva-search-response.devices", []string{"read", "--devices", "--json", "--quiet", "--oui-file", ouiFixture, filepath.Join(fixtureDir, "pva-search-response.pcap")}},
	{"pva-search-response.find", []string{"epics", "find", "MPS:SYS:STATE", "--pcap", filepath.Join(fixtureDir, "pva-search-response.pcap"), "--json", "--quiet"}},
	{"pva-beacon.events", []string{"epics", "observe", "--pcap", filepath.Join(fixtureDir, "pva-beacon.pcap"), "--json", "--quiet"}},
	{"pva-tcp-handshake.events", []string{"read", "--json", "--quiet", "--verbose", filepath.Join(fixtureDir, "pva-tcp-handshake.pcap")}},
	{"dhcp-no-offer.diagnosis", []string{"diagnose", "--pcap", filepath.Join(fixtureDir, "dhcp-no-offer.pcap"), "--local", "10.20.30.51/24", "--json", "--quiet"}},
	{"ca-duplicate-servers.diagnosis", []string{"diagnose", "--epics", "--pcap", filepath.Join(fixtureDir, "ca-duplicate-servers.pcap"), "--local", "10.20.4.88/24", "--json", "--quiet"}},
	{"two-sources.diagnosis", []string{"diagnose", "--epics", "--pcap", filepath.Join(fixtureDir, "ca-search-no-response.pcap") + "," + filepath.Join(fixtureDir, "arp-autoip-selection.pcap"), "--local", "10.20.4.88/24", "--json", "--quiet"}},
	{"epics-nothing-observed.diagnosis", []string{"diagnose", "--epics", "--pcap", filepath.Join(fixtureDir, "arp-autoip-selection.pcap"), "--local", "10.20.30.51/24", "--json", "--quiet"}},
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

func TestEPICSCommands(t *testing.T) {
	pcap := filepath.Join(fixtureDir, "ca-search-response.pcap")
	code, out, _ := runCLI(t, "epics", "observe", "--pcap", pcap, "--quiet")
	if code != exitOK || !strings.Contains(out, "CA SEARCH\n") || !strings.Contains(out, "PV           MPS:SYS:STATE") || !strings.Contains(out, "CA SEARCH RESPONSE") || !strings.Contains(out, "TCP port     5064") {
		t.Fatalf("epics observe exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "epics", "find", "MPS:SYS:STATE", "--pcap", pcap, "--quiet")
	if code != exitOK || !strings.Contains(out, "server 10.20.4.31 answered for MPS:SYS:STATE: TCP port 5064") {
		t.Fatalf("epics find exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "epics", "find", "NOPE:PV", "--pcap", pcap, "--quiet")
	if code != exitNotObserved || !strings.Contains(out, "nothing about NOPE:PV") {
		t.Fatalf("unseen pv exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "read", "--devices", "--quiet", filepath.Join(fixtureDir, "ca-search-no-response.pcap"))
	if code != exitOK || !strings.Contains(out, "CA SEARCHES WITHOUT OBSERVED RESPONSE") || !strings.Contains(out, "MISSING:PV from 10.20.4.88:40000 (x3)") {
		t.Fatalf("unanswered table:\n%s", out)
	}
	if code, _, errs := runCLI(t, "epics"); code != exitUsage || !strings.Contains(errs, "usage") {
		t.Fatalf("epics usage %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "epics", "find"); code != exitUsage || !strings.Contains(errs, "PV name") {
		t.Fatalf("find without pv %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "epics", "find", "X:Y"); code != exitUsage || !strings.Contains(errs, "--active") {
		t.Fatalf("find without source %d %s", code, errs)
	}
	if code, _, errs := runCLI(t, "epics", "find", "X:Y", "--active", "--to", "junk", "--yes"); code != exitUsage || !strings.Contains(errs, "--to") {
		t.Fatalf("bad destination %d %s", code, errs)
	}
}

func TestEPICSPVACommands(t *testing.T) {
	pcap := filepath.Join(fixtureDir, "pva-search-response.pcap")
	code, out, _ := runCLI(t, "epics", "observe", "--pcap", pcap, "--quiet")
	if code != exitOK || !strings.Contains(out, "PVA SEARCH\n") || !strings.Contains(out, "PVA SEARCH RESPONSE") || !strings.Contains(out, "GUID         57697265507570000000000") {
		t.Fatalf("pva observe exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "epics", "find", "MPS:SYS:STATE", "--pcap", pcap, "--quiet")
	if code != exitOK || !strings.Contains(out, "PVA server 10.20.4.31 answered for MPS:SYS:STATE: TCP port 5075") {
		t.Fatalf("pva find exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "read", "--devices", "--quiet", pcap)
	if code != exitOK || !strings.Contains(out, "PVA SERVERS") || !strings.Contains(out, "PVA SEARCHES WITHOUT OBSERVED RESPONSE") || !strings.Contains(out, "MISSING:PV from 10.20.4.88:40000 (x1)") {
		t.Fatalf("pva tables:\n%s", out)
	}
	code, out, _ = runCLI(t, "read", "--quiet", filepath.Join(fixtureDir, "pva-tcp-handshake.pcap"))
	if code != exitOK || !strings.Contains(out, "pva set_byte_order tcp") || !strings.Contains(out, "pva validation request from server 10.20.4.31:5075 authnz anonymous,ca") || !strings.Contains(out, "pva create channel MPS:SYS:STATE") {
		t.Fatalf("pva tcp:\n%s", out)
	}
	if code, _, errs := runCLI(t, "epics", "find", "X:Y", "--active", "--to", "10.0.0.1", "--search", "http", "--yes"); code != exitUsage || !strings.Contains(errs, "--search") {
		t.Fatalf("bad search protocol %d %s", code, errs)
	}
}

func TestDiagnoseRulesText(t *testing.T) {
	code, out, _ := runCLI(t, "diagnose", "--pcap", filepath.Join(fixtureDir, "dhcp-no-offer.pcap"), "--local", "10.20.30.51/24", "--quiet")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"DHCP discover from 00:80:f4:12:34:56", "no offer observed", "Auto-IP fallback", "check the DHCP server or relay"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in:\n%s", want, out)
		}
	}
	code, out, _ = runCLI(t, "epics", "diagnose", "--pcap", filepath.Join(fixtureDir, "ca-duplicate-servers.pcap"), "--local", "10.20.4.88/24", "--quiet")
	if code != exitOK || !strings.Contains(out, "answered by 2 servers") || strings.Contains(out, "local capture IPv4") {
		t.Fatalf("epics diagnose exit %d:\n%s", code, out)
	}
	code, out, _ = runCLI(t, "diagnose", "--epics", "--pcap", filepath.Join(fixtureDir, "ca-search-no-response.pcap")+","+filepath.Join(fixtureDir, "arp-autoip-selection.pcap"), "--quiet")
	if code != exitOK || !strings.Contains(out, "discovery activity per source") || !strings.Contains(out, "present on one source but absent on another") {
		t.Fatalf("two sources exit %d:\n%s", code, out)
	}
}
