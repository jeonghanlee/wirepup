package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// TestDiscoverIngestFollowsProtocolSet replays a capture with DHCP and
// ARP through the real device-table path: with a protocol set that
// matches none of its packets the inventory must stay empty, so that a
// kernel rule wider than the request never widens the device table.
func TestDiscoverIngestFollowsProtocolSet(t *testing.T) {
	pcap := filepath.Join(fixtureDir, "dhcp-success.pcap")
	devices := func(args ...string) int {
		code, out, errs := runCLI(t, append([]string{"read", "--devices", "--json", "--quiet"}, args...)...)
		if code != exitOK {
			t.Fatalf("%v: exit %d: %s", args, code, errs)
		}
		// The output is a stream of device events followed by the devices
		// document; the document is the last value.
		var doc struct {
			Devices []json.RawMessage `json:"devices"`
		}
		dec := json.NewDecoder(strings.NewReader(out))
		for dec.More() {
			doc.Devices = nil
			if err := dec.Decode(&doc); err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
		}
		return len(doc.Devices)
	}
	if n := devices(pcap); n == 0 {
		t.Fatal("no devices without a protocol filter")
	}
	if n := devices("--protocol", "lldp", pcap); n != 0 {
		t.Fatalf("%d device(s) ingested outside the requested protocol set", n)
	}
	if n := devices("--protocol", "arp", pcap); n == 0 {
		t.Fatal("no devices from the ARP packets of the capture")
	}
}

// TestFindValidatesProtocolName checks that epics find rejects an
// unknown --protocol name like every other capturing command, although
// it does not apply the filter.
func TestFindValidatesProtocolName(t *testing.T) {
	pcap := filepath.Join(fixtureDir, "ca-search-no-response.pcap")
	code, _, errs := runCLI(t, "epics", "find", "MISSING:PV", "--pcap", pcap, "--quiet", "--protocol", "bogus")
	if code != exitUsage || !strings.Contains(errs, "unknown protocol") {
		t.Fatalf("bogus protocol: exit %d, stderr %q", code, errs)
	}
	if code, _, errs := runCLI(t, "epics", "find", "MISSING:PV", "--pcap", pcap, "--quiet", "--protocol", "ca"); code == exitUsage {
		t.Fatalf("known protocol rejected: %s", errs)
	}
}
