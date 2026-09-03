package diagnose

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

var (
	caClient = netip.MustParseAddr("10.20.4.88")
	caBcast  = netip.MustParseAddr("10.20.4.255")
	caServer = netip.MustParseAddr("10.20.4.31")
	caOther  = netip.MustParseAddr("10.20.4.32")
	caLocal  = netip.MustParsePrefix("10.20.4.88/24")
	zero     = netip.MustParseAddr("0.0.0.0")
	bcastAll = netip.MustParseAddr("255.255.255.255")
)

func TestDHCPNoOfferAndAutoIPFallback(t *testing.T) {
	discover := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, bcastAll, zero, 67, 68, fixtures.DHCP(1, 1, 0x2001, fixtures.DeviceMAC, netip.Addr{}))
	tbl := tableFrom(t, discover, discover, fixtures.ARPProbe(fixtures.DeviceMAC, netip.MustParseAddr("169.254.22.31")), fixtures.ARPAnnounce(fixtures.DeviceMAC, netip.MustParseAddr("169.254.22.31")))
	r := RunAll(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.Addr{}, Options{End: fixtures.Epoch.Add(10 * time.Second)})
	if !strings.Contains(codes(r.Observed), CodeDHCPNoOffer) || !strings.Contains(codes(r.Inferred), CodeDHCPNoOffer) || !strings.Contains(codes(r.Recommended), CodeDHCPNoOffer) {
		t.Fatalf("dhcp: observed %s inferred %s recommended %s", codes(r.Observed), codes(r.Inferred), codes(r.Recommended))
	}
	found := false
	for _, f := range r.Inferred {
		if f.Code == CodeAutoIPFallback && strings.Contains(f.Text, "Auto-IP fallback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("auto-ip fallback missing: %+v", r.Inferred)
	}
	// Within the grace period the discover is not yet a finding.
	r = RunAll(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.Addr{}, Options{End: fixtures.Epoch.Add(2 * time.Second)})
	if strings.Contains(codes(r.Observed), CodeDHCPNoOffer) {
		t.Fatal("no-offer reported inside the grace period")
	}
}

func TestCARules(t *testing.T) {
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(1, "DUP:PV", false))
	reply1 := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, 5064, ca.SearchReplyDatagram(1, 5064))
	reply2 := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.SwitchMAC, caClient, caOther, 40000, 5064, ca.SearchReplyDatagram(1, 5064))
	missing := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(2, "MISSING:PV", false))
	foreign := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, netip.MustParseAddr("10.99.0.255"), caClient, 5064, 40000, ca.SearchDatagram(3, "FAR:PV", false))
	beaconOnly := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, caBcast, netip.MustParseAddr("10.20.4.40"), 5065, 5064, ca.BeaconDatagram(5064, 1, netip.MustParseAddr("10.20.4.40")))
	tbl := tableFrom(t, search, reply1, reply2, missing, foreign, beaconOnly)
	r := RunAll(ContextFromPrefixes("enp3s0", []netip.Prefix{caLocal}), tbl, netip.Addr{}, Options{EPICSOnly: true})
	for _, want := range []string{CodeCAMultipleServers, CodeCASearchUnanswered, CodeCAServerSeen} {
		if !strings.Contains(codes(r.Observed), want) {
			t.Fatalf("observed missing %s: %s", want, codes(r.Observed))
		}
	}
	for _, want := range []string{CodeCAMultipleServers, CodeCASearchUnanswered, CodeCASearchDestination, CodeCABeaconOnly} {
		if !strings.Contains(codes(r.Inferred), want) {
			t.Fatalf("inferred missing %s: %s", want, codes(r.Inferred))
		}
	}
	if strings.Contains(codes(r.Observed), CodeLocalContext) {
		t.Fatal("EPICSOnly ran the subnet rules")
	}
	for _, f := range r.Inferred {
		if f.Code == CodeCASearchUnanswered && !strings.Contains(f.Text, "not proof") {
			t.Fatalf("wording: %s", f.Text)
		}
	}
}

func TestPVARulesAndRestart(t *testing.T) {
	g1 := [12]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	g2 := [12]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5076, 40000, pva.SearchDatagram(1, 1, "MISSING:PV", true, false))
	b1 := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, 5076, 5076, pva.BeaconDatagram(g1, 1, 1, netip.Addr{}, 5075))
	b2 := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, 5076, 5076, pva.BeaconDatagram(g2, 1, 1, netip.Addr{}, 5075))
	tbl := tableFrom(t, search, b1, b2)
	r := RunAll(ContextFromPrefixes("enp3s0", []netip.Prefix{caLocal}), tbl, netip.Addr{}, Options{EPICSOnly: true})
	if !strings.Contains(codes(r.Observed), CodePVASearchUnanswered) || !strings.Contains(codes(r.Inferred), CodePVAServerRestart) {
		t.Fatalf("observed %s inferred %s", codes(r.Observed), codes(r.Inferred))
	}
}

func TestSourceDifference(t *testing.T) {
	tbl := tableFrom(t)
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(1, "A:B", false))
	applyFrom(t, tbl, "enp3s0", search)
	applyFrom(t, tbl, "wlp2s0", fixtures.ARPAnnounce(fixtures.DeviceMAC, netip.MustParseAddr("10.20.30.42")))
	r := RunAll(ContextFromPrefixes("enp3s0", []netip.Prefix{caLocal}), tbl, netip.Addr{}, Options{EPICSOnly: true})
	if !strings.Contains(codes(r.Observed), CodeSourceDifference) || !strings.Contains(codes(r.Inferred), CodeSourceDifference) {
		t.Fatalf("observed %s inferred %s", codes(r.Observed), codes(r.Inferred))
	}
}
