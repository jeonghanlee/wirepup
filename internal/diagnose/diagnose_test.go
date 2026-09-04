package diagnose

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/decode"
	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

func tableFrom(t *testing.T, frames ...[]byte) *device.Table {
	t.Helper()
	tbl := device.New(device.Options{LocalMACs: []string{fixtures.LaptopMAC.String()}})
	dec := decode.New("enp3s0")
	for i, f := range frames {
		p := fixtures.Packet(i, f)
		tbl.Apply(dec.Decode(p))
	}
	return tbl
}

// applyFrom decodes frames under a named source so that per-source rules
// can be exercised.
func applyFrom(t *testing.T, tbl *device.Table, source string, frames ...[]byte) {
	t.Helper()
	dec := decode.New(source)
	for i, f := range frames {
		p := fixtures.Packet(i, f)
		p.Interface = source
		tbl.Apply(dec.Decode(p))
	}
}

func codes(fs []Finding) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Code)
	}
	return strings.Join(s, " ")
}

var (
	local  = netip.MustParsePrefix("10.20.30.51/24")
	other  = netip.MustParseAddr("192.168.1.100")
	otherG = netip.MustParseAddr("192.168.1.1")
)

func TestSameL2DifferentSubnet(t *testing.T) {
	tbl := tableFrom(t,
		fixtures.ARP(fixtures.LaptopMAC, 1, local.Addr(), netip.MustParseAddr("10.20.30.1"), make([]byte, 6)),
		fixtures.ARP(fixtures.DeviceMAC, 1, other, otherG, make([]byte, 6)),
	)
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.Addr{})
	if codes(r.Observed) != "local-context l2-evidence address-claim" {
		t.Fatalf("observed %s", codes(r.Observed))
	}
	if codes(r.Inferred) != "ipv4-outside-local-subnet same-l2-different-subnet" {
		t.Fatalf("inferred %s", codes(r.Inferred))
	}
	if len(r.Recommended) != 1 || r.Recommended[0].Data["candidate"] != "192.168.1.254" || len(r.Executed) != 0 {
		t.Fatalf("recommended %+v", r.Recommended)
	}
	if r.Inferred[1].Evidence[0].PacketID != 2 {
		t.Fatalf("evidence %+v", r.Inferred[1].Evidence)
	}
}

func TestCandidateAvoidsObservedAddresses(t *testing.T) {
	tbl := tableFrom(t,
		fixtures.ARP(fixtures.DeviceMAC, 1, other, otherG, make([]byte, 6)),
		fixtures.ARP(fixtures.ServerMAC, 1, netip.MustParseAddr("192.168.1.254"), otherG, make([]byte, 6)),
		fixtures.ARPProbe(fixtures.SwitchMAC, netip.MustParseAddr("192.168.1.253")),
	)
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, other)
	if !r.TargetSeen {
		t.Fatal("target not seen")
	}
	if len(r.Recommended) != 1 || r.Recommended[0].Data["candidate"] != "192.168.1.252" {
		t.Fatalf("recommended %+v", r.Recommended)
	}
}

func TestTargetInsideLocalSubnet(t *testing.T) {
	tbl := tableFrom(t, fixtures.ARP(fixtures.DeviceMAC, 1, netip.MustParseAddr("10.20.30.42"), netip.MustParseAddr("10.20.30.1"), make([]byte, 6)))
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.MustParseAddr("10.20.30.42"))
	if !r.TargetSeen || codes(r.Inferred) != "target-on-local-subnet" || len(r.Recommended) != 0 {
		t.Fatalf("report %+v", r)
	}
}

func TestTargetNotObserved(t *testing.T) {
	tbl := tableFrom(t, fixtures.ARP(fixtures.DeviceMAC, 1, netip.MustParseAddr("10.20.30.42"), netip.MustParseAddr("10.20.30.1"), make([]byte, 6)))
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, other)
	if r.TargetSeen || codes(r.Observed) != "local-context target-not-observed" || codes(r.Inferred) != "target-not-observed" {
		t.Fatalf("report %+v", r)
	}
	if !strings.Contains(r.Inferred[0].Text, "not proof") {
		t.Fatalf("wording: %s", r.Inferred[0].Text)
	}
}

func TestDuplicateClaimReported(t *testing.T) {
	addr := netip.MustParseAddr("10.20.30.42")
	tbl := tableFrom(t, fixtures.ARPAnnounce(fixtures.DeviceMAC, addr), fixtures.ARPAnnounce(fixtures.ServerMAC, addr))
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.Addr{})
	if !strings.Contains(codes(r.Observed), CodeDuplicateAddress) || !strings.Contains(codes(r.Inferred), CodeDuplicateAddress) {
		t.Fatalf("observed %s inferred %s", codes(r.Observed), codes(r.Inferred))
	}
}

func TestNoLocalIPv4(t *testing.T) {
	tbl := tableFrom(t, fixtures.ARP(fixtures.DeviceMAC, 1, other, otherG, make([]byte, 6)))
	r := Run(ContextFromPrefixes("enp3s0", nil), tbl, netip.Addr{})
	if codes(r.Observed) != "no-local-ipv4 l2-evidence address-claim" || len(r.Inferred) != 0 || len(r.Recommended) != 0 {
		t.Fatalf("report %+v", r)
	}
}

func TestProbeOnlyIsNotAClaim(t *testing.T) {
	tbl := tableFrom(t, fixtures.ARPProbe(fixtures.DeviceMAC, other))
	r := Run(ContextFromPrefixes("enp3s0", []netip.Prefix{local}), tbl, netip.Addr{})
	if len(r.Inferred) != 0 {
		t.Fatalf("a probe produced an inference: %+v", r.Inferred)
	}
}
