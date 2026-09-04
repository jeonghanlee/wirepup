package active

import (
	"net"
	"net/netip"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

var self = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}

func TestProbeFrameParsesAsProbe(t *testing.T) {
	f := ProbeFrame(self, netip.MustParseAddr("192.168.1.254"))
	eth, err := ethernet.Parse(f)
	if err != nil || eth.EtherType != ethernet.EtherTypeARP {
		t.Fatalf("frame %v %v", err, eth)
	}
	p, err := arp.Parse(eth.Payload)
	if err != nil {
		t.Fatal(err)
	}
	if arp.Classify(p) != arp.RoleProbe || p.TargetIP.String() != "192.168.1.254" || p.SenderMAC.String() != self.String() {
		t.Fatalf("packet %+v", p)
	}
	r, ok := parseARP(f)
	if !ok || r.Kind != "probe" || r.TargetIP.String() != "192.168.1.254" {
		t.Fatalf("reply %+v", r)
	}
}

func TestHostsBounded(t *testing.T) {
	hs, err := Hosts(netip.MustParsePrefix("192.168.1.0/24"))
	if err != nil || len(hs) != 254 || hs[0].String() != "192.168.1.1" || hs[253].String() != "192.168.1.254" {
		t.Fatalf("/24: %v %d", err, len(hs))
	}
	if _, err := Hosts(netip.MustParsePrefix("10.0.0.0/23")); err != ErrPrefixTooLarge {
		t.Fatalf("/23: %v", err)
	}
	hs, _ = Hosts(netip.MustParsePrefix("10.0.0.7/32"))
	if len(hs) != 1 || hs[0].String() != "10.0.0.7" {
		t.Fatalf("/32: %v", hs)
	}
	hs, _ = Hosts(netip.MustParsePrefix("10.0.0.0/31"))
	if len(hs) != 2 {
		t.Fatalf("/31: %v", hs)
	}
	hs, _ = Hosts(netip.MustParsePrefix("10.0.0.0/30"))
	if len(hs) != 2 || hs[0].String() != "10.0.0.1" || hs[1].String() != "10.0.0.2" {
		t.Fatalf("/30: %v", hs)
	}
	if _, err := Hosts(netip.MustParsePrefix("fe80::/64")); err == nil {
		t.Fatal("ipv6 accepted")
	}
}

func TestConflictDetection(t *testing.T) {
	target := netip.MustParseAddr("192.168.1.254")
	other := net.HardwareAddr{0x00, 0x80, 0xf4, 1, 2, 3}
	cases := []struct {
		frame []byte
		want  bool
	}{
		{ARPFrame(other, opReply, target, self, netip.MustParseAddr("0.0.0.0")), true},
		{ARPFrame(other, opRequest, target, nil, target), true},
		{ProbeFrame(other, target), true},
		{ProbeFrame(self, target), false},
		{ARPFrame(other, opRequest, netip.MustParseAddr("192.168.1.9"), nil, netip.MustParseAddr("192.168.1.1")), false},
	}
	for i, c := range cases {
		r, ok := parseARP(c.frame)
		if !ok {
			t.Fatalf("case %d did not parse", i)
		}
		if got := Conflicts(r, target, self); got != c.want {
			t.Fatalf("case %d: conflict=%v want %v (%+v)", i, got, c.want, r)
		}
	}
	if _, ok := parseARP([]byte{1, 2, 3}); ok {
		t.Fatal("short frame parsed")
	}
	if _, ok := parseARP(ARPFrame(other, 3, target, nil, target)); ok {
		t.Fatal("unknown ARP opcode parsed")
	}
}

func TestPlanString(t *testing.T) {
	p := Plan{Interface: "enp3s0", Protocol: "ARP", Targets: []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.0.0.9")}, Count: 9, Rate: RatePerSecond}
	if p.String() != "transmit 9 ARP packet(s) on enp3s0 to 10.0.0.1..10.0.0.9 at 20/s" {
		t.Fatalf("%q", p.String())
	}
}
