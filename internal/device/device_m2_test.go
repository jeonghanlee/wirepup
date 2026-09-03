package device

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
)

var (
	llAddr   = [16]byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x80, 0xf4, 0xff, 0xfe, 0x12, 0x34, 0x56}
	solNode  = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x12, 0x34, 0x56}
	allNodes = [16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
)

func ipv6Frame(srcMAC []byte, src, dst [16]byte, next uint8, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[6], ip[7] = next, 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], dst[:])
	eth := append([]byte{0x33, 0x33, 0, 0, 0, 1}, srcMAC...)
	eth = append(eth, 0x86, 0xdd)
	return append(append(eth, ip...), payload...)
}

func TestDADThenAdvertisement(t *testing.T) {
	ns := append([]byte{icmpv6.TypeNeighborSolicit, 0, 0, 0, 0, 0, 0, 0}, llAddr[:]...)
	na := append([]byte{icmpv6.TypeNeighborAdvert, 0, 0, 0, 0x20, 0, 0, 0}, llAddr[:]...)
	na = append(na, icmpv6.OptTargetLL, 1)
	na = append(na, clientMAC...)
	tbl := New(Options{})
	events := run(t, tbl, ipv6Frame(clientMAC, [16]byte{}, solNode, ipv6.NextICMPv6, ns), ipv6Frame(clientMAC, llAddr, allNodes, ipv6.NextICMPv6, na))
	d := tbl.Devices()[0]
	if len(d.IPv6) != 1 || d.IPv6[0].Addr.String() != "fe80::280:f4ff:fe12:3456" || d.IPv6[0].State != StateClaimed || d.IPv6[0].Via != ViaNDPAdvert {
		t.Fatalf("ipv6 %+v", d.IPv6)
	}
	if len(d.IPv4) != 0 || d.Protocols[0] != ProtoNDP {
		t.Fatalf("device %+v", d)
	}
	var vias []string
	for _, e := range events {
		vias = append(vias, e.Via)
	}
	if len(events) != 3 || events[1].Via != ViaDAD || events[1].Method != MethodV6LinkLocal || events[2].Via != ViaNDPAdvert {
		t.Fatalf("events %v", vias)
	}
}

func TestRouterAdvertisementMarksRouter(t *testing.T) {
	ra := []byte{icmpv6.TypeRouterAdvert, 0, 0, 0, 64, 0, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0}
	prefix := make([]byte, 32)
	prefix[0], prefix[1], prefix[2], prefix[3] = icmpv6.OptPrefixInfo, 4, 64, 0xc0
	copy(prefix[16:], []byte{0x20, 0x01, 0x0d, 0xb8})
	ra = append(ra, prefix...)
	tbl := New(Options{})
	run(t, tbl, ipv6Frame(serverMAC, llAddr, allNodes, ipv6.NextICMPv6, ra))
	d := tbl.Devices()[0]
	if !d.Router || d.Protocols[0] != ProtoIPv6Router || len(d.IPv6) != 1 || d.IPv6[0].State != StateObserved {
		t.Fatalf("router %+v", d)
	}
	found := false
	for _, e := range d.Timeline {
		if e.Text == "RA prefix 2001:db8::/64" {
			found = true
		}
	}
	if !found {
		t.Fatalf("timeline %+v", d.Timeline)
	}
}

func TestVLANTagRecordedUntaggedUnknown(t *testing.T) {
	tagged, _ := hex.DecodeString("ffffffffffff0080f4123456" + "8100" + "0064" + "0806" + "0001080006040001" + "0080f4123456" + "0a141e33" + "000000000000" + "0a141e01")
	untagged, _ := hex.DecodeString("ffffffffffff001c730000010806" + "0001080006040001" + "001c73000001" + "0a141e01" + "000000000000" + "0a141e33")
	tbl := New(Options{})
	events := run(t, tbl, tagged, untagged)
	devs := tbl.Devices()
	if len(devs[0].VLANs) != 1 || devs[0].VLANs[0] != 100 || len(devs[1].VLANs) != 0 {
		t.Fatalf("vlans %v %v", devs[0].VLANs, devs[1].VLANs)
	}
	var tagEvent *Event
	for i := range events {
		if events[i].Via == ViaVLANTag {
			tagEvent = &events[i]
		}
	}
	if tagEvent == nil || tagEvent.VLAN != 100 {
		t.Fatalf("no vlan event in %+v", events)
	}
}
