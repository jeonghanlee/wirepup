package decode

import (
	"encoding/binary"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
)

func ipv6Frame(src [16]byte, next uint8, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[6], ip[7] = next, 255
	copy(ip[8:24], src[:])
	copy(ip[24:40], []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, 0x12, 0x34, 0x56})
	eth := []byte{0x33, 0x33, 0xff, 0x12, 0x34, 0x56, 0x00, 0x80, 0xf4, 0x12, 0x34, 0x56, 0x86, 0xdd}
	return append(append(eth, ip...), payload...)
}

func TestDecodeDAD(t *testing.T) {
	target := []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x80, 0xf4, 0xff, 0xfe, 0x12, 0x34, 0x56}
	ns := append([]byte{icmpv6.TypeNeighborSolicit, 0, 0, 0, 0, 0, 0, 0}, target...)
	frame := ipv6Frame([16]byte{}, ipv6.NextICMPv6, ns)
	obs := New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame, OriginalLength: len(frame)})
	if len(obs) != 3 {
		t.Fatalf("observations %d", len(obs))
	}
	ip, ok := obs[1].(ipv6.Observation)
	if !ok || !ip.Src.IsUnspecified() || ip.NextHeader != ipv6.NextICMPv6 || ip.Ref().Protocol != ProtoIPv6 {
		t.Fatalf("ipv6 %+v", obs[1])
	}
	n, ok := obs[2].(icmpv6.Observation)
	if !ok || !n.DAD || n.Kind() != icmpv6.KindNDP || n.Target.String() != "fe80::280:f4ff:fe12:3456" || n.Ref().Protocol != ProtoICMPv6 {
		t.Fatalf("ndp %+v", obs[2])
	}
	for i := 0; i <= len(frame); i++ {
		New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame[:i], OriginalLength: len(frame)})
	}
}

func TestDecodeIPv6FragmentKeepsHeaderOnly(t *testing.T) {
	frag := []byte{ipv6.NextICMPv6, 0, 0x00, 0x08, 0, 0, 0, 1, 1, 2, 3}
	frame := ipv6Frame([16]byte{0xfe, 0x80}, ipv6.NextFragment, frag)
	obs := New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame, OriginalLength: len(frame)})
	if len(obs) != 2 || !obs[1].(ipv6.Observation).Fragment {
		t.Fatalf("observations %+v", obs)
	}
}
