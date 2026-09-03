package icmpv6

import (
	"encoding/binary"
	"testing"
)

var (
	target = []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x80, 0xf4, 0xff, 0xfe, 0x12, 0x34, 0x56}
	mac    = []byte{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}
)

func TestNeighborSolicitationWithSourceLL(t *testing.T) {
	b := append([]byte{TypeNeighborSolicit, 0, 0, 0, 0, 0, 0, 0}, target...)
	b = append(b, OptSourceLL, 1)
	b = append(b, mac...)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.IsNDP() || m.TypeName() != "neighbor-solicitation" || m.Target.String() != "fe80::280:f4ff:fe12:3456" || m.SourceLL.String() != "00:80:f4:12:34:56" {
		t.Fatalf("message %+v", m)
	}
}

func TestNeighborAdvertisementFlags(t *testing.T) {
	b := append([]byte{TypeNeighborAdvert, 0, 0, 0, 0xe0, 0, 0, 0}, target...)
	b = append(b, OptTargetLL, 1)
	b = append(b, mac...)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !m.Router || !m.Solicited || !m.Override || m.TargetLL.String() != "00:80:f4:12:34:56" {
		t.Fatalf("flags %+v", m)
	}
}

func TestRouterAdvertisementOptions(t *testing.T) {
	b := []byte{TypeRouterAdvert, 0, 0, 0, 64, 0xc0, 0x07, 0x08}
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	prefix := make([]byte, 32)
	prefix[0], prefix[1] = OptPrefixInfo, 4
	prefix[2], prefix[3] = 64, 0xc0
	binary.BigEndian.PutUint32(prefix[4:], 2592000)
	binary.BigEndian.PutUint32(prefix[8:], 604800)
	copy(prefix[16:], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 1})
	b = append(b, prefix...)
	b = append(b, OptMTU, 1, 0, 0, 0, 0, 0x05, 0xdc)
	b = append(b, OptSourceLL, 1)
	b = append(b, mac...)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.CurHopLimit != 64 || !m.Managed || !m.OtherConfig || m.RouterLifetime != 1800 {
		t.Fatalf("ra %+v", m)
	}
	if len(m.Prefixes) != 1 || m.Prefixes[0].Prefix.String() != "2001:db8:0:1::/64" || !m.Prefixes[0].OnLink || !m.Prefixes[0].Autonomous || m.Prefixes[0].ValidLife != 2592000 {
		t.Fatalf("prefixes %+v", m.Prefixes)
	}
	if m.MTU != 1500 || m.SourceLL == nil || m.Malformed {
		t.Fatalf("options %+v", m)
	}
}

func TestMalformedOptions(t *testing.T) {
	b := append([]byte{TypeNeighborSolicit, 0, 0, 0, 0, 0, 0, 0}, target...)
	b = append(b, OptSourceLL, 0) // zero length option
	m, err := Parse(b)
	if err != nil || !m.Malformed {
		t.Fatalf("zero length: %+v %v", m, err)
	}
	b = append([]byte{TypeNeighborSolicit, 0, 0, 0, 0, 0, 0, 0}, target...)
	b = append(b, OptSourceLL, 9, 1, 2)
	m, err = Parse(b)
	if err != nil || !m.Malformed {
		t.Fatalf("overlong: %+v %v", m, err)
	}
	if _, err := Parse([]byte{TypeNeighborSolicit, 0, 0}); err != ErrTruncated {
		t.Fatalf("short header %v", err)
	}
	if _, err := Parse([]byte{TypeNeighborSolicit, 0, 0, 0, 0, 0}); err != ErrTruncated {
		t.Fatalf("short body %v", err)
	}
	full := append([]byte{TypeRouterAdvert, 0, 0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, OptMTU, 1, 0, 0, 0, 0, 5, 0xdc)
	for n := 0; n <= len(full); n++ {
		Parse(full[:n])
	}
}

func TestGenericTypes(t *testing.T) {
	m, err := Parse([]byte{TypeEchoRequest, 0, 0, 0, 1, 2, 3, 4})
	if err != nil || m.IsNDP() || m.TypeName() != "echo-request" {
		t.Fatalf("echo %+v %v", m, err)
	}
	m, _ = Parse([]byte{200, 0, 0, 0})
	if m.TypeName() != "type-200" {
		t.Fatalf("name %s", m.TypeName())
	}
	o := Observation{Message: m}
	if o.Kind() != KindGeneric {
		t.Fatal("kind")
	}
	o = Observation{Message: Message{Type: TypeNeighborAdvert}}
	if o.Kind() != KindNDP {
		t.Fatal("ndp kind")
	}
}
