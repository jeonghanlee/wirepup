package ipv6

import (
	"encoding/binary"
	"testing"
)

func header(next uint8, payload []byte) []byte {
	b := make([]byte, HeaderLen)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:], uint16(len(payload)))
	b[6] = next
	b[7] = 255
	copy(b[8:24], []byte{0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x80, 0xf4, 0xff, 0xfe, 0x12, 0x34, 0x56})
	copy(b[24:40], []byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, 0x12, 0x34, 0x56})
	return append(b, payload...)
}

func TestParsePlain(t *testing.T) {
	p, err := Parse(header(NextICMPv6, []byte{0x87, 0, 0, 0}))
	if err != nil {
		t.Fatal(err)
	}
	if p.NextHeader != NextICMPv6 || p.HopLimit != 255 || p.Src.String() != "fe80::280:f4ff:fe12:3456" || p.Dst.String() != "ff02::1:ff12:3456" {
		t.Fatalf("packet %+v", p)
	}
	if len(p.Payload) != 4 || p.ExtHeaders != 0 || p.PayloadDrop {
		t.Fatalf("payload %+v", p)
	}
}

func TestExtensionHeaderChain(t *testing.T) {
	// hop-by-hop (8 bytes) -> destination options (16 bytes) -> UDP payload.
	hbh := []byte{NextDestOpts, 0, 1, 0, 0, 0, 0, 0}
	dst := append([]byte{NextUDP, 1}, make([]byte, 14)...)
	udp := []byte{0x13, 0xd4, 0x13, 0xd4, 0, 8, 0, 0}
	body := append(append(hbh, dst...), udp...)
	p, err := Parse(header(NextHopByHop, body))
	if err != nil {
		t.Fatal(err)
	}
	if p.NextHeader != NextUDP || p.ExtHeaders != 2 || len(p.Payload) != 8 || p.PayloadDrop {
		t.Fatalf("packet %+v", p)
	}
}

func TestFragments(t *testing.T) {
	first := []byte{NextUDP, 0, 0x00, 0x01, 0, 0, 0, 1, 0x13, 0xd4, 0x13, 0xd4, 0, 8, 0, 0}
	p, _ := Parse(header(NextFragment, first))
	if !p.Fragment || p.PayloadDrop || p.NextHeader != NextUDP || len(p.Payload) != 8 {
		t.Fatalf("first fragment %+v", p)
	}
	later := []byte{NextUDP, 0, 0x00, 0x08, 0, 0, 0, 1, 1, 2, 3}
	p, _ = Parse(header(NextFragment, later))
	if !p.Fragment || !p.PayloadDrop || p.Payload != nil {
		t.Fatalf("later fragment %+v", p)
	}
}

func TestMalformedChains(t *testing.T) {
	// Extension header length past the buffer.
	p, err := Parse(header(NextHopByHop, []byte{NextUDP, 9, 0, 0}))
	if err != nil || !p.PayloadDrop {
		t.Fatalf("overlong ext %+v %v", p, err)
	}
	// Endless chain of hop-by-hop headers is bounded.
	var chain []byte
	for i := 0; i < 20; i++ {
		chain = append(chain, []byte{NextHopByHop, 0, 0, 0, 0, 0, 0, 0}...)
	}
	p, err = Parse(header(NextHopByHop, chain))
	if err != nil || !p.PayloadDrop || p.ExtHeaders != maxExtHeaders {
		t.Fatalf("bounded chain %+v %v", p, err)
	}
	if _, err := Parse(make([]byte, 10)); err != ErrTruncated {
		t.Fatalf("short %v", err)
	}
	b := header(NextUDP, nil)
	b[0] = 0x45
	if _, err := Parse(b); err != ErrVersion {
		t.Fatalf("version %v", err)
	}
	full := header(NextHopByHop, append([]byte{NextUDP, 0, 0, 0, 0, 0, 0, 0}, 1, 2, 3, 4, 5, 6, 7, 8))
	for n := 0; n <= len(full); n++ {
		Parse(full[:n])
	}
}
