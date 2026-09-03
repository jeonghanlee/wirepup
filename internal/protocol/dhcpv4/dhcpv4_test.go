package dhcpv4

import (
	"encoding/binary"
	"testing"
)

func fixed(op uint8, xid uint32, yiaddr [4]byte, mac []byte) []byte {
	b := make([]byte, FixedLen)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	copy(b[16:20], yiaddr[:])
	copy(b[28:], mac)
	copy(b[44:], "srv\x00")
	return b
}

func withOptions(b []byte, opts ...[]byte) []byte {
	b = append(b, 0x63, 0x82, 0x53, 0x63)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, OptEnd)
}

func opt(code uint8, v ...byte) []byte {
	return append([]byte{code, uint8(len(v))}, v...)
}

var mac = []byte{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}

func TestDiscover(t *testing.T) {
	b := withOptions(fixed(OpRequest, 0xdeadbeef, [4]byte{}, mac),
		opt(OptMessageType, Discover),
		opt(OptClientID, append([]byte{1}, mac...)...),
		opt(OptHostname, []byte("ioc-pc")...),
		opt(OptParamRequest, 1, 3, 6),
	)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.MessageType != Discover || m.TypeName() != "discover" || m.XID != 0xdeadbeef {
		t.Fatalf("message %+v", m)
	}
	if m.ClientMAC.String() != "00:80:f4:12:34:56" || m.ClientID != "00:80:f4:12:34:56" || m.Hostname != "ioc-pc" || m.ServerName != "srv" {
		t.Fatalf("identity %+v", m)
	}
	if len(m.Options[OptParamRequest]) != 3 {
		t.Fatalf("options %v", m.Options)
	}
}

func TestOfferAndAck(t *testing.T) {
	b := withOptions(fixed(OpReply, 1, [4]byte{10, 20, 30, 42}, mac),
		opt(OptMessageType, Offer),
		opt(OptServerID, 10, 20, 30, 1),
		opt(OptLeaseTime, 0, 0, 0x0e, 0x10),
		opt(OptSubnetMask, 255, 255, 255, 0),
		opt(OptRouter, 10, 20, 30, 1),
		opt(OptDNS, 10, 20, 30, 2, 10, 20, 30, 3),
	)
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.MessageType != Offer || m.YourIP.String() != "10.20.30.42" || m.ServerID.String() != "10.20.30.1" || m.LeaseTime != 3600 {
		t.Fatalf("offer %+v", m)
	}
	if m.SubnetMask.String() != "255.255.255.0" || len(m.Routers) != 1 || len(m.DNS) != 2 {
		t.Fatalf("network options %+v", m)
	}
}

func TestErrors(t *testing.T) {
	if _, err := Parse(make([]byte, 100)); err != ErrTruncated {
		t.Fatalf("short: %v", err)
	}
	plain := append(fixed(OpRequest, 1, [4]byte{}, mac), 0, 0, 0, 0)
	if _, err := Parse(plain); err != ErrCookie {
		t.Fatalf("bootp: %v", err)
	}
	bad := append(fixed(9, 1, [4]byte{}, mac), 0x63, 0x82, 0x53, 0x63, OptEnd)
	if _, err := Parse(bad); err != ErrOp {
		t.Fatalf("op: %v", err)
	}
	overrun := append(fixed(OpRequest, 1, [4]byte{}, mac), 0x63, 0x82, 0x53, 0x63, OptHostname, 40, 'a')
	if _, err := Parse(overrun); err != ErrOptions {
		t.Fatalf("overrun: %v", err)
	}
	// hlen larger than chaddr must not panic
	big := withOptions(fixed(OpRequest, 1, [4]byte{}, mac), opt(OptMessageType, Request))
	big[2] = 200
	if m, err := Parse(big); err != nil || len(m.ClientMAC) != chaddrLen {
		t.Fatalf("hlen clamp: %v %d", err, len(m.ClientMAC))
	}
}

func TestClientIDOtherType(t *testing.T) {
	b := withOptions(fixed(OpRequest, 1, [4]byte{}, mac), opt(OptMessageType, Request), opt(OptClientID, 0, 0xab, 0xcd))
	m, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if m.ClientID != "type0:abcd" {
		t.Fatalf("client id %q", m.ClientID)
	}
}
