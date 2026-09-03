package arp

import (
	"encoding/hex"
	"testing"
)

const (
	header  = "0001080006040001"
	macA    = "001122334455"
	macZero = "000000000000"
	ipA     = "0a141e33" // 10.20.30.51
	ipGW    = "0a141e01" // 10.20.30.1
	ipLL    = "a9fe161f" // 169.254.22.31
	zeroIP  = "00000000"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseRequest(t *testing.T) {
	p, err := Parse(mustHex(t, header+macA+ipA+macZero+ipGW))
	if err != nil {
		t.Fatal(err)
	}
	if p.Op != OpRequest || p.SenderMAC.String() != "00:11:22:33:44:55" || p.SenderIP.String() != "10.20.30.51" || p.TargetIP.String() != "10.20.30.1" {
		t.Fatalf("packet %+v", p)
	}
	if Classify(p) != RoleRequest {
		t.Fatalf("role %s", Classify(p))
	}
}

func TestClassify(t *testing.T) {
	cases := []struct {
		name string
		hex  string
		want Role
	}{
		{"reply", "0001080006040002" + macA + ipA + "665544332211" + ipGW, RoleReply},
		{"probe", header + macA + zeroIP + macZero + ipLL, RoleProbe},
		{"announcement request", header + macA + ipLL + macZero + ipLL, RoleAnnouncement},
		{"gratuitous reply", "0001080006040002" + macA + ipA + "ffffffffffff" + ipA, RoleAnnouncement},
	}
	for _, c := range cases {
		p, err := Parse(mustHex(t, c.hex))
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if got := Classify(p); got != c.want {
			t.Errorf("%s: role %s want %s", c.name, got, c.want)
		}
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(mustHex(t, header+macA+ipA)); err != ErrTruncated {
		t.Fatalf("truncated: %v", err)
	}
	if _, err := Parse(mustHex(t, "0001"+"86dd"+"0610"+"0001"+macA+ipA+macZero+ipGW)); err != ErrUnsupported {
		t.Fatalf("unsupported: %v", err)
	}
	if _, err := Parse(mustHex(t, "0001080006040009"+macA+ipA+macZero+ipGW)); err != ErrOpcode {
		t.Fatalf("opcode: %v", err)
	}
	// Padding after the packet is accepted.
	if _, err := Parse(mustHex(t, header+macA+ipA+macZero+ipGW+"000000000000000000000000000000000000")); err != nil {
		t.Fatalf("padded: %v", err)
	}
}

func TestIsLinkLocal(t *testing.T) {
	p, _ := Parse(mustHex(t, header+macA+ipLL+macZero+ipLL))
	if !IsLinkLocal(p.SenderIP) {
		t.Fatal("169.254.22.31 not link-local")
	}
	q, _ := Parse(mustHex(t, header+macA+ipA+macZero+ipGW))
	if IsLinkLocal(q.SenderIP) {
		t.Fatal("10.20.30.51 reported link-local")
	}
}
