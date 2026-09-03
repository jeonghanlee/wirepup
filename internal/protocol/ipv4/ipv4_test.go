package ipv4

import (
	"encoding/hex"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// 20-byte header, total length 28, UDP, 10.20.30.51 -> 10.20.30.255, plus 8 payload bytes.
const udpHex = "4500001c000040004011" + "0000" + "0a141e33" + "0a141eff" + "0044004300080000"

func TestParseUDP(t *testing.T) {
	p, err := Parse(mustHex(t, udpHex))
	if err != nil {
		t.Fatal(err)
	}
	if p.Protocol != ProtoUDP || p.TTL != 64 || p.Src.String() != "10.20.30.51" || p.Dst.String() != "10.20.30.255" {
		t.Fatalf("packet %+v", p)
	}
	if len(p.Payload) != 8 || p.Truncated || p.PayloadDrop {
		t.Fatalf("payload %d truncated %v drop %v", len(p.Payload), p.Truncated, p.PayloadDrop)
	}
}

func TestParseTruncatedTotalLength(t *testing.T) {
	p, err := Parse(mustHex(t, "450000ff000040004011"+"0000"+"0a141e33"+"0a141eff"+"0044"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Truncated || len(p.Payload) != 2 {
		t.Fatalf("truncated %v payload %d", p.Truncated, len(p.Payload))
	}
}

func TestParseOptionsAndFragment(t *testing.T) {
	// IHL 6 (24 bytes), fragment offset 8, more fragments set.
	p, err := Parse(mustHex(t, "4600002000002008"+"4011"+"0000"+"0a141e33"+"0a141eff"+"01010000"+"0044004300080000"))
	if err != nil {
		t.Fatal(err)
	}
	if p.HeaderLen != 24 || p.FragOffset != 8 || !p.MoreFrags || !p.PayloadDrop || p.Payload != nil {
		t.Fatalf("packet %+v", p)
	}
}

func TestParseErrors(t *testing.T) {
	if _, err := Parse(mustHex(t, "4500")); err != ErrTruncated {
		t.Fatalf("short: %v", err)
	}
	if _, err := Parse(mustHex(t, "6500001c000040004011"+"0000"+"0a141e33"+"0a141eff")); err != ErrVersion {
		t.Fatalf("version: %v", err)
	}
	if _, err := Parse(mustHex(t, "4400001c000040004011"+"0000"+"0a141e33"+"0a141eff")); err != ErrHeaderLen {
		t.Fatalf("ihl: %v", err)
	}
	if _, err := Parse(mustHex(t, "4600001c000040004011"+"0000"+"0a141e33"+"0a141eff")); err != ErrTruncated {
		t.Fatalf("ihl beyond buffer: %v", err)
	}
}

func TestProtocolName(t *testing.T) {
	if ProtocolName(17) != "udp" || ProtocolName(6) != "tcp" || ProtocolName(1) != "icmp" || ProtocolName(89) != "proto-89" {
		t.Fatal("names")
	}
}
