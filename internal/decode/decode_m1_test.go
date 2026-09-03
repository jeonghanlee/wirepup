package decode

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
)

// lldpFrameHex is a minimal LLDPDU: chassis MAC, port name "1", TTL 120,
// system name "sw", end.
const lldpFrameHex = "0180c200000e" + "001c73000001" + "88cc" +
	"0207" + "04001c73000001" + // chassis id, MAC subtype
	"0402" + "0531" + // port id, interface name "1"
	"0602" + "0078" + // ttl 120
	"0a02" + "7377" + // system name "sw"
	"0000"

// DHCPFrame builds Ethernet/IPv4/UDP/DHCP Discover from the given MAC.
func dhcpFrame(t *testing.T, mac []byte, msgType byte) []byte {
	t.Helper()
	dhcp := make([]byte, dhcpv4.FixedLen)
	dhcp[0], dhcp[1], dhcp[2] = 1, 1, 6
	binary.BigEndian.PutUint32(dhcp[4:], 0x1234)
	copy(dhcp[28:], mac)
	dhcp = append(dhcp, 0x63, 0x82, 0x53, 0x63, 53, 1, msgType, 12, 3, 'i', 'o', 'c', 255)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], 68)
	binary.BigEndian.PutUint16(udp[2:], 67)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(dhcp)))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)+len(dhcp)))
	ip[8] = 64
	ip[9] = 17
	copy(ip[16:20], []byte{255, 255, 255, 255})
	eth := append([]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, mac...)
	eth = append(eth, 0x08, 0x00)
	frame := append(eth, ip...)
	frame = append(frame, udp...)
	return append(frame, dhcp...)
}

func TestDecodeLLDP(t *testing.T) {
	b, _ := hex.DecodeString(lldpFrameHex)
	obs := New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: b, OriginalLength: len(b)})
	if len(obs) != 2 {
		t.Fatalf("observations %d", len(obs))
	}
	o, ok := obs[1].(lldp.Observation)
	if !ok || o.SystemName != "sw" || o.PortID != "1" || o.ChassisID != "00:1c:73:00:00:01" || o.SourceMAC.String() != "00:1c:73:00:00:01" {
		t.Fatalf("lldp %+v", obs[1])
	}
	if o.Ref().Protocol != ProtoLLDP {
		t.Fatalf("protocol %s", o.Ref().Protocol)
	}
}

func TestDecodeDHCPOverIPv4(t *testing.T) {
	mac := []byte{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}
	frame := dhcpFrame(t, mac, dhcpv4.Discover)
	obs := New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame, OriginalLength: len(frame)})
	if len(obs) != 3 {
		t.Fatalf("observations %d", len(obs))
	}
	ip, ok := obs[1].(ipv4.Observation)
	if !ok || ip.Protocol != ipv4.ProtoUDP || ip.Dst.String() != "255.255.255.255" || ip.Ref().Protocol != ProtoIPv4 {
		t.Fatalf("ipv4 %+v", obs[1])
	}
	d, ok := obs[2].(dhcpv4.Observation)
	if !ok || d.MessageType != dhcpv4.Discover || d.Hostname != "ioc" || d.ClientMAC.String() != "00:80:f4:12:34:56" {
		t.Fatalf("dhcp %+v", obs[2])
	}
}

func TestUDP67WithoutCookieIsNotDHCP(t *testing.T) {
	mac := []byte{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}
	frame := dhcpFrame(t, mac, dhcpv4.Discover)
	frame[14+20+8+dhcpv4.FixedLen] = 0 // break the magic cookie
	obs := New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame, OriginalLength: len(frame)})
	if len(obs) != 2 {
		t.Fatalf("observations %d: port alone must not claim DHCP", len(obs))
	}
}

func TestTruncationsDoNotPanic(t *testing.T) {
	frame := dhcpFrame(t, []byte{1, 2, 3, 4, 5, 6}, dhcpv4.Offer)
	for n := 0; n <= len(frame); n++ {
		New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: frame[:n], OriginalLength: len(frame)})
	}
	b, _ := hex.DecodeString(lldpFrameHex)
	for n := 0; n <= len(b); n++ {
		New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: b[:n], OriginalLength: len(b)})
	}
}
