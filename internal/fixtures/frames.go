// Package fixtures builds the Ethernet frames used by tests and by the
// PCAP fixture generator under testdata/gen. Every builder is a plain
// byte constructor; nothing here parses.
package fixtures

import (
	"encoding/binary"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
)

// Well-known addresses used across fixtures.
var (
	Broadcast   = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	DeviceMAC   = net.HardwareAddr{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}
	LaptopMAC   = net.HardwareAddr{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}
	SwitchMAC   = net.HardwareAddr{0x00, 0x1c, 0x73, 0x00, 0x00, 0x01}
	ServerMAC   = net.HardwareAddr{0x00, 0x1c, 0x73, 0x00, 0x00, 0x02}
	IPv6AllNode = netip.MustParseAddr("ff02::1")
)

// MustAddr parses an address or panics; for fixture tables only.
func MustAddr(s string) netip.Addr { return netip.MustParseAddr(s) }

// Epoch is the timestamp of the first packet in generated fixtures.
var Epoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// Packet wraps a frame as a capture packet with a deterministic time.
func Packet(i int, data []byte) capture.Packet {
	return capture.Packet{
		Timestamp:      Epoch.Add(time.Duration(i) * time.Second),
		Interface:      "enp3s0",
		LinkType:       capture.LinkTypeEthernet,
		Data:           data,
		CaptureLength:  len(data),
		OriginalLength: len(data),
	}
}

// Ethernet prepends an Ethernet II header.
func Ethernet(dst, src net.HardwareAddr, etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:], etherType)
	return append(f, payload...)
}

// EthernetVLAN prepends an Ethernet II header with an 802.1Q tag.
func EthernetVLAN(dst, src net.HardwareAddr, vlan uint16, etherType uint16, payload []byte) []byte {
	f := make([]byte, 18, 18+len(payload))
	copy(f[0:6], dst)
	copy(f[6:12], src)
	binary.BigEndian.PutUint16(f[12:], 0x8100)
	binary.BigEndian.PutUint16(f[14:], vlan&0x0fff)
	binary.BigEndian.PutUint16(f[16:], etherType)
	return append(f, payload...)
}

// ARP builds an Ethernet/IPv4 ARP frame.
func ARP(src net.HardwareAddr, op uint16, senderIP, targetIP netip.Addr, targetMAC net.HardwareAddr) []byte {
	p := make([]byte, 28)
	binary.BigEndian.PutUint16(p[0:], 1)
	binary.BigEndian.PutUint16(p[2:], 0x0800)
	p[4], p[5] = 6, 4
	binary.BigEndian.PutUint16(p[6:], op)
	copy(p[8:14], src)
	s := senderIP.As4()
	copy(p[14:18], s[:])
	copy(p[18:24], targetMAC)
	t := targetIP.As4()
	copy(p[24:28], t[:])
	dst := Broadcast
	if op == 2 && targetMAC != nil && !isBroadcast(targetMAC) {
		dst = targetMAC
	}
	return Ethernet(dst, src, 0x0806, p)
}

// ARPProbe builds an RFC 5227 probe for target.
func ARPProbe(src net.HardwareAddr, target netip.Addr) []byte {
	return ARP(src, 1, netip.AddrFrom4([4]byte{}), target, make(net.HardwareAddr, 6))
}

// ARPAnnounce builds an RFC 5227 announcement for addr.
func ARPAnnounce(src net.HardwareAddr, addr netip.Addr) []byte {
	return ARP(src, 1, addr, addr, make(net.HardwareAddr, 6))
}

// IPv4UDP builds an Ethernet/IPv4/UDP frame.
func IPv4UDP(dst, src net.HardwareAddr, dstIP, srcIP netip.Addr, dstPort, srcPort uint16, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)+len(payload)))
	ip[8], ip[9] = 64, 17
	s, d := srcIP.As4(), dstIP.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	checksum(ip)
	return Ethernet(dst, src, 0x0800, append(append(ip, udp...), payload...))
}

// IPv4TCP builds an Ethernet/IPv4/TCP frame with the given flags.
func IPv4TCP(dst, src net.HardwareAddr, dstIP, srcIP netip.Addr, dstPort, srcPort uint16, flags uint8, seq uint32, payload []byte) []byte {
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:], srcPort)
	binary.BigEndian.PutUint16(tcp[2:], dstPort)
	binary.BigEndian.PutUint32(tcp[4:], seq)
	tcp[12] = 5 << 4
	tcp[13] = flags
	binary.BigEndian.PutUint16(tcp[14:], 65535)
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(tcp)+len(payload)))
	ip[8], ip[9] = 64, 6
	s, d := srcIP.As4(), dstIP.As4()
	copy(ip[12:16], s[:])
	copy(ip[16:20], d[:])
	checksum(ip)
	return Ethernet(dst, src, 0x0800, append(append(ip, tcp...), payload...))
}

// IPv6 builds an Ethernet/IPv6 frame with the given next header.
func IPv6(dst, src net.HardwareAddr, dstIP, srcIP netip.Addr, next uint8, hop uint8, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[6], ip[7] = next, hop
	s, d := srcIP.As16(), dstIP.As16()
	copy(ip[8:24], s[:])
	copy(ip[24:40], d[:])
	return Ethernet(dst, src, 0x86dd, append(ip, payload...))
}

// DHCP builds a DHCPv4 message body. Options are appended verbatim after
// the message type option; the end option is added.
func DHCP(op, msgType uint8, xid uint32, client net.HardwareAddr, yiaddr netip.Addr, options ...[]byte) []byte {
	b := make([]byte, 236)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	if yiaddr.IsValid() {
		y := yiaddr.As4()
		copy(b[16:20], y[:])
	}
	copy(b[28:], client)
	b = append(b, 0x63, 0x82, 0x53, 0x63, 53, 1, msgType)
	for _, o := range options {
		b = append(b, o...)
	}
	return append(b, 255)
}

// Option builds one DHCP option.
func Option(code uint8, v ...byte) []byte {
	return append([]byte{code, uint8(len(v))}, v...)
}

// LLDP builds an LLDPDU from a chassis MAC, a port name, and a system
// name, with a port VLAN ID when non-zero.
func LLDP(chassis net.HardwareAddr, port, system string, ttl uint16, pvid uint16, mgmt netip.Addr) []byte {
	var b []byte
	b = append(b, tlv(1, append([]byte{4}, chassis...))...)
	b = append(b, tlv(2, append([]byte{5}, []byte(port)...))...)
	b = append(b, tlv(3, []byte{byte(ttl >> 8), byte(ttl)})...)
	b = append(b, tlv(5, []byte(system))...)
	b = append(b, tlv(7, []byte{0x00, 0x04, 0x00, 0x04})...)
	if mgmt.IsValid() {
		a := mgmt.As4()
		b = append(b, tlv(8, []byte{5, 1, a[0], a[1], a[2], a[3], 2, 0, 0, 0, 1, 0})...)
	}
	if pvid != 0 {
		b = append(b, tlv(127, []byte{0x00, 0x80, 0xc2, 1, byte(pvid >> 8), byte(pvid)})...)
	}
	return append(b, 0, 0)
}

// LLDPFrame wraps an LLDPDU in its multicast frame.
func LLDPFrame(src net.HardwareAddr, pdu []byte) []byte {
	return Ethernet(net.HardwareAddr{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e}, src, 0x88cc, pdu)
}

// NDPSolicit builds a neighbor solicitation body; src link-layer option
// is added when srcLL is non-nil.
func NDPSolicit(target netip.Addr, srcLL net.HardwareAddr) []byte {
	t := target.As16()
	b := append([]byte{135, 0, 0, 0, 0, 0, 0, 0}, t[:]...)
	if srcLL != nil {
		b = append(b, 1, 1)
		b = append(b, srcLL...)
	}
	return b
}

// NDPAdvert builds a neighbor advertisement body.
func NDPAdvert(target netip.Addr, targetLL net.HardwareAddr, solicited, override bool) []byte {
	var flags byte
	if solicited {
		flags |= 0x40
	}
	if override {
		flags |= 0x20
	}
	t := target.As16()
	b := append([]byte{136, 0, 0, 0, flags, 0, 0, 0}, t[:]...)
	if targetLL != nil {
		b = append(b, 2, 1)
		b = append(b, targetLL...)
	}
	return b
}

// SolicitedNode returns the solicited-node multicast address of addr.
func SolicitedNode(addr netip.Addr) netip.Addr {
	a := addr.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0xff, a[13], a[14], a[15]})
}

// MulticastMAC returns the Ethernet multicast address for an IPv6 group.
func MulticastMAC(addr netip.Addr) net.HardwareAddr {
	a := addr.As16()
	return net.HardwareAddr{0x33, 0x33, a[12], a[13], a[14], a[15]}
}

func tlv(typ uint8, payload []byte) []byte {
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(typ)<<9|uint16(len(payload)))
	return append(hdr, payload...)
}

func checksum(ip []byte) {
	var sum uint32
	for i := 0; i+1 < len(ip); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(ip[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(ip[10:], ^uint16(sum))
}

func isBroadcast(a net.HardwareAddr) bool {
	for _, b := range a {
		if b != 0xff {
			return false
		}
	}
	return true
}
