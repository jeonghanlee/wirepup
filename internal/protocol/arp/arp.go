// Package arp parses IPv4-over-Ethernet ARP packets and classifies the
// RFC 5227 probe and announcement patterns that reveal how a device is
// choosing an address (R-005, R-007).
package arp

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Wire constants for Ethernet/IPv4 ARP.
const (
	PacketLen        = 28
	HardwareEthernet = 1
	ProtocolIPv4     = 0x0800
	OpRequest        = 1
	OpReply          = 2
	HardwareAddrLen  = 6
	ProtocolAddrLen  = 4
)

// Kind is the observation kind.
const Kind observation.Kind = "arp"

// Errors returned by Parse.
var (
	ErrTruncated   = errors.New("arp: truncated packet")
	ErrUnsupported = errors.New("arp: not Ethernet/IPv4 ARP")
	ErrOpcode      = errors.New("arp: unknown opcode")
)

// Role is the interpretation of one ARP packet.
type Role string

// Roles WirePup distinguishes.
const (
	RoleRequest      Role = "request"
	RoleReply        Role = "reply"
	RoleProbe        Role = "probe"        // request with an unspecified sender address (RFC 5227)
	RoleAnnouncement Role = "announcement" // sender and target address equal (gratuitous ARP)
)

// Packet is a parsed ARP packet.
type Packet struct {
	Op        uint16
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr
}

// Parse decodes an Ethernet/IPv4 ARP packet. Trailing bytes (padding)
// are ignored.
func Parse(b []byte) (Packet, error) {
	if len(b) < PacketLen {
		return Packet{}, ErrTruncated
	}
	if binary.BigEndian.Uint16(b[0:2]) != HardwareEthernet || binary.BigEndian.Uint16(b[2:4]) != ProtocolIPv4 ||
		b[4] != HardwareAddrLen || b[5] != ProtocolAddrLen {
		return Packet{}, ErrUnsupported
	}
	p := Packet{
		Op:        binary.BigEndian.Uint16(b[6:8]),
		SenderMAC: net.HardwareAddr(b[8:14]),
		SenderIP:  netip.AddrFrom4([4]byte(b[14:18])),
		TargetMAC: net.HardwareAddr(b[18:24]),
		TargetIP:  netip.AddrFrom4([4]byte(b[24:28])),
	}
	if p.Op != OpRequest && p.Op != OpReply {
		return Packet{}, ErrOpcode
	}
	return p, nil
}

// Classify derives the role from the opcode and the address pattern.
func Classify(p Packet) Role {
	switch {
	case p.Op == OpRequest && p.SenderIP.IsUnspecified():
		return RoleProbe
	case p.SenderIP == p.TargetIP:
		return RoleAnnouncement
	case p.Op == OpReply:
		return RoleReply
	default:
		return RoleRequest
	}
}

// Observation is the typed observation for one ARP packet.
type Observation struct {
	observation.Evidence
	Op        uint16
	Role      Role
	SenderMAC net.HardwareAddr
	SenderIP  netip.Addr
	TargetMAC net.HardwareAddr
	TargetIP  netip.Addr
}

// Kind returns "arp".
func (Observation) Kind() observation.Kind { return Kind }

// IsLinkLocal reports an IPv4 Link-Local (169.254/16) address (R-007).
func IsLinkLocal(a netip.Addr) bool {
	return a.Is4() && a.IsLinkLocalUnicast()
}
