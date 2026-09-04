// Package active holds every code path that transmits packets (ADR-0007).
// It is imported only by the explicit active commands (probe, connect);
// a test in internal/boundary keeps it out of the passive packages. The
// budget rules of the ADR-0007 amendment live here as constants: bounded
// targets, a fixed rate, no automatic retry.
package active

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

// Budget constants from the ADR-0007 amendment.
const (
	MaxPrefixHosts = 256 // one /24 at most
	MinPrefixBits  = 24
	RatePerSecond  = 20
	SendInterval   = time.Second / RatePerSecond
)

// RFC 5227 probe parameters.
const (
	ProbeCount    = 3
	ProbeInterval = time.Second
	AnnounceWait  = 2 * time.Second
)

// frameLen is this sender's own Ethernet/ARP frame layout; every other
// wire value comes from the protocol packages.
const frameLen = 42

// Errors.
var (
	ErrPrefixTooLarge = errors.New("active: target prefix larger than /24 is not allowed")
	ErrNoIPv4         = errors.New("active: interface has no IPv4 address to send from")
)

// Reply is one ARP reply or claim heard while probing.
type Reply struct {
	At       time.Time
	MAC      net.HardwareAddr
	IP       netip.Addr
	Kind     arp.Role
	TargetIP netip.Addr
}

// Plan states what an action will transmit, printed before the first
// packet leaves (ADR-0007).
type Plan struct {
	Interface string
	Protocol  string
	Targets   []netip.Addr
	Count     int
	Rate      int
}

// String renders the plan for the terminal.
func (p Plan) String() string {
	first, last := "", ""
	if len(p.Targets) > 0 {
		first, last = p.Targets[0].String(), p.Targets[len(p.Targets)-1].String()
	}
	if first == last {
		return fmt.Sprintf("transmit %d %s packet(s) on %s to %s at %d/s", p.Count, p.Protocol, p.Interface, first, p.Rate)
	}
	return fmt.Sprintf("transmit %d %s packet(s) on %s to %s..%s at %d/s", p.Count, p.Protocol, p.Interface, first, last, p.Rate)
}

// ARPFrame builds an Ethernet/ARP frame from this host.
func ARPFrame(srcMAC net.HardwareAddr, op uint16, senderIP netip.Addr, targetMAC net.HardwareAddr, targetIP netip.Addr) []byte {
	f := make([]byte, frameLen)
	dst := net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if op == arp.OpReply && targetMAC != nil {
		dst = targetMAC
	}
	copy(f[0:6], dst)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:], ethernet.EtherTypeARP)
	binary.BigEndian.PutUint16(f[14:], arp.HardwareEthernet)
	binary.BigEndian.PutUint16(f[16:], arp.ProtocolIPv4)
	f[18], f[19] = arp.HardwareAddrLen, arp.ProtocolAddrLen
	binary.BigEndian.PutUint16(f[20:], op)
	copy(f[22:28], srcMAC)
	s := senderIP.As4()
	copy(f[28:32], s[:])
	if targetMAC != nil {
		copy(f[32:38], targetMAC)
	}
	t := targetIP.As4()
	copy(f[38:42], t[:])
	return f
}

// ProbeFrame builds an RFC 5227 probe (sender address unspecified).
func ProbeFrame(srcMAC net.HardwareAddr, target netip.Addr) []byte {
	return ARPFrame(srcMAC, arp.OpRequest, netip.AddrFrom4([4]byte{}), nil, target)
}

// Hosts enumerates the usable host addresses of a prefix, refusing
// anything larger than a /24.
func Hosts(p netip.Prefix) ([]netip.Addr, error) {
	if !p.Addr().Is4() {
		return nil, errors.New("active: IPv4 prefix required")
	}
	if p.Bits() < MinPrefixBits {
		return nil, ErrPrefixTooLarge
	}
	p = p.Masked()
	if p.Bits() == 32 {
		return []netip.Addr{p.Addr()}, nil
	}
	n := 1 << (32 - p.Bits())
	base := binary.BigEndian.Uint32(func() []byte { a := p.Addr().As4(); return a[:] }())
	var out []netip.Addr
	for i := 1; i < n-1; i++ {
		v := base + uint32(i)
		out = append(out, netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}))
	}
	if p.Bits() == 31 {
		out = []netip.Addr{p.Addr(), netip.AddrFrom4([4]byte{byte(base >> 24), byte(base >> 16), byte(base >> 8), byte(base + 1)})}
	}
	return out, nil
}

// parseARP decodes a received Ethernet frame into a Reply through the
// passive ARP parser and classifier; ok is false for anything that is
// not Ethernet/IPv4 ARP with a request or reply opcode. The sender MAC
// is copied out of the reused receive buffer.
func parseARP(b []byte) (Reply, bool) {
	if len(b) < frameLen || binary.BigEndian.Uint16(b[12:]) != ethernet.EtherTypeARP {
		return Reply{}, false
	}
	p, err := arp.Parse(b[ethernet.HeaderLen:])
	if err != nil {
		return Reply{}, false
	}
	return Reply{
		MAC:      append(net.HardwareAddr(nil), p.SenderMAC...),
		IP:       p.SenderIP,
		TargetIP: p.TargetIP,
		Kind:     arp.Classify(p),
	}, true
}

// Conflicts reports whether a heard ARP packet contradicts our claim
// on target: someone replies for it, announces it, or probes it too.
func Conflicts(r Reply, target netip.Addr, self net.HardwareAddr) bool {
	if r.MAC.String() == self.String() {
		return false
	}
	switch r.Kind {
	case arp.RoleReply, arp.RoleAnnouncement, arp.RoleRequest:
		return r.IP == target
	case arp.RoleProbe:
		return r.TargetIP == target
	}
	return false
}
