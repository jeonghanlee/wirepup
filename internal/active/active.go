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

// Wire constants.
const (
	etherTypeARP = 0x0806
	opRequest    = 1
	opReply      = 2
	frameLen     = 42
)

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
	Kind     string // "reply", "announcement", "probe"
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
	if op == opReply && targetMAC != nil {
		dst = targetMAC
	}
	copy(f[0:6], dst)
	copy(f[6:12], srcMAC)
	binary.BigEndian.PutUint16(f[12:], etherTypeARP)
	binary.BigEndian.PutUint16(f[14:], 1)
	binary.BigEndian.PutUint16(f[16:], 0x0800)
	f[18], f[19] = 6, 4
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
	return ARPFrame(srcMAC, opRequest, netip.AddrFrom4([4]byte{}), nil, target)
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

// parseARP decodes a received ARP frame into a Reply; ok is false for
// anything that is not Ethernet/IPv4 ARP.
func parseARP(b []byte) (Reply, bool) {
	if len(b) < frameLen || binary.BigEndian.Uint16(b[12:]) != etherTypeARP {
		return Reply{}, false
	}
	if binary.BigEndian.Uint16(b[14:]) != 1 || binary.BigEndian.Uint16(b[16:]) != 0x0800 || b[18] != 6 || b[19] != 4 {
		return Reply{}, false
	}
	r := Reply{
		MAC:      net.HardwareAddr(append([]byte(nil), b[22:28]...)),
		IP:       netip.AddrFrom4([4]byte(b[28:32])),
		TargetIP: netip.AddrFrom4([4]byte(b[38:42])),
	}
	op := binary.BigEndian.Uint16(b[20:])
	switch {
	case op == opRequest && r.IP.IsUnspecified():
		r.Kind = "probe"
	case r.IP == r.TargetIP:
		r.Kind = "announcement"
	case op == opReply:
		r.Kind = "reply"
	default:
		r.Kind = "request"
	}
	return r, true
}

// Conflicts reports whether a heard ARP packet contradicts our claim
// on target: someone replies for it, announces it, or probes it too.
func Conflicts(r Reply, target netip.Addr, self net.HardwareAddr) bool {
	if r.MAC.String() == self.String() {
		return false
	}
	switch r.Kind {
	case "reply", "announcement", "request":
		return r.IP == target
	case "probe":
		return r.TargetIP == target
	}
	return false
}
