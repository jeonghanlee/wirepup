// Package ipv4 parses the IPv4 header far enough for source and
// destination addresses, upper-layer dispatch, and fragment detection.
// Options are skipped, not interpreted.
package ipv4

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Header constants.
const (
	MinHeaderLen = 20
	version      = 4
	fragOffMask  = 0x1fff
	moreFragBit  = 0x2000
)

// IP protocol numbers WirePup dispatches on.
const (
	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58
)

// Kind is the observation kind.
const Kind observation.Kind = "ipv4"

// Errors returned by Parse.
var (
	ErrTruncated = errors.New("ipv4: truncated header")
	ErrVersion   = errors.New("ipv4: not version 4")
	ErrHeaderLen = errors.New("ipv4: header length below 20")
)

// Packet is a parsed IPv4 header with its payload.
type Packet struct {
	HeaderLen   int
	TotalLen    int
	TTL         uint8
	Protocol    uint8
	Src         netip.Addr
	Dst         netip.Addr
	FragOffset  uint16
	MoreFrags   bool
	Truncated   bool // the buffer was shorter than TotalLen
	Payload     []byte
	PayloadDrop bool // payload withheld because this is a non-first fragment
}

// Parse decodes the header. A buffer shorter than the declared total
// length still parses, with Truncated set and the payload cut to what
// is present. Non-first fragments keep no payload for upper layers.
func Parse(b []byte) (Packet, error) {
	if len(b) < MinHeaderLen {
		return Packet{}, ErrTruncated
	}
	if b[0]>>4 != version {
		return Packet{}, ErrVersion
	}
	hl := int(b[0]&0x0f) * 4
	if hl < MinHeaderLen {
		return Packet{}, ErrHeaderLen
	}
	if len(b) < hl {
		return Packet{}, ErrTruncated
	}
	p := Packet{
		HeaderLen: hl,
		TotalLen:  int(binary.BigEndian.Uint16(b[2:4])),
		TTL:       b[8],
		Protocol:  b[9],
		Src:       netip.AddrFrom4([4]byte(b[12:16])),
		Dst:       netip.AddrFrom4([4]byte(b[16:20])),
	}
	ff := binary.BigEndian.Uint16(b[6:8])
	p.FragOffset = ff & fragOffMask
	p.MoreFrags = ff&moreFragBit != 0
	end := p.TotalLen
	if end < hl {
		end = hl
	}
	if end > len(b) {
		end = len(b)
		p.Truncated = true
	}
	if p.FragOffset != 0 {
		p.PayloadDrop = true
		return p, nil
	}
	p.Payload = b[hl:end]
	return p, nil
}

// Observation is the per-packet IPv4 observation used for weak MAC-to-IP
// association and traffic summaries.
type Observation struct {
	observation.Evidence
	Src      netip.Addr
	Dst      netip.Addr
	Protocol uint8
	TTL      uint8
	Length   int
	Fragment bool
}

// Kind returns "ipv4".
func (Observation) Kind() observation.Kind { return Kind }

// ProtocolName returns a short name for common protocol numbers.
func ProtocolName(p uint8) string {
	switch p {
	case ProtoICMP:
		return "icmp"
	case ProtoTCP:
		return "tcp"
	case ProtoUDP:
		return "udp"
	case ProtoICMPv6:
		return "icmpv6"
	default:
		return "proto-" + itoa(int(p))
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [4]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
