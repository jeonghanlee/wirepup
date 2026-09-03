// Package ipv6 parses the IPv6 fixed header and walks the extension
// header chain far enough for upper-layer dispatch. Non-first fragments
// keep no payload; the walk is bounded so a crafted chain cannot loop.
package ipv6

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Header constants.
const (
	HeaderLen     = 40
	version       = 6
	maxExtHeaders = 8
	fragHeaderLen = 8
)

// Next-header values.
const (
	NextHopByHop  = 0
	NextTCP       = 6
	NextUDP       = 17
	NextRouting   = 43
	NextFragment  = 44
	NextESP       = 50
	NextAH        = 51
	NextICMPv6    = 58
	NextNone      = 59
	NextDestOpts  = 60
	NextMobility  = 135
	NextHostIdent = 139
	NextShim6     = 140
)

// Kind is the observation kind.
const Kind observation.Kind = "ipv6"

// Errors returned by Parse.
var (
	ErrTruncated = errors.New("ipv6: truncated header")
	ErrVersion   = errors.New("ipv6: not version 6")
)

// Packet is a parsed IPv6 packet.
type Packet struct {
	NextHeader  uint8 // upper-layer protocol after extension headers
	HopLimit    uint8
	PayloadLen  int
	Src         netip.Addr
	Dst         netip.Addr
	Fragment    bool
	PayloadDrop bool // non-first fragment or unparsable chain
	Truncated   bool
	ExtHeaders  int
	Payload     []byte
}

// Parse decodes the fixed header and skips extension headers.
func Parse(b []byte) (Packet, error) {
	if len(b) < HeaderLen {
		return Packet{}, ErrTruncated
	}
	if b[0]>>4 != version {
		return Packet{}, ErrVersion
	}
	p := Packet{
		NextHeader: b[6],
		HopLimit:   b[7],
		PayloadLen: int(binary.BigEndian.Uint16(b[4:6])),
		Src:        netip.AddrFrom16([16]byte(b[8:24])),
		Dst:        netip.AddrFrom16([16]byte(b[24:40])),
	}
	end := HeaderLen + p.PayloadLen
	if end > len(b) {
		end = len(b)
		p.Truncated = true
	}
	body := b[HeaderLen:end]
	for i := 0; i < maxExtHeaders; i++ {
		var hl int
		switch p.NextHeader {
		case NextHopByHop, NextRouting, NextDestOpts, NextMobility, NextHostIdent, NextShim6:
			if len(body) < 2 {
				p.PayloadDrop = true
				return p, nil
			}
			hl = (int(body[1]) + 1) * 8
		case NextAH:
			if len(body) < 2 {
				p.PayloadDrop = true
				return p, nil
			}
			hl = (int(body[1]) + 2) * 4
		case NextFragment:
			if len(body) < fragHeaderLen {
				p.PayloadDrop = true
				return p, nil
			}
			p.Fragment = true
			off := binary.BigEndian.Uint16(body[2:4]) >> 3
			hl = fragHeaderLen
			if off != 0 {
				p.NextHeader = body[0]
				p.ExtHeaders++
				p.PayloadDrop = true
				return p, nil
			}
		default:
			p.Payload = body
			return p, nil
		}
		if hl > len(body) {
			p.PayloadDrop = true
			return p, nil
		}
		p.NextHeader = body[0]
		p.ExtHeaders++
		body = body[hl:]
	}
	p.PayloadDrop = true
	return p, nil
}

// Observation is the per-packet IPv6 observation.
type Observation struct {
	observation.Evidence
	Src        netip.Addr
	Dst        netip.Addr
	NextHeader uint8
	HopLimit   uint8
	Length     int
	Fragment   bool
}

// Kind returns "ipv6".
func (Observation) Kind() observation.Kind { return Kind }
