// Package icmpv6 parses ICMPv6 messages with full decoding of the
// Neighbor Discovery family (RFC 4861): router and neighbor solicitation
// and advertisement, with their options, and the Duplicate Address
// Detection pattern of RFC 4862 (R-008). Other types are reported by
// number only. The checksum is not verified.
package icmpv6

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strconv"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Observation kinds.
const (
	KindNDP     observation.Kind = "ndp"
	KindGeneric observation.Kind = "icmpv6"
)

// Message types.
const (
	TypeDestUnreachable = 1
	TypePacketTooBig    = 2
	TypeTimeExceeded    = 3
	TypeParamProblem    = 4
	TypeEchoRequest     = 128
	TypeEchoReply       = 129
	TypeRouterSolicit   = 133
	TypeRouterAdvert    = 134
	TypeNeighborSolicit = 135
	TypeNeighborAdvert  = 136
	TypeRedirect        = 137
)

// NDP option types.
const (
	OptSourceLL   = 1
	OptTargetLL   = 2
	OptPrefixInfo = 3
	OptMTU        = 5
)

// Sizes.
const (
	HeaderLen       = 4
	nsFixedLen      = 20 // reserved(4) + target(16)
	naFixedLen      = 20 // flags(4) + target(16)
	raFixedLen      = 12 // hop limit(1) flags(1) lifetime(2) reachable(4) retrans(4)
	rsFixedLen      = 4
	optUnit         = 8
	prefixInfoLen   = 30
	mtuOptLen       = 6
	ethernetAddrLen = 6
)

var typeNames = map[uint8]string{
	TypeDestUnreachable: "destination-unreachable", TypePacketTooBig: "packet-too-big", TypeTimeExceeded: "time-exceeded",
	TypeParamProblem: "parameter-problem", TypeEchoRequest: "echo-request", TypeEchoReply: "echo-reply",
	TypeRouterSolicit: "router-solicitation", TypeRouterAdvert: "router-advertisement",
	TypeNeighborSolicit: "neighbor-solicitation", TypeNeighborAdvert: "neighbor-advertisement", TypeRedirect: "redirect",
}

// Errors.
var (
	ErrTruncated = errors.New("icmpv6: truncated message")
)

// Prefix is one prefix information option.
type Prefix struct {
	Prefix     netip.Prefix
	OnLink     bool
	Autonomous bool
	ValidLife  uint32
	PrefLife   uint32
}

// Message is a parsed ICMPv6 message.
type Message struct {
	Type uint8
	Code uint8
	// Neighbor discovery fields; zero when not applicable.
	Target         netip.Addr
	Router         bool // NA R flag
	Solicited      bool // NA S flag
	Override       bool // NA O flag
	CurHopLimit    uint8
	Managed        bool // RA M flag
	OtherConfig    bool // RA O flag
	RouterLifetime uint16
	ReachableTime  uint32
	RetransTimer   uint32
	SourceLL       net.HardwareAddr
	TargetLL       net.HardwareAddr
	Prefixes       []Prefix
	MTU            uint32
	Malformed      bool
}

// TypeName returns the message type name or "type-N".
func (m Message) TypeName() string {
	if n, ok := typeNames[m.Type]; ok {
		return n
	}
	return "type-" + strconv.Itoa(int(m.Type))
}

// IsNDP reports whether the message belongs to Neighbor Discovery.
func (m Message) IsNDP() bool {
	return m.Type >= TypeRouterSolicit && m.Type <= TypeRedirect
}

// Parse decodes a message. Option errors mark the message Malformed
// but keep what was decoded before them.
func Parse(b []byte) (Message, error) {
	if len(b) < HeaderLen {
		return Message{}, ErrTruncated
	}
	m := Message{Type: b[0], Code: b[1]}
	body := b[HeaderLen:]
	switch m.Type {
	case TypeRouterSolicit:
		if len(body) < rsFixedLen {
			return m, ErrTruncated
		}
		m.parseOptions(body[rsFixedLen:])
	case TypeRouterAdvert:
		if len(body) < raFixedLen {
			return m, ErrTruncated
		}
		m.CurHopLimit = body[0]
		m.Managed = body[1]&0x80 != 0
		m.OtherConfig = body[1]&0x40 != 0
		m.RouterLifetime = binary.BigEndian.Uint16(body[2:4])
		m.ReachableTime = binary.BigEndian.Uint32(body[4:8])
		m.RetransTimer = binary.BigEndian.Uint32(body[8:12])
		m.parseOptions(body[raFixedLen:])
	case TypeNeighborSolicit:
		if len(body) < nsFixedLen {
			return m, ErrTruncated
		}
		m.Target = netip.AddrFrom16([16]byte(body[4:20]))
		m.parseOptions(body[nsFixedLen:])
	case TypeNeighborAdvert:
		if len(body) < naFixedLen {
			return m, ErrTruncated
		}
		m.Router = body[0]&0x80 != 0
		m.Solicited = body[0]&0x40 != 0
		m.Override = body[0]&0x20 != 0
		m.Target = netip.AddrFrom16([16]byte(body[4:20]))
		m.parseOptions(body[naFixedLen:])
	case TypeRedirect:
		if len(body) < 36 {
			return m, ErrTruncated
		}
		m.Target = netip.AddrFrom16([16]byte(body[4:20]))
		m.parseOptions(body[36:])
	}
	return m, nil
}

func (m *Message) parseOptions(b []byte) {
	for len(b) >= 2 {
		typ := b[0]
		n := int(b[1]) * optUnit
		if n == 0 || n > len(b) {
			m.Malformed = true
			return
		}
		v := b[2:n]
		switch typ {
		case OptSourceLL:
			if len(v) >= ethernetAddrLen {
				m.SourceLL = net.HardwareAddr(append([]byte(nil), v[:ethernetAddrLen]...))
			}
		case OptTargetLL:
			if len(v) >= ethernetAddrLen {
				m.TargetLL = net.HardwareAddr(append([]byte(nil), v[:ethernetAddrLen]...))
			}
		case OptPrefixInfo:
			if len(v) >= prefixInfoLen {
				plen := int(v[0])
				if plen > 128 {
					plen = 128
				}
				m.Prefixes = append(m.Prefixes, Prefix{
					Prefix:     netip.PrefixFrom(netip.AddrFrom16([16]byte(v[14:30])), plen),
					OnLink:     v[1]&0x80 != 0,
					Autonomous: v[1]&0x40 != 0,
					ValidLife:  binary.BigEndian.Uint32(v[2:6]),
					PrefLife:   binary.BigEndian.Uint32(v[6:10]),
				})
			} else {
				m.Malformed = true
			}
		case OptMTU:
			if len(v) >= mtuOptLen {
				m.MTU = binary.BigEndian.Uint32(v[2:6])
			}
		}
		b = b[n:]
	}
}

// Observation is the typed observation for one ICMPv6 message. DAD is
// set for a neighbor solicitation sent from the unspecified address.
type Observation struct {
	observation.Evidence
	Message
	Src netip.Addr
	Dst netip.Addr
	DAD bool
}

// Kind returns "ndp" for Neighbor Discovery messages and "icmpv6" otherwise.
func (o Observation) Kind() observation.Kind {
	if o.IsNDP() {
		return KindNDP
	}
	return KindGeneric
}
