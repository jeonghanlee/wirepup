// Package dhcpv4 parses BOOTP/DHCPv4 messages (RFC 2131) far enough to
// identify the message type, the client, and the addresses being
// offered or acknowledged (R-006). Options are collected by code; the
// ones WirePup interprets are exposed as fields.
package dhcpv4

import (
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"strings"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Kind is the observation kind.
const Kind observation.Kind = "dhcp"

// Ports and fixed sizes.
const (
	ServerPort  = 67
	ClientPort  = 68
	FixedLen    = 236
	cookieLen   = 4
	chaddrLen   = 16
	snameLen    = 64
	fileLen     = 128
	MagicCookie = 0x63825363
)

// Op codes.
const (
	OpRequest = 1
	OpReply   = 2
)

// Option codes WirePup interprets.
const (
	OptPad          = 0
	OptSubnetMask   = 1
	OptRouter       = 3
	OptDNS          = 6
	OptHostname     = 12
	OptRequestedIP  = 50
	OptLeaseTime    = 51
	OptMessageType  = 53
	OptServerID     = 54
	OptParamRequest = 55
	OptClientID     = 61
	OptEnd          = 255
)

// Message types (option 53).
const (
	Discover = 1
	Offer    = 2
	Request  = 3
	Decline  = 4
	ACK      = 5
	NAK      = 6
	Release  = 7
	Inform   = 8
)

var typeNames = map[uint8]string{
	Discover: "discover", Offer: "offer", Request: "request", Decline: "decline",
	ACK: "ack", NAK: "nak", Release: "release", Inform: "inform",
}

// Errors.
var (
	ErrTruncated = errors.New("dhcpv4: truncated message")
	ErrCookie    = errors.New("dhcpv4: missing magic cookie")
	ErrOptions   = errors.New("dhcpv4: option runs past the end")
	ErrOp        = errors.New("dhcpv4: unknown op")
)

// Message is a parsed DHCPv4 message.
type Message struct {
	Op          uint8
	HType       uint8
	HLen        uint8
	XID         uint32
	Secs        uint16
	Broadcast   bool
	ClientIP    netip.Addr // ciaddr
	YourIP      netip.Addr // yiaddr
	ServerIP    netip.Addr // siaddr
	RelayIP     netip.Addr // giaddr
	ClientMAC   net.HardwareAddr
	ServerName  string
	MessageType uint8
	Hostname    string
	RequestedIP netip.Addr
	ServerID    netip.Addr
	LeaseTime   uint32
	SubnetMask  netip.Addr
	Routers     []netip.Addr
	DNS         []netip.Addr
	ClientID    string
	Options     map[uint8][]byte
}

// TypeName returns the message type name, or "unknown".
func (m Message) TypeName() string {
	if n, ok := typeNames[m.MessageType]; ok {
		return n
	}
	return "unknown"
}

// Parse decodes a message. A message without the magic cookie is plain
// BOOTP and is rejected: WirePup only claims DHCP when the cookie is
// present.
func Parse(b []byte) (Message, error) {
	if len(b) < FixedLen+cookieLen {
		return Message{}, ErrTruncated
	}
	if binary.BigEndian.Uint32(b[FixedLen:FixedLen+cookieLen]) != MagicCookie {
		return Message{}, ErrCookie
	}
	m := Message{
		Op:        b[0],
		HType:     b[1],
		HLen:      b[2],
		XID:       binary.BigEndian.Uint32(b[4:8]),
		Secs:      binary.BigEndian.Uint16(b[8:10]),
		Broadcast: b[10]&0x80 != 0,
		ClientIP:  netip.AddrFrom4([4]byte(b[12:16])),
		YourIP:    netip.AddrFrom4([4]byte(b[16:20])),
		ServerIP:  netip.AddrFrom4([4]byte(b[20:24])),
		RelayIP:   netip.AddrFrom4([4]byte(b[24:28])),
		Options:   map[uint8][]byte{},
	}
	if m.Op != OpRequest && m.Op != OpReply {
		return Message{}, ErrOp
	}
	hl := int(m.HLen)
	if hl > chaddrLen {
		hl = chaddrLen
	}
	m.ClientMAC = net.HardwareAddr(append([]byte(nil), b[28:28+hl]...))
	m.ServerName = cString(b[44 : 44+snameLen])
	if err := m.parseOptions(b[FixedLen+cookieLen:]); err != nil {
		return m, err
	}
	return m, nil
}

func (m *Message) parseOptions(b []byte) error {
	for i := 0; i < len(b); {
		code := b[i]
		if code == OptPad {
			i++
			continue
		}
		if code == OptEnd {
			return nil
		}
		if i+2 > len(b) {
			return ErrOptions
		}
		n := int(b[i+1])
		if i+2+n > len(b) {
			return ErrOptions
		}
		v := b[i+2 : i+2+n]
		m.Options[code] = v
		m.interpret(code, v)
		i += 2 + n
	}
	return nil
}

func (m *Message) interpret(code uint8, v []byte) {
	switch code {
	case OptMessageType:
		if len(v) == 1 {
			m.MessageType = v[0]
		}
	case OptHostname:
		m.Hostname = cString(v)
	case OptRequestedIP:
		m.RequestedIP = addr4(v)
	case OptServerID:
		m.ServerID = addr4(v)
	case OptSubnetMask:
		m.SubnetMask = addr4(v)
	case OptLeaseTime:
		if len(v) == 4 {
			m.LeaseTime = binary.BigEndian.Uint32(v)
		}
	case OptRouter:
		m.Routers = addrList(v)
	case OptDNS:
		m.DNS = addrList(v)
	case OptClientID:
		m.ClientID = clientID(v)
	}
}

func addr4(v []byte) netip.Addr {
	if len(v) != 4 {
		return netip.Addr{}
	}
	return netip.AddrFrom4([4]byte(v))
}

func addrList(v []byte) []netip.Addr {
	var out []netip.Addr
	for i := 0; i+4 <= len(v); i += 4 {
		out = append(out, netip.AddrFrom4([4]byte(v[i:i+4])))
	}
	return out
}

// clientID renders option 61: type 1 is a MAC address, anything else is
// shown as hex behind its type.
func clientID(v []byte) string {
	if len(v) < 2 {
		return ""
	}
	if v[0] == 1 && len(v) == 7 {
		return net.HardwareAddr(v[1:]).String()
	}
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	sb.WriteString("type")
	sb.WriteString(itoa(int(v[0])))
	sb.WriteString(":")
	for _, c := range v[1:] {
		sb.WriteByte(hexdigits[c>>4])
		sb.WriteByte(hexdigits[c&0x0f])
	}
	return sb.String()
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

func cString(v []byte) string {
	if i := strings.IndexByte(string(v), 0); i >= 0 {
		v = v[:i]
	}
	return strings.TrimSpace(string(v))
}

// Observation is the typed observation for one DHCPv4 message.
type Observation struct {
	observation.Evidence
	Message
	SrcIP netip.Addr
	DstIP netip.Addr
}

// Kind returns "dhcp".
func (Observation) Kind() observation.Kind { return Kind }
