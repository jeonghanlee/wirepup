// Package ca parses EPICS Channel Access protocol messages. Field
// layout follows caProto.h and the UDP/TCP stubs in EPICS Base
// (modules/ca/src/client/udpiiu.cpp, modules/database/src/ioc/rsrv):
// a 16-byte big-endian header of command, payload size, data type,
// count, cid, and available, extended to 24 bytes when payload size is
// 0xffff and count is 0. Identification validates structure, never the
// port alone (R-018).
package ca

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Ports and sizes.
const (
	DefaultServerPort   = 5064
	DefaultRepeaterPort = 5065
	HeaderLen           = 16
	ExtendedHeaderLen   = 24
	extendedMarker      = 0xffff
	payloadAlign        = 8
	maxPVNameLen        = 512
	MinorRevision       = 13 // CA_MINOR_PROTOCOL_REVISION in nciu.h
	AnySender           = 0xffffffff
)

// Commands from caProto.h.
const (
	CmdVersion         = 0
	CmdEventAdd        = 1
	CmdEventCancel     = 2
	CmdRead            = 3
	CmdWrite           = 4
	CmdSnapshot        = 5
	CmdSearch          = 6
	CmdBuild           = 7
	CmdEventsOff       = 8
	CmdEventsOn        = 9
	CmdReadSync        = 10
	CmdError           = 11
	CmdClearChannel    = 12
	CmdBeacon          = 13 // CA_PROTO_RSRV_IS_UP
	CmdNotFound        = 14
	CmdReadNotify      = 15
	CmdReadBuild       = 16
	CmdRepeaterConfirm = 17
	CmdCreateChan      = 18
	CmdWriteNotify     = 19
	CmdClientName      = 20
	CmdHostName        = 21
	CmdAccessRights    = 22
	CmdEcho            = 23
	CmdRepeaterReg     = 24
	CmdSignal          = 25
	CmdCreateChanFail  = 26
	CmdServerDisconn   = 27
	lastCommand        = CmdServerDisconn
)

// Search reply flags (caProto.h).
const (
	DoReply   = 10
	DontReply = 5
)

var commandNames = map[uint16]string{
	CmdVersion: "version", CmdEventAdd: "event_add", CmdEventCancel: "event_cancel", CmdRead: "read", CmdWrite: "write",
	CmdSnapshot: "snapshot", CmdSearch: "search", CmdBuild: "build", CmdEventsOff: "events_off", CmdEventsOn: "events_on",
	CmdReadSync: "read_sync", CmdError: "error", CmdClearChannel: "clear_channel", CmdBeacon: "beacon", CmdNotFound: "not_found",
	CmdReadNotify: "read_notify", CmdReadBuild: "read_build", CmdRepeaterConfirm: "repeater_confirm", CmdCreateChan: "create_channel",
	CmdWriteNotify: "write_notify", CmdClientName: "client_name", CmdHostName: "host_name", CmdAccessRights: "access_rights",
	CmdEcho: "echo", CmdRepeaterReg: "repeater_register", CmdSignal: "signal", CmdCreateChanFail: "create_channel_fail", CmdServerDisconn: "server_disconnect",
}

// Commands that may appear in a UDP datagram.
var udpCommands = map[uint16]bool{CmdVersion: true, CmdSearch: true, CmdNotFound: true, CmdBeacon: true, CmdRepeaterReg: true, CmdRepeaterConfirm: true, CmdEcho: true}

// Errors.
var (
	ErrTruncated = errors.New("ca: truncated message")
	ErrCommand   = errors.New("ca: unknown command")
	ErrPayload   = errors.New("ca: payload runs past the end")
	ErrNotCA     = errors.New("ca: not a channel access datagram")
)

// Header is a decoded message header.
type Header struct {
	Command     uint16
	PayloadSize uint32
	DataType    uint16
	Count       uint32
	CID         uint32
	Available   uint32
	HeaderLen   int
}

// ParseHeader decodes a standard or extended header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrTruncated
	}
	h := Header{
		Command:     binary.BigEndian.Uint16(b[0:2]),
		PayloadSize: uint32(binary.BigEndian.Uint16(b[2:4])),
		DataType:    binary.BigEndian.Uint16(b[4:6]),
		Count:       uint32(binary.BigEndian.Uint16(b[6:8])),
		CID:         binary.BigEndian.Uint32(b[8:12]),
		Available:   binary.BigEndian.Uint32(b[12:16]),
		HeaderLen:   HeaderLen,
	}
	if h.PayloadSize == extendedMarker && h.Count == 0 {
		if len(b) < ExtendedHeaderLen {
			return Header{}, ErrTruncated
		}
		h.PayloadSize = binary.BigEndian.Uint32(b[16:20])
		h.Count = binary.BigEndian.Uint32(b[20:24])
		h.HeaderLen = ExtendedHeaderLen
	}
	if h.Command > lastCommand {
		return h, ErrCommand
	}
	return h, nil
}

// Message is one header with its payload.
type Message struct {
	Header
	Payload []byte
}

// CommandName returns the caProto.h name without the CA_PROTO_ prefix,
// lower-cased.
func (m Message) CommandName() string {
	if n, ok := commandNames[m.Command]; ok {
		return n
	}
	return fmt.Sprintf("cmd_%d", m.Command)
}

// Parse decodes consecutive messages. udp restricts commands to the
// datagram set. Parsing stops at the first error; the messages decoded
// before it are returned with the error.
func Parse(b []byte, udp bool) ([]Message, error) {
	var out []Message
	off := 0
	for off < len(b) {
		h, err := ParseHeader(b[off:])
		if err != nil {
			return out, err
		}
		if udp && !udpCommands[h.Command] {
			return out, ErrNotCA
		}
		start := off + h.HeaderLen
		end := start + int(h.PayloadSize)
		if end > len(b) || end < start {
			return out, ErrPayload
		}
		out = append(out, Message{Header: h, Payload: b[start:end]})
		off = end
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// Probable reports whether the bytes look like a CA datagram from
// their first header alone, for traffic on non-default ports.
func Probable(b []byte) bool {
	h, err := ParseHeader(b)
	if err != nil {
		return false
	}
	switch h.Command {
	case CmdSearch:
		return (h.DataType == DoReply || h.DataType == DontReply || h.CID == AnySender) && h.PayloadSize%payloadAlign == 0
	case CmdBeacon:
		return h.PayloadSize == 0 && h.Count != 0 && h.Count < 65536
	case CmdVersion:
		return h.PayloadSize == 0 && h.Count <= 64
	}
	return false
}

// Direction of a message relative to the server.
const (
	ToServer   = "request"
	FromServer = "response"
)

// Observation is the typed observation for one CA message.
type Observation struct {
	observation.Evidence
	Message
	Transport string // "udp" or "tcp"
	Src       netip.Addr
	Dst       netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Direction string
	// Interpreted fields; zero when not applicable to the command.
	PVName       string
	SearchID     uint32
	ReplyWanted  bool
	MinorVersion uint16
	ServerPort   uint16
	ServerIP     netip.Addr // resolved: the packet source when the message says "sender"
	BeaconID     uint32
	Text         string // client name, host name
	Rights       uint32
	SID          uint32
}

// Kind returns "ca.<message>" where message distinguishes search
// requests from responses.
func (o Observation) Kind() observation.Kind {
	switch o.Command {
	case CmdSearch:
		if o.Direction == FromServer {
			return "ca.search_response"
		}
		return "ca.search"
	case CmdCreateChan:
		if o.Direction == FromServer {
			return "ca.create_channel_response"
		}
		return "ca.create_channel"
	}
	return observation.Kind("ca." + o.CommandName())
}

// Interpret fills the interpreted fields from the header, payload, and
// transport context. serverPort is the known server port; a message
// whose direction the header does not reveal is a request when it is
// addressed to that port and a response otherwise.
func Interpret(m Message, transport string, src, dst netip.Addr, srcPort, dstPort uint16, serverPort uint16) Observation {
	o := Observation{Message: m, Transport: transport, Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort}
	switch m.Command {
	case CmdSearch:
		if isSearchResponse(m) {
			o.Direction = FromServer
			o.SearchID = m.Available
			o.ServerPort = m.DataType
			o.ServerIP = src
			if m.CID != AnySender {
				o.ServerIP = addrFromU32(m.CID)
			}
			if len(m.Payload) >= 2 {
				o.MinorVersion = binary.BigEndian.Uint16(m.Payload[0:2])
			}
		} else {
			o.Direction = ToServer
			o.SearchID = m.CID
			o.PVName = cString(m.Payload)
			o.ReplyWanted = m.DataType == DoReply
			o.MinorVersion = uint16(m.Count)
		}
	case CmdNotFound:
		o.Direction = FromServer
		o.SearchID = m.Available
		o.ServerIP = src
	case CmdBeacon:
		o.Direction = FromServer
		o.MinorVersion = m.DataType
		o.ServerPort = uint16(m.Count)
		o.BeaconID = m.CID
		o.ServerIP = src
		if m.Available != 0 {
			o.ServerIP = addrFromU32(m.Available)
		}
	case CmdVersion:
		o.MinorVersion = uint16(m.Count)
		o.Direction = directionByPort(dstPort, serverPort)
	case CmdRepeaterReg, CmdRepeaterConfirm:
		o.Direction = ToServer
		if m.Command == CmdRepeaterConfirm {
			o.Direction = FromServer
		}
		if m.Available != 0 {
			o.ServerIP = addrFromU32(m.Available)
		}
	case CmdCreateChan:
		if len(m.Payload) > 0 {
			o.Direction = ToServer
			o.PVName = cString(m.Payload)
			o.MinorVersion = uint16(m.Available)
		} else {
			o.Direction = FromServer
			o.SID = m.Available
		}
	case CmdClientName, CmdHostName:
		o.Direction = ToServer
		o.Text = cString(m.Payload)
	case CmdAccessRights:
		o.Direction = FromServer
		o.Rights = m.Available
	case CmdCreateChanFail, CmdServerDisconn, CmdError:
		o.Direction = FromServer
	default:
		o.Direction = directionByPort(dstPort, serverPort)
	}
	return o
}

// isSearchResponse tells a search reply from a request: replies carry
// the server port in data type, count 0, and the "any sender" cid or
// a server address, with an empty or 8-byte payload.
func isSearchResponse(m Message) bool {
	if len(m.Payload) > 0 && m.CID == m.Available && (m.DataType == DoReply || m.DataType == DontReply) {
		return false
	}
	return m.Count == 0 && (len(m.Payload) == 0 || len(m.Payload) == payloadAlign)
}

func directionByPort(dstPort, serverPort uint16) string {
	if dstPort == serverPort {
		return ToServer
	}
	return FromServer
}

func addrFromU32(v uint32) netip.Addr {
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// cString returns the printable text up to the first NUL, or "" when
// the payload holds anything that is not printable ASCII.
func cString(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	if len(b) > maxPVNameLen {
		return ""
	}
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return ""
		}
	}
	return string(b)
}

// SearchDatagram builds the client datagram caget sends: a version
// message followed by one search for the PV (udpiiu.cpp searchMsg).
func SearchDatagram(id uint32, pv string, replyWanted bool) []byte {
	b := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(b[0:], CmdVersion)
	binary.BigEndian.PutUint16(b[4:], 1) // sequence number valid
	binary.BigEndian.PutUint16(b[6:], MinorRevision)
	binary.BigEndian.PutUint32(b[8:], id)
	name := append([]byte(pv), 0)
	for len(name)%payloadAlign != 0 {
		name = append(name, 0)
	}
	h := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(h[0:], CmdSearch)
	binary.BigEndian.PutUint16(h[2:], uint16(len(name)))
	flag := uint16(DontReply)
	if replyWanted {
		flag = DoReply
	}
	binary.BigEndian.PutUint16(h[4:], flag)
	binary.BigEndian.PutUint16(h[6:], MinorRevision)
	binary.BigEndian.PutUint32(h[8:], id)
	binary.BigEndian.PutUint32(h[12:], id)
	return append(append(b, h...), name...)
}

// SearchReplyDatagram builds a server UDP reply as rsrv does
// (camessage.c search_reply_udp): port in data type, count 0, cid
// "any sender", the search id in available, minor version payload.
func SearchReplyDatagram(id uint32, serverPort uint16) []byte {
	h := make([]byte, HeaderLen+payloadAlign)
	binary.BigEndian.PutUint16(h[0:], CmdSearch)
	binary.BigEndian.PutUint16(h[2:], payloadAlign)
	binary.BigEndian.PutUint16(h[4:], serverPort)
	binary.BigEndian.PutUint32(h[8:], AnySender)
	binary.BigEndian.PutUint32(h[12:], id)
	binary.BigEndian.PutUint16(h[16:], MinorRevision)
	return h
}

// BeaconDatagram builds a server beacon (online_notify.c).
func BeaconDatagram(serverPort uint16, beaconID uint32, serverIP netip.Addr) []byte {
	h := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(h[0:], CmdBeacon)
	binary.BigEndian.PutUint16(h[4:], MinorRevision)
	binary.BigEndian.PutUint16(h[6:], serverPort)
	binary.BigEndian.PutUint32(h[8:], beaconID)
	if serverIP.IsValid() {
		a := serverIP.As4()
		copy(h[12:16], a[:])
	}
	return h
}
