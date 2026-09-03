// Package pva parses EPICS PVAccess protocol messages as specified in
// the epics-docs PVAccess protocol (Protocol-Messages.md and
// Protocol-Encoding.md): an 8-byte header of magic 0xCA, version,
// flags, command, and payload size in the byte order the flags name,
// followed by the payloads of the discovery messages WirePup needs
// (beacon, search, search response, connection validation, create
// channel). Identification validates the header, never the port alone
// (R-019).
package pva

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Ports and sizes.
const (
	DefaultUDPPort = 5076
	DefaultTCPPort = 5075
	HeaderLen      = 8
	Magic          = 0xCA
	guidLen        = 12
	addrLen        = 16
	maxChannelName = 500
	maxVersion     = 2
)

// Header flag bits.
const (
	FlagControl   = 0x01
	FlagSegment   = 0x30
	FlagServer    = 0x40
	FlagBigEndian = 0x80
)

// Application commands.
const (
	CmdBeacon         = 0x00
	CmdValidation     = 0x01
	CmdEcho           = 0x02
	CmdSearch         = 0x03
	CmdSearchResponse = 0x04
	CmdAuthNZ         = 0x05
	CmdACLChange      = 0x06
	CmdCreateChannel  = 0x07
	CmdDestroyChannel = 0x08
	CmdValidated      = 0x09
	CmdGet            = 0x0A
	CmdPut            = 0x0B
	CmdPutGet         = 0x0C
	CmdMonitor        = 0x0D
	CmdArray          = 0x0E
	CmdDestroyRequest = 0x0F
	CmdProcess        = 0x10
	CmdGetField       = 0x11
	CmdMessage        = 0x12
	CmdMultipleData   = 0x13
	CmdRPC            = 0x14
	CmdCancelRequest  = 0x15
	CmdOriginTag      = 0x16
	lastCommand       = CmdOriginTag
)

// Control commands.
const (
	CtlMarkTotalSent = 0x00
	CtlAckTotalRecv  = 0x01
	CtlSetByteOrder  = 0x02
	CtlEchoRequest   = 0x03
	CtlEchoResponse  = 0x04
)

// Search request flags.
const (
	SearchReplyRequired = 0x01
	SearchUnicast       = 0x80
)

// Size encoding markers (Protocol-Encoding.md, Sizes).
const (
	sizeNull  = 255
	sizeLong  = 254
	statusOK  = 0xFF
	nullField = 0xFF
)

var commandNames = map[uint8]string{
	CmdBeacon: "beacon", CmdValidation: "connection_validation", CmdEcho: "echo", CmdSearch: "search", CmdSearchResponse: "search_response",
	CmdAuthNZ: "authnz", CmdACLChange: "acl_change", CmdCreateChannel: "create_channel", CmdDestroyChannel: "destroy_channel",
	CmdValidated: "connection_validated", CmdGet: "get", CmdPut: "put", CmdPutGet: "put_get", CmdMonitor: "monitor", CmdArray: "array",
	CmdDestroyRequest: "destroy_request", CmdProcess: "process", CmdGetField: "get_field", CmdMessage: "message", CmdMultipleData: "multiple_data",
	CmdRPC: "rpc", CmdCancelRequest: "cancel_request", CmdOriginTag: "origin_tag",
}

var controlNames = map[uint8]string{
	CtlMarkTotalSent: "mark_total_sent", CtlAckTotalRecv: "ack_total_received", CtlSetByteOrder: "set_byte_order",
	CtlEchoRequest: "echo_request", CtlEchoResponse: "echo_response",
}

// Errors.
var (
	ErrTruncated = errors.New("pva: truncated message")
	ErrMagic     = errors.New("pva: bad magic")
	ErrVersion   = errors.New("pva: unsupported version")
	ErrCommand   = errors.New("pva: unknown command")
	ErrFlags     = errors.New("pva: reserved flag bits set")
	ErrPayload   = errors.New("pva: payload runs past the end")
)

// Header is a decoded message header.
type Header struct {
	Version     uint8
	Flags       uint8
	Command     uint8
	PayloadSize uint32
	BigEndian   bool
	Control     bool
	FromServer  bool
}

// ParseHeader decodes and validates one header.
func ParseHeader(b []byte) (Header, error) {
	if len(b) < HeaderLen {
		return Header{}, ErrTruncated
	}
	if b[0] != Magic {
		return Header{}, ErrMagic
	}
	h := Header{Version: b[1], Flags: b[2], Command: b[3]}
	if h.Version == 0 || h.Version > maxVersion {
		return h, ErrVersion
	}
	if h.Flags&0x0e != 0 {
		return h, ErrFlags
	}
	h.BigEndian = h.Flags&FlagBigEndian != 0
	h.Control = h.Flags&FlagControl != 0
	h.FromServer = h.Flags&FlagServer != 0
	h.PayloadSize = h.order().Uint32(b[4:8])
	if !h.Control && h.Command > lastCommand {
		return h, ErrCommand
	}
	return h, nil
}

func (h Header) order() binary.ByteOrder {
	if h.BigEndian {
		return binary.BigEndian
	}
	return binary.LittleEndian
}

// Message is one header with its payload.
type Message struct {
	Header
	Payload []byte
}

// CommandName returns the specification name of the command.
func (m Message) CommandName() string {
	if m.Control {
		if n, ok := controlNames[m.Command]; ok {
			return n
		}
		return fmt.Sprintf("control_%d", m.Command)
	}
	if n, ok := commandNames[m.Command]; ok {
		return n
	}
	return fmt.Sprintf("cmd_%d", m.Command)
}

// Parse decodes consecutive messages. Control messages carry no
// payload. Parsing stops at the first error and returns what was
// decoded before it.
func Parse(b []byte) ([]Message, error) {
	var out []Message
	off := 0
	for off < len(b) {
		h, err := ParseHeader(b[off:])
		if err != nil {
			return out, err
		}
		off += HeaderLen
		if h.Control {
			out = append(out, Message{Header: h})
			continue
		}
		end := off + int(h.PayloadSize)
		if end > len(b) || end < off {
			return out, ErrPayload
		}
		out = append(out, Message{Header: h, Payload: b[off:end]})
		off = end
	}
	if len(out) == 0 {
		return nil, ErrTruncated
	}
	return out, nil
}

// Probable reports whether the bytes start with a valid PVA header.
func Probable(b []byte) bool {
	_, err := ParseHeader(b)
	return err == nil
}

// Channel is one name in a search or create request.
type Channel struct {
	ID   int32
	Name string
}

// Directions relative to the server.
const (
	ToServer   = "request"
	FromServer = "response"
)

// Observation is the typed observation for one PVA message.
type Observation struct {
	observation.Evidence
	Message
	Transport string
	Src       netip.Addr
	Dst       netip.Addr
	SrcPort   uint16
	DstPort   uint16
	Direction string
	// Interpreted fields; zero when not applicable.
	SequenceID    int32
	ReplyRequired bool
	Unicast       bool
	ResponseAddr  netip.Addr
	ResponsePort  uint16
	Protocols     []string
	Channels      []Channel
	GUID          string
	ServerAddr    netip.Addr // resolved: packet source when the message carries an all-zero address
	ServerPort    uint16
	Protocol      string
	Found         bool
	InstanceIDs   []int32
	BeaconSeq     uint8
	ChangeCount   uint16
	StatusPresent bool
	BufferSize    int32
	RegistryMax   int16
	QoS           int16
	AuthNZ        []string
	ClientChanID  int32
	ServerChanID  int32
	StatusOK      bool
	Malformed     bool
}

// Kind returns "pva.<message>".
func (o Observation) Kind() observation.Kind {
	if o.Control {
		return observation.Kind("pva.control." + o.CommandName())
	}
	switch o.Command {
	case CmdCreateChannel:
		if o.Direction == FromServer {
			return "pva.create_channel_response"
		}
		return "pva.create_channel"
	case CmdValidation:
		if o.Direction == FromServer {
			return "pva.validation_request"
		}
		return "pva.validation_response"
	}
	return observation.Kind("pva." + o.CommandName())
}

// Interpret decodes the payload of the discovery messages.
func Interpret(m Message, transport string, src, dst netip.Addr, srcPort, dstPort uint16) Observation {
	o := Observation{Message: m, Transport: transport, Src: src, Dst: dst, SrcPort: srcPort, DstPort: dstPort, Direction: ToServer}
	if m.FromServer {
		o.Direction = FromServer
	}
	if m.Control {
		return o
	}
	r := &reader{b: m.Payload, order: m.order()}
	switch m.Command {
	case CmdSearch:
		o.Direction = ToServer
		o.SequenceID = r.int32()
		flags := r.byte()
		o.ReplyRequired = flags&SearchReplyRequired != 0
		o.Unicast = flags&SearchUnicast != 0
		r.skip(3)
		o.ResponseAddr = r.addr()
		o.ResponsePort = r.uint16()
		n := r.size()
		for i := 0; i < n && !r.failed; i++ {
			o.Protocols = append(o.Protocols, r.str())
		}
		count := int(r.uint16())
		for i := 0; i < count && !r.failed; i++ {
			id := r.int32()
			name := r.str()
			if len(name) > maxChannelName {
				r.failed = true
				break
			}
			o.Channels = append(o.Channels, Channel{ID: id, Name: name})
		}
	case CmdSearchResponse:
		o.Direction = FromServer
		o.GUID = hex.EncodeToString(r.bytes(guidLen))
		o.SequenceID = r.int32()
		o.ServerAddr = resolve(r.addr(), src)
		o.ServerPort = r.uint16()
		o.Protocol = r.str()
		o.Found = r.byte() != 0
		count := int(r.uint16())
		for i := 0; i < count && !r.failed; i++ {
			o.InstanceIDs = append(o.InstanceIDs, r.int32())
		}
	case CmdBeacon:
		o.Direction = FromServer
		o.GUID = hex.EncodeToString(r.bytes(guidLen))
		r.byte()
		o.BeaconSeq = r.byte()
		o.ChangeCount = r.uint16()
		o.ServerAddr = resolve(r.addr(), src)
		o.ServerPort = r.uint16()
		o.Protocol = r.str()
		o.StatusPresent = r.byte() != nullField
	case CmdValidation:
		o.BufferSize = r.int32()
		o.RegistryMax = r.int16()
		if m.FromServer {
			n := r.size()
			for i := 0; i < n && !r.failed; i++ {
				o.AuthNZ = append(o.AuthNZ, r.str())
			}
		} else {
			o.QoS = r.int16()
			o.AuthNZ = []string{r.str()}
		}
	case CmdCreateChannel:
		if m.FromServer {
			o.ClientChanID = r.int32()
			o.ServerChanID = r.int32()
			o.StatusOK = r.status()
		} else {
			count := int(r.int16())
			for i := 0; i < count && !r.failed; i++ {
				id := r.int32()
				o.Channels = append(o.Channels, Channel{ID: id, Name: r.str()})
			}
		}
	case CmdValidated:
		o.Direction = ToServer
		o.StatusOK = r.status()
	}
	o.Malformed = r.failed
	return o
}

func resolve(a, src netip.Addr) netip.Addr {
	if !a.IsValid() || a.IsUnspecified() {
		return src
	}
	return a
}

// reader decodes payload fields with bounds checks; the first overrun
// sets failed and every later read returns zero.
type reader struct {
	b      []byte
	off    int
	order  binary.ByteOrder
	failed bool
}

func (r *reader) need(n int) bool {
	if r.failed || n < 0 || r.off+n > len(r.b) {
		r.failed = true
		return false
	}
	return true
}

func (r *reader) byte() uint8 {
	if !r.need(1) {
		return 0
	}
	v := r.b[r.off]
	r.off++
	return v
}

func (r *reader) skip(n int) {
	if r.need(n) {
		r.off += n
	}
}

func (r *reader) bytes(n int) []byte {
	if !r.need(n) {
		return nil
	}
	v := r.b[r.off : r.off+n]
	r.off += n
	return v
}

func (r *reader) uint16() uint16 {
	if !r.need(2) {
		return 0
	}
	v := r.order.Uint16(r.b[r.off:])
	r.off += 2
	return v
}

func (r *reader) int16() int16 { return int16(r.uint16()) }

func (r *reader) int32() int32 {
	if !r.need(4) {
		return 0
	}
	v := r.order.Uint32(r.b[r.off:])
	r.off += 4
	return int32(v)
}

// size decodes the Protocol-Encoding "Sizes" rule; null counts as 0.
func (r *reader) size() int {
	v := r.byte()
	switch {
	case r.failed:
		return 0
	case v == sizeNull:
		return 0
	case v < sizeLong:
		return int(v)
	}
	n := r.int32()
	if n < 0 {
		r.failed = true
		return 0
	}
	return int(n)
}

func (r *reader) str() string {
	n := r.size()
	if r.failed {
		return ""
	}
	return string(r.bytes(n))
}

func (r *reader) addr() netip.Addr {
	b := r.bytes(addrLen)
	if b == nil {
		return netip.Addr{}
	}
	return netip.AddrFrom16([16]byte(b)).Unmap()
}

// status decodes a Status: the single byte 0xFF means OK with no text.
func (r *reader) status() bool {
	t := r.byte()
	if r.failed {
		return false
	}
	if t == statusOK {
		return true
	}
	r.str()
	r.str()
	return t == 0
}

// writer builds payloads for the datagram constructors.
type writer struct {
	b []byte
}

func (w *writer) byte(v uint8)    { w.b = append(w.b, v) }
func (w *writer) uint16(v uint16) { w.b = binary.BigEndian.AppendUint16(w.b, v) }
func (w *writer) int32(v int32)   { w.b = binary.BigEndian.AppendUint32(w.b, uint32(v)) }
func (w *writer) size(n int) {
	if n < sizeLong {
		w.byte(uint8(n))
		return
	}
	w.byte(sizeLong)
	w.int32(int32(n))
}
func (w *writer) str(s string) { w.size(len(s)); w.b = append(w.b, s...) }
func (w *writer) addr(a netip.Addr) {
	if !a.IsValid() {
		w.b = append(w.b, make([]byte, addrLen)...)
		return
	}
	v := netip.AddrFrom16(a.As16())
	if a.Is4() {
		v = netip.AddrFrom16(mapped(a))
	}
	x := v.As16()
	w.b = append(w.b, x[:]...)
}

func mapped(a netip.Addr) [16]byte {
	v := a.As4()
	return [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, v[0], v[1], v[2], v[3]}
}

func frame(cmd uint8, fromServer bool, payload []byte) []byte {
	flags := uint8(FlagBigEndian)
	if fromServer {
		flags |= FlagServer
	}
	h := []byte{Magic, maxVersion, flags, cmd, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(h[4:], uint32(len(payload)))
	return append(h, payload...)
}

// SearchDatagram builds a big-endian search request for one channel.
func SearchDatagram(seq int32, id int32, name string, replyRequired, unicast bool) []byte {
	var w writer
	w.int32(seq)
	flags := uint8(0)
	if replyRequired {
		flags |= SearchReplyRequired
	}
	if unicast {
		flags |= SearchUnicast
	}
	w.byte(flags)
	w.b = append(w.b, 0, 0, 0)
	w.addr(netip.Addr{})
	w.uint16(0)
	w.size(1)
	w.str("tcp")
	w.uint16(1)
	w.int32(id)
	w.str(name)
	return frame(CmdSearch, false, w.b)
}

// SearchResponseDatagram builds a big-endian search response.
func SearchResponseDatagram(guid [12]byte, seq int32, server netip.Addr, port uint16, found bool, ids []int32) []byte {
	var w writer
	w.b = append(w.b, guid[:]...)
	w.int32(seq)
	w.addr(server)
	w.uint16(port)
	w.str("tcp")
	if found {
		w.byte(1)
	} else {
		w.byte(0)
	}
	w.uint16(uint16(len(ids)))
	for _, id := range ids {
		w.int32(id)
	}
	return frame(CmdSearchResponse, true, w.b)
}

// BeaconDatagram builds a big-endian beacon without server status.
func BeaconDatagram(guid [12]byte, seq uint8, change uint16, server netip.Addr, port uint16) []byte {
	var w writer
	w.b = append(w.b, guid[:]...)
	w.byte(0)
	w.byte(seq)
	w.uint16(change)
	w.addr(server)
	w.uint16(port)
	w.str("tcp")
	w.byte(nullField)
	return frame(CmdBeacon, true, w.b)
}

// ValidationRequest builds the server's connection validation request.
func ValidationRequest(bufSize int32, registry int16, auth []string) []byte {
	var w writer
	w.int32(bufSize)
	w.uint16(uint16(registry))
	w.size(len(auth))
	for _, a := range auth {
		w.str(a)
	}
	return frame(CmdValidation, true, w.b)
}

// SetByteOrder builds the control message a server sends first on TCP.
func SetByteOrder(bigEndian bool) []byte {
	flags := uint8(FlagControl | FlagServer)
	if bigEndian {
		flags |= FlagBigEndian
	}
	return []byte{Magic, maxVersion, flags, CtlSetByteOrder, 0, 0, 0, 0}
}

// CreateChannelRequest builds a create channel request for one channel.
func CreateChannelRequest(clientID int32, name string) []byte {
	var w writer
	w.uint16(1)
	w.int32(clientID)
	w.str(name)
	return frame(CmdCreateChannel, false, w.b)
}
