// Package tcp parses the TCP header for ports, flags, and payload
// dispatch. There is no stream reassembly: application parsers see one
// segment at a time and only claim what fits (protocol-scope Tier 1).
package tcp

import (
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Header constants.
const (
	MinHeaderLen = 20
	FlagFIN      = 0x01
	FlagSYN      = 0x02
	FlagRST      = 0x04
	FlagPSH      = 0x08
	FlagACK      = 0x10
)

// Kind is the observation kind.
const Kind observation.Kind = "tcp"

// Errors.
var (
	ErrTruncated = errors.New("tcp: truncated header")
	ErrOffset    = errors.New("tcp: data offset below 20")
)

// Segment is a parsed TCP segment.
type Segment struct {
	SrcPort   uint16
	DstPort   uint16
	Seq       uint32
	Ack       uint32
	Flags     uint8
	Window    uint16
	HeaderLen int
	Payload   []byte
}

// Parse decodes the header; options are skipped.
func Parse(b []byte) (Segment, error) {
	if len(b) < MinHeaderLen {
		return Segment{}, ErrTruncated
	}
	hl := int(b[12]>>4) * 4
	if hl < MinHeaderLen {
		return Segment{}, ErrOffset
	}
	if len(b) < hl {
		return Segment{}, ErrTruncated
	}
	return Segment{
		SrcPort:   binary.BigEndian.Uint16(b[0:2]),
		DstPort:   binary.BigEndian.Uint16(b[2:4]),
		Seq:       binary.BigEndian.Uint32(b[4:8]),
		Ack:       binary.BigEndian.Uint32(b[8:12]),
		Flags:     b[13],
		Window:    binary.BigEndian.Uint16(b[14:16]),
		HeaderLen: hl,
		Payload:   b[hl:],
	}, nil
}

// FlagNames renders the set flags.
func FlagNames(f uint8) string {
	s := ""
	for _, x := range []struct {
		bit  uint8
		name string
	}{{FlagSYN, "SYN"}, {FlagACK, "ACK"}, {FlagFIN, "FIN"}, {FlagRST, "RST"}, {FlagPSH, "PSH"}} {
		if f&x.bit != 0 {
			if s != "" {
				s += ","
			}
			s += x.name
		}
	}
	if s == "" {
		return "-"
	}
	return s
}

// Observation is emitted for connection state events (SYN, FIN, RST).
type Observation struct {
	observation.Evidence
	Src        netip.Addr
	Dst        netip.Addr
	SrcPort    uint16
	DstPort    uint16
	Flags      uint8
	Seq        uint32
	PayloadLen int
}

// Kind returns "tcp".
func (Observation) Kind() observation.Kind { return Kind }

// IsStateEvent reports whether the flags mark a connection event.
func IsStateEvent(flags uint8) bool {
	return flags&(FlagSYN|FlagFIN|FlagRST) != 0
}
