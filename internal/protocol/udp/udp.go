// Package udp parses the UDP header for ports and payload dispatch.
package udp

import (
	"encoding/binary"
	"errors"
)

// HeaderLen is the fixed UDP header size.
const HeaderLen = 8

// ErrTruncated reports a buffer shorter than the header.
var ErrTruncated = errors.New("udp: truncated header")

// Datagram is a parsed UDP datagram.
type Datagram struct {
	SrcPort   uint16
	DstPort   uint16
	Length    int
	Truncated bool
	Payload   []byte
}

// Parse decodes the header. The payload is cut to the declared length
// when the buffer is longer (Ethernet padding) and to the buffer when it
// is shorter (Truncated set).
func Parse(b []byte) (Datagram, error) {
	if len(b) < HeaderLen {
		return Datagram{}, ErrTruncated
	}
	d := Datagram{
		SrcPort: binary.BigEndian.Uint16(b[0:2]),
		DstPort: binary.BigEndian.Uint16(b[2:4]),
		Length:  int(binary.BigEndian.Uint16(b[4:6])),
	}
	end := d.Length
	if end < HeaderLen {
		end = HeaderLen
	}
	if end > len(b) {
		end = len(b)
		d.Truncated = true
	}
	d.Payload = b[HeaderLen:end]
	return d, nil
}
