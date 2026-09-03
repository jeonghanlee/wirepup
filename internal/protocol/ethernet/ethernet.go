// Package ethernet parses Ethernet II frames and their optional 802.1Q
// tag. The parser is pure: bytes in, a Frame or an error out.
package ethernet

import (
	"encoding/binary"
	"errors"
	"net"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Header and tag sizes.
const (
	HeaderLen = 14
	TagLen    = 4
	addrLen   = 6
)

// EtherType values WirePup dispatches on.
const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeVLAN uint16 = 0x8100
	EtherTypeQinQ uint16 = 0x88a8
	EtherTypeIPv6 uint16 = 0x86dd
	EtherTypeLLDP uint16 = 0x88cc
)

// KindFrame is the observation kind for a decoded frame.
const KindFrame observation.Kind = "frame"

// ErrTruncated reports a frame shorter than its headers.
var ErrTruncated = errors.New("ethernet: truncated frame")

// VLANTag is one 802.1Q tag as it appeared in the frame.
type VLANTag struct {
	TPID     uint16
	ID       uint16
	Priority uint8
	DEI      bool
}

// Frame is a parsed Ethernet II frame. VLAN is nil when the frame carried
// no tag; that means the tag was absent from the delivered bytes, not
// that no VLAN exists (R-009).
type Frame struct {
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	EtherType   uint16
	VLAN        *VLANTag
	Payload     []byte
}

// Parse decodes the header and at most one 802.1Q or 802.1ad tag. A
// second stacked tag is left in the payload with EtherType reporting the
// inner tag protocol.
func Parse(b []byte) (Frame, error) {
	if len(b) < HeaderLen {
		return Frame{}, ErrTruncated
	}
	f := Frame{
		Destination: net.HardwareAddr(b[0:addrLen]),
		Source:      net.HardwareAddr(b[addrLen : 2*addrLen]),
		EtherType:   binary.BigEndian.Uint16(b[12:14]),
	}
	off := HeaderLen
	if f.EtherType == EtherTypeVLAN || f.EtherType == EtherTypeQinQ {
		if len(b) < HeaderLen+TagLen {
			return Frame{}, ErrTruncated
		}
		tci := binary.BigEndian.Uint16(b[14:16])
		f.VLAN = &VLANTag{
			TPID:     f.EtherType,
			ID:       tci & 0x0fff,
			Priority: uint8(tci >> 13),
			DEI:      tci&0x1000 != 0,
		}
		f.EtherType = binary.BigEndian.Uint16(b[16:18])
		off += TagLen
	}
	f.Payload = b[off:]
	return f, nil
}

// Observation is the frame-level observation emitted for every decodable
// Ethernet frame. It is the evidence that a MAC address exists on the
// segment (R-003) and carries the VLAN tag when one was visible.
type Observation struct {
	observation.Evidence
	Destination net.HardwareAddr
	Source      net.HardwareAddr
	EtherType   uint16
	VLAN        *VLANTag
	Length      int
}

// Kind returns "frame".
func (Observation) Kind() observation.Kind { return KindFrame }

// IsUnicast reports whether the address has the group bit clear.
func IsUnicast(a net.HardwareAddr) bool {
	return len(a) == addrLen && a[0]&0x01 == 0
}

// IsZero reports the all-zero address, which never identifies a device.
func IsZero(a net.HardwareAddr) bool {
	for _, b := range a {
		if b != 0 {
			return false
		}
	}
	return true
}
