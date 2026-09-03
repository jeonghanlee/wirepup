// Package lldp parses IEEE 802.1AB LLDP data units: the mandatory and
// basic optional TLVs plus the IEEE 802.1 VLAN and IEEE 802.3 link TLVs
// that matter for identifying the attached switch port (R-004). Unknown
// TLVs are counted, never fatal; a malformed length ends parsing with
// what was decoded so far.
package lldp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"unicode"

	"github.com/jeonghanlee/wirepup/internal/observation"
)

// Kind is the observation kind.
const Kind observation.Kind = "lldp"

// TLV types from IEEE 802.1AB-2016 table 8-1.
const (
	TypeEnd               = 0
	TypeChassisID         = 1
	TypePortID            = 2
	TypeTTL               = 3
	TypePortDescription   = 4
	TypeSystemName        = 5
	TypeSystemDescription = 6
	TypeSystemCaps        = 7
	TypeManagementAddress = 8
	TypeOrgSpecific       = 127
)

// Chassis ID subtypes.
const (
	ChassisComponent = 1
	ChassisIfAlias   = 2
	ChassisPortComp  = 3
	ChassisMAC       = 4
	ChassisNetAddr   = 5
	ChassisIfName    = 6
	ChassisLocal     = 7
)

// Port ID subtypes.
const (
	PortIfAlias   = 1
	PortComponent = 2
	PortMAC       = 3
	PortNetAddr   = 4
	PortIfName    = 5
	PortCircuitID = 6
	PortLocal     = 7
)

// Organizationally unique identifiers and subtypes handled.
const (
	oui8021        = 0x0080c2
	oui8023        = 0x00120f
	ouiMED         = 0x0012bb
	sub8021PVID    = 1
	sub8021VLAN    = 3
	sub8023MaxSize = 4
	sub8023LinkAgg = 3
)

// Management address families (IANA AFI).
const (
	afiIPv4 = 1
	afiIPv6 = 2
)

// Sizes.
const (
	tlvHeaderLen = 2
	ouiLen       = 3
	mgmtMinLen   = 9
)

// Capability bit names, bit 0 first.
var capabilityNames = []string{"other", "repeater", "bridge", "wlan-ap", "router", "telephone", "docsis", "station", "c-vlan", "s-vlan", "tpmr"}

// Errors.
var (
	ErrTruncated = errors.New("lldp: truncated TLV")
	ErrMandatory = errors.New("lldp: missing mandatory TLV")
)

// Frame is a parsed LLDPDU.
type Frame struct {
	ChassisIDSubtype  uint8
	ChassisID         string
	PortIDSubtype     uint8
	PortID            string
	TTL               uint16
	PortDescription   string
	SystemName        string
	SystemDescription string
	Capabilities      []string
	EnabledCaps       []string
	ManagementAddrs   []string
	PortVLANID        uint16
	VLANNames         map[uint16]string
	MaxFrameSize      uint16
	LinkAggregation   string
	MEDPresent        bool
	UnknownTLVs       int
	Malformed         bool
}

// Parse decodes an LLDPDU. The three mandatory TLVs must be present in
// order; anything after a length error is dropped and Malformed is set.
func Parse(b []byte) (Frame, error) {
	f := Frame{VLANNames: map[uint16]string{}}
	seen := 0
	off := 0
	for off+tlvHeaderLen <= len(b) {
		hdr := binary.BigEndian.Uint16(b[off:])
		typ := uint8(hdr >> 9)
		length := int(hdr & 0x1ff)
		off += tlvHeaderLen
		if off+length > len(b) {
			f.Malformed = true
			break
		}
		v := b[off : off+length]
		off += length
		if typ == TypeEnd {
			break
		}
		switch typ {
		case TypeChassisID:
			if len(v) < 2 {
				f.Malformed = true
				continue
			}
			f.ChassisIDSubtype = v[0]
			f.ChassisID = identifier(v[0], v[1:], ChassisMAC, ChassisNetAddr)
			seen |= 1
		case TypePortID:
			if len(v) < 2 {
				f.Malformed = true
				continue
			}
			f.PortIDSubtype = v[0]
			f.PortID = identifier(v[0], v[1:], PortMAC, PortNetAddr)
			seen |= 2
		case TypeTTL:
			if len(v) < 2 {
				f.Malformed = true
				continue
			}
			f.TTL = binary.BigEndian.Uint16(v)
			seen |= 4
		case TypePortDescription:
			f.PortDescription = printable(v)
		case TypeSystemName:
			f.SystemName = printable(v)
		case TypeSystemDescription:
			f.SystemDescription = printable(v)
		case TypeSystemCaps:
			if len(v) < 4 {
				f.Malformed = true
				continue
			}
			f.Capabilities = capabilities(binary.BigEndian.Uint16(v[0:2]))
			f.EnabledCaps = capabilities(binary.BigEndian.Uint16(v[2:4]))
		case TypeManagementAddress:
			if a, ok := managementAddress(v); ok {
				f.ManagementAddrs = append(f.ManagementAddrs, a)
			} else {
				f.Malformed = true
			}
		case TypeOrgSpecific:
			f.orgSpecific(v)
		default:
			f.UnknownTLVs++
		}
	}
	if seen != 7 {
		return f, ErrMandatory
	}
	return f, nil
}

func (f *Frame) orgSpecific(v []byte) {
	if len(v) < ouiLen+1 {
		f.Malformed = true
		return
	}
	oui := uint32(v[0])<<16 | uint32(v[1])<<8 | uint32(v[2])
	sub := v[3]
	data := v[4:]
	switch {
	case oui == oui8021 && sub == sub8021PVID && len(data) >= 2:
		f.PortVLANID = binary.BigEndian.Uint16(data)
	case oui == oui8021 && sub == sub8021VLAN && len(data) >= 3:
		vid := binary.BigEndian.Uint16(data)
		n := int(data[2])
		if 3+n > len(data) {
			f.Malformed = true
			return
		}
		f.VLANNames[vid] = printable(data[3 : 3+n])
	case oui == oui8023 && sub == sub8023MaxSize && len(data) >= 2:
		f.MaxFrameSize = binary.BigEndian.Uint16(data)
	case oui == oui8023 && sub == sub8023LinkAgg && len(data) >= 5:
		status := "not-capable"
		if data[0]&0x01 != 0 {
			status = "capable"
			if data[0]&0x02 != 0 {
				status = fmt.Sprintf("aggregated id %d", binary.BigEndian.Uint32(data[1:5]))
			}
		}
		f.LinkAggregation = status
	case oui == ouiMED:
		f.MEDPresent = true
	default:
		f.UnknownTLVs++
	}
}

// identifier renders a chassis or port identifier by subtype.
func identifier(subtype uint8, v []byte, macSub, netSub uint8) string {
	switch subtype {
	case macSub:
		if len(v) == 6 {
			return net.HardwareAddr(v).String()
		}
	case netSub:
		if a, ok := networkAddress(v); ok {
			return a
		}
	}
	return printable(v)
}

func networkAddress(v []byte) (string, bool) {
	if len(v) < 1 {
		return "", false
	}
	switch v[0] {
	case afiIPv4:
		if len(v) == 5 {
			return netip.AddrFrom4([4]byte(v[1:5])).String(), true
		}
	case afiIPv6:
		if len(v) == 17 {
			return netip.AddrFrom16([16]byte(v[1:17])).String(), true
		}
	}
	return "", false
}

func managementAddress(v []byte) (string, bool) {
	if len(v) < mgmtMinLen {
		return "", false
	}
	n := int(v[0])
	if n < 1 || 1+n > len(v) {
		return "", false
	}
	return networkAddress(v[1 : 1+n])
}

func capabilities(bits uint16) []string {
	var out []string
	for i, name := range capabilityNames {
		if bits&(1<<uint(i)) != 0 {
			out = append(out, name)
		}
	}
	return out
}

// printable returns the bytes as text when they are all printable,
// otherwise as hex.
func printable(v []byte) string {
	for _, c := range string(v) {
		if !unicode.IsPrint(c) {
			return fmt.Sprintf("%x", v)
		}
	}
	return string(v)
}

// Observation is the typed observation for one LLDPDU.
type Observation struct {
	observation.Evidence
	SourceMAC net.HardwareAddr
	Frame
}

// Kind returns "lldp".
func (Observation) Kind() observation.Kind { return Kind }

// VLANSummary lists the VLAN names sorted by ID for rendering.
func (f Frame) VLANSummary() []string {
	ids := make([]int, 0, len(f.VLANNames))
	for id := range f.VLANNames {
		ids = append(ids, int(id))
	}
	sort.Ints(ids)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, fmt.Sprintf("%d:%s", id, f.VLANNames[uint16(id)]))
	}
	return out
}
