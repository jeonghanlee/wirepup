package lldp

import (
	"encoding/binary"
	"testing"
)

func tlv(typ uint8, payload []byte) []byte {
	hdr := make([]byte, 2)
	binary.BigEndian.PutUint16(hdr, uint16(typ)<<9|uint16(len(payload)))
	return append(hdr, payload...)
}

func org(oui uint32, sub uint8, data []byte) []byte {
	p := []byte{byte(oui >> 16), byte(oui >> 8), byte(oui), sub}
	return tlv(TypeOrgSpecific, append(p, data...))
}

func switchPDU() []byte {
	var b []byte
	b = append(b, tlv(TypeChassisID, append([]byte{ChassisMAC}, 0x00, 0x1c, 0x73, 0x00, 0x00, 0x01))...)
	b = append(b, tlv(TypePortID, append([]byte{PortIfName}, []byte("Gi1/0/12")...))...)
	b = append(b, tlv(TypeTTL, []byte{0x00, 0x78})...)
	b = append(b, tlv(TypePortDescription, []byte("lab rack A port 12"))...)
	b = append(b, tlv(TypeSystemName, []byte("sw-lab-1"))...)
	b = append(b, tlv(TypeSystemDescription, []byte("Managed Switch 1.2.3"))...)
	b = append(b, tlv(TypeSystemCaps, []byte{0x00, 0x14, 0x00, 0x04})...) // bridge+router supported, bridge enabled
	mgmt := []byte{5, afiIPv4, 10, 20, 30, 1, 2, 0, 0, 0, 12, 0}
	b = append(b, tlv(TypeManagementAddress, mgmt)...)
	b = append(b, org(oui8021, sub8021PVID, []byte{0x00, 0x64})...)
	b = append(b, org(oui8021, sub8021VLAN, append([]byte{0x00, 0x64, 3}, []byte("lab")...))...)
	b = append(b, org(oui8023, sub8023MaxSize, []byte{0x05, 0xf2})...)
	b = append(b, org(0x001122, 9, []byte{1, 2, 3})...) // unknown vendor TLV
	b = append(b, tlv(TypeEnd, nil)...)
	return b
}

func TestParseSwitchPDU(t *testing.T) {
	f, err := Parse(switchPDU())
	if err != nil {
		t.Fatal(err)
	}
	if f.ChassisID != "00:1c:73:00:00:01" || f.ChassisIDSubtype != ChassisMAC {
		t.Fatalf("chassis %q subtype %d", f.ChassisID, f.ChassisIDSubtype)
	}
	if f.PortID != "Gi1/0/12" || f.TTL != 120 || f.SystemName != "sw-lab-1" || f.PortDescription != "lab rack A port 12" {
		t.Fatalf("frame %+v", f)
	}
	if len(f.Capabilities) != 2 || f.Capabilities[0] != "bridge" || f.Capabilities[1] != "router" || len(f.EnabledCaps) != 1 {
		t.Fatalf("caps %v enabled %v", f.Capabilities, f.EnabledCaps)
	}
	if len(f.ManagementAddrs) != 1 || f.ManagementAddrs[0] != "10.20.30.1" {
		t.Fatalf("mgmt %v", f.ManagementAddrs)
	}
	if f.PortVLANID != 100 || f.VLANNames[100] != "lab" || f.MaxFrameSize != 1522 {
		t.Fatalf("vlan %d names %v max %d", f.PortVLANID, f.VLANNames, f.MaxFrameSize)
	}
	if f.UnknownTLVs != 1 || f.Malformed {
		t.Fatalf("unknown %d malformed %v", f.UnknownTLVs, f.Malformed)
	}
	if s := f.VLANSummary(); len(s) != 1 || s[0] != "100:lab" {
		t.Fatalf("summary %v", s)
	}
}

func TestMissingMandatory(t *testing.T) {
	b := append(tlv(TypeChassisID, []byte{ChassisLocal, 'x'}), tlv(TypeEnd, nil)...)
	if _, err := Parse(b); err != ErrMandatory {
		t.Fatalf("err %v", err)
	}
}

func TestOversizedLengthStopsParsing(t *testing.T) {
	b := switchPDU()
	// Append a TLV whose declared length runs past the buffer.
	b = append(b[:len(b)-2], 0x08, 0xff, 0x01)
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if !f.Malformed || f.SystemName != "sw-lab-1" {
		t.Fatalf("malformed %v name %q", f.Malformed, f.SystemName)
	}
}

func TestNonPrintableIdentifierIsHex(t *testing.T) {
	b := tlv(TypeChassisID, []byte{ChassisLocal, 0x01, 0x02})
	b = append(b, tlv(TypePortID, []byte{PortLocal, 'p'})...)
	b = append(b, tlv(TypeTTL, []byte{0, 1})...)
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.ChassisID != "0102" {
		t.Fatalf("chassis %q", f.ChassisID)
	}
}

func TestNetworkAddressChassis(t *testing.T) {
	b := tlv(TypeChassisID, []byte{ChassisNetAddr, afiIPv4, 192, 168, 1, 1})
	b = append(b, tlv(TypePortID, []byte{PortMAC, 1, 2, 3, 4, 5, 6})...)
	b = append(b, tlv(TypeTTL, []byte{0, 1})...)
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.ChassisID != "192.168.1.1" || f.PortID != "01:02:03:04:05:06" {
		t.Fatalf("ids %q %q", f.ChassisID, f.PortID)
	}
}

func TestFuzzLikeTruncations(t *testing.T) {
	full := switchPDU()
	for n := 0; n < len(full); n++ {
		Parse(full[:n]) // must not panic
	}
}
