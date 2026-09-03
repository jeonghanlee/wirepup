package ethernet

import (
	"encoding/hex"
	"testing"
)

// Fixture: ARP request from 00:11:22:33:44:55 to broadcast, untagged.
const arpFrameHex = "ffffffffffff" + "001122334455" + "0806" + "0001080006040001" + "001122334455" + "0a141e33" + "000000000000" + "0a141e01"

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseUntagged(t *testing.T) {
	f, err := Parse(mustHex(t, arpFrameHex))
	if err != nil {
		t.Fatal(err)
	}
	if f.Source.String() != "00:11:22:33:44:55" || f.Destination.String() != "ff:ff:ff:ff:ff:ff" {
		t.Fatalf("addresses: %s -> %s", f.Source, f.Destination)
	}
	if f.EtherType != EtherTypeARP || f.VLAN != nil || len(f.Payload) != 28 {
		t.Fatalf("ethertype %#x vlan %v payload %d", f.EtherType, f.VLAN, len(f.Payload))
	}
}

func TestParseTagged(t *testing.T) {
	// 802.1Q tag: priority 5, DEI 0, VLAN 100 (0x064) -> TCI 0xa064.
	b := mustHex(t, "ffffffffffff001122334455"+"8100"+"a064"+"0806"+"0001080006040001001122334455"+"0a141e33"+"000000000000"+"0a141e01")
	f, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if f.VLAN == nil || f.VLAN.ID != 100 || f.VLAN.Priority != 5 || f.VLAN.DEI || f.VLAN.TPID != EtherTypeVLAN {
		t.Fatalf("vlan %+v", f.VLAN)
	}
	if f.EtherType != EtherTypeARP || len(f.Payload) != 28 {
		t.Fatalf("ethertype %#x payload %d", f.EtherType, len(f.Payload))
	}
}

func TestParseTruncated(t *testing.T) {
	if _, err := Parse(mustHex(t, "ffffffffffff00112233")); err != ErrTruncated {
		t.Fatalf("short header: %v", err)
	}
	if _, err := Parse(mustHex(t, "ffffffffffff001122334455"+"8100"+"a0")); err != ErrTruncated {
		t.Fatalf("short tag: %v", err)
	}
}

func TestAddressClassification(t *testing.T) {
	f, _ := Parse(mustHex(t, arpFrameHex))
	if !IsUnicast(f.Source) || IsUnicast(f.Destination) {
		t.Fatal("unicast classification")
	}
	if !IsZero(mustHex(t, "000000000000")) || IsZero(f.Source) {
		t.Fatal("zero classification")
	}
}
