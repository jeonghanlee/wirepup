package device

import (
	"encoding/hex"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
)

func arpFrame(mac, senderIP, targetIP string) []byte {
	b, _ := hex.DecodeString("ffffffffffff" + mac + "0806" + "0001080006040001" + mac + senderIP + "000000000000" + targetIP)
	return b
}

func TestMACBeforeIPThenIPLater(t *testing.T) {
	tbl := New(Options{})
	plain := ipv4UDPFrame(clientMAC, serverMAC, [4]byte{0, 0, 0, 0}, [4]byte{255, 255, 255, 255}, 68, 67, []byte{1})
	events := run(t, tbl, plain)
	d := tbl.Devices()[0]
	if len(events) != 1 || d.Confidence != observation.WeakHint || len(d.IPv4) != 0 {
		t.Fatalf("frame only: %+v conf %s", events, d.Confidence)
	}
	run(t, tbl, arpFrame("0080f4123456", "0a141e2a", "0a141e01"))
	d = tbl.Devices()[0]
	if d.Confidence != observation.Confirmed || len(d.IPv4) != 1 || d.IPv4[0].State != StateObserved {
		t.Fatalf("after arp: %+v", d)
	}
}

func TestAutoIPThenDHCPKeepsHistory(t *testing.T) {
	tbl := New(Options{})
	ack := ipv4UDPFrame(serverMAC, clientMAC, [4]byte{10, 20, 30, 1}, [4]byte{10, 20, 30, 42}, 67, 68, dhcpMsg(2, dhcpv4.ACK, 9, [4]byte{10, 20, 30, 42}, []byte{54, 4, 10, 20, 30, 1}))
	run(t, tbl, arpFrame("0080f4123456", "00000000", "a9fe161f"), arpFrame("0080f4123456", "a9fe161f", "a9fe161f"), ack)
	d := tbl.Devices()[0]
	if len(d.IPv4) != 2 || d.IPv4[0].Addr.String() != "169.254.22.31" || d.IPv4[0].State != StateClaimed || d.IPv4[1].Addr.String() != "10.20.30.42" || d.IPv4[1].State != StateLeased {
		t.Fatalf("addresses %+v", d.IPv4)
	}
}

func TestSameHostnameStaysSeparate(t *testing.T) {
	tbl := New(Options{})
	name := []byte{12, 3, 'i', 'o', 'c'}
	a := ipv4UDPFrame(clientMAC, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, [4]byte{}, [4]byte{255, 255, 255, 255}, 68, 67, dhcpMsg(1, dhcpv4.Discover, 1, [4]byte{}, name))
	other := []byte{0x00, 0x80, 0xf4, 0x65, 0x43, 0x21}
	b := ipv4UDPFrame(other, []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, [4]byte{}, [4]byte{255, 255, 255, 255}, 68, 67, dhcpMsg(1, dhcpv4.Discover, 2, [4]byte{}, name))
	copy(b[14+20+8+28:], other) // chaddr of the second client
	run(t, tbl, a, b)
	devs := tbl.Devices()
	if len(devs) != 2 || devs[0].Names[0].Value != "ioc" || devs[1].Names[0].Value != "ioc" {
		t.Fatalf("devices %+v", devs)
	}
}

func TestDuplicateIPv4Claims(t *testing.T) {
	tbl := New(Options{})
	events := run(t, tbl, arpFrame("0080f4123456", "0a141e2a", "0a141e2a"), arpFrame("0080f4654321", "0a141e2a", "0a141e2a"), arpFrame("0080f4654321", "0a141e2a", "0a141e01"))
	cs := tbl.Conflicts()
	if len(cs) != 1 || cs[0].Addr.String() != "10.20.30.42" || len(cs[0].MACs) != 2 {
		t.Fatalf("conflicts %+v", cs)
	}
	var conflictEvents int
	for _, e := range events {
		if e.Change == ChangeConflict {
			conflictEvents++
			if e.Conflict == nil || len(e.Conflict.MACs) != 2 || e.Address.String() != "10.20.30.42" {
				t.Fatalf("conflict event %+v", e)
			}
		}
	}
	if conflictEvents != 1 {
		t.Fatalf("conflict events %d", conflictEvents)
	}
	if tbl.Len() != 2 {
		t.Fatal("conflicting claims must not merge devices")
	}
}

func TestProbeAloneIsNotAConflict(t *testing.T) {
	tbl := New(Options{})
	run(t, tbl, arpFrame("0080f4123456", "0a141e2a", "0a141e2a"), arpFrame("0080f4654321", "00000000", "0a141e2a"))
	if len(tbl.Conflicts()) != 0 {
		t.Fatal("a probe for a claimed address is a clue, not a conflict")
	}
}

func TestLocallyAdministeredFlag(t *testing.T) {
	tbl := New(Options{})
	run(t, tbl, arpFrame("0280f4123456", "0a141e2a", "0a141e01"))
	if !tbl.Devices()[0].LocallyAdministered {
		t.Fatal("U/L bit not flagged")
	}
}
