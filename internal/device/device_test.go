package device

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/decode"
)

const (
	probeHex    = "ffffffffffff0080f41234560806" + "0001080006040001" + "0080f4123456" + "00000000" + "000000000000" + "a9fe161f"
	announceHex = "ffffffffffff0080f41234560806" + "0001080006040001" + "0080f4123456" + "a9fe161f" + "000000000000" + "a9fe161f"
	requestHex  = "ffffffffffff0011223344550806" + "0001080006040001" + "001122334455" + "0a141e33" + "000000000000" + "0a141e01"
)

func decodeAll(t *testing.T, frames ...string) [][]capture.Packet {
	t.Helper()
	var out [][]capture.Packet
	for _, f := range frames {
		b, err := hex.DecodeString(f)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, []capture.Packet{{Timestamp: time.Unix(1700000000, 0), Interface: "enp3s0", LinkType: capture.LinkTypeEthernet, Data: b, CaptureLength: len(b), OriginalLength: len(b)}})
	}
	return out
}

func apply(t *testing.T, tbl *Table, frames ...string) []Event {
	t.Helper()
	dec := decode.New("enp3s0")
	var events []Event
	for _, pkts := range decodeAll(t, frames...) {
		for _, p := range pkts {
			events = append(events, tbl.Apply(dec.Decode(p))...)
		}
	}
	return events
}

func TestAutoIPSequence(t *testing.T) {
	tbl := New(Options{Vendor: func(mac string) string { return "Test Vendor" }})
	events := apply(t, tbl, probeHex, announceHex)
	if len(events) != 3 {
		t.Fatalf("got %d events: %+v", len(events), events)
	}
	if events[0].Change != ChangeNewDevice || events[0].Via != ViaEthernet || events[0].Device.ID != "00:80:f4:12:34:56" {
		t.Fatalf("event 0: %+v", events[0])
	}
	if events[1].Change != ChangeUpdate || events[1].Via != ViaARPProbe || events[1].Address.String() != "169.254.22.31" || events[1].Method != MethodLinkLocal {
		t.Fatalf("event 1: %+v", events[1])
	}
	if events[2].Via != ViaARPAnnouncement || events[2].Device.IPv4[0].State != StateClaimed {
		t.Fatalf("event 2: %+v", events[2])
	}
	devs := tbl.Devices()
	if len(devs) != 1 || devs[0].Vendor != "Test Vendor" || len(devs[0].Timeline) != 3 || devs[0].Protocols[0] != ProtoARP {
		t.Fatalf("devices %+v", devs)
	}
	// A second announcement changes nothing.
	if more := apply(t, tbl, announceHex); len(more) != 0 {
		t.Fatalf("repeat produced %+v", more)
	}
}

func TestTwoDevicesAndLocalFlag(t *testing.T) {
	tbl := New(Options{LocalMACs: []string{"00:11:22:33:44:55"}})
	events := apply(t, tbl, requestHex, probeHex)
	if tbl.Len() != 2 || len(events) != 4 {
		t.Fatalf("len %d events %d", tbl.Len(), len(events))
	}
	devs := tbl.Devices()
	if !devs[0].Local || devs[1].Local {
		t.Fatalf("local flags %+v", devs)
	}
	if devs[0].IPv4[0].Addr.String() != "10.20.30.51" || devs[0].IPv4[0].State != StateObserved {
		t.Fatalf("request address %+v", devs[0].IPv4)
	}
	if devs[0].IPv4[0].Ref.PacketID != 1 || devs[1].Timeline[0].Ref.PacketID != 2 {
		t.Fatalf("evidence refs %+v %+v", devs[0].IPv4, devs[1].Timeline)
	}
}

func TestBroadcastSourceIgnored(t *testing.T) {
	tbl := New(Options{})
	events := apply(t, tbl, "ffffffffffff"+"ffffffffffff"+"0806"+"0001080006040001"+"ffffffffffff"+"0a141e33"+"000000000000"+"0a141e01")
	if len(events) != 0 || tbl.Len() != 0 {
		t.Fatalf("broadcast source created a device: %+v", events)
	}
}

func TestSnapshotIsolation(t *testing.T) {
	tbl := New(Options{})
	apply(t, tbl, probeHex)
	snap := tbl.Devices()
	snap[0].IPv4[0].State = "tampered"
	if tbl.Devices()[0].IPv4[0].State == "tampered" {
		t.Fatal("snapshot shares storage with the table")
	}
}
