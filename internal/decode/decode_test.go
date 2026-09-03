package decode

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

func packet(t *testing.T, hexData string, link capture.LinkType) capture.Packet {
	t.Helper()
	b, err := hex.DecodeString(hexData)
	if err != nil {
		t.Fatal(err)
	}
	return capture.Packet{
		Timestamp:      time.Unix(1700000000, 0),
		Interface:      "enp3s0",
		LinkType:       link,
		Data:           b,
		CaptureLength:  len(b),
		OriginalLength: len(b),
	}
}

const arpProbe = "ffffffffffff" + "0080f4123456" + "0806" + "0001080006040001" + "0080f4123456" + "00000000" + "000000000000" + "a9fe161f"

func TestPipelineEmitsFrameAndARP(t *testing.T) {
	d := New("enp3s0")
	obs := d.Decode(packet(t, arpProbe, capture.LinkTypeEthernet))
	if len(obs) != 2 {
		t.Fatalf("got %d observations", len(obs))
	}
	f, ok := obs[0].(ethernet.Observation)
	if !ok || f.Kind() != ethernet.KindFrame || f.Source.String() != "00:80:f4:12:34:56" {
		t.Fatalf("frame observation %+v", obs[0])
	}
	a, ok := obs[1].(arp.Observation)
	if !ok || a.Role != arp.RoleProbe || a.TargetIP.String() != "169.254.22.31" {
		t.Fatalf("arp observation %+v", obs[1])
	}
	for i, o := range obs {
		ev := o.Ref()
		if ev.PacketID != 1 || ev.Source != "enp3s0" || ev.Interface != "enp3s0" || !ev.Timestamp.Equal(time.Unix(1700000000, 0)) {
			t.Fatalf("evidence %d: %+v", i, ev)
		}
	}
	if obs[0].Ref().Protocol != ProtoEthernet || obs[1].Ref().Protocol != ProtoARP {
		t.Fatal("protocol names")
	}
}

func TestPacketIDCountsEveryPacket(t *testing.T) {
	d := New("file.pcap")
	d.Decode(packet(t, "ff", capture.LinkTypeEthernet)) // malformed
	d.Decode(packet(t, arpProbe, capture.LinkTypeRaw))  // skipped link type
	obs := d.Decode(packet(t, arpProbe, capture.LinkTypeEthernet))
	if obs[0].Ref().PacketID != 3 {
		t.Fatalf("packet id %d", obs[0].Ref().PacketID)
	}
	st := d.Stats()
	if st.Packets != 3 || st.Decoded != 1 || st.Malformed != 1 || st.Skipped != 1 {
		t.Fatalf("stats %+v", st)
	}
}

func TestMalformedARPKeepsFrame(t *testing.T) {
	d := New("enp3s0")
	obs := d.Decode(packet(t, "ffffffffffff0080f41234560806"+"00010800", capture.LinkTypeEthernet))
	if len(obs) != 1 || obs[0].Kind() != ethernet.KindFrame {
		t.Fatalf("observations %+v", obs)
	}
}
