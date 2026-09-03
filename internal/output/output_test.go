package output

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
)

func TestEventFromARP(t *testing.T) {
	ev := observation.Evidence{Timestamp: time.Unix(0, 0).UTC(), Source: "enp3s0", Interface: "enp3s0", PacketID: 4, Protocol: "arp", Confidence: observation.Confirmed}
	o := arp.Observation{Evidence: ev, Op: 1, Role: arp.RoleProbe, SenderMAC: []byte{0, 0x80, 0xf4, 1, 2, 3}, TargetMAC: make([]byte, 6)}
	e := EventFrom(o)
	if e.Schema != SchemaEvent || e.Kind != "arp" || e.PacketID != 4 || e.Fields["role"] != "probe" {
		t.Fatalf("event %+v", e)
	}
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{`"schema":"wirepup/event/1"`, `"packet_id":4`, `"sender_mac":"00:80:f4:01:02:03"`, `"confidence":"confirmed"`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("missing %s in %s", key, b)
		}
	}
}

func TestEventFromLLDPUnknownVLAN(t *testing.T) {
	ev := observation.Evidence{Protocol: "lldp", Confidence: observation.Confirmed}
	e := EventFrom(lldp.Observation{Evidence: ev, SourceMAC: make([]byte, 6), Frame: lldp.Frame{SystemName: "sw", PortID: "1", VLANNames: map[uint16]string{}}})
	if !strings.Contains(e.Summary, "vlan unknown") || e.Fields["port_vlan_id"] != uint16(0) {
		t.Fatalf("summary %q fields %v", e.Summary, e.Fields)
	}
	if _, ok := e.Fields["capabilities"].([]string); !ok {
		t.Fatalf("capabilities must be a list, got %T", e.Fields["capabilities"])
	}
}
