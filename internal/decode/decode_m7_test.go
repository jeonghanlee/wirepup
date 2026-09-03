package decode

import (
	"net/netip"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/tcp"
)

var (
	caClient = netip.MustParseAddr("10.20.4.88")
	caBcast  = netip.MustParseAddr("10.20.4.255")
	caServer = netip.MustParseAddr("10.20.4.31")
)

func decodeOne(t *testing.T, frame []byte) []observation.Observation {
	t.Helper()
	return New("x").Decode(fixtures.Packet(0, frame))
}

func TestCASearchAndResponseOverUDP(t *testing.T) {
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(7, "MPS:SYS:STATE", false))
	obs := decodeOne(t, search)
	if len(obs) != 4 {
		t.Fatalf("observations %d", len(obs))
	}
	s, ok := obs[3].(ca.Observation)
	if !ok || s.Kind() != "ca.search" || s.PVName != "MPS:SYS:STATE" || s.Ref().Protocol != ProtoCA || s.Ref().Confidence != observation.Confirmed {
		t.Fatalf("search %+v", obs[3])
	}
	reply := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, ca.DefaultServerPort, ca.SearchReplyDatagram(7, 5064))
	obs = decodeOne(t, reply)
	r, ok := obs[2].(ca.Observation)
	if !ok || r.Kind() != "ca.search_response" || r.SearchID != 7 || r.ServerIP != caServer || r.ServerPort != 5064 {
		t.Fatalf("reply %+v", obs[2])
	}
}

func TestPortAloneDoesNotClaimCA(t *testing.T) {
	junk := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, []byte("this is not channel access at all"))
	obs := decodeOne(t, junk)
	if len(obs) != 2 {
		t.Fatalf("junk on 5064 produced %d observations", len(obs))
	}
}

func TestCAOnNonDefaultPortByStructure(t *testing.T) {
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 6064, 40000, ca.SearchDatagram(3, "X:Y", true))
	obs := decodeOne(t, search)
	if len(obs) != 4 || obs[3].Ref().Confidence != observation.StrongHint {
		t.Fatalf("non-default port: %d observations", len(obs))
	}
}

func TestCAOverTCPAndConnectionEvents(t *testing.T) {
	syn := fixtures.IPv4TCP(fixtures.ServerMAC, fixtures.LaptopMAC, caServer, caClient, 5064, 40001, tcp.FlagSYN, 1, nil)
	obs := decodeOne(t, syn)
	if len(obs) != 3 || obs[2].Kind() != tcp.Kind {
		t.Fatalf("syn %+v", obs)
	}
	var payload []byte
	payload = append(payload, ca.SearchDatagram(0, "", false)[:ca.HeaderLen]...) // version message
	name := append([]byte("MPS:SYS:STATE"), 0, 0, 0)
	hdr := make([]byte, ca.HeaderLen)
	hdr[1] = ca.CmdCreateChan
	hdr[3] = byte(len(name))
	hdr[11] = 5
	hdr[15] = ca.MinorRevision
	payload = append(payload, hdr...)
	payload = append(payload, name...)
	data := fixtures.IPv4TCP(fixtures.ServerMAC, fixtures.LaptopMAC, caServer, caClient, 5064, 40001, tcp.FlagACK|tcp.FlagPSH, 2, payload)
	obs = decodeOne(t, data)
	if len(obs) != 4 || obs[2].Kind() != "ca.version" || obs[3].Kind() != "ca.create_channel" {
		t.Fatalf("tcp ca %+v", obs)
	}
	c := obs[3].(ca.Observation)
	if c.PVName != "MPS:SYS:STATE" || c.Transport != "tcp" || c.Direction != ca.ToServer {
		t.Fatalf("create %+v", c)
	}
	// A segment cut inside a message keeps the complete messages as a strong hint.
	cut := fixtures.IPv4TCP(fixtures.ServerMAC, fixtures.LaptopMAC, caServer, caClient, 5064, 40001, tcp.FlagACK, 2, payload[:ca.HeaderLen+4])
	obs = decodeOne(t, cut)
	if len(obs) != 3 || obs[2].Ref().Confidence != observation.StrongHint {
		t.Fatalf("cut %+v", obs)
	}
	for n := 0; n <= len(data); n++ {
		New("x").Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: data[:n], OriginalLength: len(data)})
	}
}
