package device

import (
	"net/netip"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

var (
	caClient = netip.MustParseAddr("10.20.4.88")
	caBcast  = netip.MustParseAddr("10.20.4.255")
	caServer = netip.MustParseAddr("10.20.4.31")
	caOther  = netip.MustParseAddr("10.20.4.32")
)

func TestCASearchResponseCorrelation(t *testing.T) {
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(7, "MPS:SYS:STATE", false))
	reply := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, 5064, ca.SearchReplyDatagram(7, 5064))
	reply2 := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.SwitchMAC, caClient, caOther, 40000, 5064, ca.SearchReplyDatagram(7, 5064))
	unanswered := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(8, "MISSING:PV", false))
	beacon := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, 5065, 5064, ca.BeaconDatagram(5064, 3, caServer))
	tbl := New(Options{})
	run(t, tbl, search, search, reply, reply2, unanswered, beacon)
	ss := tbl.CASearches()
	if len(ss) != 2 || ss[0].PV != "MPS:SYS:STATE" || ss[0].Count != 2 || len(ss[0].Responses) != 2 || ss[0].Responses[0].ServerIP != caServer || ss[0].Responses[1].ServerIP != caOther {
		t.Fatalf("searches %+v", ss)
	}
	if len(ss[1].Responses) != 0 || ss[1].PV != "MISSING:PV" {
		t.Fatalf("unanswered %+v", ss[1])
	}
	vs := tbl.CAServers()
	if len(vs) != 2 || vs[0].Addr != caServer || vs[0].Answers != 1 || vs[0].Beacons != 1 || vs[0].BeaconID != 3 || vs[0].PVs[0] != "MPS:SYS:STATE" || vs[0].MAC != fixtures.ServerMAC.String() {
		t.Fatalf("servers %+v", vs)
	}
	devs := tbl.Devices()
	if devs[0].Protocols[0] != ProtoCAClient || devs[1].Protocols[0] != ProtoCAServer || devs[1].IPv4[0].Addr != caServer {
		t.Fatalf("device roles %+v %+v", devs[0].Protocols, devs[1])
	}
}

func TestCANotFoundTracked(t *testing.T) {
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, 5064, 40000, ca.SearchDatagram(9, "X:Y", true))
	nf := make([]byte, ca.HeaderLen)
	nf[1] = ca.CmdNotFound
	nf[15] = 9
	reply := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, 5064, nf)
	tbl := New(Options{})
	run(t, tbl, search, reply)
	ss := tbl.CASearches()
	if len(ss) != 1 || len(ss[0].NotFound) != 1 || len(ss[0].Responses) != 0 {
		t.Fatalf("searches %+v", ss)
	}
}
