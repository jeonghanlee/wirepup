package device

import (
	"net/netip"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

func TestPVASearchResponseCorrelationByGUID(t *testing.T) {
	guid := [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	search := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, pva.DefaultUDPPort, 40000, pva.SearchDatagram(5, 77, "MPS:SYS:STATE", true, false))
	reply := fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, pva.DefaultUDPPort, pva.SearchResponseDatagram(guid, 5, netip.Addr{}, 5075, true, []int32{77}))
	beacon := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, pva.DefaultUDPPort, pva.DefaultUDPPort, pva.BeaconDatagram(guid, 1, 2, netip.Addr{}, 5075))
	missing := fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, pva.DefaultUDPPort, 40000, pva.SearchDatagram(6, 78, "MISSING:PV", true, false))
	tbl := New(Options{})
	run(t, tbl, search, reply, beacon, missing)
	ss := tbl.PVASearches()
	if len(ss) != 2 || ss[0].PV != "MPS:SYS:STATE" || len(ss[0].Responses) != 1 || ss[0].Responses[0].GUID != "0102030405060708090a0b0c" || ss[0].Responses[0].ServerPort != 5075 || len(ss[1].Responses) != 0 {
		t.Fatalf("searches %+v", ss)
	}
	vs := tbl.PVAServers()
	if len(vs) != 1 || vs[0].GUID != "0102030405060708090a0b0c" || vs[0].Addr != caServer || vs[0].Answers != 1 || vs[0].Beacons != 1 || vs[0].ChangeCount != 2 || vs[0].PVs[0] != "MPS:SYS:STATE" {
		t.Fatalf("servers %+v", vs)
	}
	devs := tbl.Devices()
	if devs[0].Protocols[0] != ProtoPVAClient || devs[1].Protocols[0] != ProtoPVAServer {
		t.Fatalf("roles %+v %+v", devs[0].Protocols, devs[1].Protocols)
	}
}
