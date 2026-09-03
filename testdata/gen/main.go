// Command gen writes the PCAP fixtures under testdata/pcap from the
// frame builders in internal/fixtures. Timestamps are fixed so that the
// golden outputs under testdata/golden are stable. Run it from the
// repository root: go run ./testdata/gen
package main

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/capture/pcapfile"
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

// pvaGUID is the fixed server identity of the PVA fixtures.
var pvaGUID = [12]byte{0x57, 0x69, 0x72, 0x65, 0x50, 0x75, 0x70, 0x00, 0x00, 0x00, 0x00, 0x01}

const outDir = "testdata/pcap"

type fixture struct {
	name   string
	frames [][]byte
}

var (
	ipDevice  = netip.MustParseAddr("10.20.30.42")
	ipLaptop  = netip.MustParseAddr("10.20.30.51")
	ipServer  = netip.MustParseAddr("10.20.30.1")
	ipLL      = netip.MustParseAddr("169.254.22.31")
	ipOther   = netip.MustParseAddr("192.168.1.100")
	ipBcast   = netip.MustParseAddr("255.255.255.255")
	ipZero    = netip.MustParseAddr("0.0.0.0")
	ip6Device = netip.MustParseAddr("fe80::280:f4ff:fe12:3456")
	caClient  = netip.MustParseAddr("10.20.4.88")
	caBcast   = netip.MustParseAddr("10.20.4.255")
	caServer  = netip.MustParseAddr("10.20.4.31")
	caServer2 = netip.MustParseAddr("10.20.4.32")
	ip6Unspec = netip.MustParseAddr("::")
	hostname  = fixtures.Option(12, []byte("ioc-pc")...)
	serverID  = fixtures.Option(54, 10, 20, 30, 1)
	requestIP = fixtures.Option(50, 10, 20, 30, 42)
)

func fixtureSet() []fixture {
	return []fixture{
		{"arp-autoip-selection", [][]byte{
			fixtures.ARPProbe(fixtures.DeviceMAC, ipLL),
			fixtures.ARPProbe(fixtures.DeviceMAC, ipLL),
			fixtures.ARPProbe(fixtures.DeviceMAC, ipLL),
			fixtures.ARPAnnounce(fixtures.DeviceMAC, ipLL),
			fixtures.ARPAnnounce(fixtures.DeviceMAC, ipLL),
		}},
		{"dhcp-success", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, ipBcast, ipZero, 67, 68, fixtures.DHCP(1, 1, 0x1234, fixtures.DeviceMAC, netip.Addr{}, hostname)),
			fixtures.IPv4UDP(fixtures.DeviceMAC, fixtures.ServerMAC, ipDevice, ipServer, 68, 67, fixtures.DHCP(2, 2, 0x1234, fixtures.DeviceMAC, ipDevice, serverID)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, ipBcast, ipZero, 67, 68, fixtures.DHCP(1, 3, 0x1234, fixtures.DeviceMAC, netip.Addr{}, requestIP, serverID, hostname)),
			fixtures.IPv4UDP(fixtures.DeviceMAC, fixtures.ServerMAC, ipDevice, ipServer, 68, 67, fixtures.DHCP(2, 5, 0x1234, fixtures.DeviceMAC, ipDevice, serverID)),
			fixtures.ARPAnnounce(fixtures.DeviceMAC, ipDevice),
		}},
		{"dhcp-no-offer", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, ipBcast, ipZero, 67, 68, fixtures.DHCP(1, 1, 0x2001, fixtures.DeviceMAC, netip.Addr{}, hostname)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, ipBcast, ipZero, 67, 68, fixtures.DHCP(1, 1, 0x2001, fixtures.DeviceMAC, netip.Addr{}, hostname)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.DeviceMAC, ipBcast, ipZero, 67, 68, fixtures.DHCP(1, 1, 0x2001, fixtures.DeviceMAC, netip.Addr{}, hostname)),
			fixtures.ARPProbe(fixtures.DeviceMAC, ipLL),
			fixtures.ARPAnnounce(fixtures.DeviceMAC, ipLL),
		}},
		{"lldp-single-neighbor", [][]byte{
			fixtures.LLDPFrame(fixtures.SwitchMAC, fixtures.LLDP(fixtures.SwitchMAC, "Gi1/0/12", "sw-lab-1", 120, 100, ipServer)),
			fixtures.LLDPFrame(fixtures.SwitchMAC, fixtures.LLDP(fixtures.SwitchMAC, "Gi1/0/12", "sw-lab-1", 120, 100, ipServer)),
		}},
		{"ipv6-dad", [][]byte{
			fixtures.IPv6(fixtures.MulticastMAC(fixtures.SolicitedNode(ip6Device)), fixtures.DeviceMAC, fixtures.SolicitedNode(ip6Device), ip6Unspec, 58, 255, fixtures.NDPSolicit(ip6Device, nil)),
			fixtures.IPv6(fixtures.MulticastMAC(fixtures.IPv6AllNode), fixtures.DeviceMAC, fixtures.IPv6AllNode, ip6Device, 58, 255, fixtures.NDPAdvert(ip6Device, fixtures.DeviceMAC, false, true)),
		}},
		{"same-l2-different-subnet", [][]byte{
			fixtures.ARP(fixtures.LaptopMAC, 1, ipLaptop, ipServer, make([]byte, 6)),
			fixtures.ARP(fixtures.DeviceMAC, 1, ipOther, netip.MustParseAddr("192.168.1.1"), make([]byte, 6)),
			fixtures.ARP(fixtures.DeviceMAC, 1, ipOther, netip.MustParseAddr("192.168.1.1"), make([]byte, 6)),
		}},
		{"vlan-tagged-arp", [][]byte{
			fixtures.EthernetVLAN(fixtures.Broadcast, fixtures.DeviceMAC, 100, 0x0806, fixtures.ARPAnnounce(fixtures.DeviceMAC, ipDevice)[14:]),
		}},
		{"ca-search-response", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(1, "MPS:SYS:STATE", false)),
			fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, ca.DefaultServerPort, ca.SearchReplyDatagram(1, 5064)),
		}},
		{"ca-search-no-response", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(2, "MISSING:PV", false)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(2, "MISSING:PV", false)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(2, "MISSING:PV", false)),
		}},
		{"ca-beacon", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, ca.DefaultRepeaterPort, 5064, ca.BeaconDatagram(5064, 100, caServer)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, ca.DefaultRepeaterPort, 5064, ca.BeaconDatagram(5064, 101, caServer)),
		}},
		{"pva-search-response", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, pva.DefaultUDPPort, 40000, pva.SearchDatagram(1, 1, "MPS:SYS:STATE", true, false)),
			fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, pva.DefaultUDPPort, pva.SearchResponseDatagram(pvaGUID, 1, netip.Addr{}, pva.DefaultTCPPort, true, []int32{1})),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, pva.DefaultUDPPort, 40000, pva.SearchDatagram(2, 2, "MISSING:PV", true, false)),
		}},
		{"pva-beacon", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, pva.DefaultUDPPort, pva.DefaultUDPPort, pva.BeaconDatagram(pvaGUID, 1, 5, netip.Addr{}, pva.DefaultTCPPort)),
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.ServerMAC, caBcast, caServer, pva.DefaultUDPPort, pva.DefaultUDPPort, pva.BeaconDatagram(pvaGUID, 2, 5, netip.Addr{}, pva.DefaultTCPPort)),
		}},
		{"pva-tcp-handshake", [][]byte{
			fixtures.IPv4TCP(fixtures.ServerMAC, fixtures.LaptopMAC, caServer, caClient, pva.DefaultTCPPort, 40002, 0x02, 1, nil),
			fixtures.IPv4TCP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40002, pva.DefaultTCPPort, 0x12, 1, nil),
			fixtures.IPv4TCP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40002, pva.DefaultTCPPort, 0x18, 2, append(pva.SetByteOrder(true), pva.ValidationRequest(65536, 127, []string{"anonymous", "ca"})...)),
			fixtures.IPv4TCP(fixtures.ServerMAC, fixtures.LaptopMAC, caServer, caClient, pva.DefaultTCPPort, 40002, 0x18, 2, pva.CreateChannelRequest(1, "MPS:SYS:STATE")),
		}},
		{"ca-duplicate-servers", [][]byte{
			fixtures.IPv4UDP(fixtures.Broadcast, fixtures.LaptopMAC, caBcast, caClient, ca.DefaultServerPort, 40000, ca.SearchDatagram(3, "DUP:PV", false)),
			fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.ServerMAC, caClient, caServer, 40000, ca.DefaultServerPort, ca.SearchReplyDatagram(3, 5064)),
			fixtures.IPv4UDP(fixtures.LaptopMAC, fixtures.SwitchMAC, caClient, caServer2, 40000, ca.DefaultServerPort, ca.SearchReplyDatagram(3, 5064)),
		}},
	}
}

func main() {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fail(err)
	}
	for _, f := range fixtureSet() {
		for _, ext := range []string{".pcap"} {
			path := filepath.Join(outDir, f.name+ext)
			w, err := pcapfile.Create(path, "enp3s0", pcapfile.DefaultSnapLen)
			if err != nil {
				fail(err)
			}
			for i, frame := range f.frames {
				if err := w.Write(fixtures.Packet(i, frame)); err != nil {
					fail(err)
				}
			}
			if err := w.Close(); err != nil {
				fail(err)
			}
			fmt.Printf("%s: %d packets\n", path, len(f.frames))
		}
	}
	// One PCAPNG copy proves the second format end to end.
	path := filepath.Join(outDir, "lldp-single-neighbor.pcapng")
	w, err := pcapfile.Create(path, "enp3s0", pcapfile.DefaultSnapLen)
	if err != nil {
		fail(err)
	}
	for i, frame := range fixtureSet()[3].frames {
		if err := w.Write(fixtures.Packet(i, frame)); err != nil {
			fail(err)
		}
	}
	if err := w.Close(); err != nil {
		fail(err)
	}
	fmt.Printf("%s: %d packets\n", path, len(fixtureSet()[3].frames))
	_ = capture.LinkTypeEthernet
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
