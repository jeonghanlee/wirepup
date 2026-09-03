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
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

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
