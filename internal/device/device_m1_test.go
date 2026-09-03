package device

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/decode"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
)

var (
	clientMAC = []byte{0x00, 0x80, 0xf4, 0x12, 0x34, 0x56}
	serverMAC = []byte{0x00, 0x1c, 0x73, 0x00, 0x00, 0x01}
)

// ipv4UDPFrame wraps a UDP payload in Ethernet/IPv4 headers.
func ipv4UDPFrame(src, dst []byte, srcIP, dstIP [4]byte, sport, dport uint16, payload []byte) []byte {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(8+len(payload)))
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:], uint16(20+len(udp)+len(payload)))
	ip[8], ip[9] = 64, 17
	copy(ip[12:16], srcIP[:])
	copy(ip[16:20], dstIP[:])
	f := append(append([]byte{}, dst...), src...)
	f = append(f, 0x08, 0x00)
	f = append(f, ip...)
	f = append(f, udp...)
	return append(f, payload...)
}

func dhcpMsg(op, msgType byte, xid uint32, yiaddr [4]byte, opts ...[]byte) []byte {
	b := make([]byte, dhcpv4.FixedLen)
	b[0], b[1], b[2] = op, 1, 6
	binary.BigEndian.PutUint32(b[4:], xid)
	copy(b[16:20], yiaddr[:])
	copy(b[28:], clientMAC)
	b = append(b, 0x63, 0x82, 0x53, 0x63, 53, 1, msgType)
	for _, o := range opts {
		b = append(b, o...)
	}
	return append(b, 255)
}

func run(t *testing.T, tbl *Table, frames ...[]byte) []Event {
	t.Helper()
	dec := decode.New("enp3s0")
	var events []Event
	for i, f := range frames {
		pkt := capture.Packet{Timestamp: time.Unix(1700000000+int64(i), 0), Interface: "enp3s0", LinkType: capture.LinkTypeEthernet, Data: f, CaptureLength: len(f), OriginalLength: len(f)}
		events = append(events, tbl.Apply(dec.Decode(pkt))...)
	}
	return events
}

func TestDHCPSequence(t *testing.T) {
	bcast := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	discover := ipv4UDPFrame(clientMAC, bcast, [4]byte{}, [4]byte{255, 255, 255, 255}, 68, 67, dhcpMsg(1, dhcpv4.Discover, 7, [4]byte{}, []byte{12, 3, 'i', 'o', 'c'}))
	offer := ipv4UDPFrame(serverMAC, clientMAC, [4]byte{10, 20, 30, 1}, [4]byte{10, 20, 30, 42}, 67, 68, dhcpMsg(2, dhcpv4.Offer, 7, [4]byte{10, 20, 30, 42}, []byte{54, 4, 10, 20, 30, 1}))
	request := ipv4UDPFrame(clientMAC, bcast, [4]byte{}, [4]byte{255, 255, 255, 255}, 68, 67, dhcpMsg(1, dhcpv4.Request, 7, [4]byte{}, []byte{50, 4, 10, 20, 30, 42}))
	ack := ipv4UDPFrame(serverMAC, clientMAC, [4]byte{10, 20, 30, 1}, [4]byte{10, 20, 30, 42}, 67, 68, dhcpMsg(2, dhcpv4.ACK, 7, [4]byte{10, 20, 30, 42}, []byte{54, 4, 10, 20, 30, 1}))

	tbl := New(Options{})
	events := run(t, tbl, discover, offer, request, ack)
	devs := tbl.Devices()
	if len(devs) != 2 {
		t.Fatalf("devices %d", len(devs))
	}
	client, server := devs[0], devs[1]
	if client.ID != "00:80:f4:12:34:56" || len(client.Names) != 1 || client.Names[0].Value != "ioc" || client.Names[0].Via != ViaDHCP {
		t.Fatalf("client %+v", client)
	}
	if len(client.IPv4) != 1 || client.IPv4[0].Addr.String() != "10.20.30.42" || client.IPv4[0].State != StateLeased {
		t.Fatalf("client addresses %+v", client.IPv4)
	}
	if server.Protocols[0] != ProtoDHCPServer || len(server.IPv4) == 0 || server.IPv4[0].Addr.String() != "10.20.30.1" {
		t.Fatalf("server %+v", server)
	}
	var texts []string
	for _, e := range client.Timeline {
		texts = append(texts, e.Text)
	}
	want := []string{"MAC observed", "DHCP name ioc", "DHCP discover", "DHCP offer 10.20.30.42 from 10.20.30.1", "DHCP request 10.20.30.42", "DHCP ack 10.20.30.42"}
	if fmt.Sprint(texts) != fmt.Sprint(want) {
		t.Fatalf("timeline %v", texts)
	}
	xs := tbl.DHCPTransactions()
	if len(xs) != 1 || xs[0].XID != 7 || xs[0].Discover.IsZero() || xs[0].Offer.IsZero() || xs[0].ACK.IsZero() || xs[0].AckIP.String() != "10.20.30.42" {
		t.Fatalf("transactions %+v", xs)
	}
	var ackEvent *Event
	for i := range events {
		if events[i].Via == ViaDHCPACK {
			ackEvent = &events[i]
		}
	}
	if ackEvent == nil || ackEvent.Method != MethodDHCP || ackEvent.Address.String() != "10.20.30.42" {
		t.Fatalf("ack event %+v", ackEvent)
	}
}

func TestLLDPNeighborKeptSeparate(t *testing.T) {
	lldpHex := "0180c200000e" + "001c73000001" + "88cc" + "0207" + "04001c73000001" + "0402" + "0531" + "0602" + "0078" + "0a02" + "7377" + "0000"
	frame, _ := hex.DecodeString(lldpHex)
	tbl := New(Options{})
	events := run(t, tbl, frame, frame)
	if len(events) != 2 || events[0].Change != ChangeNewDevice || events[1].Change != ChangeNewNeighbor {
		t.Fatalf("events %+v", events)
	}
	ns := tbl.Neighbors()
	if len(ns) != 1 || ns[0].SystemName != "sw" || ns[0].PortID != "1" || ns[0].SourceMAC != "00:1c:73:00:00:01" || ns[0].TTL != 120 {
		t.Fatalf("neighbors %+v", ns)
	}
	d := tbl.Devices()[0]
	if len(d.Names) != 1 || d.Names[0].Value != "sw" || d.Names[0].Via != ViaLLDP || d.Protocols[0] != ProtoLLDP {
		t.Fatalf("device %+v", d)
	}
}

func TestWeakAddressesAreCapped(t *testing.T) {
	tbl := New(Options{})
	router := []byte{0x00, 0x1c, 0x73, 0x00, 0x00, 0x09}
	var frames [][]byte
	for i := 1; i <= maxWeakAddresses+4; i++ {
		frames = append(frames, ipv4UDPFrame(router, clientMAC, [4]byte{192, 168, byte(i), 1}, [4]byte{10, 20, 30, 42}, 4000, 4001, []byte{1}))
	}
	run(t, tbl, frames...)
	d := tbl.Devices()[0]
	if len(d.IPv4) != maxWeakAddresses || d.WeakOverflow != 4 || d.IPv4[0].State != StateSeen || d.IPv4[0].Via != ViaIPv4 {
		t.Fatalf("addresses %d overflow %d first %+v", len(d.IPv4), d.WeakOverflow, d.IPv4[0])
	}
}

func TestSeenDoesNotDowngradeARPClaim(t *testing.T) {
	tbl := New(Options{})
	announce, _ := hex.DecodeString("ffffffffffff0080f41234560806" + "0001080006040001" + "0080f4123456" + "0a141e2a" + "000000000000" + "0a141e2a")
	pkt := ipv4UDPFrame(clientMAC, serverMAC, [4]byte{10, 20, 30, 42}, [4]byte{10, 20, 30, 1}, 4000, 4001, []byte{1})
	run(t, tbl, announce, pkt)
	d := tbl.Devices()[0]
	if len(d.IPv4) != 1 || d.IPv4[0].State != StateClaimed {
		t.Fatalf("addresses %+v", d.IPv4)
	}
}
