// Package decode runs the protocol parsers over each captured packet in
// link-layer order and emits typed observations with evidence attached
// (ADR-0008). It holds no device state and produces no output. Every
// packet from a source advances the packet number, decoded or not, so
// PacketID matches the frame number Wireshark shows for the same file.
package decode

import (
	"net/netip"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
	"github.com/jeonghanlee/wirepup/internal/protocol/tcp"
	"github.com/jeonghanlee/wirepup/internal/protocol/udp"
)

// Protocol names recorded in Evidence.Protocol.
const (
	ProtoEthernet = "ethernet"
	ProtoARP      = "arp"
	ProtoLLDP     = "lldp"
	ProtoIPv4     = "ipv4"
	ProtoIPv6     = "ipv6"
	ProtoICMPv6   = "icmpv6"
	ProtoDHCP     = "dhcp"
	ProtoTCP      = "tcp"
	ProtoCA       = "epics.ca"
	ProtoPVA      = "epics.pva"
)

// Ports configure the EPICS port hints (defaults unless overridden).
type Ports struct {
	CAServer   uint16
	CARepeater uint16
	PVAUDP     uint16
	PVATCP     uint16
}

// DefaultPorts are the EPICS defaults.
var DefaultPorts = Ports{CAServer: ca.DefaultServerPort, CARepeater: ca.DefaultRepeaterPort, PVAUDP: pva.DefaultUDPPort, PVATCP: pva.DefaultTCPPort}

// Stats counts what the pipeline saw.
type Stats struct {
	Packets   uint64
	Decoded   uint64
	Malformed uint64
	Skipped   uint64 // link types the pipeline does not decode
}

// Decoder is the per-source pipeline state. Server TCP ports learned
// from search responses and beacons extend the default port hints, so a
// server advertising a non-default port is still decoded on TCP
// (docs/architecture.md sections 11 and 12).
type Decoder struct {
	source string
	next   uint64
	stats  Stats
	ports  Ports
	caTCP  map[uint16]bool
	pvaTCP map[uint16]bool
}

// New returns a pipeline for one capture source with default ports.
func New(source string) *Decoder {
	return &Decoder{source: source, ports: DefaultPorts, caTCP: map[uint16]bool{}, pvaTCP: map[uint16]bool{}}
}

// LearnedPorts returns the server TCP ports learned so far.
func (d *Decoder) LearnedPorts() (ca, pva []uint16) {
	for p := range d.caTCP {
		ca = append(ca, p)
	}
	for p := range d.pvaTCP {
		pva = append(pva, p)
	}
	return ca, pva
}

func (d *Decoder) isCATCP(port uint16) bool  { return port == d.ports.CAServer || d.caTCP[port] }
func (d *Decoder) isPVATCP(port uint16) bool { return port == d.ports.PVATCP || d.pvaTCP[port] }

// SetPorts overrides the EPICS port hints. It is the seam for a site
// that runs EPICS on offset ports (a non-default EPICS_CA_SERVER_PORT and
// its PVA counterparts): the decoder would then key its UDP and default
// TCP hints off the offset values. It has no caller yet; using it needs a
// CLI flag to carry the offset and a matching kernel-filter rule in
// cmd/wirepup/filters.go, since a live capture admits the UDP hint ports
// at the kernel. The learned TCP port maps (caTCP/pvaTCP) are unaffected.
func (d *Decoder) SetPorts(p Ports) { d.ports = p }

// Stats returns the running counters.
func (d *Decoder) Stats() Stats { return d.stats }

// Decode parses one packet and returns its observations, frame first.
func (d *Decoder) Decode(pkt capture.Packet) []observation.Observation {
	d.next++
	d.stats.Packets++
	if pkt.LinkType != capture.LinkTypeEthernet {
		d.stats.Skipped++
		return nil
	}
	frame, err := ethernet.Parse(pkt.Data)
	if err != nil {
		d.stats.Malformed++
		return nil
	}
	d.stats.Decoded++
	ev := observation.Evidence{
		Timestamp:  pkt.Timestamp,
		Source:     d.source,
		Interface:  pkt.Interface,
		PacketID:   d.next,
		Protocol:   ProtoEthernet,
		Confidence: observation.Confirmed,
	}
	obs := []observation.Observation{ethernet.Observation{
		Evidence:    ev,
		Destination: frame.Destination,
		Source:      frame.Source,
		EtherType:   frame.EtherType,
		VLAN:        frame.VLAN,
		Length:      pkt.OriginalLength,
	}}
	switch frame.EtherType {
	case ethernet.EtherTypeARP:
		if o, ok := decodeARP(ev, frame.Payload); ok {
			obs = append(obs, o)
		}
	case ethernet.EtherTypeLLDP:
		if o, ok := decodeLLDP(ev, frame); ok {
			obs = append(obs, o)
		}
	case ethernet.EtherTypeIPv4:
		obs = append(obs, d.decodeIPv4(ev, frame.Payload)...)
	case ethernet.EtherTypeIPv6:
		obs = append(obs, decodeIPv6(ev, frame.Payload)...)
	}
	return obs
}

// decodeIPv6 emits the IPv6 observation and dispatches ICMPv6; EPICS
// over IPv6 is outside V1, so UDP and TCP payloads are not decoded.
func decodeIPv6(ev observation.Evidence, payload []byte) []observation.Observation {
	p, err := ipv6.Parse(payload)
	if err != nil {
		return nil
	}
	ev.Protocol = ProtoIPv6
	obs := []observation.Observation{ipv6.Observation{
		Evidence:   ev,
		Src:        p.Src,
		Dst:        p.Dst,
		NextHeader: p.NextHeader,
		HopLimit:   p.HopLimit,
		Length:     ipv6.HeaderLen + p.PayloadLen,
		Fragment:   p.Fragment,
	}}
	if p.PayloadDrop {
		return obs
	}
	switch p.NextHeader {
	case ipv6.NextICMPv6:
		m, err := icmpv6.Parse(p.Payload)
		if err != nil {
			return obs
		}
		ev.Protocol = ProtoICMPv6
		if m.Malformed {
			ev.Confidence = observation.StrongHint
		}
		obs = append(obs, icmpv6.Observation{
			Evidence: ev,
			Message:  m,
			Src:      p.Src,
			Dst:      p.Dst,
			DAD:      m.Type == icmpv6.TypeNeighborSolicit && p.Src.IsUnspecified(),
		})
	}
	return obs
}

func decodeARP(ev observation.Evidence, payload []byte) (observation.Observation, bool) {
	p, err := arp.Parse(payload)
	if err != nil {
		return nil, false
	}
	ev.Protocol = ProtoARP
	return arp.Observation{
		Evidence:  ev,
		Op:        p.Op,
		Role:      arp.Classify(p),
		SenderMAC: p.SenderMAC,
		SenderIP:  p.SenderIP,
		TargetMAC: p.TargetMAC,
		TargetIP:  p.TargetIP,
	}, true
}

func decodeLLDP(ev observation.Evidence, frame ethernet.Frame) (observation.Observation, bool) {
	f, err := lldp.Parse(frame.Payload)
	if err != nil {
		return nil, false
	}
	ev.Protocol = ProtoLLDP
	if f.Malformed {
		ev.Confidence = observation.StrongHint
	}
	return lldp.Observation{Evidence: ev, SourceMAC: frame.Source, Frame: f}, true
}

// decodeIPv4 emits the IPv4 observation and dispatches the payload to
// the transport and application parsers.
func (d *Decoder) decodeIPv4(ev observation.Evidence, payload []byte) []observation.Observation {
	p, err := ipv4.Parse(payload)
	if err != nil {
		return nil
	}
	ev.Protocol = ProtoIPv4
	obs := []observation.Observation{ipv4.Observation{
		Evidence: ev,
		Src:      p.Src,
		Dst:      p.Dst,
		Protocol: p.Protocol,
		TTL:      p.TTL,
		Length:   p.TotalLen,
		Fragment: p.FragOffset != 0 || p.MoreFrags,
	}}
	if p.PayloadDrop {
		return obs
	}
	switch p.Protocol {
	case ipv4.ProtoUDP:
		obs = append(obs, d.decodeUDP(ev, p, p.Payload)...)
	case ipv4.ProtoTCP:
		obs = append(obs, d.decodeTCP(ev, p.Src, p.Dst, p.Payload)...)
	}
	return obs
}

// decodeUDP dispatches on the port pair. DHCP is claimed only when the
// magic cookie and message type validate; CA is claimed on its ports
// when the datagram parses, and on other ports only when the first
// header is unmistakably CA.
func (d *Decoder) decodeUDP(ev observation.Evidence, ip ipv4.Packet, payload []byte) []observation.Observation {
	dg, err := udp.Parse(payload)
	if err != nil {
		return nil
	}
	var obs []observation.Observation
	switch {
	case isPort(dg, dhcpv4.ServerPort) || isPort(dg, dhcpv4.ClientPort):
		if o, ok := decodeDHCP(ev, ip, dg); ok {
			obs = append(obs, o)
		}
	case isPort(dg, d.ports.CAServer) || isPort(dg, d.ports.CARepeater):
		obs = append(obs, d.decodeCA(ev, observation.TransportUDP, ip.Src, ip.Dst, dg.SrcPort, dg.DstPort, dg.Payload, observation.Confirmed)...)
	case isPort(dg, d.ports.PVAUDP):
		obs = append(obs, d.decodePVA(ev, observation.TransportUDP, ip.Src, ip.Dst, dg.SrcPort, dg.DstPort, dg.Payload, observation.Confirmed)...)
	case pva.Probable(dg.Payload):
		obs = append(obs, d.decodePVA(ev, observation.TransportUDP, ip.Src, ip.Dst, dg.SrcPort, dg.DstPort, dg.Payload, observation.StrongHint)...)
	case len(dg.Payload) >= ca.HeaderLen && ca.Probable(dg.Payload):
		obs = append(obs, d.decodeCA(ev, observation.TransportUDP, ip.Src, ip.Dst, dg.SrcPort, dg.DstPort, dg.Payload, observation.StrongHint)...)
	}
	return obs
}

// decodePVA parses every PVA message in the buffer; a buffer that does
// not start with a valid header is not PVA whatever the port says.
func (d *Decoder) decodePVA(ev observation.Evidence, transport string, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte, conf observation.Confidence) []observation.Observation {
	msgs, err := pva.Parse(payload)
	if len(msgs) == 0 {
		return nil
	}
	if err != nil {
		if transport == observation.TransportUDP {
			return nil
		}
		conf = observation.StrongHint
	}
	ev.Protocol = ProtoPVA
	ev.Confidence = conf
	var obs []observation.Observation
	for _, m := range msgs {
		o := pva.Interpret(m, transport, src, dst, srcPort, dstPort)
		o.Evidence = ev
		if o.Malformed && o.Evidence.Confidence == observation.Confirmed {
			o.Evidence.Confidence = observation.StrongHint
		}
		if (o.Command == pva.CmdSearchResponse || o.Command == pva.CmdBeacon) && o.ServerPort != 0 && !o.Malformed {
			d.pvaTCP[o.ServerPort] = true
		}
		obs = append(obs, o)
	}
	return obs
}

// decodeTCP emits connection events and parses application messages
// that start at the segment boundary; a partial trailing message lowers
// the confidence to a strong hint because no reassembly is done.
func (d *Decoder) decodeTCP(ev observation.Evidence, src, dst netip.Addr, payload []byte) []observation.Observation {
	seg, err := tcp.Parse(payload)
	if err != nil {
		return nil
	}
	var obs []observation.Observation
	if tcp.IsStateEvent(seg.Flags) {
		tev := ev
		tev.Protocol = ProtoTCP
		obs = append(obs, tcp.Observation{Evidence: tev, Src: src, Dst: dst, SrcPort: seg.SrcPort, DstPort: seg.DstPort, Flags: seg.Flags, Seq: seg.Seq, PayloadLen: len(seg.Payload)})
	}
	if len(seg.Payload) == 0 {
		return obs
	}
	switch {
	case d.isPVATCP(seg.SrcPort) || d.isPVATCP(seg.DstPort) || pva.Probable(seg.Payload):
		conf := observation.Confirmed
		if !d.isPVATCP(seg.SrcPort) && !d.isPVATCP(seg.DstPort) {
			conf = observation.StrongHint
		}
		obs = append(obs, d.decodePVA(ev, observation.TransportTCP, src, dst, seg.SrcPort, seg.DstPort, seg.Payload, conf)...)
	case d.isCATCP(seg.SrcPort) || d.isCATCP(seg.DstPort):
		obs = append(obs, d.decodeCA(ev, observation.TransportTCP, src, dst, seg.SrcPort, seg.DstPort, seg.Payload, observation.Confirmed)...)
	}
	return obs
}

// decodeCA parses every message in the buffer. A datagram that does
// not parse at all is not CA, whatever the port says.
func (d *Decoder) decodeCA(ev observation.Evidence, transport string, src, dst netip.Addr, srcPort, dstPort uint16, payload []byte, conf observation.Confidence) []observation.Observation {
	msgs, err := ca.Parse(payload, transport == observation.TransportUDP)
	if len(msgs) == 0 {
		return nil
	}
	if err != nil {
		if transport == observation.TransportUDP {
			return nil
		}
		conf = observation.StrongHint
	}
	ev.Protocol = ProtoCA
	ev.Confidence = conf
	var obs []observation.Observation
	for _, m := range msgs {
		o := ca.Interpret(m, transport, src, dst, srcPort, dstPort, d.ports.CAServer)
		o.Evidence = ev
		if (o.Kind() == "ca.search_response" || o.Kind() == "ca.beacon") && o.ServerPort != 0 {
			d.caTCP[o.ServerPort] = true
		}
		obs = append(obs, o)
	}
	return obs
}

func isPort(d udp.Datagram, port uint16) bool {
	return d.SrcPort == port || d.DstPort == port
}

func decodeDHCP(ev observation.Evidence, ip ipv4.Packet, d udp.Datagram) (observation.Observation, bool) {
	m, err := dhcpv4.Parse(d.Payload)
	if err != nil {
		return nil, false
	}
	ev.Protocol = ProtoDHCP
	if m.MessageType == 0 {
		ev.Confidence = observation.StrongHint
	}
	return dhcpv4.Observation{Evidence: ev, Message: m, SrcIP: ip.Src, DstIP: ip.Dst}, true
}
