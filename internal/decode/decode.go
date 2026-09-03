// Package decode runs the protocol parsers over each captured packet in
// link-layer order and emits typed observations with evidence attached
// (ADR-0008). It holds no device state and produces no output. Every
// packet from a source advances the packet number, decoded or not, so
// PacketID matches the frame number Wireshark shows for the same file.
package decode

import (
	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
	"github.com/jeonghanlee/wirepup/internal/protocol/udp"
)

// Protocol names recorded in Evidence.Protocol.
const (
	ProtoEthernet = "ethernet"
	ProtoARP      = "arp"
	ProtoLLDP     = "lldp"
	ProtoIPv4     = "ipv4"
	ProtoDHCP     = "dhcp"
)

// Stats counts what the pipeline saw.
type Stats struct {
	Packets   uint64
	Decoded   uint64
	Malformed uint64
	Skipped   uint64 // link types the pipeline does not decode
}

// Decoder is the per-source pipeline state.
type Decoder struct {
	source string
	next   uint64
	stats  Stats
}

// New returns a pipeline for one capture source.
func New(source string) *Decoder {
	return &Decoder{source: source}
}

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
		obs = append(obs, decodeIPv4(ev, frame.Payload)...)
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
func decodeIPv4(ev observation.Evidence, payload []byte) []observation.Observation {
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
		obs = append(obs, decodeUDP(ev, p, p.Payload)...)
	}
	return obs
}

// decodeUDP dispatches on the port pair. DHCP is claimed only when the
// magic cookie and message type validate, not from the port alone.
func decodeUDP(ev observation.Evidence, ip ipv4.Packet, payload []byte) []observation.Observation {
	d, err := udp.Parse(payload)
	if err != nil {
		return nil
	}
	var obs []observation.Observation
	if isPort(d, dhcpv4.ServerPort) || isPort(d, dhcpv4.ClientPort) {
		if o, ok := decodeDHCP(ev, ip, d); ok {
			obs = append(obs, o)
		}
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
