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
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

// Protocol names recorded in Evidence.Protocol.
const (
	ProtoEthernet = "ethernet"
	ProtoARP      = "arp"
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
