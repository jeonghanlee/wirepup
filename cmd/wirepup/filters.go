package main

import (
	"fmt"
	"sort"

	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
)

// protocolFilter maps a --protocol name to the kernel filter rules that
// admit its frames and to the observation protocols it displays.
type protocolFilter struct {
	rules    []bpf.Rule
	displays []string
}

var protocolFilters = map[string]protocolFilter{
	"frame": {displays: []string{"ethernet"}},
	"arp":   {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeARP}}, displays: []string{"arp"}},
	"lldp":  {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeLLDP}}, displays: []string{"lldp"}},
	"ipv4":  {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv4}}, displays: []string{"ipv4"}},
	"dhcp":  {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoUDP, Port: dhcpv4.ServerPort}, {EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoUDP, Port: dhcpv4.ClientPort}}, displays: []string{"dhcp"}},
	"ipv6":  {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv6}}, displays: []string{"ipv6"}},
	"ndp":   {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv6, IPProto: ipv6.NextICMPv6}}, displays: []string{"icmpv6"}},
	"tcp":   {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoTCP}}, displays: []string{"tcp"}},
	// A CA or PVA server advertises its TCP port in search responses and
	// beacons, so the kernel cannot know it in advance: the rules admit
	// the UDP search and beacon ports and every IPv4 TCP segment, and the
	// decoder applies the learned port. wantPacket keeps the wider rule
	// from widening the device table.
	"ca":  {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoUDP, Port: ca.DefaultServerPort}, {EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoUDP, Port: ca.DefaultRepeaterPort}, {EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoTCP}}, displays: []string{"epics.ca"}},
	"pva": {rules: []bpf.Rule{{EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoUDP, Port: pva.DefaultUDPPort}, {EtherType: ethernet.EtherTypeIPv4, IPProto: ipv4.ProtoTCP}}, displays: []string{"epics.pva"}},
}

// wantPacket applies the display filter to one packet's observations:
// the device table ingests a packet only when one of its observations
// belongs to a requested protocol, so a kernel rule wider than the
// request never widens the inventory. A nil display set admits all.
func wantPacket(obs []observation.Observation, display map[string]bool) bool {
	if display == nil {
		return true
	}
	for _, o := range obs {
		if display[o.Ref().Protocol] {
			return true
		}
	}
	return false
}

// hiddenProtocols are shown only in verbose mode or when requested.
var hiddenProtocols = map[string]bool{"ethernet": true, "ipv4": true, "ipv6": true, "tcp": true}

// filterFor resolves the --protocol flag into a BPF program and the set
// of displayed protocol names. An empty spec means everything.
func filterFor(spec string) ([]bpf.Instruction, map[string]bool, error) {
	names := protocolSet(spec)
	if len(names) == 0 {
		return nil, nil, nil
	}
	var rules []bpf.Rule
	display := map[string]bool{}
	kernel := true
	for n := range names {
		f, ok := protocolFilters[n]
		if !ok {
			return nil, nil, fmt.Errorf("%w: unknown protocol %q (known: %s)", errUsage, n, knownProtocols())
		}
		if len(f.rules) == 0 {
			kernel = false
		}
		rules = append(rules, f.rules...)
		for _, d := range f.displays {
			display[d] = true
		}
	}
	if !kernel {
		return nil, display, nil
	}
	prog, err := bpf.Assemble(rules)
	if err != nil {
		return nil, nil, err
	}
	return prog, display, nil
}

func knownProtocols() string {
	names := make([]string, 0, len(protocolFilters))
	for n := range protocolFilters {
		names = append(names, n)
	}
	sort.Strings(names)
	s := ""
	for i, n := range names {
		if i > 0 {
			s += ", "
		}
		s += n
	}
	return s
}
