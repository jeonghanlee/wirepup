package main

import (
	"fmt"
	"sort"

	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
)

// protocolFilter maps a --protocol name to the kernel filter rules that
// admit its frames and to the observation protocols it displays.
type protocolFilter struct {
	rules    []bpf.Rule
	displays []string
}

// Ethernet and transport constants used by the filter table.
const (
	etherTypeARP  = 0x0806
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeLLDP = 0x88cc
	ipProtoUDP    = 17
	ipProtoTCP    = 6
	ipProtoICMPv6 = 58
)

var protocolFilters = map[string]protocolFilter{
	"frame": {displays: []string{"ethernet"}},
	"arp":   {rules: []bpf.Rule{{EtherType: etherTypeARP}}, displays: []string{"arp"}},
	"lldp":  {rules: []bpf.Rule{{EtherType: etherTypeLLDP}}, displays: []string{"lldp"}},
	"ipv4":  {rules: []bpf.Rule{{EtherType: etherTypeIPv4}}, displays: []string{"ipv4"}},
	"dhcp":  {rules: []bpf.Rule{{EtherType: etherTypeIPv4, IPProto: ipProtoUDP, Port: 67}, {EtherType: etherTypeIPv4, IPProto: ipProtoUDP, Port: 68}}, displays: []string{"dhcp"}},
	"ipv6":  {rules: []bpf.Rule{{EtherType: etherTypeIPv6}}, displays: []string{"ipv6"}},
	"ndp":   {rules: []bpf.Rule{{EtherType: etherTypeIPv6, IPProto: ipProtoICMPv6}}, displays: []string{"icmpv6"}},
	"tcp":   {rules: []bpf.Rule{{EtherType: etherTypeIPv4, IPProto: ipProtoTCP}}, displays: []string{"tcp"}},
	"ca":    {rules: []bpf.Rule{{EtherType: etherTypeIPv4, IPProto: ipProtoUDP, Port: 5064}, {EtherType: etherTypeIPv4, IPProto: ipProtoUDP, Port: 5065}, {EtherType: etherTypeIPv4, IPProto: ipProtoTCP, Port: 5064}}, displays: []string{"epics.ca"}},
	"pva":   {rules: []bpf.Rule{{EtherType: etherTypeIPv4, IPProto: ipProtoUDP, Port: 5076}, {EtherType: etherTypeIPv4, IPProto: ipProtoTCP, Port: 5075}}, displays: []string{"epics.pva"}},
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
