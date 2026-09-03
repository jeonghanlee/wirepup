// Package bpf assembles the classic BPF programs that the Linux capture
// backend attaches with SO_ATTACH_FILTER (ADR-0002). Programs are built
// from a small set of match rules so that no external compiler is needed.
// The Linux socket filter sees an Ethernet frame without its 802.1Q tag
// (the tag travels in PACKET_AUXDATA), so untagged offsets hold for
// tagged frames as well. IPv6 extension headers are not followed.
package bpf

import "fmt"

// Instruction is one classic BPF instruction (struct sock_filter).
type Instruction struct {
	Code uint16
	JT   uint8
	JF   uint8
	K    uint32
}

// Opcodes from <linux/filter.h>: class | size | mode.
const (
	OpLdHalfAbs  uint16 = 0x28 // A = P[k:2]
	OpLdByteAbs  uint16 = 0x30 // A = P[k:1]
	OpLdHalfInd  uint16 = 0x48 // A = P[X+k:2]
	OpLdxMshByte uint16 = 0xb1 // X = 4 * (P[k:1] & 0x0f)
	OpJeqK       uint16 = 0x15 // pc += (A == k) ? jt : jf
	OpJsetK      uint16 = 0x45 // pc += (A & k) ? jt : jf
	OpRetK       uint16 = 0x06 // return k
)

// Frame offsets and constants for an untagged Ethernet frame.
const (
	offEtherType   = 12
	offIPv4Header  = 14
	offIPv4FragOff = 20
	offIPv4Proto   = 23
	offIPv6Next    = 20
	offIPv6SrcPort = 54
	offIPv6DstPort = 56
	relSrcPort     = 14 // X + 14: transport header start after the IPv4 header
	relDstPort     = 16
	ipv4FragMask   = 0x1fff
	etherTypeIPv4  = 0x0800
	etherTypeIPv6  = 0x86dd

	// AcceptLength is the byte count returned for an accepted frame; the
	// kernel truncates it to the real frame length.
	AcceptLength = 262144
	maxJump      = 255
)

// Rule accepts frames matching every non-zero field. Port matches either
// the source or the destination port. A rule without EtherType but with
// IPProto or Port applies to both IPv4 and IPv6.
type Rule struct {
	EtherType uint16
	IPProto   uint8
	Port      uint16
}

// Symbolic jump targets used while a block is being built; non-negative
// values are instruction indexes inside the block.
const (
	targetAccept = -1
	targetNext   = -2
)

type pending struct {
	code   uint16
	jt, jf int
	k      uint32
}

// AcceptAll returns the one-instruction program that passes every frame.
func AcceptAll() []Instruction {
	return []Instruction{{Code: OpRetK, K: AcceptLength}}
}

// Assemble builds a program that accepts a frame matching any rule and
// drops every other frame. An empty rule set yields AcceptAll.
func Assemble(rules []Rule) ([]Instruction, error) {
	if len(rules) == 0 {
		return AcceptAll(), nil
	}
	var blocks [][]pending
	for _, r := range rules {
		b, err := blocksFor(r)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, b...)
	}
	return link(blocks)
}

// blocksFor expands one rule into one block per address family it covers.
func blocksFor(r Rule) ([][]pending, error) {
	if r.IPProto == 0 && r.Port == 0 {
		if r.EtherType == 0 {
			return nil, fmt.Errorf("bpf: empty rule")
		}
		return [][]pending{{
			{code: OpLdHalfAbs, k: offEtherType},
			{code: OpJeqK, jt: targetAccept, jf: targetNext, k: uint32(r.EtherType)},
		}}, nil
	}
	var out [][]pending
	switch r.EtherType {
	case 0:
		out = append(out, ipv4Block(r), ipv6Block(r))
	case etherTypeIPv4:
		out = append(out, ipv4Block(r))
	case etherTypeIPv6:
		out = append(out, ipv6Block(r))
	default:
		return nil, fmt.Errorf("bpf: transport rule needs EtherType IPv4, IPv6, or none")
	}
	return out, nil
}

func ipv4Block(r Rule) []pending {
	b := []pending{
		{code: OpLdHalfAbs, k: offEtherType},
		{code: OpJeqK, jt: 2, jf: targetNext, k: etherTypeIPv4},
	}
	if r.IPProto != 0 {
		next := len(b) + 2
		if r.Port == 0 {
			next = targetAccept
		}
		b = append(b,
			pending{code: OpLdByteAbs, k: offIPv4Proto},
			pending{code: OpJeqK, jt: next, jf: targetNext, k: uint32(r.IPProto)})
	}
	if r.Port != 0 {
		n := len(b)
		b = append(b,
			pending{code: OpLdHalfAbs, k: offIPv4FragOff},
			pending{code: OpJsetK, jt: targetNext, jf: n + 2, k: ipv4FragMask},
			pending{code: OpLdxMshByte, k: offIPv4Header},
			pending{code: OpLdHalfInd, k: relSrcPort},
			pending{code: OpJeqK, jt: targetAccept, jf: n + 5, k: uint32(r.Port)},
			pending{code: OpLdHalfInd, k: relDstPort},
			pending{code: OpJeqK, jt: targetAccept, jf: targetNext, k: uint32(r.Port)})
	}
	return b
}

func ipv6Block(r Rule) []pending {
	b := []pending{
		{code: OpLdHalfAbs, k: offEtherType},
		{code: OpJeqK, jt: 2, jf: targetNext, k: etherTypeIPv6},
	}
	if r.IPProto != 0 {
		next := len(b) + 2
		if r.Port == 0 {
			next = targetAccept
		}
		b = append(b,
			pending{code: OpLdByteAbs, k: offIPv6Next},
			pending{code: OpJeqK, jt: next, jf: targetNext, k: uint32(r.IPProto)})
	}
	if r.Port != 0 {
		n := len(b)
		b = append(b,
			pending{code: OpLdHalfAbs, k: offIPv6SrcPort},
			pending{code: OpJeqK, jt: targetAccept, jf: n + 2, k: uint32(r.Port)},
			pending{code: OpLdHalfAbs, k: offIPv6DstPort},
			pending{code: OpJeqK, jt: targetAccept, jf: targetNext, k: uint32(r.Port)})
	}
	return b
}

// link concatenates the blocks, appends the accept and drop returns, and
// resolves every symbolic jump into a forward offset.
func link(blocks [][]pending) ([]Instruction, error) {
	total := 0
	for _, b := range blocks {
		total += len(b)
	}
	accept := total
	drop := total + 1
	prog := make([]Instruction, 0, total+2)
	start := 0
	for i, b := range blocks {
		next := drop
		if i+1 < len(blocks) {
			next = start + len(b)
		}
		for j, p := range b {
			pos := start + j
			in := Instruction{Code: p.code, K: p.k}
			if p.code == OpJeqK || p.code == OpJsetK {
				jt, err := offset(pos, resolve(p.jt, start, accept, next))
				if err != nil {
					return nil, err
				}
				jf, err := offset(pos, resolve(p.jf, start, accept, next))
				if err != nil {
					return nil, err
				}
				in.JT, in.JF = jt, jf
			}
			prog = append(prog, in)
		}
		start += len(b)
	}
	prog = append(prog,
		Instruction{Code: OpRetK, K: AcceptLength},
		Instruction{Code: OpRetK, K: 0})
	return prog, nil
}

func resolve(target, start, accept, next int) int {
	switch target {
	case targetAccept:
		return accept
	case targetNext:
		return next
	default:
		return start + target
	}
}

func offset(pos, target int) (uint8, error) {
	d := target - (pos + 1)
	if d < 0 || d > maxJump {
		return 0, fmt.Errorf("bpf: jump from %d to %d out of range", pos, target)
	}
	return uint8(d), nil
}
