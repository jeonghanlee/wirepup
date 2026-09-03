package bpf

import (
	"encoding/binary"
	"testing"
)

// run executes a program over one frame with a minimal classic BPF
// interpreter covering the opcodes the assembler emits. It stands in for
// the kernel, which cannot be reached without CAP_NET_RAW in unit tests.
func run(t *testing.T, prog []Instruction, frame []byte) uint32 {
	t.Helper()
	var a, x uint32
	for pc := 0; pc < len(prog); pc++ {
		in := prog[pc]
		switch in.Code {
		case OpLdHalfAbs:
			if int(in.K)+2 > len(frame) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(frame[in.K:]))
		case OpLdByteAbs:
			if int(in.K)+1 > len(frame) {
				return 0
			}
			a = uint32(frame[in.K])
		case OpLdHalfInd:
			off := int(x) + int(in.K)
			if off+2 > len(frame) {
				return 0
			}
			a = uint32(binary.BigEndian.Uint16(frame[off:]))
		case OpLdxMshByte:
			if int(in.K)+1 > len(frame) {
				return 0
			}
			x = 4 * uint32(frame[in.K]&0x0f)
		case OpJeqK:
			if a == in.K {
				pc += int(in.JT)
			} else {
				pc += int(in.JF)
			}
		case OpJsetK:
			if a&in.K != 0 {
				pc += int(in.JT)
			} else {
				pc += int(in.JF)
			}
		case OpRetK:
			return in.K
		default:
			t.Fatalf("unknown opcode %#x at %d", in.Code, pc)
		}
	}
	t.Fatalf("program fell off the end")
	return 0
}

func ethFrame(etherType uint16, payload []byte) []byte {
	f := make([]byte, 14, 14+len(payload))
	binary.BigEndian.PutUint16(f[12:], etherType)
	return append(f, payload...)
}

func ipv4UDP(srcPort, dstPort uint16, fragOff uint16) []byte {
	ip := make([]byte, 20)
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[6:], fragOff)
	ip[9] = 17
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	return ethFrame(etherTypeIPv4, append(ip, udp...))
}

func ipv6UDP(srcPort, dstPort uint16) []byte {
	ip := make([]byte, 40)
	ip[0] = 0x60
	ip[6] = 17
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:], srcPort)
	binary.BigEndian.PutUint16(udp[2:], dstPort)
	return ethFrame(etherTypeIPv6, append(ip, udp...))
}

func TestAcceptAll(t *testing.T) {
	prog := AcceptAll()
	if len(prog) != 1 || prog[0].Code != OpRetK || prog[0].K != AcceptLength {
		t.Fatalf("unexpected program %+v", prog)
	}
	if run(t, prog, ethFrame(0x0806, nil)) == 0 {
		t.Fatal("accept-all dropped a frame")
	}
}

func TestEtherTypeRule(t *testing.T) {
	prog, err := Assemble([]Rule{{EtherType: 0x0806}})
	if err != nil {
		t.Fatal(err)
	}
	want := []Instruction{
		{Code: OpLdHalfAbs, K: 12},
		{Code: OpJeqK, JT: 0, JF: 1, K: 0x0806},
		{Code: OpRetK, K: AcceptLength},
		{Code: OpRetK, K: 0},
	}
	if len(prog) != len(want) {
		t.Fatalf("got %d instructions, want %d", len(prog), len(want))
	}
	for i := range want {
		if prog[i] != want[i] {
			t.Fatalf("instruction %d: got %+v want %+v", i, prog[i], want[i])
		}
	}
	if run(t, prog, ethFrame(0x0806, nil)) == 0 {
		t.Fatal("ARP frame dropped")
	}
	if run(t, prog, ethFrame(0x0800, nil)) != 0 {
		t.Fatal("IPv4 frame accepted")
	}
}

func TestUDPPortRuleBothFamilies(t *testing.T) {
	prog, err := Assemble([]Rule{{IPProto: 17, Port: 5064}})
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"ipv4 dst port", ipv4UDP(40000, 5064, 0), true},
		{"ipv4 src port", ipv4UDP(5064, 40000, 0), true},
		{"ipv4 other port", ipv4UDP(40000, 5075, 0), false},
		{"ipv4 fragment", ipv4UDP(40000, 5064, 0x0010), false},
		{"ipv6 dst port", ipv6UDP(40000, 5064), true},
		{"ipv6 src port", ipv6UDP(5064, 40000), true},
		{"ipv6 other port", ipv6UDP(40000, 5076), false},
		{"arp", ethFrame(0x0806, make([]byte, 28)), false},
		{"short frame", ethFrame(etherTypeIPv4, []byte{0x45}), false},
	}
	for _, c := range cases {
		got := run(t, prog, c.frame) != 0
		if got != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.want)
		}
	}
}

func TestMultipleRulesAndProtoOnly(t *testing.T) {
	prog, err := Assemble([]Rule{{EtherType: 0x88cc}, {EtherType: etherTypeIPv6, IPProto: 58}, {EtherType: etherTypeIPv4, IPProto: 17, Port: 67}})
	if err != nil {
		t.Fatal(err)
	}
	icmp6 := make([]byte, 40)
	icmp6[6] = 58
	cases := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{"lldp", ethFrame(0x88cc, nil), true},
		{"icmpv6", ethFrame(etherTypeIPv6, icmp6), true},
		{"ipv6 udp", ipv6UDP(1, 67), false},
		{"dhcp v4", ipv4UDP(68, 67, 0), true},
		{"other v4 udp", ipv4UDP(68, 69, 0), false},
	}
	for _, c := range cases {
		got := run(t, prog, c.frame) != 0
		if got != c.want {
			t.Errorf("%s: accepted=%v want %v", c.name, got, c.want)
		}
	}
}

func TestInvalidRules(t *testing.T) {
	if _, err := Assemble([]Rule{{}}); err == nil {
		t.Fatal("empty rule accepted")
	}
	if _, err := Assemble([]Rule{{EtherType: 0x88cc, Port: 5}}); err == nil {
		t.Fatal("transport rule with non-IP ethertype accepted")
	}
}
