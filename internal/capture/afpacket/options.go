// Package afpacket implements live capture on Linux with an AF_PACKET
// SOCK_RAW socket (ADR-0002). The socket is receive-only: this package
// contains no send path. Frames stripped of their 802.1Q tag by the
// kernel are restored from PACKET_AUXDATA so decoders see the frame as
// it appeared on the wire; timestamps come from SO_TIMESTAMPNS and drop
// counts from PACKET_STATISTICS.
package afpacket

import (
	"errors"

	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
)

// ErrPrivilege marks a socket failure caused by a missing CAP_NET_RAW so
// that the CLI can map it to the insufficient-privilege exit code.
var ErrPrivilege = errors.New("raw packet capture requires CAP_NET_RAW")

// Options configure a live source.
type Options struct {
	Interface   string
	Promiscuous bool
	SnapLen     int
	// Filter is a classic BPF program; nil accepts every frame.
	Filter []bpf.Instruction
}
