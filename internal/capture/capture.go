// Package capture defines the packet source abstraction shared by live
// capture and file replay (ADR-0002). Sources yield timestamped packets
// with their link type and capture context; nothing here decodes bytes.
package capture

import (
	"context"
	"time"
)

// LinkType is the data link type of a packet, using the PCAP DLT registry
// values so that file sources and live sources agree.
type LinkType uint32

// Link types WirePup recognizes.
const (
	LinkTypeNull     LinkType = 0
	LinkTypeEthernet LinkType = 1
	LinkTypeRaw      LinkType = 101
	LinkTypeLinuxSLL LinkType = 113
)

// DefaultSnapLen is the capture length a source uses when asked for zero:
// large enough to keep the whole frame on any common link. Both the file
// writer and the live socket default to it. It is not the BPF accept
// length (`bpf.AcceptLength`), which only needs to be no smaller.
const DefaultSnapLen = 262144

// Packet is one captured frame together with the context needed for
// evidence: when it was seen, on which interface, and how much of it
// the source kept.
type Packet struct {
	Timestamp      time.Time
	Interface      string
	LinkType       LinkType
	Data           []byte
	CaptureLength  int
	OriginalLength int
}

// Stats reports receive and drop counts for a source.
type Stats struct {
	Received uint64
	Dropped  uint64
}

// Source yields packets until the context is cancelled or the source is
// exhausted. Implementations close the packet channel when finished and
// deliver at most one error on the error channel before closing it.
type Source interface {
	// Name identifies the source in evidence: the interface name for
	// live capture, the file path for replay.
	Name() string
	Packets(ctx context.Context) (<-chan Packet, <-chan error)
	Stats() Stats
	Close() error
}
