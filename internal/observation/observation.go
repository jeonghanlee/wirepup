// Package observation defines the evidence record and confidence levels
// that every typed observation carries (ADR-0008). Observation types
// themselves live next to the parsers that produce them.
package observation

import "time"

// Confidence states how sure a parser is that the bytes are what the
// observation claims. It says nothing about the device.
type Confidence string

// Confidence levels from ADR-0008.
const (
	Confirmed  Confidence = "confirmed"
	StrongHint Confidence = "strong_hint"
	WeakHint   Confidence = "weak_hint"
)

// Kind is the stable public name of an observation type, for example
// "arp" or "ca.search". Kind strings are part of the JSON contract.
type Kind string

// Evidence is the capture context every observation embeds. PacketID is
// the 1-based frame number within one source and equals the Wireshark
// frame number of the same capture file.
type Evidence struct {
	Timestamp  time.Time
	Source     string
	Interface  string
	PacketID   uint64
	Protocol   string
	Confidence Confidence
}

// Ref returns the evidence itself, so that every struct embedding
// Evidence satisfies Observation without declaring the method.
func (e Evidence) Ref() Evidence { return e }

// Observation is any typed observation emitted by the decode pipeline.
type Observation interface {
	Kind() Kind
	Ref() Evidence
}
