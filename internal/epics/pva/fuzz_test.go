package pva

import (
	"net/netip"
	"testing"
)

// FuzzParse feeds arbitrary bytes to the parser; the only failure mode
// checked is a panic, which no network input may cause.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		if msgs, err := Parse(b); err == nil || len(msgs) > 0 {
			for _, m := range msgs {
				Interpret(m, "udp", netip.Addr{}, netip.Addr{}, 0, 0).Kind()
			}
		}
		Probable(b)
	})
}
