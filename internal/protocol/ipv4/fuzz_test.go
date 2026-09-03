package ipv4

import "testing"

// FuzzParse feeds arbitrary bytes to the parser; the only failure mode
// checked is a panic, which no network input may cause.
func FuzzParse(f *testing.F) {
	f.Add([]byte{})
	f.Add(make([]byte, 64))
	f.Fuzz(func(t *testing.T, b []byte) {
		Parse(b)
	})
}
