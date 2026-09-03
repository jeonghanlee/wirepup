package decode

import (
	"testing"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

// FuzzDecode runs the whole pipeline over arbitrary frames; observations
// are additionally rendered through their Kind and Ref accessors.
func FuzzDecode(f *testing.F) {
	f.Add(fixtures.ARPProbe(fixtures.DeviceMAC, fixtures.MustAddr("169.254.1.1")))
	f.Add(fixtures.LLDPFrame(fixtures.SwitchMAC, fixtures.LLDP(fixtures.SwitchMAC, "1", "sw", 120, 100, fixtures.MustAddr("10.0.0.1"))))
	f.Fuzz(func(t *testing.T, b []byte) {
		d := New("fuzz")
		for _, o := range d.Decode(capture.Packet{LinkType: capture.LinkTypeEthernet, Data: b, CaptureLength: len(b), OriginalLength: len(b)}) {
			_ = o.Kind()
			_ = o.Ref()
		}
	})
}
