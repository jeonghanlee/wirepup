package udp

import "testing"

func TestParse(t *testing.T) {
	d, err := Parse([]byte{0x13, 0xc8, 0x00, 0x43, 0x00, 0x0a, 0x00, 0x00, 0xaa, 0xbb, 0xcc})
	if err != nil {
		t.Fatal(err)
	}
	if d.SrcPort != 5064 || d.DstPort != 67 || d.Length != 10 || len(d.Payload) != 2 || d.Truncated {
		t.Fatalf("datagram %+v", d)
	}
	d, _ = Parse([]byte{0x13, 0xc8, 0x00, 0x43, 0x00, 0x20, 0x00, 0x00, 0xaa})
	if !d.Truncated || len(d.Payload) != 1 {
		t.Fatalf("truncated %+v", d)
	}
	if _, err := Parse([]byte{1, 2, 3}); err != ErrTruncated {
		t.Fatalf("short: %v", err)
	}
}
