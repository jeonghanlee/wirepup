package tcp

import "testing"

func TestParse(t *testing.T) {
	b := []byte{0x13, 0xc8, 0x9c, 0x40, 0, 0, 0, 1, 0, 0, 0, 2, 0x60, 0x12, 0xff, 0xff, 0, 0, 0, 0, 1, 2, 3, 4, 0xaa}
	s, err := Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	if s.SrcPort != 5064 || s.DstPort != 40000 || s.Seq != 1 || s.Ack != 2 || s.HeaderLen != 24 || s.Flags != FlagSYN|FlagACK || len(s.Payload) != 1 {
		t.Fatalf("segment %+v", s)
	}
	if FlagNames(s.Flags) != "SYN,ACK" || FlagNames(0) != "-" || !IsStateEvent(FlagRST) || IsStateEvent(FlagACK) {
		t.Fatal("flags")
	}
	if _, err := Parse(b[:10]); err != ErrTruncated {
		t.Fatalf("short %v", err)
	}
	b[12] = 0x40
	if _, err := Parse(b); err != ErrOffset {
		t.Fatalf("offset %v", err)
	}
	b[12] = 0xf0
	if _, err := Parse(b); err != ErrTruncated {
		t.Fatalf("offset beyond %v", err)
	}
}
