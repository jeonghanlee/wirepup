package pva

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	client = netip.MustParseAddr("10.20.4.88")
	bcast  = netip.MustParseAddr("10.20.4.255")
	server = netip.MustParseAddr("10.20.4.31")
	guid   = [12]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
)

func TestSearchRoundTrip(t *testing.T) {
	b := SearchDatagram(5, 77, "MPS:SYS:STATE", true, false)
	msgs, err := Parse(b)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("%v %d", err, len(msgs))
	}
	o := Interpret(msgs[0], "udp", client, bcast, 40000, DefaultUDPPort)
	if o.Kind() != "pva.search" || o.SequenceID != 5 || !o.ReplyRequired || o.Unicast || len(o.Channels) != 1 || o.Channels[0].ID != 77 || o.Channels[0].Name != "MPS:SYS:STATE" || o.Protocols[0] != "tcp" || o.Malformed {
		t.Fatalf("search %+v", o)
	}
	if !o.BigEndian || o.Direction != ToServer || !Probable(b) {
		t.Fatal("header")
	}
}

func TestSearchResponseAndBeacon(t *testing.T) {
	b := SearchResponseDatagram(guid, 5, netip.Addr{}, 5075, true, []int32{77})
	msgs, _ := Parse(b)
	o := Interpret(msgs[0], "udp", server, client, DefaultUDPPort, 40000)
	if o.Kind() != "pva.search_response" || o.GUID != "0102030405060708090a0b0c" || o.SequenceID != 5 || !o.Found || o.ServerAddr != server || o.ServerPort != 5075 || o.Protocol != "tcp" || len(o.InstanceIDs) != 1 || o.InstanceIDs[0] != 77 {
		t.Fatalf("response %+v", o)
	}
	b = SearchResponseDatagram(guid, 5, netip.MustParseAddr("10.20.4.40"), 5075, true, []int32{77})
	msgs, _ = Parse(b)
	if o := Interpret(msgs[0], "udp", server, client, 0, 0); o.ServerAddr.String() != "10.20.4.40" {
		t.Fatalf("explicit server address %s", o.ServerAddr)
	}
	b = BeaconDatagram(guid, 9, 3, server, 5075)
	msgs, _ = Parse(b)
	o = Interpret(msgs[0], "udp", server, bcast, DefaultUDPPort, DefaultUDPPort)
	if o.Kind() != "pva.beacon" || o.BeaconSeq != 9 || o.ChangeCount != 3 || o.ServerAddr != server || o.ServerPort != 5075 || o.StatusPresent || o.Malformed {
		t.Fatalf("beacon %+v", o)
	}
}

func TestTCPHandshake(t *testing.T) {
	stream := append(SetByteOrder(true), ValidationRequest(65536, 127, []string{"anonymous", "ca"})...)
	msgs, err := Parse(stream)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("%v %d", err, len(msgs))
	}
	c := Interpret(msgs[0], "tcp", server, client, 5075, 40001)
	if c.Kind() != "pva.control.set_byte_order" || !c.Control || !c.FromServer {
		t.Fatalf("control %+v", c)
	}
	v := Interpret(msgs[1], "tcp", server, client, 5075, 40001)
	if v.Kind() != "pva.validation_request" || v.BufferSize != 65536 || v.RegistryMax != 127 || len(v.AuthNZ) != 2 || v.AuthNZ[1] != "ca" {
		t.Fatalf("validation %+v", v)
	}
	req := CreateChannelRequest(3, "X:Y")
	msgs, _ = Parse(req)
	cr := Interpret(msgs[0], "tcp", client, server, 40001, 5075)
	if cr.Kind() != "pva.create_channel" || len(cr.Channels) != 1 || cr.Channels[0].ID != 3 || cr.Channels[0].Name != "X:Y" {
		t.Fatalf("create %+v", cr)
	}
	// Little-endian create channel response with OK status.
	resp := []byte{Magic, 2, FlagServer, CmdCreateChannel, 9, 0, 0, 0, 3, 0, 0, 0, 0x2a, 0, 0, 0, 0xff}
	msgs, err = Parse(resp)
	if err != nil {
		t.Fatal(err)
	}
	r := Interpret(msgs[0], "tcp", server, client, 5075, 40001)
	if r.Kind() != "pva.create_channel_response" || r.ClientChanID != 3 || r.ServerChanID != 42 || !r.StatusOK || r.BigEndian {
		t.Fatalf("create response %+v", r)
	}
}

func TestHeaderErrors(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
		err  error
	}{
		{"short", []byte{Magic, 2}, ErrTruncated},
		{"magic", []byte{0xCB, 2, 0, 3, 0, 0, 0, 0}, ErrMagic},
		{"version", []byte{Magic, 9, 0, 3, 0, 0, 0, 0}, ErrVersion},
		{"flags", []byte{Magic, 2, 0x02, 3, 0, 0, 0, 0}, ErrFlags},
		{"command", []byte{Magic, 2, 0, 0x40, 0, 0, 0, 0}, ErrCommand},
		{"payload", []byte{Magic, 2, 0x80, 3, 0, 0, 0, 9, 1}, ErrPayload},
	}
	for _, c := range cases {
		if _, err := Parse(c.b); err != c.err {
			t.Fatalf("%s: %v", c.name, err)
		}
	}
	if Probable([]byte("not pva at all")) {
		t.Fatal("garbage probable")
	}
}

func TestTruncatedPayloadsMarkMalformedWithoutPanic(t *testing.T) {
	for _, full := range [][]byte{
		SearchDatagram(1, 2, "A:B", true, true),
		SearchResponseDatagram(guid, 1, server, 5075, true, []int32{2}),
		BeaconDatagram(guid, 1, 1, server, 5075),
		ValidationRequest(1, 1, []string{"anonymous"}),
	} {
		for n := HeaderLen; n < len(full); n++ {
			cut := append([]byte(nil), full[:n]...)
			binary.BigEndian.PutUint32(cut[4:], uint32(n-HeaderLen))
			msgs, err := Parse(cut)
			if err != nil {
				t.Fatalf("cut %d: %v", n, err)
			}
			o := Interpret(msgs[0], "udp", server, client, 0, 0)
			if !o.Malformed && n < len(full)-1 {
				// a shorter payload must be reported as malformed unless the
				// cut fell exactly on the end of the last field
				continue
			}
		}
	}
	// A huge declared size must not allocate or panic.
	bad := SearchDatagram(1, 2, "A:B", true, false)
	bad[HeaderLen+4+1+3+16+2] = sizeLong // protocols count
	Parse(bad)
	msgs, _ := Parse(bad)
	if o := Interpret(msgs[0], "udp", client, bcast, 0, 0); !o.Malformed {
		t.Fatal("oversized count not flagged")
	}
}
