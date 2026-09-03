package ca

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

var (
	client = netip.MustParseAddr("10.20.4.88")
	bcast  = netip.MustParseAddr("10.20.4.255")
	server = netip.MustParseAddr("10.20.4.31")
)

func TestSearchRequestDatagram(t *testing.T) {
	b := SearchDatagram(7, "MPS:SYS:STATE", false)
	msgs, err := Parse(b, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 2 || msgs[0].Command != CmdVersion || msgs[1].Command != CmdSearch {
		t.Fatalf("messages %+v", msgs)
	}
	if msgs[1].PayloadSize != 16 || msgs[1].CID != 7 || msgs[1].Available != 7 || msgs[1].DataType != DontReply || msgs[1].Count != MinorRevision {
		t.Fatalf("search header %+v", msgs[1].Header)
	}
	o := Interpret(msgs[1], "udp", client, bcast, 40000, DefaultServerPort, DefaultServerPort)
	if o.Kind() != "ca.search" || o.PVName != "MPS:SYS:STATE" || o.SearchID != 7 || o.ReplyWanted || o.Direction != ToServer || o.MinorVersion != 13 {
		t.Fatalf("observation %+v", o)
	}
	v := Interpret(msgs[0], "udp", client, bcast, 40000, DefaultServerPort, DefaultServerPort)
	if v.Kind() != "ca.version" || v.MinorVersion != 13 || v.Direction != ToServer {
		t.Fatalf("version %+v", v)
	}
	if !Probable(b) {
		t.Fatal("search datagram not probable")
	}
}

func TestSearchReply(t *testing.T) {
	b := SearchReplyDatagram(7, 5066)
	msgs, err := Parse(b, true)
	if err != nil || len(msgs) != 1 {
		t.Fatalf("%v %d", err, len(msgs))
	}
	o := Interpret(msgs[0], "udp", server, client, DefaultServerPort, 40000, DefaultServerPort)
	if o.Kind() != "ca.search_response" || o.Direction != FromServer || o.SearchID != 7 || o.ServerPort != 5066 || o.ServerIP != server || o.MinorVersion != 13 {
		t.Fatalf("reply %+v", o)
	}
	// Older servers put their address in cid instead of "any sender".
	binary.BigEndian.PutUint32(b[8:], 0x0a14041f)
	msgs, _ = Parse(b, true)
	o = Interpret(msgs[0], "udp", server, client, DefaultServerPort, 40000, DefaultServerPort)
	if o.ServerIP.String() != "10.20.4.31" {
		t.Fatalf("server ip from cid %s", o.ServerIP)
	}
	// TCP-style reply with no payload.
	short := SearchReplyDatagram(9, 5064)[:HeaderLen]
	binary.BigEndian.PutUint16(short[2:], 0)
	msgs, err = Parse(short, true)
	if err != nil || Interpret(msgs[0], "udp", server, client, 5064, 40000, 5064).Kind() != "ca.search_response" {
		t.Fatalf("no-payload reply %v", err)
	}
}

func TestBeacon(t *testing.T) {
	b := BeaconDatagram(5064, 42, server)
	msgs, err := Parse(b, true)
	if err != nil {
		t.Fatal(err)
	}
	o := Interpret(msgs[0], "udp", server, bcast, 5064, DefaultRepeaterPort, DefaultServerPort)
	if o.Kind() != "ca.beacon" || o.BeaconID != 42 || o.ServerPort != 5064 || o.ServerIP != server || o.MinorVersion != 13 {
		t.Fatalf("beacon %+v", o)
	}
	anon := BeaconDatagram(5064, 43, netip.Addr{})
	msgs, _ = Parse(anon, true)
	if Interpret(msgs[0], "udp", server, bcast, 5064, 5065, 5064).ServerIP != server {
		t.Fatal("beacon without address must resolve to the sender")
	}
	if !Probable(b) {
		t.Fatal("beacon not probable")
	}
}

func TestTCPMessages(t *testing.T) {
	name := append([]byte("MPS:SYS:STATE"), 0, 0, 0)
	req := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(req[0:], CmdCreateChan)
	binary.BigEndian.PutUint16(req[2:], uint16(len(name)))
	binary.BigEndian.PutUint32(req[8:], 5)
	binary.BigEndian.PutUint32(req[12:], MinorRevision)
	req = append(req, name...)
	host := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(host[0:], CmdHostName)
	binary.BigEndian.PutUint16(host[2:], 8)
	host = append(host, []byte("lab-pc\x00\x00")...)
	stream := append(host, req...)
	msgs, err := Parse(stream, false)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("%v %d", err, len(msgs))
	}
	h := Interpret(msgs[0], "tcp", client, server, 40001, 5064, 5064)
	if h.Kind() != "ca.host_name" || h.Text != "lab-pc" {
		t.Fatalf("host name %+v", h)
	}
	c := Interpret(msgs[1], "tcp", client, server, 40001, 5064, 5064)
	if c.Kind() != "ca.create_channel" || c.PVName != "MPS:SYS:STATE" || c.CID != 5 || c.MinorVersion != 13 {
		t.Fatalf("create %+v", c)
	}
	resp := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(resp[0:], CmdCreateChan)
	binary.BigEndian.PutUint16(resp[4:], 6) // DBR_DOUBLE
	binary.BigEndian.PutUint16(resp[6:], 1)
	binary.BigEndian.PutUint32(resp[8:], 5)
	binary.BigEndian.PutUint32(resp[12:], 99)
	msgs, _ = Parse(resp, false)
	r := Interpret(msgs[0], "tcp", server, client, 5064, 40001, 5064)
	if r.Kind() != "ca.create_channel_response" || r.SID != 99 || r.DataType != 6 || r.Count != 1 {
		t.Fatalf("create response %+v", r)
	}
	if _, err := Parse(stream, true); err != ErrNotCA {
		t.Fatalf("tcp commands accepted as udp: %v", err)
	}
}

func TestExtendedHeaderAndErrors(t *testing.T) {
	ext := make([]byte, ExtendedHeaderLen+8)
	binary.BigEndian.PutUint16(ext[0:], CmdEventAdd)
	binary.BigEndian.PutUint16(ext[2:], extendedMarker)
	binary.BigEndian.PutUint32(ext[16:], 8)
	binary.BigEndian.PutUint32(ext[20:], 100000)
	msgs, err := Parse(ext, false)
	if err != nil || msgs[0].HeaderLen != ExtendedHeaderLen || msgs[0].PayloadSize != 8 || msgs[0].Count != 100000 {
		t.Fatalf("extended %v %+v", err, msgs)
	}
	if _, err := Parse(ext[:20], false); err != ErrTruncated {
		t.Fatalf("truncated extended %v", err)
	}
	bad := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(bad[0:], 200)
	if _, err := Parse(bad, true); err != ErrCommand {
		t.Fatalf("command %v", err)
	}
	over := make([]byte, HeaderLen)
	binary.BigEndian.PutUint16(over[0:], CmdSearch)
	binary.BigEndian.PutUint16(over[2:], 64)
	if _, err := Parse(over, true); err != ErrPayload {
		t.Fatalf("overrun %v", err)
	}
	if _, err := Parse(nil, true); err != ErrTruncated {
		t.Fatalf("empty %v", err)
	}
	if Probable([]byte("hello world, not ca")) {
		t.Fatal("garbage probable")
	}
	full := SearchDatagram(1, "X", true)
	for n := 0; n <= len(full); n++ {
		Parse(full[:n], true)
	}
	if m, err := Parse(SearchDatagram(1, "\x01bad", true), true); err == nil && Interpret(m[1], "udp", client, bcast, 1, 5064, 5064).PVName != "" {
		t.Fatal("non-printable name accepted")
	}
}
