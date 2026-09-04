package active

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
)

// TestCASearchAgainstLoopbackServer runs the real search path against a
// UDP responder on loopback that answers like rsrv does.
func TestCASearchAgainstLoopbackServer(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("loopback udp not available:", err)
	}
	defer srv.Close()
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			msgs, err := ca.Parse(buf[:n], true)
			if err != nil {
				continue
			}
			for _, m := range msgs {
				if m.Command != ca.CmdSearch {
					continue
				}
				o := ca.Interpret(m, "udp", netip.Addr{}, netip.Addr{}, 0, 0, 0)
				if o.PVName == "LAB:EXISTS" {
					srv.WriteToUDPAddrPort(ca.SearchReplyDatagram(o.SearchID, 5066), from)
				} else if o.ReplyWanted {
					nf := make([]byte, ca.HeaderLen)
					nf[1] = ca.CmdNotFound
					nf[12], nf[13], nf[14], nf[15] = byte(o.SearchID>>24), byte(o.SearchID>>16), byte(o.SearchID>>8), byte(o.SearchID)
					srv.WriteToUDPAddrPort(nf, from)
				}
			}
		}
	}()
	dest := netip.MustParseAddrPort(srv.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	res, err := CASearch(ctx, "LAB:EXISTS", []Destination{{AddrPort: dest}}, 11, false, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sent) != 1 || len(res.Responses) != 1 || res.Responses[0].TCPPort != 5066 || res.Responses[0].ServerIP.String() != "127.0.0.1" {
		t.Fatalf("result %+v", res)
	}
	res, err = CASearch(ctx, "LAB:MISSING", []Destination{{AddrPort: dest}}, 12, true, 500*time.Millisecond)
	if err != nil || len(res.Responses) != 0 || len(res.NotFound) != 1 {
		t.Fatalf("not found: %v %+v", err, res)
	}
	if _, err := CASearch(ctx, "X", nil, 1, false, 0); err != ErrNoDestinations {
		t.Fatalf("no destinations: %v", err)
	}
}

func TestBroadcastDestinations(t *testing.T) {
	out := BroadcastDestinations([]netip.Prefix{netip.MustParsePrefix("10.20.4.88/24"), netip.MustParsePrefix("192.168.0.7/22"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("10.0.0.1/32")}, 5064)
	if len(out) != 2 || out[0].AddrPort.String() != "10.20.4.255:5064" || out[1].AddrPort.String() != "192.168.3.255:5064" || !out[0].Broadcast || !out[1].Broadcast {
		t.Fatalf("destinations %v", out)
	}
}

func TestIsBroadcast(t *testing.T) {
	prefixes := []netip.Prefix{netip.MustParsePrefix("10.20.4.88/25"), netip.MustParsePrefix("10.30.0.7/23")}
	cases := map[string]bool{
		"10.20.4.127":     true,  // directed broadcast of the /25
		"10.20.4.255":     false, // outside the /25
		"10.30.0.255":     false, // a host inside the /23
		"10.30.1.255":     true,  // directed broadcast of the /23
		"255.255.255.255": true,
		"224.0.0.128":     true,
		"192.168.9.255":   false, // broadcast of a prefix that is not local
	}
	for s, want := range cases {
		if got := IsBroadcast(netip.MustParseAddr(s), prefixes); got != want {
			t.Errorf("%s: broadcast=%v want %v", s, got, want)
		}
	}
	if IsBroadcast(netip.MustParseAddr("10.20.4.127"), nil) {
		t.Error("directed broadcast counted without a prefix table")
	}
	if !IsBroadcast(netip.MustParseAddr("255.255.255.255"), nil) {
		t.Error("limited broadcast not counted without a prefix table")
	}
}
