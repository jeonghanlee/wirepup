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
	res, err := CASearch(ctx, "LAB:EXISTS", []netip.AddrPort{dest}, 11, false, 500*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sent) != 1 || len(res.Responses) != 1 || res.Responses[0].TCPPort != 5066 || res.Responses[0].ServerIP.String() != "127.0.0.1" {
		t.Fatalf("result %+v", res)
	}
	res, err = CASearch(ctx, "LAB:MISSING", []netip.AddrPort{dest}, 12, true, 500*time.Millisecond)
	if err != nil || len(res.Responses) != 0 || len(res.NotFound) != 1 {
		t.Fatalf("not found: %v %+v", err, res)
	}
	if _, err := CASearch(ctx, "X", nil, 1, false, 0); err != ErrNoDestinations {
		t.Fatalf("no destinations: %v", err)
	}
}

func TestBroadcastDestinations(t *testing.T) {
	out := BroadcastDestinations([]netip.Prefix{netip.MustParsePrefix("10.20.4.88/24"), netip.MustParsePrefix("192.168.0.7/22"), netip.MustParsePrefix("fe80::1/64"), netip.MustParsePrefix("10.0.0.1/32")}, 5064)
	if len(out) != 2 || out[0].String() != "10.20.4.255:5064" || out[1].String() != "192.168.3.255:5064" {
		t.Fatalf("destinations %v", out)
	}
}
