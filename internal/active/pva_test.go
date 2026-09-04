package active

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/pva"
)

func TestPVASearchAgainstLoopbackServer(t *testing.T) {
	srv, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skip("loopback udp not available:", err)
	}
	defer srv.Close()
	guid := [12]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	// flags records the "sent as unicast" flag of each received search.
	flags := make(chan bool, 8)
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := srv.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			msgs, err := pva.Parse(buf[:n])
			if err != nil {
				continue
			}
			for _, m := range msgs {
				o := pva.Interpret(m, "udp", netip.Addr{}, netip.Addr{}, 0, 0)
				if o.Kind() != "pva.search" {
					continue
				}
				select {
				case flags <- o.Unicast:
				default:
				}
				for _, ch := range o.Channels {
					found := ch.Name == "LAB:EXISTS"
					if found || o.ReplyRequired {
						srv.WriteToUDPAddrPort(pva.SearchResponseDatagram(guid, o.SequenceID, netip.Addr{}, 5075, found, []int32{ch.ID}), from)
					}
				}
			}
		}
	}()
	dest := netip.MustParseAddrPort(srv.LocalAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	nextFlag := func() bool {
		select {
		case u := <-flags:
			return u
		case <-time.After(2 * time.Second):
			t.Fatal("no search received")
			return false
		}
	}
	res, err := PVASearch(ctx, "LAB:EXISTS", []Destination{{AddrPort: dest}}, 4, 21, 500*time.Millisecond)
	if err != nil || len(res.Responses) != 1 || res.Responses[0].ServerPort != 5075 || res.Responses[0].GUID != "090909090909090909090909" || res.Responses[0].ServerAddr.String() != "127.0.0.1" {
		t.Fatalf("result %v %+v", err, res)
	}
	if !nextFlag() {
		t.Fatal("search to a unicast destination not flagged as sent as unicast")
	}
	res, err = PVASearch(ctx, "LAB:MISSING", []Destination{{AddrPort: dest}}, 5, 22, 500*time.Millisecond)
	if err != nil || len(res.Responses) != 0 || len(res.NotFound) != 1 {
		t.Fatalf("not found %v %+v", err, res)
	}
	nextFlag()
	// A destination the caller classified as broadcast clears the flag.
	if _, err := PVASearch(ctx, "LAB:EXISTS", []Destination{{AddrPort: dest, Broadcast: true}}, 6, 23, 500*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if nextFlag() {
		t.Fatal("search to a broadcast destination flagged as sent as unicast")
	}
}
