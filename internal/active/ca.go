package active

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
)

// CA search budget: one datagram per destination, no retry.
const (
	caRecvBuffer   = 4096
	CADefaultWait  = 2 * time.Second
	caReadInterval = 200 * time.Millisecond
)

// ErrNoDestinations rejects a search without an explicit target list.
var ErrNoDestinations = errors.New("active: CA search needs explicit destinations")

// CASearchResult is the outcome of one explicit CA search.
type CASearchResult struct {
	Plan      Plan
	SearchID  uint32
	Sent      []netip.AddrPort
	Responses []CAAnswer
	NotFound  []CAAnswer
}

// CAAnswer is one server reply.
type CAAnswer struct {
	From     netip.AddrPort
	ServerIP netip.Addr
	TCPPort  uint16
	At       time.Time
}

// CASearch sends one CA search datagram for pv to each destination and
// collects answers for the wait period. Destinations are explicit;
// the caller prints them before this runs (ADR-0007 amendment).
func CASearch(ctx context.Context, pv string, dests []netip.AddrPort, id uint32, replyWanted bool, wait time.Duration) (CASearchResult, error) {
	if len(dests) == 0 {
		return CASearchResult{}, ErrNoDestinations
	}
	if wait <= 0 {
		wait = CADefaultWait
	}
	res := CASearchResult{SearchID: id, Plan: Plan{Protocol: "CA search", Count: len(dests), Rate: RatePerSecond}}
	for _, d := range dests {
		res.Plan.Targets = append(res.Plan.Targets, d.Addr())
	}
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		return res, fmt.Errorf("active: udp socket: %w", err)
	}
	defer conn.Close()
	if err := setBroadcast(conn); err != nil {
		return res, err
	}
	datagram := ca.SearchDatagram(id, pv, replyWanted)
	for i, d := range dests {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if _, err := conn.WriteToUDPAddrPort(datagram, d); err != nil {
			return res, fmt.Errorf("active: send to %s: %w", d, err)
		}
		res.Sent = append(res.Sent, d)
		if i+1 < len(dests) {
			time.Sleep(SendInterval)
		}
	}
	buf := make([]byte, caRecvBuffer)
	until := time.Now().Add(wait)
	for time.Now().Before(until) && ctx.Err() == nil {
		conn.SetReadDeadline(time.Now().Add(caReadInterval))
		n, from, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return res, fmt.Errorf("active: recv: %w", err)
		}
		msgs, err := ca.Parse(buf[:n], true)
		if err != nil {
			continue
		}
		for _, m := range msgs {
			o := ca.Interpret(m, "udp", from.Addr().Unmap(), netip.Addr{}, from.Port(), 0, ca.DefaultServerPort)
			if o.SearchID != id {
				continue
			}
			ans := CAAnswer{From: from, ServerIP: o.ServerIP, TCPPort: o.ServerPort, At: time.Now()}
			switch o.Kind() {
			case "ca.search_response":
				res.Responses = append(res.Responses, ans)
			case "ca.not_found":
				res.NotFound = append(res.NotFound, ans)
			}
		}
	}
	return res, nil
}

// BroadcastDestinations derives the directed broadcast address of each
// IPv4 prefix, the same targets a CA client derives by default.
func BroadcastDestinations(prefixes []netip.Prefix, port uint16) []netip.AddrPort {
	var out []netip.AddrPort
	for _, p := range prefixes {
		if !p.Addr().Is4() || p.Bits() > 30 {
			continue
		}
		a := p.Masked().Addr().As4()
		host := uint32(0xffffffff) >> p.Bits()
		v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | host
		out = append(out, netip.AddrPortFrom(netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), port))
	}
	return out
}
