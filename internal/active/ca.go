package active

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/observation"
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
func CASearch(ctx context.Context, pv string, dests []Destination, id uint32, replyWanted bool, wait time.Duration) (CASearchResult, error) {
	if len(dests) == 0 {
		return CASearchResult{}, ErrNoDestinations
	}
	if wait <= 0 {
		wait = CADefaultWait
	}
	res := CASearchResult{SearchID: id, Plan: Plan{Protocol: "CA search", Count: len(dests), Rate: RatePerSecond}}
	for _, d := range dests {
		res.Plan.Targets = append(res.Plan.Targets, d.AddrPort.Addr())
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
		if _, err := conn.WriteToUDPAddrPort(datagram, d.AddrPort); err != nil {
			return res, fmt.Errorf("active: send to %s: %w", d.AddrPort, err)
		}
		res.Sent = append(res.Sent, d.AddrPort)
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
			o := ca.Interpret(m, observation.TransportUDP, from.Addr().Unmap(), netip.Addr{}, from.Port(), 0, ca.DefaultServerPort)
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

// limitedBroadcast is the all-ones IPv4 broadcast address.
var limitedBroadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

// Destination is one search target and the way the datagram reaches
// it. Broadcast is true for the limited broadcast, a multicast group,
// and the directed broadcast of one of the sender's own prefixes. PVA
// states it in the search flags (Protocol-Messages.md, searchRequest
// flags bit 7: "sent as unicast" (1) / "sent as broadcast/multicast"
// (0)); a server may forward a unicast-flagged search over loopback
// multicast (CMD_ORIGIN_TAG), so the flag must say how the datagram
// was actually sent. The decision is made where the destination list
// is built, from the sender's own prefix table.
type Destination struct {
	AddrPort  netip.AddrPort
	Broadcast bool
}

// IsBroadcast reports whether a datagram to addr is sent as broadcast
// or multicast rather than unicast, judged from the sender's own IPv4
// prefixes; without a prefix table only the limited broadcast and
// multicast qualify.
func IsBroadcast(addr netip.Addr, prefixes []netip.Prefix) bool {
	if addr == limitedBroadcast || addr.IsMulticast() {
		return true
	}
	for _, p := range prefixes {
		if b, ok := directedBroadcast(p); ok && b == addr {
			return true
		}
	}
	return false
}

// directedBroadcast is the broadcast address of an IPv4 prefix; ok is
// false for IPv6 and for a prefix too small to have one.
func directedBroadcast(p netip.Prefix) (netip.Addr, bool) {
	if !p.Addr().Is4() || p.Bits() > 30 {
		return netip.Addr{}, false
	}
	a := p.Masked().Addr().As4()
	host := uint32(0xffffffff) >> p.Bits()
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
}

// BroadcastDestinations derives the directed broadcast address of each
// IPv4 prefix, the same targets a CA client derives by default.
func BroadcastDestinations(prefixes []netip.Prefix, port uint16) []Destination {
	var out []Destination
	for _, p := range prefixes {
		if b, ok := directedBroadcast(p); ok {
			out = append(out, Destination{AddrPort: netip.AddrPortFrom(b, port), Broadcast: true})
		}
	}
	return out
}
