package active

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/pva"
)

// PVASearchResult is the outcome of one explicit PVA search.
type PVASearchResult struct {
	Plan      Plan
	Sent      []netip.AddrPort
	Responses []PVAAnswer
	NotFound  []PVAAnswer
}

// PVAAnswer is one server reply.
type PVAAnswer struct {
	From       netip.AddrPort
	GUID       string
	ServerAddr netip.Addr
	ServerPort uint16
	At         time.Time
}

// PVASearch sends one PVA search datagram for pv to each destination
// and collects answers for the wait period.
func PVASearch(ctx context.Context, pv string, dests []netip.AddrPort, seq, instance int32, wait time.Duration) (PVASearchResult, error) {
	if len(dests) == 0 {
		return PVASearchResult{}, ErrNoDestinations
	}
	if wait <= 0 {
		wait = CADefaultWait
	}
	res := PVASearchResult{Plan: Plan{Protocol: "PVA search", Count: len(dests), Rate: RatePerSecond}}
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
	for i, d := range dests {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		unicast := !d.Addr().IsMulticast() && d.Addr().As4()[3] != 0xff
		if _, err := conn.WriteToUDPAddrPort(pva.SearchDatagram(seq, instance, pv, true, unicast), d); err != nil {
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
		msgs, err := pva.Parse(buf[:n])
		if err != nil {
			continue
		}
		for _, m := range msgs {
			o := pva.Interpret(m, "udp", from.Addr().Unmap(), netip.Addr{}, from.Port(), 0)
			if o.Kind() != "pva.search_response" || o.SequenceID != seq {
				continue
			}
			mine := false
			for _, id := range o.InstanceIDs {
				if id == instance {
					mine = true
				}
			}
			if !mine {
				continue
			}
			ans := PVAAnswer{From: from, GUID: o.GUID, ServerAddr: o.ServerAddr, ServerPort: o.ServerPort, At: time.Now()}
			if o.Found {
				res.Responses = append(res.Responses, ans)
			} else {
				res.NotFound = append(res.NotFound, ans)
			}
		}
	}
	return res, nil
}
