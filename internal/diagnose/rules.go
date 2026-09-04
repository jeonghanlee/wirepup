package diagnose

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
)

// Finding codes of the address-assignment and EPICS rules (M9).
const (
	CodeDHCPNoOffer          = "dhcp-discover-no-offer"
	CodeDHCPNak              = "dhcp-nak"
	CodeAutoIPFallback       = "auto-ip-fallback"
	CodeCASearchUnanswered   = "ca-search-no-response"
	CodeCAMultipleServers    = "ca-multiple-servers"
	CodeCAServerSeen         = "ca-server-seen"
	CodeCABeaconOnly         = "ca-beacon-without-search"
	CodeCASearchDestination  = "ca-search-destination-not-local"
	CodePVASearchUnanswered  = "pva-search-no-response"
	CodePVAMultipleServers   = "pva-multiple-servers"
	CodePVAServerSeen        = "pva-server-seen"
	CodePVAServerRestart     = "pva-server-restarted"
	CodeSourceDifference     = "discovery-differs-between-sources"
	CodeEPICSNothingObserved = "epics-nothing-observed"
)

// dhcpOfferGrace is how long after the last discover an offer may still
// arrive before the exchange counts as unanswered.
const dhcpOfferGrace = 2 * time.Second

// Options select which rule families run.
type Options struct {
	EPICSOnly bool
	// End is the end of the observation window (last packet or now);
	// rules that wait for an answer compare against it.
	End time.Time
}

// RunAll evaluates the subnet rules (unless EPICSOnly), then the
// address-assignment rules and the EPICS rules.
func RunAll(ctx Context, table *device.Table, target netip.Addr, opts Options) Report {
	var r Report
	if opts.EPICSOnly {
		r = Report{Interface: ctx.Interface, Target: target}
	} else {
		r = Run(ctx, table, target)
		r.dhcpRules(table, opts.End)
		r.autoIPRules(table, opts.End)
	}
	r.caRules(ctx, table)
	r.pvaRules(table)
	r.sourceRules(table)
	return r
}

// dhcpRules reports discovers that never got an offer and NAKs.
func (r *Report) dhcpRules(table *device.Table, end time.Time) {
	for _, x := range table.DHCPTransactions() {
		if !x.Discover.IsZero() && x.Offer.IsZero() && x.ACK.IsZero() {
			if !end.IsZero() && end.Sub(x.Discover) < dhcpOfferGrace {
				continue
			}
			r.Observed = append(r.Observed, Finding{
				Code:     CodeDHCPNoOffer,
				Text:     fmt.Sprintf("DHCP discover from %s (xid 0x%08x) with no offer observed", x.ClientMAC, x.XID),
				Evidence: []Ref{x.Ref},
				Data:     map[string]string{"mac": x.ClientMAC, "xid": fmt.Sprintf("0x%08x", x.XID)},
			})
			r.Inferred = append(r.Inferred, Finding{
				Code:     CodeDHCPNoOffer,
				Text:     fmt.Sprintf("no DHCP server answered %s on this segment during the window; a server or relay may be absent, or the answer took another path", x.ClientMAC),
				Evidence: []Ref{x.Ref},
			})
			r.Recommended = append(r.Recommended, Finding{
				Code:     CodeDHCPNoOffer,
				Text:     "check the DHCP server or relay for this VLAN; a device without DHCP usually falls back to IPv4 Link-Local (169.254/16) or stays at 0.0.0.0",
				Evidence: []Ref{x.Ref},
			})
		}
		if !x.NAK.IsZero() {
			r.Observed = append(r.Observed, Finding{
				Code:     CodeDHCPNak,
				Text:     fmt.Sprintf("DHCP NAK to %s from %s", x.ClientMAC, addrText(x.ServerIP)),
				Evidence: []Ref{x.Ref},
			})
			r.Inferred = append(r.Inferred, Finding{
				Code:     CodeDHCPNak,
				Text:     fmt.Sprintf("the server refused the lease %s requested; the device may hold a stale address from another subnet", x.ClientMAC),
				Evidence: []Ref{x.Ref},
			})
		}
	}
}

// autoIPRules links a Link-Local claim to a preceding failed DHCP
// exchange; an exchange counts as failed under the same grace period
// dhcpRules applies, so the text never asserts a failure the report
// has not found.
func (r *Report) autoIPRules(table *device.Table, end time.Time) {
	failed := map[string]bool{}
	for _, x := range table.DHCPTransactions() {
		if !x.Discover.IsZero() && x.ACK.IsZero() {
			if !end.IsZero() && end.Sub(x.Discover) < dhcpOfferGrace {
				continue
			}
			failed[x.ClientMAC] = true
		}
	}
	for _, d := range table.Devices() {
		for _, a := range d.IPv4 {
			if a.Addr.Is4() && a.Addr.IsLinkLocalUnicast() && strongClaim(a) {
				text := fmt.Sprintf("%s uses IPv4 Link-Local %s", d.ID, a.Addr)
				if failed[d.ID] {
					text += " after a DHCP discover without a lease: Auto-IP fallback"
				}
				r.Inferred = append(r.Inferred, Finding{Code: CodeAutoIPFallback, Text: text, Evidence: []Ref{a.Ref}, Data: map[string]string{"mac": d.ID, "address": a.Addr.String()}})
			}
		}
	}
}

// caRules covers the R-020 symptoms for Channel Access.
func (r *Report) caRules(ctx Context, table *device.Table) {
	searches := table.CASearches()
	servers := table.CAServers()
	if len(searches) == 0 && len(servers) == 0 {
		return
	}
	unanswered := 0
	for _, s := range searches {
		switch {
		case len(s.Responses) == 0 && len(s.NotFound) == 0:
			unanswered++
			r.Observed = append(r.Observed, Finding{
				Code:     CodeCASearchUnanswered,
				Text:     fmt.Sprintf("CA search for %s from %s:%d (x%d) with no response observed", s.PV, s.ClientIP, s.ClientPort, s.Count),
				Evidence: []Ref{s.Ref},
				Data:     map[string]string{"pv": s.PV, "client": s.ClientIP.String(), "count": fmt.Sprint(s.Count)},
			})
		case len(s.Responses) > 1:
			var who []string
			var refs []Ref
			for _, a := range s.Responses {
				who = append(who, fmt.Sprintf("%s:%d", a.ServerIP, a.TCPPort))
				refs = append(refs, a.Ref)
			}
			r.Observed = append(r.Observed, Finding{
				Code:     CodeCAMultipleServers,
				Text:     fmt.Sprintf("CA search for %s answered by %d servers: %s", s.PV, len(s.Responses), strings.Join(who, ", ")),
				Evidence: refs,
				Data:     map[string]string{"pv": s.PV, "servers": strings.Join(who, ",")},
			})
			r.Inferred = append(r.Inferred, Finding{
				Code:     CodeCAMultipleServers,
				Text:     fmt.Sprintf("more than one CA server claims %s; clients connect to whichever answers first, so the value they see may change between runs", s.PV),
				Evidence: refs,
				Data:     map[string]string{"pv": s.PV, "servers": strings.Join(who, ",")},
			})
		}
		if dst := searchDestinationFinding(ctx, s); dst != nil {
			r.Inferred = append(r.Inferred, *dst)
		}
	}
	if unanswered > 0 {
		r.Inferred = append(r.Inferred, Finding{
			Code: CodeCASearchUnanswered,
			Text: fmt.Sprintf("%d CA search(es) received no observed response; absence of a reply is not proof that the PV does not exist: the server may be on another subnet, its reply may not cross this interface, or EPICS_CA_ADDR_LIST may not reach it", unanswered),
		})
	}
	for _, srv := range servers {
		r.Observed = append(r.Observed, Finding{
			Code:     CodeCAServerSeen,
			Text:     fmt.Sprintf("CA server %s TCP port %d: %d search answer(s), %d beacon(s)", srv.Addr, srv.TCPPort, srv.Answers, srv.Beacons),
			Evidence: []Ref{srv.Ref},
			Data:     map[string]string{"server": srv.Addr.String(), "tcp_port": fmt.Sprint(srv.TCPPort)},
		})
		if srv.Beacons > 0 && srv.Answers == 0 && len(searches) > 0 {
			r.Inferred = append(r.Inferred, Finding{
				Code:     CodeCABeaconOnly,
				Text:     fmt.Sprintf("CA server %s sends beacons but answered no observed search; the searched PVs are probably not hosted there", srv.Addr),
				Evidence: []Ref{srv.Ref},
			})
		}
	}
}

// searchDestinationFinding flags a search sent to a destination outside
// every local IPv4 subnet, which is what a stale EPICS_CA_ADDR_LIST
// looks like on the wire.
func searchDestinationFinding(ctx Context, s device.CASearch) *Finding {
	if len(ctx.LocalIPv4) == 0 || !s.Destination.IsValid() || s.Destination == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return nil
	}
	if _, ok := containing(ctx.LocalIPv4, s.Destination); ok {
		return nil
	}
	return &Finding{
		Code:     CodeCASearchDestination,
		Text:     fmt.Sprintf("CA search for %s from %s was sent to %s, which is outside every local IPv4 subnet (%s); EPICS_CA_ADDR_LIST on the client may name another network", s.PV, s.ClientIP, s.Destination, joinPrefixes(ctx.LocalIPv4)),
		Evidence: []Ref{s.Ref},
		Data:     map[string]string{"pv": s.PV, "destination": s.Destination.String()},
	}
}

// pvaRules covers the same symptoms for PVAccess plus GUID changes.
func (r *Report) pvaRules(table *device.Table) {
	searches := table.PVASearches()
	servers := table.PVAServers()
	if len(searches) == 0 && len(servers) == 0 {
		return
	}
	unanswered := 0
	for _, s := range searches {
		switch {
		case len(s.Responses) == 0 && len(s.NotFound) == 0:
			unanswered++
			r.Observed = append(r.Observed, Finding{
				Code:     CodePVASearchUnanswered,
				Text:     fmt.Sprintf("PVA search for %s from %s:%d (x%d) with no response observed", s.PV, s.ClientIP, s.ClientPort, s.Count),
				Evidence: []Ref{s.Ref},
				Data:     map[string]string{"pv": s.PV, "client": s.ClientIP.String(), "count": fmt.Sprint(s.Count)},
			})
		case len(s.Responses) > 1:
			var who []string
			var refs []Ref
			for _, a := range s.Responses {
				who = append(who, fmt.Sprintf("%s:%d (guid %s)", a.ServerAddr, a.ServerPort, a.GUID))
				refs = append(refs, a.Ref)
			}
			r.Observed = append(r.Observed, Finding{
				Code:     CodePVAMultipleServers,
				Text:     fmt.Sprintf("PVA search for %s answered by %d servers: %s", s.PV, len(s.Responses), strings.Join(who, ", ")),
				Evidence: refs,
				Data:     map[string]string{"pv": s.PV, "servers": strings.Join(who, ",")},
			})
			r.Inferred = append(r.Inferred, Finding{
				Code:     CodePVAMultipleServers,
				Text:     fmt.Sprintf("more than one PVA server claims %s", s.PV),
				Evidence: refs,
				Data:     map[string]string{"pv": s.PV, "servers": strings.Join(who, ",")},
			})
		}
	}
	if unanswered > 0 {
		r.Inferred = append(r.Inferred, Finding{
			Code: CodePVASearchUnanswered,
			Text: fmt.Sprintf("%d PVA search(es) received no observed response; absence of a reply is not proof that the PV does not exist", unanswered),
		})
	}
	byAddr := map[string][]device.PVAServer{}
	for _, srv := range servers {
		r.Observed = append(r.Observed, Finding{
			Code:     CodePVAServerSeen,
			Text:     fmt.Sprintf("PVA server %s TCP port %d guid %s: %d search answer(s), %d beacon(s)", srv.Addr, srv.TCPPort, srv.GUID, srv.Answers, srv.Beacons),
			Evidence: []Ref{srv.Ref},
			Data:     map[string]string{"server": srv.Addr.String(), "tcp_port": fmt.Sprint(srv.TCPPort), "guid": srv.GUID},
		})
		key := fmt.Sprintf("%s:%d", srv.Addr, srv.TCPPort)
		byAddr[key] = append(byAddr[key], srv)
	}
	keys := make([]string, 0, len(byAddr))
	for k := range byAddr {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		list := byAddr[k]
		if len(list) < 2 {
			continue
		}
		var guids []string
		var refs []Ref
		for _, srv := range list {
			guids = append(guids, srv.GUID)
			refs = append(refs, srv.Ref)
		}
		r.Inferred = append(r.Inferred, Finding{
			Code:     CodePVAServerRestart,
			Text:     fmt.Sprintf("PVA server %s appeared with %d different GUIDs (%s): it restarted during the window", k, len(list), strings.Join(guids, ", ")),
			Evidence: refs,
		})
	}
}

// sourceRules compares discovery activity between capture sources when
// more than one source fed the table (several interfaces or files).
func (r *Report) sourceRules(table *device.Table) {
	type counts struct{ caSearch, caServer, pvaSearch, pvaServer int }
	per := map[string]*counts{}
	get := func(src string) *counts {
		c, ok := per[src]
		if !ok {
			c = &counts{}
			per[src] = c
		}
		return c
	}
	for _, s := range table.CASearches() {
		get(s.Ref.Source).caSearch += s.Count
	}
	for _, s := range table.CAServers() {
		get(s.Ref.Source).caServer++
	}
	for _, s := range table.PVASearches() {
		get(s.Ref.Source).pvaSearch += s.Count
	}
	for _, s := range table.PVAServers() {
		get(s.Ref.Source).pvaServer++
	}
	for _, d := range table.Devices() {
		for _, t := range d.Timeline {
			get(t.Ref.Source)
		}
	}
	total := 0
	for _, c := range per {
		total += c.caSearch + c.caServer + c.pvaSearch + c.pvaServer
	}
	if len(per) < 2 || total == 0 {
		return
	}
	srcs := make([]string, 0, len(per))
	for s := range per {
		srcs = append(srcs, s)
	}
	sort.Strings(srcs)
	var lines []string
	differs := false
	for _, s := range srcs {
		c := per[s]
		lines = append(lines, fmt.Sprintf("%s: CA searches %d, CA servers %d, PVA searches %d, PVA servers %d", s, c.caSearch, c.caServer, c.pvaSearch, c.pvaServer))
		if (c.caSearch+c.caServer+c.pvaSearch+c.pvaServer == 0) != (per[srcs[0]].caSearch+per[srcs[0]].caServer+per[srcs[0]].pvaSearch+per[srcs[0]].pvaServer == 0) {
			differs = true
		}
	}
	r.Observed = append(r.Observed, Finding{Code: CodeSourceDifference, Text: "discovery activity per source: " + strings.Join(lines, "; ")})
	if differs {
		r.Inferred = append(r.Inferred, Finding{Code: CodeSourceDifference, Text: "EPICS discovery traffic is present on one source but absent on another; clients and servers may be attached to different interfaces or VLANs"})
	}
}

func addrText(a netip.Addr) string {
	if !a.IsValid() || a.IsUnspecified() {
		return "unknown"
	}
	return a.String()
}
