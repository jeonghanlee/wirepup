// Package diagnose turns device evidence and local host context into a
// report that keeps observed facts, inferences, recommendations, and
// executed actions apart (NFR-008, ADR-0009). Rules never present an
// inference as a packet-level fact; every finding cites its evidence.
package diagnose

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
)

// Finding sections.
const (
	SectionObserved    = "observed"
	SectionInferred    = "inferred"
	SectionRecommended = "recommended"
	SectionExecuted    = "executed"
)

// Finding codes are stable identifiers in the JSON output.
const (
	CodeLocalContext        = "local-context"
	CodeL2Evidence          = "l2-evidence"
	CodeAddressClaim        = "address-claim"
	CodeOutsideLocalSubnet  = "ipv4-outside-local-subnet"
	CodeSameL2DiffSubnet    = "same-l2-different-subnet"
	CodeTemporaryAddress    = "temporary-secondary-address"
	CodeDuplicateAddress    = "duplicate-ipv4-claim"
	CodeTargetNotObserved   = "target-not-observed"
	CodeTargetOnLocalSubnet = "target-on-local-subnet"
	CodeNoLocalIPv4         = "no-local-ipv4"
)

// assumedPrefixBits is used when a foreign address gives no prefix hint.
const assumedPrefixBits = 24

// Ref is a packet reference.
type Ref = device.Ref

// Finding is one line of the report.
type Finding struct {
	Code     string
	Text     string
	Evidence []Ref
	Data     map[string]string
}

// Report is the result of one diagnosis run.
type Report struct {
	Interface   string
	Target      netip.Addr // zero when the run is not about one address
	TargetSeen  bool
	Observed    []Finding
	Inferred    []Finding
	Recommended []Finding
	Executed    []Finding
}

// Context is what the host knows about itself on the capture interface.
type Context struct {
	Interface string
	LocalIPv4 []netip.Prefix
	LocalIPv6 []netip.Prefix
	Routes    []interfaces.Route
}

// ContextFor builds the context from the live host for one interface.
func ContextFor(name string) (Context, error) {
	ifc, err := interfaces.ByName(name)
	if err != nil {
		return Context{}, err
	}
	c := Context{Interface: name, LocalIPv4: ifc.IPv4, LocalIPv6: ifc.IPv6}
	if routes, err := interfaces.Routes(); err == nil {
		for _, r := range routes {
			if r.Interface == name {
				c.Routes = append(c.Routes, r)
			}
		}
	}
	return c, nil
}

// ContextFromPrefixes builds a context from explicit local prefixes, for
// offline analysis where the capture host is not this host.
func ContextFromPrefixes(name string, prefixes []netip.Prefix) Context {
	c := Context{Interface: name}
	for _, p := range prefixes {
		if p.Addr().Is4() {
			c.LocalIPv4 = append(c.LocalIPv4, p)
		} else {
			c.LocalIPv6 = append(c.LocalIPv6, p)
		}
	}
	return c
}

// Run evaluates the subnet rules over the table. When target is valid,
// the report focuses on that address and TargetSeen says whether any
// device claimed it.
func Run(ctx Context, table *device.Table, target netip.Addr) Report {
	r := Report{Interface: ctx.Interface, Target: target}
	r.observeContext(ctx)
	devices := table.Devices()
	conflicts := table.Conflicts()
	if target.IsValid() {
		r.diagnoseTarget(ctx, devices, conflicts, target)
		return r
	}
	for _, d := range devices {
		for _, a := range d.IPv4 {
			if !strongClaim(a) || d.Local {
				continue
			}
			r.evaluateAddress(ctx, d, a, devices)
		}
	}
	r.reportConflicts(conflicts)
	return r
}

func (r *Report) observeContext(ctx Context) {
	if len(ctx.LocalIPv4) == 0 {
		r.Observed = append(r.Observed, Finding{Code: CodeNoLocalIPv4, Text: fmt.Sprintf("local %s has no IPv4 address", ctx.Interface)})
		return
	}
	r.Observed = append(r.Observed, Finding{
		Code: CodeLocalContext,
		Text: fmt.Sprintf("local %s IPv4 = %s", ctx.Interface, joinPrefixes(ctx.LocalIPv4)),
		Data: map[string]string{"interface": ctx.Interface, "ipv4": joinPrefixes(ctx.LocalIPv4)},
	})
}

func (r *Report) diagnoseTarget(ctx Context, devices []device.Device, conflicts []device.Conflict, target netip.Addr) {
	for _, d := range devices {
		for _, a := range d.IPv4 {
			if a.Addr != target || !strongClaim(a) {
				continue
			}
			r.TargetSeen = true
			r.evaluateAddress(ctx, d, a, devices)
		}
	}
	if !r.TargetSeen {
		r.Observed = append(r.Observed, Finding{Code: CodeTargetNotObserved, Text: fmt.Sprintf("no frame claiming %s was observed on %s during the window", target, ctx.Interface)})
		r.Inferred = append(r.Inferred, Finding{Code: CodeTargetNotObserved, Text: fmt.Sprintf("%s is silent, absent, or on another segment or VLAN; absence of traffic is not proof of absence", target)})
	}
	for _, c := range conflicts {
		if c.Addr == target {
			r.reportConflicts([]device.Conflict{c})
		}
	}
}

// evaluateAddress applies the same-L2/different-subnet rule to one
// address claim of one device.
func (r *Report) evaluateAddress(ctx Context, d device.Device, a device.Address, devices []device.Device) {
	mac := d.ID
	ev := []Ref{a.Ref}
	r.Observed = append(r.Observed, Finding{
		Code:     CodeL2Evidence,
		Text:     fmt.Sprintf("%s frame from MAC %s on %s", a.Via, mac, ctx.Interface),
		Evidence: ev,
		Data:     map[string]string{"mac": mac, "via": a.Via},
	})
	r.Observed = append(r.Observed, Finding{
		Code:     CodeAddressClaim,
		Text:     fmt.Sprintf("%s sender IPv4 = %s", a.Via, a.Addr),
		Evidence: ev,
		Data:     map[string]string{"mac": mac, "address": a.Addr.String(), "state": a.State},
	})
	if len(ctx.LocalIPv4) == 0 {
		return
	}
	if p, ok := containing(ctx.LocalIPv4, a.Addr); ok {
		r.Inferred = append(r.Inferred, Finding{
			Code:     CodeTargetOnLocalSubnet,
			Text:     fmt.Sprintf("MAC %s appears to use %s, inside local %s", mac, a.Addr, p),
			Evidence: ev,
			Data:     map[string]string{"mac": mac, "address": a.Addr.String(), "local_prefix": p.String()},
		})
		return
	}
	r.Inferred = append(r.Inferred, Finding{
		Code:     CodeOutsideLocalSubnet,
		Text:     fmt.Sprintf("MAC %s appears to use %s", mac, a.Addr),
		Evidence: ev,
		Data:     map[string]string{"mac": mac, "address": a.Addr.String()},
	})
	r.Inferred = append(r.Inferred, Finding{
		Code:     CodeSameL2DiffSubnet,
		Text:     fmt.Sprintf("%s is outside every configured local IPv4 subnet (%s) although its MAC is on the same Layer-2 segment", a.Addr, joinPrefixes(ctx.LocalIPv4)),
		Evidence: ev,
		Data:     map[string]string{"mac": mac, "address": a.Addr.String(), "local_ipv4": joinPrefixes(ctx.LocalIPv4)},
	})
	prefix := netip.PrefixFrom(a.Addr, assumedPrefixBits).Masked()
	cand, ok := candidate(prefix, ctx, devices)
	if !ok {
		r.Recommended = append(r.Recommended, Finding{
			Code:     CodeTemporaryAddress,
			Text:     fmt.Sprintf("no free address found in %s for a temporary secondary address", prefix),
			Evidence: ev,
		})
		return
	}
	r.Recommended = append(r.Recommended, Finding{
		Code:     CodeTemporaryAddress,
		Text:     fmt.Sprintf("consider a temporary secondary address %s on %s to reach %s (prefix /%d assumed; verify before use); no host configuration is changed without an explicit connect command", cand, ctx.Interface, a.Addr, assumedPrefixBits),
		Evidence: ev,
		Data:     map[string]string{"candidate": cand.String(), "prefix": prefix.String(), "interface": ctx.Interface, "target": a.Addr.String()},
	})
}

func (r *Report) reportConflicts(conflicts []device.Conflict) {
	for _, c := range conflicts {
		r.Observed = append(r.Observed, Finding{
			Code:     CodeDuplicateAddress,
			Text:     fmt.Sprintf("%s claimed by %s", c.Addr, strings.Join(c.MACs, " and ")),
			Evidence: c.Refs,
			Data:     map[string]string{"address": c.Addr.String(), "macs": strings.Join(c.MACs, ",")},
		})
		r.Inferred = append(r.Inferred, Finding{
			Code:     CodeDuplicateAddress,
			Text:     fmt.Sprintf("two devices may be configured with %s, or one device changed its MAC", c.Addr),
			Evidence: c.Refs,
		})
	}
}

// candidate picks the highest free host address in the prefix (R-013):
// not observed on the segment in any state, not local, not the network
// or broadcast address.
func candidate(prefix netip.Prefix, ctx Context, devices []device.Device) (netip.Addr, bool) {
	used := map[netip.Addr]bool{}
	for _, d := range devices {
		for _, a := range d.IPv4 {
			used[a.Addr] = true
		}
	}
	for _, p := range ctx.LocalIPv4 {
		used[p.Addr()] = true
	}
	for _, r := range ctx.Routes {
		if r.Gateway.IsValid() {
			used[r.Gateway] = true
		}
	}
	network := prefix.Addr().As4()
	bits := prefix.Bits()
	hosts := 1 << (32 - bits)
	base := uint32(network[0])<<24 | uint32(network[1])<<16 | uint32(network[2])<<8 | uint32(network[3])
	for i := hosts - 2; i >= 1; i-- {
		v := base + uint32(i)
		a := netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
		if !used[a] {
			return a, true
		}
	}
	return netip.Addr{}, false
}

func strongClaim(a device.Address) bool {
	switch a.State {
	case device.StateObserved, device.StateClaimed, device.StateLeased:
		return true
	}
	return false
}

func containing(prefixes []netip.Prefix, a netip.Addr) (netip.Prefix, bool) {
	for _, p := range prefixes {
		if p.Contains(a) {
			return p, true
		}
	}
	return netip.Prefix{}, false
}

func joinPrefixes(ps []netip.Prefix) string {
	s := make([]string, 0, len(ps))
	for _, p := range ps {
		s = append(s, p.String())
	}
	sort.Strings(s)
	return strings.Join(s, ", ")
}
