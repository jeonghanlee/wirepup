// Package device correlates typed observations into inferred device
// records (ADR-0003, ADR-0004). The source MAC is the initial key; a
// Device stays an inference backed by evidence, never an asserted fact.
// Merging by hostname or vendor never happens here (R-010).
package device

import (
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

// Address states, from weakest to strongest claim.
const (
	StateProbing  = "probing"  // the device is testing the address (ARP probe target)
	StateObserved = "observed" // the device used the address as a sender
	StateClaimed  = "claimed"  // the device announced the address (gratuitous ARP)
)

// Via labels name the evidence that produced an event.
const (
	ViaEthernet        = "Ethernet"
	ViaARPProbe        = "ARP Probe"
	ViaARPAnnouncement = "ARP Announcement"
	ViaARPRequest      = "ARP Request"
	ViaARPReply        = "ARP Reply"
)

// Event changes.
const (
	ChangeNewDevice = "new_device"
	ChangeUpdate    = "update"
)

// MethodLinkLocal labels IPv4 Link-Local / Auto-IP behavior (R-007).
const MethodLinkLocal = "IPv4 Link-Local / Auto-IP"

// Protocol labels recorded on a device.
const (
	ProtoARP = "arp"
)

var stateRank = map[string]int{StateProbing: 1, StateObserved: 2, StateClaimed: 3}

// Ref points at the packet that supports a claim.
type Ref struct {
	Source   string
	PacketID uint64
}

// RefOf extracts the packet reference from evidence.
func RefOf(ev observation.Evidence) Ref {
	return Ref{Source: ev.Source, PacketID: ev.PacketID}
}

// Address is one IP address associated with a device.
type Address struct {
	Addr      netip.Addr
	State     string
	Via       string
	FirstSeen time.Time
	LastSeen  time.Time
	Ref       Ref
}

// Name is a name learned for a device from a protocol.
type Name struct {
	Value string
	Via   string
	Ref   Ref
}

// TimelineEntry is one line of the device timeline (R-022).
type TimelineEntry struct {
	Time time.Time
	Text string
	Ref  Ref
}

// Device is an inferred endpoint.
type Device struct {
	ID         string
	MACs       []string
	IPv4       []Address
	IPv6       []Address
	Names      []Name
	Vendor     string
	Protocols  []string
	FirstSeen  time.Time
	LastSeen   time.Time
	Local      bool
	Confidence observation.Confidence
	Timeline   []TimelineEntry
}

// Event describes one change to the table.
type Event struct {
	Time    time.Time
	Change  string
	Device  Device
	Via     string
	Method  string
	Address netip.Addr
	Ref     Ref
}

// Options configure a table.
type Options struct {
	// LocalMACs marks devices that are this host's own interfaces.
	LocalMACs []string
	// Vendor returns a vendor hint for a MAC, or "" (R-021).
	Vendor func(mac string) string
}

// Table holds the device records.
type Table struct {
	mu    sync.Mutex
	opts  Options
	local map[string]bool
	byMAC map[string]*Device
	order []*Device
}

// New returns an empty table.
func New(opts Options) *Table {
	t := &Table{opts: opts, local: map[string]bool{}, byMAC: map[string]*Device{}}
	for _, m := range opts.LocalMACs {
		t.local[m] = true
	}
	return t
}

// Len returns the number of devices.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.order)
}

// Devices returns snapshot copies ordered by first sighting.
func (t *Table) Devices() []Device {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Device, 0, len(t.order))
	for _, d := range t.order {
		out = append(out, snapshot(d))
	}
	return out
}

// Apply folds the observations of one packet into the table and returns
// the events they produced.
func (t *Table) Apply(obs []observation.Observation) []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var events []Event
	for _, o := range obs {
		switch v := o.(type) {
		case ethernet.Observation:
			events = append(events, t.applyFrame(v)...)
		case arp.Observation:
			events = append(events, t.applyARP(v)...)
		}
	}
	return events
}

func (t *Table) applyFrame(v ethernet.Observation) []Event {
	if !validKey(v.Source) {
		return nil
	}
	_, ev := t.touch(v.Source.String(), v.Timestamp, ViaEthernet, RefOf(v.Evidence))
	return ev
}

func (t *Table) applyARP(v arp.Observation) []Event {
	if !validKey(v.SenderMAC) {
		return nil
	}
	mac := v.SenderMAC.String()
	d, events := t.touch(mac, v.Timestamp, ViaEthernet, RefOf(v.Evidence))
	addProtocol(d, ProtoARP)
	ref := RefOf(v.Evidence)
	switch v.Role {
	case arp.RoleProbe:
		events = append(events, t.addAddress(d, v.TargetIP, StateProbing, ViaARPProbe, v.Timestamp, ref)...)
	case arp.RoleAnnouncement:
		events = append(events, t.addAddress(d, v.SenderIP, StateClaimed, ViaARPAnnouncement, v.Timestamp, ref)...)
	case arp.RoleRequest:
		events = append(events, t.addAddress(d, v.SenderIP, StateObserved, ViaARPRequest, v.Timestamp, ref)...)
	case arp.RoleReply:
		events = append(events, t.addAddress(d, v.SenderIP, StateObserved, ViaARPReply, v.Timestamp, ref)...)
	}
	return events
}

// touch returns the device for a MAC, creating it (and a new-device
// event) on first sight, and advances its last-seen time.
func (t *Table) touch(mac string, at time.Time, via string, ref Ref) (*Device, []Event) {
	if d, ok := t.byMAC[mac]; ok {
		if at.After(d.LastSeen) {
			d.LastSeen = at
		}
		return d, nil
	}
	d := &Device{
		ID:         mac,
		MACs:       []string{mac},
		FirstSeen:  at,
		LastSeen:   at,
		Local:      t.local[mac],
		Confidence: observation.Confirmed,
	}
	if t.opts.Vendor != nil {
		d.Vendor = t.opts.Vendor(mac)
	}
	d.Timeline = append(d.Timeline, TimelineEntry{Time: at, Text: "MAC observed", Ref: ref})
	t.byMAC[mac] = d
	t.order = append(t.order, d)
	return d, []Event{{Time: at, Change: ChangeNewDevice, Device: snapshot(d), Via: via, Ref: ref}}
}

// addAddress records an IPv4 address claim and emits an update event when
// the address is new or the claim became stronger.
func (t *Table) addAddress(d *Device, addr netip.Addr, state, via string, at time.Time, ref Ref) []Event {
	if !addr.IsValid() || addr.IsUnspecified() {
		return nil
	}
	method := ""
	if arp.IsLinkLocal(addr) {
		method = MethodLinkLocal
	}
	for i := range d.IPv4 {
		a := &d.IPv4[i]
		if a.Addr != addr {
			continue
		}
		if at.After(a.LastSeen) {
			a.LastSeen = at
		}
		if stateRank[state] <= stateRank[a.State] {
			return nil
		}
		a.State, a.Via, a.Ref = state, via, ref
		d.Timeline = append(d.Timeline, TimelineEntry{Time: at, Text: timelineText(via, addr), Ref: ref})
		return []Event{{Time: at, Change: ChangeUpdate, Device: snapshot(d), Via: via, Method: method, Address: addr, Ref: ref}}
	}
	d.IPv4 = append(d.IPv4, Address{Addr: addr, State: state, Via: via, FirstSeen: at, LastSeen: at, Ref: ref})
	d.Timeline = append(d.Timeline, TimelineEntry{Time: at, Text: timelineText(via, addr), Ref: ref})
	return []Event{{Time: at, Change: ChangeUpdate, Device: snapshot(d), Via: via, Method: method, Address: addr, Ref: ref}}
}

func timelineText(via string, addr netip.Addr) string {
	switch via {
	case ViaARPProbe:
		return "ARP probe " + addr.String()
	case ViaARPAnnouncement:
		return "ARP announcement " + addr.String()
	default:
		return "IPv4 observed " + addr.String()
	}
}

func addProtocol(d *Device, p string) {
	for _, x := range d.Protocols {
		if x == p {
			return
		}
	}
	d.Protocols = append(d.Protocols, p)
	sort.Strings(d.Protocols)
}

func validKey(mac []byte) bool {
	return ethernet.IsUnicast(mac) && !ethernet.IsZero(mac)
}

func snapshot(d *Device) Device {
	c := *d
	c.MACs = append([]string(nil), d.MACs...)
	c.IPv4 = append([]Address(nil), d.IPv4...)
	c.IPv6 = append([]Address(nil), d.IPv6...)
	c.Names = append([]Name(nil), d.Names...)
	c.Protocols = append([]string(nil), d.Protocols...)
	c.Timeline = append([]TimelineEntry(nil), d.Timeline...)
	return c
}
