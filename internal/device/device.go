// Package device correlates typed observations into inferred device
// records (ADR-0003, ADR-0004). The source MAC is the initial key; a
// Device stays an inference backed by evidence, never an asserted fact.
// Merging by hostname or vendor never happens here (R-010). LLDP
// neighbors are kept as their own entity so that switch ports are not
// folded into endpoint records.
package device

import (
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
)

// Address states, from weakest to strongest claim.
const (
	StateSeen     = "seen"     // used as an IP source address behind this MAC (weak: routers forward)
	StateProbing  = "probing"  // the device is testing the address (ARP probe target)
	StateObserved = "observed" // the device used the address as an ARP sender
	StateClaimed  = "claimed"  // the device announced the address (gratuitous ARP)
	StateLeased   = "leased"   // a DHCP server acknowledged the address for this client
)

// Via labels name the evidence that produced an event.
const (
	ViaEthernet        = "Ethernet"
	ViaARPProbe        = "ARP Probe"
	ViaARPAnnouncement = "ARP Announcement"
	ViaARPRequest      = "ARP Request"
	ViaARPReply        = "ARP Reply"
	ViaIPv4            = "IPv4 packet"
	ViaIPv6            = "IPv6 packet"
	ViaVLANTag         = "802.1Q tag"
	ViaDAD             = "NDP DAD"
	ViaNDPSolicit      = "NDP Solicitation"
	ViaNDPAdvert       = "NDP Advertisement"
	ViaRouterAdvert    = "NDP Router Advertisement"
	ViaDHCP            = "DHCP"
	ViaDHCPACK         = "DHCP ACK"
	ViaDHCPServer      = "DHCP server"
	ViaLLDP            = "LLDP"
)

// Event changes.
const (
	ChangeNewDevice   = "new_device"
	ChangeUpdate      = "update"
	ChangeNewNeighbor = "new_neighbor"
	ChangeConflict    = "address_conflict"
)

// ViaConflict labels an address claimed by more than one MAC.
const ViaConflict = "duplicate address claim"

// Methods label how an address was obtained.
const (
	MethodLinkLocal   = "IPv4 Link-Local / Auto-IP"
	MethodDHCP        = "DHCP"
	MethodV6LinkLocal = "IPv6 Link-Local"
)

// Protocol labels recorded on a device.
const (
	ProtoARP        = "arp"
	ProtoDHCP       = "dhcp"
	ProtoDHCPServer = "dhcp-server"
	ProtoLLDP       = "lldp"
	ProtoNDP        = "ndp"
	ProtoIPv6Router = "ipv6-router"
)

// maxWeakAddresses bounds the "seen" addresses kept per device so that a
// router's MAC does not accumulate every remote source address.
const maxWeakAddresses = 16

var stateRank = map[string]int{StateSeen: 1, StateProbing: 1, StateObserved: 2, StateClaimed: 3, StateLeased: 3}

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
	ID        string
	MACs      []string
	IPv4      []Address
	IPv6      []Address
	Names     []Name
	Vendor    string
	Protocols []string
	FirstSeen time.Time
	LastSeen  time.Time
	Local     bool
	Router    bool // advertised itself as an IPv6 router
	VLANs     []uint16
	// LocallyAdministered marks a MAC with the U/L bit set (randomized
	// or virtual), whose prefix carries no vendor meaning and which may
	// not be stable over time.
	LocallyAdministered bool
	Confidence          observation.Confidence
	Timeline            []TimelineEntry
	WeakOverflow        int // "seen" addresses not recorded because the cap was reached
}

// Conflict is one address claimed by more than one MAC through strong
// evidence (ARP, NDP, DHCP), which is duplicate-address evidence rather
// than a merge reason (R-010).
type Conflict struct {
	Addr      netip.Addr
	MACs      []string
	FirstSeen time.Time
	LastSeen  time.Time
	Refs      []Ref
}

// Neighbor is an LLDP-advertising network device, kept apart from
// endpoint records.
type Neighbor struct {
	ID          string
	ChassisID   string
	PortID      string
	SourceMAC   string
	SystemName  string
	SystemDesc  string
	PortDesc    string
	Caps        []string
	EnabledCaps []string
	MgmtAddrs   []string
	PortVLANID  uint16
	VLANNames   []string
	MaxFrame    uint16
	TTL         uint16
	FirstSeen   time.Time
	LastSeen    time.Time
	Ref         Ref
}

// DHCPTransaction tracks one client exchange by transaction ID.
type DHCPTransaction struct {
	XID       uint32
	ClientMAC string
	Discover  time.Time
	Offer     time.Time
	Request   time.Time
	ACK       time.Time
	NAK       time.Time
	OfferedIP netip.Addr
	AckIP     netip.Addr
	ServerIP  netip.Addr
	Ref       Ref
}

// Event describes one change to the table.
type Event struct {
	Time     time.Time
	Change   string
	Device   Device
	Neighbor *Neighbor
	Conflict *Conflict
	Via      string
	Method   string
	Address  netip.Addr
	VLAN     uint16
	Ref      Ref
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
	mu        sync.Mutex
	opts      Options
	local     map[string]bool
	byMAC     map[string]*Device
	order     []*Device
	neighbors map[string]*Neighbor
	norder    []*Neighbor
	dhcp      map[string]*DHCPTransaction
	dorder    []*DHCPTransaction
	claims    map[netip.Addr]*Conflict
	corder    []*Conflict
}

// New returns an empty table.
func New(opts Options) *Table {
	t := &Table{
		opts:      opts,
		local:     map[string]bool{},
		byMAC:     map[string]*Device{},
		neighbors: map[string]*Neighbor{},
		dhcp:      map[string]*DHCPTransaction{},
		claims:    map[netip.Addr]*Conflict{},
	}
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

// Neighbors returns snapshot copies of the LLDP neighbors.
func (t *Table) Neighbors() []Neighbor {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]Neighbor, 0, len(t.norder))
	for _, n := range t.norder {
		out = append(out, neighborSnapshot(n))
	}
	return out
}

// Conflicts returns the addresses claimed by more than one MAC.
func (t *Table) Conflicts() []Conflict {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Conflict
	for _, c := range t.corder {
		if len(c.MACs) > 1 {
			out = append(out, conflictSnapshot(c))
		}
	}
	return out
}

// DHCPTransactions returns copies of the tracked exchanges in order of
// first sighting.
func (t *Table) DHCPTransactions() []DHCPTransaction {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]DHCPTransaction, 0, len(t.dorder))
	for _, x := range t.dorder {
		out = append(out, *x)
	}
	return out
}

// Apply folds the observations of one packet into the table and returns
// the events they produced. The frame observation of the packet supplies
// the source MAC for protocols that do not carry one.
func (t *Table) Apply(obs []observation.Observation) []Event {
	t.mu.Lock()
	defer t.mu.Unlock()
	var events []Event
	var frame *ethernet.Observation
	for _, o := range obs {
		switch v := o.(type) {
		case ethernet.Observation:
			frame = &v
			events = append(events, t.applyFrame(v)...)
		case arp.Observation:
			events = append(events, t.applyARP(v)...)
		case lldp.Observation:
			events = append(events, t.applyLLDP(v)...)
		case ipv4.Observation:
			events = append(events, t.applyIPv4(frame, v)...)
		case ipv6.Observation:
			events = append(events, t.applyIPv6(frame, v)...)
		case icmpv6.Observation:
			events = append(events, t.applyICMPv6(frame, v)...)
		case dhcpv4.Observation:
			events = append(events, t.applyDHCP(frame, v)...)
		}
	}
	return events
}

func (t *Table) applyFrame(v ethernet.Observation) []Event {
	if !validKey(v.Source) {
		return nil
	}
	d, ev := t.touch(v.Source.String(), v.Timestamp, ViaEthernet, RefOf(v.Evidence))
	if v.VLAN != nil {
		ev = append(ev, t.addVLAN(d, v.VLAN.ID, v.Timestamp, RefOf(v.Evidence))...)
	}
	return ev
}

// addVLAN records a tag seen on a frame from the device. Absence of a
// tag is never recorded: it means "unknown", not "no VLAN" (R-009).
func (t *Table) addVLAN(d *Device, id uint16, at time.Time, ref Ref) []Event {
	for _, v := range d.VLANs {
		if v == id {
			return nil
		}
	}
	d.VLANs = append(d.VLANs, id)
	addTimeline(d, at, fmt.Sprintf("VLAN %d tag observed", id), ref)
	return []Event{{Time: at, Change: ChangeUpdate, Device: snapshot(d), Via: ViaVLANTag, VLAN: id, Ref: ref}}
}

// applyIPv6 binds the packet's source address to the frame's source MAC
// as a weak "seen" claim, like applyIPv4.
func (t *Table) applyIPv6(frame *ethernet.Observation, v ipv6.Observation) []Event {
	if frame == nil || !validKey(frame.Source) || !usableIPv6(v.Src) {
		return nil
	}
	d, events := t.touch(frame.Source.String(), v.Timestamp, ViaEthernet, RefOf(v.Evidence))
	return append(events, t.addAddress(d, v.Src, StateSeen, ViaIPv6, "", v.Timestamp, RefOf(v.Evidence))...)
}

// applyICMPv6 interprets Neighbor Discovery: DAD probes, solicitations
// and advertisements as address claims, router advertisements as the
// router role.
func (t *Table) applyICMPv6(frame *ethernet.Observation, v icmpv6.Observation) []Event {
	if frame == nil || !validKey(frame.Source) || !v.IsNDP() {
		return nil
	}
	ref := RefOf(v.Evidence)
	d, events := t.touch(frame.Source.String(), v.Timestamp, ViaEthernet, ref)
	addProtocol(d, ProtoNDP)
	switch v.Type {
	case icmpv6.TypeNeighborSolicit:
		if v.DAD {
			events = append(events, t.addAddress(d, v.Target, StateProbing, ViaDAD, "", v.Timestamp, ref)...)
		} else if usableIPv6(v.Src) {
			events = append(events, t.addAddress(d, v.Src, StateObserved, ViaNDPSolicit, "", v.Timestamp, ref)...)
		}
	case icmpv6.TypeNeighborAdvert:
		state := StateObserved
		if !v.Solicited {
			state = StateClaimed
		}
		events = append(events, t.addAddress(d, v.Target, state, ViaNDPAdvert, "", v.Timestamp, ref)...)
		if v.Router {
			t.markRouter(d, v.Timestamp, ref)
		}
	case icmpv6.TypeRouterAdvert:
		t.markRouter(d, v.Timestamp, ref)
		if usableIPv6(v.Src) {
			events = append(events, t.addAddress(d, v.Src, StateObserved, ViaRouterAdvert, "", v.Timestamp, ref)...)
		}
		for _, p := range v.Prefixes {
			addTimeline(d, v.Timestamp, "RA prefix "+p.Prefix.String(), ref)
		}
	case icmpv6.TypeRouterSolicit:
		if usableIPv6(v.Src) {
			events = append(events, t.addAddress(d, v.Src, StateObserved, ViaNDPSolicit, "", v.Timestamp, ref)...)
		}
	}
	return events
}

func (t *Table) markRouter(d *Device, at time.Time, ref Ref) {
	if d.Router {
		return
	}
	d.Router = true
	addProtocol(d, ProtoIPv6Router)
	addTimeline(d, at, "IPv6 router advertisement", ref)
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
		events = append(events, t.addAddress(d, v.TargetIP, StateProbing, ViaARPProbe, "", v.Timestamp, ref)...)
	case arp.RoleAnnouncement:
		events = append(events, t.addAddress(d, v.SenderIP, StateClaimed, ViaARPAnnouncement, "", v.Timestamp, ref)...)
	case arp.RoleRequest:
		events = append(events, t.addAddress(d, v.SenderIP, StateObserved, ViaARPRequest, "", v.Timestamp, ref)...)
	case arp.RoleReply:
		events = append(events, t.addAddress(d, v.SenderIP, StateObserved, ViaARPReply, "", v.Timestamp, ref)...)
	}
	return events
}

// applyIPv4 binds the packet's source address to the frame's source MAC
// as a weak "seen" claim; routers forward for many sources, so the cap
// keeps such records bounded.
func (t *Table) applyIPv4(frame *ethernet.Observation, v ipv4.Observation) []Event {
	if frame == nil || !validKey(frame.Source) || !usableIPv4(v.Src) {
		return nil
	}
	d, events := t.touch(frame.Source.String(), v.Timestamp, ViaEthernet, RefOf(v.Evidence))
	return append(events, t.addAddress(d, v.Src, StateSeen, ViaIPv4, "", v.Timestamp, RefOf(v.Evidence))...)
}

func (t *Table) applyLLDP(v lldp.Observation) []Event {
	ref := RefOf(v.Evidence)
	var events []Event
	if validKey(v.SourceMAC) {
		d, ev := t.touch(v.SourceMAC.String(), v.Timestamp, ViaLLDP, ref)
		events = append(events, ev...)
		addProtocol(d, ProtoLLDP)
		if v.SystemName != "" {
			addName(d, v.SystemName, ViaLLDP, ref, v.Timestamp)
		}
	}
	key := v.ChassisID + "|" + v.PortID
	if n, ok := t.neighbors[key]; ok {
		n.LastSeen = v.Timestamp
		n.TTL = v.TTL
		return events
	}
	n := &Neighbor{
		ID:          key,
		ChassisID:   v.ChassisID,
		PortID:      v.PortID,
		SourceMAC:   v.SourceMAC.String(),
		SystemName:  v.SystemName,
		SystemDesc:  v.SystemDescription,
		PortDesc:    v.PortDescription,
		Caps:        append([]string(nil), v.Capabilities...),
		EnabledCaps: append([]string(nil), v.EnabledCaps...),
		MgmtAddrs:   append([]string(nil), v.ManagementAddrs...),
		PortVLANID:  v.PortVLANID,
		VLANNames:   v.VLANSummary(),
		MaxFrame:    v.MaxFrameSize,
		TTL:         v.TTL,
		FirstSeen:   v.Timestamp,
		LastSeen:    v.Timestamp,
		Ref:         ref,
	}
	t.neighbors[key] = n
	t.norder = append(t.norder, n)
	snap := neighborSnapshot(n)
	return append(events, Event{Time: v.Timestamp, Change: ChangeNewNeighbor, Neighbor: &snap, Via: ViaLLDP, Ref: ref})
}

// applyDHCP records the client side by chaddr and the server side by the
// frame source MAC, and keeps the transaction for diagnosis.
func (t *Table) applyDHCP(frame *ethernet.Observation, v dhcpv4.Observation) []Event {
	ref := RefOf(v.Evidence)
	var events []Event
	if !validKey(v.ClientMAC) {
		return nil
	}
	cmac := v.ClientMAC.String()
	client, ev := t.touch(cmac, v.Timestamp, ViaDHCP, ref)
	events = append(events, ev...)
	addProtocol(client, ProtoDHCP)
	if v.Hostname != "" {
		addName(client, v.Hostname, ViaDHCP, ref, v.Timestamp)
	}
	x := t.transaction(v.XID, cmac, v.Timestamp, ref)
	switch v.MessageType {
	case dhcpv4.Discover:
		x.Discover = v.Timestamp
		addTimeline(client, v.Timestamp, "DHCP discover", ref)
	case dhcpv4.Request:
		x.Request = v.Timestamp
		want := v.RequestedIP
		if !want.IsValid() || want.IsUnspecified() {
			want = v.ClientIP
		}
		addTimeline(client, v.Timestamp, "DHCP request "+addrText(want), ref)
	case dhcpv4.Offer:
		x.Offer = v.Timestamp
		x.OfferedIP = v.YourIP
		x.ServerIP = serverAddr(v)
		addTimeline(client, v.Timestamp, fmt.Sprintf("DHCP offer %s from %s", addrText(v.YourIP), addrText(x.ServerIP)), ref)
		events = append(events, t.applyDHCPServer(frame, v, ref)...)
	case dhcpv4.ACK:
		x.ACK = v.Timestamp
		x.AckIP = v.YourIP
		if !x.AckIP.IsValid() || x.AckIP.IsUnspecified() {
			x.AckIP = v.ClientIP
		}
		x.ServerIP = serverAddr(v)
		events = append(events, t.addAddress(client, x.AckIP, StateLeased, ViaDHCPACK, MethodDHCP, v.Timestamp, ref)...)
		events = append(events, t.applyDHCPServer(frame, v, ref)...)
	case dhcpv4.NAK:
		x.NAK = v.Timestamp
		x.ServerIP = serverAddr(v)
		addTimeline(client, v.Timestamp, "DHCP nak from "+addrText(x.ServerIP), ref)
		events = append(events, t.applyDHCPServer(frame, v, ref)...)
	}
	return events
}

func (t *Table) applyDHCPServer(frame *ethernet.Observation, v dhcpv4.Observation, ref Ref) []Event {
	if frame == nil || !validKey(frame.Source) {
		return nil
	}
	srv, events := t.touch(frame.Source.String(), v.Timestamp, ViaDHCPServer, ref)
	addProtocol(srv, ProtoDHCPServer)
	if a := serverAddr(v); usableIPv4(a) {
		events = append(events, t.addAddress(srv, a, StateObserved, ViaDHCPServer, "", v.Timestamp, ref)...)
	}
	return events
}

func serverAddr(v dhcpv4.Observation) netip.Addr {
	if v.ServerID.IsValid() && !v.ServerID.IsUnspecified() {
		return v.ServerID
	}
	return v.SrcIP
}

func (t *Table) transaction(xid uint32, mac string, at time.Time, ref Ref) *DHCPTransaction {
	key := fmt.Sprintf("%08x|%s", xid, mac)
	if x, ok := t.dhcp[key]; ok {
		return x
	}
	x := &DHCPTransaction{XID: xid, ClientMAC: mac, Ref: ref}
	t.dhcp[key] = x
	t.dorder = append(t.dorder, x)
	return x
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
		ID:                  mac,
		MACs:                []string{mac},
		FirstSeen:           at,
		LastSeen:            at,
		Local:               t.local[mac],
		LocallyAdministered: locallyAdministered(mac),
		Confidence:          observation.WeakHint,
	}
	if t.opts.Vendor != nil {
		d.Vendor = t.opts.Vendor(mac)
	}
	d.Timeline = append(d.Timeline, TimelineEntry{Time: at, Text: "MAC observed", Ref: ref})
	t.byMAC[mac] = d
	t.order = append(t.order, d)
	return d, []Event{{Time: at, Change: ChangeNewDevice, Device: snapshot(d), Via: via, Ref: ref}}
}

// addAddress records an address claim and emits an update event when
// the address is new or the claim became stronger.
func (t *Table) addAddress(d *Device, addr netip.Addr, state, via, method string, at time.Time, ref Ref) []Event {
	if !addr.IsValid() || addr.IsUnspecified() {
		return nil
	}
	if method == "" {
		switch {
		case arp.IsLinkLocal(addr):
			method = MethodLinkLocal
		case addr.Is6() && addr.IsLinkLocalUnicast():
			method = MethodV6LinkLocal
		}
	}
	list := &d.IPv4
	if addr.Is6() {
		list = &d.IPv6
	}
	for i := range *list {
		a := &(*list)[i]
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
		raiseConfidence(d, state)
		addTimeline(d, at, timelineText(via, addr), ref)
		events := []Event{{Time: at, Change: ChangeUpdate, Device: snapshot(d), Via: via, Method: method, Address: addr, Ref: ref}}
		return append(events, t.noteClaim(d, addr, state, at, ref)...)
	}
	if state == StateSeen && weakCount(*list) >= maxWeakAddresses {
		d.WeakOverflow++
		return nil
	}
	*list = append(*list, Address{Addr: addr, State: state, Via: via, FirstSeen: at, LastSeen: at, Ref: ref})
	raiseConfidence(d, state)
	addTimeline(d, at, timelineText(via, addr), ref)
	events := []Event{{Time: at, Change: ChangeUpdate, Device: snapshot(d), Via: via, Method: method, Address: addr, Ref: ref}}
	return append(events, t.noteClaim(d, addr, state, at, ref)...)
}

// raiseConfidence upgrades the device confidence when strong evidence
// (an address claim through ARP, NDP, or DHCP) arrives; weak sightings
// leave it at the level a frame alone justifies.
func raiseConfidence(d *Device, state string) {
	switch {
	case stateRank[state] >= stateRank[StateObserved]:
		d.Confidence = observation.Confirmed
	case d.Confidence == observation.WeakHint:
		d.Confidence = observation.StrongHint
	}
}

// noteClaim tracks which MACs claim an address with strong evidence and
// emits a conflict event when a second MAC appears.
func (t *Table) noteClaim(d *Device, addr netip.Addr, state string, at time.Time, ref Ref) []Event {
	if stateRank[state] < stateRank[StateObserved] {
		return nil
	}
	c, ok := t.claims[addr]
	if !ok {
		c = &Conflict{Addr: addr, FirstSeen: at}
		t.claims[addr] = c
		t.corder = append(t.corder, c)
	}
	c.LastSeen = at
	for _, m := range c.MACs {
		if m == d.ID {
			return nil
		}
	}
	c.MACs = append(c.MACs, d.ID)
	c.Refs = append(c.Refs, ref)
	if len(c.MACs) < 2 {
		return nil
	}
	addTimeline(d, at, "address "+addr.String()+" also claimed by "+strings.Join(c.MACs[:len(c.MACs)-1], ", "), ref)
	snap := conflictSnapshot(c)
	return []Event{{Time: at, Change: ChangeConflict, Device: snapshot(d), Conflict: &snap, Via: ViaConflict, Address: addr, Ref: ref}}
}

func conflictSnapshot(c *Conflict) Conflict {
	s := *c
	s.MACs = append([]string(nil), c.MACs...)
	s.Refs = append([]Ref(nil), c.Refs...)
	return s
}

func locallyAdministered(mac string) bool {
	hw, err := net.ParseMAC(mac)
	return err == nil && len(hw) > 0 && hw[0]&0x02 != 0
}

func weakCount(list []Address) int {
	n := 0
	for _, a := range list {
		if a.State == StateSeen {
			n++
		}
	}
	return n
}

func timelineText(via string, addr netip.Addr) string {
	switch via {
	case ViaARPProbe:
		return "ARP probe " + addr.String()
	case ViaARPAnnouncement:
		return "ARP announcement " + addr.String()
	case ViaDHCPACK:
		return "DHCP ack " + addr.String()
	case ViaIPv4:
		return "IPv4 seen " + addr.String()
	case ViaIPv6:
		return "IPv6 seen " + addr.String()
	case ViaDAD:
		return "DAD probe " + addr.String()
	case ViaNDPAdvert:
		return "NDP advertisement " + addr.String()
	case ViaNDPSolicit, ViaRouterAdvert:
		return "IPv6 observed " + addr.String()
	default:
		return "IPv4 observed " + addr.String()
	}
}

func addTimeline(d *Device, at time.Time, text string, ref Ref) {
	d.Timeline = append(d.Timeline, TimelineEntry{Time: at, Text: text, Ref: ref})
}

func addName(d *Device, value, via string, ref Ref, at time.Time) {
	for _, n := range d.Names {
		if n.Value == value && n.Via == via {
			return
		}
	}
	d.Names = append(d.Names, Name{Value: value, Via: via, Ref: ref})
	addTimeline(d, at, via+" name "+value, ref)
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

func addrText(a netip.Addr) string {
	if !a.IsValid() || a.IsUnspecified() {
		return "unknown"
	}
	return a.String()
}

func usableIPv4(a netip.Addr) bool {
	return a.IsValid() && a.Is4() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback() && a != netip.AddrFrom4([4]byte{255, 255, 255, 255})
}

func usableIPv6(a netip.Addr) bool {
	return a.IsValid() && a.Is6() && !a.IsUnspecified() && !a.IsMulticast() && !a.IsLoopback()
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
	c.VLANs = append([]uint16(nil), d.VLANs...)
	c.Timeline = append([]TimelineEntry(nil), d.Timeline...)
	return c
}

func neighborSnapshot(n *Neighbor) Neighbor {
	c := *n
	c.Caps = append([]string(nil), n.Caps...)
	c.EnabledCaps = append([]string(nil), n.EnabledCaps...)
	c.MgmtAddrs = append([]string(nil), n.MgmtAddrs...)
	c.VLANNames = append([]string(nil), n.VLANNames...)
	return c
}
