// Package output defines the result structs shared by every renderer
// (text, JSON, TUI). The JSON shape is a versioned public contract
// (ADR-0009): internal types are converted here and never marshalled
// directly.
package output

import (
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/diagnose"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
)

// Schema identifiers; the major number changes only on a breaking change.
const (
	SchemaInterfaces  = "wirepup/interfaces/1"
	SchemaEvent       = "wirepup/event/1"
	SchemaDeviceEvent = "wirepup/device-event/1"
	SchemaDevices     = "wirepup/devices/1"
	SchemaDiagnosis   = "wirepup/diagnosis/1"
)

// Diagnosis is the document for the diagnose command. The four arrays
// are the NFR-008 categories; each finding cites its packets.
type Diagnosis struct {
	Schema      string    `json:"schema"`
	Source      string    `json:"source"`
	Interface   string    `json:"interface"`
	Target      string    `json:"target,omitempty"`
	TargetSeen  bool      `json:"target_observed"`
	GeneratedAt time.Time `json:"generated_at"`
	Observed    []Finding `json:"observed"`
	Inferred    []Finding `json:"inferred"`
	Recommended []Finding `json:"recommended"`
	Executed    []Finding `json:"executed"`
}

// Finding is one diagnosis line.
type Finding struct {
	Code     string            `json:"code"`
	Text     string            `json:"text"`
	Evidence []Ref             `json:"evidence"`
	Data     map[string]string `json:"data,omitempty"`
}

// DiagnosisFrom converts a report.
func DiagnosisFrom(source string, at time.Time, r diagnose.Report) Diagnosis {
	d := Diagnosis{
		Schema:      SchemaDiagnosis,
		Source:      source,
		Interface:   r.Interface,
		TargetSeen:  r.TargetSeen,
		GeneratedAt: at,
		Observed:    findings(r.Observed),
		Inferred:    findings(r.Inferred),
		Recommended: findings(r.Recommended),
		Executed:    findings(r.Executed),
	}
	if r.Target.IsValid() {
		d.Target = r.Target.String()
	}
	return d
}

func findings(fs []diagnose.Finding) []Finding {
	out := make([]Finding, 0, len(fs))
	for _, f := range fs {
		o := Finding{Code: f.Code, Text: f.Text, Evidence: make([]Ref, 0, len(f.Evidence)), Data: f.Data}
		for _, r := range f.Evidence {
			o.Evidence = append(o.Evidence, refFrom(r))
		}
		out = append(out, o)
	}
	return out
}

// Ref is a packet reference: which source and which frame.
type Ref struct {
	Source   string `json:"source"`
	PacketID uint64 `json:"packet_id"`
}

// Interfaces is the document for the interfaces command.
type Interfaces struct {
	Schema     string      `json:"schema"`
	Interfaces []Interface `json:"interfaces"`
}

// Interface is one local interface.
type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac,omitempty"`
	Up        bool     `json:"up"`
	OperState string   `json:"oper_state"`
	MTU       int      `json:"mtu"`
	Loopback  bool     `json:"loopback"`
	IPv4      []string `json:"ipv4"`
	IPv6      []string `json:"ipv6"`
}

// Event is one observation as a stream record.
type Event struct {
	Schema     string         `json:"schema"`
	Source     string         `json:"source"`
	PacketID   uint64         `json:"packet_id"`
	Time       time.Time      `json:"time"`
	Interface  string         `json:"interface"`
	Protocol   string         `json:"protocol"`
	Kind       string         `json:"kind"`
	Confidence string         `json:"confidence"`
	Summary    string         `json:"summary"`
	Fields     map[string]any `json:"fields"`
}

// DeviceEvent is one change to the device table as a stream record.
type DeviceEvent struct {
	Schema   string    `json:"schema"`
	Time     time.Time `json:"time"`
	Change   string    `json:"change"`
	Via      string    `json:"via"`
	Method   string    `json:"method,omitempty"`
	Address  string    `json:"address,omitempty"`
	VLAN     uint16    `json:"vlan,omitempty"`
	Device   Device    `json:"device"`
	Neighbor *Neighbor `json:"neighbor,omitempty"`
	Conflict *Conflict `json:"conflict,omitempty"`
	Ref      Ref       `json:"evidence"`
}

// Conflict is one address claimed by more than one MAC.
type Conflict struct {
	Address   string    `json:"address"`
	MACs      []string  `json:"macs"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Refs      []Ref     `json:"evidence"`
}

// Devices is the document for the discover command.
type Devices struct {
	Schema      string     `json:"schema"`
	Source      string     `json:"source"`
	GeneratedAt time.Time  `json:"generated_at"`
	OUIFile     string     `json:"oui_file,omitempty"`
	Devices     []Device   `json:"devices"`
	Neighbors   []Neighbor `json:"neighbors"`
	Conflicts   []Conflict `json:"conflicts"`
}

// Neighbor is one LLDP-advertising network device.
type Neighbor struct {
	ID          string    `json:"id"`
	ChassisID   string    `json:"chassis_id"`
	PortID      string    `json:"port_id"`
	SourceMAC   string    `json:"source_mac"`
	SystemName  string    `json:"system_name,omitempty"`
	SystemDesc  string    `json:"system_description,omitempty"`
	PortDesc    string    `json:"port_description,omitempty"`
	Caps        []string  `json:"capabilities"`
	EnabledCaps []string  `json:"enabled_capabilities"`
	MgmtAddrs   []string  `json:"management_addresses"`
	PortVLANID  uint16    `json:"port_vlan_id,omitempty"`
	VLANNames   []string  `json:"vlan_names"`
	MaxFrame    uint16    `json:"max_frame_size,omitempty"`
	TTL         uint16    `json:"ttl"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Ref         Ref       `json:"evidence"`
}

// Device is one inferred device.
type Device struct {
	ID                     string          `json:"id"`
	MACs                   []string        `json:"macs"`
	MACLocallyAdministered bool            `json:"mac_locally_administered"`
	PrimaryIPv4            string          `json:"primary_ipv4,omitempty"`
	PrimaryIPv6            string          `json:"primary_ipv6,omitempty"`
	Vendor                 string          `json:"vendor_hint,omitempty"`
	IPv4                   []Address       `json:"ipv4"`
	IPv6                   []Address       `json:"ipv6"`
	Names                  []Name          `json:"names"`
	Protocols              []string        `json:"protocols"`
	FirstSeen              time.Time       `json:"first_seen"`
	LastSeen               time.Time       `json:"last_seen"`
	Local                  bool            `json:"local"`
	Router                 bool            `json:"ipv6_router"`
	VLANs                  []uint16        `json:"vlans"`
	VLAN                   string          `json:"vlan"`
	Confidence             string          `json:"confidence"`
	Timeline               []TimelineEntry `json:"timeline"`
	WeakOverflow           int             `json:"seen_addresses_dropped,omitempty"`
}

// Address is one address claim with its evidence.
type Address struct {
	Address   string    `json:"address"`
	State     string    `json:"state"`
	Via       string    `json:"via"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Ref       Ref       `json:"evidence"`
}

// Name is one learned name.
type Name struct {
	Value string `json:"value"`
	Via   string `json:"via"`
	Ref   Ref    `json:"evidence"`
}

// TimelineEntry is one timeline line.
type TimelineEntry struct {
	Time time.Time `json:"time"`
	Text string    `json:"text"`
	Ref  Ref       `json:"evidence"`
}

// InterfacesFrom converts the interface list.
func InterfacesFrom(ifs []interfaces.Interface) Interfaces {
	out := Interfaces{Schema: SchemaInterfaces, Interfaces: make([]Interface, 0, len(ifs))}
	for _, i := range ifs {
		out.Interfaces = append(out.Interfaces, Interface{
			Name:      i.Name,
			MAC:       i.MAC,
			Up:        i.Up,
			OperState: i.OperState,
			MTU:       i.MTU,
			Loopback:  i.Loopback,
			IPv4:      prefixes(i.IPv4),
			IPv6:      prefixes(i.IPv6),
		})
	}
	return out
}

func prefixes(ps []netip.Prefix) []string {
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.String())
	}
	return out
}

// EventFrom converts one observation into a stream record with a
// one-line summary and kind-specific fields.
func EventFrom(o observation.Observation) Event {
	ev := o.Ref()
	e := Event{
		Schema:     SchemaEvent,
		Source:     ev.Source,
		PacketID:   ev.PacketID,
		Time:       ev.Timestamp,
		Interface:  ev.Interface,
		Protocol:   ev.Protocol,
		Kind:       string(o.Kind()),
		Confidence: string(ev.Confidence),
		Fields:     map[string]any{},
	}
	switch v := o.(type) {
	case ethernet.Observation:
		e.Fields["source_mac"] = v.Source.String()
		e.Fields["destination_mac"] = v.Destination.String()
		e.Fields["ether_type"] = fmt.Sprintf("0x%04x", v.EtherType)
		e.Fields["length"] = v.Length
		vlan := "unknown"
		if v.VLAN != nil {
			vlan = fmt.Sprintf("%d", v.VLAN.ID)
			e.Fields["vlan_id"] = v.VLAN.ID
			e.Fields["vlan_priority"] = v.VLAN.Priority
		}
		e.Fields["vlan"] = vlan
		e.Summary = fmt.Sprintf("frame %s -> %s ethertype 0x%04x len %d vlan %s", v.Source, v.Destination, v.EtherType, v.Length, vlan)
	case arp.Observation:
		e.Fields["role"] = string(v.Role)
		e.Fields["sender_mac"] = v.SenderMAC.String()
		e.Fields["sender_ip"] = v.SenderIP.String()
		e.Fields["target_mac"] = v.TargetMAC.String()
		e.Fields["target_ip"] = v.TargetIP.String()
		e.Fields["link_local"] = arp.IsLinkLocal(v.SenderIP) || arp.IsLinkLocal(v.TargetIP)
		e.Summary = arpSummary(v)
	case lldp.Observation:
		e.Fields["source_mac"] = v.SourceMAC.String()
		e.Fields["chassis_id"] = v.ChassisID
		e.Fields["port_id"] = v.PortID
		e.Fields["ttl"] = v.TTL
		e.Fields["system_name"] = v.SystemName
		e.Fields["system_description"] = v.SystemDescription
		e.Fields["port_description"] = v.PortDescription
		e.Fields["capabilities"] = emptyList(v.Capabilities)
		e.Fields["enabled_capabilities"] = emptyList(v.EnabledCaps)
		e.Fields["management_addresses"] = emptyList(v.ManagementAddrs)
		e.Fields["port_vlan_id"] = v.PortVLANID
		e.Fields["vlan_names"] = emptyList(v.VLANSummary())
		e.Fields["max_frame_size"] = v.MaxFrameSize
		e.Fields["malformed"] = v.Malformed
		e.Summary = fmt.Sprintf("lldp %s port %s (%s) vlan %s mgmt %s", dashIf(v.SystemName), dashIf(v.PortID), dashIf(v.PortDescription), vlanText(v.PortVLANID), strings.Join(v.ManagementAddrs, ","))
	case ipv4.Observation:
		e.Fields["src"] = v.Src.String()
		e.Fields["dst"] = v.Dst.String()
		e.Fields["protocol"] = ipv4.ProtocolName(v.Protocol)
		e.Fields["ttl"] = v.TTL
		e.Fields["length"] = v.Length
		e.Fields["fragment"] = v.Fragment
		e.Summary = fmt.Sprintf("ipv4 %s -> %s %s len %d ttl %d", v.Src, v.Dst, ipv4.ProtocolName(v.Protocol), v.Length, v.TTL)
	case ipv6.Observation:
		e.Fields["src"] = v.Src.String()
		e.Fields["dst"] = v.Dst.String()
		e.Fields["next_header"] = v.NextHeader
		e.Fields["hop_limit"] = v.HopLimit
		e.Fields["length"] = v.Length
		e.Fields["fragment"] = v.Fragment
		e.Summary = fmt.Sprintf("ipv6 %s -> %s next %d len %d hop %d", v.Src, v.Dst, v.NextHeader, v.Length, v.HopLimit)
	case icmpv6.Observation:
		e.Fields["type"] = v.Type
		e.Fields["type_name"] = v.TypeName()
		e.Fields["code"] = v.Code
		e.Fields["src"] = v.Src.String()
		e.Fields["dst"] = v.Dst.String()
		e.Fields["dad"] = v.DAD
		if v.IsNDP() {
			e.Fields["target"] = addrOrEmpty(v.Target)
			e.Fields["source_ll"] = macOrEmpty(v.SourceLL)
			e.Fields["target_ll"] = macOrEmpty(v.TargetLL)
			e.Fields["router"] = v.Router
			e.Fields["solicited"] = v.Solicited
			e.Fields["override"] = v.Override
			e.Fields["malformed"] = v.Malformed
			if v.Type == icmpv6.TypeRouterAdvert {
				e.Fields["managed"] = v.Managed
				e.Fields["other_config"] = v.OtherConfig
				e.Fields["router_lifetime"] = v.RouterLifetime
				e.Fields["mtu"] = v.MTU
				var ps []string
				for _, p := range v.Prefixes {
					ps = append(ps, p.Prefix.String())
				}
				e.Fields["prefixes"] = emptyList(ps)
			}
		}
		e.Summary = ndpSummary(v)
	case dhcpv4.Observation:
		e.Fields["message_type"] = v.TypeName()
		e.Fields["xid"] = fmt.Sprintf("0x%08x", v.XID)
		e.Fields["client_mac"] = v.ClientMAC.String()
		e.Fields["client_id"] = v.ClientID
		e.Fields["hostname"] = v.Hostname
		e.Fields["client_ip"] = addrOrEmpty(v.ClientIP)
		e.Fields["your_ip"] = addrOrEmpty(v.YourIP)
		e.Fields["requested_ip"] = addrOrEmpty(v.RequestedIP)
		e.Fields["server_id"] = addrOrEmpty(v.ServerID)
		e.Fields["lease_seconds"] = v.LeaseTime
		e.Fields["src"] = v.SrcIP.String()
		e.Fields["dst"] = v.DstIP.String()
		e.Summary = dhcpSummary(v)
	default:
		e.Summary = string(o.Kind())
	}
	return e
}

func dhcpSummary(v dhcpv4.Observation) string {
	switch v.MessageType {
	case dhcpv4.Offer, dhcpv4.ACK:
		return fmt.Sprintf("dhcp %s %s -> client %s server %s", v.TypeName(), addrOrEmpty(v.YourIP), v.ClientMAC, addrOrEmpty(v.ServerID))
	case dhcpv4.Request:
		return fmt.Sprintf("dhcp request %s from %s (%s)", addrOrEmpty(v.RequestedIP), v.ClientMAC, dashIf(v.Hostname))
	case dhcpv4.NAK:
		return fmt.Sprintf("dhcp nak to %s from %s", v.ClientMAC, addrOrEmpty(v.ServerID))
	default:
		return fmt.Sprintf("dhcp %s from %s (%s)", v.TypeName(), v.ClientMAC, dashIf(v.Hostname))
	}
}

func ndpSummary(v icmpv6.Observation) string {
	switch v.Type {
	case icmpv6.TypeNeighborSolicit:
		if v.DAD {
			return fmt.Sprintf("ndp dad probe for %s", v.Target)
		}
		return fmt.Sprintf("ndp solicitation who-has %s tell %s", v.Target, v.Src)
	case icmpv6.TypeNeighborAdvert:
		kind := "unsolicited"
		if v.Solicited {
			kind = "solicited"
		}
		return fmt.Sprintf("ndp advertisement %s is-at %s (%s)", v.Target, macOrEmpty(v.TargetLL), kind)
	case icmpv6.TypeRouterAdvert:
		var ps []string
		for _, p := range v.Prefixes {
			ps = append(ps, p.Prefix.String())
		}
		return fmt.Sprintf("ndp router advertisement from %s prefixes %s", v.Src, dashIf(strings.Join(ps, ",")))
	case icmpv6.TypeRouterSolicit:
		return fmt.Sprintf("ndp router solicitation from %s", v.Src)
	default:
		return fmt.Sprintf("icmpv6 %s %s -> %s", v.TypeName(), v.Src, v.Dst)
	}
}

func macOrEmpty(hw []byte) string {
	if len(hw) != 6 {
		return ""
	}
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", hw[0], hw[1], hw[2], hw[3], hw[4], hw[5])
}

func vlanList(ids []uint16) string {
	if len(ids) == 0 {
		return "unknown"
	}
	var s []string
	for _, id := range ids {
		s = append(s, fmt.Sprintf("%d", id))
	}
	return strings.Join(s, ",")
}

func addrOrEmpty(a netip.Addr) string {
	if !a.IsValid() || a.IsUnspecified() {
		return ""
	}
	return a.String()
}

func dashIf(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func vlanText(id uint16) string {
	if id == 0 {
		return "unknown"
	}
	return fmt.Sprintf("%d", id)
}

func emptyList(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func arpSummary(v arp.Observation) string {
	switch v.Role {
	case arp.RoleProbe:
		return fmt.Sprintf("arp probe %s asks %s", v.SenderMAC, v.TargetIP)
	case arp.RoleAnnouncement:
		return fmt.Sprintf("arp announcement %s is-at %s", v.SenderIP, v.SenderMAC)
	case arp.RoleReply:
		return fmt.Sprintf("arp reply %s is-at %s", v.SenderIP, v.SenderMAC)
	default:
		return fmt.Sprintf("arp request who-has %s tell %s (%s)", v.TargetIP, v.SenderIP, v.SenderMAC)
	}
}

// DeviceFrom converts a device record.
func DeviceFrom(d device.Device) Device {
	out := Device{
		ID:                     d.ID,
		MACs:                   append([]string{}, d.MACs...),
		MACLocallyAdministered: d.LocallyAdministered,
		PrimaryIPv4:            primaryAddress(d.IPv4),
		PrimaryIPv6:            primaryAddress(d.IPv6),
		Vendor:                 d.Vendor,
		IPv4:                   addresses(d.IPv4),
		IPv6:                   addresses(d.IPv6),
		Names:                  make([]Name, 0, len(d.Names)),
		Protocols:              append([]string{}, d.Protocols...),
		FirstSeen:              d.FirstSeen,
		LastSeen:               d.LastSeen,
		Local:                  d.Local,
		Router:                 d.Router,
		VLANs:                  append([]uint16{}, d.VLANs...),
		VLAN:                   vlanList(d.VLANs),
		Confidence:             string(d.Confidence),
		Timeline:               make([]TimelineEntry, 0, len(d.Timeline)),
		WeakOverflow:           d.WeakOverflow,
	}
	for _, n := range d.Names {
		out.Names = append(out.Names, Name{Value: n.Value, Via: n.Via, Ref: refFrom(n.Ref)})
	}
	for _, t := range d.Timeline {
		out.Timeline = append(out.Timeline, TimelineEntry{Time: t.Time, Text: t.Text, Ref: refFrom(t.Ref)})
	}
	return out
}

// primaryAddress picks the strongest claim, most recent on ties, and
// never a mere probe.
func primaryAddress(as []device.Address) string {
	rank := map[string]int{device.StateSeen: 1, device.StateObserved: 2, device.StateClaimed: 3, device.StateLeased: 3}
	best := -1
	var bestAddr device.Address
	for _, a := range as {
		r, ok := rank[a.State]
		if !ok {
			continue
		}
		if r > best || (r == best && a.LastSeen.After(bestAddr.LastSeen)) {
			best, bestAddr = r, a
		}
	}
	if best < 0 {
		return ""
	}
	return bestAddr.Addr.String()
}

// ConflictFrom converts a duplicate-claim record.
func ConflictFrom(c device.Conflict) Conflict {
	out := Conflict{Address: c.Addr.String(), MACs: append([]string{}, c.MACs...), FirstSeen: c.FirstSeen, LastSeen: c.LastSeen, Refs: make([]Ref, 0, len(c.Refs))}
	for _, r := range c.Refs {
		out.Refs = append(out.Refs, refFrom(r))
	}
	return out
}

func addresses(as []device.Address) []Address {
	out := make([]Address, 0, len(as))
	for _, a := range as {
		out = append(out, Address{Address: a.Addr.String(), State: a.State, Via: a.Via, FirstSeen: a.FirstSeen, LastSeen: a.LastSeen, Ref: refFrom(a.Ref)})
	}
	return out
}

func refFrom(r device.Ref) Ref {
	return Ref{Source: r.Source, PacketID: r.PacketID}
}

// DeviceEventFrom converts a table event.
func DeviceEventFrom(e device.Event) DeviceEvent {
	out := DeviceEvent{
		Schema: SchemaDeviceEvent,
		Time:   e.Time,
		Change: e.Change,
		Via:    e.Via,
		Method: e.Method,
		Device: DeviceFrom(e.Device),
		Ref:    refFrom(e.Ref),
	}
	if e.Address.IsValid() {
		out.Address = e.Address.String()
	}
	out.VLAN = e.VLAN
	if e.Neighbor != nil {
		n := NeighborFrom(*e.Neighbor)
		out.Neighbor = &n
	}
	if e.Conflict != nil {
		c := ConflictFrom(*e.Conflict)
		out.Conflict = &c
	}
	return out
}

// NeighborFrom converts an LLDP neighbor record.
func NeighborFrom(n device.Neighbor) Neighbor {
	return Neighbor{
		ID:          n.ID,
		ChassisID:   n.ChassisID,
		PortID:      n.PortID,
		SourceMAC:   n.SourceMAC,
		SystemName:  n.SystemName,
		SystemDesc:  n.SystemDesc,
		PortDesc:    n.PortDesc,
		Caps:        emptyList(n.Caps),
		EnabledCaps: emptyList(n.EnabledCaps),
		MgmtAddrs:   emptyList(n.MgmtAddrs),
		PortVLANID:  n.PortVLANID,
		VLANNames:   emptyList(n.VLANNames),
		MaxFrame:    n.MaxFrame,
		TTL:         n.TTL,
		FirstSeen:   n.FirstSeen,
		LastSeen:    n.LastSeen,
		Ref:         refFrom(n.Ref),
	}
}

// DevicesFrom converts a table snapshot.
func DevicesFrom(source string, at time.Time, ouiFile string, ds []device.Device, ns []device.Neighbor, cs []device.Conflict) Devices {
	out := Devices{Schema: SchemaDevices, Source: source, GeneratedAt: at, OUIFile: ouiFile, Devices: make([]Device, 0, len(ds)), Neighbors: make([]Neighbor, 0, len(ns)), Conflicts: make([]Conflict, 0, len(cs))}
	for _, d := range ds {
		out.Devices = append(out.Devices, DeviceFrom(d))
	}
	for _, n := range ns {
		out.Neighbors = append(out.Neighbors, NeighborFrom(n))
	}
	for _, c := range cs {
		out.Conflicts = append(out.Conflicts, ConflictFrom(c))
	}
	return out
}
