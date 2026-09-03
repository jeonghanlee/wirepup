// Package output defines the result structs shared by every renderer
// (text, JSON, TUI). The JSON shape is a versioned public contract
// (ADR-0009): internal types are converted here and never marshalled
// directly.
package output

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/jeonghanlee/wirepup/internal/device"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

// Schema identifiers; the major number changes only on a breaking change.
const (
	SchemaInterfaces  = "wirepup/interfaces/1"
	SchemaEvent       = "wirepup/event/1"
	SchemaDeviceEvent = "wirepup/device-event/1"
	SchemaDevices     = "wirepup/devices/1"
)

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
	Schema  string    `json:"schema"`
	Time    time.Time `json:"time"`
	Change  string    `json:"change"`
	Via     string    `json:"via"`
	Method  string    `json:"method,omitempty"`
	Address string    `json:"address,omitempty"`
	Device  Device    `json:"device"`
	Ref     Ref       `json:"evidence"`
}

// Devices is the document for the discover command.
type Devices struct {
	Schema      string    `json:"schema"`
	Source      string    `json:"source"`
	GeneratedAt time.Time `json:"generated_at"`
	Devices     []Device  `json:"devices"`
}

// Device is one inferred device.
type Device struct {
	ID         string          `json:"id"`
	MACs       []string        `json:"macs"`
	Vendor     string          `json:"vendor_hint,omitempty"`
	IPv4       []Address       `json:"ipv4"`
	IPv6       []Address       `json:"ipv6"`
	Names      []Name          `json:"names"`
	Protocols  []string        `json:"protocols"`
	FirstSeen  time.Time       `json:"first_seen"`
	LastSeen   time.Time       `json:"last_seen"`
	Local      bool            `json:"local"`
	Confidence string          `json:"confidence"`
	Timeline   []TimelineEntry `json:"timeline"`
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
	default:
		e.Summary = string(o.Kind())
	}
	return e
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
		ID:         d.ID,
		MACs:       append([]string{}, d.MACs...),
		Vendor:     d.Vendor,
		IPv4:       addresses(d.IPv4),
		IPv6:       addresses(d.IPv6),
		Names:      make([]Name, 0, len(d.Names)),
		Protocols:  append([]string{}, d.Protocols...),
		FirstSeen:  d.FirstSeen,
		LastSeen:   d.LastSeen,
		Local:      d.Local,
		Confidence: string(d.Confidence),
		Timeline:   make([]TimelineEntry, 0, len(d.Timeline)),
	}
	for _, n := range d.Names {
		out.Names = append(out.Names, Name{Value: n.Value, Via: n.Via, Ref: refFrom(n.Ref)})
	}
	for _, t := range d.Timeline {
		out.Timeline = append(out.Timeline, TimelineEntry{Time: t.Time, Text: t.Text, Ref: refFrom(t.Ref)})
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
	return out
}

// DevicesFrom converts a table snapshot.
func DevicesFrom(source string, at time.Time, ds []device.Device) Devices {
	out := Devices{Schema: SchemaDevices, Source: source, GeneratedAt: at, Devices: make([]Device, 0, len(ds))}
	for _, d := range ds {
		out.Devices = append(out.Devices, DeviceFrom(d))
	}
	return out
}
