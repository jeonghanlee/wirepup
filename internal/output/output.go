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
	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/epics/pva"
	"github.com/jeonghanlee/wirepup/internal/interfaces"
	"github.com/jeonghanlee/wirepup/internal/observation"
	"github.com/jeonghanlee/wirepup/internal/protocol/arp"
	"github.com/jeonghanlee/wirepup/internal/protocol/dhcpv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
	"github.com/jeonghanlee/wirepup/internal/protocol/icmpv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv4"
	"github.com/jeonghanlee/wirepup/internal/protocol/ipv6"
	"github.com/jeonghanlee/wirepup/internal/protocol/lldp"
	"github.com/jeonghanlee/wirepup/internal/protocol/tcp"
)

// Change values of a device event as rendered; they pass through from
// device.Event unchanged, and the renderers compare against these so
// that they depend on this package only.
const (
	ChangeNewDevice   = device.ChangeNewDevice
	ChangeUpdate      = device.ChangeUpdate
	ChangeNewNeighbor = device.ChangeNewNeighbor
	ChangeConflict    = device.ChangeConflict
)

// OperStateUnknown is the interface oper-state sentinel, mirrored from
// internal/interfaces so the text and tui renderers compare against this
// package only.
const OperStateUnknown = interfaces.OperStateUnknown

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
	EPICS       EPICS      `json:"epics"`
}

// EPICS is the controls-protocol view of a capture.
type EPICS struct {
	CAServers   []CAServer  `json:"ca_servers"`
	CASearches  []CASearch  `json:"ca_searches"`
	PVAServers  []PVAServer `json:"pva_servers"`
	PVASearches []PVASearch `json:"pva_searches"`
}

// PVAServer is one PVAccess server identified by GUID.
type PVAServer struct {
	GUID        string    `json:"guid"`
	Address     string    `json:"address"`
	TCPPort     uint16    `json:"tcp_port"`
	Protocol    string    `json:"protocol"`
	MAC         string    `json:"mac,omitempty"`
	PVs         []string  `json:"pvs_answered"`
	Answers     int       `json:"search_answers"`
	Beacons     int       `json:"beacons"`
	ChangeCount uint16    `json:"change_count"`
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	Ref         Ref       `json:"evidence"`
}

// PVASearch is one PVA channel search with its answers.
type PVASearch struct {
	Client     string        `json:"client"`
	ClientMAC  string        `json:"client_mac,omitempty"`
	SequenceID int32         `json:"sequence_id"`
	InstanceID int32         `json:"instance_id"`
	PV         string        `json:"pv"`
	Count      int           `json:"count"`
	FirstSeen  time.Time     `json:"first_seen"`
	LastSeen   time.Time     `json:"last_seen"`
	Answers    []PVAResponse `json:"answers"`
	NotFound   []PVAResponse `json:"not_found"`
	Ref        Ref           `json:"evidence"`
}

// PVAResponse is one PVA server answer.
type PVAResponse struct {
	GUID    string    `json:"guid"`
	Server  string    `json:"server"`
	TCPPort uint16    `json:"tcp_port"`
	MAC     string    `json:"mac,omitempty"`
	At      time.Time `json:"time"`
	Ref     Ref       `json:"evidence"`
}

// PVAFrom converts the PVA state of a table.
func PVAFrom(servers []device.PVAServer, searches []device.PVASearch) ([]PVAServer, []PVASearch) {
	vs := make([]PVAServer, 0, len(servers))
	for _, s := range servers {
		vs = append(vs, PVAServer{GUID: s.GUID, Address: s.Addr.String(), TCPPort: s.TCPPort, Protocol: s.Protocol, MAC: s.MAC, PVs: emptyList(s.PVs), Answers: s.Answers, Beacons: s.Beacons, ChangeCount: s.ChangeCount, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Ref: refFrom(s.Ref)})
	}
	ss := make([]PVASearch, 0, len(searches))
	for _, s := range searches {
		ps := PVASearch{Client: fmt.Sprintf("%s:%d", s.ClientIP, s.ClientPort), ClientMAC: s.ClientMAC, SequenceID: s.SequenceID, InstanceID: s.InstanceID, PV: s.PV, Count: s.Count, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Answers: []PVAResponse{}, NotFound: []PVAResponse{}, Ref: refFrom(s.Ref)}
		for _, r := range s.Responses {
			ps.Answers = append(ps.Answers, PVAResponse{GUID: r.GUID, Server: r.ServerAddr.String(), TCPPort: r.ServerPort, MAC: r.ServerMAC, At: r.At, Ref: refFrom(r.Ref)})
		}
		for _, r := range s.NotFound {
			ps.NotFound = append(ps.NotFound, PVAResponse{GUID: r.GUID, Server: r.ServerAddr.String(), TCPPort: r.ServerPort, MAC: r.ServerMAC, At: r.At, Ref: refFrom(r.Ref)})
		}
		ss = append(ss, ps)
	}
	return vs, ss
}

// CAServer is one Channel Access server seen on the wire.
type CAServer struct {
	Address   string    `json:"address"`
	TCPPort   uint16    `json:"tcp_port"`
	MAC       string    `json:"mac,omitempty"`
	PVs       []string  `json:"pvs_answered"`
	Answers   int       `json:"search_answers"`
	Beacons   int       `json:"beacons"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
	Ref       Ref       `json:"evidence"`
}

// CASearch is one client search with its answers.
type CASearch struct {
	Client    string       `json:"client"`
	ClientMAC string       `json:"client_mac,omitempty"`
	ID        uint32       `json:"search_id"`
	PV        string       `json:"pv"`
	Count     int          `json:"count"`
	FirstSeen time.Time    `json:"first_seen"`
	LastSeen  time.Time    `json:"last_seen"`
	Answers   []CAResponse `json:"answers"`
	NotFound  []CAResponse `json:"not_found"`
	Ref       Ref          `json:"evidence"`
}

// CAResponse is one server answer.
type CAResponse struct {
	Server  string    `json:"server"`
	TCPPort uint16    `json:"tcp_port"`
	MAC     string    `json:"mac,omitempty"`
	At      time.Time `json:"time"`
	Ref     Ref       `json:"evidence"`
}

// EPICSFrom converts the CA state of a table.
func EPICSFrom(servers []device.CAServer, searches []device.CASearch) EPICS {
	out := EPICS{CAServers: make([]CAServer, 0, len(servers)), CASearches: make([]CASearch, 0, len(searches))}
	for _, s := range servers {
		out.CAServers = append(out.CAServers, CAServer{Address: s.Addr.String(), TCPPort: s.TCPPort, MAC: s.MAC, PVs: emptyList(s.PVs), Answers: s.Answers, Beacons: s.Beacons, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Ref: refFrom(s.Ref)})
	}
	for _, s := range searches {
		cs := CASearch{Client: fmt.Sprintf("%s:%d", s.ClientIP, s.ClientPort), ClientMAC: s.ClientMAC, ID: s.ID, PV: s.PV, Count: s.Count, FirstSeen: s.FirstSeen, LastSeen: s.LastSeen, Answers: []CAResponse{}, NotFound: []CAResponse{}, Ref: refFrom(s.Ref)}
		for _, r := range s.Responses {
			cs.Answers = append(cs.Answers, CAResponse{Server: r.ServerIP.String(), TCPPort: r.TCPPort, MAC: r.ServerMAC, At: r.At, Ref: refFrom(r.Ref)})
		}
		for _, r := range s.NotFound {
			cs.NotFound = append(cs.NotFound, CAResponse{Server: r.ServerIP.String(), TCPPort: r.TCPPort, MAC: r.ServerMAC, At: r.At, Ref: refFrom(r.Ref)})
		}
		out.CASearches = append(out.CASearches, cs)
	}
	return out
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
		e.Summary = fmt.Sprintf("lldp %s port %s (%s) vlan %s mgmt %s", Dash(v.SystemName), Dash(v.PortID), Dash(v.PortDescription), vlanText(v.PortVLANID), strings.Join(v.ManagementAddrs, ","))
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
	case tcp.Observation:
		e.Fields["src"] = v.Src.String()
		e.Fields["dst"] = v.Dst.String()
		e.Fields["src_port"] = v.SrcPort
		e.Fields["dst_port"] = v.DstPort
		e.Fields["flags"] = tcp.FlagNames(v.Flags)
		e.Fields["seq"] = v.Seq
		e.Fields["payload_length"] = v.PayloadLen
		e.Summary = fmt.Sprintf("tcp %s:%d -> %s:%d [%s]", v.Src, v.SrcPort, v.Dst, v.DstPort, tcp.FlagNames(v.Flags))
	case ca.Observation:
		e.Fields["command"] = v.CommandName()
		e.Fields["transport"] = v.Transport
		e.Fields["direction"] = v.Direction
		e.Fields["src"] = fmt.Sprintf("%s:%d", v.Src, v.SrcPort)
		e.Fields["dst"] = fmt.Sprintf("%s:%d", v.Dst, v.DstPort)
		e.Fields["data_type"] = v.DataType
		e.Fields["count"] = v.Count
		e.Fields["cid"] = v.CID
		e.Fields["available"] = v.Available
		e.Fields["payload_size"] = v.PayloadSize
		if v.PVName != "" {
			e.Fields["pv"] = v.PVName
		}
		switch v.Kind() {
		case "ca.search":
			e.Fields["search_id"] = v.SearchID
			e.Fields["reply_wanted"] = v.ReplyWanted
			e.Fields["minor_version"] = v.MinorVersion
		case "ca.search_response", "ca.not_found":
			e.Fields["search_id"] = v.SearchID
			e.Fields["server"] = v.ServerIP.String()
			e.Fields["server_tcp_port"] = v.ServerPort
			e.Fields["minor_version"] = v.MinorVersion
		case "ca.beacon":
			e.Fields["server"] = v.ServerIP.String()
			e.Fields["server_tcp_port"] = v.ServerPort
			e.Fields["beacon_id"] = v.BeaconID
			e.Fields["minor_version"] = v.MinorVersion
		case "ca.version":
			e.Fields["minor_version"] = v.MinorVersion
		case "ca.client_name", "ca.host_name":
			e.Fields["text"] = v.Text
		case "ca.create_channel":
			e.Fields["minor_version"] = v.MinorVersion
		case "ca.create_channel_response":
			e.Fields["sid"] = v.SID
		case "ca.access_rights":
			e.Fields["rights"] = v.Rights
		}
		e.Summary = caSummary(v)
	case pva.Observation:
		e.Fields["command"] = v.CommandName()
		e.Fields["control"] = v.Control
		e.Fields["version"] = v.Version
		e.Fields["big_endian"] = v.BigEndian
		e.Fields["transport"] = v.Transport
		e.Fields["direction"] = v.Direction
		e.Fields["src"] = fmt.Sprintf("%s:%d", v.Src, v.SrcPort)
		e.Fields["dst"] = fmt.Sprintf("%s:%d", v.Dst, v.DstPort)
		e.Fields["payload_size"] = v.PayloadSize
		e.Fields["malformed"] = v.Malformed
		switch v.Kind() {
		case "pva.search":
			e.Fields["sequence_id"] = v.SequenceID
			e.Fields["reply_required"] = v.ReplyRequired
			e.Fields["unicast"] = v.Unicast
			e.Fields["protocols"] = emptyList(v.Protocols)
			e.Fields["channels"] = channelList(v.Channels)
		case "pva.search_response":
			e.Fields["sequence_id"] = v.SequenceID
			e.Fields["guid"] = v.GUID
			e.Fields["server"] = v.ServerAddr.String()
			e.Fields["server_tcp_port"] = v.ServerPort
			e.Fields["protocol"] = v.Protocol
			e.Fields["found"] = v.Found
			e.Fields["instance_ids"] = int32List(v.InstanceIDs)
		case "pva.beacon":
			e.Fields["guid"] = v.GUID
			e.Fields["server"] = v.ServerAddr.String()
			e.Fields["server_tcp_port"] = v.ServerPort
			e.Fields["protocol"] = v.Protocol
			e.Fields["beacon_sequence"] = v.BeaconSeq
			e.Fields["change_count"] = v.ChangeCount
		case "pva.validation_request", "pva.validation_response":
			e.Fields["buffer_size"] = v.BufferSize
			e.Fields["registry_max"] = v.RegistryMax
			e.Fields["qos"] = v.QoS
			e.Fields["authnz"] = emptyList(v.AuthNZ)
		case "pva.create_channel":
			e.Fields["channels"] = channelList(v.Channels)
		case "pva.create_channel_response":
			e.Fields["client_channel_id"] = v.ClientChanID
			e.Fields["server_channel_id"] = v.ServerChanID
			e.Fields["status_ok"] = v.StatusOK
		}
		e.Summary = pvaSummary(v)
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
		return fmt.Sprintf("dhcp request %s from %s (%s)", addrOrEmpty(v.RequestedIP), v.ClientMAC, Dash(v.Hostname))
	case dhcpv4.NAK:
		return fmt.Sprintf("dhcp nak to %s from %s", v.ClientMAC, addrOrEmpty(v.ServerID))
	default:
		return fmt.Sprintf("dhcp %s from %s (%s)", v.TypeName(), v.ClientMAC, Dash(v.Hostname))
	}
}

func channelList(cs []pva.Channel) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, fmt.Sprintf("%d:%s", c.ID, c.Name))
	}
	return out
}

func int32List(ids []int32) []int32 {
	if ids == nil {
		return []int32{}
	}
	return ids
}

func pvaSummary(v pva.Observation) string {
	switch v.Kind() {
	case "pva.search":
		return fmt.Sprintf("pva search %s from %s:%d to %s:%d seq %d", strings.Join(channelNames(v.Channels), ","), v.Src, v.SrcPort, v.Dst, v.DstPort, v.SequenceID)
	case "pva.search_response":
		found := "found"
		if !v.Found {
			found = "not found"
		}
		return fmt.Sprintf("pva search response seq %d %s from server %s tcp port %d guid %s to %s:%d", v.SequenceID, found, v.ServerAddr, v.ServerPort, v.GUID, v.Dst, v.DstPort)
	case "pva.beacon":
		return fmt.Sprintf("pva beacon from server %s tcp port %d guid %s seq %d change %d", v.ServerAddr, v.ServerPort, v.GUID, v.BeaconSeq, v.ChangeCount)
	case "pva.create_channel":
		return fmt.Sprintf("pva create channel %s %s:%d -> %s:%d", strings.Join(channelNames(v.Channels), ","), v.Src, v.SrcPort, v.Dst, v.DstPort)
	case "pva.create_channel_response":
		return fmt.Sprintf("pva channel created client %d server %d ok=%v from %s:%d", v.ClientChanID, v.ServerChanID, v.StatusOK, v.Src, v.SrcPort)
	case "pva.validation_request":
		return fmt.Sprintf("pva validation request from server %s:%d authnz %s", v.Src, v.SrcPort, strings.Join(v.AuthNZ, ","))
	case "pva.validation_response":
		return fmt.Sprintf("pva validation response from client %s:%d authnz %s", v.Src, v.SrcPort, strings.Join(v.AuthNZ, ","))
	default:
		return fmt.Sprintf("pva %s %s %s:%d -> %s:%d", v.CommandName(), v.Transport, v.Src, v.SrcPort, v.Dst, v.DstPort)
	}
}

func channelNames(cs []pva.Channel) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Name)
	}
	return out
}

func caSummary(v ca.Observation) string {
	switch v.Kind() {
	case "ca.search":
		return fmt.Sprintf("ca search %s from %s:%d to %s:%d id %d", v.PVName, v.Src, v.SrcPort, v.Dst, v.DstPort, v.SearchID)
	case "ca.search_response":
		return fmt.Sprintf("ca search response id %d from server %s tcp port %d to %s:%d", v.SearchID, v.ServerIP, v.ServerPort, v.Dst, v.DstPort)
	case "ca.not_found":
		return fmt.Sprintf("ca not found id %d from %s to %s:%d", v.SearchID, v.Src, v.Dst, v.DstPort)
	case "ca.beacon":
		return fmt.Sprintf("ca beacon from server %s tcp port %d id %d", v.ServerIP, v.ServerPort, v.BeaconID)
	case "ca.version":
		return fmt.Sprintf("ca version minor %d %s %s:%d -> %s:%d", v.MinorVersion, v.Transport, v.Src, v.SrcPort, v.Dst, v.DstPort)
	case "ca.create_channel":
		return fmt.Sprintf("ca create channel %s cid %d %s:%d -> %s:%d", v.PVName, v.CID, v.Src, v.SrcPort, v.Dst, v.DstPort)
	case "ca.create_channel_response":
		return fmt.Sprintf("ca channel created cid %d sid %d type %d count %d from %s:%d", v.CID, v.SID, v.DataType, v.Count, v.Src, v.SrcPort)
	case "ca.client_name", "ca.host_name":
		return fmt.Sprintf("ca %s %q %s:%d -> %s:%d", v.CommandName(), v.Text, v.Src, v.SrcPort, v.Dst, v.DstPort)
	default:
		return fmt.Sprintf("ca %s %s %s:%d -> %s:%d", v.CommandName(), v.Transport, v.Src, v.SrcPort, v.Dst, v.DstPort)
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
		return fmt.Sprintf("ndp router advertisement from %s prefixes %s", v.Src, Dash(strings.Join(ps, ",")))
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

// Dash returns "-" for an empty string. The dash appears in the JSON
// contract's summary field (docs/output-schema.md), so changing the
// literal is a contract change, not a rendering change; the text and tui
// renderers share this one helper.
func Dash(s string) string {
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
// never a mere probe: a probe ranks like a sighting, so it is skipped
// before ranking.
func primaryAddress(as []device.Address) string {
	best := 0
	var bestAddr device.Address
	for _, a := range as {
		if a.State == device.StateProbing {
			continue
		}
		r := device.Rank(a.State)
		if r == 0 {
			continue
		}
		if r > best || (r == best && a.LastSeen.After(bestAddr.LastSeen)) {
			best, bestAddr = r, a
		}
	}
	if best == 0 {
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
func DevicesFrom(source string, at time.Time, ouiFile string, t *device.Table) Devices {
	ds, ns, cs := t.Devices(), t.Neighbors(), t.Conflicts()
	out := Devices{Schema: SchemaDevices, Source: source, GeneratedAt: at, OUIFile: ouiFile, Devices: make([]Device, 0, len(ds)), Neighbors: make([]Neighbor, 0, len(ns)), Conflicts: make([]Conflict, 0, len(cs)), EPICS: EPICSFrom(t.CAServers(), t.CASearches())}
	out.EPICS.PVAServers, out.EPICS.PVASearches = PVAFrom(t.PVAServers(), t.PVASearches())
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
