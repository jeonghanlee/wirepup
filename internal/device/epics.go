package device

import (
	"fmt"
	"net/netip"
	"sort"
	"time"

	"github.com/jeonghanlee/wirepup/internal/epics/ca"
	"github.com/jeonghanlee/wirepup/internal/protocol/ethernet"
)

// Protocol labels for EPICS roles.
const (
	ProtoCAClient = "ca-client"
	ProtoCAServer = "ca-server"
)

// maxSearches bounds the search table so a busy client cannot grow it
// without limit; the oldest entries are dropped first.
const maxSearches = 10000

// CASearch is one client search and the responses it received.
type CASearch struct {
	ClientIP   netip.Addr
	ClientPort uint16
	ClientMAC  string
	ID         uint32
	PV         string
	Count      int
	FirstSeen  time.Time
	LastSeen   time.Time
	Responses  []CAResponse
	NotFound   []CAResponse
	Ref        Ref
}

// CAResponse is one server answer to a search.
type CAResponse struct {
	ServerIP  netip.Addr
	ServerMAC string
	TCPPort   uint16
	At        time.Time
	Ref       Ref
}

// CAServer is a server seen answering searches or sending beacons.
type CAServer struct {
	Addr      netip.Addr
	TCPPort   uint16
	MAC       string
	PVs       []string
	Answers   int
	Beacons   int
	BeaconID  uint32
	FirstSeen time.Time
	LastSeen  time.Time
	Ref       Ref
}

// caState is the CA correlation state inside the table.
type caState struct {
	searches map[string]*CASearch
	sorder   []*CASearch
	servers  map[string]*CAServer
	vorder   []*CAServer
}

func newCAState() *caState {
	return &caState{searches: map[string]*CASearch{}, servers: map[string]*CAServer{}}
}

// CASearches returns copies of the tracked searches in order.
func (t *Table) CASearches() []CASearch {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]CASearch, 0, len(t.ca.sorder))
	for _, s := range t.ca.sorder {
		c := *s
		c.Responses = append([]CAResponse(nil), s.Responses...)
		c.NotFound = append([]CAResponse(nil), s.NotFound...)
		out = append(out, c)
	}
	return out
}

// CAServers returns copies of the servers seen.
func (t *Table) CAServers() []CAServer {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]CAServer, 0, len(t.ca.vorder))
	for _, s := range t.ca.vorder {
		c := *s
		c.PVs = append([]string(nil), s.PVs...)
		out = append(out, c)
	}
	return out
}

func searchKey(client netip.Addr, id uint32) string {
	return fmt.Sprintf("%s|%d", client, id)
}

func serverKey(addr netip.Addr, port uint16) string {
	return fmt.Sprintf("%s:%d", addr, port)
}

// applyCA folds one CA observation into the device and EPICS state.
func (t *Table) applyCA(frame *ethernet.Observation, v ca.Observation) []Event {
	ref := RefOf(v.Evidence)
	var events []Event
	var mac string
	var dev *Device
	if frame != nil && validKey(frame.Source) {
		mac = frame.Source.String()
		var ev []Event
		dev, ev = t.touch(mac, v.Timestamp, ViaEthernet, ref)
		events = append(events, ev...)
	}
	switch v.Kind() {
	case "ca.search":
		if dev != nil {
			addProtocol(dev, ProtoCAClient)
		}
		if v.PVName == "" {
			return events
		}
		key := searchKey(v.Src, v.SearchID)
		s, ok := t.ca.searches[key]
		if !ok {
			s = &CASearch{ClientIP: v.Src, ClientPort: v.SrcPort, ClientMAC: mac, ID: v.SearchID, PV: v.PVName, FirstSeen: v.Timestamp, Ref: ref}
			t.ca.searches[key] = s
			t.ca.sorder = append(t.ca.sorder, s)
			if len(t.ca.sorder) > maxSearches {
				old := t.ca.sorder[0]
				delete(t.ca.searches, searchKey(old.ClientIP, old.ID))
				t.ca.sorder = t.ca.sorder[1:]
			}
		}
		s.Count++
		s.LastSeen = v.Timestamp
	case "ca.search_response", "ca.not_found":
		srv := t.caServer(v.ServerIP, v.ServerPort, mac, v.Timestamp, ref)
		if dev != nil {
			addProtocol(dev, ProtoCAServer)
			if v.Transport == "udp" {
				events = append(events, t.addAddress(dev, v.Src, StateObserved, "CA "+v.CommandName(), "", v.Timestamp, ref)...)
			}
		}
		resp := CAResponse{ServerIP: v.ServerIP, ServerMAC: mac, TCPPort: v.ServerPort, At: v.Timestamp, Ref: ref}
		if s, ok := t.ca.searches[searchKey(v.Dst, v.SearchID)]; ok {
			if v.Kind() == "ca.search_response" {
				s.Responses = append(s.Responses, resp)
				srv.Answers++
				addUnique(&srv.PVs, s.PV)
			} else {
				s.NotFound = append(s.NotFound, resp)
			}
		} else if v.Kind() == "ca.search_response" {
			srv.Answers++
		}
	case "ca.beacon":
		srv := t.caServer(v.ServerIP, v.ServerPort, mac, v.Timestamp, ref)
		srv.Beacons++
		srv.BeaconID = v.BeaconID
		if dev != nil {
			addProtocol(dev, ProtoCAServer)
			events = append(events, t.addAddress(dev, v.Src, StateObserved, "CA beacon", "", v.Timestamp, ref)...)
		}
	case "ca.create_channel":
		if dev != nil {
			addProtocol(dev, ProtoCAClient)
		}
	case "ca.create_channel_response", "ca.access_rights":
		if dev != nil {
			addProtocol(dev, ProtoCAServer)
		}
	}
	return events
}

func (t *Table) caServer(addr netip.Addr, port uint16, mac string, at time.Time, ref Ref) *CAServer {
	key := serverKey(addr, port)
	s, ok := t.ca.servers[key]
	if !ok {
		s = &CAServer{Addr: addr, TCPPort: port, MAC: mac, FirstSeen: at, Ref: ref}
		t.ca.servers[key] = s
		t.ca.vorder = append(t.ca.vorder, s)
	}
	if s.MAC == "" {
		s.MAC = mac
	}
	s.LastSeen = at
	return s
}

func addUnique(list *[]string, v string) {
	for _, x := range *list {
		if x == v {
			return
		}
	}
	*list = append(*list, v)
	sort.Strings(*list)
}
