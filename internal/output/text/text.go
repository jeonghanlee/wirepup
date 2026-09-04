// Package text renders output structs for a human reader. Layouts follow
// docs/cli-design.md and the README examples.
package text

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/jeonghanlee/wirepup/internal/output"
)

// Layout constants.
const (
	timeLayout   = "15:04:05.000000"
	tabMinWidth  = 2
	tabPadding   = 2
	labelWidth   = 12
	unknownValue = "unknown"
)

// Interfaces prints the interface table.
func Interfaces(w io.Writer, doc output.Interfaces) error {
	tw := tabwriter.NewWriter(w, tabMinWidth, 0, tabPadding, ' ', 0)
	fmt.Fprintln(tw, "NAME\tLINK\tMAC\tMTU\tIPv4\tIPv6")
	for _, i := range doc.Interfaces {
		link := "down"
		if i.Up {
			link = "up"
		}
		if i.OperState != "" && i.OperState != output.OperStateUnknown {
			link = i.OperState
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", i.Name, link, output.Dash(i.MAC), i.MTU, output.Dash(strings.Join(i.IPv4, ",")), output.Dash(strings.Join(i.IPv6, ",")))
	}
	return tw.Flush()
}

// Event prints one observation line.
func Event(w io.Writer, e output.Event) {
	fmt.Fprintf(w, "%s %s #%d %s\n", e.Time.Local().Format(timeLayout), e.Interface, e.PacketID, e.Summary)
}

// DeviceEvent prints one device change as a labelled block.
func DeviceEvent(w io.Writer, e output.DeviceEvent) {
	var b strings.Builder
	switch e.Change {
	case output.ChangeNewDevice:
		b.WriteString("NEW DEVICE\n")
	case output.ChangeNewNeighbor:
		neighborBlock(&b, e)
		io.WriteString(w, b.String())
		return
	case output.ChangeConflict:
		if e.Conflict != nil {
			b.WriteString("ADDRESS CONFLICT\n")
			line(&b, "Address", e.Conflict.Address)
			line(&b, "Claimed by", strings.Join(e.Conflict.MACs, ", "))
			line(&b, "Evidence", fmt.Sprintf("%s #%d", e.Ref.Source, e.Ref.PacketID))
			b.WriteString("\n")
		}
		io.WriteString(w, b.String())
		return
	default:
		b.WriteString("UPDATE\n")
	}
	mac := strings.Join(e.Device.MACs, ", ")
	if e.Device.MACLocallyAdministered {
		mac += " (locally administered)"
	}
	line(&b, "MAC", mac)
	if len(e.Device.Names) > 0 {
		var names []string
		for _, n := range e.Device.Names {
			names = append(names, n.Value+" ("+n.Via+")")
		}
		line(&b, "Name", strings.Join(names, ", "))
	}
	addr := e.Address
	if addr == "" {
		addr = bestIPv4(e.Device)
	}
	if strings.Contains(addr, ":") {
		line(&b, "IPv6", addr)
	} else {
		line(&b, "IPv4", addr)
	}
	if e.VLAN != 0 {
		line(&b, "VLAN", fmt.Sprintf("%d", e.VLAN))
	} else if e.Change == output.ChangeNewDevice {
		line(&b, "VLAN", e.Device.VLAN)
	}
	if e.Device.Vendor != "" {
		line(&b, "Vendor", e.Device.Vendor+" (hint)")
	}
	line(&b, "Seen via", e.Via)
	if e.Method != "" {
		line(&b, "Method", e.Method)
	}
	line(&b, "Evidence", fmt.Sprintf("%s #%d", e.Ref.Source, e.Ref.PacketID))
	b.WriteString("\n")
	io.WriteString(w, b.String())
}

// Devices prints the device table.
func Devices(w io.Writer, doc output.Devices) error {
	tw := tabwriter.NewWriter(w, tabMinWidth, 0, tabPadding, ' ', 0)
	fmt.Fprintln(tw, "MAC\tIPv4\tIPv6\tVLAN\tVENDOR\tPROTOCOLS\tFIRST\tLAST")
	for _, d := range doc.Devices {
		var v4, v6 []string
		for _, a := range d.IPv4 {
			v4 = append(v4, a.Address+" ("+a.State+")")
		}
		for _, a := range d.IPv6 {
			v6 = append(v6, a.Address+" ("+a.State+")")
		}
		mac := strings.Join(d.MACs, ",")
		if d.Local {
			mac += " (local)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", mac, output.Dash(strings.Join(v4, " ")), output.Dash(strings.Join(v6, " ")), d.VLAN, output.Dash(d.Vendor), output.Dash(strings.Join(d.Protocols, ",")),
			d.FirstSeen.Local().Format(timeLayout), d.LastSeen.Local().Format(timeLayout))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if len(doc.Conflicts) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "ADDRESS CONFLICTS")
		for _, c := range doc.Conflicts {
			fmt.Fprintf(w, "%s claimed by %s\n", c.Address, strings.Join(c.MACs, ", "))
		}
	}
	if len(doc.EPICS.CAServers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CA SERVERS")
		tw = tabwriter.NewWriter(w, tabMinWidth, 0, tabPadding, ' ', 0)
		fmt.Fprintln(tw, "SERVER\tTCP PORT\tMAC\tANSWERS\tBEACONS\tPVs ANSWERED")
		for _, s := range doc.EPICS.CAServers {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%d\t%d\t%s\n", s.Address, s.TCPPort, output.Dash(s.MAC), s.Answers, s.Beacons, output.Dash(strings.Join(s.PVs, ",")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if len(doc.EPICS.PVAServers) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "PVA SERVERS")
		tw = tabwriter.NewWriter(w, tabMinWidth, 0, tabPadding, ' ', 0)
		fmt.Fprintln(tw, "SERVER\tTCP PORT\tGUID\tMAC\tANSWERS\tBEACONS\tPVs ANSWERED")
		for _, s := range doc.EPICS.PVAServers {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%d\t%d\t%s\n", s.Address, s.TCPPort, s.GUID, output.Dash(s.MAC), s.Answers, s.Beacons, output.Dash(strings.Join(s.PVs, ",")))
		}
		if err := tw.Flush(); err != nil {
			return err
		}
	}
	if unanswered := unansweredPVASearches(doc.EPICS.PVASearches); len(unanswered) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "PVA SEARCHES WITHOUT OBSERVED RESPONSE (absence of a reply is not proof the PV does not exist)")
		for _, s := range unanswered {
			fmt.Fprintf(w, "%s from %s (x%d)\n", s.PV, s.Client, s.Count)
		}
	}
	if unanswered := unansweredSearches(doc.EPICS.CASearches); len(unanswered) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "CA SEARCHES WITHOUT OBSERVED RESPONSE (absence of a reply is not proof the PV does not exist)")
		for _, s := range unanswered {
			fmt.Fprintf(w, "%s from %s (x%d)\n", s.PV, s.Client, s.Count)
		}
	}
	if len(doc.Neighbors) == 0 {
		return nil
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "NEIGHBORS (LLDP)")
	tw = tabwriter.NewWriter(w, tabMinWidth, 0, tabPadding, ' ', 0)
	fmt.Fprintln(tw, "SYSTEM\tPORT\tPORT VLAN\tMGMT\tCHASSIS")
	for _, n := range doc.Neighbors {
		vlan := unknownValue
		if n.PortVLANID != 0 {
			vlan = fmt.Sprintf("%d", n.PortVLANID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", output.Dash(n.SystemName), n.PortID, vlan, output.Dash(strings.Join(n.MgmtAddrs, ",")), n.ChassisID)
	}
	return tw.Flush()
}

func neighborBlock(b *strings.Builder, e output.DeviceEvent) {
	n := e.Neighbor
	if n == nil {
		return
	}
	b.WriteString("NETWORK NEIGHBOR (LLDP)\n")
	line(b, "System", output.Dash(n.SystemName))
	line(b, "Chassis", n.ChassisID)
	line(b, "Port", n.PortID)
	if n.PortDesc != "" {
		line(b, "Port desc", n.PortDesc)
	}
	if len(n.MgmtAddrs) > 0 {
		line(b, "Mgmt addr", strings.Join(n.MgmtAddrs, ", "))
	}
	vlan := unknownValue
	if n.PortVLANID != 0 {
		vlan = fmt.Sprintf("%d", n.PortVLANID)
	}
	line(b, "Port VLAN", vlan)
	if len(n.VLANNames) > 0 {
		line(b, "VLANs", strings.Join(n.VLANNames, ", "))
	}
	if len(n.Caps) > 0 {
		line(b, "Caps", strings.Join(n.Caps, ",")+" (enabled: "+output.Dash(strings.Join(n.EnabledCaps, ","))+")")
	}
	line(b, "Evidence", fmt.Sprintf("%s #%d", e.Ref.Source, e.Ref.PacketID))
	b.WriteString("\n")
}

// Diagnosis prints the four sections in order with evidence references.
func Diagnosis(w io.Writer, d output.Diagnosis) {
	if d.Target != "" {
		seen := "not observed"
		if d.TargetSeen {
			seen = "observed"
		}
		fmt.Fprintf(w, "Target %s: %s on %s\n\n", d.Target, seen, d.Interface)
	}
	passive := len(d.Executed) == 0
	if passive {
		section(w, "Observed", d.Observed)
		section(w, "Inferred", d.Inferred)
		section(w, "Recommended", d.Recommended)
		fmt.Fprintln(w, "Executed")
		fmt.Fprintln(w, "  (none: no host network configuration is changed without an explicit connect command)")
		return
	}
	if len(d.Observed)+len(d.Inferred)+len(d.Recommended) > 0 {
		section(w, "Observed", d.Observed)
		section(w, "Inferred", d.Inferred)
		section(w, "Recommended", d.Recommended)
	}
	section(w, "Executed", d.Executed)
}

func section(w io.Writer, title string, fs []output.Finding) {
	fmt.Fprintln(w, title)
	if len(fs) == 0 {
		fmt.Fprintln(w, "  (none)")
		fmt.Fprintln(w)
		return
	}
	for _, f := range fs {
		fmt.Fprintf(w, "  - %s%s\n", f.Text, refs(f.Evidence))
	}
	fmt.Fprintln(w)
}

func refs(rs []output.Ref) string {
	if len(rs) == 0 {
		return ""
	}
	var parts []string
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("#%d", r.PacketID))
	}
	return "  [" + rs[0].Source + " " + strings.Join(parts, ",") + "]"
}

func unansweredPVASearches(ss []output.PVASearch) []output.PVASearch {
	var out []output.PVASearch
	for _, s := range ss {
		if len(s.Answers) == 0 {
			out = append(out, s)
		}
	}
	return out
}

func unansweredSearches(ss []output.CASearch) []output.CASearch {
	var out []output.CASearch
	for _, s := range ss {
		if len(s.Answers) == 0 {
			out = append(out, s)
		}
	}
	return out
}

// EPICSEvent prints a CA observation as the labelled block used by the
// epics observe command (README examples).
func EPICSEvent(w io.Writer, e output.Event) {
	var b strings.Builder
	f := e.Fields
	str := func(k string) string { return fmt.Sprint(f[k]) }
	switch e.Kind {
	case "ca.search":
		b.WriteString("CA SEARCH\n")
		line(&b, "Client", str("src"))
		line(&b, "Destination", str("dst"))
		line(&b, "PV", str("pv"))
		line(&b, "Search ID", str("search_id"))
	case "ca.search_response":
		b.WriteString("CA SEARCH RESPONSE\n")
		line(&b, "Server", str("server"))
		line(&b, "TCP port", str("server_tcp_port"))
		line(&b, "Client", str("dst"))
		line(&b, "Search ID", str("search_id"))
	case "ca.beacon":
		b.WriteString("CA BEACON\n")
		line(&b, "Server", str("server"))
		line(&b, "TCP port", str("server_tcp_port"))
		line(&b, "Beacon ID", str("beacon_id"))
	case "ca.not_found":
		b.WriteString("CA NOT FOUND\n")
		line(&b, "Server", str("server"))
		line(&b, "Client", str("dst"))
		line(&b, "Search ID", str("search_id"))
	case "pva.search":
		b.WriteString("PVA SEARCH\n")
		line(&b, "Client", str("src"))
		line(&b, "Destination", str("dst"))
		if cs, ok := f["channels"].([]string); ok {
			line(&b, "PV", strings.Join(cs, ", "))
		}
		line(&b, "Sequence", str("sequence_id"))
	case "pva.search_response":
		b.WriteString("PVA SEARCH RESPONSE\n")
		line(&b, "Server", str("server"))
		line(&b, "TCP port", str("server_tcp_port"))
		line(&b, "GUID", str("guid"))
		line(&b, "Found", str("found"))
		line(&b, "Client", str("dst"))
		line(&b, "Sequence", str("sequence_id"))
	case "pva.beacon":
		b.WriteString("PVA BEACON\n")
		line(&b, "Server", str("server"))
		line(&b, "TCP port", str("server_tcp_port"))
		line(&b, "GUID", str("guid"))
		line(&b, "Change count", str("change_count"))
	default:
		b.WriteString(strings.ToUpper(strings.ReplaceAll(e.Kind, "_", " ")) + "\n")
		line(&b, "Summary", e.Summary)
	}
	line(&b, "Time", e.Time.Local().Format(timeLayout))
	line(&b, "Evidence", fmt.Sprintf("%s #%d (%s)", e.Source, e.PacketID, e.Confidence))
	b.WriteString("\n")
	io.WriteString(w, b.String())
}

func bestIPv4(d output.Device) string {
	if d.PrimaryIPv4 != "" {
		return d.PrimaryIPv4
	}
	if d.PrimaryIPv6 != "" {
		return d.PrimaryIPv6
	}
	return unknownValue
}

func line(b *strings.Builder, label, value string) {
	fmt.Fprintf(b, "%-*s %s\n", labelWidth, label, value)
}
