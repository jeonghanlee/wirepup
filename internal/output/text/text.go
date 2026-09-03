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
	labelWidth   = 10
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
		if i.OperState != "" && i.OperState != unknownValue {
			link = i.OperState
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\t%s\n", i.Name, link, dash(i.MAC), i.MTU, dash(strings.Join(i.IPv4, ",")), dash(strings.Join(i.IPv6, ",")))
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
	case "new_device":
		b.WriteString("NEW DEVICE\n")
	case "new_neighbor":
		neighborBlock(&b, e)
		io.WriteString(w, b.String())
		return
	case "address_conflict":
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
	} else if e.Change == "new_device" {
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", mac, dash(strings.Join(v4, " ")), dash(strings.Join(v6, " ")), d.VLAN, dash(d.Vendor), dash(strings.Join(d.Protocols, ",")),
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
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", dash(n.SystemName), n.PortID, vlan, dash(strings.Join(n.MgmtAddrs, ",")), n.ChassisID)
	}
	return tw.Flush()
}

func neighborBlock(b *strings.Builder, e output.DeviceEvent) {
	n := e.Neighbor
	if n == nil {
		return
	}
	b.WriteString("NETWORK NEIGHBOR (LLDP)\n")
	line(b, "System", dash(n.SystemName))
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
		line(b, "Caps", strings.Join(n.Caps, ",")+" (enabled: "+dash(strings.Join(n.EnabledCaps, ","))+")")
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
	section(w, "Observed", d.Observed)
	section(w, "Inferred", d.Inferred)
	section(w, "Recommended", d.Recommended)
	section(w, "Executed", d.Executed)
	fmt.Fprintln(w, "No host network configuration is changed without an explicit connect command.")
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

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
