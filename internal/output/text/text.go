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
	default:
		b.WriteString("UPDATE\n")
	}
	line(&b, "MAC", strings.Join(e.Device.MACs, ", "))
	addr := e.Address
	if addr == "" {
		addr = bestIPv4(e.Device)
	}
	line(&b, "IPv4", addr)
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
	fmt.Fprintln(tw, "MAC\tIPv4\tVENDOR\tPROTOCOLS\tFIRST\tLAST")
	for _, d := range doc.Devices {
		var v4 []string
		for _, a := range d.IPv4 {
			v4 = append(v4, a.Address+" ("+a.State+")")
		}
		mac := strings.Join(d.MACs, ",")
		if d.Local {
			mac += " (local)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", mac, dash(strings.Join(v4, " ")), dash(d.Vendor), dash(strings.Join(d.Protocols, ",")),
			d.FirstSeen.Local().Format(timeLayout), d.LastSeen.Local().Format(timeLayout))
	}
	return tw.Flush()
}

func bestIPv4(d output.Device) string {
	for _, a := range d.IPv4 {
		if a.State != "probing" {
			return a.Address
		}
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
