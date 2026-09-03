// Package tui renders the live device, event, EPICS, interface, and
// diagnosis views in the terminal using only ANSI escape sequences and
// golang.org/x/term for raw mode and size (ADR-0012). It is a renderer
// over the same output structs as the text and JSON renderers; it owns
// no protocol logic.
package tui

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jeonghanlee/wirepup/internal/output"
)

// View identifiers, in tab order.
const (
	ViewDevices = iota
	ViewEvents
	ViewEPICS
	ViewInterfaces
	ViewDiagnostics
	viewCount
)

var viewNames = []string{"Devices", "Events", "EPICS", "Interfaces", "Diagnostics"}

// Layout constants.
const (
	maxEvents    = 500
	headerRows   = 2
	footerRows   = 1
	timeLayout   = "15:04:05"
	minWidth     = 20
	minHeight    = 5
	unknownValue = "unknown"
)

// Key bytes handled by the loop.
const (
	keyQuit     = 'q'
	keyCtrlC    = 0x03
	keyTab      = 0x09
	keyDown     = 'j'
	keyUp       = 'k'
	keyEscape   = 0x1b
	keyRefresh  = 'r'
	keyPageDown = ' '
)

// Model is the state the views render; it is safe for concurrent
// updates from the capture pipeline.
type Model struct {
	mu         sync.Mutex
	source     string
	view       int
	scroll     [viewCount]int
	events     []output.Event
	devices    output.Devices
	interfaces output.Interfaces
	diagnosis  output.Diagnosis
	stats      string
	updated    time.Time
	quit       bool
}

// New returns an empty model for one source name.
func New(source string) *Model {
	return &Model{source: source}
}

// AddEvent appends one event to the ring.
func (m *Model) AddEvent(e output.Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, e)
	if len(m.events) > maxEvents {
		m.events = m.events[len(m.events)-maxEvents:]
	}
	m.updated = time.Now()
}

// SetDevices replaces the device document.
func (m *Model) SetDevices(d output.Devices) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.devices = d
	m.updated = time.Now()
}

// SetInterfaces replaces the interface document.
func (m *Model) SetInterfaces(d output.Interfaces) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.interfaces = d
}

// SetDiagnosis replaces the diagnosis document.
func (m *Model) SetDiagnosis(d output.Diagnosis) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.diagnosis = d
}

// SetStats sets the footer counters text.
func (m *Model) SetStats(s string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stats = s
}

// Quit reports whether the user asked to leave.
func (m *Model) Quit() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.quit
}

// HandleKey applies one key press and reports whether a redraw is
// needed. Digits select a view, Tab cycles, j/k and space scroll, q
// leaves.
func (m *Model) HandleKey(k byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	switch {
	case k == keyQuit || k == keyCtrlC:
		m.quit = true
	case k == keyTab:
		m.view = (m.view + 1) % viewCount
	case k >= '1' && k <= '0'+viewCount:
		m.view = int(k - '1')
	case k == keyDown:
		m.scroll[m.view]++
	case k == keyUp:
		if m.scroll[m.view] > 0 {
			m.scroll[m.view]--
		}
	case k == keyPageDown:
		m.scroll[m.view] += 10
	case k == keyRefresh:
		m.scroll[m.view] = 0
	default:
		return false
	}
	return true
}

// Render draws the whole screen for the given size as lines of at most
// width characters and exactly height rows.
func (m *Model) Render(width, height int) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if width < minWidth {
		width = minWidth
	}
	if height < minHeight {
		height = minHeight
	}
	body := height - headerRows - footerRows
	lines := make([]string, 0, height)
	lines = append(lines, fit(m.header(), width), fit(strings.Repeat("-", width), width))
	content := m.content()
	off := m.scroll[m.view]
	if off > len(content) {
		off = len(content)
		m.scroll[m.view] = off
	}
	for i := 0; i < body; i++ {
		if off+i < len(content) {
			lines = append(lines, fit(content[off+i], width))
		} else {
			lines = append(lines, fit("", width))
		}
	}
	lines = append(lines, fit(m.footer(len(content), off, body), width))
	return lines
}

func (m *Model) header() string {
	var tabs []string
	for i, n := range viewNames {
		if i == m.view {
			tabs = append(tabs, fmt.Sprintf("[%d %s]", i+1, n))
		} else {
			tabs = append(tabs, fmt.Sprintf(" %d %s ", i+1, n))
		}
	}
	return fmt.Sprintf("WirePup %s  %s", m.source, strings.Join(tabs, " "))
}

func (m *Model) footer(total, off, body int) string {
	pos := ""
	if total > body {
		pos = fmt.Sprintf("  lines %d-%d of %d", off+1, min(off+body, total), total)
	}
	return fmt.Sprintf("q quit  Tab/1-5 view  j/k space scroll  r top%s  %s", pos, m.stats)
}

func (m *Model) content() []string {
	switch m.view {
	case ViewDevices:
		return m.deviceLines()
	case ViewEvents:
		return m.eventLines()
	case ViewEPICS:
		return m.epicsLines()
	case ViewInterfaces:
		return m.interfaceLines()
	default:
		return m.diagnosisLines()
	}
}

func (m *Model) deviceLines() []string {
	lines := []string{fmt.Sprintf("%-18s %-16s %-24s %-8s %-22s %-18s %s", "MAC", "IPv4", "IPv6", "VLAN", "VENDOR (hint)", "PROTOCOLS", "LAST")}
	for _, d := range m.devices.Devices {
		mac := d.MACs[0]
		if d.Local {
			mac += "*"
		}
		lines = append(lines, fmt.Sprintf("%-18s %-16s %-24s %-8s %-22s %-18s %s", mac, dash(d.PrimaryIPv4), dash(d.PrimaryIPv6), d.VLAN, truncate(dash(d.Vendor), 22), truncate(strings.Join(d.Protocols, ","), 18), d.LastSeen.Local().Format(timeLayout)))
	}
	if len(m.devices.Neighbors) > 0 {
		lines = append(lines, "", "NEIGHBORS (LLDP)")
		for _, n := range m.devices.Neighbors {
			vlan := unknownValue
			if n.PortVLANID != 0 {
				vlan = fmt.Sprint(n.PortVLANID)
			}
			lines = append(lines, fmt.Sprintf("%s port %s  port VLAN %s  mgmt %s", dash(n.SystemName), n.PortID, vlan, dash(strings.Join(n.MgmtAddrs, ","))))
		}
	}
	if len(m.devices.Conflicts) > 0 {
		lines = append(lines, "", "ADDRESS CONFLICTS")
		for _, c := range m.devices.Conflicts {
			lines = append(lines, fmt.Sprintf("%s claimed by %s", c.Address, strings.Join(c.MACs, ", ")))
		}
	}
	if len(m.devices.Devices) == 0 {
		lines = append(lines, "(no devices yet)")
	}
	return lines
}

func (m *Model) eventLines() []string {
	lines := make([]string, 0, len(m.events))
	for i := len(m.events) - 1; i >= 0; i-- {
		e := m.events[i]
		lines = append(lines, fmt.Sprintf("%s #%-6d %s", e.Time.Local().Format(timeLayout), e.PacketID, e.Summary))
	}
	if len(lines) == 0 {
		lines = append(lines, "(no events yet)")
	}
	return lines
}

func (m *Model) epicsLines() []string {
	ep := m.devices.EPICS
	lines := []string{"CA SERVERS"}
	for _, s := range ep.CAServers {
		lines = append(lines, fmt.Sprintf("  %s tcp %d  answers %d  beacons %d  PVs %s", s.Address, s.TCPPort, s.Answers, s.Beacons, truncate(dash(strings.Join(s.PVs, ",")), 60)))
	}
	if len(ep.CAServers) == 0 {
		lines = append(lines, "  (none observed)")
	}
	lines = append(lines, "", "PVA SERVERS")
	for _, s := range ep.PVAServers {
		lines = append(lines, fmt.Sprintf("  %s tcp %d  guid %s  answers %d  beacons %d", s.Address, s.TCPPort, s.GUID, s.Answers, s.Beacons))
	}
	if len(ep.PVAServers) == 0 {
		lines = append(lines, "  (none observed)")
	}
	lines = append(lines, "", "SEARCHES (most recent first; no reply is not proof of absence)")
	type row struct {
		t    time.Time
		text string
	}
	var rows []row
	for _, s := range ep.CASearches {
		rows = append(rows, row{s.LastSeen, fmt.Sprintf("  CA  %-30s from %-21s x%-4d answers %d", truncate(s.PV, 30), s.Client, s.Count, len(s.Answers))})
	}
	for _, s := range ep.PVASearches {
		rows = append(rows, row{s.LastSeen, fmt.Sprintf("  PVA %-30s from %-21s x%-4d answers %d", truncate(s.PV, 30), s.Client, s.Count, len(s.Answers))})
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].t.After(rows[j].t) })
	for _, r := range rows {
		lines = append(lines, r.text)
	}
	if len(rows) == 0 {
		lines = append(lines, "  (none observed)")
	}
	return lines
}

func (m *Model) interfaceLines() []string {
	lines := []string{fmt.Sprintf("%-12s %-6s %-18s %-6s %-20s %s", "NAME", "LINK", "MAC", "MTU", "IPv4", "IPv6")}
	for _, i := range m.interfaces.Interfaces {
		link := "down"
		if i.Up {
			link = "up"
		}
		if i.OperState != "" && i.OperState != unknownValue {
			link = i.OperState
		}
		lines = append(lines, fmt.Sprintf("%-12s %-6s %-18s %-6d %-20s %s", i.Name, link, dash(i.MAC), i.MTU, dash(strings.Join(i.IPv4, ",")), dash(strings.Join(i.IPv6, ","))))
	}
	return lines
}

func (m *Model) diagnosisLines() []string {
	var lines []string
	add := func(title string, fs []output.Finding) {
		lines = append(lines, title)
		if len(fs) == 0 {
			lines = append(lines, "  (none)")
		}
		for _, f := range fs {
			lines = append(lines, "  - "+f.Text)
		}
		lines = append(lines, "")
	}
	add("Observed", m.diagnosis.Observed)
	add("Inferred", m.diagnosis.Inferred)
	add("Recommended", m.diagnosis.Recommended)
	add("Executed", m.diagnosis.Executed)
	if !m.diagnosis.GeneratedAt.IsZero() {
		lines = append(lines, "as of "+m.diagnosis.GeneratedAt.Local().Format(timeLayout)+"  (rules run every few seconds; passive only)")
	}
	return lines
}

// Screen writes the rendered lines with ANSI positioning.
func Screen(w io.Writer, lines []string) {
	var b strings.Builder
	b.WriteString("\x1b[H")
	for i, l := range lines {
		b.WriteString(l)
		b.WriteString("\x1b[K")
		if i < len(lines)-1 {
			b.WriteString("\r\n")
		}
	}
	io.WriteString(w, b.String())
}

// Enter and Leave switch the alternate screen and cursor visibility.
const (
	Enter = "\x1b[?1049h\x1b[?25l\x1b[2J"
	Leave = "\x1b[?25h\x1b[?1049l"
)

func fit(s string, width int) string {
	if len(s) > width {
		return s[:width]
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 1 {
		return s[:n]
	}
	return s[:n-1] + "~"
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
