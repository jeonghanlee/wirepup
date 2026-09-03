package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/output"
)

func TestRenderShapeAndViews(t *testing.T) {
	m := New("enp3s0")
	m.SetDevices(output.Devices{Devices: []output.Device{{ID: "00:80:f4:12:34:56", MACs: []string{"00:80:f4:12:34:56"}, PrimaryIPv4: "10.20.30.42", VLAN: "unknown", Vendor: "A Very Long Vendor Name That Overflows", Protocols: []string{"arp", "dhcp"}, LastSeen: time.Now()}}})
	m.SetInterfaces(output.Interfaces{Interfaces: []output.Interface{{Name: "enp3s0", Up: true, OperState: "up", MAC: "00:11:22:33:44:55", MTU: 1500, IPv4: []string{"10.20.30.51/24"}}}})
	m.SetDiagnosis(output.Diagnosis{Observed: []output.Finding{{Text: "local enp3s0 IPv4 = 10.20.30.51/24"}}, GeneratedAt: time.Now()})
	for i := 0; i < 20; i++ {
		m.AddEvent(output.Event{PacketID: uint64(i + 1), Time: time.Now(), Summary: "arp request who-has 10.20.30.1"})
	}
	m.SetStats("42 packets")
	for view := 0; view < viewCount; view++ {
		m.HandleKey(byte('1' + view))
		lines := m.Render(60, 12)
		if len(lines) != 12 {
			t.Fatalf("view %d: %d lines", view, len(lines))
		}
		for _, l := range lines {
			if len(l) > 60 {
				t.Fatalf("view %d: line too long: %q", view, l)
			}
		}
		if wide := m.Render(120, 12); !strings.Contains(wide[0], "["+string(rune('1'+view))) {
			t.Fatalf("view %d header %q", view, wide[0])
		}
	}
	m.HandleKey('1')
	lines := m.Render(120, 12)
	if !strings.Contains(lines[2], "MAC") || !strings.Contains(lines[3], "10.20.30.42") || !strings.Contains(lines[3], "A Very Long Vendor Na~") {
		t.Fatalf("devices view %q %q", lines[2], lines[3])
	}
	if !strings.Contains(lines[11], "42 packets") {
		t.Fatalf("footer %q", lines[11])
	}
}

func TestScrollAndQuit(t *testing.T) {
	m := New("x")
	for i := 0; i < 30; i++ {
		m.AddEvent(output.Event{PacketID: uint64(i + 1), Time: time.Now(), Summary: "e"})
	}
	m.HandleKey('2')
	m.HandleKey(keyDown)
	m.HandleKey(keyDown)
	lines := m.Render(40, 8)
	if !strings.Contains(lines[2], "#28") {
		t.Fatalf("scrolled first line %q", lines[2])
	}
	m.HandleKey(keyPageDown)
	m.HandleKey(keyPageDown)
	m.HandleKey(keyPageDown)
	if !strings.Contains(m.Render(80, 8)[7], "of 30") {
		t.Fatalf("footer %q", m.Render(80, 8)[7])
	}
	m.HandleKey(keyRefresh)
	if !strings.Contains(m.Render(40, 8)[2], "#30") {
		t.Fatal("refresh did not scroll to top")
	}
	if m.HandleKey('z') {
		t.Fatal("unknown key reported a redraw")
	}
	m.HandleKey(keyTab)
	if !strings.Contains(m.Render(80, 8)[0], "[3 EPICS]") {
		t.Fatal("tab did not advance the view")
	}
	m.HandleKey(keyQuit)
	if !m.Quit() {
		t.Fatal("quit")
	}
}

func TestEventRingIsBounded(t *testing.T) {
	m := New("x")
	for i := 0; i < maxEvents+50; i++ {
		m.AddEvent(output.Event{PacketID: uint64(i + 1)})
	}
	if len(m.events) != maxEvents || m.events[0].PacketID != 51 {
		t.Fatalf("ring %d first %d", len(m.events), m.events[0].PacketID)
	}
}

func TestScreenUsesCarriageReturns(t *testing.T) {
	var b strings.Builder
	Screen(&b, []string{"a", "b"})
	if b.String() != "\x1b[Ha\x1b[K\r\nb\x1b[K" {
		t.Fatalf("%q", b.String())
	}
}
