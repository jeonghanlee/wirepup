//go:build linux

package networkcfg

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// boundaryManager runs the production Manager with temporary session storage
// and a nonexistent executable. These tests check guards and read-only kernel
// inspection, never a successful ip mutation or a simulated lifecycle.
func boundaryManager(t *testing.T) (*Manager, Entry) {
	t.Helper()
	m := New("test")
	m.Path = filepath.Join(t.TempDir(), "session.json")
	m.IPPath = filepath.Join(t.TempDir(), "missing-ip")
	ifi, err := net.InterfaceByName(loopback(t))
	if err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParsePrefix("192.0.2.254/32")
	e := Entry{
		Interface: ifi.Name, Index: ifi.Index, Address: addr, Label: Label(ifi.Name),
		AddedAt: time.Now(), Version: m.Version,
		Argv: append([]string{m.IPPath}, AddArgv(ifi.Name, addr)...),
	}
	return m, e
}

func saveBoundarySession(t *testing.T, m *Manager, entries ...Entry) []byte {
	t.Helper()
	if err := m.save(Session{Version: SessionVersion, Entries: entries}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func assertSessionUnchanged(t *testing.T, m *Manager, before []byte) {
	t.Helper()
	after, err := os.ReadFile(m.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("session changed: err=%v before=%s after=%s", err, before, after)
	}
}

func TestAddContextKnownStartFailurePreservesOtherEntries(t *testing.T) {
	m, other := boundaryManager(t)
	saveBoundarySession(t, m, other)
	entry, err := m.AddContext(context.Background(), other.Interface, netip.MustParsePrefix("192.0.2.253/32"))
	if !errors.Is(err, os.ErrNotExist) || errors.Is(err, ErrOutcomeUnknown) || entry.Address.IsValid() {
		t.Fatalf("start failure: entry=%+v err=%v", entry, err)
	}
	s, err := m.Load()
	if err != nil || s.Version != SessionVersion || len(s.Entries) != 1 || !sameEntry(s.Entries[0], other) {
		t.Fatalf("unrelated entry changed: session=%+v err=%v", s, err)
	}
}

func TestAddRefusesExistingRecordIncludingDifferentPrefix(t *testing.T) {
	for _, prefix := range []string{"192.0.2.254/32", "192.0.2.254/24"} {
		t.Run(prefix, func(t *testing.T) {
			m, e := boundaryManager(t)
			before := saveBoundarySession(t, m, e)
			entry, err := m.Add(e.Interface, netip.MustParsePrefix(prefix))
			if !errors.Is(err, ErrAlreadyRecorded) || entry.Address.IsValid() {
				t.Fatalf("duplicate add: entry=%+v err=%v", entry, err)
			}
			assertSessionUnchanged(t, m, before)
		})
	}
}

func TestCancelledOperationsDoNotWriteSession(t *testing.T) {
	m, e := boundaryManager(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	entry, err := m.AddContext(ctx, e.Interface, e.Address)
	if !errors.Is(err, context.Canceled) || entry.Address.IsValid() {
		t.Fatalf("cancelled add: entry=%+v err=%v", entry, err)
	}
	if ran, err := m.RemoveOwned(ctx, e); ran || !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled cleanup: ran=%v err=%v", ran, err)
	}
	for _, path := range []string{m.Path, m.Path + ".lock"} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("cancelled operation wrote %s: %v", path, err)
		}
	}
}

func TestRemoveOwnedPreservesReplacementRecord(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Entry)
	}{
		{"interface", func(e *Entry) { e.Interface = "wp-absent" }},
		{"index", func(e *Entry) { e.Index++ }},
		{"prefix", func(e *Entry) { e.Address = netip.PrefixFrom(e.Address.Addr(), 24) }},
		{"label", func(e *Entry) { e.Label = "different" }},
		{"time", func(e *Entry) { e.AddedAt = e.AddedAt.Add(time.Nanosecond) }},
		{"version", func(e *Entry) { e.Version = "another" }},
		{"argv-path", func(e *Entry) { e.Argv[0] = "/another/ip" }},
		{"argv-value", func(e *Entry) { e.Argv[len(e.Argv)-1] = "different" }},
		{"argv-length", func(e *Entry) { e.Argv = e.Argv[:len(e.Argv)-1] }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, e := boundaryManager(t)
			replacement := e
			replacement.Argv = slices.Clone(e.Argv)
			tc.change(&replacement)
			before := saveBoundarySession(t, m, replacement)
			if ran, err := m.RemoveOwned(context.Background(), e); ran || !errors.Is(err, ErrOwnershipChanged) {
				t.Fatalf("replacement: ran=%v err=%v", ran, err)
			}
			assertSessionUnchanged(t, m, before)
		})
	}
}

func TestRemoveOwnedAbsentAddressRoundTripAndIdempotence(t *testing.T) {
	m, e := boundaryManager(t)
	if Present(e) {
		t.Skip("boundary address is configured on loopback")
	}
	other := e
	other.Address = netip.MustParsePrefix("192.0.2.253/32")
	other.Argv = append([]string{m.IPPath}, AddArgv(other.Interface, other.Address)...)
	saveBoundarySession(t, m, e, other)
	// The supplied timestamp keeps its monotonic component while Load
	// returns the persisted instant. Raw time.Time equality would fail here.
	if ran, err := m.RemoveOwned(context.Background(), e); ran || err != nil {
		t.Fatalf("absent address: ran=%v err=%v", ran, err)
	}
	before, err := os.ReadFile(m.Path)
	if err != nil {
		t.Fatal(err)
	}
	s, err := m.Load()
	if err != nil || len(s.Entries) != 1 || !sameEntry(s.Entries[0], other) {
		t.Fatalf("other entry changed: session=%+v err=%v", s, err)
	}
	if ran, err := m.RemoveOwned(context.Background(), e); ran || err != nil {
		t.Fatalf("repeated cleanup: ran=%v err=%v", ran, err)
	}
	assertSessionUnchanged(t, m, before)
}

func TestRemoveOwnedMissingRecordProtectsLiveAddress(t *testing.T) {
	m, e := boundaryManager(t)
	e.Address = netip.MustParsePrefix("127.0.0.1/8")
	e.Label = ""
	if !Present(e) {
		t.Skip("loopback without 127.0.0.1/8")
	}
	if ran, err := m.RemoveOwned(context.Background(), e); ran || !errors.Is(err, ErrNotRecorded) {
		t.Fatalf("unrecorded live address: ran=%v err=%v", ran, err)
	}
}

func TestRemoveOwnedLiveIdentityMismatchRetainsRecord(t *testing.T) {
	for _, field := range []string{"index", "prefix", "label"} {
		t.Run(field, func(t *testing.T) {
			m, e := boundaryManager(t)
			e.Address = netip.MustParsePrefix("127.0.0.1/8")
			e.Label = ""
			if !Present(e) {
				t.Skip("loopback without 127.0.0.1/8")
			}
			switch field {
			case "index":
				e.Index++
			case "prefix":
				e.Address = netip.MustParsePrefix("127.0.0.1/32")
			case "label":
				e.Label = Label(e.Interface)
			}
			before := saveBoundarySession(t, m, e)
			if ran, err := m.RemoveOwned(context.Background(), e); ran || !errors.Is(err, ErrOwnershipChanged) {
				t.Fatalf("live mismatch: ran=%v err=%v", ran, err)
			}
			assertSessionUnchanged(t, m, before)
		})
	}
}

func TestSessionContentionRespectsContext(t *testing.T) {
	m, e := boundaryManager(t)
	before := saveBoundarySession(t, m, e)
	lock, err := m.lock(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	other := New(m.Version)
	other.Path, other.IPPath = m.Path, m.IPPath
	for _, operation := range []string{"add", "cleanup"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
			defer cancel()
			start := time.Now()
			var err error
			if operation == "add" {
				_, err = other.AddContext(ctx, e.Interface, e.Address)
			} else {
				_, err = other.RemoveOwned(ctx, e)
			}
			if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
				t.Fatalf("contended operation: elapsed=%v err=%v", time.Since(start), err)
			}
			assertSessionUnchanged(t, m, before)
		})
	}
}

func TestUnsupportedSessionVersionIsNotRewritten(t *testing.T) {
	m, e := boundaryManager(t)
	before := []byte(`{"version":2,"entries":[]}`)
	if err := os.WriteFile(m.Path, before, sessionFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Add(e.Interface, e.Address); err == nil {
		t.Fatal("unsupported session version accepted")
	}
	if _, err := m.Remove(e); err == nil {
		t.Fatal("unsupported session version accepted by direct removal")
	}
	if _, err := m.RemoveOwned(context.Background(), e); err == nil {
		t.Fatal("unsupported session version accepted by owned removal")
	}
	assertSessionUnchanged(t, m, before)
}
