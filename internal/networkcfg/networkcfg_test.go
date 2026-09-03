package networkcfg

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeRunner records commands instead of executing iproute2; everything
// else (session file, argv construction, interface lookup) is real.
type fakeRunner struct {
	calls [][]string
	fail  error
	out   string
}

func (f *fakeRunner) run(path string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, append([]string{path}, args...))
	return []byte(f.out), f.fail
}

func loopback(t *testing.T) string {
	t.Helper()
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			return i.Name
		}
	}
	t.Skip("no loopback interface")
	return ""
}

func TestLabel(t *testing.T) {
	if Label("enp3s0") != "enp3s0:wirepup" || Label("enx001122334455") != "" {
		t.Fatalf("labels %q %q", Label("enp3s0"), Label("enx001122334455"))
	}
}

func TestAddRecordsBeforeRunningAndRemoveReconciles(t *testing.T) {
	lo := loopback(t)
	fr := &fakeRunner{}
	m := &Manager{Path: filepath.Join(t.TempDir(), "run", "session.json"), IPPath: "/usr/sbin/ip", Runner: fr.run, Version: "test"}
	addr := netip.MustParsePrefix("192.168.1.254/24")
	e, err := m.Add(lo, addr)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/sbin/ip", "-4", "address", "add", "192.168.1.254/24", "dev", lo, "label", lo + LabelSuffix}
	if strings.Join(fr.calls[0], " ") != strings.Join(want, " ") || strings.Join(e.Argv, " ") != strings.Join(want, " ") {
		t.Fatalf("argv %v", fr.calls[0])
	}
	st, err := os.Stat(m.Path)
	if err != nil || st.Mode().Perm() != sessionFileMode {
		t.Fatalf("session file %v %v", err, st)
	}
	s, _ := m.Load()
	if len(s.Entries) != 1 || s.Entries[0].Address != addr || s.Entries[0].Interface != lo || s.Entries[0].Version != "test" {
		t.Fatalf("session %+v", s)
	}
	// The fake did not configure the address, so Remove treats it as
	// already gone: no ip call, record dropped.
	ran, err := m.Remove(e)
	if err != nil || ran || len(fr.calls) != 1 {
		t.Fatalf("remove: ran=%v err=%v calls=%d", ran, err, len(fr.calls))
	}
	s, _ = m.Load()
	if len(s.Entries) != 0 {
		t.Fatalf("session after remove %+v", s)
	}
	if _, err := m.Remove(e); err != ErrNotRecorded {
		t.Fatalf("second remove %v", err)
	}
}

func TestAddFailureDropsRecord(t *testing.T) {
	lo := loopback(t)
	fr := &fakeRunner{fail: errors.New("exit status 2"), out: "RTNETLINK answers: Operation not permitted"}
	m := &Manager{Path: filepath.Join(t.TempDir(), "session.json"), IPPath: "/usr/sbin/ip", Runner: fr.run}
	_, err := m.Add(lo, netip.MustParsePrefix("192.168.1.254/24"))
	if !errors.Is(err, ErrPrivilege) {
		t.Fatalf("err %v", err)
	}
	s, _ := m.Load()
	if len(s.Entries) != 0 {
		t.Fatalf("record kept after failure: %+v", s)
	}
}

func TestPresentMatchesRealLoopback(t *testing.T) {
	lo := loopback(t)
	if !Present(Entry{Interface: lo, Address: netip.MustParsePrefix("127.0.0.1/8")}) {
		t.Skip("loopback without 127.0.0.1/8")
	}
	if Present(Entry{Interface: lo, Address: netip.MustParsePrefix("192.0.2.1/24")}) {
		t.Fatal("absent address reported present")
	}
}

func TestMissingIPAndUnknownInterface(t *testing.T) {
	m := &Manager{Path: filepath.Join(t.TempDir(), "session.json"), Runner: (&fakeRunner{}).run}
	if _, err := m.Add("lo", netip.MustParsePrefix("192.168.1.254/24")); err != ErrNoIP {
		t.Fatalf("no ip: %v", err)
	}
	m.IPPath = "/usr/sbin/ip"
	if _, err := m.Add("no-such-if-0", netip.MustParsePrefix("192.168.1.254/24")); err == nil {
		t.Fatal("unknown interface accepted")
	}
	if s, err := m.Load(); err != nil || len(s.Entries) != 0 {
		t.Fatalf("empty session %v %v", s, err)
	}
}
