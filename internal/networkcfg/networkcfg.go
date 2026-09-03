// Package networkcfg owns every change WirePup makes to host network
// configuration: temporary secondary IPv4 addresses added and removed
// through iproute2 and recorded in a session file (ADR-0010). Passive
// code never imports this package. The session record is written before
// the address is applied, so an interrupted run leaves a record that
// disconnect can reconcile, never an unrecorded address.
package networkcfg

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Session file location and modes.
const (
	SessionPath     = "/run/wirepup/session.json"
	sessionDirMode  = 0o700
	sessionFileMode = 0o600
	SessionVersion  = 1
)

// Address label conventions (iproute2 limits a label to 15 characters
// and requires the interface name as prefix).
const (
	LabelSuffix = ":wirepup"
	labelMaxLen = 15
)

// ipPaths are tried in order; PATH is never consulted.
var ipPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/bin/ip"}

// Errors.
var (
	ErrNoIP        = errors.New("networkcfg: iproute2 executable not found")
	ErrPrivilege   = errors.New("networkcfg: changing addresses requires CAP_NET_ADMIN")
	ErrNotRecorded = errors.New("networkcfg: address is not in the session file")
)

// Entry is one address WirePup added.
type Entry struct {
	Interface string       `json:"interface"`
	Index     int          `json:"ifindex"`
	Address   netip.Prefix `json:"address"`
	Label     string       `json:"label,omitempty"`
	AddedAt   time.Time    `json:"added_at"`
	Version   string       `json:"wirepup_version"`
	Argv      []string     `json:"argv"`
}

// Session is the on-disk record.
type Session struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

// Runner executes a command and returns its combined output.
type Runner func(path string, args ...string) ([]byte, error)

// Manager applies and records changes.
type Manager struct {
	Path    string
	IPPath  string
	Runner  Runner
	Version string
}

// New returns a manager for the real host.
func New(version string) *Manager {
	return &Manager{Path: SessionPath, IPPath: findIP(), Runner: execRunner, Version: version}
}

func findIP() string {
	for _, p := range ipPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

func execRunner(path string, args ...string) ([]byte, error) {
	return exec.Command(path, args...).CombinedOutput()
}

// Label returns the address label for an interface, or "" when the
// name is too long to carry one.
func Label(iface string) string {
	if len(iface)+len(LabelSuffix) > labelMaxLen {
		return ""
	}
	return iface + LabelSuffix
}

// Load reads the session; a missing file is an empty session.
func (m *Manager) Load() (Session, error) {
	b, err := os.ReadFile(m.Path)
	if errors.Is(err, os.ErrNotExist) {
		return Session{Version: SessionVersion}, nil
	}
	if err != nil {
		return Session{}, fmt.Errorf("networkcfg: %w", err)
	}
	var s Session
	if err := json.Unmarshal(b, &s); err != nil {
		return Session{}, fmt.Errorf("networkcfg: session file: %w", err)
	}
	return s, nil
}

func (m *Manager) save(s Session) error {
	s.Version = SessionVersion
	if err := os.MkdirAll(filepath.Dir(m.Path), sessionDirMode); err != nil {
		return fmt.Errorf("networkcfg: %w", err)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.Path + ".tmp"
	if err := os.WriteFile(tmp, b, sessionFileMode); err != nil {
		return fmt.Errorf("networkcfg: %w", err)
	}
	if err := os.Rename(tmp, m.Path); err != nil {
		return fmt.Errorf("networkcfg: %w", err)
	}
	return nil
}

// AddArgv is the exact iproute2 command Add runs, for display before
// execution.
func AddArgv(iface string, addr netip.Prefix) []string {
	argv := []string{"-4", "address", "add", addr.String(), "dev", iface}
	if l := Label(iface); l != "" {
		argv = append(argv, "label", l)
	}
	return argv
}

// DelArgv is the exact iproute2 command Remove runs.
func DelArgv(e Entry) []string {
	return []string{"-4", "address", "del", e.Address.String(), "dev", e.Interface}
}

// Add records then applies a temporary address. On failure the record
// is removed again.
func (m *Manager) Add(iface string, addr netip.Prefix) (Entry, error) {
	if m.IPPath == "" {
		return Entry{}, ErrNoIP
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return Entry{}, fmt.Errorf("networkcfg: interface %q: %w", iface, err)
	}
	e := Entry{
		Interface: ifi.Name,
		Index:     ifi.Index,
		Address:   addr,
		Label:     Label(ifi.Name),
		AddedAt:   time.Now(),
		Version:   m.Version,
		Argv:      append([]string{m.IPPath}, AddArgv(ifi.Name, addr)...),
	}
	s, err := m.Load()
	if err != nil {
		return Entry{}, err
	}
	s.Entries = append(s.Entries, e)
	if err := m.save(s); err != nil {
		return Entry{}, err
	}
	out, err := m.Runner(e.Argv[0], e.Argv[1:]...)
	if err != nil {
		s.Entries = s.Entries[:len(s.Entries)-1]
		_ = m.save(s)
		return Entry{}, wrapIPError(err, out)
	}
	return e, nil
}

// Remove deletes one recorded address and drops its record. When the
// address is already gone the record is dropped without running ip.
func (m *Manager) Remove(e Entry) (ran bool, err error) {
	s, err := m.Load()
	if err != nil {
		return false, err
	}
	idx := -1
	for i, x := range s.Entries {
		if x.Interface == e.Interface && x.Address == e.Address {
			idx = i
		}
	}
	if idx < 0 {
		return false, ErrNotRecorded
	}
	if Present(e) {
		if m.IPPath == "" {
			return false, ErrNoIP
		}
		argv := DelArgv(e)
		out, err := m.Runner(m.IPPath, argv...)
		if err != nil {
			return true, wrapIPError(err, out)
		}
		ran = true
	}
	s.Entries = append(s.Entries[:idx], s.Entries[idx+1:]...)
	return ran, m.save(s)
}

// Present reports whether the recorded address is configured on the
// recorded interface right now.
func Present(e Entry) bool {
	ifi, err := net.InterfaceByName(e.Interface)
	if err != nil {
		return false
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return false
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ones, _ := ipn.Mask.Size()
		if ip.Unmap() == e.Address.Addr() && ones == e.Address.Bits() {
			return true
		}
	}
	return false
}

func wrapIPError(err error, out []byte) error {
	msg := strings.TrimSpace(string(out))
	if strings.Contains(msg, "not permitted") {
		return fmt.Errorf("%w: %s", ErrPrivilege, msg)
	}
	return fmt.Errorf("networkcfg: ip: %v: %s", err, msg)
}
