// Package networkcfg owns every change WirePup makes to host network
// configuration: temporary secondary IPv4 addresses added and removed
// through iproute2 and recorded in a session file (ADR-0010). Passive
// code never imports this package. The session record is written before
// the address is applied, so an interrupted run leaves a record that
// disconnect can reconcile, never an unrecorded address.
package networkcfg

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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

// Bounds for session contention, local inspection, and subprocess pipe drain.
const (
	lockTimeout       = 5 * time.Second
	inspectionTimeout = 5 * time.Second
	waitInterval      = 10 * time.Millisecond
	ipWaitDelay       = 100 * time.Millisecond
)

// ipPaths are tried in order; PATH is never consulted.
var ipPaths = []string{"/usr/sbin/ip", "/sbin/ip", "/bin/ip"}

// Errors.
var (
	ErrNoIP        = errors.New("networkcfg: iproute2 executable not found")
	ErrPrivilege   = errors.New("networkcfg: changing addresses requires CAP_NET_ADMIN")
	ErrNotRecorded = errors.New("networkcfg: address is not in the session file")
	// ErrAlreadyRecorded refuses an add that would duplicate a recovery record.
	ErrAlreadyRecorded = errors.New("networkcfg: address already has a session record")
	// ErrOwnershipChanged means stored or live identity no longer matches the
	// confirmed Entry. The record is retained for explicit selective recovery.
	ErrOwnershipChanged = errors.New("networkcfg: address ownership changed")
	// ErrUnsafeRemoval means deleting the owned primary could also remove
	// another address. The complete session record is retained for recovery.
	ErrUnsafeRemoval = errors.New("networkcfg: primary address has another address in its subnet")
	// ErrOutcomeUnknown means ip started but its outcome was not confirmed.
	// The attempted change remains recorded; it does not confer ownership.
	ErrOutcomeUnknown = errors.New("networkcfg: ip outcome unknown; session record retained for selective recovery")
)

// Entry records one attempted address add. Only a successful Add or
// AddContext return establishes ownership; a loaded entry can describe an
// interrupted operation whose outcome requires explicit selective recovery.
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

// Runner executes a command and returns its combined output. It is a
// synchronous legacy unit-test hook without subprocess cancellation support.
type Runner func(path string, args ...string) ([]byte, error)

// Manager applies and records changes.
type Manager struct {
	Path    string
	IPPath  string
	Runner  Runner
	Version string
}

// New returns a manager for the real host. With Runner nil, operations run
// exec.CommandContext and wait for the child; cancellation reaches ip itself.
func New(version string) *Manager {
	return &Manager{Path: SessionPath, IPPath: findIP(), Version: version}
}

func findIP() string {
	for _, p := range ipPaths {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p
		}
	}
	return ""
}

// runIP separates confirmed success, known failure, and an uncertain outcome.
// A zero child exit status confirms success even if cancellation follows it.
func (m *Manager) runIP(ctx context.Context, args ...string) (out []byte, err error, unknown bool) {
	if err := ctx.Err(); err != nil {
		return nil, err, false
	}
	if m.Runner != nil {
		out, err = m.Runner(m.IPPath, args...)
		return out, err, err != nil && (ctx.Err() != nil || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded))
	}
	cmd := exec.CommandContext(ctx, m.IPPath, args...)
	cmd.WaitDelay = ipWaitDelay
	out, err = cmd.CombinedOutput()
	if cmd.ProcessState != nil && cmd.ProcessState.Success() {
		return out, nil, false
	}
	// Start failure cannot have applied an address. A started process killed
	// by a signal, cancellation, or an unsuccessful wait has an unknown outcome.
	unknown = cmd.Process != nil && (ctx.Err() != nil || cmd.ProcessState == nil || !cmd.ProcessState.Exited())
	return out, errors.Join(err, ctx.Err()), unknown
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

func (m *Manager) loadForUpdate() (Session, error) {
	s, err := m.Load()
	if err == nil && s.Version != SessionVersion {
		err = fmt.Errorf("networkcfg: unsupported session version %d", s.Version)
	}
	return s, err
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

// Add is AddContext with a background context. It leaves the address
// configured until explicit removal, preserving the direct-command contract.
func (m *Manager) Add(iface string, addr netip.Prefix) (Entry, error) {
	return m.AddContext(context.Background(), iface, addr)
}

// AddContext records then applies a temporary IPv4 address. It returns an
// owned Entry only after confirmed ip success, including success immediately
// followed by cancellation. A cancelled or uncertain running ip leaves its
// record and returns ErrOutcomeUnknown with a zero Entry. A known failure
// rolls back only this record and reports any failure to save that rollback.
// Session writers serialize across processes with a bounded, cancellable wait.
func (m *Manager) AddContext(ctx context.Context, iface string, addr netip.Prefix) (Entry, error) {
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	if m.IPPath == "" {
		return Entry{}, ErrNoIP
	}
	if !addr.IsValid() || !addr.Addr().Is4() {
		return Entry{}, errors.New("networkcfg: temporary address must be an IPv4 prefix")
	}
	lock, err := m.lock(ctx)
	if err != nil {
		return Entry{}, err
	}
	defer lock.Close()
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return Entry{}, fmt.Errorf("networkcfg: interface %q: %w", iface, err)
	}
	s, err := m.loadForUpdate()
	if err != nil {
		return Entry{}, err
	}
	for _, x := range s.Entries {
		if x.Interface == ifi.Name && x.Address.Addr() == addr.Addr() {
			return Entry{}, ErrAlreadyRecorded
		}
	}
	if err := ctx.Err(); err != nil {
		return Entry{}, err
	}
	e := Entry{
		Interface: ifi.Name,
		Index:     ifi.Index,
		Address:   addr,
		Label:     Label(ifi.Name),
		AddedAt:   time.Now().UTC(),
		Version:   m.Version,
		Argv:      append([]string{m.IPPath}, AddArgv(ifi.Name, addr)...),
	}
	s.Entries = append(s.Entries, e)
	if err := m.save(s); err != nil {
		return Entry{}, err
	}
	out, err, unknown := m.runIP(ctx, e.Argv[1:]...)
	if err != nil {
		if unknown {
			return Entry{}, errors.Join(ErrOutcomeUnknown, wrapIPError(err, out), ctx.Err())
		}
		s.Entries = s.Entries[:len(s.Entries)-1]
		return Entry{}, errors.Join(wrapIPError(err, out), m.save(s))
	}
	return e, nil
}

// Remove deletes one recorded address and drops its record. When the
// address is already gone the record is dropped without running ip.
func (m *Manager) Remove(e Entry) (ran bool, err error) {
	ctx := context.Background()
	lock, err := m.lock(ctx)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	s, err := m.loadForUpdate()
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
		out, err, unknown := m.runIP(ctx, argv...)
		if err != nil {
			if unknown {
				return true, errors.Join(ErrOutcomeUnknown, wrapIPError(err, out))
			}
			return true, wrapIPError(err, out)
		}
		ran = true
	}
	s.Entries = append(s.Entries[:idx], s.Entries[idx+1:]...)
	return ran, m.save(s)
}

// RemoveOwned removes only the complete stored identity of a confirmed Entry
// returned by Add or AddContext. It also checks the current interface index,
// address, prefix and label; mismatches and inspection errors retain the record.
// Shared-subnet primary deletion is refused because Linux may remove secondary
// addresses with it. No sysctl or unrelated address is changed to permit it.
// Callers must supply a separate cleanup context if their work was cancelled.
// The deadline reaches lock waits, live inspection and the real ip subprocess.
// ran reports whether deletion was attempted, not whether it succeeded.
// An absent address drops its exact record; an absent record and address are
// an idempotent no-op unless a replacement identity is found. A live address
// without its record returns ErrNotRecorded and is never deleted.
func (m *Manager) RemoveOwned(ctx context.Context, e Entry) (ran bool, err error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if e.Interface == "" || e.Index <= 0 || !e.Address.IsValid() || !e.Address.Addr().Is4() || e.AddedAt.IsZero() {
		return false, fmt.Errorf("%w: invalid owned entry", ErrOwnershipChanged)
	}
	lock, err := m.lock(ctx)
	if err != nil {
		return false, err
	}
	defer lock.Close()
	s, err := m.loadForUpdate()
	if err != nil {
		return false, err
	}
	idx := -1
	for i, x := range s.Entries {
		if sameEntry(x, e) {
			if idx >= 0 {
				return false, fmt.Errorf("%w: duplicate records", ErrOwnershipChanged)
			}
			idx = i
		} else if (x.Interface == e.Interface || x.Index == e.Index) && x.Address.Addr() == e.Address.Addr() {
			return false, fmt.Errorf("%w: session entry differs", ErrOwnershipChanged)
		}
	}
	present, err := ownedAddressPresent(ctx, e)
	if err != nil {
		return false, err
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if idx < 0 {
		if present {
			return false, ErrNotRecorded
		}
		return false, nil
	}
	if present {
		if m.IPPath == "" {
			return false, ErrNoIP
		}
		out, err, unknown := m.runIP(ctx, DelArgv(e)...)
		if err != nil {
			if unknown {
				return true, errors.Join(ErrOutcomeUnknown, wrapIPError(err, out), ctx.Err())
			}
			return true, wrapIPError(err, out)
		}
		ran = true
	}
	s.Entries = append(s.Entries[:idx], s.Entries[idx+1:]...)
	return ran, m.save(s)
}

func sameEntry(a, b Entry) bool {
	return a.Interface == b.Interface && a.Index == b.Index && a.Address == b.Address &&
		a.Label == b.Label && a.AddedAt.Equal(b.AddedAt) && a.Version == b.Version && slices.Equal(a.Argv, b.Argv)
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
		return fmt.Errorf("%w: %w: %s", ErrPrivilege, err, msg)
	}
	return fmt.Errorf("networkcfg: ip: %w: %s", err, msg)
}
