// Package oui resolves MAC address prefixes to vendor names from an
// external IEEE MA-L registry file (ADR-0011). Nothing is bundled: when
// no file is found, lookups return an empty hint.
package oui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
)

// DefaultPaths are tried in order when no file is given.
var DefaultPaths = []string{
	"/var/lib/ieee-data/oui.txt",
	"/usr/share/ieee-data/oui.txt",
	"/usr/share/hwdata/oui.txt",
}

// Format markers of the IEEE text registry.
const (
	hexMarker  = "(hex)"
	prefixLen  = 8 // "00-80-F4"
	prefixByte = 3
)

// ErrNotFound reports that no registry file exists at any given path.
var ErrNotFound = errors.New("oui: no registry file found")

// Table maps 24-bit prefixes to organization names.
type Table struct {
	path    string
	entries map[uint32]string
}

// Load reads the first file that exists among the paths; an explicit
// path that does not exist is an error, a missing default is not.
func Load(explicit string, defaults []string) (*Table, error) {
	if explicit != "" {
		f, err := os.Open(explicit)
		if err != nil {
			return nil, fmt.Errorf("oui: %w", err)
		}
		defer f.Close()
		return Parse(f, explicit)
	}
	for _, p := range defaults {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		t, err := Parse(f, p)
		f.Close()
		return t, err
	}
	return nil, fmt.Errorf("%w (tried %s)", ErrNotFound, strings.Join(defaults, ", "))
}

// Parse reads the IEEE text format: one "XX-XX-XX   (hex)  Name" line per
// assignment, everything else ignored.
func Parse(r io.Reader, path string) (*Table, error) {
	t := &Table{path: path, entries: map[uint32]string{}}
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := sc.Text()
		i := strings.Index(line, hexMarker)
		if i < prefixLen {
			continue
		}
		key, ok := prefixKey(strings.TrimSpace(line[:i]))
		if !ok {
			continue
		}
		name := strings.TrimSpace(line[i+len(hexMarker):])
		if name != "" {
			t.entries[key] = name
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("oui: %w", err)
	}
	return t, nil
}

func prefixKey(s string) (uint32, bool) {
	if len(s) != prefixLen {
		return 0, false
	}
	var key uint32
	for i := 0; i < prefixByte; i++ {
		var b byte
		for _, c := range s[i*3 : i*3+2] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= byte(c - '0')
			case c >= 'A' && c <= 'F':
				b |= byte(c-'A') + 10
			case c >= 'a' && c <= 'f':
				b |= byte(c-'a') + 10
			default:
				return 0, false
			}
		}
		key = key<<8 | uint32(b)
	}
	return key, true
}

// Path returns the file the table was read from.
func (t *Table) Path() string { return t.path }

// Len returns the number of prefixes.
func (t *Table) Len() int { return len(t.entries) }

// Lookup returns the organization for a MAC, or "" when unknown or when
// the address is locally administered (randomized or virtual, so the
// prefix carries no vendor meaning). A nil table always returns "".
func (t *Table) Lookup(mac string) string {
	if t == nil {
		return ""
	}
	hw, err := net.ParseMAC(mac)
	if err != nil || len(hw) < prefixByte || IsLocallyAdministered(hw) {
		return ""
	}
	return t.entries[uint32(hw[0])<<16|uint32(hw[1])<<8|uint32(hw[2])]
}

// IsLocallyAdministered reports the U/L bit of the first octet.
func IsLocallyAdministered(hw net.HardwareAddr) bool {
	return len(hw) > 0 && hw[0]&0x02 != 0
}
