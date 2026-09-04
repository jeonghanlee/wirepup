// Package interfaces enumerates local network interfaces with their link
// state, MTU, and addresses (R-001). It only reads; host configuration
// changes live in networkcfg.
package interfaces

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// sysfs locations for link state.
const (
	sysClassNet      = "/sys/class/net"
	operStateFile    = "operstate"
	OperStateUnknown = "unknown"
)

// Interface is one local interface.
type Interface struct {
	Name      string
	Index     int
	MAC       string
	Up        bool
	Loopback  bool
	OperState string
	MTU       int
	IPv4      []netip.Prefix
	IPv6      []netip.Prefix
}

// List returns every interface sorted by index.
func List() ([]Interface, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("interfaces: %w", err)
	}
	out := make([]Interface, 0, len(ifs))
	for _, ifi := range ifs {
		out = append(out, convert(ifi))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Index < out[j].Index })
	return out, nil
}

// ByName returns one interface.
func ByName(name string) (Interface, error) {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return Interface{}, fmt.Errorf("interface %q: %w", name, err)
	}
	return convert(*ifi), nil
}

func convert(ifi net.Interface) Interface {
	out := Interface{
		Name:      ifi.Name,
		Index:     ifi.Index,
		MAC:       ifi.HardwareAddr.String(),
		Up:        ifi.Flags&net.FlagUp != 0,
		Loopback:  ifi.Flags&net.FlagLoopback != 0,
		OperState: operState(ifi.Name),
		MTU:       ifi.MTU,
	}
	addrs, err := ifi.Addrs()
	if err != nil {
		return out
	}
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		addr, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		ones, _ := ipn.Mask.Size()
		p := netip.PrefixFrom(addr, ones)
		if addr.Is4() {
			out.IPv4 = append(out.IPv4, p)
		} else {
			out.IPv6 = append(out.IPv6, p)
		}
	}
	return out
}

func operState(name string) string {
	b, err := os.ReadFile(filepath.Join(sysClassNet, name, operStateFile))
	if err != nil {
		return OperStateUnknown
	}
	return strings.TrimSpace(string(b))
}

// LocalMACs returns the hardware addresses of all interfaces, used by the
// device table to mark the host's own frames.
func LocalMACs() ([]string, error) {
	ifs, err := List()
	if err != nil {
		return nil, err
	}
	var macs []string
	for _, i := range ifs {
		if i.MAC != "" {
			macs = append(macs, i.MAC)
		}
	}
	return macs, nil
}
