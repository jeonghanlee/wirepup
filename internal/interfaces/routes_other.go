//go:build !linux

package interfaces

import (
	"errors"
	"net/netip"
)

// Route is one IPv4 unicast route.
type Route struct {
	Dst       netip.Prefix
	Gateway   netip.Addr
	Interface string
	Index     int
	Metric    int
}

// Routes is implemented for Linux only.
func Routes() ([]Route, error) {
	return nil, errors.New("routes: implemented for Linux only")
}
