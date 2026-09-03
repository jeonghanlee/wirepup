//go:build linux

package interfaces

import (
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"
)

// Route is one IPv4 unicast route from the main table.
type Route struct {
	Dst       netip.Prefix // 0.0.0.0/0 for the default route
	Gateway   netip.Addr   // invalid when the route is directly connected
	Interface string
	Index     int
	Metric    int
}

// mainTable is the kernel routing table WirePup reads.
const mainTable = syscall.RT_TABLE_MAIN

// Routes reads the IPv4 unicast routes of the main table over rtnetlink
// using the standard library dump helpers. This is read-only; WirePup
// never writes netlink (ADR-0010).
func Routes() ([]Route, error) {
	data, err := syscall.NetlinkRIB(syscall.RTM_GETROUTE, syscall.AF_INET)
	if err != nil {
		return nil, fmt.Errorf("routes: %w", err)
	}
	msgs, err := syscall.ParseNetlinkMessage(data)
	if err != nil {
		return nil, fmt.Errorf("routes: %w", err)
	}
	names := map[int]string{}
	if ifs, err := List(); err == nil {
		for _, i := range ifs {
			names[i.Index] = i.Name
		}
	}
	var out []Route
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != syscall.RTM_NEWROUTE || len(m.Data) < syscall.SizeofRtMsg {
			continue
		}
		rt := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
		if rt.Family != syscall.AF_INET || rt.Type != syscall.RTN_UNICAST {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		r := Route{Dst: netip.PrefixFrom(netip.AddrFrom4([4]byte{}), int(rt.Dst_len))}
		table := int(rt.Table)
		for _, a := range attrs {
			switch a.Attr.Type {
			case syscall.RTA_DST:
				if len(a.Value) == 4 {
					r.Dst = netip.PrefixFrom(netip.AddrFrom4([4]byte(a.Value)), int(rt.Dst_len))
				}
			case syscall.RTA_GATEWAY:
				if len(a.Value) == 4 {
					r.Gateway = netip.AddrFrom4([4]byte(a.Value))
				}
			case syscall.RTA_OIF:
				if len(a.Value) == 4 {
					r.Index = int(*(*int32)(unsafe.Pointer(&a.Value[0])))
				}
			case syscall.RTA_PRIORITY:
				if len(a.Value) == 4 {
					r.Metric = int(*(*int32)(unsafe.Pointer(&a.Value[0])))
				}
			case syscall.RTA_TABLE:
				if len(a.Value) == 4 {
					table = int(*(*int32)(unsafe.Pointer(&a.Value[0])))
				}
			}
		}
		if table != mainTable {
			continue
		}
		r.Interface = names[r.Index]
		out = append(out, r)
	}
	return out, nil
}
