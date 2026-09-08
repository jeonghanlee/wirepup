//go:build linux

package networkcfg

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const netlinkBufferSize = 64 * 1024

// ownedAddressPresent reads only rtnetlink dumps. An omitted add label has
// the interface name as its live IPv4 label. An interrupted or incomplete
// dump is an inspection error, never evidence that an address disappeared.
func ownedAddressPresent(ctx context.Context, e Entry) (bool, error) {
	ctx, cancel := context.WithTimeout(ctx, inspectionTimeout)
	defer cancel()
	live, err := ownedInterfacePresent(ctx, e)
	if err != nil || !live {
		return false, err
	}
	msgs, err := netlinkDump(ctx, unix.RTM_GETADDR, unix.AF_INET)
	if err != nil {
		return false, fmt.Errorf("networkcfg: inspect addresses: %w", err)
	}
	wantLabel := e.Label
	if wantLabel == "" {
		wantLabel = e.Interface
	}
	present := false
	var primarySubnet netip.Prefix
	var otherSubnets []netip.Prefix
	for _, msg := range msgs {
		if msg.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		if len(msg.Data) < unix.SizeofIfAddrmsg {
			return false, errors.New("networkcfg: inspect addresses: short address message")
		}
		if msg.Data[0] != unix.AF_INET || int(binary.NativeEndian.Uint32(msg.Data[4:8])) != e.Index {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			return false, fmt.Errorf("networkcfg: inspect address attributes: %w", err)
		}
		var local, address netip.Addr
		var label string
		for _, attr := range attrs {
			switch attr.Attr.Type {
			case unix.IFA_LOCAL, unix.IFA_ADDRESS:
				if len(attr.Value) != 4 {
					return false, errors.New("networkcfg: inspect addresses: invalid IPv4 address")
				}
				ip := netip.AddrFrom4([4]byte(attr.Value))
				if attr.Attr.Type == unix.IFA_LOCAL {
					local = ip
				} else {
					address = ip
				}
			case unix.IFA_LABEL:
				label = strings.TrimRight(string(attr.Value), "\x00")
			}
		}
		// IFA_ADDRESS can name the peer on point-to-point interfaces.
		if !local.IsValid() {
			local = address
		}
		if !local.IsValid() {
			return false, errors.New("networkcfg: inspect addresses: missing IPv4 address")
		}
		if !address.IsValid() {
			address = local
		}
		subnet := netip.PrefixFrom(address, int(msg.Data[1])).Masked()
		if !subnet.IsValid() {
			return false, errors.New("networkcfg: inspect addresses: invalid IPv4 prefix")
		}
		if local != e.Address.Addr() {
			otherSubnets = append(otherSubnets, subnet)
			continue
		}
		if int(msg.Data[1]) != e.Address.Bits() || label != wantLabel {
			return false, fmt.Errorf("%w: live prefix or label differs", ErrOwnershipChanged)
		}
		present = true
		if msg.Data[2]&unix.IFA_F_SECONDARY == 0 {
			primarySubnet = subnet
		}
	}
	// Linux groups primary/secondary IPv4 addresses by equal prefix length
	// and IFA_ADDRESS subnet (the peer on point-to-point interfaces). Deleting
	// the primary can cascade to its secondaries. Refuse this dependency even
	// if promote_secondaries is currently enabled; it is not our setting to
	// rely on or change between inspection and deletion.
	for _, subnet := range otherSubnets {
		if subnet == primarySubnet {
			return false, fmt.Errorf("%w: %s; automatic cleanup refused", ErrUnsafeRemoval, subnet)
		}
	}
	// Recheck the link after the address dump, including when an address is
	// absent, so a replaced or renamed interface cannot discard its evidence.
	live, err = ownedInterfacePresent(ctx, e)
	return present && live, err
}

func ownedInterfacePresent(ctx context.Context, e Entry) (bool, error) {
	msgs, err := netlinkDump(ctx, unix.RTM_GETLINK, unix.AF_UNSPEC)
	if err != nil {
		return false, fmt.Errorf("networkcfg: inspect interfaces: %w", err)
	}
	present := false
	for _, msg := range msgs {
		if msg.Header.Type != unix.RTM_NEWLINK {
			continue
		}
		if len(msg.Data) < unix.SizeofIfInfomsg {
			return false, errors.New("networkcfg: inspect interfaces: short interface message")
		}
		index := int(binary.NativeEndian.Uint32(msg.Data[4:8]))
		attrs, err := syscall.ParseNetlinkRouteAttr(&msg)
		if err != nil {
			return false, fmt.Errorf("networkcfg: inspect interface attributes: %w", err)
		}
		var name string
		for _, attr := range attrs {
			if attr.Attr.Type == unix.IFLA_IFNAME {
				name = strings.TrimRight(string(attr.Value), "\x00")
			}
		}
		if name == "" {
			return false, errors.New("networkcfg: inspect interfaces: missing interface name")
		}
		if name == e.Interface || index == e.Index {
			if name != e.Interface || index != e.Index {
				return false, fmt.Errorf("%w: live interface name or index differs", ErrOwnershipChanged)
			}
			present = true
		}
	}
	return present, nil
}

// netlinkDump bounds receive waits with the caller's context. The private
// nonblocking socket requests only RTM_GETLINK or RTM_GETADDR, never a change.
func netlinkDump(ctx context.Context, kind uint16, family byte) ([]syscall.NetlinkMessage, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	defer unix.Close(fd)
	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Bind(fd, sa); err != nil {
		return nil, err
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		return nil, err
	}
	local, ok := bound.(*unix.SockaddrNetlink)
	if !ok {
		return nil, errors.New("invalid netlink socket address")
	}
	request := make([]byte, unix.NLMSG_HDRLEN+unix.SizeofRtGenmsg)
	binary.NativeEndian.PutUint32(request[0:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], kind)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[unix.NLMSG_HDRLEN] = family
	if err := unix.Sendto(fd, request, 0, sa); err != nil {
		return nil, err
	}
	buf := make([]byte, netlinkBufferSize)
	var result []syscall.NetlinkMessage
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buf, nil, 0)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			if err := waitContext(ctx); err != nil {
				return nil, err
			}
			continue
		}
		if err != nil {
			return nil, err
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if !ok || sender.Pid != 0 || flags&unix.MSG_TRUNC != 0 || n < unix.NLMSG_HDRLEN {
			return nil, errors.New("incomplete or invalid netlink reply")
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, msg := range msgs {
			if msg.Header.Seq != 1 || msg.Header.Pid != local.Pid || msg.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
				return nil, errors.New("interrupted or mismatched netlink dump")
			}
			switch msg.Header.Type {
			case unix.NLMSG_DONE, unix.NLMSG_ERROR:
				if len(msg.Data) < 4 && msg.Header.Type == unix.NLMSG_ERROR {
					return nil, errors.New("short netlink error")
				}
				if len(msg.Data) >= 4 {
					if code := int32(binary.NativeEndian.Uint32(msg.Data[:4])); code != 0 {
						return nil, unix.Errno(-code)
					}
				}
				if msg.Header.Type == unix.NLMSG_DONE {
					return result, nil
				}
			case unix.NLMSG_OVERRUN:
				return nil, errors.New("netlink dump overrun")
			default:
				msg.Data = append([]byte(nil), msg.Data...)
				result = append(result, msg)
			}
		}
	}
}
