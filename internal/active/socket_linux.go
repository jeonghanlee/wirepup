//go:build linux

package active

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"golang.org/x/sys/unix"
)

// Socket errors.
var ErrPrivilege = errors.New("active: transmitting requires CAP_NET_RAW")

const (
	readTimeout = 200 * time.Millisecond
	recvBuffer  = 2048
)

// arpSocket is a raw socket that can send and hear ARP on one interface.
type arpSocket struct {
	fd    int
	index int
	mac   net.HardwareAddr
	name  string
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

func openARP(iface string) (*arpSocket, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return nil, fmt.Errorf("active: interface %q: %w", iface, err)
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, int(htons(etherTypeARP)))
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("%w: %v", ErrPrivilege, err)
		}
		return nil, fmt.Errorf("active: socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: ifi.Index}); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("active: bind: %w", err)
	}
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		unix.Close(fd)
		return nil, fmt.Errorf("active: SO_RCVTIMEO: %w", err)
	}
	return &arpSocket{fd: fd, index: ifi.Index, mac: ifi.HardwareAddr, name: ifi.Name}, nil
}

func (s *arpSocket) send(frame []byte) error {
	var addr [8]byte
	copy(addr[:], frame[0:6])
	sa := &unix.SockaddrLinklayer{Protocol: htons(etherTypeARP), Ifindex: s.index, Halen: 6, Addr: addr}
	return unix.Sendto(s.fd, frame, 0, sa)
}

// listen collects ARP replies until the deadline, calling onReply for
// each parsed packet; it stops early when onReply returns false.
func (s *arpSocket) listen(ctx context.Context, until time.Time, onReply func(Reply) bool) error {
	buf := make([]byte, recvBuffer)
	for time.Now().Before(until) && ctx.Err() == nil {
		n, _, err := unix.Recvfrom(s.fd, buf, 0)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			return fmt.Errorf("active: recv: %w", err)
		}
		r, ok := parseARP(buf[:n])
		if !ok {
			continue
		}
		r.At = time.Now()
		if !onReply(r) {
			return nil
		}
	}
	return nil
}

func (s *arpSocket) close() { unix.Close(s.fd) }

// ProbeResult is the outcome of an RFC 5227 probe sequence.
type ProbeResult struct {
	Plan     Plan
	Sent     int
	Conflict *Reply
}

// Probe sends RFC 5227 probes for target and listens for any claim on
// it. A conflict ends the sequence at once.
func Probe(ctx context.Context, iface string, target netip.Addr) (ProbeResult, error) {
	s, err := openARP(iface)
	if err != nil {
		return ProbeResult{}, err
	}
	defer s.close()
	res := ProbeResult{Plan: Plan{Interface: s.name, Protocol: "ARP probe", Targets: []netip.Addr{target}, Count: ProbeCount, Rate: 1}}
	frame := ProbeFrame(s.mac, target)
	for i := 0; i < ProbeCount; i++ {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err := s.send(frame); err != nil {
			return res, fmt.Errorf("active: send: %w", err)
		}
		res.Sent++
		wait := ProbeInterval
		if i == ProbeCount-1 {
			wait = AnnounceWait
		}
		var conflict *Reply
		err := s.listen(ctx, time.Now().Add(wait), func(r Reply) bool {
			if Conflicts(r, target, s.mac) {
				c := r
				conflict = &c
				return false
			}
			return true
		})
		if err != nil {
			return res, err
		}
		if conflict != nil {
			res.Conflict = conflict
			return res, nil
		}
	}
	return res, nil
}

// SweepResult is the outcome of an ARP sweep.
type SweepResult struct {
	Plan    Plan
	Sent    int
	Replies []Reply
}

// Sweep sends one ARP request per host of the prefix at the fixed rate
// and collects replies until AnnounceWait after the last request.
func Sweep(ctx context.Context, iface string, prefix netip.Prefix) (SweepResult, error) {
	hosts, err := Hosts(prefix)
	if err != nil {
		return SweepResult{}, err
	}
	s, err := openARP(iface)
	if err != nil {
		return SweepResult{}, err
	}
	defer s.close()
	sender, err := senderAddress(iface, prefix)
	if err != nil {
		return SweepResult{}, err
	}
	res := SweepResult{Plan: Plan{Interface: s.name, Protocol: "ARP request", Targets: hosts, Count: len(hosts), Rate: RatePerSecond}}
	seen := map[string]bool{}
	collect := func(r Reply) bool {
		if r.Kind != "reply" || r.MAC.String() == s.mac.String() {
			return true
		}
		key := r.IP.String() + "|" + r.MAC.String()
		if !seen[key] {
			seen[key] = true
			res.Replies = append(res.Replies, r)
		}
		return true
	}
	for _, h := range hosts {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		if err := s.send(ARPFrame(s.mac, opRequest, sender, nil, h)); err != nil {
			return res, fmt.Errorf("active: send: %w", err)
		}
		res.Sent++
		if err := s.listen(ctx, time.Now().Add(SendInterval), collect); err != nil {
			return res, err
		}
	}
	if err := s.listen(ctx, time.Now().Add(AnnounceWait), collect); err != nil {
		return res, err
	}
	return res, nil
}

// senderAddress picks the interface address inside the prefix, else
// any IPv4 address of the interface.
func senderAddress(iface string, prefix netip.Prefix) (netip.Addr, error) {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return netip.Addr{}, err
	}
	addrs, _ := ifi.Addrs()
	var any netip.Addr
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		ip, ok := netip.AddrFromSlice(ipn.IP)
		if !ok {
			continue
		}
		ip = ip.Unmap()
		if !ip.Is4() {
			continue
		}
		if prefix.Contains(ip) {
			return ip, nil
		}
		if !any.IsValid() {
			any = ip
		}
	}
	if !any.IsValid() {
		return netip.Addr{}, ErrNoIPv4
	}
	return any, nil
}
