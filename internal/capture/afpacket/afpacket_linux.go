//go:build linux

package afpacket

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/capture/bpf"
)

const (
	readTimeout   = 200 * time.Millisecond
	oobBufferSize = 512
	packetBuffer  = 256
	vlanHeaderLen = 4
	etherTypeOff  = 12
	etherTypeVLAN = 0x8100
)

// Source is one receive-only AF_PACKET socket bound to one interface.
type Source struct {
	fd      int
	name    string
	snapLen int

	mu       sync.Mutex
	closed   bool
	received uint64
	dropped  uint64
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }

// Open binds a raw packet socket to the named interface. The socket is
// created with protocol 0 so that no frame is queued before the filter
// is attached and the socket is bound.
func Open(opts Options) (*Source, error) {
	ifi, err := net.InterfaceByName(opts.Interface)
	if err != nil {
		return nil, fmt.Errorf("interface %q: %w", opts.Interface, err)
	}
	snap := opts.SnapLen
	if snap <= 0 {
		snap = capture.DefaultSnapLen
	}
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return nil, fmt.Errorf("%w: %v", ErrPrivilege, err)
		}
		return nil, fmt.Errorf("socket: %w", err)
	}
	s := &Source{fd: fd, name: ifi.Name, snapLen: snap}
	if err := s.configure(ifi.Index, opts); err != nil {
		unix.Close(fd)
		return nil, err
	}
	return s, nil
}

func (s *Source) configure(index int, opts Options) error {
	prog := opts.Filter
	if len(prog) == 0 {
		prog = bpf.AcceptAll()
	}
	if err := attachFilter(s.fd, prog); err != nil {
		return fmt.Errorf("attach filter: %w", err)
	}
	sa := &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_ALL), Ifindex: index}
	if err := unix.Bind(s.fd, sa); err != nil {
		return fmt.Errorf("bind: %w", err)
	}
	if err := unix.SetsockoptInt(s.fd, unix.SOL_PACKET, unix.PACKET_AUXDATA, 1); err != nil {
		return fmt.Errorf("PACKET_AUXDATA: %w", err)
	}
	if err := unix.SetsockoptInt(s.fd, unix.SOL_SOCKET, unix.SO_TIMESTAMPNS, 1); err != nil {
		return fmt.Errorf("SO_TIMESTAMPNS: %w", err)
	}
	tv := unix.NsecToTimeval(readTimeout.Nanoseconds())
	if err := unix.SetsockoptTimeval(s.fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv); err != nil {
		return fmt.Errorf("SO_RCVTIMEO: %w", err)
	}
	if opts.Promiscuous {
		mreq := &unix.PacketMreq{Ifindex: int32(index), Type: unix.PACKET_MR_PROMISC}
		if err := unix.SetsockoptPacketMreq(s.fd, unix.SOL_PACKET, unix.PACKET_ADD_MEMBERSHIP, mreq); err != nil {
			return fmt.Errorf("promiscuous mode: %w", err)
		}
	}
	return nil
}

func attachFilter(fd int, prog []bpf.Instruction) error {
	insns := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		insns[i] = unix.SockFilter{Code: in.Code, Jt: in.JT, Jf: in.JF, K: in.K}
	}
	fprog := &unix.SockFprog{Len: uint16(len(insns)), Filter: &insns[0]}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, fprog)
}

// Name returns the interface name.
func (s *Source) Name() string { return s.name }

// Packets starts the receive loop. The loop ends when the context is
// cancelled, the source is closed, or the socket fails.
func (s *Source) Packets(ctx context.Context) (<-chan capture.Packet, <-chan error) {
	out := make(chan capture.Packet, packetBuffer)
	errc := make(chan error, 1)
	go s.readLoop(ctx, out, errc)
	return out, errc
}

// readLoop receives one frame per recvmsg. The frame is read at an offset
// of four bytes into the buffer so that a VLAN tag reported in the
// auxiliary data can be reinserted by moving the two address fields back
// without a second copy. MSG_TRUNC makes recvmsg return the original
// frame length even when the buffer was shorter.
func (s *Source) readLoop(ctx context.Context, out chan<- capture.Packet, errc chan<- error) {
	defer close(out)
	defer close(errc)
	buf := make([]byte, vlanHeaderLen+s.snapLen)
	oob := make([]byte, oobBufferSize)
	for ctx.Err() == nil {
		n, oobn, _, _, err := unix.Recvmsg(s.fd, buf[vlanHeaderLen:], oob, unix.MSG_TRUNC)
		if err != nil {
			if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EINTR) {
				continue
			}
			if s.isClosed() {
				return
			}
			errc <- fmt.Errorf("recvmsg: %w", err)
			return
		}
		pkt := s.packetFrom(buf, n, oob[:oobn])
		select {
		case out <- pkt:
		case <-ctx.Done():
			return
		}
	}
}

func (s *Source) packetFrom(buf []byte, n int, oob []byte) capture.Packet {
	captured := n
	if captured > s.snapLen {
		captured = s.snapLen
	}
	ts := time.Now()
	var aux *unix.TpacketAuxdata
	if msgs, err := unix.ParseSocketControlMessage(oob); err == nil {
		for _, m := range msgs {
			switch {
			case m.Header.Level == unix.SOL_SOCKET && m.Header.Type == unix.SCM_TIMESTAMPNS && len(m.Data) >= int(unsafe.Sizeof(unix.Timespec{})):
				tsv := (*unix.Timespec)(unsafe.Pointer(&m.Data[0]))
				ts = time.Unix(tsv.Sec, tsv.Nsec)
			case m.Header.Level == unix.SOL_PACKET && m.Header.Type == unix.PACKET_AUXDATA && len(m.Data) >= int(unsafe.Sizeof(unix.TpacketAuxdata{})):
				aux = (*unix.TpacketAuxdata)(unsafe.Pointer(&m.Data[0]))
			}
		}
	}
	data := buf[vlanHeaderLen : vlanHeaderLen+captured]
	original := n
	if aux != nil && aux.Status&unix.TP_STATUS_VLAN_VALID != 0 && captured >= etherTypeOff {
		copy(buf[:etherTypeOff], buf[vlanHeaderLen:vlanHeaderLen+etherTypeOff])
		tpid := uint16(etherTypeVLAN)
		if aux.Status&unix.TP_STATUS_VLAN_TPID_VALID != 0 {
			tpid = aux.Vlan_tpid
		}
		binary.BigEndian.PutUint16(buf[etherTypeOff:], tpid)
		binary.BigEndian.PutUint16(buf[etherTypeOff+2:], aux.Vlan_tci)
		data = buf[:vlanHeaderLen+captured]
		original += vlanHeaderLen
	}
	frame := make([]byte, len(data))
	copy(frame, data)
	return capture.Packet{
		Timestamp:      ts,
		Interface:      s.name,
		LinkType:       capture.LinkTypeEthernet,
		Data:           frame,
		CaptureLength:  len(frame),
		OriginalLength: original,
	}
}

// Stats folds the kernel counters, which reset on every read, into the
// running totals.
func (s *Source) Stats() capture.Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		if st, err := unix.GetsockoptTpacketStats(s.fd, unix.SOL_PACKET, unix.PACKET_STATISTICS); err == nil {
			s.received += uint64(st.Packets)
			s.dropped += uint64(st.Drops)
		}
	}
	return capture.Stats{Received: s.received, Dropped: s.dropped}
}

func (s *Source) isClosed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Close releases the socket; it is safe to call more than once.
func (s *Source) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return unix.Close(s.fd)
}
