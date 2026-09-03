// Package pcapfile reads and writes PCAP and PCAPNG files through
// gopacket/pcapgo (ADR-0002) so that replay and live capture share one
// analysis pipeline. The format is detected from the file magic.
package pcapfile

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcapgo"

	"github.com/jeonghanlee/wirepup/internal/capture"
)

// File magic values (host order as read from the first four bytes).
const (
	magicPcapLE     = 0xd4c3b2a1
	magicPcapBE     = 0xa1b2c3d4
	magicPcapNanoLE = 0x4d3cb2a1
	magicPcapNanoBE = 0xa1b23c4d
	magicPcapng     = 0x0a0d0d0a
	magicLen        = 4
)

// Sizes and names.
const (
	packetBuffer   = 256
	DefaultSnapLen = 262144
	extPcapng      = ".pcapng"
	unnamedIface   = "pcap"
)

// ErrFormat reports a file that is neither PCAP nor PCAPNG.
var ErrFormat = errors.New("pcapfile: not a pcap or pcapng file")

// Reader is a file-backed capture source.
type Reader struct {
	name  string
	f     *os.File
	pcap  *pcapgo.Reader
	ng    *pcapgo.NgReader
	link  capture.LinkType
	names map[int]string

	mu       sync.Mutex
	received uint64
	closed   bool
}

// Open opens a PCAP or PCAPNG file for replay.
func Open(path string) (*Reader, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("pcapfile: %w", err)
	}
	br := bufio.NewReader(f)
	head, err := br.Peek(magicLen)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("pcapfile: %w", ErrFormat)
	}
	r := &Reader{name: path, f: f, names: map[int]string{}}
	switch binary.BigEndian.Uint32(head) {
	case magicPcapng:
		ng, err := pcapgo.NewNgReader(br, pcapgo.DefaultNgReaderOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("pcapfile: %w", err)
		}
		r.ng = ng
		r.link = capture.LinkType(ng.LinkType())
		for i := 0; i < ng.NInterfaces(); i++ {
			if ifc, err := ng.Interface(i); err == nil && ifc.Name != "" {
				r.names[i] = ifc.Name
			}
		}
	case magicPcapLE, magicPcapBE, magicPcapNanoLE, magicPcapNanoBE:
		p, err := pcapgo.NewReader(br)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("pcapfile: %w", err)
		}
		r.pcap = p
		r.link = capture.LinkType(p.LinkType())
	default:
		f.Close()
		return nil, ErrFormat
	}
	return r, nil
}

// Name returns the file path.
func (r *Reader) Name() string { return r.name }

// LinkType returns the file's link type.
func (r *Reader) LinkType() capture.LinkType { return r.link }

// Packets replays the file. The channel closes at end of file.
func (r *Reader) Packets(ctx context.Context) (<-chan capture.Packet, <-chan error) {
	out := make(chan capture.Packet, packetBuffer)
	errc := make(chan error, 1)
	go func() {
		defer close(out)
		defer close(errc)
		for ctx.Err() == nil {
			data, ci, err := r.read()
			if err != nil {
				if !errors.Is(err, io.EOF) {
					errc <- fmt.Errorf("pcapfile: %w", err)
				}
				return
			}
			r.mu.Lock()
			r.received++
			r.mu.Unlock()
			pkt := capture.Packet{
				Timestamp:      ci.Timestamp,
				Interface:      r.ifaceName(ci.InterfaceIndex),
				LinkType:       r.link,
				Data:           data,
				CaptureLength:  ci.CaptureLength,
				OriginalLength: ci.Length,
			}
			select {
			case out <- pkt:
			case <-ctx.Done():
				return
			}
		}
	}()
	return out, errc
}

func (r *Reader) read() ([]byte, gopacket.CaptureInfo, error) {
	if r.ng != nil {
		return r.ng.ReadPacketData()
	}
	return r.pcap.ReadPacketData()
}

func (r *Reader) ifaceName(idx int) string {
	if n, ok := r.names[idx]; ok {
		return n
	}
	return unnamedIface
}

// Stats reports the packets read; a file never drops.
func (r *Reader) Stats() capture.Stats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return capture.Stats{Received: r.received}
}

// Close closes the file.
func (r *Reader) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return nil
	}
	r.closed = true
	return r.f.Close()
}

// Writer writes packets to a PCAP or PCAPNG file; the format follows
// the file extension (".pcapng" selects PCAPNG).
type Writer struct {
	f     *os.File
	w     *bufio.Writer
	pcap  *pcapgo.Writer
	ng    *pcapgo.NgWriter
	count uint64
}

// Create creates the output file. The interface name is recorded in a
// PCAPNG interface description block.
func Create(path, iface string, snapLen int) (*Writer, error) {
	if snapLen <= 0 {
		snapLen = DefaultSnapLen
	}
	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("pcapfile: %w", err)
	}
	w := &Writer{f: f, w: bufio.NewWriter(f)}
	if strings.EqualFold(filepath.Ext(path), extPcapng) {
		ng, err := pcapgo.NewNgWriterInterface(w.w, pcapgo.NgInterface{
			Name:       iface,
			LinkType:   layers.LinkTypeEthernet,
			SnapLength: uint32(snapLen),
		}, pcapgo.DefaultNgWriterOptions)
		if err != nil {
			f.Close()
			return nil, fmt.Errorf("pcapfile: %w", err)
		}
		w.ng = ng
		return w, nil
	}
	p := pcapgo.NewWriter(w.w)
	if err := p.WriteFileHeader(uint32(snapLen), layers.LinkTypeEthernet); err != nil {
		f.Close()
		return nil, fmt.Errorf("pcapfile: %w", err)
	}
	w.pcap = p
	return w, nil
}

// Write appends one packet.
func (w *Writer) Write(pkt capture.Packet) error {
	ci := gopacket.CaptureInfo{Timestamp: pkt.Timestamp, CaptureLength: len(pkt.Data), Length: pkt.OriginalLength}
	if ci.Length < ci.CaptureLength {
		ci.Length = ci.CaptureLength
	}
	var err error
	if w.ng != nil {
		err = w.ng.WritePacket(ci, pkt.Data)
	} else {
		err = w.pcap.WritePacket(ci, pkt.Data)
	}
	if err != nil {
		return fmt.Errorf("pcapfile: %w", err)
	}
	w.count++
	return nil
}

// Count returns the packets written.
func (w *Writer) Count() uint64 { return w.count }

// Close flushes and closes the file.
func (w *Writer) Close() error {
	var first error
	if w.ng != nil {
		first = w.ng.Flush()
	}
	if err := w.w.Flush(); err != nil && first == nil {
		first = err
	}
	if err := w.f.Close(); err != nil && first == nil {
		first = err
	}
	if first != nil {
		return fmt.Errorf("pcapfile: %w", first)
	}
	return nil
}
