package pcapfile

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/capture"
	"github.com/jeonghanlee/wirepup/internal/fixtures"
)

const fixtureDir = "../../../testdata/pcap"

func drain(t *testing.T, src capture.Source) []capture.Packet {
	t.Helper()
	pkts, errc := src.Packets(context.Background())
	var out []capture.Packet
	for p := range pkts {
		out = append(out, p)
	}
	if err, ok := <-errc; ok && err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRoundTripBothFormats(t *testing.T) {
	for _, ext := range []string{".pcap", ".pcapng"} {
		path := filepath.Join(t.TempDir(), "rt"+ext)
		w, err := Create(path, "enp3s0", 0)
		if err != nil {
			t.Fatal(err)
		}
		in := []capture.Packet{
			fixtures.Packet(0, fixtures.ARPAnnounce(fixtures.DeviceMAC, fixtures.MustAddr("10.0.0.1"))),
			fixtures.Packet(1, fixtures.LLDPFrame(fixtures.SwitchMAC, fixtures.LLDP(fixtures.SwitchMAC, "1", "sw", 120, 0, fixtures.MustAddr("10.0.0.254")))),
		}
		in[1].OriginalLength = in[1].CaptureLength + 100 // truncated capture
		for _, p := range in {
			if err := w.Write(p); err != nil {
				t.Fatal(err)
			}
		}
		if w.Count() != 2 {
			t.Fatalf("count %d", w.Count())
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		r, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if r.LinkType() != capture.LinkTypeEthernet || r.Name() != path {
			t.Fatalf("%s: link %d name %s", ext, r.LinkType(), r.Name())
		}
		out := drain(t, r)
		r.Close()
		if len(out) != 2 {
			t.Fatalf("%s: read %d packets", ext, len(out))
		}
		for i := range in {
			if string(out[i].Data) != string(in[i].Data) || !out[i].Timestamp.Equal(in[i].Timestamp) || out[i].OriginalLength != in[i].OriginalLength || out[i].CaptureLength != len(in[i].Data) {
				t.Fatalf("%s packet %d: %+v vs %+v", ext, i, out[i], in[i])
			}
		}
		wantIface := "pcap"
		if ext == ".pcapng" {
			wantIface = "enp3s0"
		}
		if out[0].Interface != wantIface {
			t.Fatalf("%s interface %q", ext, out[0].Interface)
		}
		if st := r.Stats(); st.Received != 2 || st.Dropped != 0 {
			t.Fatalf("stats %+v", st)
		}
	}
}

func TestOpenErrors(t *testing.T) {
	if _, err := Open(filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Fatal("missing file opened")
	}
	bad := filepath.Join(t.TempDir(), "bad.pcap")
	os.WriteFile(bad, []byte("not a capture file at all"), 0o644)
	if _, err := Open(bad); err != ErrFormat {
		t.Fatalf("bad magic: %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pcap")
	os.WriteFile(empty, nil, 0o644)
	if _, err := Open(empty); err == nil {
		t.Fatal("empty file opened")
	}
}

func TestCommittedFixturesReplay(t *testing.T) {
	entries, err := os.ReadDir(fixtureDir)
	if err != nil {
		t.Skip("fixtures not present")
	}
	n := 0
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".pcap") && !strings.HasSuffix(e.Name(), ".pcapng") {
			continue
		}
		r, err := Open(filepath.Join(fixtureDir, e.Name()))
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		pkts := drain(t, r)
		r.Close()
		if len(pkts) == 0 {
			t.Fatalf("%s: no packets", e.Name())
		}
		n++
	}
	if n == 0 {
		t.Skip("no fixtures")
	}
}

// TestExternalReaderAgrees checks the written file with tcpdump when it
// is installed: the packet count reported by an independent reader must
// match what WirePup wrote.
func TestExternalReaderAgrees(t *testing.T) {
	tcpdump, err := exec.LookPath("tcpdump")
	if err != nil {
		t.Skip("tcpdump not installed")
	}
	for _, ext := range []string{".pcap", ".pcapng"} {
		path := filepath.Join(t.TempDir(), "ext"+ext)
		w, err := Create(path, "enp3s0", 0)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			w.Write(fixtures.Packet(i, fixtures.ARPProbe(fixtures.DeviceMAC, fixtures.MustAddr("169.254.1.1"))))
		}
		w.Close()
		out, err := exec.Command(tcpdump, "-nn", "-r", path).CombinedOutput()
		if err != nil {
			t.Fatalf("%s: tcpdump: %v\n%s", ext, err, out)
		}
		if got := strings.Count(string(out), "ARP, Request who-has 169.254.1.1"); got != 3 {
			t.Fatalf("%s: tcpdump saw %d ARP probes:\n%s", ext, got, out)
		}
	}
}
