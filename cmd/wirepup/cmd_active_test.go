package main

import (
	"bytes"
	"encoding/json"
	"testing"
)

// TestActiveReportSource renders an executed-action report the way
// probe, connect, and disconnect do and checks the documented rule: the
// source is the interface, or the literal "active" without one, and the
// interface field is never invented.
func TestActiveReportSource(t *testing.T) {
	render := func(g globalFlags) (source, iface string) {
		var out bytes.Buffer
		g.json = true
		renderExecuted(&env{stdout: &out, stderr: &bytes.Buffer{}}, &g, nil)
		var doc struct {
			Source    string `json:"source"`
			Interface string `json:"interface"`
		}
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatalf("%v\n%s", err, out.String())
		}
		return doc.Source, doc.Interface
	}
	if s, i := render(globalFlags{}); s != "active" || i != "" {
		t.Fatalf("without -i: source %q interface %q", s, i)
	}
	if s, i := render(globalFlags{iface: "enp3s0"}); s != "enp3s0" || i != "enp3s0" {
		t.Fatalf("with -i: source %q interface %q", s, i)
	}
	if s, _ := render(globalFlags{pcap: "issue.pcap"}); s != "active" {
		t.Fatalf("--pcap reported as the source of a transmission: %q", s)
	}
}
