package oui

import (
	"net"
	"path/filepath"
	"testing"
)

const fixture = "../../testdata/fixtures/oui/oui.txt"

func TestLoadFixture(t *testing.T) {
	tbl, err := Load(fixture, nil)
	if err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 3 || filepath.Base(tbl.Path()) != "oui.txt" {
		t.Fatalf("entries %d path %s", tbl.Len(), tbl.Path())
	}
	if v := tbl.Lookup("00:80:f4:12:34:56"); v != "Example Controls GmbH" {
		t.Fatalf("lookup %q", v)
	}
	if v := tbl.Lookup("00:1C:73:AA:BB:CC"); v != "Example Networks Inc." {
		t.Fatalf("upper-case lookup %q", v)
	}
	if v := tbl.Lookup("02:80:f4:12:34:56"); v != "" {
		t.Fatalf("locally administered lookup %q", v)
	}
	if v := tbl.Lookup("00:00:00:00:00:01"); v != "" {
		t.Fatalf("unknown prefix %q", v)
	}
	if v := tbl.Lookup("not a mac"); v != "" {
		t.Fatalf("garbage %q", v)
	}
}

func TestDefaultsFallbackAndMissing(t *testing.T) {
	if _, err := Load("/nonexistent/oui.txt", nil); err == nil {
		t.Fatal("explicit missing file accepted")
	}
	tbl, err := Load("", []string{"/nonexistent/a.txt", fixture})
	if err != nil || tbl.Len() != 3 {
		t.Fatalf("fallback: %v %v", err, tbl)
	}
	if _, err := Load("", []string{"/nonexistent/a.txt"}); err == nil {
		t.Fatal("missing defaults accepted")
	}
	var nilTable *Table
	if nilTable.Lookup("00:80:f4:12:34:56") != "" {
		t.Fatal("nil table lookup")
	}
}

func TestLocallyAdministered(t *testing.T) {
	if !IsLocallyAdministered(net.HardwareAddr{0x02, 0, 0, 0, 0, 0}) || IsLocallyAdministered(net.HardwareAddr{0x00, 0, 0, 0, 0, 0}) {
		t.Fatal("U/L bit")
	}
}
