package main

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeonghanlee/wirepup/internal/output"
)

func runCLI(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(context.Background(), &env{stdout: &out, stderr: &errb}, args)
	return code, out.String(), errb.String()
}

func TestUsageAndUnknownCommand(t *testing.T) {
	if code, _, _ := runCLI(t); code != exitUsage {
		t.Fatalf("no args exit %d", code)
	}
	if code, _, errs := runCLI(t, "bogus"); code != exitUsage || !strings.Contains(errs, "unknown command") {
		t.Fatalf("unknown command exit %d: %s", code, errs)
	}
	if code, out, _ := runCLI(t, "help"); code != exitOK || !strings.Contains(out, "interfaces") {
		t.Fatalf("help exit %d: %s", code, out)
	}
}

func TestInterfacesText(t *testing.T) {
	code, out, errs := runCLI(t, "interfaces")
	if code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if !strings.HasPrefix(out, "NAME") || !strings.Contains(out, "lo") {
		t.Fatalf("output:\n%s", out)
	}
}

func TestInterfacesJSON(t *testing.T) {
	code, out, _ := runCLI(t, "interfaces", "--json")
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var doc output.Interfaces
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Schema != output.SchemaInterfaces || len(doc.Interfaces) == 0 {
		t.Fatalf("document %+v", doc)
	}
}

func TestObserveRequiresInterface(t *testing.T) {
	code, _, errs := runCLI(t, "observe")
	if code != exitUsage || !strings.Contains(errs, "interface") {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if code, _, errs := runCLI(t, "observe", "-i", "lo", "--protocol", "nope"); code != exitUsage || !strings.Contains(errs, "unknown protocol") {
		t.Fatalf("bad protocol exit %d: %s", code, errs)
	}
}

func TestObserveWithoutPrivilege(t *testing.T) {
	code, _, errs := runCLI(t, "discover", "-i", "lo", "--timeout", "100ms", "--quiet")
	switch code {
	case exitOK:
		t.Log("raw capture is permitted in this environment")
	case exitPrivilege:
		if !strings.Contains(errs, "CAP_NET_RAW") {
			t.Fatalf("privilege message: %s", errs)
		}
	default:
		t.Fatalf("exit %d: %s", code, errs)
	}
}

func TestDiscoverRejectsMissingExplicitOUIFile(t *testing.T) {
	code, _, errs := runCLI(t, "discover", "-i", "lo", "--oui-file", "/nonexistent/oui.txt")
	if code != exitUsage || !strings.Contains(errs, "oui") {
		t.Fatalf("exit %d: %s", code, errs)
	}
}
