// Package boundary holds the import-graph test that keeps transmission
// and host-configuration code out of every passive package (ADR-0007,
// ADR-0010, docs/architecture.md section 17).
package boundary

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/jeonghanlee/wirepup"

var passivePackages = []string{
	"./internal/capture/...",
	"./internal/observation",
	"./internal/decode",
	"./internal/protocol/...",
	"./internal/epics/...",
	"./internal/device",
	"./internal/oui",
	"./internal/interfaces",
	"./internal/diagnose",
	"./internal/output/...",
	"./internal/tui/...",
}

var forbidden = []string{module + "/internal/active", module + "/internal/networkcfg"}

func TestPassivePackagesNeverImportActiveCode(t *testing.T) {
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go toolchain not on PATH")
	}
	args := append([]string{"list", "-e", "-deps", "-f", "{{.ImportPath}}"}, passivePackages...)
	cmd := exec.Command(goBin, args...)
	cmd.Dir = "../.."
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		for _, f := range forbidden {
			if strings.TrimSpace(line) == f {
				t.Fatalf("passive package graph reaches %s", f)
			}
		}
	}
	if !strings.Contains(string(out), module+"/internal/decode") {
		t.Fatalf("dependency listing looks wrong:\n%s", out)
	}
}
