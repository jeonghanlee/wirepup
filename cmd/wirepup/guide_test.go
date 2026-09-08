package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/jeonghanlee/wirepup/internal/output"
)

// Compare the typed result with the document emitted by the same real
// operation, including finding data, evidence and replay timestamps.
func TestGuidedOperationRetainsDiagnosis(t *testing.T) {
	var rendered bytes.Buffer
	e := &env{stdout: &rendered, stderr: &bytes.Buffer{}}
	args := []string{"epics", "find", "DUP:PV", "--pcap", filepath.Join(fixtureDir, "ca-duplicate-servers.pcap"), "--json", "--quiet"}
	r := executeOperation(context.Background(), e, args)
	if r.Code != exitOK || r.Report == nil || r.Source == "" || r.At.IsZero() {
		t.Fatalf("incomplete result: %+v", r)
	}
	var actual output.Diagnosis
	if err := json.Unmarshal(rendered.Bytes(), &actual); err != nil {
		t.Fatal(err)
	}
	want := output.DiagnosisFrom(r.Source, r.At, *r.Report)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("rendered diagnosis differs from retained result: %#v / %#v", actual, want)
	}
}

func TestGuidancePTY(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		t.Skip("PTY guidance test requires Linux or macOS")
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the real PTY integration suite")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	binary := filepath.Join(t.TempDir(), "wirepup")
	if out, err := exec.CommandContext(ctx, "go", "build", "-o", binary, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	if out, err := exec.CommandContext(ctx, python, "../../tests/guidance.py", binary).CombinedOutput(); err != nil {
		t.Fatalf("real PTY suite: %v\n%s", err, out)
	}
}
