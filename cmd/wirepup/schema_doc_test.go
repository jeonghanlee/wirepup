package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const schemaDoc = "../../docs/output-schema.md"

// TestOutputSchemaDocNamesEveryGoldenKey keeps docs/output-schema.md
// honest: every JSON key that the committed golden outputs contain must
// appear in the document as a backticked name.
func TestOutputSchemaDocNamesEveryGoldenKey(t *testing.T) {
	doc, err := os.ReadFile(schemaDoc)
	if err != nil {
		t.Fatal(err)
	}
	named := map[string]bool{}
	for _, m := range regexp.MustCompile("`([a-z0-9_.*]+)`").FindAllStringSubmatch(string(doc), -1) {
		named[m[1]] = true
	}
	files, _ := filepath.Glob(filepath.Join(goldenDir, "*.jsonl"))
	if len(files) == 0 {
		t.Skip("no golden files")
	}
	seen := map[string]bool{}
	for _, f := range files {
		dec := json.NewDecoder(strings.NewReader(readFile(t, f)))
		for dec.More() {
			var v any
			if err := dec.Decode(&v); err != nil {
				t.Fatalf("%s: %v", f, err)
			}
			collectKeys(v, seen)
		}
	}
	var missing []string
	for k := range seen {
		if !named[k] {
			missing = append(missing, k)
		}
	}
	sort.Strings(missing)
	if len(missing) > 0 {
		t.Fatalf("keys present in golden output but not named in %s: %s", schemaDoc, strings.Join(missing, ", "))
	}
}

func collectKeys(v any, into map[string]bool) {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			into[k] = true
			collectKeys(val, into)
		}
	case []any:
		for _, val := range x {
			collectKeys(val, into)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
