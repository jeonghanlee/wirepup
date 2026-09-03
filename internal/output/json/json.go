// Package json renders output structs as JSON documents or JSON Lines
// (ADR-0009).
package json

import (
	"encoding/json"
	"io"
)

const indent = "  "

// Document writes one indented JSON document.
func Document(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", indent)
	return enc.Encode(v)
}

// Line writes one compact JSON object followed by a newline.
func Line(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}
