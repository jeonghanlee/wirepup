# ADR-0009: Machine-readable output is a versioned contract

Status: Accepted

## Context

R-017 requires JSON for discovery and diagnostic results, and NFR-008 requires that output distinguish observed, inferred, recommended, and executed. Once a script depends on the JSON, field names and semantics are a public contract; internal Go struct layouts must not leak into it by accident.

tshark offers two JSON shapes: `-T json` (one nested document per packet) and `-T ek` (one JSON object per line, for streaming consumers). WirePup needs the streaming shape for `observe` and a document shape for `discover`, `diagnose`, and `interfaces`.

## Decision

- JSON is produced only by `internal/output/json` from dedicated output structs. Internal types (observations, device records, diagnosis results) are never marshalled directly.
- Every document and every stream record carries `"schema": "wirepup/<document>/<major>"`, for example `wirepup/devices/1`, `wirepup/event/1`, `wirepup/diagnosis/1`, `wirepup/interfaces/1`.
- The major number changes only when a field is removed, renamed, or changes meaning. Adding a field does not change it. Consumers must ignore unknown fields.
- `observe --json` writes one JSON object per line (JSON Lines). `discover --json`, `diagnose --json`, and `interfaces --json` write one document.
- A diagnosis document has four top-level arrays named exactly `observed`, `inferred`, `recommended`, and `executed`. Every entry in `inferred` and `recommended` carries an `evidence` array of packet references (`source`, `packet_id`); every `executed` entry records the exact action performed.
- Field names are `snake_case`. Timestamps are RFC 3339 with sub-second digits and a numeric UTC offset. MAC addresses are lower-case and colon-separated. IP addresses use the canonical text form of the Go standard library (`net/netip`).
- Confidence values and observation `Kind` strings (ADR-0008) appear verbatim.

## Consequences

- JSON output gets golden-file tests; a change that breaks a golden file is either a bug or a deliberate major version change recorded in this ADR.
- `docs/output-schema.md` documents every document type from the milestone that introduces JSON output (M4) onward.
- Human-readable text output is a separate renderer over the same output structs and may change freely.
