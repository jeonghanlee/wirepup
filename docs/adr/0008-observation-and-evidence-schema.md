# ADR-0008: Typed observations carry evidence and confidence

Status: Accepted

## Context

ADR-0003 fixes the flow `packet -> decoder -> typed observation -> device engine -> diagnosis/output` and leaves the observation schema to be designed. That schema is expensive to change later: every decoder, the device correlator, the diagnosis rules, the JSON output (ADR-0009), and every fixture test depend on it.

`docs/architecture.md` sections 4, 5, and 13 sketch the observation types, an `Evidence` concept, and three confidence levels. This ADR fixes those sketches.

Wireshark solves the same traceability problem with the frame number: every dissected field is reachable from the 1-based frame index within one capture file, and `frame.time`, `frame.interface_id`, and `frame.protocols` carry the capture context. WirePup adopts the same reference scheme rather than inventing another.

## Decision

### Evidence

Package `internal/observation` defines one `Evidence` value that every observation embeds:

```text
Evidence
  Timestamp   capture time supplied by the capture source (kernel timestamp for
              live capture, record timestamp for a PCAP/PCAPNG file)
  Interface   capture interface name, or the interface name recorded in the file
  PacketID    1-based frame number within one capture source; every record
              counts, decoded or not, so it equals the Wireshark frame number
              of the same file
  Protocol    name of the decoder that produced the observation, for example
              "arp", "lldp", "epics.ca"
  Confidence  confirmed | strong_hint | weak_hint
```

`PacketID` restarts at 1 for every capture source (one live session, one file). Output documents name the source so that `(source, PacketID)` is unambiguous.

### Observation types

Every observation is a Go struct that embeds `Evidence` and reports a `Kind`: a stable string such as `arp`, `lldp`, `ca.search`. Observation types are declared next to the parser that produces them (`internal/protocol/arp` declares the ARP observation; `internal/epics/ca` declares the CA observations). `Kind` strings are part of the public JSON contract (ADR-0009) and are not renamed casually.

### Parsers and the frame pipeline

Each protocol package exposes a pure parser from bytes to a message struct or an error. Parsers never read or write device state, never print, and never transmit; they are testable from byte fixtures without root.

The frame pipeline in `internal/decode` runs the parsers in link-layer order (Ethernet, 802.1Q, then ARP or IPv4 or IPv6, then UDP or TCP, then application protocols), attaches `Evidence`, and emits observations. Live capture and file replay feed the same pipeline.

### Confidence

- `confirmed`: framing validated and the semantic fields checked.
- `strong_hint`: framing validated but at least one semantic field could not be checked, or identification relies on a well-known port plus partial validation.
- `weak_hint`: port number or heuristic only.

Confidence describes how sure the parser is that the bytes are what the observation claims. It is not a statement about the device.

### Immutability

Observations are values. Once emitted they are not modified. A consumer that adds interpretation (a device event, a diagnosis) produces a new record that references the supporting observations by `PacketID`.

### VLAN visibility

An 802.1Q tag is recorded on the frame-level observation only when the tag was present in the bytes the capture source delivered (natively, or reinserted from `PACKET_AUXDATA` as ADR-0002 describes). A frame without a tag is reported as `vlan: unknown`, never as "no VLAN": an access port normally strips the tag before the frame reaches the host (R-009).

VLAN membership learned from another protocol (for example an LLDP port VLAN ID TLV) is an inference that the device correlator attaches to a device record with its own evidence reference. It is never written back onto a frame observation.

## Consequences

- Fixture tests assert on parser output; pipeline tests assert on observation kinds and evidence.
- The device correlator and the diagnosis engine cite `PacketID` values as evidence; renderers print them, so an engineer can open the same capture in Wireshark and jump to the frame.
- Adding a protocol means one parser package, one or more observation types, and one dispatch entry in the pipeline.
- Observation structs are internal; the JSON shape is defined separately (ADR-0009).
