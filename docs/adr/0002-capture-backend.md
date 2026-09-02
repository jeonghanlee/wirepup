# ADR-0002: Abstract capture backend; start with a libpcap-compatible implementation

Status: Proposed

## Context

WirePup needs:

- live Linux capture;
- filtering;
- PCAP interoperability;
- future portability.

Candidate approaches:

- Linux AF_PACKET directly;
- libpcap;
- multiple backends.

## Decision

Define a capture abstraction first.

For the initial vertical slice, prefer a mature libpcap-compatible implementation unless deployment constraints make that impractical.

Preserve the ability to add a native Linux AF_PACKET backend later.

## Rationale

A libpcap-compatible path accelerates:

- live capture;
- BPF filtering;
- PCAP interoperability;
- validation against established tooling.

A backend abstraction prevents libpcap-specific semantics from spreading through the codebase.

## Consequences

- initial builds may depend on libpcap/cgo depending on the chosen Go package;
- packaging requirements must be documented;
- a future pure-Go/Linux backend remains possible.

## Required pre-implementation check

Evaluate candidate Go libraries for:

- maintenance status;
- Linux behavior/performance;
- PCAP/PCAPNG support;
- cgo requirements;
- license compatibility.
