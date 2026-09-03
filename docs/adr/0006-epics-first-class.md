# ADR-0006: Treat EPICS CA and PVA as first-class protocols

Status: Accepted

## Context

WirePup is intended for laboratory/controls engineering, where generic packet viewing does not directly answer common EPICS discovery questions.

## Decision

Support both Channel Access and PVAccess as first-class protocol decoders and diagnosis inputs.

Initial defaults:

```text
CA:
  server/search   5064
  repeater/beacon 5065

PVA:
  UDP search      5076
  TCP server      5075
```

Ports are defaults only and can be overridden by EPICS configuration.

Protocol identification must validate packet structure and semantics rather than relying only on port numbers.

## Consequences

WirePup can provide domain-specific diagnostics such as:

- search observed / no response observed;
- responding IOC/server identity;
- broadcast/search destination visibility;
- server beacon visibility;
- apparent duplicate CA PV claims;
- CA/PVA visibility differences across interfaces.
