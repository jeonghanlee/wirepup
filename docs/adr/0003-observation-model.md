# ADR-0003: Protocol decoders emit typed observations

Status: Proposed

## Context

One physical device may be observed through:

- Ethernet;
- LLDP;
- ARP;
- DHCP;
- IPv6 NDP;
- CA;
- PVA.

If each protocol package manages devices directly, state becomes inconsistent and tightly coupled.

## Decision

Protocol decoders emit typed observations.

A separate device-correlation engine consumes observations and maintains inferred device records.

## Example

```text
LLDP -> LLDPObservation
ARP  -> ARPObservation
DHCP -> DHCPObservation
CA   -> CAObservation
PVA  -> PVAObservation
              |
              v
       Device Correlator
```

## Consequences

Benefits:

- independently testable protocol packages;
- consistent multi-protocol correlation;
- easier replay/diagnosis;
- easier addition of future protocols.

Cost:

- observation schemas need deliberate design;
- correlation becomes a first-class subsystem.
