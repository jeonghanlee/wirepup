# ADR-0004: Treat device identity as evidence-based inference

Status: Accepted

## Context

A source MAC is extremely useful on a local Ethernet segment but does not always map one-to-one to a physical device.

Examples:

- device with multiple NICs;
- redundancy/virtual MAC;
- bridge/switch;
- virtual machine/container;
- wireless MAC randomization.

## Decision

Use MAC as the strongest initial endpoint key for M0, but model `Device` as an inference backed by evidence.

Do not encode `MAC == physical device` as an invariant.

## Consequences

The data model must support:

- multiple MACs per inferred device when justified;
- confidence/evidence;
- separate LLDP network-neighbor entities;
- conservative merge rules.
