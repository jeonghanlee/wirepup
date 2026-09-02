# ADR-0007: Make passive and active behavior explicit and structurally separate

Status: Proposed

## Context

Engineering and controls networks can be sensitive to unexpected traffic.

A user running a discovery/diagnostic tool must know whether it is only observing or actively probing.

## Decision

Passive commands must never transmit traffic or change host networking.

Active behavior must live behind explicit commands/options and separate internal interfaces.

## Consequences

Preferred command distinction:

```text
observe/discover/capture/read/diagnose  passive
probe/connect                           active
```

An active CA/PVA PV search must also be explicitly identified as active.

This rule is a safety contract and should be tested.
