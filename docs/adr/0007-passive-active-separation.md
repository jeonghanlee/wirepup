# ADR-0007: Make passive and active behavior explicit and structurally separate

Status: Accepted

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

## Amendment 2026-09-02: bounds on active behavior

Explicit invocation alone is not enough on a controls network; the amount of traffic an active command can produce must also be bounded by design. Every active command:

- names its targets explicitly: one address, an explicit list, or one prefix no larger than /24; there is no "scan everything reachable" default;
- has a fixed packet budget and rate: at most one packet per target per pass, at most 20 packets per second, and no automatic retry beyond the count printed before transmission;
- prints what it will transmit (protocol, destination, count) before the first packet and lists what it transmitted afterwards under `Executed`;
- sends EPICS CA/PVA searches only to the destinations it prints, never to a discovered list the user has not seen.

Port scanning is not an active command in V1 (`docs/requirements.md` section 3).
