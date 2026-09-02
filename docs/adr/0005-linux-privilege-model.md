# ADR-0005: Minimize Linux privileges by operation

Status: Proposed

## Context

WirePup may need raw capture, active probing, and optional local address changes.

These have different privilege requirements.

## Decision

Separate privilege needs by operation.

Target model:

```text
passive capture       raw capture privilege only
active L2 probe       raw transmit privilege
temporary IP change   network-administration privilege
```

Do not make `CAP_NET_ADMIN` a blanket requirement for passive commands.

## Consequences

- CLI must report insufficient privileges clearly;
- helper/subprocess separation may be introduced later;
- privilege-sensitive code requires cross-review.
