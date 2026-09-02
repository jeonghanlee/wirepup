# AGENTS.md — Multi-agent development rules

WirePup is designed for collaborative development by the repository owner and coding assistants such as Claude and Codex/ChatGPT.

Repository documentation is the shared source of truth.

## Before changing code

Read:

1. `README.md`
2. `docs/requirements.md`
3. `docs/architecture.md`
4. `docs/protocol-scope.md`
5. `docs/safety.md`
6. relevant ADRs
7. existing tests for the subsystem being changed

Do not introduce an architecture pattern that conflicts with these documents without proposing an ADR.

## Core engineering rules

### Protocol decoders emit observations

Preferred flow:

```text
packet -> decoder -> typed observation -> device engine -> diagnosis/output
```

A decoder must not:

- update global device state;
- print user-facing output;
- change host networking;
- initiate probes.

### Passive mode stays passive

Commands documented as passive must not transmit packets or change host configuration.

No hidden:

- ARP probes;
- ping;
- service scans;
- CA/PVA active searches;
- secondary IP assignment;
- route changes.

### Active actions require explicit user intent

Any action that transmits or modifies host networking must be explicitly selected and reported.

### Preserve evidence

Diagnostics should retain enough evidence to explain their conclusions.

Distinguish:

```text
Observed
Inferred
Recommended
Executed
```

### Prefer deterministic offline tests

Protocol parsing and most diagnosis logic should be testable from byte fixtures and PCAP files without root access.

### Least privilege

Do not require `CAP_NET_ADMIN` for passive capture.

### Controls-network safety

Do not add write-capable PLC/industrial actions or aggressive scans without a separate architecture/safety review.

## Suggested ownership split

Example:

```text
Claude
  protocol decoder implementation
  protocol fixture analysis
  parser tests

Codex / ChatGPT
  capture abstraction
  observation/device model
  CLI integration
  architecture consistency review

Repository owner
  architecture approval
  merge/review
  hardware validation
  network-safety decisions
```

Ownership may rotate by milestone.

## Cross-review required for

Prefer a second-agent review for changes affecting:

- packet parsing;
- device correlation;
- Linux capabilities/privileges;
- temporary address assignment;
- CA/PVA semantics;
- active scanning;
- output schema;
- architecture or ADRs.
