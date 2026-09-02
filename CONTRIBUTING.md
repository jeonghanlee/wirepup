# Contributing

## Workflow

1. Read the relevant design documents.
2. Identify a small issue/task.
3. Add or update tests first when practical.
4. Keep commits focused.
5. Update documentation when externally visible behavior changes.
6. Add an ADR for decisions difficult or expensive to reverse.
7. Validate packet-parsing changes against stored fixtures.
8. Validate privileged/network-changing features only in controlled environments.

## Commit examples

```text
capture: add Linux live packet source
arp: decode ARP probe and announcement
device: correlate MAC and IPv4 observations
lldp: decode system and port identity
epics/ca: decode search request
diagnose: report same-L2 different-subnet condition
```

## Definition of done

A feature is complete when:

- behavior is documented;
- unit tests pass;
- relevant fixture/PCAP tests pass;
- errors are understandable;
- passive-mode guarantees are preserved;
- privilege requirements are documented;
- no unrelated architecture changes are introduced.
