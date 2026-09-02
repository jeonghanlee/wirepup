# WirePup Bootstrap Guide

This is the recommended path from documentation to the first working implementation.

## 1. Create the local repository

Copy this bootstrap package into a new directory named `wirepup`, then:

```bash
cd wirepup
git init
git add .
git commit -m "docs: bootstrap WirePup design"
```

Optionally create a private remote later. Keep development local-first.

## 2. Read the source-of-truth documents

Before implementation:

```text
README.md
docs/requirements.md
docs/architecture.md
docs/protocol-scope.md
docs/safety.md
docs/roadmap.md
docs/adr/*
```

## 3. Review the proposed ADRs

The included ADRs are marked **Proposed**.

Do not automatically mark them Accepted.

Recommended first review order:

```text
0000 Apache-2.0 license
0001 Go language
0002 capture backend abstraction
0003 observation model
0004 device identity
0005 Linux privilege model
0006 EPICS CA/PVA first-class support
0007 passive/active separation
```

After review, change each ADR status to `Accepted`, `Superseded`, or keep `Proposed`.

## 4. Ask Claude for architecture review

Use:

```text
prompts/claude-architecture-review.md
```

Do not ask Claude to implement code yet.

Commit the review separately if you want to preserve it:

```bash
git add docs/
git commit -m "docs: incorporate architecture review"
```

## 5. Cross-review the architecture

Give Claude's review and the updated repository to another coding agent and use:

```text
prompts/cross-review.md
```

Resolve blocking disagreements before M0.

## 6. Start M0

M0 question:

> Can WirePup observe an unknown Ethernet device and track its MAC/IP behavior without needing a known IP address?

Minimum scope:

- Go module/bootstrap;
- interface enumeration;
- Linux live capture;
- Ethernet source/destination MAC;
- ARP parser;
- ARP probe recognition;
- ARP announcement recognition;
- typed observations;
- minimal device correlation;
- passive CLI;
- offline tests.

Use:

```text
prompts/codex-m0-bootstrap.md
```

## 7. First real-world validation

Use a controlled network:

```text
Laptop ---- small switch/direct link ---- test device
```

Prefer a device that:

- starts without DHCP or uses Auto-IP;
- emits ARP;
- optionally emits LLDP.

Verify:

- no packets are transmitted by passive mode;
- MAC appears before/without known IP;
- Auto-IP behavior is interpreted correctly;
- observations retain packet/time/interface evidence.

## 8. Capture fixtures

Save sanitized captures under:

```text
testdata/pcap/
```

Recommended initial files:

```text
arp-request.pcap
arp-probe.pcap
arp-autoip-announcement.pcap
lldp-single-neighbor.pcap
dhcp-discover.pcap
```

Never commit sensitive production captures without sanitizing them.

## 9. Progress milestone by milestone

Follow `docs/roadmap.md`.

Do not jump directly to a TUI or GUI. Keep the protocol, observation, correlation, and diagnosis layers independently testable first.
