# Claude + Codex Collaborative Workflow

## Goal

Use multiple agents without allowing each agent to invent a different architecture.

The repository documents and ADRs are the shared contract.

## V1 delivery sequence

V1 is delivered as one sequence with two independent full reviews. Phase 1 below is complete once the ADRs are Accepted; the Phase 2 parallel split is not used for V1, and Phase 3 applies to increments after V1.

```text
design completion
  ADRs accepted, package layout fixed
        |
        v
Claude: implement V1
  M0 -> M1 -> ... -> M7 CA -> M8 PVA -> M9 diagnose -> M10 TUI
        |
        v
Claude: full self-review and fixes
  prompts/full-repository-review.md
        |
        v
git commit
        |
        v
Codex / ChatGPT: independent full review
  prompts/full-repository-review.md
        |
        v
fixes and tests
        |
        v
release candidate
```

### Reference rule

When a mechanism is unclear, study how established tools solve the same problem before designing one: Wireshark and tshark for dissection, frame references, and JSON shapes; libpcap (`pcap-linux.c`) for Linux capture details; iproute2 for address changes; the `cashark` Wireshark plugin for CA and PVA framing. Adopt the simpler form that fits the ADRs, and name the source in the ADR or the code comment.

## Phase 1 — Architecture

### Claude

Ask Claude to challenge:

- unknown-device discovery;
- capture backend;
- observation model;
- device identity;
- privilege boundaries;
- CA/PVA design.

No implementation yet.

### Second agent

Cross-review Claude's conclusions.

Look specifically for:

- over-coupling;
- hidden active behavior;
- assumptions about VLAN visibility;
- assumptions that MAC always equals physical device;
- incorrect CA/PVA port/protocol assumptions;
- privilege creep.

### Repository owner

Resolve disagreements and mark ADRs Accepted/Rejected/Superseded.

## Phase 2 — M0 parallelization

Suggested split:

### Agent A

```text
capture abstraction
Linux capture implementation
interface enumeration
```

### Agent B

```text
Ethernet/ARP decoder
fixture tests
ARP Probe/announcement interpretation
```

### Integration owner/agent

```text
typed observation model
device correlation
CLI
cross-review
```

Avoid two agents modifying the same package concurrently unless coordinated.

## Phase 3 — Protocol increments

For each new protocol:

1. add/confirm requirement;
2. identify fixture captures;
3. implement decoder;
4. emit observations;
5. add correlation behavior only if needed;
6. add diagnosis rules separately;
7. cross-review.

## Agent handoff template

Every agent should report:

```text
Goal
Files changed
Behavior added
Tests added
Assumptions
Open questions
Architecture impact
Privilege/safety impact
Recommended next task
```

## Architecture-change rule

If an agent discovers that a current ADR blocks a better design:

- do not silently bypass it;
- propose a new ADR or amendment;
- explain migration cost;
- stop architecture-sensitive implementation until decided.
