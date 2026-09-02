# Claude + Codex Collaborative Workflow

## Goal

Use multiple agents without allowing each agent to invent a different architecture.

The repository documents and ADRs are the shared contract.

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
