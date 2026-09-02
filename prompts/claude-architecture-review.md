# Claude Prompt — Initial Architecture Review

Read the repository in this order:

1. README.md
2. docs/requirements.md
3. docs/architecture.md
4. docs/protocol-scope.md
5. docs/safety.md
6. docs/roadmap.md
7. all docs/adr/*.md
8. AGENTS.md

Do not implement code yet.

Review WirePup as a Linux-first, lightweight engineering network discovery and diagnostic tool.

Focus on:

1. Whether an unknown device can be discovered without knowing its IP address.
2. Whether the observation/device-correlation model cleanly supports Ethernet, LLDP, ARP, DHCP, NDP, CA, and PVA.
3. Whether device identity is too strongly tied to MAC.
4. Whether passive and active behavior are structurally separated.
5. Linux privilege requirements and privilege minimization.
6. Capture backend options and whether the proposed abstraction is sufficient.
7. PCAP/PCAPNG interoperability.
8. Correctness of CA/PVA discovery architecture and default-port assumptions.
9. Architectural decisions that would be expensive to change later.
10. M0 scope: whether it is small enough to validate quickly but still proves the architecture.

Produce:

- blocking design issues;
- non-blocking recommendations;
- ADRs that should be changed/added;
- assumptions that need validation from real packet captures;
- a concrete M0 implementation plan;
- a proposed package tree for M0 only.

Do not write implementation code.
