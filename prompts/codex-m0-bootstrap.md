# Codex/ChatGPT Prompt — M0 Bootstrap

Read:

- README.md
- AGENTS.md
- docs/requirements.md
- docs/architecture.md
- docs/safety.md
- docs/roadmap.md
- all Accepted ADRs

Implement **M0 only**.

M0 goal:

> Observe an unknown Ethernet device and track MAC/ARP IPv4 behavior without requiring a known IP address.

Required scope:

- initialize Go module if not already present;
- interface enumeration;
- capture abstraction;
- Linux live capture backend selected by Accepted ADR;
- Ethernet source/destination MAC decode;
- ARP request/reply decode;
- ARP Probe recognition;
- ARP announcement/gratuitous behavior recognition;
- typed observations;
- minimal device correlator keyed conservatively by MAC;
- `wirepup interfaces`;
- passive `wirepup discover -i <iface>`;
- unit tests and offline fixtures.

Do not implement yet:

- LLDP;
- DHCP;
- IPv6;
- VLAN;
- CA/PVA;
- active probing;
- temporary IP configuration;
- TUI.

Hard requirements:

- passive commands transmit nothing;
- decoders do not print;
- decoders do not own device state;
- tests must run unprivileged where possible;
- document any new dependency and license.

At the end report:

- files changed;
- tests added/run;
- privilege requirements;
- unresolved assumptions;
- proposed next task.
