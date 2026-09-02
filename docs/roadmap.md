# Roadmap

Milestones are vertical slices. Each should produce a usable, testable behavior.

## M0 — See an unknown device

Question:

> Can WirePup observe an unknown Ethernet device and track its MAC/IP behavior without knowing the IP first?

Scope:

- Go project bootstrap;
- interface enumeration;
- Linux live capture;
- Ethernet source/destination MAC;
- ARP decode;
- ARP Probe recognition;
- ARP announcement recognition;
- typed observations;
- minimal MAC-based device table;
- passive CLI;
- offline tests.

Exit criteria:

- works against at least one controlled device or replay capture;
- passive mode transmits nothing;
- ARP decoder does not own global device state.

## M1 — Network identity

Add:

- LLDP;
- DHCPv4;
- OUI vendor hints;
- first_seen/last_seen;
- multiple IPv4 addresses;
- device event timeline.

## M2 — IPv6 and VLAN visibility

Add:

- IPv6;
- ICMPv6;
- NDP;
- DAD;
- 802.1Q parsing;
- explicit "VLAN unknown" semantics.

## M3 — Device correlation

Strengthen:

- evidence model;
- confidence;
- multiple addresses/names;
- duplicate-IP clues;
- safe non-merging rules.

## M4 — PCAP interoperability

Add:

- PCAP/PCAPNG write;
- offline read;
- filtering;
- JSON event output.

## M5 — Subnet diagnosis

Add:

- local address/route context;
- same-L2/different-subnet diagnosis;
- temporary-address recommendation;
- address-conflict checks.

No host network changes yet.

## M6 — Explicit temporary connectivity

Add:

- temporary secondary IPv4 workflow;
- reversible state;
- clean removal;
- privilege architecture review.

## M7 — EPICS Channel Access

Add:

- CA framing detection;
- search request;
- search response;
- beacon;
- TCP connection metadata;
- PV/server correlation;
- CA diagnostics.

## M8 — EPICS PVAccess

Add:

- PVA framing;
- search/discovery;
- search response;
- beacon;
- server GUID correlation;
- combined CA/PVA device view.

## M9 — Diagnostic engine

Rules for:

- DHCP Discover with no Offer;
- Auto-IP fallback;
- duplicate IPv4 evidence;
- same-L2/different-subnet;
- unexpected local interface;
- CA/PVA searches without observed response;
- multiple CA server claims;
- discovery activity differing between interfaces.

Every diagnosis should reference evidence.

## M10 — TUI

Optional interactive terminal view:

```text
Devices | Events | EPICS | Interfaces | Diagnostics
```

CLI and JSON remain first-class.

## Later candidates

- Modbus/TCP;
- EtherNet/IP;
- OPC UA;
- improved mDNS/SSDP;
- vendor discovery protocols;
- read-only managed-switch integration;
- topology view;
- compare two captures;
- diagnostic report export.
