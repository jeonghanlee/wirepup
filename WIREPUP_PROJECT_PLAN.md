# WirePup — Complete Project Plan


---

## Source: `README.md`

# WirePup

**WirePup** is a lightweight, engineer-focused network discovery and diagnostic tool for laboratory, controls, commissioning, and troubleshooting work.

WirePup is **not** intended to replace Wireshark. Wireshark is a general-purpose packet analyzer. WirePup focuses on quickly answering practical field questions such as:

- What is physically connected to this Ethernet link?
- What MAC addresses are present even when IP addresses are unknown?
- Is a newly powered device trying DHCP, IPv4 Link-Local/Auto-IP, static addressing, or IPv6 autoconfiguration?
- Is a device on the same Layer-2 segment but a different IPv4 subnet?
- What switch and switch port am I connected to?
- Is there evidence of VLAN tagging or VLAN-related LLDP information?
- Can I temporarily add a safe secondary local IP to reach a directly connected device?
- Are EPICS Channel Access (CA) or PVAccess (PVA) discovery packets present?
- Why is an IOC or PV not visible from this host?

## Project identity

**Name:** WirePup  
**Tagline:** A lightweight network discovery and diagnostic tool for engineers.  
**License:** Apache License 2.0  
**Initial platform:** Linux  
**Initial implementation language:** Go  
**Development model:** local-first, documentation-first, multi-agent assisted

## Core goals

WirePup should:

1. Work locally on a laptop without requiring a central service.
2. Discover devices before their IP configuration is known.
3. Treat MAC identity and Layer-2 observations as first-class data.
4. Correlate LLDP, ARP, DHCP, IPv6, CA, and PVA observations into device records.
5. Separate passive observation from active probing.
6. Provide actionable diagnostics, not only raw packet dumps.
7. Read/write standard packet captures for Wireshark interoperability.
8. Treat EPICS CA and PVA as first-class controls protocols.
9. Remain small enough to deploy as a practical engineering tool.
10. Prefer safe, explainable behavior suitable for laboratory and controls networks.

## Non-goals

Initial versions will not attempt to:

- replace Wireshark's full protocol coverage;
- implement every application protocol;
- perform aggressive vulnerability scanning;
- exploit devices;
- automatically reconfigure production switches;
- silently modify host network configuration;
- perform write operations against PLC/industrial protocols;
- guarantee discovery of a completely silent device that emits no traffic and is not visible through a managed switch.

## Core architecture

```text
Live Interface / PCAP
        |
        v
+-------------------+
| Capture Backend   |
+-------------------+
        |
        v
+-------------------+
| Frame Decoding    |
+-------------------+
        |
        v
+-------------------+
| Protocol Decoders |
| LLDP ARP DHCP NDP |
| CA PVA ...        |
+-------------------+
        |
        v
+-------------------+
| Typed Observations|
+-------------------+
        |
        v
+-------------------+
| Device Correlator |
+-------------------+
        |
        +--------------------+
        |                    |
        v                    v
+-------------------+  +------------------+
| Diagnosis Engine  |  | Event Stream     |
+-------------------+  +------------------+
        |
        v
+-------------------+
| CLI / JSON / TUI  |
+-------------------+
```

The central rule is:

> **Protocol decoders decode packets and emit observations. They do not own global device state.**

## Proposed command families

```text
wirepup interfaces    # local interfaces
wirepup observe       # passive event stream
wirepup discover      # passive device-oriented discovery
wirepup capture       # capture to PCAP/PCAPNG
wirepup read          # offline packet analysis
wirepup diagnose      # rule-based diagnosis
wirepup epics         # CA/PVA focused tools

wirepup probe         # explicitly active discovery
wirepup connect       # explicitly change local secondary IP
wirepup disconnect    # remove WirePup-created temporary configuration
```

Passive commands must never transmit packets or change the host configuration.

## Example: unknown device

```text
$ sudo wirepup discover -i enp3s0

Listening on enp3s0...

NEW DEVICE
MAC        00:80:F4:12:34:56
IPv4       unknown
Seen via   Ethernet

UPDATE
MAC        00:80:F4:12:34:56
IPv4       169.254.22.31
Seen via   ARP Probe

UPDATE
MAC        00:80:F4:12:34:56
IPv4       169.254.22.31
Seen via   ARP Announcement
Method     IPv4 Link-Local / Auto-IP
```

## Example: same Layer 2, different subnet

```text
$ wirepup diagnose 192.168.1.100

Observed target
  MAC       00:80:F4:12:34:56
  IPv4      192.168.1.100

Local host
  enp3s0    10.20.30.51/24

Diagnosis
  ✓ Layer-2 evidence observed on enp3s0
  ✗ Target IPv4 is outside all configured local IPv4 subnets

Recommendation
  Consider a temporary secondary address in 192.168.1.0/24.

No host network configuration will be changed without explicit user action.
```

## Example: EPICS CA

```text
$ wirepup epics observe -i enp3s0

CA SEARCH
Client      10.20.4.88
Destination 10.20.4.255:5064
PV          MPS:SYS:STATE

CA SEARCH RESPONSE
Server      10.20.4.31
TCP port    5064
PV          MPS:SYS:STATE
```

The default CA server/search port is 5064 and the default CA repeater/beacon port is 5065, unless overridden by EPICS configuration.

## Example: EPICS PVA

```text
PVA SEARCH
Client      10.20.4.88
Destination 10.20.4.255:5076
PV          MPS:SYS:STATE

PVA SEARCH RESPONSE
Server      10.20.4.31
TCP port    5075
PV          MPS:SYS:STATE
```

The default PVA UDP search/broadcast port is 5076 and the default PVA TCP server port is 5075, unless overridden.

## Repository layout

```text
wirepup/
├── README.md
├── LICENSE
├── AGENTS.md
├── CLAUDE.md
├── CONTRIBUTING.md
├── BOOTSTRAP.md
├── docs/
│   ├── requirements.md
│   ├── architecture.md
│   ├── protocol-scope.md
│   ├── cli-design.md
│   ├── safety.md
│   ├── testing.md
│   ├── roadmap.md
│   ├── ai-workflow.md
│   ├── references.md
│   └── adr/
├── prompts/
│   ├── claude-architecture-review.md
│   ├── codex-m0-bootstrap.md
│   └── cross-review.md
├── testdata/
└── internal/             # created during implementation
```

## Development order

1. Review and accept/revise ADRs.
2. Have Claude review the architecture before code is written.
3. Cross-review Claude's findings.
4. Implement M0: Ethernet + ARP + device observation.
5. Validate with offline captures and one controlled real device.
6. Add LLDP/DHCP, then IPv6/VLAN.
7. Stabilize device correlation.
8. Add PCAP interoperability and diagnosis.
9. Add CA.
10. Add PVA.
11. Add temporary-IP workflow only after privilege/safety review.

See `BOOTSTRAP.md` for the exact starting workflow.


---

## Source: `BOOTSTRAP.md`

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


---

## Source: `docs/requirements.md`

# WirePup Requirements

## 1. Purpose

WirePup is a local network discovery and diagnostic tool aimed at engineers commissioning and troubleshooting Ethernet-connected equipment, especially laboratory and controls systems.

The primary use case is a laptop connected to an unknown or partially configured network/device where IP addressing, VLAN placement, switch attachment, or controls-protocol visibility may be unclear.

## 2. Functional requirements

### R-001 Interface discovery

WirePup shall enumerate local network interfaces and report at minimum:

- interface name;
- MAC address;
- administrative/link state when available;
- MTU;
- assigned IPv4 addresses;
- assigned IPv6 addresses.

### R-002 Passive Ethernet observation

WirePup shall capture Ethernet frames from a selected interface without transmitting traffic in passive mode.

### R-003 Unknown-MAC discovery

WirePup shall identify source MAC addresses observed on the selected Layer-2 network even when no usable IP address is known.

### R-004 LLDP discovery

WirePup shall decode LLDP and expose, when present:

- chassis ID;
- port ID;
- TTL;
- port description;
- system name;
- system description;
- management address;
- system capabilities;
- VLAN-related TLVs supported by the decoder.

### R-005 ARP behavior

WirePup shall distinguish at minimum:

- ARP request;
- ARP reply;
- ARP probe;
- gratuitous ARP / announcement where recognizable.

### R-006 DHCPv4 state

WirePup shall identify common DHCPv4 messages:

- Discover;
- Offer;
- Request;
- ACK;
- NAK.

It should associate client identity with MAC address where possible.

### R-007 IPv4 Link-Local / Auto-IP

WirePup shall recognize behavior associated with IPv4 Link-Local addressing (`169.254.0.0/16`) including ARP probing and announcement.

### R-008 IPv6 neighbor behavior

WirePup shall decode enough ICMPv6/NDP to identify:

- Neighbor Solicitation;
- Neighbor Advertisement;
- Router Solicitation;
- Router Advertisement;
- Duplicate Address Detection patterns.

### R-009 VLAN observation

WirePup shall decode IEEE 802.1Q tags when visible to the host.

WirePup must not assume that absence of a VLAN tag means no VLAN exists. Access ports commonly remove tags before frames reach endpoints.

### R-010 Device correlation

WirePup shall maintain a device model that correlates observations using strong evidence such as:

- source MAC;
- explicit protocol identifiers;
- stable address relationships.

It must avoid merging two devices solely because they share a hostname or vendor.

### R-011 Multiple addresses

A device record shall support multiple observed:

- MAC addresses where justified;
- IPv4 addresses;
- IPv6 addresses;
- names;
- protocols;
- first/last observation timestamps.

### R-012 Same-L2 / different-subnet diagnosis

When evidence indicates a device is present at Layer 2 but its IPv4 address is outside all configured local IPv4 subnets, WirePup shall report that condition separately from ordinary IP reachability failure.

### R-013 Temporary secondary IP recommendation

WirePup may recommend a candidate temporary IPv4 address for a device on the same observed Layer-2 segment but a different subnet.

A recommendation must:

- avoid addresses already observed;
- avoid network/broadcast addresses;
- clearly state that it is a recommendation;
- not be applied automatically.

### R-014 Temporary secondary IP assignment

A future active command may add a temporary secondary IP to a selected local interface.

This action must:

- require explicit invocation;
- report the exact address and interface;
- perform reasonable conflict checks first;
- record what WirePup added;
- support clean removal;
- never silently replace a primary address.

### R-015 PCAP interoperability

WirePup shall be able to read standard packet capture files.

Capture mode should produce files usable by Wireshark.

### R-016 Packet/event summary

WirePup shall provide a compact summary for supported packets/events.

### R-017 Structured output

Major discovery and diagnostic results shall support machine-readable JSON.

### R-018 EPICS Channel Access

WirePup shall treat EPICS Channel Access as a first-class controls protocol.

Initial CA scope:

- recognize CA payload semantics rather than port alone;
- decode UDP search requests;
- decode search responses;
- recognize server beacons where practical;
- identify TCP virtual-circuit establishment metadata where practical;
- associate CA servers with IP/device records;
- retain PV search IDs/names when available;
- diagnose common discovery-path symptoms.

Default ports, unless overridden:

- CA server/search: 5064;
- CA repeater/beacon: 5065.

### R-019 EPICS PVAccess

WirePup shall treat EPICS PVAccess as a first-class controls protocol.

Initial PVA scope:

- recognize PVA framing/semantics rather than port alone;
- decode search/discovery messages;
- decode search responses;
- decode server beacon information where practical;
- associate PVA server GUID/address/port with device records;
- retain PV search information when available.

Default ports, unless overridden:

- UDP search/broadcast: 5076;
- TCP server: 5075.

### R-020 EPICS diagnosis

WirePup should report conditions such as:

- client search observed but no response observed within the observation window;
- discovery activity present on one interface but not another;
- local subnet/broadcast mismatch relevant to discovery;
- multiple CA servers apparently claiming the same PV when evidence is sufficient;
- CA/PVA server announcements without expected client visibility.

The tool must distinguish a network observation from a claim that a PV definitely does or does not exist.

### R-021 OUI/vendor hints

WirePup may identify a vendor from MAC OUI data.

Vendor identity must be treated as a hint, not proof of exact device model.

### R-022 Device timeline

WirePup should maintain a timeline such as:

```text
10:31 MAC observed
10:32 ARP probe 169.254.11.22
10:33 ARP announcement 169.254.11.22
10:37 DHCP request
10:38 IPv4 observed 10.20.30.42
```

This is particularly useful during commissioning.

## 3. Active-discovery requirements

Active discovery is not required for M0.

When added it must be isolated from passive behavior and may include:

- ARP discovery;
- ICMP probing;
- limited service checks;
- explicit CA/PVA search actions;
- selected protocol-specific discovery.

Aggressive port scanning is not a default goal.

## 4. Non-functional requirements

### NFR-001 Local-first

Core operation shall not depend on cloud services.

### NFR-002 Small deployment footprint

Preferred deployment is a single executable plus optional local data files.

### NFR-003 Explainability

Diagnostic conclusions should retain the observations supporting them.

### NFR-004 Least privilege

Each command should require only the minimum OS privileges needed.

### NFR-005 Testability

Packet decoding must be testable offline using byte fixtures and PCAPs.

### NFR-006 Performance

The tool should comfortably process ordinary engineering-laptop capture rates. It is not initially a high-rate data-center packet recorder.

### NFR-007 Linux first

Linux is the initial platform.

The architecture should avoid unnecessary barriers to future macOS/Windows capture backends.

### NFR-008 Stable semantics

CLI and JSON output should distinguish:

- observed;
- inferred;
- recommended;
- executed.

## 5. Safety requirements

- Passive commands must not transmit.
- Active commands must be explicit.
- Network configuration changes must be reversible.
- WirePup must not automatically change switch configuration.
- Industrial/controls write operations are outside initial scope.


---

## Source: `docs/architecture.md`

# Architecture

## 1. Design principles

WirePup uses an observation-driven architecture.

Central rule:

> **Protocol decoders decode packets; they do not own device state.**

This allows multiple protocols to describe one physical device without coupling parsers to correlation logic.

## 2. Data flow

```text
Network Interface / PCAP
          |
          v
+-----------------------+
| Capture Backend       |
+-----------------------+
          |
          v
+-----------------------+
| Link/Network Decoder  |
+-----------------------+
          |
          v
+-----------------------+
| Protocol Decoders     |
| LLDP ARP DHCP NDP     |
| DNS CA PVA ...        |
+-----------------------+
          |
          v
+-----------------------+
| Observation Stream    |
+-----------------------+
          |
          +-------------------------+
          |                         |
          v                         v
+-----------------------+   +-----------------------+
| Device Correlation    |   | Raw/Event View        |
+-----------------------+   +-----------------------+
          |
          v
+-----------------------+
| Diagnosis Engine      |
+-----------------------+
          |
          v
+-----------------------+
| CLI / JSON / TUI      |
+-----------------------+
```

## 3. Capture abstraction

Live capture and offline replay should implement the same conceptual interface.

Example:

```go
type Packet struct {
    Timestamp      time.Time
    Interface      string
    Data           []byte
    CaptureLength  int
    OriginalLength int
}

type Source interface {
    Packets(ctx context.Context) (<-chan Packet, <-chan error)
    Close() error
}
```

The concrete API may evolve during implementation.

## 4. Decoder model

A decoder consumes packet data or a lower-layer decoded object and emits typed observations.

Examples:

```text
EthernetObservation
VLANObservation
ARPObservation
LLDPObservation
DHCPObservation
IPv6NeighborObservation
CASearchObservation
CASearchResponseObservation
CABeaconObservation
PVASearchObservation
PVASearchResponseObservation
PVABeaconObservation
```

## 5. Evidence

Every observation should preserve enough context to answer:

- when was this seen?
- on which interface?
- which packet/frame produced it?
- which protocol parser produced it?
- what exact fields support this claim?

Concept:

```go
type Evidence struct {
    Timestamp time.Time
    Interface string
    PacketID  uint64
    Protocol  string
}
```

## 6. Device identity

### Initial strong key

For ordinary Ethernet endpoints, source MAC is the strongest initial key.

### Identity is still inferred

Complications include:

- multi-interface equipment;
- redundant controllers;
- bridges;
- virtual machines;
- virtual/redundancy MACs;
- MAC randomization;
- switch control-plane addresses.

Therefore a `Device` is an inferred entity, not absolute truth.

Concept:

```text
Device
  ID
  MACs[]
  IPv4[]
  IPv6[]
  names[]
  vendor_hints[]
  protocols[]
  first_seen
  last_seen
  evidence_refs[]
  confidence
```

## 7. Diagnosis model

Diagnostics must distinguish facts from inference.

Example:

```text
Observed
  ARP frame from MAC A on enp3s0
  ARP sender IPv4 = 192.168.1.100
  local enp3s0 IPv4 = 10.20.30.51/24

Inferred
  MAC A appears to use 192.168.1.100
  IPv4 address is outside the local configured subnet

Recommended
  consider a temporary secondary IPv4 in 192.168.1.0/24
```

Do not present an inference as a packet-level fact.

## 8. Passive/active separation

Recommended command semantics:

```text
wirepup observe      passive event stream
wirepup discover     passive device view
wirepup capture      passive packet capture
wirepup read         offline analysis
wirepup diagnose     passive unless explicitly told otherwise

wirepup probe        active discovery
wirepup connect      explicit temporary network configuration
wirepup disconnect   reverse WirePup-created configuration
```

The separation should exist in package dependencies, not only CLI wording.

## 9. Host network configuration subsystem

`internal/networkcfg` should own explicit host changes such as adding/removing temporary addresses.

Concept:

```text
TemporaryAddressSession
  interface
  address
  prefix
  added_at
  added_by_wirepup
```

WirePup must remove only configuration it knows it added.

## 10. Linux privilege model

Privilege classes:

### Passive capture

Likely root or raw-packet capability depending on backend.

### Active Layer-2 probing

Requires raw-packet access.

### Temporary address changes

Requires administrative networking privilege such as `CAP_NET_ADMIN`.

Design goal:

> Do not grant `CAP_NET_ADMIN` to the entire tool merely because one optional workflow needs it.

A narrow helper/subprocess is preferable if it materially reduces privilege exposure.

## 11. EPICS CA architecture

CA support lives under:

```text
internal/epics/ca
```

Initial observations:

```text
CASearchObservation
CASearchResponseObservation
CABeaconObservation
CAConnectionObservation
```

Important semantics:

- UDP PV searches normally target configured unicast/broadcast destinations at the CA server/search port.
- Default CA server/search port: 5064.
- Default CA repeater/beacon port: 5065.
- Search responses can advertise the TCP port the client should use.
- Do not assume the returned TCP port always equals 5064.

## 12. EPICS PVA architecture

PVA support lives under:

```text
internal/epics/pva
```

Initial observations:

```text
PVASearchObservation
PVASearchResponseObservation
PVABeaconObservation
PVAConnectionObservation
```

Important semantics:

- default UDP search/broadcast port: 5076;
- default TCP server port: 5075;
- PVA search responses include server identity/address/port information;
- PVA server GUIDs are valuable correlation evidence.

## 13. Protocol identification

Do not identify a protocol solely because a packet uses a common port.

Prefer:

```text
port hint + valid framing + semantic field validation
```

Output confidence can be:

```text
confirmed
strong_hint
weak_hint
```

## 14. Output architecture

Human CLI and JSON should be separate renderers over common result models.

Potential future renderers:

- compact table;
- event stream;
- JSON;
- TUI;
- report export.

Protocol decoders must never directly format terminal output.

## 15. Package dependency direction

Preferred direction:

```text
capture
  ↓
decode/protocol
  ↓
observation
  ↓
device
  ↓
diagnose
  ↓
output
```

Avoid cycles.

`networkcfg` must not be reachable through passive code paths except through explicit active workflow boundaries.

## 16. Capture backend strategy

Initial recommendation:

- define capture abstraction first;
- use a mature libpcap-compatible backend for early implementation;
- preserve an option for native Linux AF_PACKET later.

The exact library is intentionally not fixed until ADR-0002 review.


---

## Source: `docs/protocol-scope.md`

# Protocol Scope

## Tier 0 — Foundation

### Ethernet II

Fields:

- source MAC;
- destination MAC;
- EtherType.

### IEEE 802.1Q

Fields when visible:

- VLAN ID;
- priority;
- encapsulated EtherType.

Important:

> An endpoint connected to an access port usually receives untagged frames. Absence of an 802.1Q tag does not prove that no VLAN is configured.

### ARP

Recognize:

- request;
- reply;
- probe;
- gratuitous/announcement patterns.

Primary uses:

- MAC discovery;
- IPv4 observation;
- IPv4 Link-Local/Auto-IP behavior;
- duplicate-address clues;
- same-L2/different-subnet evidence.

### LLDP

Recognize core TLVs:

- chassis ID;
- port ID;
- TTL;
- port description;
- system name;
- system description;
- system capabilities;
- management address.

Add useful organizational TLVs incrementally.

### DHCPv4

Recognize:

- Discover;
- Offer;
- Request;
- ACK;
- NAK.

Capture useful options such as:

- client identifier;
- hostname;
- requested IP;
- server identifier.

### IPv4 / IPv6

Enough parsing for:

- source/destination;
- upper-layer dispatch;
- diagnosis context.

### ICMP / ICMPv6

Initial uses:

- reachability events;
- errors;
- NDP support.

### IPv6 NDP / DAD

Recognize:

- Neighbor Solicitation;
- Neighbor Advertisement;
- Router Solicitation;
- Router Advertisement;
- DAD-style behavior.

## Tier 1 — General troubleshooting

### TCP

Initial scope:

- source/destination;
- ports;
- flags;
- SYN/RST/FIN observations;
- payload dispatch to known decoders when safe.

Full generic stream reassembly is not required initially.

### UDP

Initial scope:

- source/destination;
- ports;
- payload dispatch.

### DNS / mDNS

Useful for general diagnostics and device/service discovery.

## Tier 1 — EPICS Channel Access

CA is a first-class protocol.

### Default ports

Unless overridden:

```text
5064  CA server/search
5065  CA repeater/beacon
```

### Initial semantic targets

- CA protocol framing/version;
- PV search request;
- PV search response;
- server beacon;
- basic TCP virtual-circuit metadata.

### Diagnostic questions

- Are CA searches leaving this interface?
- Which destination/broadcast addresses are used?
- Are search replies observed?
- Which server IP replies?
- Which TCP port is advertised by the reply?
- Does one searched PV appear to receive multiple server claims?
- Are beacons present?
- Are searches visible on an unexpected local interface?

### Important rule

Do not label traffic as CA solely because it uses port 5064/5065. Validate protocol structure where practical.

## Tier 1 — EPICS PVAccess

PVA is a first-class protocol.

### Default ports

Unless overridden:

```text
5076  UDP search/broadcast
5075  TCP server
```

### Initial semantic targets

- PVA message header;
- search request;
- search response;
- server beacon;
- server GUID;
- server address/port;
- basic TCP connection metadata.

### Diagnostic questions

- Is PVA discovery traffic present?
- Which server GUIDs are visible?
- Which server addresses/ports are advertised?
- Are search replies observed?
- Is PVA traffic leaving/arriving on the expected interface?

### Important rule

Do not label traffic as PVA solely because it uses port 5075/5076. Validate PVA framing and message semantics.

## Tier 2 — Controls expansion

Candidates:

- Modbus/TCP;
- EtherNet/IP;
- OPC UA;
- vendor-specific discovery protocols.

These should be added only after the observation/correlation model is stable.

## Protocol confidence

Each decoder should expose one of:

```text
confirmed
strong_hint
weak_hint
```

where useful.

Port number alone should generally be only a hint.

## Encrypted traffic

WirePup is not initially intended to decrypt encrypted application traffic.

It may still report connection metadata and validated protocol hints.


---

## Source: `docs/cli-design.md`

# CLI Design

## Goal

The CLI must make it obvious whether a command:

- only listens;
- transmits traffic;
- changes host networking.

## `wirepup interfaces`

```text
$ wirepup interfaces

NAME      LINK  MAC                IPv4             IPv6
enp3s0    up    00:11:22:33:44:55 10.20.30.51/24   fe80::...
wlp2s0    up    ...
```

## `wirepup observe`

Passive event stream.

```bash
wirepup observe -i enp3s0
wirepup observe -i enp3s0 --protocol lldp
wirepup observe -i enp3s0 --protocol arp
wirepup observe -i enp3s0 --protocol ca
wirepup observe -i enp3s0 --protocol pva
```

Guarantee: no transmission.

## `wirepup discover`

Passive device-oriented view.

```bash
wirepup discover -i enp3s0
wirepup discover -i enp3s0 --json
```

Guarantee: no transmission.

## `wirepup capture`

```bash
wirepup capture -i enp3s0 -o issue.pcap
```

## `wirepup read`

```bash
wirepup read issue.pcap
wirepup read issue.pcap --protocol ca
wirepup read issue.pcap --protocol pva
```

## `wirepup diagnose`

```bash
wirepup diagnose -i enp3s0
wirepup diagnose --pcap issue.pcap
wirepup diagnose --epics
```

Passive unless an explicit active option is selected.

## `wirepup epics`

Possible subcommands:

```text
wirepup epics observe
wirepup epics diagnose
wirepup epics find <PV>
```

`find <PV>` must clearly distinguish:

- passive observation of existing searches;
- explicit active CA/PVA search initiated by WirePup.

## `wirepup probe`

Explicit active discovery.

```bash
wirepup probe -i enp3s0 --arp
```

The command must report what it will transmit.

## `wirepup connect`

Explicit temporary addressing workflow.

```text
$ sudo wirepup connect 192.168.1.100 -i enp3s0

Observed target
  192.168.1.100
  MAC 00:80:F4:12:34:56

Current local addresses
  10.20.30.51/24

Suggested temporary address
  192.168.1.254/24

Requested action
  add 192.168.1.254/24 to enp3s0
```

No primary address replacement.

## `wirepup disconnect`

Remove only temporary configuration WirePup previously created.

## Global options

Potential:

```text
-i, --interface
--json
--quiet
--verbose
--no-resolve
--timeout
```

## Exit codes

Proposed:

```text
0 success
1 general error
2 invalid arguments
3 insufficient privilege
4 capture failure
5 requested target not observed/reached
6 unsafe or conflicting requested network change
```


---

## Source: `docs/safety.md`

# Safety and Privilege Model

WirePup may be used on laboratory and controls networks where unplanned traffic or configuration changes can be disruptive.

Safety is therefore an architectural requirement.

## 1. Passive-by-default

These commands are intended to be passive:

```text
interfaces
observe
discover
capture
read
diagnose
```

Passive means:

- no ARP probing;
- no ping;
- no port scan;
- no CA/PVA search generated by WirePup;
- no mDNS/SSDP query generated by WirePup;
- no address/route changes.

## 2. Explicit active commands

Active behavior belongs in commands such as:

```text
probe
connect
```

Every active command should:

1. state what it will transmit/change;
2. require explicit invocation;
3. use a bounded target/scope;
4. avoid broad defaults;
5. log executed actions.

## 3. Temporary IP assignment

WirePup must not automatically assign a secondary IP just because it sees a different subnet.

Workflow:

```text
observe -> infer -> recommend -> explicit execute
```

Before adding an address:

- verify interface;
- verify prefix;
- avoid obvious conflicts;
- warn about route ambiguity if relevant;
- record the exact address WirePup adds.

On removal:

- remove only the exact configuration created by WirePup.

## 4. Linux capabilities

Expected categories:

```text
CAP_NET_RAW    raw packet capture / selected L2 probing
CAP_NET_ADMIN  local interface/address administration
```

Do not grant more privilege than necessary.

Potential architecture:

```text
wirepup              unprivileged core/UI
wirepup-capture      narrow raw capture helper, if needed
wirepup-netcfg       narrow network-config helper, if needed
```

Whether helpers are necessary should be decided after the M0 backend is known.

## 5. Industrial protocol policy

Initial support for controls protocols is observation-oriented.

Allowed early behavior:

- identify;
- decode;
- correlate;
- diagnose.

Not in initial scope:

- PLC writes;
- register modifications;
- device configuration writes;
- firmware operations;
- exploit/security testing.

## 6. Managed switch integration

If switch APIs/SNMP are added later, they should initially be read-only.

Potential read-only data:

- forwarding/MAC table;
- LLDP neighbor table;
- port status;
- VLAN membership.

Any configuration write requires a separate ADR and safety review.

## 7. Capture privacy

PCAP files may contain:

- hostnames;
- IP addresses;
- credentials in unencrypted protocols;
- process-variable names;
- operational topology.

Do not commit production PCAPs without review/sanitization.

## 8. Diagnostic wording

Use wording such as:

```text
Observed
Likely
Possible
Recommended
```

Avoid claiming certainty when the packet evidence is incomplete.


---

## Source: `docs/testing.md`

# Testing Strategy

## 1. Principles

Most protocol logic must be testable without root and without a live network.

Testing layers:

1. byte-level unit tests;
2. complete-frame fixtures;
3. PCAP replay tests;
4. device-correlation tests;
5. diagnosis tests;
6. controlled live integration tests.

## 2. Decoder fixtures

Create fixtures for:

- Ethernet/VLAN;
- LLDP;
- ARP request/reply/probe/announcement;
- DHCP;
- IPv6 NDP/DAD;
- CA;
- PVA.

Each fixture should document its expected interpretation.

## 3. PCAP corpus

Suggested:

```text
testdata/pcap/
  lldp-single-neighbor.pcap
  arp-autoip-selection.pcap
  dhcp-success.pcap
  dhcp-no-offer.pcap
  ipv6-dad.pcap
  ca-search-response.pcap
  ca-search-no-response.pcap
  ca-beacon.pcap
  pva-search-response.pcap
  pva-beacon.pcap
  same-l2-different-subnet.pcap
```

Sanitize sensitive captures before committing.

## 4. Device correlation tests

At minimum:

- MAC observed before IP;
- IP appears later;
- Auto-IP followed by DHCP/static IP;
- one device with multiple addresses;
- two devices with same/similar hostname;
- duplicate IPv4 claims;
- LLDP switch neighbor kept distinct from endpoint device records.

## 5. Diagnosis tests

Use explicit evidence sets.

Example:

```text
Given:
  local enp3s0 = 10.20.30.51/24
  observed ARP from MAC A
  ARP sender IPv4 = 192.168.1.100

Expect:
  observed: L2 frame from MAC A on enp3s0
  inferred: MAC A appears to use 192.168.1.100
  diagnosis: IPv4 outside configured local subnet
```

## 6. CA tests

Validate semantics, not only ports.

Cases:

- valid CA search;
- valid CA search response;
- valid CA beacon;
- malformed CA message;
- UDP/5064 packet that is not CA;
- response matching prior search ID;
- apparent duplicate server claims.

## 7. PVA tests

Cases:

- valid PVA search;
- valid search response;
- server GUID extraction;
- valid beacon;
- malformed PVA message;
- UDP/5076 packet that is not PVA;
- TCP/5075 traffic without valid PVA framing.

## 8. Live integration lab

Recommended topology:

```text
Laptop
  |
small managed switch
  |---- test Linux host / IOC
  |---- embedded controller
  |---- optional second VLAN
```

Scenarios:

- no DHCP server;
- DHCP available;
- static device on different subnet;
- Auto-IP device;
- LLDP-enabled switch;
- tagged trunk/mirror capture;
- CA IOC;
- PVA IOC.

## 9. Privileged tests

CI should run parser/correlation/diagnosis tests unprivileged.

Privileged capture/network-config tests should be optional and clearly separated.


---

## Source: `docs/roadmap.md`

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


---

## Source: `docs/ai-workflow.md`

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
