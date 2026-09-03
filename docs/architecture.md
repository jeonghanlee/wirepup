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
    LinkType       LinkType   // DLT value; DLT_EN10MB for Ethernet
    Data           []byte
    CaptureLength  int
    OriginalLength int
}

type Source interface {
    Packets(ctx context.Context) (<-chan Packet, <-chan error)
    Close() error
}
```

ADR-0002 fixes these fields and the Linux backend; method names may still change during implementation.

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

ADR-0008 fixes this structure and adds `Confidence`. `PacketID` is the 1-based frame number within one capture source and equals the Wireshark frame number of the same file.

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

V1 ships one executable without a helper; `connect` and `disconnect` run under `sudo`, and passive packages must not import the active or network-configuration packages (ADR-0010).

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

The definitions are in ADR-0008.

## 14. Output architecture

Human CLI and JSON should be separate renderers over common result models.

Potential future renderers:

- compact table;
- event stream;
- JSON;
- TUI;
- report export.

Protocol decoders must never directly format terminal output.

The JSON renderer is a versioned public contract (ADR-0009).

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

Decided in ADR-0002:

- `internal/capture` defines the abstraction (section 3);
- the Linux live source is a native `AF_PACKET` socket opened through `golang.org/x/sys/unix`, with classic BPF filtering and the 802.1Q tag recovered from `PACKET_AUXDATA`;
- PCAP and PCAPNG files are read and written with `gopacket/pcapgo`;
- no cgo and no libpcap in V1; a libpcap-backed source remains possible behind the same interface.

## 17. Package layout (V1)

```text
cmd/wirepup/                 entry point: flag parsing, subcommand dispatch, exit codes

internal/capture/            Packet, Source interface, link types
internal/capture/afpacket/   Linux AF_PACKET live source: receive only, BPF attach, PACKET_AUXDATA
internal/capture/pcapfile/   PCAP/PCAPNG read and write over gopacket/pcapgo

internal/observation/        Evidence, Confidence, Kind (ADR-0008)
internal/decode/             frame pipeline: runs parsers in link-layer order, emits observations

internal/protocol/ethernet/  Ethernet II and 802.1Q
internal/protocol/arp/
internal/protocol/lldp/
internal/protocol/ipv4/
internal/protocol/ipv6/
internal/protocol/icmpv6/    NDP and DAD
internal/protocol/udp/
internal/protocol/tcp/
internal/protocol/dhcpv4/
internal/protocol/dns/       DNS and mDNS (after V1; no milestone of the V1 roadmap needs it)
internal/epics/ca/           Channel Access parser and observations
internal/epics/pva/          PVAccess parser and observations

internal/device/             correlator, Device, timeline (ADR-0004)
internal/oui/                vendor hints from the external registry file (ADR-0011)
internal/interfaces/         read-only local interfaces, addresses, routes
internal/diagnose/           rules; Observed/Inferred/Recommended/Executed result model

internal/output/             result structs shared by every renderer
internal/output/text/        human-readable renderer
internal/output/json/        JSON renderer (ADR-0009)
internal/tui/                terminal view (M10)

internal/active/             packet transmission: ARP probe, ICMP, explicit CA/PVA search
internal/networkcfg/         temporary address session over iproute2 (ADR-0010)

testdata/fixtures/           byte fixtures, one directory per protocol
testdata/pcap/               replay captures
```

Rules that the layout enforces:

- one package per protocol; each exposes a pure parser and its observation types, and has no import of `device`, `diagnose`, `output`, `active`, or `networkcfg`;
- `capture/afpacket` contains no send path; `active` opens its own socket for transmission;
- `active` and `networkcfg` are imported only by the `probe`, `connect`, and `disconnect` command paths in `cmd/wirepup`; a test walks the import graph of the passive command paths and fails if either package appears;
- `output/text`, `output/json`, and `tui` render the same structs from `output`; nothing else formats user-facing text.
