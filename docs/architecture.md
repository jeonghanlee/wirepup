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
