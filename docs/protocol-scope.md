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
