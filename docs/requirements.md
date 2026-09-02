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
