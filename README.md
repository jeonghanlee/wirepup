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
