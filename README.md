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
**Initial implementation language:** Go (1.25 or newer)  
**Development model:** local-first, documentation-first, multi-agent assisted

## Building

WirePup builds with the Go toolchain only; no cgo and no C libraries.

- **Go 1.25 or newer** is required. The `golang.org/x` modules track the two
  most recent Go releases, so a security update to a dependency raises this
  floor; `go.mod` records the current minimum.
- On Debian 13 (trixie) the base archive ships Go 1.24. Enable
  `trixie-backports` first (it is off by default), then `apt install -t
  trixie-backports golang-go` (currently Go 1.26); or install from the
  official `go.dev` tarball, which needs no backports.
- `make` or `make help` shows the workflows; `make build` produces the static binary in
  `bin/`, and `make check` runs gofmt, vet, and the tests.

The entry-point `Makefile` loads configuration and rules from `configure/`.
`RELEASE` defines project identity and the embedded version; `CONFIG_SITE`
selects tools, the output path, and test scope; `CONFIG_VARS` derives build
settings. `RULES_BUILD`, `RULES_INSTALL`, `RULES_CHECK`, `RULES_HELP`, and `RULES_VARS` provide
the targets, using common definitions from `RULES_FUNC`.

Use `make -C <repository> help` for common workflows and `help.detail` for the
full target reference. `vars` prints effective settings (`FILTER=GO` selects
a prefix); `PRINT.GO` also reports a variable's origin. `VERBOSE=1` displays
recipe commands, and `DEBUG_SHELL=1` enables shell tracing.

Local settings belong in `configure/CONFIG_SITE.local` or
`configure/RELEASE.local`, both ignored by Git. Matching files in the parent
directory load first; command-line assignments take precedence. Supported
settings include `GO`, `GOFMT`, `BIN`, `PKG`, `TEST_FLAGS`, and `VERSION`.
The selected Go toolchain supplies gofmt and enforces the minimum in `go.mod`.
`test` and `race` accept `TEST_FLAGS=-count=1` to bypass the Go test cache.
Builds use `CGO_ENABLED=0`; only `race` enables cgo and requires a C compiler.
`clean` removes only the file selected by `BIN`, leaving its directory intact.

Local installation defaults to `$HOME/.local/bin/wirepup`, without sudo.
Use `install.dry-run` to preview, `install` (an alias of `install.apply`) to
build and install, and `install.check` to verify the executable, version,
and active PATH. Set `INSTALL_LOCATION` to change the installation prefix;
pass the same value to all three operations. `INSTALL` selects the GNU
coreutils install command. Installation refuses a symlink or directory at
the executable destination.

If `$HOME/.local/bin` is absent from PATH or another wirepup takes precedence,
`install.check` fails and prints the PATH activation command.

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
wirepup tui           # interactive terminal view

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
│   ├── cross-review.md
│   └── full-repository-review.md
├── Makefile
├── configure/               # build configuration and target rules
├── go.mod
├── cmd/wirepup/          # CLI entry point
├── internal/             # capture, decode, protocol parsers, device, diagnose, output, active, networkcfg, tui
└── testdata/
    ├── fixtures/
    ├── gen/
    ├── golden/
    └── pcap/
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
