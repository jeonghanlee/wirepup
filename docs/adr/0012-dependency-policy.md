# ADR-0012: Standard library first; every third-party module is listed here

Status: Accepted

## Context

ADR-0001 chose Go and asked that cgo be isolated; ADR-0002 removed cgo from V1. The remaining question is how much of the Go ecosystem WirePup pulls in for the CLI, the TUI, netlink, and file formats. A framework adopted early (a CLI framework, a TUI framework, a netlink library) shapes the package structure and is expensive to remove later. Fewer dependencies also keep the license inventory required by ADR-0000 short and the passive-safety audit small.

## Decision

The Go standard library is the default. A third-party module is added only when the standard library cannot do the job, and each one is listed in this ADR with its purpose and license. Adding a module amends this ADR before the import appears.

V1 modules:

| Module | Purpose | License |
| --- | --- | --- |
| `golang.org/x/sys` | `AF_PACKET` socket, `SO_ATTACH_FILTER`, `PACKET_AUXDATA`, rtnetlink reads | BSD-3 |
| `golang.org/x/term` | raw terminal mode and size for the TUI | BSD-3 |
| `github.com/gopacket/gopacket` (`pcapgo` only) | PCAP and PCAPNG read and write | BSD-3 |

Specific choices:

- CLI: `flag` from the standard library with a small subcommand dispatcher in `cmd/wirepup`. No CLI framework.
- TUI (M10): the standard library plus `x/term`, rendering with ANSI escape sequences and a full redraw per refresh. No TUI framework. The TUI is a renderer over the same output structs as text and JSON (ADR-0009).
- Netlink: reads through `net.Interfaces`, `net.Interface.Addrs`, and `unix.NetlinkRIB`; writes through iproute2 (ADR-0010). No netlink library.
- Logging: `log/slog`.
- Builds use `CGO_ENABLED=0`; `go.sum` is committed; vendoring is not used.

## Consequences

- The dependency license inventory required by ADR-0000 is the table above.
- A future need (for example a richer TUI) is met by amending this ADR with the module, the reason the standard library was insufficient, and the license.
- Supply-chain exposure is limited to the Go project modules and `gopacket`.
