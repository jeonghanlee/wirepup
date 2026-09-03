# ADR-0002: Abstract the capture backend; implement Linux capture natively in Go

Status: Accepted

## Context

WirePup needs:

- live Linux capture;
- kernel-side filtering;
- PCAP/PCAPNG interoperability;
- future portability to other capture backends.

Candidate approaches:

- libpcap through cgo;
- Linux AF_PACKET directly through the Go standard library and `golang.org/x/sys`;
- multiple backends behind one abstraction.

Pre-implementation evaluation (2026-09-02):

| Criterion | libpcap through cgo | Native AF_PACKET in Go |
| --- | --- | --- |
| Build requirement | libpcap headers and a C toolchain | Go toolchain only |
| Runtime requirement | libpcap shared library | none |
| Deployment shape | dynamically linked executable | single static executable (NFR-002) |
| Kernel filtering | BPF compiled by libpcap | classic BPF program attached with `SO_ATTACH_FILTER` |
| VLAN tag visibility | libpcap reinserts the tag | tag recovered from `PACKET_AUXDATA` |
| PCAP/PCAPNG files | libpcap | `github.com/gopacket/gopacket/pcapgo` (pure Go) |
| License | BSD-3 | BSD-3 (`gopacket`, `x/sys`) |

The reference build host carries the libpcap runtime but not its headers, which makes the cgo path impractical for the initial vertical slice.

## Decision

Define the capture abstraction first (`internal/capture`): a `Source` yields timestamped packets with capture length, original length, interface name, and link type; live and file sources implement the same interface.

Implement the Linux live backend natively: an `AF_PACKET` `SOCK_RAW` socket bound to one interface, opened through `golang.org/x/sys/unix`, without cgo. Filtering uses classic BPF programs assembled in-process. The 802.1Q tag that the kernel strips from received frames is recovered from `PACKET_AUXDATA` and reinserted so that decoders see the frame as it appeared on the wire.

Read and write PCAP and PCAPNG files with `github.com/gopacket/gopacket/pcapgo`. No other part of `gopacket` is used; WirePup keeps its own decoders.

A libpcap-backed source remains possible behind the same interface as an optional build, but it is not part of V1.

## Rationale

- The passive guarantee is easier to audit when the socket code is small and in the repository: a receive-only loop with no call to any send function.
- A static executable matches the intended deployment (a laptop tool copied to a field machine).
- `pcapgo` gives Wireshark-compatible PCAP and PCAPNG without libpcap.
- The abstraction keeps socket details out of decoders and lets replay and live capture share one analysis pipeline.

## Consequences

- Direct dependencies are limited to `golang.org/x/sys` and `github.com/gopacket/gopacket`; both are BSD-3 and compatible with Apache-2.0.
- Passive capture requires `CAP_NET_RAW` (or root). The tool must never require `CAP_NET_ADMIN` for passive commands.
- The receive loop uses `recvmsg` per packet. This is adequate for engineering-laptop rates (NFR-006); a `TPACKET` ring can be added later behind the same interface.
- Dropped-packet counts are read from `PACKET_STATISTICS` and reported.
- Offloaded receive features on the NIC (checksum, GRO) can change what the host sees; WirePup reports what the kernel delivered and does not claim wire-level fidelity.
