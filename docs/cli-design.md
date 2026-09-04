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
wirepup diagnose 192.168.1.100 -i enp3s0
wirepup diagnose --pcap issue.pcap --local 10.20.30.51/24
wirepup diagnose --epics -i enp3s0
wirepup diagnose --pcap a.pcap,b.pcap --epics
```

Passive. A live run observes for `--timeout` (default 10 s) and then applies the rules; a capture file needs `--local` for the capture host's prefixes. Several interfaces or files, comma-separated, feed one report so that discovery activity can be compared between sources. With a target address the exit code is 5 when the target was not observed. With `--epics` and no target address, a window with no CA or PVA activity observed is reported under Inferred and the exit code stays 0.

## `wirepup epics`

```bash
wirepup epics observe -i enp3s0
wirepup epics observe --pcap issue.pcap --protocol ca
wirepup epics diagnose -i enp3s0
wirepup epics find MPS:SYS:STATE -i enp3s0
wirepup epics find MPS:SYS:STATE --pcap issue.pcap
wirepup epics find MPS:SYS:STATE --active -i enp3s0
wirepup epics find MPS:SYS:STATE --active --to 10.20.4.255,10.30.0.31:5064 --search ca
```

`observe` prints CA and PVA messages as labelled blocks; `diagnose` is `wirepup diagnose --epics`. `find` is passive by default: it reports the searches and answers seen for the PV. With `--active` it sends one CA and one PVA search datagram per printed destination (the interface's directed broadcasts unless `--to` names hosts), asks for confirmation unless `--yes`, and reports what was sent under `Executed`. Exit code 5 means nothing was observed or answered.

## `wirepup probe`

Explicit active discovery.

```bash
wirepup probe -i enp3s0 --arp 192.168.1.0/24
wirepup probe -i enp3s0 --arp 192.168.1.0/24 --yes
```

The prefix is required and may not be larger than a /24. The command prints what it will transmit (one ARP request per host at 20 per second), asks for confirmation unless `--yes`, and lists the replies under `Observed` and the transmission under `Executed`.

## `wirepup connect`

Explicit temporary addressing workflow.

```bash
sudo wirepup connect 192.168.1.100 -i enp3s0
sudo wirepup connect -i enp3s0 --address 192.168.1.254/24 --yes
```

With a target, the command observes passively for `--timeout` (default 5 s), prints the diagnosis and the exact `ip address add` command it intends to run, asks for confirmation unless `--yes`, sends three RFC 5227 ARP probes for the candidate, refuses with exit code 6 when anything answers, applies the address through iproute2, and records it in `/run/wirepup/session.json` (ADR-0010). `--address` names the address explicitly; the network and broadcast addresses and addresses already configured locally are refused. No primary address is replaced.

## `wirepup disconnect`

```bash
sudo wirepup disconnect
sudo wirepup disconnect -i enp3s0 192.168.1.254
```

Removes only the addresses recorded in the session file, drops the record of an address that is already gone, and never touches anything else.

## `wirepup tui`

```bash
sudo wirepup tui -i enp3s0
wirepup tui --pcap issue.pcap
```

Passive. Five views (Devices, Events, EPICS, Interfaces, Diagnostics) over the same pipeline and rules as the text commands; `q` leaves, `Tab` or `1`-`5` switch views, `j`/`k` scroll by one line, the space bar by ten, `r` returns to the top.

## Global options

```text
-i, --interface   interface to capture on (comma-separated list for diagnose)
--pcap            capture file instead of an interface (comma-separated list for diagnose)
--local           local prefixes of the capture host, for --pcap (diagnose, epics diagnose, tui)
--protocol        comma-separated filter: frame, arp, lldp, ipv4, dhcp, ipv6, ndp, tcp, ca, pva (observe, discover, capture, read, diagnose, tui, epics observe, epics diagnose)
--json            machine-readable output (ADR-0009)
--quiet           no progress messages
--verbose         include frame, ipv4, ipv6, and tcp observations (observe, read, tui)
--timeout         stop after this duration
--no-promisc      leave promiscuous mode off
--oui-file        IEEE oui.txt for vendor hints (ADR-0011; discover, read --devices, diagnose, epics diagnose, tui)
--yes             skip the confirmation of an active command
```

`ca` and `pva` admit their UDP search and beacon ports and every IPv4 TCP
segment at the kernel. A server advertises its TCP port in its search
responses and beacons, and the decoder (`internal/decode`) learns it from
them, so the kernel cannot know that port in advance. The decoder labels a
segment CA only on a default or learned port, and PVA on such a port or on
recognisable PVA framing (then `strong_hint`, ADR-0008); other segments
still yield `ipv4` and `tcp` observations. `observe`, `epics observe`, and
`read` show only the observations of the requested protocols; `discover`,
`read --devices`, `diagnose`, `epics diagnose`, and `tui` ingest a packet
into the device table only when one of its observations belongs to them;
`capture` writes every admitted
frame, so a `--protocol ca` capture file holds every IPv4 TCP segment.
`epics find` checks the `--protocol` value but always observes CA and PVA
together. IPv6 CA and PVA are outside these rules.

## Exit codes

```text
0 success
1 general error
2 invalid arguments
3 insufficient privilege
4 capture failure (live capture error, or a capture file that ends inside a packet)
5 requested target not observed/reached
6 unsafe or conflicting requested network change
```
