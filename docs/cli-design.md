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
