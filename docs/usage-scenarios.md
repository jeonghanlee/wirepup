# Usage Scenarios

## Scope

Choose a task, run the command, and check the result. These examples are based
on the [recorded VM tests](vm-test-results.md).

**Out of scope:** guided entry and physical cable tests. Bare `wirepup`
currently prints usage and exits 2; use a command below.

## Try a recorded example first

No VM or root access is needed. From the repository root:

```bash
make build
mkdir -p work/vm-example
tar -xzf tests/vm/evidence/2026-09-05/main.tar.gz -C work/vm-example
bin/wirepup epics find WP:VALUE --pcap work/vm-example/epics-reads.pcap
```

**Check:** the report identifies CA and PVA servers that answered for
`WP:VALUE`. The capture contains real client reads of value 42.

The live examples below assume [WirePup is installed](../README.md#building).
Replace `enp3s0`, addresses and PV names with your own. Active examples ask for
confirmation; `disconnect` removes recorded addresses immediately.

## Scenario and option map

| Task | Example | Options used |
| --- | --- | --- |
| Save and inspect peer traffic | [Capture and replay](#capture-and-replay) | `-i`, `-o`, `--protocol`, `--timeout` |
| Ask one local address to respond | [Bounded ARP search](#bounded-arp-search) | `-i`, `--arp` |
| Reach another subnet on the same link | [Temporary connection](#temporary-connection) | Target, `-i`, `--address` |
| Explain DHCP failure or Auto-IP | [DHCP and auto-ip](#dhcp-and-auto-ip) | `--pcap`, `--local` |
| Identify the IOC answering a PV | [Passive EPICS analysis](#passive-epics-analysis) | PV, `--pcap` |
| Send a CA or PVA search | [Active EPICS search](#active-epics-search) | `--active`, `--to`, `--search` |
| Check duplicates or missing replies | [Duplicate and missing PVs](#duplicate-and-missing-pvs) | `--epics`, `--search` |
| Stop or remove temporary configuration | [Interruption and cleanup](#interruption-and-cleanup) | Ctrl-C, `disconnect`, `-i` |

These are the options used in the examples, not a list of mandatory flags.
Add `--json` for scripts. Use `--yes` only to skip confirmation in authorized
automation. Defaults and applicability are in the [option reference](cli-reference.md).

## Capture and replay

Find the interface, then capture a short passive window:

```bash
wirepup interfaces
sudo wirepup capture -i enp3s0 --protocol arp --timeout 10s -o arp.pcap
wirepup read arp.pcap --protocol arp
wirepup read arp.pcap --devices
```

**Check:** ARP events identify observed peers; `--devices` shows the inventory.
The VM test identified peer `192.0.2.2` from real kernel ARP traffic.

**If empty:** check the interface, filter, drop statistics and whether the peer
sent traffic during the window. An empty file does not prove an empty network.
Choose a new filename: capture overwrites an existing output file.

Options: [interface](cli-reference.md#-i---interface),
[protocol](cli-reference.md#--protocol), [output](cli-reference.md#-o---output),
[timeout](cli-reference.md#--timeout), [device view](cli-reference.md#--devices).

## Bounded ARP search

When active testing is authorized, start with one address:

```bash
sudo wirepup probe -i enp3s0 --arp 192.0.2.2/32
```

**Check:** after confirmation, WirePup sends ARP; an answering peer produces
`arp-reply`. No reply does not prove the address is unused.
The prefix controls the search extent; `--timeout` does not change its fixed budget.

Option: [ARP prefix](cli-reference.md#--arp).

## Temporary connection

For an observed device on the same link but another IPv4 subnet:

```bash
sudo wirepup connect 10.44.0.2 -i enp3s0 --timeout 5s
```

**Check:** WirePup observes, proposes an address, and prints the conflict-check
and address-add plan. Review it before confirming. The VM selected
`10.44.0.254`; other observations may produce a different candidate.
The inferred prefix size is an assumption, not authoritative configuration.

If you already know the correct local address, use it directly:

```bash
sudo wirepup connect -i enp3s0 --address 192.0.2.10/24
sudo wirepup disconnect 192.0.2.10 -i enp3s0
```

**Check:** an occupied address is refused with exit 6. Disconnect removes the
matching WirePup entry without a prompt and preserves independently configured
addresses. If the first command recommended a different address, remove that
actual address instead.

Options: [address](cli-reference.md#--address),
[confirmation](cli-reference.md#--yes), [interface](cli-reference.md#-i---interface).

## DHCP and auto-ip

Capture at the DHCP client or a mirror port, starting before lease acquisition:

```bash
sudo wirepup capture -i enp3s0 --timeout 40s -o dhcp.pcap
wirepup read dhcp.pcap --protocol dhcp
wirepup diagnose --pcap dhcp.pcap --local 192.0.2.1/24
```

**Check:** a successful exchange contains an ACK. The VM client acquired
`192.0.2.107/24`; without an offer it assigned `169.254.10.136/16`, and
WirePup reported `dhcp-discover-no-offer`.

**If replies are missing:** a normal third switch port may miss unicast OFFER
or ACK packets. Check the capture point and DHCP server reachability.
Set `--local` to the capture host's actual address/prefix; it changes no address.

Offline diagnosis uses the last packet timestamp. The capture must include
traffic at least two seconds after the last DISCOVER; waiting without receiving
another packet does not extend that recorded window.

Options: [capture input](cli-reference.md#--pcap),
[local context](cli-reference.md#--local).

## Passive EPICS analysis

Capture while your normal EPICS client searches for the PV in another terminal:

```bash
sudo wirepup capture -i enp3s0 --timeout 15s -o epics.pcap
wirepup epics find WP:VALUE --pcap epics.pcap
```

**Check:** the report identifies servers answering the search. In the VM,
`caget` and `pvget` read 42 and WirePup identified both protocols' answers.
WirePup observes these exchanges; it does not perform the PV value read.

**If nothing is found:** an idle client may produce no search traffic.
In passive mode, exit 0 means a search for this PV was observed, even without
a reply. Exit 5 means no matching search was observed, not that the PV is absent.
Check the report for server answers; exit 0 alone does not confirm one.

Options: [capture input](cli-reference.md#--pcap),
[JSON for scripts](cli-reference.md#--json).

## Active EPICS search

When sending a search is authorized, choose a server or directed broadcast:

```bash
wirepup epics find WP:VALUE --active --to 192.0.2.255 --search ca --timeout 2s
wirepup epics find WP:VALUE --active --to 192.0.2.255 --search pva --timeout 2s
```

**Check:** after confirmation, one datagram is sent per selected protocol and
destination. A server answer identifies the IOC; no PV value is read or written.

Without `--search`, both protocols are selected. Use `--search`, not
`--protocol`, to select what find transmits. The reply timeout applies to each
protocol in turn.

With `--to` and no `-i`, the UDP search needs no raw capture or root access.
The OS selects its route. Use the correct broadcast for your prefix: `.255`
is not always broadcast. Adding `-i` enables prior passive capture and local
prefix lookup; it does not bind the UDP socket to that interface.

Options: [active mode](cli-reference.md#--active),
[destinations](cli-reference.md#--to), [search protocol](cli-reference.md#--search).

## Duplicate and missing PVs

The same search detects duplicates: two real VM IOCs serving `WP:VALUE`
produced `ca-multiple-servers` and `pva-multiple-servers`.
Check the reported servers before changing an IOC database.

For a missing reply, capture while the normal client searches for that PV:

```bash
sudo wirepup capture -i enp3s0 --timeout 15s -o missing-pv.pcap
wirepup diagnose --epics --pcap missing-pv.pcap
```

**Check:** `ca-search-no-response` records an unanswered CA search.
If active investigation is authorized:

```bash
wirepup epics find WP:ABSENT --active --to 192.0.2.255 --search ca,pva --timeout 2s
```

Exit 5 means no server answer was obtained. Check the destination, subnet
reachability, IOC state and client address lists; it does not prove the PV
cannot exist elsewhere.

Options: [EPICS diagnosis](cli-reference.md#--epics),
[exit status](cli-reference.md#exit-status-and-scripts).

## Interruption and cleanup

Ctrl-C stops capture. The VM test reopened an empty PCAP after interruption;
it did not test every buffered-write timing. Interrupting connect during its
ARP probes added no address in the tested window.

Remove an address that was already added with:

```bash
sudo wirepup disconnect 192.0.2.10 -i enp3s0
```

A real VM reboot removed the test namespaces and `/run/wirepup/session.json`;
disconnect then succeeded with nothing to remove. On an operational host,
use selective disconnect for routine cleanup.
