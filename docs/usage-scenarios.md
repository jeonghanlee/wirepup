# Usage Scenarios

## Scope

Start from a task, choose direct commands or the terminal guide, and check what
the observations establish. The examples use the implemented CLI and
[recorded VM traffic](vm-test-results.md).

**Out of scope:** changing device/IOC configuration, physical cable tests,
and proving that an unobserved device or PV does not exist.

## Start here

Use the [installed command](../README.md#building), or run these commands from
the repository root to try the shipped captures without root or a VM:

```bash
make build
export PATH="$PWD/bin:$PATH"
wirepup epics find WP:VALUE --pcap tests/vm/pcap/epics-reads.pcap --quiet
```

**Check:** CA and PVA servers at `192.0.2.2` answered for `WP:VALUE`.
The capture contains real client reads of value 42; WirePup reports the
discovery exchanges, not the PV value.

For the same task without choosing flags, run `wirepup` in a terminal.
Choose **Diagnose EPICS connectivity**, **Capture file**, enter
`tests/vm/pcap/epics-reads.pcap`, then enter `WP:VALUE`.
The guide prints the equivalent direct command and its result.
Choose **Finish** when done.

Menu numbers depend on the available actions: follow the labels below.
Use `b`/`q` in menus and `/back`/`/quit` at text prompts.
Enter file paths and PV names literally, without shell quotes; use `//`
for a literal leading slash when it would otherwise be a control.
Answers are limited to 253 bytes. Bare invocation with redirected stdin or
stdout exits 2 instead of starting guidance.

Live examples use `enp3s0` as a placeholder. Select your actual interface
with `wirepup interfaces`; substitute your own addresses and PV names.
Live capture needs Linux raw-packet privileges. Start the live guide with
`sudo wirepup` when approved; the guide itself never invokes sudo.
Active operations still require their own confirmation.

## Choose a task

| Task | Direct entry | Guided entry |
| --- | --- | --- |
| [Find an unknown device](#find-an-unknown-device) | `discover` | Find devices |
| [Capture and replay](#capture-and-replay) | `capture`, then `read` | Analyze a capture file after saving it |
| [Bounded ARP search](#bounded-arp-search) | `probe` | Find devices, then Send bounded ARP requests |
| [Temporary connection](#temporary-connection) | `diagnose`, then `connect` | Diagnose an observed address, then a recommended connection |
| [DHCP and Auto-IP](#dhcp-and-auto-ip) | `read`, `diagnose` | Analyze a capture file, General diagnosis |
| [Passive EPICS analysis](#passive-epics-analysis) | `epics find` | Diagnose EPICS connectivity |
| [Active EPICS search](#active-epics-search) | `epics find --active` | An unanswered live PV report can offer an explicit search |
| [Duplicate and missing PVs](#duplicate-and-missing-pvs) | `diagnose --epics` | Analyze a capture file, EPICS diagnosis |
| [Use the TUI](#use-the-tui) | `tui` | Use the corresponding device/event/diagnosis reports |
| [Interruption and cleanup](#interruption-and-cleanup) | Ctrl-C, selective `disconnect` | Finish or cancel; inspect any cleanup refusal |
| [Scripts and help](#scripts-and-help) | Explicit commands and JSON | Copy the displayed command for later direct use |
| [Complete commands in Bash](#complete-commands-in-bash) | Tab completion | Menus already list available choices |

Options are refinements, not a required checklist. Each task links to its
relevant [option definitions](cli-reference.md); each definition links back
to a task using it.

## Find an unknown device

Observe a finite passive window:

```bash
wirepup interfaces
sudo wirepup discover -i enp3s0 --timeout 10s
```

**Guided:** Find devices -> Live interface -> your interface -> accept
the 10-second duration or enter another positive duration.
An inventory offers **Diagnose an observed IPv4 address**. If it is empty,
repeat the window or change source; a silent device may still be connected.

For an offline example that includes an LLDP neighbor and a vendor hint:

```bash
wirepup read testdata/pcap/lldp-single-neighbor.pcapng --devices --oui-file testdata/fixtures/oui/oui.txt
```

**Check:** the fixture names switch `sw-lab-1`, port `Gi1/0/12`, and
vendor hint `Example Networks Inc.`. In the guide, choose Find devices ->
Capture file with that path; the guide uses normal OUI defaults, so the
explicit fixture vendor hint belongs to the direct example only.
A vendor hint does not establish the device's identity.

Options: [interface](cli-reference.md#-i---interface),
[duration](cli-reference.md#--timeout),
[device view](cli-reference.md#--devices),
[OUI file and default search paths](cli-reference.md#--oui-file).

## Capture and replay

Save a short window, then select a view:

```bash
sudo wirepup capture -i enp3s0 --protocol arp --timeout 10s -o arp.pcap
wirepup read arp.pcap --protocol arp
wirepup read arp.pcap --devices
```

Choose a new filename: capture overwrites an existing file.
For PCAPNG output with a limited saved length and no promiscuous request:

```bash
sudo wirepup capture -i enp3s0 -o short.pcapng --snaplen 128 --no-promisc --timeout 3s
```

The default saved length is 262144 bytes. A smaller `--snaplen` can remove
payload needed by diagnosis. `--no-promisc` does not alter switch forwarding.
CA/PVA capture filters admit all IPv4 TCP to allow learned server ports, so
`--protocol ca` is not an EPICS-only capture file.

**Guided:** saving a new capture is a direct operation. Afterwards choose
Analyze a capture file -> the saved path -> Events or Devices.
Use **Choose another capture view** to switch views without entering the path
again. File analysis stays offline.

Try additional event detail on a shipped capture:

```bash
wirepup read tests/vm/pcap/epics-reads.pcap --verbose --quiet
```

**Check:** verbose mode includes the normally hidden frame/IP/TCP observations.
An explicit `--protocol` takes precedence over verbose.
If the capture is empty, check the interface, filter, drops and whether traffic
crossed that capture point; an empty file does not prove an empty network.

Options: [interface](cli-reference.md#-i---interface),
[protocol](cli-reference.md#--protocol), [output](cli-reference.md#-o---output),
[saved length](cli-reference.md#--snaplen),
[promiscuous mode](cli-reference.md#--no-promisc),
[duration](cli-reference.md#--timeout), [devices](cli-reference.md#--devices),
[verbose events](cli-reference.md#--verbose), [progress](cli-reference.md#--quiet).

## Bounded ARP search

When transmission is authorized, start with one address:

```bash
sudo wirepup probe -i enp3s0 --arp 192.0.2.2/32
```

**Guided:** Find devices -> Live interface -> observe, then
**Send bounded ARP requests (active)**. Enter `192.0.2.2` or its `/32`
prefix. Check the printed interface and extent before answering `y`.

**Check:** an answering peer produces `arp-reply`; no reply does not prove
that an address is unused. The supported extent is /24 through /32, with
one request per usable host at 20 per second. This fixed budget is independent
of `--timeout`. Each repeat requires another confirmation.

Options: [ARP extent](cli-reference.md#--arp),
[interface](cli-reference.md#-i---interface),
[automation consent](cli-reference.md#--yes).

## Temporary connection

First determine whether the peer was observed on the same link:

```bash
sudo wirepup diagnose 10.44.0.2 -i enp3s0 --timeout 5s
sudo wirepup connect 10.44.0.2 -i enp3s0 --timeout 5s
```

**Check:** connect observes again, prints the proposed local address and ARP
conflict-check plan, and asks for confirmation. The VM selected
`10.44.0.254/24`; your result can differ. The inferred /24 is an assumption
to verify, not authoritative configuration. A conflict is refused with exit 6.

**Guided:** Find devices -> Live interface -> Diagnose an observed IPv4 address.
When the diagnosis recommends a temporary address, choose
**Connect temporarily to a recommended target (active)** and review its plan.
Keep the guide open while using the address. **Finish** attempts to remove
only that guide's own entry; follow [cleanup](#interruption-and-cleanup)
if it refuses.

If the correct local address is already known, the direct form is:

```bash
sudo wirepup connect -i enp3s0 --address 192.0.2.10/24
sudo wirepup disconnect 192.0.2.10 -i enp3s0
```

An address-only connect skips observation but still confirms and probes for
conflicts. Direct connect leaves its address until explicit cleanup.
Disconnect has no confirmation prompt; inspect shared-subnet dependencies
before removing a primary address.

Reproduce the subnet diagnosis without changing any address:

```bash
wirepup diagnose --pcap testdata/pcap/same-l2-different-subnet.pcap --local 10.20.30.51/24 --quiet
```

**Check:** `192.168.1.100` is outside `10.20.30.51/24` despite its MAC
being observed. In the guide, choose Analyze a capture file -> that path ->
General diagnosis and enter `10.20.30.51/24` as the original host prefix.
Leaving it blank means unknown, not this computer's current addresses.
File analysis offers no active connection.

Options: [explicit address](cli-reference.md#--address),
[original prefixes](cli-reference.md#--local), [file input](cli-reference.md#--pcap),
[duration](cli-reference.md#--timeout), [confirmation](cli-reference.md#--yes),
[interface](cli-reference.md#-i---interface).

## DHCP and Auto-IP

Capture at the client or a mirror port before lease acquisition:

```bash
sudo wirepup capture -i enp3s0 --timeout 40s -o dhcp.pcap
wirepup read dhcp.pcap --protocol dhcp
wirepup diagnose --pcap dhcp.pcap --local 192.0.2.1/24
```

Or use the retained real captures:

```bash
wirepup read tests/vm/pcap/dhcp-success.pcap --protocol dhcp --quiet
wirepup diagnose --pcap tests/vm/pcap/dhcp-no-offer.pcap --local 192.0.2.1/24 --quiet
```

**Guided:** Analyze a capture file -> the DHCP capture -> General diagnosis;
enter the original capture host's address/prefix, or leave it unknown.

**Check:** success contains an ACK; the no-offer capture reports a DISCOVER
with no offer and link-local evidence (`dhcp-discover-no-offer` with `--json`). The recorded VM client
acquired `192.0.2.107/24` with DHCP and `169.254.10.136/16` without an offer.
A third switch port can miss unicast OFFER/ACK traffic.
Offline diagnosis uses the last packet timestamp: include traffic at least
two seconds after the last DISCOVER, not just an idle wait.

Options: [protocol selection](cli-reference.md#--protocol),
[file input](cli-reference.md#--pcap), [original context](cli-reference.md#--local),
[duration](cli-reference.md#--timeout), [output](cli-reference.md#-o---output).

## Passive EPICS analysis

Capture while a normal client searches, then inspect its discovery traffic:

```bash
sudo wirepup capture -i enp3s0 --timeout 15s -o epics.pcap
wirepup epics find WP:VALUE --pcap epics.pcap
```

**Guided:** Diagnose EPICS connectivity -> Live interface or Capture file ->
enter the PV name. Leave it blank for all EPICS activity. Live windows default
to 5 seconds for a named PV and 10 seconds for all activity.

**Check:** look for an observed server answer. Passive find can exit 0 after
seeing a search with no reply; exit 5 means no matching search was observed.
An idle client may send no searches. WirePup does not read or write the PV value.

For an event stream rather than a PV-specific report:

```bash
wirepup epics observe --pcap tests/vm/pcap/epics-reads.pcap --protocol ca,pva --quiet
```

Options: [file input](cli-reference.md#--pcap), [events](cli-reference.md#--protocol),
[duration](cli-reference.md#--timeout), [structured output](cli-reference.md#--json).

## Active EPICS search

When transmission is authorized, choose a server or the correct broadcast:

```bash
wirepup epics find WP:VALUE --active --to 192.0.2.255 --search ca --timeout 2s
wirepup epics find WP:VALUE --active --to 192.0.2.255 --search pva --timeout 2s
```

**Check:** after confirmation, one datagram is sent per selected protocol per
destination. Without `--search`, both protocols are selected. Reply waits
apply to each protocol in turn; no PV value is read or written.

**Guided:** choose a live EPICS source and a PV with no observed answer.
The result can offer **Send an explicit PV search (active)**. Select CA/PVA,
enter numeric destinations or accept the interface broadcasts, then review
the printed plan. The guide observes again before confirming transmission.
This action is not offered from file analysis; change to a live source first.

With `--to` and no `-i`, direct UDP search needs no raw capture or root.
The OS selects its route. Adding `-i` supplies passive capture and prefix
context but does not bind the UDP socket. A .255 suffix is not always broadcast.
For a nondefault port use `--to 192.0.2.2:5066 --search ca`; an explicit
port applies to every selected protocol. Use `--search`, not `--protocol`,
to choose transmissions.

Options: [active mode](cli-reference.md#--active),
[destinations](cli-reference.md#--to), [search protocols](cli-reference.md#--search),
[reply/window duration](cli-reference.md#--timeout),
[automation consent](cli-reference.md#--yes).

## Duplicate and missing PVs

Compare actual duplicate-server and unanswered-search captures:

```bash
wirepup diagnose --epics --pcap tests/vm/pcap/duplicate-ca.pcap --quiet
wirepup diagnose --epics --pcap tests/vm/pcap/duplicate-pva.pcap --quiet
wirepup diagnose --epics --pcap tests/vm/pcap/missing-pv.pcap --quiet
```

**Guided:** Analyze a capture file -> the chosen path -> EPICS diagnosis.
For a specific name, choose **Choose another capture view** -> **Find a PV**,
then enter the PV name. To request an active search, choose
**Change source or purpose** and select a live EPICS source.

**Check:** duplicates report multiple CA or PVA servers; the missing-PV capture
reports searches with no observed response. With `--json`, the duplicate codes
are `ca-multiple-servers` and `pva-multiple-servers`. The missing-PV example has
`ca-search-no-response` under Observed for the individual search and
`ca-searches-no-response` under Inferred for the aggregate.
Inspect the reported servers before changing IOC configuration.
For a confirmed active investigation of a missing PV:

```bash
wirepup epics find WP:ABSENT --active --to 192.0.2.255 --search ca,pva --timeout 2s
```

Exit 5 means no server answer was obtained, not that the PV cannot exist.
Check destinations, subnet reachability, IOC state and client address lists.
An EPICS-only diagnosis with no target can exit 0 with an absence finding.

Options: [EPICS rules](cli-reference.md#--epics),
[active selection](cli-reference.md#--active), [destinations](cli-reference.md#--to),
[search protocols](cli-reference.md#--search),
[exit status](cli-reference.md#exit-status-and-scripts).

## Use the TUI

Start an interactive passive display:

```bash
sudo wirepup tui -i enp3s0
wirepup tui --pcap tests/vm/pcap/epics-reads.pcap
```

Press `Tab` or `1`-`5` for Devices, Events, EPICS, Interfaces and
Diagnostics; `j`/`k` scroll, Space advances ten lines, `r` returns to
the top and `q` quits. File replay reaches EOF but the display stays open.
Use `--timeout 5s` for a timed display.

For offline subnet findings:

```bash
wirepup tui --pcap testdata/pcap/same-l2-different-subnet.pcap --local 10.20.30.51/24
```

**Check:** the EPICS view lists observed servers; Diagnostics interprets the
available source and local context. TUI is a direct command, not a guide menu
entry. The guide's Events, Devices and diagnosis reports are the corresponding
non-TUI path. Neither view sends an active search.

Options: [file input](cli-reference.md#--pcap), [interface](cli-reference.md#-i---interface),
[original context](cli-reference.md#--local), [duration](cli-reference.md#--timeout),
[filter](cli-reference.md#--protocol), [event detail](cli-reference.md#--verbose).

## Interruption and cleanup

Ctrl-C stops capture; inspect the saved file before relying on it.
In the guide, **Finish**, `q`, EOF or a signal also attempts cleanup of
entries that this guide actually added. Cleanup is bounded to five seconds.
An incomplete confirmation does not start the proposed action.

A cleanup refusal preserves the recovery record. Inspect the named address,
other addresses on the interface, and `/run/wirepup/session.json` first.
Deleting a primary IPv4 address can remove manual secondary addresses in the
same subnet. Direct `disconnect` does not perform the guide's complete
ownership/shared-subnet checks; resolve the reported condition before using it.

For a known independent WirePup entry, remove exactly that address:

```bash
sudo wirepup disconnect 192.0.2.10 -i enp3s0
```

It acts immediately, without `--yes` or a prompt. Omitting filters removes
all matching recorded entries. Direct connect does not arrange automatic
cleanup when its process exits; remove its actual selected address explicitly.

The earlier VM reboot test verified removal of its temporary namespaces and
/run state. It does not replace routine selective cleanup on a running host.

Options: [interface filter](cli-reference.md#-i---interface),
[address assignment](cli-reference.md#--address),
[confirmation semantics](cli-reference.md#--yes),
[exit status](cli-reference.md#exit-status-and-scripts).

## Scripts and help

Inspect the available syntax before automating:

```bash
wirepup help
wirepup epics find --help
wirepup version
```

`-h` and `--help` are equivalent. Use leaf help for EPICS:
`wirepup epics --help` exits 2. Version is a command, not `--version`.
Scripts must invoke an explicit command instead of piping answers into the guide.

Keep structured stdout separate from progress/errors:

```bash
wirepup epics find WP:VALUE --pcap tests/vm/pcap/epics-reads.pcap --json --quiet
```

In a script, redirect stdout/stderr to separate files and save `$?` immediately.
The example emits one diagnosis document; streaming commands can emit multiple
JSON lines. Quiet does not hide errors or confirmation prompts.
Use the [JSON contract](output-schema.md) and the report's findings together
with [exit status](cli-reference.md#exit-status-and-scripts).

Only for separately approved active automation:

```bash
sudo wirepup probe -i enp3s0 --arp 192.0.2.2/32 --yes --json
```

`--yes` skips confirmation, not conflict or privilege checks, and does not
enable `--active`. In the guide, copy the displayed command for subsequent
direct use; repeated active actions still ask again.

Options: [help](cli-reference.md#-h---help),
[JSON](cli-reference.md#--json), [progress](cli-reference.md#--quiet),
[confirmation](cli-reference.md#--yes).

## Complete commands in Bash

Activate completion using the path for your installation; see
[installation and activation](../README.md#bash-completion).
From the source checkout with `bin` on PATH:

```bash
source completions/wirepup.bash
```

| Type | Press | Expected result |
| --- | --- | --- |
| `wirepup cap` | Tab | `wirepup capture` |
| `wirepup epics fi` | Tab | `wirepup epics find` |
| `wirepup observe --js` | Tab | `--json` |
| `wirepup observe --protocol arp,ll` | Tab | `arp,lldp` |
| `wirepup capture -i ` | Tab, then Tab if ambiguous | Local interface candidates |
| `wirepup read tests/vm/pcap/epics-r` | Tab | `tests/vm/pcap/epics-reads.pcap` |

Do not type the word Tab or press Enter to request completion.
The first Tab extends a common prefix; a second lists remaining candidates.
Paths with spaces can be quoted or escaped; start a dash-prefixed path with
`./`. Completion lists syntax, local interfaces and files without capturing
or transmitting. PV names must be supplied by the operator.

Complete an explicit command before running it with the needed privileges.
The guide uses menus instead of Bash completion for its answers.

Options: [protocol values](cli-reference.md#--protocol),
[interface names](cli-reference.md#-i---interface),
[file input](cli-reference.md#--pcap), [JSON](cli-reference.md#--json).
