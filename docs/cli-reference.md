# Command and Option Reference

## Scope

This reference describes the implemented WirePup CLI for direct terminal use and scripts. Use the [tested usage scenarios](usage-scenarios.md) to start from a task, or the option sections below to understand a particular flag.

**Out of scope:** interactive guidance that is not implemented yet, protocol internals, and a guarantee that an unobserved device or PV does not exist. See the [execution-mode contract](cli-design.md#execution-modes) and [safety rules](safety.md).

## Invocation and help

Run `wirepup <command> [options]`. Place options after the command, or after the second command word for `epics observe`, `epics find`, and `epics diagnose`.

- `wirepup help`, `wirepup -h`, and `wirepup --help` print general help and exit 0.
- A leaf command other than `version` accepts `-h` or `--help`, prints its flag help to stderr, and exits 0. For example: `wirepup epics find --help`.
- `wirepup epics` alone and `wirepup epics --help` exit 2; use leaf-command help.
- `wirepup version` prints the build version and exits 0. There is no top-level `--version` option; arguments after `version` are currently ignored.
- Bare `wirepup` currently prints usage to stderr and exits 2, including on a terminal. Guidance is a planned entry mode, not a current feature.

Named flags accept one or two leading dashes: `-json` and `--json` are equivalent. Value flags accept `--timeout 5s` or `--timeout=5s`. Boolean flags take no following value; use `--json=false` to turn one off, not `--json false`. Repeating a flag or its alias uses the last value.

`read`, `diagnose`, `epics diagnose`, `epics find`, `connect`, and `disconnect` accept one positional argument before or after their flags. Avoid a bare `--` separator on these commands: their positional extractor does not implement the conventional end-of-options behavior. Use `./` before a capture filename beginning with a dash. For commands without a positional argument, do not append extra words: the underlying flag parser stops at the first one and later flags may not apply.

## Commands and required inputs

| Command | Required input | Purpose and action |
| --- | --- | --- |
| `interfaces` | None | List local interfaces; read-only. |
| `observe` | `-i IFACE` or `--pcap FILE` | Passive event stream. |
| `discover` | `-i IFACE` or `--pcap FILE` | Passive device events and final inventory. |
| `capture` | `-i IFACE -o FILE` | Passive live capture to a file; overwrites an existing output file. |
| `read FILE` | One capture filename | Passive replay; `--devices` selects the device view. |
| `diagnose [TARGET]` | `-i IFACE` or `--pcap FILE` | Passive diagnosis; optional target is an IPv4 address. |
| `epics observe` | `-i IFACE` or `--pcap FILE` | Passive labelled CA/PVA events. |
| `epics find PV` | PV name, plus a source or `--active --to ...` | Passive PV-specific report; `--active` explicitly enables transmission. |
| `epics diagnose [TARGET]` | Same as `diagnose` | Starts with EPICS-only rules enabled. |
| `tui` | `-i IFACE` or `--pcap FILE`; terminal stdin and stdout | Passive interactive views. |
| `probe` | `-i IFACE --arp PREFIX` | Active bounded ARP sweep. |
| `connect [TARGET]` | `-i IFACE`, plus either an IPv4 target or `--address PREFIX` | ARP conflict probes followed by a temporary address change. |
| `disconnect [ADDRESS]` | None; optional `-i IFACE` and address filter | Immediately remove matching WirePup-recorded addresses; no confirmation prompt. |
| `version` | None | Print the build version. |

Live capture needs raw-packet privileges on Linux. `probe` needs raw-packet privileges; `connect` and `disconnect` need permission for host address changes. An active EPICS UDP search with `--to` and no capture interface does not require raw capture. Reading captures, listing interfaces, and displaying help need no network administration privilege.

## Where shared options take effect

All leaf commands except `version` register the shared options below. Registration does not mean a command uses them. Unlisted shared options in this table are accepted but do not affect that command; a malformed value can still fail during parsing.

| Command | Shared options that affect behavior |
| --- | --- |
| `interfaces` | `--json` only; `-i` does not filter the list. |
| `observe`, `read` event view | `-i`, `--pcap`, `--protocol`, `--json`, `--quiet`, `--verbose`, `--timeout`, `--no-promisc`; `read` supplies the file positionally. |
| `discover`, `read --devices` | Same source/filter/output options, plus `--oui-file`; `--verbose` has no effect. |
| `capture` | `-i`, `--protocol`, `--quiet`, `--timeout`, `--no-promisc`; `--pcap` does not select a file source. |
| `diagnose`, `epics diagnose` | `-i`, `--pcap`, `--local`, `--protocol`, `--json`, `--quiet`, `--timeout`, `--no-promisc`, `--oui-file`. |
| `epics observe` | `-i`, `--pcap`, `--protocol`, `--json`, `--quiet`, `--timeout`, `--no-promisc`; its explicit protocol selection makes `--verbose` ineffective. |
| `epics find` | `-i`, `--pcap`, `--json`, `--quiet`, `--timeout`, `--no-promisc`; `--protocol` is validated but never filters observation or transmission. |
| `tui` | `-i`, `--pcap`, `--local`, `--protocol`, `--quiet`, `--verbose`, `--timeout`, `--no-promisc`, `--oui-file`; `--json` does not replace the terminal display. |
| `probe` | `-i`, `--json`; timing and transmission budget are fixed, not controlled by `--timeout`. |
| `connect` | `-i`, `--json`; `--timeout`, `--quiet`, and `--no-promisc` affect the passive window when a target is supplied. |
| `disconnect` | `-i` filters recorded entries; `--json` selects report output. |

Source-dependent flags only apply when that source is used: `--no-promisc` has no effect on file replay, and `--local` is read only for offline diagnosis/TUI. `--quiet` suppresses selected progress and statistics, not errors, active plans, confirmations, or every operational notice.

## Shared option details

### Options in tested scenarios

| Options | Scenario and verified result |
| --- | --- |
| `-i`, `--protocol`, `--timeout`, `-o`, `--devices` | [Capture and replay](usage-scenarios.md#capture-and-replay): real peer ARP decoded |
| `--arp`, `--yes` | [Bounded ARP search](usage-scenarios.md#bounded-arp-search): real kernel reply; VM automation uses `--yes` |
| `--address`, `-i`, target argument | [Temporary connection](usage-scenarios.md#temporary-connection): conflict refusal and selective removal |
| `--pcap`, `--local` | [DHCP and Auto-IP](usage-scenarios.md#dhcp-and-auto-ip): lease ACK or no-offer diagnosis |
| `--pcap`, `--json`, PV argument | [Passive EPICS analysis](usage-scenarios.md#passive-epics-analysis): actual CA/PVA client traffic |
| `--active`, `--to`, `--search` | [Active EPICS search](usage-scenarios.md#active-epics-search): real IOC answers |
| `--epics`, `--json` | [Duplicate and missing PVs](usage-scenarios.md#duplicate-and-missing-pvs): distinct findings and exit status |

This table covers the recorded VM scenarios, not a claim that every option
combination has been tested live. The sections below cover the full option set.

### `-i`, `--interface`

Value: local interface name; default: empty. Required for live capture, ARP sweep, and temporary connection. Start with `wirepup interfaces` to find a name. `diagnose` and `epics diagnose` also accept comma-separated interfaces; local context comes from the first interface. Other capture commands accept one interface.

Do not combine it with `--pcap` on commands that select between live and file input: they reject the combination. On active EPICS find it provides the passive observation interface and local prefixes for default broadcast destinations; the UDP search socket itself is not bound to this interface. On `disconnect`, omitting it allows removal across all recorded interfaces.

Use cases: [observe a link](cli-design.md#wirepup-observe), [diagnose a target](cli-design.md#wirepup-diagnose), [remove temporary addresses](cli-design.md#wirepup-disconnect).

### `--pcap`

Value: PCAP or PCAPNG input path; default: empty (live source). See the applicability table. `diagnose` and `epics diagnose` accept comma-separated paths; other replay commands accept one path. Replay processes packets as fast as it can rather than reproducing capture timing.

For `read`, the positional filename is required and overrides a supplied `--pcap`. Avoid redundant input specifications. `capture`, `probe`, and `connect` do not become offline operations when given this flag. `epics find --active --pcap FILE --to ADDRESS` reads the file and can then transmit after confirmation; omit `--active` for passive-only replay.

Use cases: [offline analysis](cli-design.md#wirepup-read), [compare captures](cli-design.md#wirepup-diagnose), [find a PV in a capture](cli-design.md#wirepup-epics).

### `--local`

Value: comma-separated IPv4/IPv6 CIDR prefixes of the capture host; default: none. Read by `diagnose`, `epics diagnose`, and `tui` only with file input. Preserve the host address in each prefix, for example `192.0.2.10/24`, rather than substituting just a subnet address.

Use it to explain whether an observed address is outside the original host's subnet. The capture does not supply all original host configuration; omitting this optional flag leaves that context empty. It does not assign an address or change routes. Live diagnosis obtains local context from the current host and ignores `--local`.

Use case: [offline subnet diagnosis](cli-design.md#wirepup-diagnose).

### `--protocol`

Value: comma-separated names from `frame`, `arp`, `lldp`, `ipv4`, `dhcp`, `ipv6`, `ndp`, `tcp`, `ca`, `pva`. Names are case-insensitive; surrounding spaces are trimmed. Default: no selection, except `epics observe`, which defaults to `ca,pva`.

On live input, this narrows kernel admission where a rule exists. On replay there is no kernel filter. Event views select matching observations; device-table views keep the entire packet's observations when any observation matches. An explicit selection takes precedence over `--verbose`. With no selection, event views hide frame/IPv4/IPv6/TCP observations unless verbose.

CA/PVA rules admit all IPv4 TCP because server ports may be learned later. Consequently `capture --protocol ca` can save unrelated IPv4 TCP traffic. Including `frame` disables kernel narrowing for the combined set. `tcp` currently filters IPv4 TCP; it is not an IPv6 TCP decoder. The `ndp` name selects ICMPv6 observations.

`epics find` validates names but does not apply this filter; use `--search` to select its active protocols. See the [kernel and display distinction](cli-design.md#global-options).

Use cases: [watch ARP or LLDP](cli-design.md#wirepup-observe), [inspect CA/PVA](cli-design.md#wirepup-epics), [filter replay](cli-design.md#wirepup-read).

### `--json`

Boolean; default: false. Selects structured stdout where the applicability table lists it. `interfaces` and `diagnose` produce documents; event streams produce JSON lines; discovery produces device events followed by a device document. `connect` can emit multiple diagnosis documents as it progresses. Consumers must use the [output contract](output-schema.md), not assume every command emits one JSON object.

Progress, plans, confirmations, and errors remain on stderr. This flag does not suppress confirmation and has no output-format effect on `capture` or `tui`.

Use case: [machine-readable discovery](cli-design.md#wirepup-discover).

### `--quiet`

Boolean; default: false. Suppresses listening notices, closing capture/decode statistics, and the missing-default-OUI notice on paths that print them. It does not suppress result output or errors, and does not authorize or silence an active action's confirmation.

Use it with `--json` when a script needs fewer progress messages. See [discovery](cli-design.md#wirepup-discover) and [offline analysis](cli-design.md#wirepup-read).

### `--verbose`

Boolean; default: false. Adds frame, IPv4, IPv6, and TCP observations to `observe`, event-mode `read`, and TUI Events when no explicit protocol filter is set. It is not a debug logging switch and does not override `--protocol`.

Use case: [inspect replay events](cli-design.md#wirepup-read).

### `--timeout`

Value: Go duration such as `500ms`, `5s`, or `2m`; parsed default: `0`. Use positive values for a bounded run. This is elapsed execution time, not a timestamp range within a PCAP.

| Operation | Behavior when omitted or explicitly zero |
| --- | --- |
| Live `observe`, `discover`, `capture`, `epics observe` | Run until interrupted. |
| Offline replay/diagnosis | Process to end of file. |
| Live `diagnose`, `epics diagnose` | Observe for 10 seconds. |
| Live passive window in `epics find` | Observe for 5 seconds. |
| `connect` with a target | Observe for 5 seconds before deciding on an address. |
| `epics find --active --to ...` without live observation | Wait up to 2 seconds for each selected protocol's replies. |
| `tui` | Stay in the interface until quit/interrupted, even after a file ends. |

Active find runs CA and PVA sequentially. After a live passive window, it reuses that window's timeout (default 5 seconds) for each protocol's reply wait; it is not a single end-to-end deadline. A positive timeout also ends TUI. `probe`, `disconnect`, and address-only `connect` do not use this option to bound their active actions. Negative durations currently disable observation deadlines; active search functions replace nonpositive reply waits with 2 seconds. Prefer positive durations rather than depending on that edge behavior.

Use cases: [bounded observation](cli-design.md#wirepup-observe), [diagnosis](cli-design.md#wirepup-diagnose), [active search](cli-design.md#wirepup-epics).

### `--no-promisc`

Boolean; default: false. Set it to prevent the live capture socket from requesting promiscuous membership. It does not change switch forwarding or make traffic from other switch ports visible. File input is unaffected. It applies to the passive capture window of `connect`/`epics find`, not to ARP/UDP transmit behavior.

Use case: [live capture](cli-design.md#wirepup-capture).

### `--oui-file`

Value: IEEE `oui.txt` path; default: first readable file from `/var/lib/ieee-data/oui.txt`, `/usr/share/ieee-data/oui.txt`, `/usr/share/hwdata/oui.txt`. Used by `discover`, `read --devices`, `diagnose`, `epics diagnose`, and `tui`.

A missing default registry disables vendor hints and normally prints a notice. A missing explicitly requested registry fails with exit 2. No registry is downloaded automatically. Vendor names remain hints, and locally administered MAC addresses do not get a vendor inferred from their prefix.

Use cases: [device inventory](cli-design.md#wirepup-discover), [device replay](cli-design.md#wirepup-read).

## Command-specific options

### `--devices`

`read` only; Boolean; default: false. Changes replay from event output to device events plus the final device inventory. Combine with `--oui-file` for vendor hints, `--protocol` for packet selection, and `--json` for structured output. See [read](cli-design.md#wirepup-read).

### `-o`, `--output`

`capture` only; required output path; default: empty. A `.pcapng` suffix (case-insensitive) selects PCAPNG; other suffixes select PCAP. The file is created or truncated after the live source opens. This does not convert an input capture. See [capture](cli-design.md#wirepup-capture).

### `--snaplen`

`capture` only; integer byte count; default: 0. Positive values truncate saved packet bytes without changing original-length metadata. Nonpositive values use the writer default of 262144 bytes and apply no extra CLI truncation. The live capture buffer also defaults to 262144 bytes; increasing this flag cannot recover bytes already omitted by capture. Smaller values may remove payload required by diagnosis. See [capture](cli-design.md#wirepup-capture).

### `--epics`

`diagnose` and `epics diagnose`; Boolean. Default: false for `diagnose`, enabled by the `epics diagnose` wrapper. Selects CA/PVA rules instead of general network diagnosis; it is a rule selector, not a packet filter. `epics diagnose --epics=false` overrides the wrapper. `--protocol` may further restrict input, changing what can be inferred. See [diagnose](cli-design.md#wirepup-diagnose).

### `--yes`

`probe`, `connect`, `epics find`; Boolean; default: false. Skips the confirmation prompt only. It does not imply `--active` for EPICS find, bypass argument/privilege checks, or bypass ARP conflict checks. Without it, an active action requiring confirmation refuses non-terminal stdin with exit 2. A terminal answer other than `y`/`yes` aborts with exit 1.

`disconnect` does not register `--yes` and never prompts: explicit invocation is the action. See [probe](cli-design.md#wirepup-probe), [connect](cli-design.md#wirepup-connect), and [EPICS search](cli-design.md#wirepup-epics).

### `--arp`

`probe` only; required IPv4 CIDR prefix; default: empty. Accepts `/24` through `/32`; shorter prefix lengths (larger networks) and IPv6 are refused. One request per usable host at 20 per second; `/31` includes both addresses and `/32` one address. There is no rate or retry option. Use only on the intended interface and prefix after reviewing the printed plan. See [probe](cli-design.md#wirepup-probe).

### `--address`

`connect` only; IPv4 address with CIDR prefix; default: a recommended candidate if a target was observed. Without this option, the target positional address is required. Without a target, an explicit `--address` skips the passive discovery window but still runs confirmation and conflict probes before adding the address.

With both a target and `--address`, the command observes the target but uses the explicit candidate even when that target was not observed. Existing local addresses and network/broadcast addresses for prefixes shorter than `/31` are refused. Three ARP probes precede any address assignment. Remove the result later with `disconnect`; the session file is `/run/wirepup/session.json`. See [connect](cli-design.md#wirepup-connect).

### `--active`

`epics find` only; Boolean; default: false. After any selected passive/file observation, print the destinations and request confirmation, then send one search datagram per selected protocol per destination. Requires `--to` or an interface with usable broadcast prefixes. It can transmit even with `--pcap`; never treat file selection as an override of this flag. See [EPICS search](cli-design.md#wirepup-epics).

### `--to`

`epics find --active`; comma-separated numeric IP addresses or `IP:port`; default: interface-directed broadcast destinations. Despite the help term `host`, DNS hostnames are not resolved. Use IPv4 destinations with the current UDP4 search implementation.

An address without a port uses 5064 for CA and 5076 for PVA. An explicit port is reused for every selected protocol; choose `--search ca` or `--search pva` when the port is protocol-specific. With no `-i`, explicit destinations avoid a live observation window and the OS routing table chooses the outgoing path. Without `--active`, this option is ignored. See [EPICS search](cli-design.md#wirepup-epics).

### `--search`

`epics find --active`; default: `ca,pva`. Use `ca`, `pva`, or `ca,pva` to select outgoing searches. Case and surrounding whitespace are normalized. It does not select passive observations; both CA and PVA remain observed. Without `--active`, it is ignored. The current validator rejects a set with neither CA nor PVA, but ignores additional unknown names if a supported name is present; use only the documented values. See [EPICS search](cli-design.md#wirepup-epics).

## Exit status and scripts

| Code | Meaning |
| --- | --- |
| 0 | Successful operation; not necessarily a response or reachable target. |
| 1 | General error or user-aborted confirmation. |
| 2 | Invalid arguments, missing terminal requirement, or refused non-terminal confirmation. |
| 3 | Insufficient capture or active-operation privilege. |
| 4 | Capture failure, including a file ending inside a packet. |
| 5 | Requested target/PV not observed, or active search got no positive answer. |
| 6 | Unsafe or conflicting address change. |

A missing input file normally yields 1, not 4. Passive find can exit 0 because it observed a search for the PV even if no server answered. Targeted diagnosis uses 5 when the address was not seen; untargeted diagnosis can succeed with an absence finding. Consult the report, not just the status, before deciding the next action.

Keep stdout and stderr separate when consuming JSON. Use explicit commands for scripts and supply `--yes` only when deliberately authorizing that active operation. The [execution-mode contract](cli-design.md#execution-modes) preserves this path when guidance is implemented.
