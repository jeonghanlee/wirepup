# Output Schema

## Scope

This document is the public contract for the JSON that WirePup writes with `--json` (ADR-0009): the five document types, their fields, and the rules that keep them stable. A test under `cmd/wirepup` checks that every key appearing in the committed golden outputs is named here.

**Out of scope:** the human-readable text and TUI renderers, which may change freely, and the internal Go types, which are never marshalled directly.

## Rules

- Every document and every stream record carries `schema` with the value `wirepup/<document>/<major>`. The major number changes only when a field is removed, renamed, or changes meaning; adding a field does not change it, and consumers must ignore unknown fields.
- Field names are `snake_case`. Timestamps are RFC 3339 with sub-second digits and a numeric UTC offset. MAC addresses are lower case and colon-separated. IP addresses use the canonical text form of Go's `net/netip`.
- A packet reference (`evidence`) is an object with `source` (the interface name or capture file path) and `packet_id` (the 1-based frame number within that source, equal to the Wireshark frame number of the same file).
- Absent optional values are omitted (`omitempty`) or written as an empty string, an empty list, or `unknown` where the text form has that meaning; a consumer must treat all three as "not observed".

## `wirepup/interfaces/1`

Written by `wirepup interfaces --json` as one document.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `wirepup/interfaces/1` |
| `interfaces` | list of interface | one entry per local interface, ordered by index |

Interface: `name`, `mac` (omitted when absent), `up` (administrative flag), `oper_state` (sysfs operstate or `unknown`), `mtu`, `loopback`, `ipv4` and `ipv6` (lists of prefixes in text form).

## `wirepup/event/1`

Written by `observe --json`, `read --json`, and `epics observe --json` as JSON Lines: one object per observation.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `wirepup/event/1` |
| `source` | string | capture source |
| `packet_id` | integer | frame number within the source |
| `time` | timestamp | capture time |
| `interface` | string | capture interface, or `pcap` for a classic PCAP file |
| `protocol` | string | parser that produced the observation: `ethernet`, `arp`, `lldp`, `ipv4`, `ipv6`, `icmpv6`, `tcp`, `dhcp`, `epics.ca`, `epics.pva` |
| `kind` | string | observation kind (ADR-0008), for example `frame`, `arp`, `ndp`, `ca.search`, `pva.beacon` |
| `confidence` | string | `confirmed`, `strong_hint`, or `weak_hint` |
| `summary` | string | one-line text form of the same observation |
| `fields` | object | kind-specific fields, listed below |

Fields by kind:

- `frame`: `source_mac`, `destination_mac`, `ether_type` (hex string), `length`, `vlan` (`unknown` when no tag was visible), `vlan_id`, `vlan_priority` (the last two only when a tag was visible).
- `arp`: `role` (`request`, `reply`, `probe`, `announcement`), `sender_mac`, `sender_ip`, `target_mac`, `target_ip`, `link_local`.
- `lldp`: `source_mac`, `chassis_id`, `port_id`, `ttl`, `system_name`, `system_description`, `port_description`, `capabilities`, `enabled_capabilities`, `management_addresses`, `port_vlan_id` (0 when absent), `vlan_names` (list of `id:name`), `max_frame_size`, `malformed`.
- `ipv4`: `src`, `dst`, `protocol` (name), `ttl`, `length`, `fragment`.
- `ipv6`: `src`, `dst`, `next_header`, `hop_limit`, `length`, `fragment`.
- `ndp` and `icmpv6`: `type`, `type_name`, `code`, `src`, `dst`, `dad`; for Neighbor Discovery also `target`, `source_ll`, `target_ll`, `router`, `solicited`, `override`, `malformed`; for a router advertisement also `managed`, `other_config`, `router_lifetime`, `mtu`, `prefixes`.
- `tcp`: `src`, `dst`, `src_port`, `dst_port`, `flags`, `seq`, `payload_length`.
- `dhcp`: `message_type`, `xid` (hex string), `client_mac`, `client_id`, `hostname`, `client_ip`, `your_ip`, `requested_ip`, `server_id`, `lease_seconds`, `src`, `dst`.
- `ca.*`: `command`, `transport`, `direction`, `src`, `dst` (both `address:port`), `data_type`, `count`, `cid`, `available`, `payload_size`, and when present `pv`, `search_id`, `reply_wanted`, `minor_version`, `server`, `server_tcp_port`, `beacon_id`, `text`, `sid`, `rights`.
- `pva.*`: `command`, `control`, `version`, `big_endian`, `transport`, `direction`, `src`, `dst`, `payload_size`, `malformed`, and when present `sequence_id`, `reply_required`, `unicast`, `protocols`, `channels` (list of `id:name`), `guid`, `server`, `server_tcp_port`, `protocol`, `found`, `instance_ids`, `beacon_sequence`, `change_count`, `buffer_size`, `registry_max`, `qos`, `authnz`, `client_channel_id`, `server_channel_id`, `status_ok`.

## `wirepup/device-event/1`

Written by `discover --json` and `read --devices --json` as JSON Lines: one object per change to the device table, followed by one `wirepup/devices/1` document at the end of the run.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `wirepup/device-event/1` |
| `time` | timestamp | time of the packet that caused the change |
| `change` | string | `new_device`, `update`, `new_neighbor`, or `address_conflict` |
| `via` | string | evidence label, for example `Ethernet`, `ARP Probe`, `DHCP ACK`, `802.1Q tag` |
| `method` | string | how an address was obtained when known: `IPv4 Link-Local / Auto-IP`, `DHCP`, `IPv6 Link-Local` |
| `address` | string | the address the change is about, when any |
| `vlan` | integer | the tag observed, when the change is a VLAN sighting |
| `device` | device | snapshot of the device after the change |
| `neighbor` | neighbor | present for `new_neighbor` |
| `conflict` | conflict | present for `address_conflict` |
| `evidence` | reference | the packet |

## `wirepup/devices/1`

Written at the end of `discover --json` and `read --devices --json`.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `wirepup/devices/1` |
| `source` | string | capture source |
| `generated_at` | timestamp | end of the run (the last packet for a file) |
| `oui_file` | string | vendor registry file read, omitted when none |
| `devices` | list of device | inferred endpoints in order of first sighting |
| `neighbors` | list of neighbor | LLDP neighbors, kept apart from endpoints |
| `conflicts` | list of conflict | addresses claimed by more than one MAC |
| `epics` | object | `ca_servers`, `ca_searches`, `pva_servers`, `pva_searches` |

Device: `id` (the MAC), `macs`, `mac_locally_administered`, `primary_ipv4` and `primary_ipv6` (strongest and most recent claim, never a probe; omitted when none), `vendor_hint` (omitted when unknown), `ipv4` and `ipv6` (lists of address), `names` (list of name), `protocols`, `first_seen`, `last_seen`, `local` (one of this host's interfaces), `ipv6_router`, `vlans` (tags observed), `vlan` (`unknown` when no tag was observed), `confidence`, `timeline` (list of timeline entry), `seen_addresses_dropped` (omitted when zero).

Address: `address`, `state` (`seen`, `probing`, `observed`, `claimed`, `leased`), `via`, `first_seen`, `last_seen`, `evidence`.

Name: `value`, `via`, `evidence`. Timeline entry: `time`, `text`, `evidence`.

Neighbor: `id`, `chassis_id`, `port_id`, `source_mac`, `system_name`, `system_description`, `port_description`, `capabilities`, `enabled_capabilities`, `management_addresses`, `port_vlan_id`, `vlan_names`, `max_frame_size`, `ttl`, `first_seen`, `last_seen`, `evidence`.

Conflict: `address`, `macs`, `first_seen`, `last_seen`, `evidence` (a list, one reference per claiming MAC).

CA server: `address`, `tcp_port`, `mac`, `pvs_answered`, `search_answers`, `beacons`, `first_seen`, `last_seen`, `evidence`. CA search: `client` (`address:port`), `client_mac`, `search_id`, `pv`, `count`, `first_seen`, `last_seen`, `answers` and `not_found` (lists of CA response), `evidence`. CA response: `server`, `tcp_port`, `mac`, `time`, `evidence`.

PVA server: `guid`, `address`, `tcp_port`, `protocol`, `mac`, `pvs_answered`, `search_answers`, `beacons`, `change_count`, `first_seen`, `last_seen`, `evidence`. PVA search: `client`, `client_mac`, `sequence_id`, `instance_id`, `pv`, `count`, `first_seen`, `last_seen`, `answers` and `not_found` (lists of PVA response), `evidence`. PVA response: `guid`, `server`, `tcp_port`, `mac`, `time`, `evidence`.

## `wirepup/diagnosis/1`

Written by `diagnose --json`, `epics diagnose --json`, `epics find --json`, `probe --json`, `connect --json`, and `disconnect --json`.

| Field | Type | Meaning |
| --- | --- | --- |
| `schema` | string | `wirepup/diagnosis/1` |
| `source` | string | capture source; for an active command the interface, or the literal `active` when the command ran without one |
| `interface` | string | interface the local context came from; `capture` when a capture file was replayed (`--pcap`) |
| `target` | string | the address asked about, omitted otherwise |
| `target_observed` | boolean | whether any device claimed the target |
| `generated_at` | timestamp | when the rules ran |
| `observed` | list of finding | packet-level facts |
| `inferred` | list of finding | interpretations |
| `recommended` | list of finding | suggested actions; nothing here is executed |
| `executed` | list of finding | actions an active command performed, with the exact command in `data` |

Finding: `code` (stable identifier such as `same-l2-different-subnet` or `ca-search-no-response`), `text`, `evidence` (list of packet references, empty when the finding is about the local context), `data` (string map of the values the text was built from; omitted when empty).

### Finding `data` keys by code

| Code | Keys |
| --- | --- |
| `local-context` | `interface`, `ipv4` |
| `l2-evidence` | `mac`, `via` |
| `address-claim` | `mac`, `address`, `state` |
| `target-on-local-subnet` | `mac`, `address`, `local_prefix` |
| `ipv4-outside-local-subnet` | `mac`, `address` |
| `same-l2-different-subnet` | `mac`, `address`, `local_ipv4` |
| `temporary-secondary-address` | `candidate`, `prefix`, `interface`, `target` |
| `duplicate-ipv4-claim` | `address`, `macs` |
| `dhcp-discover-no-offer` | `mac`, `xid` |
| `auto-ip-fallback` | `mac`, `address` |
| `ca-search-no-response`, `pva-search-no-response` | `pv`, `client`, `count` |
| `ca-multiple-servers`, `pva-multiple-servers` | `pv`, `servers` |
| `ca-server-seen` | `server`, `tcp_port` |
| `pva-server-seen` | `server`, `tcp_port`, `guid` |
| `ca-search-destination-not-local` | `pv`, `destination` |
| `ca-search-seen`, `pva-search-seen` | `client`, `count` |
| `ca-search-answer` | `server`, `tcp_port`, `pv` (active search only) |
| `pva-search-answer` | `server`, `tcp_port`, `guid`, `pv` (active search only) |
| `ca-search-sent`, `pva-search-sent` | `pv`, `destinations` |
| `arp-sweep` | `prefix`, `sent` |
| `arp-reply` | `ip`, `mac` |
| `requested-action` | `argv` |
| `arp-probe` | `sent`, `address` |
| `address-in-use` | `mac`, `kind` |
| `address-added` | `address`, `interface`, `label`, `argv`, `session` |
| `address-removed` | `address`, `interface` |

Codes not listed carry no `data`.
