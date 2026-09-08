# Work Register

## Scope

This document tracks WirePup work, dependencies, verification, and completion evidence on master.

**Out of scope:** command usage and test procedures. See the [option reference](cli-reference.md), [usage scenarios](usage-scenarios.md), and [testing guide](testing.md).

Release line: master
Milestone index: 182961f
Canonical path: `docs/milestone-182961f.md`
Canonical branch or ref: master
Git upstream: origin/master
Remote tracker: none

Next session entry point: `docs/milestone-182961f.md`: M21 is Complete. M22 documentation and T1-T2 are verified in the working tree; review the 13 changed paths, then commit and push under the separate Git authorizations. Record M22 completion after verifying its Git landing.

## Milestone

### Work

| Group | ID | Work unit | Type | Status | Ready | Deps | Done when / Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |
| filter | M1 | Kernel filter and device-table ingest apply one protocol set | Milestone | Complete | No | D1 | `ca`/`pva` admit every IPv4 TCP segment; discover, diagnose, tui drop packets outside the requested set; docs updated; [detail](#m1---kernel-filter-and-device-table-ingest-apply-one-protocol-set) |
| contract | M2 | Diagnosis documents agree on interface, source, and finding codes | Milestone | Complete | No | D1 | find and active commands fill `interface`/`source` by one rule; find codes match the rules; data keys match the schema table; [detail](#m2---diagnosis-documents-agree-on-interface-source-and-finding-codes) |
| vocabulary | M3 | One name for transport, change, and CA/PVA via labels | Milestone | Complete | No | D1 | constants replace the literals; timelineText labels CA/PVA sightings; [detail](#m3---one-name-for-transport-change-and-capva-via-labels) |
| vocabulary | M4 | One address rank and one assumed prefix length | Milestone | Complete | No | D1 | `device.Rank`/`device.Strong` used by output and diagnose; `diagnose.AssumedPrefixBits` used by cmd_active; [detail](#m4---one-address-rank-and-one-assumed-prefix-length) |
| vocabulary | M5 | Active ARP classification reuses the passive parser | Milestone | Complete | No | D1 | `parseARP` uses `arp.Parse` and `arp.Classify`; `Reply.Kind` is `arp.Role`; [detail](#m5---active-arp-classification-reuses-the-passive-parser) |
| cli | M6 | Global options documented per command and validated on find | Milestone | Complete | No | D1 | cli-design.md names the readers of each option; `epics find` rejects an unknown protocol name; [detail](#m6---global-options-documented-per-command-and-validated-on-find) |
| rules | M7 | Auto-IP fallback waits for the DHCP offer grace | Milestone | Complete | No | D1 | `autoIPRules` applies `dhcpOfferGrace` like `dhcpRules`; [detail](#m7---auto-ip-fallback-waits-for-the-dhcp-offer-grace) |
| fixtures | M8 | Fixture generator selects the PCAPNG copy by name | Milestone | Complete | No | D1 | no positional index; regenerated fixtures byte-identical; [detail](#m8---fixture-generator-selects-the-pcapng-copy-by-name) |
| cleanup | M9 | Unused declarations removed | Milestone | Complete | No | D1 | `Section*` and `Interface.Running` gone; build and tests pass; [detail](#m9---unused-declarations-removed) |
| active | M10 | PVA search flag derived from local prefixes | Milestone | Complete | No | D1 | `active.Destination` carries `Broadcast`; `PVASearch` sets the flag from it; [detail](#m10---pva-search-flag-derived-from-local-prefixes) |
| cleanup | M11 | `decode.SetPorts` recorded as the seam for offset EPICS ports | Milestone | Complete | No | D4 | doc comment names the seam and its missing halves; [detail](#m11---decodesetports-recorded-as-the-seam-for-offset-epics-ports) |
| capture | M12 | One default snap length | Milestone | Complete | No | D3 | `capture.DefaultSnapLen` used by pcapfile, afpacket, and the generator; fixtures byte-identical; [detail](#m12---one-default-snap-length) |
| vocabulary | M13 | Wire constants of bpf and active come from the parsers | Milestone | Complete | No | D3 | no EtherType, opcode, hardware, or protocol literal in `bpf.go` or `active.go` that a parser exports by name; [detail](#m13---wire-constants-of-bpf-and-active-come-from-the-parsers) |
| vocabulary | M14 | Shared helpers named once where both users already import | Milestone | Complete | No | D3 | `output.Dash`, `device.AddrText`, `active.DirectedBroadcast` replace six copies; output unchanged; [detail](#m14---shared-helpers-named-once-where-both-users-already-import) |
| vocabulary | M15 | Oper-state unknown sentinel named once | Milestone | Complete | No | D4 | `interfaces.OperStateUnknown` mirrored as `output.OperStateUnknown`; `text` and `tui` compare against it; [detail](#m15---oper-state-unknown-sentinel-named-once) |
| rules | M16 | diagnose --epics reports the absence of EPICS traffic | Milestone | Complete | No | D2 | one Inferred finding under `--epics` when no CA/PVA record exists; golden added; [detail](#m16---diagnose---epics-reports-the-absence-of-epics-traffic) |
| contract | M17 | Aggregate unanswered-search findings carry no data keys | Milestone | Complete | No | D4, D5 | own codes `ca-searches-no-response`/`pva-searches-no-response` with a `searches` key; [detail](#m17---aggregate-unanswered-search-findings-carry-no-data-keys) |
| cli | M18 | Direct execution and option reference | Milestone | Complete | No | D6 | Existing script behavior preserved; every option documented against the implementation; [detail](#m18---direct-execution-and-option-reference) |
| cli | M19 | Guided execution from observed results | Milestone | Complete | No | D6, M18 | Bare terminal invocation guides the user through the existing operations and explains next actions; [detail](#m19---guided-execution-from-observed-results) |
| shell | M20 | Bash completion and installation | Milestone | Complete | No | D6, M18 | Context-aware completion works and make installs and verifies it; [detail](#m20---bash-completion-and-installation) |
| docs | M21 | Executable scenarios and bidirectional option links | Milestone | Complete | No | D6, M18, M19, M20 | Scenarios explain their options; each option links to relevant verified scenarios; [detail](#m21---executable-scenarios-and-bidirectional-option-links) |
| docs | M22 | Usage-first documentation navigation and cleanup | Milestone | In progress | No | D6, M21 | User navigation leads to verified usage; obsolete plans retired without losing current requirements; [detail](#m22---usage-first-documentation-navigation-and-cleanup) |

Status totals: 21 Complete, 1 In progress. Ready: none; M22 verification is recorded and Git landing remains. No Backlog rows.

### Decisions

| ID | Decision | Decision Date |
| --- | --- | --- |
| D1 | Apply the fates of M1-M10 and the 2026-09-03 Keep rows of `docs/CLOSED_DOORS.md` as converged in the paired review debate of that date (chat only, no artifact); the oper-state sentinel (M15) and `decode.SetPorts` (M11) stay undecided | 2026-09-03 |
| D2 | M16 fate converged in the same debate: an Inferred `epics-nothing-observed` finding under `--epics`, exit code unchanged; implementation not yet authorized | 2026-09-03 |
| D3 | Re-examination of the Keep rows of `docs/CLOSED_DOORS.md` (paired review debate, chat only): `dashIf`, `addrText`, `broadcastOf` become M14; the two snap-length defaults become M12; the EtherType, opcode, hardware and protocol constants of bpf and active become M13, with `arp` exporting its address-length constants; the U/L-bit test, the frame offsets, and `bpf.AcceptLength` stay Keep; the fixtures row keeps its verdict with a corrected premise; implementation of M12-M14 not yet authorized | 2026-09-03 |
| D4 | M15, M11, and M17 move from Backlog to Milestone: M15 names the oper-state sentinel once (`interfaces.OperStateUnknown`, mirrored by `output`); M11 keeps `decode.SetPorts` and records it as the seam for offset EPICS ports; M17 is to be done, its shape still to be picked; implementation not yet authorized | 2026-09-03 |
| D5 | M17 shape: separate aggregate codes `ca-searches-no-response`/`pva-searches-no-response`, per-search codes unchanged. The aggregate data key is `searches` (number of unanswered searches), distinct from the per-search `count`, so the two never collide under one key | 2026-09-04 |
| D6 | Assign M18-M22 to plan direct execution alongside no-argument terminal guidance, Bash completion with installation support, real scenario walkthroughs, two-way scenario/option links, and usage-first documentation cleanup. Preserve current safety rules, output contracts, and engineering references. Draft implementation plans are not yet accepted; implementation is not yet authorized. | 2026-09-05 |

### Assignment History

| Work Identity | From Canonical | To Canonical | Target Commit | Authority Moved At |
| --- | --- | --- | --- | --- |
| M15 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |
| M11 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |
| M17 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |

### Milestone Details

M1-M17 summaries state the defects as found at commit 182961f. M18-M22 describe usage work assigned on 2026-09-05. Current state is in each Implementation Plan and Verification Results.

#### M1 - Kernel filter and device-table ingest apply one protocol set

Origin: 182961f / M1
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

The `ca` and `pva` kernel rules pin TCP to the default server ports while the decoder learns server ports from search responses and beacons, so a live `--protocol ca` run drops the segments of a server on a non-default port. Widening the rule to every IPv4 TCP segment fixes that only if the commands that build a device table drop packets outside the requested protocol set; today `discover`, `diagnose`, and `tui` apply every decoded observation.

##### Scope

- `cmd/wirepup/filters.go`: `ca` and `pva` TCP rules without a port; `wantPacket`.
- `cmd/wirepup/cmd_discover.go`, `cmd_diagnose.go`, `cmd_tui.go`: apply `wantPacket` before `table.Apply`.
- `docs/cli-design.md`: paragraph after the Global options block.
- `docs/architecture.md`: paragraph at the end of section 13.

Out of scope: IPv6 CA/PVA (outside V1); the CPU and drop-count cost of the wider rule on a busy link (accepted); shipping the BPF VM check of T1, which needs `golang.org/x/net/bpf` as a direct test dependency.

##### Completion Criteria

- The assembled `ca` program accepts an IPv4 TCP segment on port 5066.
- `discover --protocol ca` over a capture with non-CA packets lists no device seen only through those packets.
- Both documents carry the agreed paragraphs.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Drop `Port` from the TCP rules of `ca` and `pva` in `protocolFilters`.
2. Add `wantPacket(obs, display)`: true when `display` is nil or any observation's protocol is in `display`.
3. Keep the display set in `discoverWith`, `runDiagnose`, `runTUI` and gate `table.Apply` with it.
4. Add the two document paragraphs.
5. Verify with T1-T3.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit, not shipped | `go test -overlay` with a test file outside the tree (`TestSweepCAFilterVsLearnedTCPPort`, not kept) that calls the real `filterFor` and runs the assembled program in the `golang.org/x/net/bpf` VM on frames from `internal/fixtures` | linux, go 1.24 | segment to TCP 5066 accepted for `ca` and `pva`; before the change rejected |
| T2 | CLI | `go test ./cmd/wirepup -run TestDiscoverIngestFollowsProtocolSet` replaying a committed fixture with `--protocol` | linux, go 1.24 | device table excludes packets outside the set |
| T3 | suite | `make check` | linux, go 1.24 | gofmt clean, vet clean, all tests pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:56Z | linux, go1.24.4 | Pass | `go test -overlay=<overlay.json outside the tree> ./cmd/wirepup -run TestSweepCAFilterVsLearnedTCPPort -v` from the module root: `--protocol ca` TCP 5064, 5066, 41234 accept=262144; `--protocol pva` TCP 5075, 5077 accept=262144. The same run before the change accepted only 5064 and 5075. |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./cmd/wirepup -run TestDiscoverIngestFollowsProtocolSet`: `read --devices --protocol lldp dhcp-success.pcap` lists 0 devices, `--protocol arp` and no filter list devices |
| T3 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0; no golden changed by this work (the six regenerated goldens belong to M2 and M3) |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M2 - Diagnosis documents agree on interface, source, and finding codes

Origin: 182961f / M2
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`epics find --pcap` reports `interface: ""` where `diagnose --pcap` reports `capture`; `disconnect` without `-i` reports `source: ""` where the schema promises `active`; the passive find path emits `ca-no-answer`/`pva-no-answer` for the condition the rules call `ca-search-no-response`/`pva-search-no-response`, and the `*-multiple-servers` findings of find and of the PVA rule carry none of the data keys the schema table lists.

##### Scope

- `cmd/wirepup/cmd_epics.go`: `interface` of the passive find report; codes and data of the passive and active find findings.
- `cmd/wirepup/cmd_active.go`: `activeSourceName`; `renderExecuted` keeps `Interface: g.iface`.
- `internal/diagnose/rules.go`: `pv` and `servers` data on every `*-multiple-servers` finding.
- `docs/output-schema.md`: `interface` row; merged `*-multiple-servers` row.
- `docs/adr/0009-json-output-contract.md`: code rename is a minor change; old names listed.
- Goldens `*.find.jsonl` regenerated; the diff reviewed field by field.

Out of scope: the aggregate `*-search-no-response` Inferred findings without data (M17); the active `no-answer` code (kept as its own code).

##### Completion Criteria

- `epics find X --pcap f --json` reports `"interface": "capture"`.
- `renderExecuted` with no `-i` reports `"source": "active"` and `"interface": ""`.
- Every `ca-multiple-servers`, `pva-multiple-servers`, `ca-search-no-response`, `pva-search-no-response` finding of find carries the keys of the schema table.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. `findInterface(g)`: `g.iface`, or `capture` when a capture file is replayed.
2. `activeSourceName(g)`: `g.iface` or `active`; `renderExecuted(e, g, executed)`.
3. Rename the find codes to the `diagnose` constants and fill `Data`; fill `Data` on the PVA rule and on the CA Inferred multiple-servers finding.
4. Update the two documents; regenerate the find goldens and review the diff.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | golden | `go test ./cmd/wirepup -run TestGolden` after `WIREPUP_UPDATE_GOLDEN=1`; `git diff testdata/golden` reviewed | linux, go 1.24 | only `interface`, `code`, and `data` fields of the find goldens change |
| T2 | unit | `go test ./cmd/wirepup -run TestActiveReportSource` rendering through `renderExecuted` with `--json` | linux, go 1.24 | `source` is `active`, `interface` is empty without `-i` |
| T3 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `WIREPUP_UPDATE_GOLDEN=1 go test ./cmd/wirepup -run TestGolden`, then `git diff testdata/golden`: `*.find.jsonl` change only `interface` ("" to `capture`), `code` (`ca-no-answer` to `ca-search-no-response`), and added `data`; `ca-duplicate-servers.diagnosis.jsonl` gains `data` on the Inferred multiple-servers finding |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./cmd/wirepup -run TestActiveReportSource`: no `-i` gives `source` `active` and empty `interface`; `-i enp3s0` gives both `enp3s0`; `--pcap` alone still gives `active` |
| T3 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0 |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M3 - One name for transport, change, and CA/PVA via labels

Origin: 182961f / M3
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

The transport strings `udp`/`tcp` are spelled in decode, device, and active; the device-event change strings are compared as literals in the text renderer; the CA/PVA address sightings use ad-hoc via labels outside the `Via*` block, so `timelineText` labels them as generic IPv4 sightings.

##### Scope

- `internal/observation`: `TransportUDP`, `TransportTCP`.
- `internal/decode`, `internal/device/epics.go`, `internal/active/ca.go`, `internal/active/pva.go`: use them.
- `internal/device/device.go`: `ViaCASearchResponse`, `ViaCANotFound`, `ViaCABeacon`, `ViaPVASearchResponse`, `ViaPVABeacon`; cases in `timelineText`.
- `internal/output`: `Change*` constants mirrored from device; `text` and `tui` compare against them.

Out of scope: the CA/PVA kind strings and direction constants (kept per protocol); the oper-state `unknown` sentinel (M15).

##### Completion Criteria

- No `"udp"`/`"tcp"` transport literal outside the constants.
- `internal/output/text` and `internal/tui` import only `internal/output` for the change vocabulary.
- Devices goldens show CA/PVA timeline entries labelled by protocol.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Add the constants; replace the literals.
2. Add the via constants and `timelineText` cases; regenerate devices goldens and review the diff.
3. Mirror `Change*` in output; switch text and tui to them.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | golden | `go test ./cmd/wirepup -run TestGolden` after regeneration; diff reviewed | linux, go 1.24 | only CA/PVA timeline texts change |
| T2 | boundary | `go test ./internal/boundary` | linux, go 1.24 | passive packages still do not import active |
| T3 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `git diff testdata/golden`: `ca-search-response.devices.jsonl` and `pva-search-response.devices.jsonl` change only the timeline text `IPv4 observed 10.20.4.31` to `CA server 10.20.4.31` / `PVA server 10.20.4.31`; the `via` labels are unchanged |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/boundary -count=1` ok |
| T3 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0 |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M4 - One address rank and one assumed prefix length

Origin: 182961f / M4
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

The address-state ranking exists three times (`device.stateRank`, `output.primaryAddress`, `diagnose.strongClaim`) and the assumed /24 twice (`cmd_active`, `diagnose`), both printed to users.

##### Scope

- `internal/device`: `Rank(state)`, `Strong(state)`.
- `internal/output`: `primaryAddress` skips `StateProbing` explicitly, then ranks with `device.Rank`.
- `internal/diagnose`: `strongClaim` uses `device.Strong`; `AssumedPrefixBits` exported.
- `cmd/wirepup/cmd_active.go`: uses `diagnose.AssumedPrefixBits`.

Out of scope: changing any rank value.

##### Completion Criteria

- One rank map in the tree; `primaryAddress` never returns a probing address.
- One assumed prefix constant.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Export `Rank` and `Strong` from device.
2. Rewrite `primaryAddress` and `strongClaim` on them.
3. Export `AssumedPrefixBits`; delete the cmd_active copy.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/output -run TestPrimaryAddressSkipsProbe` | linux, go 1.24 | a table with only a probing address yields no primary address |
| T2 | suite | `make check` | linux, go 1.24 | all pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/output`: a probe alone yields no primary address, a sighting beats a probe, a claim beats a sighting |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0; no golden changed by this work |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M5 - Active ARP classification reuses the passive parser

Origin: 182961f / M5
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`active.parseARP` re-implements the four-way role ladder of `arp.Classify`, and `Conflicts` switches on the role strings.

##### Scope

- `internal/active/active.go`: `parseARP` slices the Ethernet header and calls `arp.Parse`/`arp.Classify`; `Reply.Kind` is `arp.Role`; `Conflicts` uses `arp.Role*`.

Out of scope: `ARPFrame` (transmit side stays in active).

##### Completion Criteria

- `parseARP` contains no role ladder.
- An ARP opcode other than request or reply is rejected (was classified as `request`).

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Replace the body of `parseARP`; keep the copy of the sender MAC out of the reused receive buffer.
2. Retype `Reply.Kind` and the `Conflicts` cases.
3. Extend the parseARP test with an unknown opcode.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/active -run 'TestConflictDetection|TestProbeFrameParsesAsProbe'` | linux, go 1.24 | existing cases pass; opcode 3 is rejected |
| T2 | boundary | `go test ./internal/boundary` | linux, go 1.24 | passes |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/active`: the five conflict cases pass and an ARP frame with opcode 3 is rejected by `parseARP` |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/boundary -count=1` ok |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M6 - Global options documented per command and validated on find

Origin: 182961f / M6
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`--protocol`, `--verbose`, `--local`, and `--oui-file` are registered on every command but read by a few; cli-design.md presents them as global. `epics find` never calls `filterFor`, so an unknown protocol name is accepted silently where every other capturing command exits 2.

##### Scope

- `docs/cli-design.md`: the four lines of the Global options block name their readers.
- `cmd/wirepup/cmd_epics.go`: `runEPICSFind` validates `--protocol` through `filterFor` and discards the program.

Out of scope: applying `--protocol` on find (Keep, see CLOSED_DOORS); per-command flag registration.

##### Completion Criteria

- The four lines read as agreed.
- `epics find X --pcap f --protocol bogus` exits 2 with the unknown-protocol message.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Edit the four lines.
2. Add the validation after `parse` in `runEPICSFind`.
3. Add the CLI test.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | CLI | `go test ./cmd/wirepup -run TestFindValidatesProtocolName` | linux, go 1.24 | exit 2 and `unknown protocol` on stderr; a known name still runs |
| T2 | doc | second-person pass on the edited block | reviewer | a reader can tell from the block alone which commands read each option |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./cmd/wirepup -run TestFindValidatesProtocolName`: `--protocol bogus` exits 2 with `unknown protocol`; `--protocol ca` runs |
| T2 | 2026-09-03T21:20Z | reviewer (fresh sub-agent, second-person stance, read-only) | Pass after fixes | First pass: 17 findings over the edited documents (two `epics diagnose` omissions in the option block, the PVA framing label, the `capture` and `epics find` exceptions, per-packet ingest wording, self-contained decisions in this register, test names, cited line numbers); all applied. Re-read: two residual findings (the epics commands in the paragraph, this row), applied; no remaining defect reported. |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M7 - Auto-IP fallback waits for the DHCP offer grace

Origin: 182961f / M7
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`dhcpRules` waits `dhcpOfferGrace` before calling a discover unanswered; `autoIPRules` calls the same exchange failed at once, so inside the window the Auto-IP text asserts a DHCP failure the report has not found.

##### Scope

- `internal/diagnose/rules.go`: `autoIPRules(table, end)` with the same guard; `RunAll` passes `opts.End`.

Out of scope: the rule text.

##### Completion Criteria

- Inside the grace window the Auto-IP finding carries no DHCP suffix; after it, the suffix and `dhcp-discover-no-offer` appear together.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Thread `end` and add the guard.
2. Add a rules test for the inside-window case.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/diagnose -run TestDHCPNoOfferAndAutoIPFallback` extended with an `End` inside the grace | linux, go 1.24 | suffix absent inside, present after |
| T2 | suite | `make check` | linux, go 1.24 | all pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/diagnose`: at `End` = 10 s the Auto-IP text carries the DHCP suffix and `dhcp-discover-no-offer` is reported; at `End` = 2 s neither appears |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0; `dhcp-no-offer.diagnosis.jsonl` unchanged |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M8 - Fixture generator selects the PCAPNG copy by name

Origin: 182961f / M8
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`testdata/gen/main.go` writes the PCAPNG copy from `fixtureSet()[3]` and loops over a one-element extension list; an insertion above index 3 silently regenerates the wrong file.

##### Scope

- `testdata/gen/main.go`: select the fixture by name; drop the one-element loop.

Out of scope: fixture contents.

##### Completion Criteria

- Regenerating leaves every committed fixture byte-identical.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Add a named lookup and use it for the PCAPNG copy.
2. Run the generator and check the tree.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | generator | `go run ./testdata/gen` then `git status --porcelain testdata/pcap` | linux, go 1.24 | empty |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go run ./testdata/gen` regenerated every `.pcap` and the `.pcapng`; `git status --porcelain testdata/pcap` printed nothing |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M9 - Unused declarations removed

Origin: 182961f / M9
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`diagnose.Section*` (four constants) and `interfaces.Interface.Running` have no caller, test, or document.

##### Scope

- `internal/diagnose/diagnose.go`: delete the `Section*` block.
- `internal/interfaces/interfaces.go`: delete the `Running` field and its assignment.

Out of scope: `CodeEPICSNothingObserved` (M16 gives it an emitter); `decode.SetPorts` (M11).

##### Completion Criteria

- Build and tests pass without the declarations.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Delete the declarations.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0 after the deletions |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M10 - PVA search flag derived from local prefixes

Origin: 182961f / M10
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`PVASearch` sets the "sent as unicast" search flag (PVAccess `searchRequest` flags bit 7) from the last address byte, so a directed broadcast of a prefix longer than /24 is flagged unicast and a `.255` host inside a /23 is flagged broadcast. Servers re-forward unicast-flagged searches over loopback (CMD_ORIGIN_TAG).

##### Scope

- `internal/active`: `Destination{AddrPort, Broadcast}`; `BroadcastDestinations` returns it; `IsBroadcast(addr, prefixes)`; `CASearch`/`PVASearch` take `[]Destination`; `PVASearch` sets the flag from `Broadcast`.
- `cmd/wirepup/cmd_epics.go`: `searchDestinations` classifies every destination against the interface prefixes when `-i` is given; `joinDests` takes `[]Destination`.

Out of scope: CA (no such flag).

##### Completion Criteria

- A destination is broadcast when it is `255.255.255.255`, multicast, or the directed broadcast of a local prefix containing it; otherwise unicast; without `-i` only the first two are broadcast.
- The datagram sent to a unicast destination carries flag 0x80; to a broadcast destination it does not.

##### Dependencies And Decisions

- D1

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (items 1-17)
Implementation Authorization: 2026-09-03, owner direction
Superseded Plan Artifacts: none

1. Add `Destination` and `IsBroadcast`; change the signatures.
2. Classify in `searchDestinations`; fetch prefixes whenever `-i` is given.
3. Set the PVA flag from `Broadcast`; cite the specification on the field.
4. Update the active tests.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/active -run 'TestIsBroadcast|TestBroadcastDestinations'` | linux, go 1.24 | /25 `.127` broadcast; /23 `.0.255` host unicast; limited broadcast and multicast broadcast; non-local `.255` unicast |
| T2 | socket | `go test ./internal/active -run TestPVASearch` reading the flags byte of the received search | linux, go 1.24 | 0x80 set for the loopback unicast destination |
| T3 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `go test ./internal/active`: `TestIsBroadcast` and `TestBroadcastDestinations` pass on the listed cases |
| T2 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `TestPVASearchAgainstLoopbackServer`: the loopback server parsed the flag as unicast for a plain destination and as broadcast for a destination marked `Broadcast` |
| T3 | 2026-09-03T20:55Z | linux, go1.24.4 | Pass | `make check` exit 0 |

##### Closure Evidence

- committed in a08a9ba (push pending)

#### M11 - decode.SetPorts recorded as the seam for offset EPICS ports

Origin: 182961f / M11
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`decode.SetPorts` is the only writer of the decoder's port set besides `New` and has no caller, flag, or document. It stays as the seam for a site that runs EPICS on offset ports (`EPICS_CA_SERVER_PORT` and its PVA counterparts); its comment must say so, and say that using it also needs a CLI flag and a matching kernel filter rule, neither of which exists.

##### Scope

- `internal/decode/decode.go`: the doc comment of `SetPorts`.

Out of scope: the flag and the filter rule (a later work unit).

##### Completion Criteria

- The comment names the seam and its two missing halves; build and tests pass.

##### Dependencies And Decisions

- D4

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, owner decision D4
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Rewrite the doc comment.
2. Verify with T1.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in e3f7074 (push pending); single-reviewer review accepted, no must-fix findings

#### M12 - One default snap length

Origin: 182961f / M12
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`pcapfile.DefaultSnapLen` and `afpacket.DefaultSnapLen` both equal 262144 and nothing ties them together; both packages already import the root `internal/capture`.

##### Scope

- `internal/capture`: `DefaultSnapLen`.
- `internal/capture/pcapfile`, `internal/capture/afpacket`, `testdata/gen/main.go`: use it; the two package constants go.

Out of scope: `bpf.AcceptLength` (Keep, CLOSED_DOORS: it must stay no smaller than any snap length, not equal to it).

##### Completion Criteria

- One snap-length default in the tree; regenerated fixtures byte-identical.

##### Dependencies And Decisions

- D3

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, owner decision D3
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Add the root constant; replace the two package constants and the generator's reference.
2. Verify with T1 and T2.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | generator | `go run ./testdata/gen` then `git status --porcelain testdata/pcap` | linux, go 1.24 | empty |
| T2 | suite | `make check` | linux, go 1.24 | all pass |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T2 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in c2aee82 (push pending); single-reviewer review accepted, no must-fix findings

#### M13 - Wire constants of bpf and active come from the parsers

Origin: 182961f / M13
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`internal/capture/bpf/bpf.go` defines `etherTypeIPv4`/`etherTypeIPv6` that `internal/protocol/ethernet` exports by name; `internal/active/active.go` defines `etherTypeARP`, `opRequest`, `opReply`, `ethernetHeaderLen` and, in `ARPFrame`, writes the literals `1`, `0x0800`, `6`, `4`, although it already imports `internal/protocol/arp` (M5) and `ethernet` is a passive package it may import. Only the byte offsets and `frameLen` are the packages' own layout.

##### Scope

- `internal/protocol/arp`: export `HardwareAddrLen` and `ProtocolAddrLen` (today `hwAddrLen`, `protoAddrLen`).
- `internal/capture/bpf/bpf.go`: `ethernet.EtherTypeIPv4`/`EtherTypeIPv6`, with a `uint32` conversion where the value feeds `pending.k`.
- `internal/active/active.go`: `arp.OpRequest`/`OpReply`, `ethernet.EtherTypeARP`/`HeaderLen`, `arp.HardwareEthernet`/`ProtocolIPv4`, `arp.HardwareAddrLen`/`ProtocolAddrLen`; `frameLen` stays.

Out of scope: the offsets (`off*`, `rel*`) and `frameLen` (Keep, CLOSED_DOORS).

##### Completion Criteria

- No literal in `bpf.go` or `active.go` for a value a parser exports by name; the boundary test still passes.

##### Dependencies And Decisions

- D3

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, owner decision D3
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Export the two `arp` length constants.
2. Replace the constants and literals in `bpf.go` and `active.go`.
3. Verify with T1-T3.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/capture/bpf ./internal/active ./internal/protocol/arp` | linux, go 1.24 | all pass |
| T2 | boundary | `go test ./internal/boundary` | linux, go 1.24 | passes |
| T3 | suite | `make check` | linux, go 1.24 | all pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T2 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T3 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in 131dc1b (push pending); single-reviewer review accepted, no must-fix findings

#### M14 - Shared helpers named once where both users already import

Origin: 182961f / M14
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Four identical `dash` helpers (`cmd/wirepup/cmd_active.go` `dashIfEmpty`, `internal/output/output.go` `dashIf`, `internal/output/text/text.go` `dash`, `internal/tui/tui.go` `dash`), two identical `addrText` helpers (`internal/device`, `internal/diagnose`), and `cmd_active.broadcastOf` beside `active.directedBroadcast`. In every case the users already import the package that can own the one copy, so sharing adds no import edge.

##### Scope

- `internal/output`: export `Dash` (renamed from `dashIf`) with a doc comment stating that the dash also appears in the JSON contract's `summary` field, so a change of the literal is a contract change; `text`, `tui`, and `cmd_active` use it and drop their copies.
- `internal/device`: export `AddrText`; `diagnose` uses it and drops its copy.
- `internal/active`: export `DirectedBroadcast` (the `(netip.Addr, bool)` form); `refuseIfConfigured` in `cmd_active` uses it in place of `broadcastOf`, inside the existing `p.Bits() < 31` guard, so behaviour is unchanged and the `As4()` call on a non-IPv4 prefix disappears.

Out of scope: `htons`/`readTimeout`, the receive buffers, `unanswered*` (Keep, CLOSED_DOORS); the U/L-bit test (Keep, CLOSED_DOORS); any change to the `/32` handling of `connect --address`.

##### Completion Criteria

- One body for each of the three helpers in the tree.
- Every golden unchanged; `connect --address 192.168.1.254` is still refused with the broadcast reason.

##### Dependencies And Decisions

- D3

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, owner decision D3
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Export the three helpers with their doc comments.
2. Replace the copies at the call sites.
3. Verify with T1 and T2.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | CLI | `go test ./cmd/wirepup -run TestActiveCommandArgumentChecks` (the `192.168.1.254` case exercises the broadcast refusal) | linux, go 1.24 | passes |
| T2 | suite | `make check` | linux, go 1.24 | all pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T2 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in 793421a (push pending); single-reviewer review accepted, no must-fix findings

#### M15 - Oper-state unknown sentinel named once

Origin: 182961f / M15
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`interfaces.operState` returns the unexported `operUnknown` (`unknown`) when sysfs is unreadable, and `text.go` and `tui.go` each compare `OperState` against their own `unknownValue`. One value crosses two package boundaries under three names. The VLAN and address `unknown` strings are different domains and stay local.

##### Scope

- `internal/interfaces`: export `OperStateUnknown` (rename of `operUnknown`); the interfaces test that requires a non-empty `OperState` is unchanged.
- `internal/output`: `OperStateUnknown = interfaces.OperStateUnknown`, mirrored the way `Change*` mirrors `device`, so that `text` and `tui` keep depending on `output` only.
- `internal/output/text`, `internal/tui`: compare against `output.OperStateUnknown`; drop `unknownValue` where it served only that comparison.

Out of scope: the VLAN `unknown` and `addrText` literals (Keep).

##### Completion Criteria

- One definition of the oper-state sentinel in the tree; the interfaces table renders exactly as before.

##### Dependencies And Decisions

- D4

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, owner decision D4
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Export and mirror the constant.
2. Replace the two comparisons.
3. Verify with T1 and T2.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | unit | `go test ./internal/interfaces ./internal/output/... ./internal/tui` | linux, go 1.24 | all pass |
| T2 | suite | `make check` | linux, go 1.24 | all pass, goldens unchanged |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T2 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in 793421a (push pending); single-reviewer review accepted, no must-fix findings

#### M16 - diagnose --epics reports the absence of EPICS traffic

Origin: 182961f / M16
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

`RunAll` in `EPICSOnly` mode builds a bare report and every EPICS rule returns early on an empty table, so `diagnose --epics` over a window without CA or PVA traffic emits a document with no finding and exit 0, while a plain `diagnose` always carries `local-context` and `epics find` states the absence for one PV.

##### Scope

- `internal/diagnose/rules.go`: in `EPICSOnly` mode, after the EPICS rules, append `Finding{Code: CodeEPICSNothingObserved, Text: "no CA or PVA search, server, or beacon was observed in this window; nothing can be said about EPICS from passive observation alone"}` when the table holds no CA search, CA server, PVA search, or PVA server.
- `docs/cli-design.md`: after the diagnose target sentence: "With `--epics` and no CA or PVA activity observed in the window, the report says so under Inferred and the exit code stays 0."
- New golden `epics-nothing-observed.diagnosis` from `diagnose --epics --pcap arp-autoip-selection.pcap --local 10.20.30.51/24`.

Out of scope: exit code 5 (target-bound); a plain `diagnose`; `nothing-seen` of find (PV-scoped, kept).

##### Completion Criteria

- The finding appears exactly when the four table counts are zero; never for a beacon-only capture; never twice in a two-source run.

##### Dependencies And Decisions

- D2

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-03, paired-debate synthesis (item 18)
Implementation Authorization: 2026-09-04, owner loop direction
Superseded Plan Artifacts: none

1. Add the guard and finding in `RunAll`.
2. Add the document sentence and the golden case.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | golden | `go test ./cmd/wirepup -run TestGolden` with the new case | linux, go 1.24 | one Inferred finding, `code` `epics-nothing-observed`, exit 0 |
| T2 | unit | `go test ./internal/diagnose -run 'TestCARules|TestPVARulesAndRestart|TestSourceDifference'` | linux, go 1.24 | no new finding where any EPICS record exists |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |
| T2 | 2026-09-04 | linux, go1.24.4 | Pass | make check exit 0; single-reviewer third-person pass accepted |

##### Closure Evidence

- committed in c6b8268 (push pending); single-reviewer review accepted, no must-fix findings

#### M17 - Aggregate unanswered-search findings carry no data keys

Origin: 182961f / M17
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Found while applying M2. `caRules` and `pvaRules` emit one Inferred finding summarising all unanswered searches ("N CA search(es) received no observed response"). It reused the per-search code, which the schema table lists with `pv`, `client`, `count`, yet the aggregate has none of those. Shape 1 (D5) separates it: the aggregate gets its own codes and carries only a `searches` count.

##### Scope

- `internal/diagnose/rules.go`: new codes `CodeCASearchesUnanswered`/`CodePVASearchesUnanswered`; the two aggregate emitters use them with data `searches`. Per-search codes and keys unchanged.
- `docs/output-schema.md`: one row for the new codes with key `searches`.
- Golden `two-sources.diagnosis` regenerated; `rules_test.go` asserts both the CA and PVA aggregate code and its `searches` data.

Out of scope: the per-search Observed findings (they carry `pv`, `client`, `count`).

##### Completion Criteria

- The aggregate emits a distinct code with data `searches`; per-search emitters unchanged; schema table matches; golden regenerated.

##### Dependencies And Decisions

- D4, D5

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-04, owner decision D5 (shape 1)
Implementation Authorization: 2026-09-04, owner direction
Superseded Plan Artifacts: none

1. Add the two codes; switch the aggregate emitters to them with data `searches`.
2. Add the schema row; regenerate the golden; extend the tests.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | golden | `go test ./cmd/wirepup -run TestGolden` | linux, go 1.24 | two-sources golden shows the aggregate code with `searches` |
| T2 | unit | `go test ./internal/diagnose -run 'TestCARules|TestPVARulesAndRestart'` | linux, go 1.24 | both aggregate codes emitted with non-empty `searches` |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-04T10:37Z | linux, go1.24.4 | Pass | golden diff limited to the aggregate line: `ca-search-no-response` to `ca-searches-no-response` plus `searches: "1"`; per-search `count: "3"` unchanged |
| T2 | 2026-09-04T10:37Z | linux, go1.24.4 | Pass | `make check` exit 0; CA and PVA aggregate assertions pass; single-reviewer third-person and second-person passes accepted, no must-fix |

##### Closure Evidence

- committed in f85b84f; info items (data key `count` to `searches`, PVA aggregate assertion) applied and reviewed

#### M18 - Direct execution and option reference

Origin: 182961f / M18
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Preserve explicit command execution for scripts and establish the option contract shared by guidance, completion, and documentation.

##### Scope

- Inventory all public commands, subcommands, and options from parser registrations and actual consumers, including accepted-but-unused options.
- Document each option's meaning, default, required or optional status, valid values, applicable commands, combinations, exclusions, privilege needs, and confirmation behavior.
- Define direct versus guided entry: explicit commands remain direct; bare terminal invocation enters guidance; non-terminal invocation must not wait for interactive answers.

Out of scope: implementing guidance or completion, new protocol behavior, or changing existing JSON and exit-code contracts.

##### Completion Criteria

- Every public option has an accurate reference checked against the implementation.
- Existing explicit commands preserve their output, exit status, and confirmation behavior; help does not enter guidance.
- Reference entries support the scenario links completed by M21.

##### Dependencies And Decisions

- D6. This contract supplies M19 and M20; they can proceed independently after it is complete.

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-05, proceed with the recorded M18 plan
Implementation Authorization: 2026-09-05, proceed with M18
Superseded Plan Artifacts: none

1. Inventory command registrations, option consumers, and existing CLI tests.
2. Write the detailed option reference and direct-versus-guided entry contract under docs/.
3. Add focused regression coverage for script invocations and any required dispatch changes.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | CLI integration | Run the built CLI on shipped PCAPs with explicit commands, JSON, invalid arguments, and redirected stdin; run existing golden tests. | Debian 13, Go minimum from go.mod | Existing output and exit status retained; no unexpected prompts. |
| T2 | Reference review | Compare every reference entry against registrations, defaults, command help, and actual option consumers. | Source and built CLI | Complete option coverage with accurate defaults and restrictions. |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-06T07:59:49Z | Debian 13.6, linux/amd64, Go 1.25.0 | Pass | Formatting, vet, and all 24 tested packages; real CLI and golden checks described below. |
| T2 | 2026-09-06 | Source and built CLI at `1e2d816` | Pass | Registered-option coverage and 46 local links checked; accepted reference unchanged. |

T1: `GOTOOLCHAIN=go1.25.0 make check TEST_FLAGS=-count=1` exited 0. `GOTOOLCHAIN=go1.25.0 go version` confirmed the exact minimum version from `go.mod`. `TestDirectInvocationNonTerminal` built the real CLI, exercised nine argument/confirmation cases with closed stdin, and compared three outputs to shipped goldens. Existing golden tests passed without changing their files. The earlier Go 1.26.7 run passed on 2026-09-05.

T2: `TestCLIReferenceCoversCommandHelp` passed against actual command help. The reference and execution-mode contract are unchanged from the review accepted on 2026-09-05; production CLI files are also unchanged since `b708e25`. All 45 local links in `docs/cli-reference.md` and the one local link in `docs/cli-design.md` resolve, including their Markdown heading anchors.

##### Closure Evidence

- Deliverables: [option reference](cli-reference.md), [execution-mode contract](cli-design.md#execution-modes), and [direct CLI regression tests](../cmd/wirepup/cli_reference_test.go).
- Local review accepted on 2026-09-05: no remaining must-fix or minor finding in the M18 scope. Production command behavior is unchanged; guidance and completion remain outside this milestone.
- Implementation commit: `b708e253cbe48dd481877642efd9351258712993`.
- Upstream observed at 2026-09-06T08:00:25Z: after `git fetch origin`, `origin/master` was `1e2d8167cf615e13d83a77008609fea356e1c7ef`. The implementation commit is an ancestor of that ref, and the three deliverables have no diff against the fetched upstream.
- Completed on 2026-09-06: T1 and T2 passed, deliverables landed upstream, and no external gate or linked issue remains.

#### M19 - Guided execution from observed results

Origin: 182961f / M19
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Let users start without knowing command names or a full option set. Ask for the purpose, obtain context, observe, interpret findings, and offer the next appropriate action.

##### Scope

- Enter guidance on bare wirepup in a terminal; preserve direct execution and prompt-free non-terminal behavior.
- Support device discovery, EPICS connection diagnosis, and capture-file analysis with contextual interface or file selection.
- Ask only for information that cannot be safely obtained locally; start with passive observation and explain uncertainty using existing findings.
- Show the equivalent explicit command with safely quoted values for later reuse.
- Explain and confirm exact transmissions or host changes before active actions; handle cancellation, EOF, interruption, and temporary-address cleanup.

Out of scope: LLM services, remote execution, new diagnosis rules, or autonomous active probing.

##### Completion Criteria

- Guided and direct execution use the same operation implementation and evidence model.
- Users can complete each primary workflow without first supplying every option.
- Cancellation and non-terminal use cannot hang or start a new transmission or address add. Previously authorized cleanup may remove only the guided session's own entry; confirmed actions remain bounded and reported.

##### Dependencies And Decisions

- D6 defines the assigned scope. M18 is a behavioral dependency: the guide must preserve its direct-command contract in `docs/cli-design.md` under Execution modes and `docs/cli-reference.md`.
- M20 is complete and supplies completion/install regression checks; it is not an additional dependency on starting M19.
- ADR-0007 and ADR-0010 continue to govern active operations and recorded address ownership. The cleanup policy below is accepted for guided sessions; it does not change direct `connect` or `disconnect` semantics.

##### Plan Review Baseline

Baseline: `da904fa52cdd15971c9ed0718f863ffe9883e7fa`. Existing operations and the recorded examples in `docs/usage-scenarios.md` are the implementation baseline; a second decoder, diagnosis engine, or shell-command execution layer is unnecessary.

- Confirmed plan gap: `cmd/wirepup/main.go` supplies output writers through `env`, while `confirm` in `cmd_active.go` reads `os.Stdin` through a new buffered reader. Guided prompts need one input owner and cancellation-aware reads, including the active confirmation.
- Confirmed by execution on 2026-09-07: a fresh build printed usage and exited 2 on bare terminal and non-terminal invocation. At the real `probe -i lo --arp 192.0.2.1/32` confirmation prompt, SIGINT and SIGTERM each left it waiting for at least one second; a subsequent `n` ended it with exit 1. Neither run received affirmative input or reached the sweep. These are baseline observations, not M19 verification results.
- Confirmed integration requirement: `discoverWith`, `runDiagnose`, and `runEPICSFind` currently render their results and return only an exit code. Guidance needs their structured results before rendering; it must not recover decisions by parsing text or JSON stdout.
- Confirmed by file replay on 2026-09-07: `WP:VALUE` in `tests/vm/pcap/epics-reads.pcap` produced both CA and PVA answers at exit 0; `NOPE:PV` in `testdata/pcap/ca-search-response.pcap` produced `nothing-seen` at exit 5; EPICS-only diagnosis of `arp-autoip-selection.pcap` produced `epics-nothing-observed` at exit 0.
- Unverified until implementation: prompt cancellation during an active operation, exact ownership after an interrupted address add, and cleanup failure handling. T3, T6, and T7 below must exercise these paths in the real implementation.

##### Accepted User Flow

Start with a numbered purpose menu and a visible quit choice. Read local interface names, link state, and prefixes with `interfaces.List`; show that context before asking the user to choose. Never silently select the first interface or enable a down interface. Offer a file source when live capture is unavailable. Each prompt explains its default and offers back/quit without making valid PV/file names impossible to enter; a filename is literal input, not shell syntax.

| Purpose | Input requested | First operation | Result and next choice |
| --- | --- | --- | --- |
| Find devices | Live interface or capture file | `discover` on live input; `read --devices` on file input | Show observed devices; choose an observed IPv4 address for diagnosis, repeat observation, change source, or finish. |
| Diagnose EPICS connectivity | Live interface or capture file; optional PV name | `epics diagnose` without a PV; passive `epics find` with a PV | Show search/answer evidence and limitations; inspect another PV, observe again, or explicitly request a bounded active search from live context. |
| Analyze a capture | One PCAP/PCAPNG path; view choice | `read`, `read --devices`, or `diagnose --pcap` | Offer events, devices, general diagnosis, or EPICS analysis of the same file; request original host prefixes only when subnet diagnosis is wanted. |

Interaction rules:

- Use finite live windows: 10 seconds for guided discovery/diagnosis and the existing 5-second passive PV-find window. Show the duration before starting; let the user change it to a positive duration. Direct-command defaults remain unchanged. Replay normally runs to EOF.
- Do not ask for every shared flag. Obtain local context automatically; ask for a PV, destination, original capture-host prefixes, or a different duration only when the selected operation needs them. Allow unknown original prefixes and explain that local-subnet conclusions need that context.
- Keep file analysis offline. Do not derive active destinations from a capture or substitute the current host's prefixes for the capture host. Moving from file analysis to a live action requires a new live-source choice and fresh context.
- Use existing finding codes and evidence to offer next actions. Missing observations offer another passive window/source; unanswered PV searches may offer an explicitly selected active search; a `temporary-secondary-address` recommendation may offer `connect`; duplicate claims offer inspection, not automatic repair. An empty inventory is not evidence that a network is empty.
- Print the exact equivalent direct invocation before each operation. Pass the same values to the shared Go operation without a shell. Quote every displayed argument for Bash, preserve literal spaces/quotes/dollar signs, and use an unambiguous path for dash-prefixed files. If a value cannot round-trip through the existing command grammar, explain that limitation and request a representable input; do not silently split it.
- After an operation, retain its result and exit status while offering further choices. Ordinary quit before any operation or after successful work returns 0; finishing after an unresolved operation error returns that error's existing status. Cancellation by EOF or signal returns 1 after cleanup, unless cleanup itself fails. No new public exit-code family is introduced.

##### Accepted Active And Cleanup Rules

The user must choose an active action and confirm the actual target list, protocol, packet budget, and host change. A menu choice alone is not confirmation. Empty input, EOF, an incomplete affirmative line, and cancellation never authorize action. Interactive answers are limited to 253 bytes before newline, including direct confirmations; reject longer input before dispatch, discard its queued tail even across EOF, and preserve terminal settings. This limit does not apply to explicit command-line arguments. Do not manufacture `--yes`, automatically invoke `sudo`, or retry an active operation. Keep the existing ARP and CA/PVA bounds and use their existing plan and execution reporting.

For a live PV search, show the resolved per-protocol destinations and explain that `-i` supplies capture/context but does not bind the UDP socket; OS routing still applies. A bounded ARP request requires an explicit address or prefix, never a range inferred from unrelated traffic. Privilege errors offer the safely quoted direct command and a return to passive/file work.

For a guided temporary connection, the accepted lifecycle is: the confirmation names the add and the later removal; the guide stays open while the address is useful, and removes only the exact entry successfully added by this guided session when the user finishes, sends EOF, or interrupts. Direct `connect` continues to leave its address until explicit `disconnect`. Existing WirePup entries and independently configured addresses are never cleanup candidates.

Track the successful `networkcfg.Entry` returned by the shared add operation, including identity and add time; do not infer ownership from a before/after address-list difference or call unfiltered `disconnect`. Revalidate ownership before removal and stop with an explicit recovery instruction if it changed. Cancellation before add must prevent the add; cancellation during/after add must reconcile the recorded outcome before exit. Use a separate bounded cleanup context so a cancelled observation context cannot skip cleanup; the deadline must reach the real iproute2 subprocess, not just stop waiting for it. If removal fails or the process is killed uncatchably, preserve the session record and print the exact selective recovery command when possible; do not claim restoration.

Before deleting a guide-owned primary, check the full live IPv4 address set. Another address in its subnet requires refusal at exit 1 with addresses, routes and the complete record retained, regardless of secondary-promotion settings. A guide-owned secondary remains removable while its manual primary survives. Do not change sysctls. The recovery instruction must state that direct `disconnect` lacks this guard and can trigger Linux secondary deletion; resolve the dependency before recovery.

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-07; the three guided workflows and guided-entry cleanup rule.
Implementation Authorization: 2026-09-07; proceed with this M19 plan, including implementation and verification. The same day's explicit direction to apply the re-review findings authorizes the complete-input and shared-subnet cleanup corrections and their verification.
Superseded Plan Artifacts: none

1. In `cmd/wirepup/main.go` and a new `cmd_guide.go`, route only bare invocation with terminal stdin and stdout into guidance. Explicit help/commands remain direct; redirected or closed input/output retains usage and exit 2. Give the guide one cancellation-aware input reader shared with its confirmations. Display guided questions on terminal stdout even when stderr is redirected; direct-command prompts keep their existing stderr destination. Verify dispatch and input lifetime with T1 and T3.
2. Factor the existing bodies in `cmd_discover.go`, `cmd_diagnose.go`, and `cmd_epics.go` only as needed to return structured outcomes, timestamps, statistics, and errors to both direct and guided callers. Preserve `runSource`, `wantPacket`, diagnosis rules, existing renderers, and exit mapping. Reuse `cmd_read.go` for event/device replay. T2 and T4 compare real outputs; do not add an independent inference path.
3. Implement the three purpose flows, contextual selections, finite windows, equivalent-command display, and finding-based next choices in `cmd_guide.go`. Keep unsupported or ambiguous values out of the invocation rather than silently changing them. Cover all three flows and empty/invalid/unknown-context cases in T2 and T3.
4. Reuse the active planning and execution bodies in `cmd_active.go` and `cmd_epics.go`. Provide the guide's input reader to the existing confirmation point; check cancellation immediately before each send/add and stop subsequent protocol searches after cancellation. Return the actual added entry to the guide. If needed, add a narrowly scoped ownership/cancellation check to `internal/networkcfg`; retain the session format and direct-operation behavior. Verify passive boundaries, bounded sends, and cleanup through T5-T7.
5. Add `cmd/wirepup/guide_test.go` and `tests/guidance.py` using the real executable and PTYs. Extend the isolated VM runner/catalog for guided scenarios; V17 must exercise terminal guidance rather than its current non-terminal usage check. Preserve that non-terminal check under T1. Keep full logs local and record each scenario's actual outcome; no future check is marked PASS from this plan.
6. Update the execution-mode paragraphs in `README.md`, `docs/cli-design.md`, and `docs/cli-reference.md`, plus the changed test procedures in `docs/testing.md` and `tests/vm/README.md`, only when their behavior exists. Record T results here. M21 owns the full scenario/option walkthrough work; M22 owns broader documentation cleanup. Before closure, perform second-person and third-person review of the implementation and its reader-facing text, including an independent review of active/input/cleanup changes.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | Entry integration | Extend `TestDirectInvocationNonTerminal`; run the built CLI with terminal/non-terminal stdin and stdout independently, redirected stderr, closed descriptors, explicit help, and invalid explicit arguments under a deadline. | Debian 13, real PTYs and pipes | Only bare invocation with both streams on terminals enters guidance; guided questions remain visible when stderr is redirected; all other invocation contracts remain unchanged. |
| T2 | Workflow integration | `tests/guidance.py` drives all three purpose flows over `testdata/pcap/` fixtures (`same-l2-different-subnet.pcap`, `ca-search-no-response.pcap`, `ca-duplicate-servers.pcap`, `arp-autoip-selection.pcap`) and `tests/vm/pcap/epics-reads.pcap`. Execute each displayed direct command and compare operation results/status. | Debian 13, fresh binary, PTY, no root | Same devices, finding codes, data, evidence and replay timestamps; active/host-context suggestions obey source context. Known, unanswered, absent and duplicate PVs remain distinct. |
| T3 | Input and cancellation | Exercise invalid selections, back/quit, literal special-character paths/PVs, partial lines, EOF, SIGINT and SIGTERM while selecting, reading input, observing, and confirming. Test cancellation before operation dispatch and between active protocol steps. | Real CLI/PTY; active stages in disposable VM | No hang, evaluated shell input, stale answer reuse, affirmative EOF, or new operation after cancellation. Prompt regression must fail on the baseline waiting behavior. |
| T4 | Direct regression | Run `make check`, then `make build` and `python3 tests/completion.py`; run `bash tests/install.bash` and `python3 tests/install-confirmation.py` against their temporary installed executables. | Debian 13, repository and temporary install prefix | Existing direct output, schema, help, completion and exit contracts pass; unrelated goldens stay unchanged. |
| T5 | Passive safety | Extend `tests/vm/scenarios.py` with PTY-driven live discovery/EPICS guidance and cancelled active selections. Capture the guide host's source MAC at the peer on the idle isolated bridge; compare addresses/routes before and after. | Dedicated Debian 13 VM, isolated namespaces, tcpdump/tshark | Zero WirePup transmissions for passive or pre-confirmation-cancelled flows; addresses/routes unchanged. Existing direct passive checks remain separate. |
| T6 | Active integration | Drive explicitly confirmed ARP and CA/PVA actions against real kernel/IOC peers; compare captured destinations, counts, protocols, replies and reported execution with the displayed plan. Include negative/default/EOF confirmation, privilege failure and interruption. | Dedicated VM and real peers; no internal mocks | Only the confirmed bounded action runs; absence remains qualified, pre-confirmation refusals send nothing, cancellation starts no later action. |
| T7 | Address lifecycle | Drive guided `connect`, conflict refusal, quit, EOF and interruption before/during/after add. Retain a separate recorded entry and an independently configured address as controls. Exercise removal failure and subsequent selective recovery; inspect real addresses, routes and session records. | Disposable VM; real ARP and iproute2; isolated session storage | Only the guided entry is cleaned up; other entries/addresses survive; failure retains recovery evidence and a nonzero outcome. Direct connect/disconnect behavior remains unchanged. |
| T8 | Reader and record check | Follow each changed usage/procedure passage against the installed CLI. Reconcile VM catalog/results and M19 verification rows with completed runs. | Repository documents, installed CLI, local run evidence | Current behavior is distinguished from planned work; all required scenarios have recorded outcomes and limitations; no guide claim rests on old V17 usage-only evidence. |

Use one freshly built executable per verification set and record its hash. Integration checks run the shipped operations and shipped captures end to end; filesystem/clock/transport boundary controls may induce failures, but decoder, diagnosis, confirmation, and network-configuration operations are not replaced. A skipped or unavailable privileged scenario remains Pending and prevents M19 closure.

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-07 | Debian 13 PTYs/pipes | PASS | `TestDirectInvocationNonTerminal` and `tests/guidance.py`: terminal stream matrix, closed descriptors, redirected stderr and explicit dispatch; no skip. |
| T2 | 2026-09-07 | Debian 13 PTY and shipped captures | PASS | All three flows; displayed commands executed in real Bash; outputs/status equal. `TestGuidedOperationRetainsDiagnosis` compares typed evidence/data/timestamp with emitted JSON. |
| T3 | 2026-09-07 | Debian 13 PTY and dedicated VM | PASS | Eight PTY groups on the corrected binary: overlong menu/file/PV refusal, exact 253-byte UTF-8 boundary, canonical editing and no readable rejected tail even after EOF. G02/G05/G07-G12/G18-G24 cover active cancellation and confirmation; G24 sends zero frames for malformed long approvals. |
| T4 | 2026-09-07 | Debian 13 repository/install prefix | PASS with dated scope | Fresh `make check TEST_FLAGS=-count=1` and build pass; eight real CLI PTY groups also pass under race instrumentation. Three completion tests, temporary-prefix install/check and eight replacement-confirmation tests passed on the earlier f4af7 binary and were not repeated after these corrections. |
| T5 | 2026-09-07 | Isolated VM namespaces | PASS | Fresh G01/G02/G23/G24 independently decode zero source-MAC frames and preserve addresses/routes. Management state is unchanged. V08 remains earlier full-run evidence. |
| T6 | 2026-09-07 | Isolated VM and real kernel/IOC peers | PASS | Fresh G03-G06/G20/G23/G24: confirmed ARP/CA/PVA plans match captured traffic; replies, privilege refusal, signal/EOF cancellation, fresh confirmation and malformed-approval refusal all pass. |
| T7 | 2026-09-07 | Isolated VM and real iproute2 | PASS | Fresh G07-G19/G21-G22 pass. G25/G26 refuse primary cleanup with promotion off/on and preserve addresses, routes, full session and sysctls; selective recovery succeeds after removing the test secondary. G27 removes a real guide-owned secondary at exit 0 while preserving its manual primary and all controls. No new reboot run. |
| T8 | 2026-09-07 16:36 PDT | Documents, installed CLI and actual run records | PASS | Both independent correction reviewers accepted the final implementation and second-person reader records. Their real EOF-tail checks pass; final G01-G27 hashes and owned-secondary raw state match the reported outcomes. Earlier reboot/install evidence remains explicitly historical. |

The [VM results](vm-test-results.md) identify the corrected executable (`52879872eac29d9069d8ff9347ea7e38e5ca798eeb1ebee2396e53c526fb8e68`) and its 27 PASS guided cases in `wirepup-m19-corrections-1ockrjfs`. Local checks passed eight PTY groups, common checks and eight race-instrumented CLI PTY groups; Darwin amd64 and Windows amd64 compiled. Earlier full-run V01-V17/reboot evidence uses f4af7 in `wirepup-scenarios-l5k25goz` and `wirepup-scenarios-nql_1x9z`; it is historical, not a corrected-binary rerun. Linux arm64, installation and completion remain earlier evidence. Full logs stay local. Runtime behavior outside Linux, physical hardware and exhaustive scheduling remain unverified.

##### Closure Evidence

- 2026-09-07: the owner authorized correction of the two re-review defects. Complete-input refusal and shared-subnet preservation are implemented and verified as recorded above. Both independent implementation and reader reviews accepted the corrections at 16:36 PDT; no in-scope finding remains. Execution scope and limits are recorded in [VM Scenario Results](vm-test-results.md).
- Implementation commit: `aeda686bffb1375b3b62d3d529f4ac5d72db3dc3`.
- Upstream observed at 2026-09-07T19:13:17-07:00: after `git fetch origin`, HEAD and `origin/master` both equal the implementation commit. All 32 committed paths match the accepted review hashes; no incoming or outgoing commit or uncommitted change remained.
- Completed on 2026-09-07: T1-T8 and independent implementation, reader, and delivery-record reviews are accepted; the implementation landed upstream. No external gate or linked issue remains. Verification limits above remain unchanged.

#### M20 - Bash completion and installation

Origin: 182961f / M20
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Complete commands, options, finite values, interfaces, and capture paths in Bash and install completion alongside the executable.

##### Scope

- Respect subcommand context, argument position, options consuming values, and file paths containing spaces.
- Discover local interfaces without privileges; do not issue active PV searches or other network operations during completion.
- Extend make install, install.dry-run, and install.check for completion using INSTALL_LOCATION and conventional Bash completion discovery.
- Document activation, optional bash-completion requirements, custom prefixes, and reload behavior in existing shells.

Out of scope: Zsh or Fish support, active queries, or automatic shell startup-file edits.

##### Completion Criteria

- Candidates match M18 and omit invalid options or values for the current context.
- Completion works through the installed artifact and handles missing optional shell integration clearly.
- Preview is read-only; install and check cover both binary and completion at the selected prefix.

##### Dependencies And Decisions

- D6, M18: completion consumes the same public command and option contract as guidance.

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-06 - command, option, value, interface, and file completion with installation verification.
Implementation Authorization: 2026-09-06 - proceed with M20 using the epics-ioc-runner completion and installation example.
Superseded Plan Artifacts: none

1. Add `completions/wirepup.bash`: obtain commands and option arity from the real CLI help; complete finite values, local interfaces, and file paths without active queries. Keep shell input as data.
2. Extend `tools/install-wirepup.bash`, its protected-copy helper, and `configure/RULES_INSTALL` to install mode-0644 completion under `INSTALL_LOCATION/share/bash-completion/completions/wirepup`. Check both destinations and obtain replacement consent before copying either artifact; validate completion only as the invoking user.
3. Exercise the shipped function in Bash, including value positions, quoting, comma lists, and installed files. Extend the real installation tests for both artifacts and retain existing consent/noexec protection.
4. Document automatic discovery, explicit activation in existing shells, optional bash-completion integration, and custom prefixes. Do not edit shell startup files.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | Bash integration | Run `make check` including `TestBashCompletion`; after `make build`, run `python3 tests/completion.py` for real Readline Tab input. | Debian 13, Bash, temporary filesystem | Correct candidates, quoting, and autoload; Readline never executes the edited command. Separately, completed dash-prefixed paths replay the shipped PCAP in the CLI tests. |
| T2 | Install integration | Run `bash tests/install.bash` and `python3 tests/install-confirmation.py`; in an isolated VM run `bash tests/install.bash --system` with the payload in `docs/testing.md`. | Debian 13 host and isolated Debian 13 VM; custom INSTALL_LOCATION | Preview changes nothing; installed completion works; consent, path conflicts, registration failure, privilege separation, concurrent destinations, and noexec checks preserve existing files. |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-06 PDT | Debian 13, Bash 5.2.37 | Pass | `make check TEST_FLAGS=-count=1` passed. Completed dash-prefixed paths decoded both events from `ca-beacon.pcap`. Real Readline tests passed all 3 groups locally and through installed artifacts, including quoted assignments, colon/equals paths, safe `./` prefixes, and framework autoload. `bash -n` and ShellCheck passed. |
| T2 | 2026-09-06 PDT | Temporary user prefix and isolated Debian 13 VM root-owned prefix | Pass | Local Make install/check and 8 consent/error tests passed, including undefined registered functions and inherited-function isolation. VM system tests passed protected copies, root-driver refusal, both destination races, noexec preservation and noexec TMPDIR installation. The final test prefix was removed and the existing VM system binary SHA-256 was unchanged. |

##### Closure Evidence

- 2026-09-06: independent review accepted completion behavior, installation privilege boundaries and failure preservation, and reader-facing instructions after the reported defects were corrected and rechecked.
- 2026-09-06: accepted follow-up corrections use `./` for dash-prefixed positional paths and require the registered completion function to be defined by the loaded file. Regression tests and local/VM installation checks passed.
- Implementation commit: `0259eb352c226b90f7307d14b8d414ca1cd6f8d6`.
- Upstream observed at 2026-09-07T07:36:14Z: after `git fetch origin`, `origin/master` was `0259eb352c226b90f7307d14b8d414ca1cd6f8d6`. The implementation commit is an ancestor of that ref, and all 11 paths in the commit have no diff against the fetched upstream.
- Completed on 2026-09-07: T1 and T2 passed, implementation and reader-facing corrections landed upstream, and no external gate or linked issue remains.

#### M21 - Executable scenarios and bidirectional option links

Origin: 182961f / M21
Identity History: none
GitHub Issue: none
Status: Complete

##### Summary

Provide reproducible tasks with direct and guided entry. Each scenario explains its options, and each option links back to relevant scenarios.

##### Scope

- Cover unknown-device discovery, same-layer-2 different-subnet diagnosis, CA/PVA connection problems, capture and replay, temporary address setup and removal, and TUI use.
- Include prerequisites, minimum command, required options, optional refinements with defaults and reasons, combinations, expected output, interpretation, next actions, and cleanup.
- Link scenarios to option entries and options to scenarios, including help/version and automation-oriented usage.
- Show guided choices, equivalent direct commands, and completion examples.
- Use shipped PCAPs for offline reproduction; distinguish illustrative output from observed output and state live hardware and privilege requirements.

Out of scope: new diagnosis behavior or claiming live validation from an offline substitute.

##### Completion Criteria

- Each scenario has an executable direct path and explains its relevant guided path.
- Every public option has a meaningful scenario link; every scenario option resolves to its reference.
- Outputs and next actions are checked on real execution paths; required live cases have lab evidence before completion.

##### Dependencies And Decisions

- D6, M18, M19, M20: final walkthroughs must match the implemented options, guidance, and completion.

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-07 - complete the existing direct scenarios with the implemented guided paths, Bash completion examples, and links in both directions for every public option.
Implementation Authorization: 2026-09-07 - proceed with M19 completion recording and M21 scenario/option documentation and real-path verification.
Superseded Plan Artifacts: none

1. Update `docs/usage-scenarios.md` around concrete tasks. Give minimum direct commands, the relevant guide choices, expected results, next actions, cleanup, and optional refinements. Identify operations available only as direct commands instead of inventing guide controls.
2. Complete `docs/cli-reference.md` links for all public options, aliases, help, and version. Link each scenario's options to its reference and each option to a scenario that actually uses it. Preserve option defaults and restrictions.
3. Execute the documented offline commands against shipped PCAPs, all three guided entries through real PTYs, and completion through real Bash. Follow the live discovery/capture/TUI/temporary-address paths in the isolated existing VM lab and compare addresses/routes after cleanup.
4. Record dated outcomes and limits here and in `docs/vm-test-results.md`; document the repeatable checks in `docs/testing.md`. Run independent second- and third-person review before requesting Git landing.

Plan review: before this change, `docs/usage-scenarios.md` excluded guidance and said bare invocation exited 2, contradicting the implemented terminal guide in `cmd/wirepup/cmd_guide.go`. Several option links in `docs/cli-reference.md` led only to the design document, not executable scenarios. M19/M20 are implemented and landed; no feature dependency remains. This work changes documentation and its verification, not CLI behavior.

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | Offline walkthrough | Execute each offline command and guided equivalent on its named shipped PCAP; compare output and exit status with the document. | Debian 13, shipped fixtures | Reproducible cases with no omitted required options. |
| T2 | Documentation coverage | Check both directions of option/scenario links against M18, including defaults, combinations, and restrictions. | Markdown and built CLI | No orphan option, broken link, or unsupported example. |
| T3 | Live walkthrough | Follow discovery, capture, TUI, and temporary-address procedures on the real CLI and execute cleanup. | Disposable Linux namespace lab and PTY | Instructions match actual behavior and restore initial lab state. |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-07 | Debian 13 source checkout; executable `311286be5e82` | PASS | 14 documented noninteractive commands exited 0; 10 file-based guide paths matched stdout/status from their printed command executed in real Bash. Shipped PCAPs covered LLDP, subnet context, DHCP, CA/PVA, duplicates and missing replies. Two offline TUI examples and the five-second timeout ran through actual PTYs. See [dated results](vm-test-results.md#usage-walkthrough-verification). |
| T2 | 2026-09-07 | Markdown, built CLI and real Bash Readline | PASS | All 21 option entries have links in both directions; 140 relative links in the two guides resolve. Leaf help coverage and fresh `make check TEST_FLAGS=-count=1` pass. Three completion tests, all six usage-table examples and eight guidance test groups pass. |
| T3 | 2026-09-07 19:38-19:39 PDT | Dedicated Debian 13 VM; real namespaces, kernel/IOC peers and PTYs | PASS | 13 focused checks including isolation, discovery, ARP capture/replay, PCAPNG snap length/no-promisc, confirmed direct/guided ARP and CA/PVA search, active missing-PV exit 5, temporary connections, TUI keys and interruption. Complete client addresses/routes/other record were preserved; actors/namespaces were removed and original session/management state restored. DHCP acquisition, duplicate IOC setup and reboot retain earlier evidence. |

The executable verified for M21 was built from `aeda686bffb1375b3b62d3d529f4ac5d72db3dc3`; its full hash and verification limits are in [VM Scenario Results](vm-test-results.md#usage-walkthrough-verification). Local command output, PTY transcripts, VM orchestration and raw results remain under `work/` or in the dedicated guest. The public [walkthrough procedure](testing.md#13-usage-walkthrough-verification) describes repetition without depending on a private results path.

##### Closure Evidence

- 2026-09-07: independent second-person and third-person review accepted all five documentation files and their recorded evidence. The capture-view navigation and text/JSON finding explanations were corrected; no in-scope finding remains.
- 2026-09-08: the five reviewed documentation files landed in commit `f886426a1fee9bad436d6177f1c87bb3607d7d5d`. After `git fetch origin`, observed at `2026-09-08T00:37:03-07:00`, both `master` and `origin/master` resolved to that commit; comparing the five committed paths against the fetched upstream returned no difference. Implementation, T1-T3 and reader review are accepted. M21 is Complete.

#### M22 - Usage-first documentation navigation and cleanup

Origin: 182961f / M22
Identity History: none
GitHub Issue: none
Status: In progress

##### Summary

Make maintained usage instructions easy to find while preserving the safety, schema, and design material required to maintain WirePup.

##### Scope

- Inventory README, docs/, and linked development prompts as current usage, maintained engineering references, or superseded initial plans.
- Structure README and a docs index around installation, first use, direct/guided operation, completion, scenarios, and the option reference.
- Compare each initial plan with current implementation and M21 before retirement; relocate unique current requirements to maintained documents.
- Retain safety rules, output contracts, relevant ADRs, the current milestone document, and CLOSED_DOORS; preserve committed historical evidence and update inbound links.

Out of scope: deletion based only on age, Git history rewriting, or resetting the current milestone generation.

##### Completion Criteria

- Readers reach current executable instructions without first learning development history.
- Every retired plan has a documented replacement or committed historical reference, with no loss of current requirements.
- Local links resolve and engineering references remain accessible separately from user workflows.

##### Dependencies And Decisions

- D6, M21: verified user instructions must exist before older usage material is retired.

##### Implementation Plan

Plan Status: accepted
Plan Acceptance: 2026-09-08 - organize README and documentation around installation, first use and verified scenarios; replace initial implementation instructions with maintained references and committed history.
Implementation Authorization: 2026-09-08 - proceed with M21 completion recording and M22 documentation navigation and cleanup.
Superseded Plan Artifacts: none

1. Compare the bundled project plan, bootstrap guide, original roadmap, initial agent workflow and prompts against maintained requirements, ADRs, tests and M21. Record replacements and the pre-cleanup commit in this detail.
2. Shorten `README.md` to installation, first guided/offline use, direct commands and task links. Create `docs/README.md` as the user/engineering index and `docs/installation.md` for the existing installation, replacement, PATH and completion instructions. Preserve the installation safeguards and recovery links.
3. Move maintained build and contribution instructions into `CONTRIBUTING.md`; update `CLAUDE.md` and usage links. Remove only the six superseded initial-development files listed below. Keep reusable review prompts, the test-environment design, all safety/schema/engineering references, ADRs and CLOSED_DOORS.
4. Verify local links and historical replacement coverage. Follow the real build/install/check path into a temporary user-owned prefix, then use that installed CLI for help, offline direct/guided operation and Bash completion. Review the final text from operator and maintainer perspectives; record actual results and limits without claiming a new full VM or hardware run.

Plan review at `f886426`: the 1,994-line bundle reproduced ten source documents. Its requirements and protocol scope exactly matched the standalone files; the maintained architecture, CLI, safety and testing documents added the implemented behavior. README included illustrative pre-implementation output and an M0 starting sequence. The initial prompts and `CLAUDE.md` directed a new checkout to first-implementation work. M21 supplied the executable replacement scenarios; its Git landing is verified above.

##### Documentation inventory

Disposition date: 2026-09-08. Historical links below name the immutable pre-cleanup commit `f886426a1fee9bad436d6177f1c87bb3607d7d5d`; they preserve the removed files without a second current copy. No Git history is rewritten. Future candidates in the original roadmap remain historical proposals, not current implementation claims or newly assigned work.

| Document or group | Disposition | Current purpose or replacement |
| --- | --- | --- |
| [README](../README.md) | Rewrite | Installation, first live/offline use, direct task routes and completion; replace illustrative early output with M21 walkthrough links. |
| [Documentation index](README.md) | Add | User routes first, test procedures and engineering references separately. |
| [Installation](installation.md) | Extract | Preserve prerequisites, user/system/custom prefixes, replacement consent, PATH, completion activation and protected-copy safeguards from README. |
| [Contributing](../CONTRIBUTING.md), [Claude entry point](../CLAUDE.md) | Update | Move build configuration, reference selection, protocol increments and collaboration guidance into current contributor instructions. Point to the canonical work entry. |
| [Usage scenarios](usage-scenarios.md), [CLI reference](cli-reference.md) | Maintain | M21 owns executable tasks and option links. Redirect installation links to the extracted guide. |
| [Requirements](requirements.md), [architecture](architecture.md), [protocol scope](protocol-scope.md), [CLI design](cli-design.md), [safety](safety.md), [output schema](output-schema.md) | Retain | Current requirements, design and public contracts; no semantic change in this cleanup. |
| [ADRs](adr/), [technical references](references.md) | Retain | Design decisions and protocol sources remain available to maintainers. |
| [Testing](testing.md), [VM results](vm-test-results.md), [VM procedure](../tests/vm/README.md) | Retain | Existing repeatable methods and dated results; no result is promoted to broader coverage. |
| [Test environment plan](test-environment-plan.md) | Retain as planned coverage | Unique reporting, OS-matrix and release-gate design beyond the implemented VM suite; the index labels its planned status. |
| This milestone document, [Closed Doors](CLOSED_DOORS.md), [AGENTS](../AGENTS.md), [license](../LICENSE) | Retain | Work/evidence authority, no-change decisions, contributor constraints and license remain current. |
| [Cross-review](../prompts/cross-review.md), [full-repository review](../prompts/full-repository-review.md) | Retain | Reusable checks, reachable from Contributing; not first-implementation instructions. |
| [Historical project bundle](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/WIREPUP_PROJECT_PLAN.md) | Remove duplicate | Ten embedded source documents; maintained requirements/protocol scope are identical, other current source documents carry subsequent decisions and behavior. Replaced by the documentation index and the rows below. |
| [Historical bootstrap](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/BOOTSTRAP.md) | Retire | Repository creation and first M0 are superseded by Installation and the current milestone. Passive/evidence checks and capture privacy remain in Testing, Safety and AGENTS. |
| [Historical roadmap](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/docs/roadmap.md) | Retire | Original M0-M10 sequencing is historical; current work is tracked here. Feature requirements, protocol scope and executable coverage remain in their maintained documents. |
| [Historical agent workflow](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/docs/ai-workflow.md) | Retire | Initial role/stage sequence is historical. Reference rule, protocol increments, handoff information and ADR-change discipline move to Contributing; reusable review checklists remain. |
| [Historical architecture prompt](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/prompts/claude-architecture-review.md) | Retire | Initial M0 design proposal is superseded by the accepted ADRs and current plan. Architecture, safety and validation checks remain in the reusable review prompts. |
| [Historical M0 prompt](https://github.com/jeonghanlee/wirepup/blob/f886426a1fee9bad436d6177f1c87bb3607d7d5d/prompts/codex-m0-bootstrap.md) | Retire | Bootstrap-only scope is superseded by implemented commands and current milestones. Decoder isolation, passive behavior, testability and dependency licensing remain in AGENTS and Contributing. |

##### Test Plan

| Label | Layer | Method | Environment | Expected Result |
| --- | --- | --- | --- | --- |
| T1 | Documentation integrity | Check local links and compare each removed document with its replacement and committed history. | Repository Markdown and Git history | No dangling links or lost current safety, schema, or implementation requirements. |
| T2 | Reader walkthrough | Follow README through installation, first guided run, direct execution, completion setup, and option reference. | Debian 13, installed CLI | Accurate complete usage route without initial-development documents. |

##### Verification Results

| Label | Observed At | Environment | Result | Evidence |
| --- | --- | --- | --- | --- |
| T1 | 2026-09-08 | Repository Markdown and Git history at `f886426` | PASS | Parsed 36 Markdown files: all 297 relative links resolve. Each of the six retired files has an immutable historical link and a maintained replacement in the inventory. Compared all ten embedded source documents; 29 retained engineering, safety, schema, test, license and instruction files are byte-identical to the baseline. Changed Markdown is ASCII, uses fenced examples and passes `git diff --check`. Rendered README and the documentation index for layout inspection. |
| T2 | 2026-09-08 | Debian 13.6, Go 1.26.7, Bash, actual installed CLI in a temporary user prefix | PASS | Real Make build/install/check and `tests/install.bash` passed, including a prefix with spaces, PATH shadowing and symlink refusal. Replacement consent passed all 8 `tests/install-confirmation.py` cases. The installed CLI passed all 8 `tests/guidance.py` and 3 `tests/completion.py` cases; README's shipped CA capture replay, help, version and interfaces ran successfully. `make check TEST_FLAGS=-count=1` passed without changes to shipped fixtures or goldens. |

The M22 walkthrough executable reports `f886426-dirty` (documentation-only changes), with SHA-256 `af61d9a9ef11e028bd65e786d9be6a28f902b9425cc4b61a7deea275d9ea17a8`. Raw logs, rendered previews and the temporary installation remain local under `work/`. No new APT installation, protected system-prefix installation, VM network run or physical hardware validation was performed; the retained testing procedures and dated results define those separate checks.

##### Closure Evidence

- 2026-09-08: README, the documentation index and installation guide provide current user entry points. CONTRIBUTING and the Claude entry point preserve maintained development instructions. Six superseded files were removed only after comparison and historical-reference checks; the inventory records every replacement. M22 implementation and T1-T2 are recorded in the working tree. Self-review covers reader routes (C1), retained requirements and history (C2), and command/evidence consistency (C3). Git landing and its completion record remain pending; M22 stays In progress.

## Backlog

### Work

| Group | ID | Work unit | Type | Status | Ready | Deps | Done when / Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |

### Backlog Details

No Backlog rows at present.
