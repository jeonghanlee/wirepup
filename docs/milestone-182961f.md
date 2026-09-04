# Work Register

Release line: master
Milestone index: 182961f
Canonical path: `docs/milestone-182961f.md`
Canonical branch or ref: master
Git upstream: origin/master
Remote tracker: none

Next session entry point: `docs/milestone-182961f.md`: M1-M17 are committed and verified. No open milestone remains.

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

### Decisions

| ID | Decision | Decision Date |
| --- | --- | --- |
| D1 | Apply the fates of M1-M10 and the 2026-09-03 Keep rows of `docs/CLOSED_DOORS.md` as converged in the paired review debate of that date (chat only, no artifact); the oper-state sentinel (M15) and `decode.SetPorts` (M11) stay undecided | 2026-09-03 |
| D2 | M16 fate converged in the same debate: an Inferred `epics-nothing-observed` finding under `--epics`, exit code unchanged; implementation not yet authorized | 2026-09-03 |
| D3 | Re-examination of the Keep rows of `docs/CLOSED_DOORS.md` (paired review debate, chat only): `dashIf`, `addrText`, `broadcastOf` become M14; the two snap-length defaults become M12; the EtherType, opcode, hardware and protocol constants of bpf and active become M13, with `arp` exporting its address-length constants; the U/L-bit test, the frame offsets, and `bpf.AcceptLength` stay Keep; the fixtures row keeps its verdict with a corrected premise; implementation of M12-M14 not yet authorized | 2026-09-03 |
| D4 | M15, M11, and M17 move from Backlog to Milestone: M15 names the oper-state sentinel once (`interfaces.OperStateUnknown`, mirrored by `output`); M11 keeps `decode.SetPorts` and records it as the seam for offset EPICS ports; M17 is to be done, its shape still to be picked; implementation not yet authorized | 2026-09-03 |
| D5 | M17 shape: separate aggregate codes `ca-searches-no-response`/`pva-searches-no-response`, per-search codes unchanged. The aggregate data key is `searches` (number of unanswered searches), distinct from the per-search `count`, so the two never collide under one key | 2026-09-04 |

### Assignment History

| Work Identity | From Canonical | To Canonical | Target Commit | Authority Moved At |
| --- | --- | --- | --- | --- |
| M15 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |
| M11 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |
| M17 | master, `docs/milestone-182961f.md`, Backlog | master, `docs/milestone-182961f.md`, Milestone | this synchronization commit | this synchronization commit |

### Milestone Details

Each Summary states the defect as found at commit 182961f; the current state is in Implementation Plan and Verification Results.

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

## Backlog

### Work

| Group | ID | Work unit | Type | Status | Ready | Deps | Done when / Evidence |
| --- | --- | --- | --- | --- | --- | --- | --- |

### Backlog Details

No Backlog rows at present.
