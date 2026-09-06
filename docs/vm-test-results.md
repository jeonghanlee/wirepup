# VM Scenario Results

## Scope

**2026-09-05: 16 passed; 1 not implemented.** The initial run and the full
rerun used a dedicated Debian 13 VM and included an actual guest reboot.
These are recorded results, not a fresh test whenever this page is opened.
Use the [procedure](../tests/vm/README.md) to repeat them and the
[usage scenarios](usage-scenarios.md) to apply the results.

**Out of scope:** production networks, physical hardware and the complete
release matrix. Detailed logs and intermediate failure records remain local.

## Scenario matrix

| ID | Scenario | Result | What was confirmed |
| --- | --- | --- | --- |
| V01 | Installed binary | PASS | Version and SHA-256 on the dedicated VM |
| V02 | Network isolation | PASS | Five namespaces; no endpoint default route |
| V03 | Live ARP capture/replay | PASS | 2 real ARP frames; peer `192.0.2.2` identified |
| V04 | ARP search | PASS | Real peer answered |
| V05 | Address add/remove | PASS | Added address removed; original and manual addresses retained |
| V06 | Occupied address | PASS | Exit 6; no address added |
| V07 | Automatic recommendation | PASS | `10.44.0.254` selected, added, then removed |
| V08 | Passive transmission count | PASS | Six commands; zero source-MAC frames on an idle segment |
| V09 | DHCP lease | PASS | ACK and client address `192.0.2.107/24` |
| V10 | DHCP failure/Auto-IP | PASS | No-offer diagnosis and `169.254.10.136/16` |
| V11 | Real CA/PVA reads | PASS | Both clients read 42; both search answers identified |
| V12 | Active CA/PVA search | PASS | Actual IOC answered both protocols |
| V13 | Duplicate IOC servers | PASS | Two servers detected by both protocols |
| V14 | Missing PV reply | PASS | Unanswered CA search; active find exited 5 |
| V15 | Interruption | PASS | Empty PCAP reopened; interrupted probes added no address |
| V16 | Actual VM reboot | PASS | Temporary namespaces and session record gone |
| V17 | Guided entry | NOT_IMPLEMENTED | Bare CLI prints usage and exits 2 |

**Guided entry** means selecting an interface and task interactively, then
receiving next-step suggestions from observations. That feature is M19;
its absence is not a passing implementation test.

## Source and build checks

The full rerun used Go 1.26.7 on Linux amd64.

| Check | Recorded result |
| --- | --- |
| Formatting, vet, unit and golden tests | PASS: 24 tested packages |
| Race detector | PASS |
| Fuzz smoke | PASS: 12 targets, 5 seconds each, 2 workers |
| Fixture regeneration | PASS: 41 capture/golden files unchanged |
| Native build and installation | PASS: static binary, separate install directory and PATH check |
| Cross-builds | PASS: Linux arm64, Darwin amd64 and Windows amd64; compilation only |

## Verification limits

- V08 covers six passive commands on an idle isolated segment, not all host traffic.
- V15 covers one interruption point, not every interruption or buffered-write outcome.
- TUI keys, confirmation prompts, Bash completion, Rocky Linux and physical
  switches/cables were not tested. Active automation used `--yes`.
- LLDP, VLAN and IPv6/NDP have source/fixture coverage only in these runs.
- Exact Go 1.25 was not exercised. Cross-builds do not prove runtime compatibility;
  bounded fuzzing does not exhaust the input space.

Management IPv4 addresses and routes were unchanged. These results do not
complete the remaining guidance, completion or documentation milestones.

## Retained regression captures

Eight original PCAPs from the initial run are kept under
[`tests/vm/pcap`](../tests/vm/pcap). They contain controlled Linux, DHCP and
EPICS test traffic, with no production or VM management traffic. Their bytes
are unchanged from the captured files. The [manifest](../tests/vm/pcap/manifest.json)
records each checksum, the tested binary hash and the source commits.

| Capture | Regression assertion |
| --- | --- |
| `epics-reads.pcap` | CA and PVA answers after real clients read 42 |
| `active-ca.pcap` | CA answer to an active search |
| `active-pva.pcap` | PVA answer to an active search |
| `duplicate-ca.pcap` | Multiple CA servers for one PV |
| `duplicate-pva.pcap` | Multiple PVA servers for one PV |
| `missing-pv.pcap` | Unanswered CA search |
| `dhcp-no-offer.pcap` | DHCP no-offer diagnosis |
| `dhcp-success.pcap` | Real DHCP ACK |

`TestRecordedVMCaptures` reads these files through the real CLI during
`make check`, without root or a VM. Full archives, command output, actor logs
and intermediate failures are not included in the public repository.

## Reproduce an example

From the repository root, after `make build`:

```bash
bin/wirepup epics find WP:VALUE --pcap tests/vm/pcap/epics-reads.pcap
bin/wirepup epics find WP:VALUE --pcap tests/vm/pcap/duplicate-pva.pcap
bin/wirepup diagnose --pcap tests/vm/pcap/dhcp-no-offer.pcap --local 192.0.2.1/24
```

Check for server answers, multiple PVA servers and `dhcp-discover-no-offer`,
respectively. Offline replay does not replace live transmission, address
changes or reboot testing.
