# VM Scenario Results

## Scope

**2026-09-07: all 27 guided checks passed on the corrected executable.**
This focused run used the dedicated Debian 13 VM. An earlier full run passed
17 scenario rows, including 23 guided checks and an actual guest reboot;
that broader run used the earlier executable identified below.
These are recorded results, not a fresh test whenever this page is opened.
Use the [procedure](../tests/vm/README.md) to repeat them and the
[usage scenarios](usage-scenarios.md) to apply the results.

**Out of scope:** production networks, physical hardware and the complete
release matrix. Detailed logs and intermediate failure records remain local.

## Scenario matrix

V01-V16 retain the earlier full-run results. V17 reports the fresh focused
G01-G27 run; the broader suite and reboot were not repeated after the corrections.

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
| V17 | Guided workflows, input limits and cleanup | PASS | 27 real terminal, packet, address, cancellation and recovery checks on the corrected executable |

The corrected executable has SHA-256
`52879872eac29d9069d8ff9347ea7e38e5ca798eeb1ebee2396e53c526fb8e68`.
The same file ran the local PTY suite and G01-G27 in the VM. Guest evidence is
under `/var/tmp/wirepup-m19-corrections-1ockrjfs`, including
`guidance-results.json` and `owned-secondary-results.json`.

The earlier full-run executable had SHA-256
`f4af7be91e1c9da57da6a2406e16aca40d1a7098cf19e0f13067080ef4400a86`.
Both were built from the M19 working tree based on `da904fa`. The earlier file
was used for the original VM installation and reboot recovery. Its evidence
directories are `wirepup-scenarios-l5k25goz` (main) and
`wirepup-scenarios-nql_1x9z` (reboot), under the guest's `/var/tmp`.

## Guided checks

These checks drive the installed program through a real PTY. tcpdump captures
are decoded by tshark with a required successful exit before final assertions.
Addresses, all client routing tables and session records are inspected through
the real kernel and filesystem. Other recorded and manually configured addresses
serve as preservation controls.

| Checks | Result | What was confirmed |
| --- | --- | --- |
| G01, G02, G23 | PASS | Passive flows, six confirmation refusals and queued-input cases send zero source-MAC frames; addresses/routes unchanged |
| G03 | PASS | One confirmed ARP request to `192.0.2.2`; real peer reply |
| G04, G05, G20 | PASS | One CA and one PVA search to the confirmed broadcast destination; signal or EOF after CA prevents PVA |
| G06 | PASS | Unprivileged live/ARP operations report exit 3; no automatic sudo |
| G07-G10 | PASS | Finish, EOF, SIGINT and SIGTERM remove only the guide's successfully added address |
| G11-G13, G21 | PASS | Cancellation before/during probes and address conflict prevent the add; EOF after a captured probe stops the operation |
| G14-G17, G22 | PASS | Changed record/label, failed exec, held lock and stalled real cleanup child retain recovery evidence; selective recovery restores controls |
| G18, G19 | PASS | Interruption before/after the kernel add keeps an uncertain attempt recorded; no ownership inferred from address appearance |
| G24 | PASS | Malformed long approvals through guided and direct PTYs return 1 and send zero source-MAC frames; terminal/configuration unchanged |
| G25, G26 | PASS | Guide-owned primary with a manual secondary: refuse cleanup at exit 1 with promotion off/on; all addresses, routes, complete record and sysctls preserved; selective recovery succeeds after removing the test secondary |
| G27 | PASS | Guide-owned address verified as secondary by real kernel flags; exit 0 removes it while the manual primary, routes, other entries and sysctls remain unchanged |

The cleanup-child check delays the actual iproute2 syscall. The guide's separate
five-second deadline kills that child, reports failure and exits within eight
seconds including tracing overhead. It does not claim that cleanup succeeded.

## Source and build checks

The M19 checks used Go 1.26.7 on Debian 13 amd64. The normal binary is static;
the separately built race binary instruments the real guided CLI.

| Check | Recorded result |
| --- | --- |
| Formatting, vet, unit and golden tests | Fresh PASS: `make check TEST_FLAGS=-count=1` |
| Guided local PTYs | Fresh PASS: eight groups; displayed commands executed by Bash; 253-byte UTF-8/editing boundary and rejected-input tail after EOF checked |
| Race detector | Fresh PASS: separately instrumented real CLI through eight PTY groups; package race-suite evidence is from the earlier run |
| Completion and installation | Earlier PASS on f4af7: 3 completion tests, temporary-prefix install/check, 8 replacement-confirmation tests; not repeated after the corrections |
| Cross-builds | Fresh PASS: Darwin amd64 and Windows amd64; Linux arm64 is earlier evidence; compilation only |

Existing goldens and retained PCAPs have no diff. The earlier 2026-09-05 run
also passed 12 fuzz targets (five seconds each, two workers) and regenerated
41 capture/golden files without changes. Those two checks were not rerun for M19.

## Verification limits

- V08 covers six passive commands on an idle isolated segment, not all host traffic.
- V15 and V17 cover the named interruption points, not every possible schedule
  or buffered-write outcome. SIGKILL cannot execute guided cleanup.
- TUI keys, Rocky Linux and physical switches/cables were not tested in this run.
  Guided active cases use actual confirmations; older direct cases use `--yes`.
- Darwin and Windows have compilation evidence only. Interactive behavior was
  executed on Linux; the guide supports terminal input on Linux and macOS.
- The session lock coordinates WirePup processes. It cannot serialize an
  unrelated privileged process changing the interface between inspection and deletion.
- LLDP, VLAN and IPv6/NDP have source/fixture coverage only in these runs.
- Exact Go 1.25 was not exercised. Cross-builds do not prove runtime compatibility;
  bounded fuzzing does not exhaust the input space.

Management IPv4 addresses and routes were unchanged. Passing this focused suite
does not complete the broader scenario-documentation or release-matrix work.

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
