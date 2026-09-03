# Test Environment Plan

## Scope

This document plans the verification environment for WirePup from a developer's checkout to a release gate: the test suites, their execution boundaries, the reporting contract, the lab that exercises live capture and host changes, and the phases in which the environment is built.

**Out of scope:** the test strategy per layer (`docs/testing.md`), the release procedure itself (a future `gate/RUNBOOK.md`), and the hardware validation lab beyond the checklist it feeds.

## Basis

The structure follows `epics-ioc-runner/tests` (README, `REPORTING_CONTRACT.md`, `lib/test-reporting.bash`) and `epics-ioc-runner/gate/RUNBOOK.md`. Three of its rules carry over unchanged:

1. Every check has a category (what is verified), a check kind (its role in the result), and a test method (how evidence was obtained). The three axes are independent.
2. A test method is `real-path` (the shipped path runs; only an outermost boundary such as a file, a socket peer, or the clock may be redirected), `direct-inspection` (state is read, no behavior is claimed), or `hand-built-reproduction` (invalid as evidence; never in an accepted catalog).
3. A suite declares its complete check catalog before running, compares the counts with a committed CSV, and closes every declared check exactly once; an unexpected exit is a `SCRIPT_ERROR`, not a pass.

Result dimensions stay the same (`suite`, `scope`, `runner`, `os`, `arch`, `run`) so the same collector and gate tooling can consume WirePup results. `runner` names the binary origin: `source` (a `go build` of the tree) or `installed` (`/usr/local/bin/wirepup`).

## Suites

| Suite | Category | Privilege | Where it runs |
| --- | --- | --- | --- |
| `source-regression` | source-regression | none | any host with Go |
| `protocol-conformance` | source-regression | none | any host with tshark |
| `error-contract` | error-contract | none | any host |
| `lab-lifecycle` | lifecycle-behavior | root | golden VM |
| `installed-conformance` | installed-conformance | none | installed host |

### source-regression

Wraps what exists today into a catalog: `gofmt`, `go vet`, unit and fixture tests, JSON golden files, the race detector, the import-boundary test, and the fixture generator round trip (`go run ./testdata/gen` leaves no diff). It adds Go fuzz targets for every parser (`ethernet`, `arp`, `lldp`, `ipv4`, `ipv6`, `icmpv6`, `udp`, `tcp`, `dhcpv4`, `ca`, `pva`) with a short fuzz run in the gate and the corpus committed under `testdata/fuzz`. The claim is limited to the parsers and the pipeline on the committed bytes; nothing here proves the wire format.

### protocol-conformance

Replaces self-generated fixtures as the wire-format truth. Captures are taken with tcpdump on a golden VM while the real implementations talk: EPICS Base `caget`, `camonitor`, and `softIoc` for CA; pvxs `pvxget` and `softIocPVX` for PVA; `dnsmasq` and the distribution's DHCP client (`dhcpcd` on Debian 13, `dhclient` where it still ships) for DHCPv4; `lldpd` for LLDP; the kernel for ARP probing, NDP, and DAD. Each capture is sanitized, committed under `testdata/pcap/real/`, and decoded twice: `tshark -T json` is the independent oracle, and a test compares the fields WirePup claims (PV name, search id, server port, GUID, DHCP message type, LLDP system name, and so on) with the oracle's fields. The existing generated fixtures stay for negative and truncation cases.

### error-contract

Exercises the shipped command path with invalid or unsafe input and checks the exit code and message: unknown command or flag (2), missing `CAP_NET_RAW` (3), a missing or unreadable capture file (1), a capture file that ends inside a packet (4), target not observed (5), conflicting address (6), `connect` and `tui` without a terminal (2), `--search` and `--to` validation, oversized `--arp` prefixes. Most of this exists as Go tests; the suite gives it a catalog and machine records.

### lab-lifecycle

The only suite that needs root, and the one that covers what unit tests cannot: the live `AF_PACKET` path, transmission, and host changes. It builds a virtual segment with `ip netns` and veth pairs on a golden VM:

```
              +----------+
              | switch   |  Linux bridge in its own namespace
              +--+--+--+-+
                 |  |  |
      +----------+  |  +----------+
      |             |             |
+-----+----+  +-----+----+  +-----+----+
| laptop   |  | device   |  | ioc      |
| wirepup  |  | dhcp cli.|  | softIoc  |
|          |  | Auto-IP  |  | softIocPVX
+----------+  +----------+  +----------+
```

Checks, all `real-path`:

- Passive guarantee: while `observe`, `discover`, `capture`, `diagnose`, and `epics observe` run in the laptop namespace, tcpdump on the bridge counts frames whose source MAC is the laptop's; the expected count is zero. This is the mechanical form of the ADR-0007 contract.
- Discovery: `discover` reports the device's ARP probe, announcement, DHCP exchange (with `dnsmasq` in the switch namespace) and, with `dnsmasq` stopped, the Auto-IP fallback; `diagnose` produces the DHCP-no-offer and same-L2/different-subnet findings against a device configured on another subnet.
- EPICS: `epics find` passive sees `caget` searches and `softIoc` replies; `epics find --active` gets an answer from `softIoc` and `softIocPVX`; `diagnose --epics` reports an unanswered search for a PV that no IOC hosts.
- Host changes: `connect` adds the recommended address to the laptop veth, the session file records it, a second `connect` for an address the device already uses is refused by the ARP probe with exit 6, and `disconnect` removes only the recorded address while a hand-added address on the same interface survives.
- Budget: `probe --arp` on a /24 sends at most one frame per host and, measured from tcpdump timestamps, no more than 20 frames per second; `epics find --active` sends exactly one datagram per printed destination.
- Privilege: every passive command runs with `cap_net_raw` only (a copy of the binary with that file capability, as a non-root user); `connect` without `cap_net_admin` exits 3.

### installed-conformance

Reads the installed host: the binary is statically linked (`ldd` reports not a dynamic executable), `wirepup version` matches the injected build identity, the passive commands work under the documented `setcap cap_net_raw+ep` grant, the man page or `--help` lists the same commands as `docs/cli-design.md`, and `/run/wirepup` does not exist before any `connect` has run.

## Infrastructure

The `cloud-provision` images provide what the lab needs in two forms. The `*-iocrunner` goldens are baked with an installed EPICS-env whose `epics_env_version` and `epics_base_version` are recorded in the image manifest (`bin/bake_iocrunner_image.bash`). The `*-epics-dev` VMs get EPICS-env built in place by `bin/run_epics_env_build.bash` (playbook `playbooks/species/epics_dev.yml` of `ansible-provision`); until that step has run they carry no EPICS. EPICS-env includes EPICS Base and pvxs (`epics-base-src`, `pvxs-src`), so `softIoc`, `caget`, `camonitor`, `softIocPVX`, and `pvxget` are available inside either kind of VM without a container. The OS matrix follows `epics-ioc-runner` (`rocky8` and `debian13` by default; `rocky10`, `debian12`, `ubuntu24`, `ubuntu26` as the extended matrix). Rocky 8's kernel is the oldest target and fixes the minimum for `AF_PACKET` and `PACKET_AUXDATA` behavior.

The lab script (`tests/lib/netns-lab.bash`) creates and destroys the namespaces, installs `dnsmasq`, `lldpd`, and the EPICS actors into them, and leaves nothing behind on exit; it is the outermost boundary for the whole suite and is itself covered by a self-test.

## Reporting contract

`tests/lib/test-reporting.bash` is copied from `epics-ioc-runner` with its version pinned in `tests/lib/VERSION`; a refresh is a deliberate commit that records the upstream commit. `tests/reporting-counts.csv` holds the expected check and step counts per suite. `tests/run-all-tests.bash` selects suites the same way: `--source-regression` alone, `--local` for the unprivileged suites, `--system` for the lab and installed suites, `--source` or `--installed` for the binary origin.

## Gate

The release gate runs, in order: `source-regression` on the tree, bake or refresh the golden images, deploy the binary, `installed-conformance`, `lab-lifecycle` on each OS of the matrix, then the hardware checklist from `docs/testing.md` section 8 (managed switch with LLDP, one IOC, one Auto-IP device, one tagged trunk capture). The four identity facts of the `epics-ioc-runner` runbook (branch, commit, uncommitted paths, deployed identity per host) are recorded before and after.

## Phases

1. Wrap the existing Go tests into `source-regression` and `error-contract` catalogs with machine records; add the fuzz targets and corpus. Runs on any developer host.
2. Take the real captures on one `*-epics-dev` VM, commit the sanitized files, and add the tshark comparison. Adds `protocol-conformance`.
3. Write the namespace lab and the `lab-lifecycle` suite on the same VM; make the passive-guarantee check the first one in its catalog.
4. Add `installed-conformance`, the gate runbook, and the hardware checklist; run the full matrix once before the first release.

## Open decisions

- Whether the reporting library is copied with a version pin (proposed) or shared through a separate repository used by both projects.
- Whether the extended OS matrix is part of every gate run or only of a release run.
- Whether link-level diagnostics (speed, duplex, error counters through `ethtool`, and the active `ethtool --cable-test`) join V1.1, in which case `installed-conformance` and `lab-lifecycle` gain checks for them.
