# Dedicated VM Scenarios

## Scope

Run the installed WirePup CLI against real Linux, DHCP and EPICS peers in the
dedicated Debian 13 guest `lab-debian13-wirepup`. The [catalog](catalog.csv)
contains 17 checks; [recorded results](../../docs/vm-test-results.md) show their
status.

**Out of scope:** production networks, physical hardware, Rocky Linux, and
implementation of guidance. This is a focused suite, not the full
[test environment plan](../../docs/test-environment-plan.md).

## Run on the prepared VM

Complete [prerequisites](#prerequisites) first. Allow about three minutes plus
an actual guest reboot. The runner requires root and checks the guest hostname.

### 1. In the guest: run the scenarios

Place `scenarios.py` and `catalog.csv` together in `~/vm`, then run:

```bash
cd ~/vm
sudo python3 -I scenarios.py
```

**Check:** save the directory printed as `RESULTS=/var/tmp/...`.
V16 is `PENDING`: the isolated client deliberately retains `192.0.2.30/24`
and its WirePup session record for the reboot test. V17 is `NOT_IMPLEMENTED`.

The runner stops its actors and retains logs, captures and namespaces.
It refuses existing suite namespaces or a nonempty address record.

### 2. On the libvirt host: reboot only the test guest

```bash
virsh -c qemu:///system reboot lab-debian13-wirepup
```

Wait until SSH to that guest works again.

### 3. In the guest: check recovery

Paste only the directory after `RESULTS=` from step 1 when prompted:

```bash
cd ~/vm
read -r -p 'Main RESULTS path: ' RUN
sudo python3 -I scenarios.py --reboot-check "$RUN"
```

**Check:** V16 passes only if the boot ID changed, the binary is unchanged,
the test namespaces and `/run/wirepup/session.json` are gone, and an empty
`disconnect --json` succeeds.

Save the newly printed results directory too. Its `results.json` contains
the final verdicts; earlier command evidence stays in the first directory.
For the recorded implementation, success means 16 PASS and V17 NOT_IMPLEMENTED,
with no FAIL, SCRIPT_ERROR or PENDING. A shell exit code alone is insufficient.

## Prerequisites

Use the disposable guest, not a workstation. This runner consumes a ready VM;
it does not create/delete domains or download images. The recorded VM used
the sibling `cloud-provision` checkout's
`bin/create_vm.bash -o debian13 -n wirepup -m 4096 -F`, its cached Debian image
and the `lab` management network.

Install the following inside the guest as root:

```bash
apt-get update
apt-get install python3 iproute2 iputils-ping tcpdump tshark dnsmasq-base dhcpcd-base epics-base
apt-get install libevent-pthreads-2.1-7t64
```

Install the built WirePup at `/usr/local/bin/wirepup`.
The Debian `epics-base` package supplies `caget` and `pvget`, not this IOC.
Supply a matching EPICS Base/PVXS build under:

```text
/opt/wirepup-epics/bin/softIocPVX
/opt/wirepup-epics/dbd/softIocPVX.dbd
/opt/wirepup-epics/lib/
```

The recorded library set is `libpvxsIoc.so.1.5`, `libpvxs.so.1.5`,
`libdbCore.so.3.25.0`, `libdbRecStd.so.3.25.0`, `libCom.so.3.25.0` and
`libca.so.4.15.0`. Use libraries and DBD from the same IOC build; these names
are not a universal ABI requirement. Record package versions and IOC/library
hashes with the local results for each run.

The runner sets `LD_LIBRARY_PATH` and starts the IOC with `-S`. Its single
`ai` record is `WP:VALUE`, with `VAL=42`; clients only read the value.

## Isolated topology

| Namespace | Initial address | Role |
| --- | --- | --- |
| `wpl-switch` | None | Bridge `br0` |
| `wpl-client` | `192.0.2.1/24` | WirePup and EPICS clients |
| `wpl-peer` | `192.0.2.2/24` | ARP peer, DHCP server, first IOC |
| `wpl-ioc2` | `192.0.2.3/24` | Duplicate IOC |
| `wpl-dhcp` | `192.0.2.4/24` | DHCP/IPv4LL client |

Each endpoint has loopback and a veth, with no default route. The bridge is
inside its own namespace and has no management-network connection. IPv6 is
disabled there. Management IPv4 addresses and routes are checked before and
after the scenarios.

DHCP capture runs at the client so unicast replies are visible. A third bridge
port is not a substitute for port mirroring.

## Read the results

| State | Meaning |
| --- | --- |
| `PASS` | The real command and its assertions passed |
| `FAIL` | A reached command or assertion failed |
| `SCRIPT_ERROR` | The check was not reached |
| `PENDING` | Reboot and recovery check are still required |
| `NOT_IMPLEMENTED` | The feature is absent, not a passing implementation test |

Root-owned `/var/tmp/wirepup-scenarios-*` directories retain `results.json`,
`commands.jsonl`, command output, actor logs and actual PCAPs. Both success and
failure evidence remain available. Background-process logs are separate from
the foreground command exit records.

Keep detailed logs, failed-run records and full archives in local storage.
Publish only the result summary and reviewed PCAPs needed by regression tests.
The retained [captures and checksums](pcap/manifest.json) contain isolated test
traffic; `TestRecordedVMCaptures` reads these files directly.

V08 measures six passive commands on an idle segment; it is not a guarantee
about all host traffic. V17 checks the current bare-CLI exit 2, not a guide.
See the [result matrix and limits](../../docs/vm-test-results.md) before
treating a passed row as broader coverage.
