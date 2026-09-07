# Testing Strategy

The implemented [VM suite](../tests/vm/README.md) exercises live Linux and
EPICS paths. Its [results and evidence](vm-test-results.md) distinguish passed,
unimplemented and unverified scenarios. `TestRecordedVMCaptures` also replays
the retained real captures during normal `make check`, without a VM or root.

## 1. Principles

Most protocol logic must be testable without root and without a live network.

Testing layers:

1. byte-level unit tests;
2. complete-frame fixtures;
3. PCAP replay tests;
4. device-correlation tests;
5. diagnosis tests;
6. controlled live integration tests.

## 2. Decoder fixtures

Create fixtures for:

- Ethernet/VLAN;
- LLDP;
- ARP request/reply/probe/announcement;
- DHCP;
- IPv6 NDP/DAD;
- CA;
- PVA.

Each fixture should document its expected interpretation.

## 3. PCAP corpus

Suggested:

```text
testdata/pcap/
  lldp-single-neighbor.pcap
  arp-autoip-selection.pcap
  dhcp-success.pcap
  dhcp-no-offer.pcap
  ipv6-dad.pcap
  ca-search-response.pcap
  ca-search-no-response.pcap
  ca-beacon.pcap
  pva-search-response.pcap
  pva-beacon.pcap
  same-l2-different-subnet.pcap
```

Sanitize sensitive captures before committing.

## 4. Device correlation tests

At minimum:

- MAC observed before IP;
- IP appears later;
- Auto-IP followed by DHCP/static IP;
- one device with multiple addresses;
- two devices with same/similar hostname;
- duplicate IPv4 claims;
- LLDP switch neighbor kept distinct from endpoint device records.

## 5. Diagnosis tests

Use explicit evidence sets.

Example:

```text
Given:
  local enp3s0 = 10.20.30.51/24
  observed ARP from MAC A
  ARP sender IPv4 = 192.168.1.100

Expect:
  observed: L2 frame from MAC A on enp3s0
  inferred: MAC A appears to use 192.168.1.100
  diagnosis: IPv4 outside configured local subnet
```

## 6. CA tests

Validate semantics, not only ports.

Cases:

- valid CA search;
- valid CA search response;
- valid CA beacon;
- malformed CA message;
- UDP/5064 packet that is not CA;
- response matching prior search ID;
- apparent duplicate server claims.

## 7. PVA tests

Cases:

- valid PVA search;
- valid search response;
- server GUID extraction;
- valid beacon;
- malformed PVA message;
- UDP/5076 packet that is not PVA;
- TCP/5075 traffic without valid PVA framing.

## 8. Live integration lab

Recommended topology:

```text
Laptop
  |
small managed switch
  |---- test Linux host / IOC
  |---- embedded controller
  |---- optional second VLAN
```

Scenarios:

- no DHCP server;
- DHCP available;
- static device on different subnet;
- Auto-IP device;
- LLDP-enabled switch;
- tagged trunk/mirror capture;
- CA IOC;
- PVA IOC.

## 9. Privileged tests

CI should run parser/correlation/diagnosis tests unprivileged.

Privileged capture/network-config tests should be optional and clearly separated.

## 10. Installation tests

From the repository, `bash tests/install.bash` builds and installs into a temporary
user-owned prefix, then checks the bytes, mode, PATH selection, spaces in paths,
and symlink refusal. It checks completion bytes and mode, rejects missing completion,
and runs real Tab tests against the installed files. It requires Go, Make, Bash,
GNU coreutils, and Python 3 on Linux.

`python3 tests/install-confirmation.py` also requires Python 3 on Linux. It builds two
versions of WirePup and runs the real `make install` target through a PTY:
`y` replaces the old version; `n`, Enter, and EOF preserve it. Non-interactive
replacement must fail unless `INSTALL_FORCE=1` explicitly approves it.
Accepting the binary replacement but declining completion must preserve both files.
Build output targeting the installed completion must fail before the build changes it.
A syntax-valid completion without a registration or its registered function must
leave both installed files intact. `install.check` must also reject a missing
handler, even when the parent shell exports a function with that name.
It also creates a destination after the initial consent check and verifies that
installation refuses to overwrite it.

For the isolated Linux VM test, first produce a distinct previous executable:
`make build BIN=bin/wirepup.previous VERSION=install-test-previous`.
Copy `bin/wirepup`, `bin/wirepup.previous`, `completions/wirepup.bash`,
`tools/install-wirepup.bash`, `tools/install-system-wirepup.bash`,
`tests/completion.py`, `tests/install-confirmation.py`, and `tests/install.bash` with their relative
paths intact. Run `bash tests/install.bash --system` as a normal user with
non-interactive sudo and Python 3. This uses the two prebuilt executables and the real installation
driver, without rebuilding on the VM. It creates a temporary root-owned prefix
under `/opt`, tests the protected copy and failure preservation, and removes that
prefix on success. Existing `/usr/local/bin/wirepup` is not changed. Failed tests
retain their temporary paths for inspection. These tests run separately from
`make check` and do not capture or transmit network traffic.
The system test invokes the installation driver's `check` action as root and verifies
refusal before executing the binary or sourcing completion.

The system test also requires util-linux (`unshare`, `mount`, `umount`, `runuser`).
In a private mount namespace it checks that a `noexec` destination preserves the
previous executable and that a `noexec` `TMPDIR` permits installation elsewhere.
The temporary mount is removed before the namespace exits.

## 11. Bash completion tests

`go test ./cmd/wirepup -run TestBashCompletion -count=1` builds the real CLI and
calls the shipped Bash completion function with command, flag, value, and file
contexts. The command and protocol candidate sets are checked against production
definitions. The tests cover aliases, value arity, comma lists, quoting, `--`, local
interfaces, and unevaluated shell input. Completed dash-prefixed paths are passed
to the real `read` command with the shipped `ca-beacon.pcap`; both beacon events
must be decoded. This test is also part of `make check`.

After `make build`, run `python3 tests/completion.py` for actual Readline Tab
input through a PTY. It tests command/option completion, quoted equals assignments,
paths after `--`, and quoted or escaped paths containing spaces, colons, or equals.
The edited command is inspected through
Readline and never executed. If the optional `bash-completion` package is present,
its real autoloader is tested too; otherwise that one case is reported as skipped.
`tests/install.bash` runs the same tests with the installed binary and completion.
