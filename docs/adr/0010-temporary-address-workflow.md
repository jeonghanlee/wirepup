# ADR-0010: Temporary addresses are applied through iproute2 and recorded in a session file

Status: Accepted

## Context

R-013 and R-014 define the temporary secondary IPv4 workflow (`connect` and `disconnect`), and `docs/safety.md` section 3 fixes the sequence `observe -> infer -> recommend -> explicit execute`. Two decisions were deferred until the capture backend was known (`docs/safety.md` section 4): whether a separate privileged helper is needed, and how the change is applied and recorded.

ADR-0002 settled the backend: passive capture needs `CAP_NET_RAW` only. The address workflow is the one place that needs `CAP_NET_ADMIN`.

Options for applying the change:

- run the iproute2 `ip` command with an exact argument list;
- build rtnetlink messages in-process;
- delegate to a separate helper executable that alone holds `CAP_NET_ADMIN`.

## Decision

### Application

`internal/networkcfg` applies and removes addresses by running iproute2 with an explicit argument vector and no shell:

```text
ip -4 address add <address>/<prefix> dev <interface> label <interface>:wp
ip -4 address del <address>/<prefix> dev <interface>
```

The executable is resolved from `/usr/sbin/ip`, `/sbin/ip`, `/bin/ip` in that order, never from `PATH`. iproute2 is present on every Linux distribution WirePup targets; the argument list is printed before execution and stored afterwards, so the engineer can repeat or undo the action by hand with the same command. The label marks the address as WirePup-created in `ip address show` output. When the interface name is too long to carry a label (the limit is 15 characters in total), the label is omitted and the session file alone identifies the address.

No route is added or removed explicitly. The kernel installs the connected-subnet route with the address and removes it with the address; WirePup reports this consequence when the new subnet overlaps an existing route.

Netlink remains the mechanism for reading interfaces, addresses, and routes through the Go standard library and `golang.org/x/sys/unix`; WirePup sends no netlink write message.

### Session file

Every applied change is recorded before the command returns, in `/run/wirepup/session.json` (file mode 0600, directory mode 0700). `/run` is a memory-backed filesystem cleared at boot, which matches the address itself: both disappear at reboot, so the record cannot describe an address that no longer exists after a restart.

Each record carries the interface name and index, the address and prefix, the label, the time added, the WirePup version, and the exact argument vector that was executed.

### Removal

`disconnect` removes only addresses listed in the session file, and only when the address is still present on the recorded interface. An address that is already gone is reported and its record dropped. No other address is ever removed, and a primary address is never replaced (R-014).

### Conflict check before adding

Before the `add` command runs, `connect` requires that the candidate address:

- is not configured on any local interface;
- has not been observed as a sender in the passive device table;
- is not the network or broadcast address of the prefix;
- receives no reply to an RFC 5227 style ARP probe (three probes with RFC 5227 timing) sent on the target interface.

The ARP probe is active behavior and is reported under `Executed`; `connect` is an active command under ADR-0007.

### Privilege

V1 ships one executable and no helper process. `connect` and `disconnect` require an effective `CAP_NET_ADMIN` and are normally run under `sudo`. The documented file-capability grant for unattended passive use is `CAP_NET_RAW` only; granting `CAP_NET_ADMIN` on the executable is not recommended. Passive command packages must not import `internal/networkcfg` or `internal/active`; a test enforces this through the Go import graph.

A helper process was rejected for V1 because under `sudo` it does not reduce exposure, and it would break the single-executable deployment (NFR-002). The package boundary keeps the option open.

## Consequences

- WirePup depends on the `ip` executable at runtime for `connect` and `disconnect` only; passive commands do not.
- The ARP probe means `connect` also needs `CAP_NET_RAW`, which `sudo` provides.
- Interrupted sessions recover from the file: `disconnect` and `connect` both read it first and report stale entries.
- `docs/safety.md` section 4 is satisfied without a `wirepup-netcfg` helper; a future ADR may introduce one if a deployment requires capabilities without `sudo`.
