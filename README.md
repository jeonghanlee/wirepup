# WirePup

## Scope

WirePup is a local network discovery and diagnosis tool for engineers working
with Ethernet devices and EPICS Channel Access (CA) or PVAccess (PVA).
It starts with passive observation and explains the evidence behind a diagnosis.

**Out of scope:** industrial device writes, switch configuration and aggressive
scans. A device that sends no visible traffic may remain undiscovered.
See the [safety rules](docs/safety.md) and [verification limits](docs/vm-test-results.md#verification-limits).

## Install

Use Linux, Go 1.25 or newer, GNU Make and Bash. See
[installation prerequisites](docs/installation.md#prerequisites) for Debian 13
and toolchain setup.

From the repository directory, as your normal user:

```bash
make build
make install.dry-run INSTALL_LOCATION=/usr/local
make install INSTALL_LOCATION=/usr/local
export PATH="/usr/local/bin:$PATH"
make install.check INSTALL_LOCATION=/usr/local
sudo wirepup version
```

This installs the executable at `/usr/local/bin/wirepup` and Bash completion
under `/usr/local/share/bash-completion/`. Existing files require confirmation;
only protected file copies use sudo. Do not run `sudo make`.
The [installation guide](docs/installation.md) covers checkout, user-only installation,
updates, PATH checks and completion activation.

## First use

For a guided live session, run in a terminal:

```bash
sudo wirepup
```

Choose **Find devices** or **Diagnose EPICS connectivity**. The guide asks for
the interface and observation time, then shows the direct command it will run.
It starts passively. A proposed transmission or temporary address change needs
a separate confirmation.

For offline work, run `wirepup` without sudo and choose
**Analyze a capture file**. To try a direct command without network access,
run from this repository:

```bash
wirepup read testdata/pcap/ca-search-response.pcap --protocol ca
```

Menus accept a number, `b` for back and `q` for quit. Free-text prompts use
`/back` and `/quit` so names such as `b` remain usable.
Keep a guide-created temporary connection open while using it. Read
[interruption and cleanup](docs/usage-scenarios.md#interruption-and-cleanup)
before relying on automatic removal.

## Choose a task

| Task | Command | Walkthrough |
| --- | --- | --- |
| Inspect local interfaces | `interfaces` | [Start here](docs/usage-scenarios.md#start-here) |
| Find an unknown device | `discover` | [Device discovery](docs/usage-scenarios.md#find-an-unknown-device) |
| Watch live protocol events | `observe` | [Event stream](docs/cli-design.md#wirepup-observe) |
| Save or analyze a capture | `capture`, `read` | [Capture and replay](docs/usage-scenarios.md#capture-and-replay) |
| Explain subnet or DHCP symptoms | `diagnose` | [Temporary connection](docs/usage-scenarios.md#temporary-connection), [DHCP and Auto-IP](docs/usage-scenarios.md#dhcp-and-auto-ip) |
| Inspect CA/PVA discovery | `epics observe`, `epics diagnose`, `epics find` | [Passive EPICS analysis](docs/usage-scenarios.md#passive-epics-analysis) |
| Send an explicit PV search | `epics find --active` | [Active EPICS search](docs/usage-scenarios.md#active-epics-search) |
| Send a bounded ARP search | `probe` | [Bounded ARP search](docs/usage-scenarios.md#bounded-arp-search) |
| Add or remove a temporary address | `connect`, `disconnect` | [Temporary connection](docs/usage-scenarios.md#temporary-connection) |
| Watch interactive views | `tui` | [Use the TUI](docs/usage-scenarios.md#use-the-tui) |
| Use scripts, help or version output | `--help`, `version`, `--json` | [Scripts and help](docs/usage-scenarios.md#scripts-and-help) |

For repeat work, use explicit commands and the
[option reference](docs/cli-reference.md). Bare invocation with redirected
stdin or stdout prints usage and exits 2 instead of asking questions.

`probe`, `connect` and `epics find --active` ask before acting unless
`--yes` is supplied. Direct `disconnect` requests deletion of recorded addresses
without a prompt; inspect the [recovery conditions](docs/usage-scenarios.md#interruption-and-cleanup) first.
Other command modes in the table are passive.

## Bash completion

After system installation, activate completion in your current Bash shell:

```bash
source /usr/local/share/bash-completion/completions/wirepup
```

Type `wirepup cap` and press Tab to complete `capture`.
If Tab makes no further change, press it again to list the remaining choices.
See [activation for other prefixes](docs/installation.md#bash-completion)
and [completion examples](docs/usage-scenarios.md#complete-commands-in-bash).

## Documentation

The [documentation index](docs/README.md) connects installation, scenarios,
options, test procedures and engineering references.
Start [contributing](CONTRIBUTING.md) for build settings and development checks.

Copyright 2026 Lee, Jeong Han. Licensed under the [Apache License 2.0](LICENSE).
