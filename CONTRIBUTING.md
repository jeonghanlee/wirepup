# Contributing

## Scope

Build, verify and change WirePup while preserving its documented behavior
and safety boundaries.

**Out of scope:** operator walkthroughs. Use the
[documentation index](docs/README.md) for installation and usage.

## Start from current work

Read the [milestone entry point](docs/milestone-182961f.md), then the
[requirements](docs/requirements.md), [architecture](docs/architecture.md),
[protocol scope](docs/protocol-scope.md), [safety rules](docs/safety.md)
and relevant [ADRs](docs/adr/). Requirements and future protocol scope are
not a substitute for the [executed coverage](docs/vm-test-results.md).

Keep work status and plans in the current milestone document.
[Closed Doors](docs/CLOSED_DOORS.md) records examined no-change decisions.
Coding assistants also read [AGENTS.md](AGENTS.md).

## Build settings

The entry-point `Makefile` loads configuration and rules from `configure/`.
`RELEASE` defines project identity and the embedded version;
`CONFIG_SITE` selects tools, output and test scope;
`CONFIG_VARS` derives build settings.
`RULES_BUILD`, `RULES_INSTALL`, `RULES_CHECK`, `RULES_HELP` and `RULES_VARS`
use common definitions from `RULES_FUNC`.

From the repository root:

```bash
make help
make help.detail
make vars FILTER=GO
make PRINT.GO
make build
make check
```

`vars` prints effective settings; `PRINT.GO` also reports origin.
`VERBOSE=1` displays recipe commands; `DEBUG_SHELL=1` enables shell tracing.
`make` without a target shows help.

Local settings belong in `configure/CONFIG_SITE.local` or
`configure/RELEASE.local`, both ignored by Git. Matching files in the parent
directory load first; command-line assignments take precedence.
Settings include `GO`, `GOFMT`, `BIN`, `PKG`, `TEST_FLAGS` and `VERSION`.
The selected Go toolchain supplies gofmt and enforces the minimum in
`go.mod`. Builds use `CGO_ENABLED=0`; only `race` enables cgo and requires
a C compiler. `clean` removes only the file selected by `BIN`, preserving its
directory. See [installation](docs/installation.md) for install-prefix,
replacement and completion controls.

## Make a change

1. Read the subsystem's existing tests and agree its scope in the milestone.
2. Implement a small change with tests that exercise its real path. Keep
   decoders separate from device correlation, diagnosis and output.
3. Update usage documentation when behavior changes; update an ADR for a
   decision that is difficult or expensive to reverse. Do not bypass an
   accepted ADR; propose its amendment and migration cost first.
4. Validate packet parsing with byte fixtures and stored PCAPs. Validate
   privileged or network-changing behavior only in a controlled lab.
5. Review the changed code and reader-facing instructions before committing.

For a new protocol, confirm its requirement and fixtures first, emit typed
observations from the parser, then add correlation and diagnosis separately
where needed. Document each new dependency and its license.

When a mechanism is unclear, consult established implementations:
Wireshark/tshark for dissection and frame references, libpcap for Linux
capture details, iproute2 for address changes, and cashark for CA/PVA framing.
Choose the simpler form consistent with the ADRs and cite the source in the
ADR or code comment.

For collaborative work, assign disjoint file ownership and share the goal,
changed files, behavior, tests actually run, assumptions, open questions,
architecture/privilege impact and next action. The owner resolves design
disagreements. Use the [cross-review checklist](prompts/cross-review.md)
or the [full-repository checklist](prompts/full-repository-review.md)
within the review scope requested for that change.

## Verification

`make check` runs formatting checks, vet and the Go tests, including golden
PCAP output. Its `mode-check` step fails when a tracked file whose first line
starts with `#!` is not recorded with Git mode `100755`, and when run outside
a Git checkout. Use fresh runs when the change requires them:

```bash
make check TEST_FLAGS=-count=1
make race TEST_FLAGS=-count=1
```

Installation, Bash Readline and guided PTY checks are described in the
[testing guide](docs/testing.md). Privileged Linux/EPICS checks use the
[dedicated VM procedure](tests/vm/README.md). The
[test environment plan](docs/test-environment-plan.md) describes broader
planned coverage; it is not an implemented release gate.

A change is ready when its behavior is documented, relevant checks actually
pass, errors are understandable, passive guarantees and privilege boundaries
hold, and unrelated architecture is unchanged. Record scope and skipped
hardware checks with the result. Keep raw logs and unreviewed captures local;
publish only the evidence needed by the maintained tests and result summary.
