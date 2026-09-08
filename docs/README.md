# WirePup Documentation

## Scope

Find the instructions for installing, using and maintaining WirePup.

**Out of scope:** live network or hardware certification. The
[verification results](vm-test-results.md) state what was actually tested.

## Use WirePup

| Goal | Start here |
| --- | --- |
| Build, install, update or fix PATH selection | [Installation](installation.md) |
| Run the guide for the first time | [First use](../README.md#first-use) |
| Follow a real task and interpret its result | [Usage scenarios](usage-scenarios.md#choose-a-task) |
| Find defaults, required inputs or compatible options | [CLI reference](cli-reference.md) |
| Complete commands with Tab | [Activation](installation.md#bash-completion), [examples](usage-scenarios.md#complete-commands-in-bash) |
| Recover after a temporary connection or interruption | [Cleanup and recovery](usage-scenarios.md#interruption-and-cleanup) |
| Read JSON from scripts | [Exit status](cli-reference.md#exit-status-and-scripts), [JSON contract](output-schema.md) |

Start with a scenario when you know the task; start with an option when you
need its exact meaning. Both documents link back to each other.

## Verify an installation or a change

| Goal | Procedure or evidence |
| --- | --- |
| Check the installed executable and completion | [Installation verification](installation.md#verify-the-selected-command) |
| Run source, installation, guide and completion tests | [Testing guide](testing.md) |
| Run Linux and EPICS integration tests in the lab | [Dedicated VM procedure](../tests/vm/README.md) |
| Check executed cases and remaining limits | [VM scenario results](vm-test-results.md) |

## Engineering references

These references describe requirements and design, including future scope;
they are not a claim that every possible feature is implemented.

| Area | Reference |
| --- | --- |
| Requirements and supported protocol intent | [Requirements](requirements.md), [protocol scope](protocol-scope.md) |
| Components, data flow and package boundaries | [Architecture](architecture.md) |
| Command semantics and guided recovery contract | [CLI design](cli-design.md) |
| Passive/active behavior, privileges and capture privacy | [Safety](safety.md) |
| Versioned events, devices and findings | [Output schema](output-schema.md) |
| Accepted design decisions | [ADRs](adr/) |
| Protocol standards and upstream references | [Technical references](references.md) |
| Planned verification infrastructure beyond the focused VM suite | [Test environment plan](test-environment-plan.md) |
| Build configuration, contributions and review | [Contributing](../CONTRIBUTING.md) |

## Work and history

The [current milestone document](milestone-182961f.md) owns work status, plans,
verification and the next entry point. Its
[documentation inventory](milestone-182961f.md#documentation-inventory)
records replacements and committed history for retired initial plans.
[Closed Doors](CLOSED_DOORS.md) records examined decisions to leave code unchanged.
