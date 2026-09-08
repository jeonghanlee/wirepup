# Claude entry point

Read [AGENTS.md](AGENTS.md) first, then the
[current milestone entry point](docs/milestone-182961f.md).

Use [README.md](README.md) and the [documentation index](docs/README.md)
for current user workflows. Before changing code, read the requirements,
architecture, protocol scope, safety rules, relevant ADRs and subsystem
tests listed in [Contributing](CONTRIBUTING.md#start-from-current-work).

Implement only the authorized scope of the current plan. Do not restart
repository creation or the original M0 sequence. Reusable review checklists
are linked from [Contributing](CONTRIBUTING.md#make-a-change).

WirePup's design intent is:

- local-first;
- passive-by-default;
- explicit active behavior;
- evidence-based diagnosis;
- protocol decoders emit typed observations;
- device identity is inferred by a separate correlator;
- CA/PVA are first-class protocols.
