# Claude entry point

Read `AGENTS.md` first.

Then read:

```text
README.md
docs/requirements.md
docs/architecture.md
docs/protocol-scope.md
docs/safety.md
docs/roadmap.md
docs/adr/*
```

For the first interaction, do **not** implement code. Use the architecture-review prompt in:

```text
prompts/claude-architecture-review.md
```

WirePup's non-negotiable design intent is:

- local-first;
- passive-by-default;
- explicit active behavior;
- evidence-based diagnosis;
- protocol decoders emit typed observations;
- device identity is inferred by a separate correlator;
- CA/PVA are first-class protocols, not afterthoughts.
