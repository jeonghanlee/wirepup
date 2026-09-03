# ADR-0001: Use Go as the initial implementation language

Status: Accepted

## Context

WirePup should be easy to deploy on engineering laptops, support concurrent packet processing, and preferably ship as a small executable.

## Decision

Use Go for the initial implementation.

## Rationale

Benefits:

- straightforward executable deployment;
- strong networking ecosystem;
- good concurrency model;
- mature CLI/TUI ecosystem;
- cross-compilation options;
- suitable performance for the target workload.

## Consequences

- cgo dependencies should be isolated if the capture backend needs them;
- parser hot paths should avoid unnecessary allocations;
- protocol fixtures/tests should remain portable.
