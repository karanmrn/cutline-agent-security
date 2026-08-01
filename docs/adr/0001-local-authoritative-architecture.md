# ADR 0001: Keep local execution authoritative

## Status

Accepted.

## Context

CUTLINE must deliver a reliable local demonstration even when sponsor services are absent, misconfigured, rate-limited, or unavailable. An adapter that silently changes execution path would make the replay result impossible to defend.

## Decision

The local deterministic runner and in-memory state are the source of truth for the core product path.

Optional providers sit behind narrow boundaries. Provider selection is explicit. A requested provider failure is returned as that provider's failure and never reclassified as local success. Telemetry and persistence adapters may copy sanitized state, but their output cannot authorize a policy, change a decision, or overwrite the local result.

Runtime status distinguishes disabled, unverified, ready, and error. Configuration or package installation can establish only configured or unverified state. Ready requires an observed successful smoke path.

## Consequences

- Core incident, policy, and replay behavior remains testable without external accounts.
- Integration outages remain visible and cannot corrupt the local demonstration.
- Each adapter needs explicit contract tests and separate smoke evidence before any readiness claim.
- External copies are derivative evidence, not recovery or consistency authorities.
