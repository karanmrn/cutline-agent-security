# ADR 0002: Make enforcement deterministic

## Status

Accepted.

## Context

Evidence explanation may benefit from probabilistic models, but a security boundary must be replayable and auditable. The same approved policy and session context must yield the same decision.

## Decision

Enforcement evaluates a fixed-schema policy against typed runtime facts. The narrow rule denies a `SECRET` `EXTERNAL_WRITE` when its destination is outside the session allowlist. All other actions remain allowed unless a future, separately approved schema says otherwise.

Policy generation requires the causal evidence chain defined in [CONTEXT.md](../../CONTEXT.md). Approval carries policy ID, version, and content hash. Replay rejects missing, stale, or altered approval rather than reconstructing intent.

LLMs may summarize evidence or explain a result. They do not produce the final allow or deny decision at execution time.

## Consequences

- Decisions can be unit-tested as an input and output matrix.
- Replays can prove which exact policy was used.
- Preserving the code fix and tests remains a separate required outcome, not an inference from blocked egress.
- New match fields require a schema decision and compatibility tests instead of prompt changes.
