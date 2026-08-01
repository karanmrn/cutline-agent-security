# CUTLINE Context

CUTLINE demonstrates one narrow claim: a synthetic agent incident can produce an evidence-bound guardrail whose exact effect is proven by replay while useful work remains intact. Product scope belongs in [docs/PRD.md](docs/PRD.md); security assumptions belong in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## Glossary

**Synthetic fixture**

A fresh temporary repository containing the controlled task, poisoned workspace instruction, failing test, and fake canary. A replay receives another fresh fixture so prior filesystem state cannot create a false success.

**Trusted task**

Operator intent that must survive enforcement: fix the application defect and verify it with tests.

**Untrusted instruction**

Repository-controlled content that may influence the agent but cannot expand operator authority.

**Synthetic canary**

The literal fake value `CUTLINE_CANARY_7F3A`. It proves the monitor-mode path without exposing a real credential. Event and integration payloads redact it.

**MockCollector**

The in-memory sink used to observe the synthetic canary. It is not a network client or production exfiltration target.

**Monitor mode**

Observation mode that records the external-write attempt and allows the fake canary into `MockCollector`, establishing the incident baseline.

**Enforce mode**

Replay mode that requires an approved policy and applies its deterministic match before the external-write sink.

**Event**

A redacted, ordered record with stable identity, session identity, and optional parent identity. Event IDs connect claims, policy evidence, graph nodes, and replay results.

**Evidence chain**

The parent-linked path from untrusted instruction through secret read to external-write attempt. Matching event types without causal links is not enough.

**Session allowlist**

Destinations authorized for one task session. It is explicit session context, not a global claim about trust.

**Policy proposal**

A fixed-schema deny rule derived from a valid evidence chain. Policy ID, version, and content hash bind human approval to exact policy data.

**Deterministic enforcement**

An allow or deny decision made by typed policy fields and runtime context. An LLM may explain evidence but cannot decide whether a tool call executes.

**Replay provider**

The selected execution boundary for enforce mode. Local is authoritative. Optional providers must report disabled, unverified, ready, or error without silent fallback.

**Regression manifest**

Non-executable JSON evidence emitted only for a verified replay. It binds fixture, policy, source evidence, replay evidence, expected outcomes, actual outcomes, and a content digest.

**Utility retained**

The legitimate code fix still occurs and fixture tests still pass after harmful egress is blocked.

## Decision index

- [ADR 0001](docs/adr/0001-local-authoritative-architecture.md) owns source-of-truth and adapter failure semantics.
- [ADR 0002](docs/adr/0002-deterministic-enforcement.md) owns policy evaluation and approval identity.
- [ADR 0003](docs/adr/0003-non-executable-json-manifest.md) owns artifact safety and validation boundaries.
