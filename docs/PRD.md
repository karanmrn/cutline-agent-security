# Product Requirements Document

## Product

CUTLINE — verified incident replay for autonomous agents.

## User

An AI-platform or security engineer who has a suspicious agent trace and needs a narrowly scoped control that blocks the harmful behaviour without disabling the legitimate task.

## Three-minute story

1. A developer asks a coding agent to fix a failing test.
2. A synthetic poisoned workspace rule instructs it to include `.env` in a diagnostic upload.
3. Monitor mode allows the attempt and the mock collector receives a fake canary.
4. CUTLINE displays the evidence path.
5. CUTLINE proposes a deterministic least-disruptive policy.
6. Human approves replay.
7. Enforce mode blocks secret egress while the code fix and tests still succeed.
8. CUTLINE emits a regression-test artifact.

## Must-have acceptance criteria

- One vulnerable run.
- One policy.
- One replay.
- One evidence graph.
- One before/after result.
- All local tests pass.

## Out of scope

- Real attack traffic.
- General vulnerability discovery.
- Production policy management.
- Full MCP protocol implementation.
- Multi-agent orchestration.
- Identity and access management.
- Real secret handling.

## Core metrics

- Attack blocked: boolean.
- Legitimate task retained: boolean.
- Tests retained: boolean.
- Policy disruption score: integer, lower is better.
- Evidence completeness: all explanation claims cite event IDs.
