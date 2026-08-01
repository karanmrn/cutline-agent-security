# ADR 0003: Keep regression manifests non-executable

## Status

Accepted.

## Context

A replay artifact must preserve evidence and expected outcomes without becoming another instruction channel. Embedding commands, scripts, or arbitrary payloads would let an evidence file influence execution outside the approved policy contract.

## Decision

The regression artifact is fixed-schema JSON data. It contains identifiers, policy identity, evidence references, expected and actual booleans, verification status, and a SHA-256 content digest. It never contains shell commands, executable code, arbitrary tool arguments, raw secret values, or an instruction to contact a destination.

Consumers parse the manifest as data, reject unknown fields, verify its digest and policy identity, and validate required outcomes before displaying a verified result. Loading a manifest does not execute a replay. Any replay command remains application-owned and accepts only validated typed fields.

## Consequences

- Artifacts are portable evidence but not trusted programs.
- Tampering, stale policy identity, secret exposure, lost utility, or failed tests invalidate verification.
- Schema evolution requires an explicit version and compatible validator.
- Human-readable guidance lives in documentation, not inside executable artifact fields.
