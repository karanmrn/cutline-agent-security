# Release Checklist

Use this checklist for a release candidate. A green command is evidence only for the commit and environment where it ran.

## Automated gate

From repository root:

```bash
make setup
make check
```

Require GitHub Actions jobs for backend, frontend, and secret scanning to pass on the same commit. Backend installation and tests use `uv.lock` with `--frozen`; frontend installation uses `npm ci`. Frontend tests are required and run before the production build.

Do not waive dependency findings or secret-scan results. Investigate and resolve them without adding real credentials or broad allowlists.

## Product invariant

Run the local browser flow from a reset state and confirm:

- monitor mode exposes only the fake canary to the in-memory collector;
- untrusted instruction, secret read, and external-write attempt form one parent-linked evidence path;
- displayed claims and graph nodes carry evidence IDs;
- policy approval binds ID, version, and hash;
- enforce replay blocks synthetic egress;
- legitimate code fix still occurs;
- fixture tests still pass;
- downloaded regression manifest is JSON data, contains no raw canary, and corresponds to the verified replay.

## Claim discipline

Local behavior may be called ready only after the automated gate and full browser flow succeed on the release commit.

An optional integration may be called ready only after its documented smoke path succeeds against the intended account and the runtime reports ready. Disabled, configured, unverified, and error are valid release states. Never turn an optional provider failure into a local success claim.

Provider-specific setup and evidence requirements live in
[../INTEGRATIONS.md](../INTEGRATIONS.md). For telemetry, inspect the remote trace
tree. For Supabase, inspect stored sanitized rows. SDK flush or client creation
alone is not proof of remote ingestion.

## Freeze

- Rehearse the three-minute flow five times.
- Check the 1440 by 900 presentation and one mobile viewport for clipping or page overflow.
- Prepare screenshots or a short local recording as fallback evidence.
- Confirm repository history contains no real credential.
- Record exact commands, commit, and any integration still disabled or unverified in release notes.
