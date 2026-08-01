# Build Plan

## Phase 0 — run the starter unchanged

Acceptance:

- `pytest -q` passes.
- frontend production build passes.
- all three buttons complete the demo.

Do not add a sponsor integration before this works.

## Phase 1 — improve local product quality

Acceptance:

- incident timeline is readable;
- attack path is visually obvious;
- evidence IDs are visible;
- before/after cards fit on one screen;
- failures surface cleanly.

## Phase 2 — Modal

Goal: execute the replay worker in a Modal Sandbox with outbound networking blocked.

Acceptance:

- local mode still works;
- Modal setup is documented;
- one explicit smoke-test command succeeds;
- UI accurately labels the provider;
- failed Modal calls fall back only when the user chooses local mode, not silently.

## Phase 3 — Overmind

Goal: emit entry-point, workflow, and tool spans for vulnerable and replay runs.

Acceptance:

- missing API key leaves the demo working;
- secret-bearing tools disable input/output capture if supported;
- trace identity remains stable;
- one vulnerable and one replay trace are visible in Overmind.

## Phase 4 — Supabase

Goal: mirror sessions, events, policies, and replays to Postgres and optionally stream event inserts to the frontend.

Acceptance:

- local in-memory state remains authoritative for the demo;
- no service-role key reaches the browser;
- Realtime is enabled only for required tables;
- UI still works when Supabase is disabled.

## Phase 5 — Ossprey

Do this only if sponsor staff provide a documented API, CLI, starter repository, or direct technical support.

Goal: use an Ossprey finding as an upstream trigger or contextual signal. Do not make Ossprey part of the core replay logic.

## Final freeze

At least 45 minutes before submission:

- stop adding features;
- run all tests;
- rehearse the demo five times;
- prepare screenshots or a short fallback recording;
- verify no real credential is in git.
