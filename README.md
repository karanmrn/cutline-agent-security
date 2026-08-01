# CUTLINE

CUTLINE is a defensive, synthetic demonstration of verified incident replay for autonomous agents. It turns one controlled monitor-mode incident into an evidence-linked policy, then replays the task to prove that the policy blocks synthetic secret egress without blocking the legitimate code fix.

Only the literal fake canary `CUTLINE_CANARY_7F3A` reaches an in-memory `MockCollector`. Local execution does not send payloads to an external collector. See [CONTEXT.md](CONTEXT.md) for domain language and [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) for the safety boundary.

## Local start

Requirements:

- Python 3.11 or newer
- `uv` 0.11.28 for parity with CI
- Node.js 22.12 or newer
- npm included with Node.js

Install both locked dependency sets:

```bash
make setup
```

Start the API:

```bash
cd backend
uv run --frozen uvicorn app.main:app --reload --port 8000
```

Start the frontend in another terminal:

```bash
cd frontend
npm run dev
```

Open the URL printed by Vite, normally `http://localhost:5173`. Run the three actions in order: compromised run, guardrail generation, then approval and replay.

## Verification

```bash
make test
make build
make audit
```

`make test` includes both backend and frontend tests. `make check` runs tests, production build, and both dependency audits. CI repeats those locked commands and performs a static secret scan over repository history.

Release evidence and manual invariants live in [docs/release/CHECKLIST.md](docs/release/CHECKLIST.md).

## Optional Modal smoke test

Modal is never required for the local demo. After the local gates pass, configure
your own Modal profile and run one explicit network-blocked replay:

```bash
cd backend
uv sync --frozen --extra modal
uv run modal setup
CUTLINE_MODAL_ENABLED=1 uv run python modal_sandbox.py --mode enforce
```

The command uses only a generated synthetic fixture and `block_network=True`.
With `CUTLINE_MODAL_ENABLED=1`, Modal appears as configured but unverified in the
UI. Selecting it and explicitly approving replay performs the verification run;
the runtime marks it ready only after that replay succeeds.
If the profile is missing, keep `CUTLINE_MODAL_ENABLED` unset and use Local in
the UI; the status remains `disabled` or `unverified` and no silent fallback
occurs. Never put Modal credentials in this repository or in frontend code.

## Architecture and status

Local execution is authoritative. Optional Modal, Overmind, Supabase, and Ossprey adapters cannot turn an unavailable or failed integration into local success. Installed packages or configuration alone do not make an integration ready. Claim readiness only after its explicit smoke path succeeds and the runtime reports that result.

Architecture decisions:

- [Local-authoritative execution](docs/adr/0001-local-authoritative-architecture.md)
- [Deterministic enforcement](docs/adr/0002-deterministic-enforcement.md)
- [Non-executable JSON regression manifest](docs/adr/0003-non-executable-json-manifest.md)

Product scope and delivery order remain in [docs/PRD.md](docs/PRD.md) and [docs/BUILD_PLAN.md](docs/BUILD_PLAN.md). Demo narration lives in [docs/DEMO_SCRIPT.md](docs/DEMO_SCRIPT.md).
