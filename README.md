# CUTLINE Starter

CUTLINE is a defensive, synthetic agent-security demo for the Cursor Cybersecurity London Hackathon.

It demonstrates one controlled incident:

1. A coding-agent fixture reads a poisoned workspace instruction.
2. The fixture reads a synthetic canary from `.env`.
3. In monitor mode, the agent is allowed to send the canary to an in-memory mock collector.
4. CUTLINE reconstructs the evidence path and proposes a deterministic policy.
5. The same task is replayed from a clean fixture.
6. The policy blocks the synthetic exfiltration while the legitimate code fix and tests still succeed.

No real secrets, external victims, exploit code, or real exfiltration endpoints are used.

## Fastest local start

Requirements:

- Python 3.11+
- Node.js 20.19+ or 22.12+
- `uv` recommended, or ordinary `pip`

Terminal 1:

```bash
cd backend
uv sync --frozen
uv run uvicorn app.main:app --reload --port 8000
```

Terminal 2:

```bash
cd frontend
npm ci
npm run dev
```

Open the frontend URL printed by Vite, normally `http://localhost:5173`.

Run the demo in this order:

1. **Run compromised agent**
2. **Generate guardrail**
3. **Approve and replay**

## Verify before changing anything

```bash
cd backend
uv run pytest -q
```

```bash
cd frontend
npm run build
```

## Repository map

- `AGENTS.md` — the project constitution Cursor should always follow.
- `.cursor/rules/` — persistent Cursor project rules.
- `.cursor/agents/` — scoped planner, security reviewer, and verifier subagents.
- `docs/` — product scope, threat model, build order, and demo script.
- `prompts/` — exact prompts to paste into Cursor one phase at a time.
- `backend/` — deterministic FastAPI security demo.
- `frontend/` — single-screen React/Vite demo console.

## Critical scope rule

The local end-to-end demo is the product. Modal, Overmind, Supabase, and Ossprey are optional adapters. Do not break the local path while adding sponsor integrations.

## Optional integration order

1. Modal replay
2. Overmind tracing
3. Supabase event mirroring
4. Ossprey only if the sponsor gives a documented API/CLI during the event

Read `docs/BUILD_PLAN.md` before editing the architecture.

## Optional Modal smoke test

After the local path works:

```bash
cd backend
uv sync --extra modal
uv run modal setup
uv run python modal_sandbox.py --mode enforce
```

This runs the same synthetic worker in a fresh Modal Sandbox with `block_network=True`. The starter does not label Modal as ready until this command succeeds on your machine.
