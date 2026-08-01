Implement only the approved local-MVP plan.

Hard constraints:

- Preserve the architecture and safety boundary in @AGENTS.md.
- Use only the synthetic canary and in-memory MockCollector.
- Do not add any network-based exfiltration.
- Keep enforcement deterministic.
- Do not add sponsor integrations in this phase.

Process:

1. Run the existing backend tests and frontend build before editing.
2. Fix only reproducible failures or the approved local UX issues.
3. Add focused tests for behavioural changes.
4. Run `uv run pytest -q` in backend.
5. Run `npm run build` in frontend.
6. Summarize changed files, exact commands, results, and remaining limitations.

The task is incomplete unless the three-button flow proves:

- vulnerable canary exposure = true;
- policy generated with evidence IDs;
- replay canary exposure = false;
- replay code fixed = true;
- replay tests passed = true.
