Enter final-freeze mode. Do not add features.

Read @AGENTS.md and @docs/DEMO_SCRIPT.md.

1. Run backend tests.
2. Run frontend production build.
3. Run the local three-button demo end to end.
4. Run each enabled sponsor integration smoke test once.
5. Search the repository for likely secrets, tokens, `.env` files, private keys, and hardcoded credentials.
6. Verify the UI does not show raw payload contents.
7. Verify every incident explanation cites event IDs.
8. Verify the vulnerable and replay fixtures are created fresh.
9. Produce a concise launch checklist and fallback plan.
10. Make no code change unless it fixes a reproducible blocker; after any fix, rerun all checks.

Report only verified pass/fail evidence and exact commands.
