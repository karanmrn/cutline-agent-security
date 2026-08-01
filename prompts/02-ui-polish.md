Improve only the one-screen demo UX. Read @docs/DEMO_SCRIPT.md and inspect the current frontend.

Requirements:

- Preserve the three primary actions and their order.
- The attack path must be understandable in under five seconds.
- Show event IDs beside evidence.
- Show vulnerable and replay outcomes side by side.
- Do not expose raw secret values.
- Add visible loading, disabled, and error states.
- Keep the core result above the fold on a laptop.
- Do not create settings, authentication, navigation, or a second page.
- Do not change backend semantics unless required for a documented frontend bug.

After editing, run the frontend production build and the backend tests. Report exact results.
