Implement Supabase as optional event mirroring, not as a rewrite of local state.

Use current official Supabase documentation.

Requirements:

- Add SQL for sessions, events, incidents, policies, and replays.
- Backend may use a server-side key; never expose a service-role key to the frontend.
- Mirror writes best-effort with explicit health/status reporting.
- Keep in-memory state authoritative for the live demo.
- Add Realtime only for the event table if time permits.
- If using browser Realtime, use a publishable/anon key and narrowly scoped RLS.
- The app must work when all Supabase variables are absent.
- Add setup and teardown documentation.
- Test the disabled path locally and mock the enabled path.

Do not add authentication, user profiles, storage, edge functions, or multi-tenancy.
