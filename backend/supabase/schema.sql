-- Optional CUTLINE event mirror. Apply only after the local demo works.

create table if not exists public.cutline_sessions (
  session_id text primary key,
  mode text not null,
  provider text not null,
  status text not null,
  secret_exposed boolean not null,
  tests_passed boolean not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_events (
  event_id text primary key,
  session_id text not null references public.cutline_sessions(session_id) on delete cascade,
  sequence_number integer not null,
  parent_event_id text null,
  actor text not null,
  source_trust text not null,
  data_class text not null,
  tool_name text not null,
  action_type text not null,
  policy_decision text not null,
  outcome text not null,
  resource text null,
  destination text null,
  message text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_incidents (
  incident_id text primary key,
  source_session_id text not null references public.cutline_sessions(session_id) on delete cascade,
  severity text not null,
  summary text not null,
  evidence_event_ids jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_policies (
  id text primary key,
  version integer not null,
  policy_hash text not null,
  effect text not null,
  disruption_score integer not null,
  evidence_event_ids jsonb not null,
  policy_yaml text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_replays (
  session_id text primary key references public.cutline_sessions(session_id) on delete cascade,
  policy_id text references public.cutline_policies(id),
  blocked boolean not null,
  utility_retained boolean not null,
  manifest_sha256 text not null,
  created_at timestamptz not null default now()
);

-- For a hackathon browser demo, add narrowly scoped RLS before exposing any
-- table through a publishable/anon key. Never expose the service-role key.
-- Enable Realtime only if needed:
-- alter publication supabase_realtime add table public.cutline_events;
