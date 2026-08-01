begin;

-- New fixed-schema tables leave the published legacy mirror untouched. Browser
-- roles receive no access; only the configured server-side client may write.
create table if not exists public.cutline_safe_sessions (
  run_id text primary key,
  mode text not null,
  provider text not null,
  status text not null,
  secret_exposed boolean not null,
  exfiltration_attempted boolean not null,
  exfiltration_blocked boolean not null,
  code_fixed boolean not null,
  tests_passed boolean not null,
  collector_count integer not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_safe_events (
  event_id text primary key,
  run_id text not null references public.cutline_safe_sessions(run_id) on delete cascade,
  sequence_number integer not null,
  parent_event_id text null,
  source_trust text not null,
  data_class text not null,
  action_type text not null,
  policy_decision text not null,
  tool_category text not null,
  outcome text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_safe_incidents (
  incident_id text primary key,
  source_run_id text not null references public.cutline_safe_sessions(run_id) on delete cascade,
  secret_exposed boolean not null,
  exfiltration_attempted boolean not null,
  evidence_event_ids jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_safe_policies (
  id text primary key,
  version integer not null,
  policy_hash text not null,
  effect text not null,
  disruption_score integer not null,
  evidence_event_ids jsonb not null,
  created_at timestamptz not null default now()
);

create table if not exists public.cutline_safe_replays (
  run_id text primary key references public.cutline_safe_sessions(run_id) on delete cascade,
  policy_id text references public.cutline_safe_policies(id),
  blocked boolean not null,
  utility_retained boolean not null,
  tests_passed boolean not null,
  created_at timestamptz not null default now()
);

alter table public.cutline_safe_sessions enable row level security;
alter table public.cutline_safe_events enable row level security;
alter table public.cutline_safe_incidents enable row level security;
alter table public.cutline_safe_policies enable row level security;
alter table public.cutline_safe_replays enable row level security;

revoke all on table public.cutline_safe_sessions from anon, authenticated;
revoke all on table public.cutline_safe_events from anon, authenticated;
revoke all on table public.cutline_safe_incidents from anon, authenticated;
revoke all on table public.cutline_safe_policies from anon, authenticated;
revoke all on table public.cutline_safe_replays from anon, authenticated;

commit;
