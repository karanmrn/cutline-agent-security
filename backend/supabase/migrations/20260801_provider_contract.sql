begin;

alter table public.cutline_events
  add column if not exists source_type text;

update public.cutline_events
set source_type = 'unknown'
where source_type is null;

alter table public.cutline_events
  alter column source_type set not null;

alter table public.cutline_sessions enable row level security;
alter table public.cutline_events enable row level security;
alter table public.cutline_incidents enable row level security;
alter table public.cutline_policies enable row level security;
alter table public.cutline_replays enable row level security;

revoke all on table public.cutline_sessions from anon, authenticated;
revoke all on table public.cutline_events from anon, authenticated;
revoke all on table public.cutline_incidents from anon, authenticated;
revoke all on table public.cutline_policies from anon, authenticated;
revoke all on table public.cutline_replays from anon, authenticated;

commit;
