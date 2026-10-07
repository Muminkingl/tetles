create table public.projects (
  id uuid primary key default gen_random_uuid(),
  owner_id uuid not null references auth.users (id) on delete cascade,
  name text not null check (char_length(name) between 1 and 120),
  allowed_origins text[] not null default '{}',
  created_at timestamptz not null default now(),
  constraint projects_owner_name_unique unique (owner_id, name)
);

create table public.api_keys (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects (id) on delete cascade,
  key_hash text not null unique check (key_hash ~ '^[0-9a-f]{64}$'),
  prefix text not null check (char_length(prefix) between 8 and 32),
  last_used_at timestamptz,
  revoked_at timestamptz,
  created_at timestamptz not null default now()
);

create index api_keys_project_id_idx on public.api_keys (project_id);

create table public.bindings (
  project_id uuid not null references public.projects (id) on delete cascade,
  session_id uuid not null,
  jkt text not null check (jkt ~ '^[A-Za-z0-9_-]{43}$'),
  created_at timestamptz not null default now(),
  last_seen_at timestamptz not null default now(),
  revoked_at timestamptz,
  primary key (project_id, session_id)
);

create table public.events (
  id uuid primary key default gen_random_uuid(),
  project_id uuid not null references public.projects (id) on delete cascade,
  session_id uuid,
  type text not null check (type in ('request_verified', 'request_blocked', 'relogin_required')),
  reason_code text check (reason_code is null or reason_code in (
    'PROOF_MISSING',
    'PROOF_MALFORMED',
    'PROOF_TYPE_REJECTED',
    'PROOF_ALGORITHM_REJECTED',
    'PROOF_BAD_SIG',
    'PROOF_KEY_MISMATCH',
    'PROOF_METHOD_MISMATCH',
    'PROOF_URL_MISMATCH',
    'PROOF_TOKEN_MISMATCH',
    'PROOF_STALE',
    'PROOF_NONCE_REQUIRED',
    'PROOF_REPLAY',
    'PROOF_REPLAY_STORE_UNAVAILABLE'
  )),
  ip_prefix cidr check (
    ip_prefix is null
    or (family(ip_prefix) = 4 and masklen(ip_prefix) <= 24)
    or (family(ip_prefix) = 6 and masklen(ip_prefix) <= 48)
  ),
  ua_family text check (ua_family is null or ua_family in ('Chrome', 'Edge', 'Firefox', 'Safari', 'Other')),
  created_at timestamptz not null default now(),
  constraint events_block_reason_required check (type <> 'request_blocked' or reason_code is not null)
);

create index events_project_created_at_idx on public.events (project_id, created_at desc);

alter table public.projects enable row level security;
alter table public.api_keys enable row level security;
alter table public.bindings enable row level security;
alter table public.events enable row level security;

revoke all on public.projects, public.api_keys, public.bindings, public.events from public, anon, authenticated;
revoke all on public.projects, public.api_keys, public.bindings, public.events from service_role;
grant select, insert, update on public.projects to service_role;
grant select, insert, update on public.api_keys to service_role;
grant select, insert on public.bindings to service_role;
grant select, insert on public.events to service_role;

grant select (id, owner_id, name, allowed_origins, created_at) on public.projects to authenticated;
grant insert (owner_id, name, allowed_origins) on public.projects to authenticated;
grant update (name, allowed_origins) on public.projects to authenticated;

create policy projects_select_own
  on public.projects for select to authenticated
  using (owner_id = (select auth.uid()));
create policy projects_insert_own
  on public.projects for insert to authenticated
  with check (owner_id = (select auth.uid()));
create policy projects_update_own
  on public.projects for update to authenticated
  using (owner_id = (select auth.uid()))
  with check (owner_id = (select auth.uid()));

grant select (id, project_id, prefix, last_used_at, revoked_at, created_at) on public.api_keys to authenticated;
create policy api_keys_select_own_project
  on public.api_keys for select to authenticated
  using (exists (
    select 1 from public.projects p
    where p.id = api_keys.project_id and p.owner_id = (select auth.uid())
  ));

grant select (project_id, session_id, jkt, created_at, last_seen_at, revoked_at) on public.bindings to authenticated;
create policy bindings_select_own_project
  on public.bindings for select to authenticated
  using (exists (
    select 1 from public.projects p
    where p.id = bindings.project_id and p.owner_id = (select auth.uid())
  ));

grant select (id, project_id, session_id, type, reason_code, ip_prefix, ua_family, created_at)
  on public.events to authenticated;
create policy events_select_own_project
  on public.events for select to authenticated
  using (exists (
    select 1 from public.projects p
    where p.id = events.project_id and p.owner_id = (select auth.uid())
  ));

create function public.delete_expired_tether_events()
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  deleted_count bigint;
begin
  delete from public.events where created_at < now() - interval '30 days';
  get diagnostics deleted_count = row_count;
  return deleted_count;
end;
$$;

revoke all on function public.delete_expired_tether_events() from public, anon, authenticated;
grant execute on function public.delete_expired_tether_events() to service_role;

comment on column public.api_keys.key_hash is 'SHA-256 hex digest of a high-entropy API key; raw keys are never stored.';
comment on column public.events.ip_prefix is 'Optional truncated network prefix only; never store a full client IP address.';
comment on column public.events.ua_family is 'Allowlisted browser family only; never store the raw User-Agent header.';
