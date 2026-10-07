create table public.plans (
  id text primary key check (id in ('free', 'team', 'business', 'enterprise')),
  name text not null,
  limits jsonb not null check (jsonb_typeof(limits) = 'object'),
  features text[] not null default '{}',
  created_at timestamptz not null default now()
);

insert into public.plans (id, name, limits, features)
values
  ('free', 'Free', '{"mpu":500,"projects":1,"retention_days":7,"seats":1}', '{"policies"}'),
  ('team', 'Team', '{"mpu":10000,"projects":5,"retention_days":90,"seats":5}', '{"alerts","shared_store","policies","webhooks","retention"}'),
  ('business', 'Business', '{"mpu":100000,"projects":25,"retention_days":365,"seats":20}', '{"alerts","shared_store","policies","webhooks","audit_exports","retention"}'),
  ('enterprise', 'Enterprise', '{"mpu":0,"projects":0,"retention_days":0,"seats":0}', '{"alerts","shared_store","policies","webhooks","audit_exports","retention"}')
on conflict (id) do update
  set name = excluded.name,
      limits = excluded.limits,
      features = excluded.features;

alter table public.projects
  add column plan_id text not null default 'free' references public.plans (id),
  add column license_state text not null default 'active'
    check (license_state in ('trial', 'active', 'grace', 'limited', 'suspended', 'revoked')),
  add column trial_started_at timestamptz,
  add column trial_ends_at timestamptz,
  add column grace_ends_at timestamptz;

alter table public.api_keys
  add column env text not null default 'production'
    check (env in ('production', 'development'));

create table public.licenses_issued (
  id uuid primary key default gen_random_uuid(),
  jti uuid not null unique,
  project_id uuid not null references public.projects (id) on delete cascade,
  key_id uuid not null references public.api_keys (id) on delete cascade,
  kid text not null check (char_length(kid) between 1 and 128),
  env text not null check (env in ('production', 'development')),
  issued_at timestamptz not null,
  exp timestamptz not null,
  constraint licenses_issued_exp_after_issue check (exp > issued_at)
);
create index licenses_issued_project_issued_idx
  on public.licenses_issued (project_id, issued_at desc);

create table public.signing_keys (
  kid text primary key check (char_length(kid) between 1 and 128),
  public_jwk jsonb not null check (jsonb_typeof(public_jwk) = 'object'),
  status text not null check (status in ('active', 'retiring', 'retired')),
  created_at timestamptz not null default now()
);

create table public.license_rate_limits (
  bucket_hash text primary key check (bucket_hash ~ '^[0-9a-f]{64}$'),
  window_started_at timestamptz not null,
  request_count integer not null check (request_count > 0),
  updated_at timestamptz not null default now()
);

alter table public.plans enable row level security;
alter table public.licenses_issued enable row level security;
alter table public.signing_keys enable row level security;
alter table public.license_rate_limits enable row level security;

revoke all on public.plans, public.licenses_issued, public.signing_keys, public.license_rate_limits
  from public, anon, authenticated, service_role;
grant select on public.plans to service_role;
grant select, insert on public.licenses_issued to service_role;
grant select, insert, update on public.signing_keys to service_role;

create function public.consume_tether_license_rate_limit(p_bucket_hash text, p_limit integer)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_count integer;
begin
  if p_bucket_hash is null or p_bucket_hash !~ '^[0-9a-f]{64}$'
    or p_limit is null or p_limit < 1 or p_limit > 10000
  then
    raise exception 'invalid license rate limit request';
  end if;

  insert into public.license_rate_limits as current_limit
    (bucket_hash, window_started_at, request_count, updated_at)
  values (p_bucket_hash, v_now, 1, v_now)
  on conflict (bucket_hash) do update
    set window_started_at = case
          when current_limit.window_started_at <= v_now - interval '1 minute'
            then v_now
          else current_limit.window_started_at
        end,
        request_count = case
          when current_limit.window_started_at <= v_now - interval '1 minute'
            then 1
          else current_limit.request_count + 1
        end,
        updated_at = v_now
  returning request_count into v_count;

  return v_count <= p_limit;
end;
$$;

revoke all on function public.consume_tether_license_rate_limit(text, integer)
  from public, anon, authenticated;
grant execute on function public.consume_tether_license_rate_limit(text, integer)
  to service_role;

create or replace function public.delete_expired_tether_events()
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
  delete from public.tether_refresh_tokens where expires_at < now() - interval '1 day';
  delete from public.license_rate_limits where window_started_at < now() - interval '2 days';
  return deleted_count;
end;
$$;

comment on column public.api_keys.env is 'Runtime environment this high-entropy license API key may activate.';
comment on table public.licenses_issued is 'Audit metadata only; signed license tokens and raw API keys are never stored.';
comment on table public.signing_keys is 'Public ES256 JWKS material only; the signing private key exists only in server environment secrets.';
