alter table public.events drop constraint if exists events_reason_code_check;
alter table public.events
  add constraint events_reason_code_check check (reason_code is null or reason_code in (
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
    'PROOF_REPLAY_STORE_UNAVAILABLE',
    'REFRESH_REUSE'
  ));

create table public.tether_refresh_tokens (
  project_id uuid not null,
  session_id uuid not null,
  token_id uuid not null,
  expires_at timestamptz not null,
  consumed_at timestamptz,
  created_at timestamptz not null default now(),
  primary key (project_id, session_id, token_id),
  foreign key (project_id, session_id)
    references public.bindings (project_id, session_id) on delete cascade,
  constraint tether_refresh_tokens_expiry_after_creation check (expires_at > created_at)
);

create unique index tether_refresh_tokens_one_active_per_session_idx
  on public.tether_refresh_tokens (project_id, session_id)
  where consumed_at is null;
create index tether_refresh_tokens_expiry_idx
  on public.tether_refresh_tokens (expires_at);

alter table public.tether_refresh_tokens enable row level security;
revoke all on public.tether_refresh_tokens from public, anon, authenticated, service_role;

create function public.rotate_tether_cookie(
  p_project_id uuid,
  p_user_id uuid,
  p_session_id uuid,
  p_presented_token_id uuid,
  p_presented_expires_at timestamptz,
  p_next_token_id uuid,
  p_next_expires_at timestamptz
)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_binding_revoked_at timestamptz;
  v_inserted_token_id uuid;
  v_consumed_at timestamptz;
begin
  if p_next_token_id is null
    or p_next_expires_at is null
    or p_next_expires_at <= v_now
    or p_next_expires_at > v_now + interval '5 minutes'
    or ((p_presented_token_id is null) <> (p_presented_expires_at is null))
    or (p_presented_expires_at is not null and p_presented_expires_at <= v_now)
  then
    raise exception 'invalid cookie rotation request';
  end if;

  select b.revoked_at
    into v_binding_revoked_at
    from public.bindings as b
    join public.projects as p on p.id = b.project_id
   where b.project_id = p_project_id
     and b.session_id = p_session_id
     and p.owner_id = p_user_id
   for update of b;

  if not found or v_binding_revoked_at is not null then
    return 'revoked';
  end if;

  delete from public.tether_refresh_tokens
   where project_id = p_project_id
     and session_id = p_session_id
     and expires_at < v_now - interval '1 day';

  if p_presented_token_id is not null then
    insert into public.tether_refresh_tokens (
      project_id, session_id, token_id, expires_at, consumed_at
    ) values (
      p_project_id, p_session_id, p_presented_token_id, p_presented_expires_at, v_now
    )
    on conflict (project_id, session_id, token_id) do nothing
    returning token_id into v_inserted_token_id;

    if v_inserted_token_id is null then
      select t.consumed_at
        into v_consumed_at
        from public.tether_refresh_tokens as t
       where t.project_id = p_project_id
         and t.session_id = p_session_id
         and t.token_id = p_presented_token_id
       for update;

      if v_consumed_at is not null then
        update public.bindings
           set revoked_at = coalesce(revoked_at, v_now)
         where project_id = p_project_id
           and session_id = p_session_id;

        update public.tether_refresh_tokens
           set consumed_at = coalesce(consumed_at, v_now)
         where project_id = p_project_id
           and session_id = p_session_id
           and consumed_at is null;

        insert into public.events (project_id, session_id, type, reason_code)
        values (p_project_id, p_session_id, 'request_blocked', 'REFRESH_REUSE');
        return 'reuse';
      end if;

      update public.tether_refresh_tokens
         set consumed_at = v_now
       where project_id = p_project_id
         and session_id = p_session_id
         and token_id = p_presented_token_id;
    end if;
  end if;

  update public.tether_refresh_tokens
     set consumed_at = v_now
   where project_id = p_project_id
     and session_id = p_session_id
     and consumed_at is null;

  insert into public.tether_refresh_tokens (
    project_id, session_id, token_id, expires_at
  ) values (
    p_project_id, p_session_id, p_next_token_id, p_next_expires_at
  );

  return 'rotated';
end;
$$;

revoke all on function public.rotate_tether_cookie(uuid, uuid, uuid, uuid, timestamptz, uuid, timestamptz)
  from public, anon, authenticated;
grant execute on function public.rotate_tether_cookie(uuid, uuid, uuid, uuid, timestamptz, uuid, timestamptz)
  to service_role;

comment on table public.tether_refresh_tokens is
  'Tracks current and consumed signed Tether cookie tickets for one-use rotation and reuse detection.';
comment on function public.rotate_tether_cookie(uuid, uuid, uuid, uuid, timestamptz, uuid, timestamptz) is
  'Atomically rotates a cookie ticket; reuse revokes its binding and writes a REFRESH_REUSE event.';

create or replace function public.delete_expired_tether_events()
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  deleted_event_count bigint;
begin
  delete from public.events where created_at < now() - interval '30 days';
  get diagnostics deleted_event_count = row_count;
  delete from public.tether_refresh_tokens where expires_at < now() - interval '1 day';
  return deleted_event_count;
end;
$$;
