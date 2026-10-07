alter table public.tether_refresh_tokens
  add column issued_at timestamptz not null default now(),
  add column consumed_jkt text check (consumed_jkt is null or consumed_jkt ~ '^[A-Za-z0-9_-]{43}$');

update public.tether_refresh_tokens as t
   set consumed_jkt = b.jkt
  from public.bindings as b
 where b.project_id = t.project_id
   and b.session_id = t.session_id
   and t.consumed_at is not null
   and t.consumed_jkt is null;

drop function if exists public.rotate_tether_cookie(
  uuid, uuid, uuid, uuid, timestamptz, uuid, timestamptz
);

create function public.rotate_tether_cookie(
  p_project_id uuid,
  p_user_id uuid,
  p_session_id uuid,
  p_proof_jkt text,
  p_presented_token_id uuid,
  p_presented_expires_at timestamptz,
  p_next_token_id uuid,
  p_next_issued_at timestamptz,
  p_next_expires_at timestamptz
)
returns jsonb
language plpgsql
security definer
set search_path = ''
as $$
declare
  v_now timestamptz := clock_timestamp();
  v_binding_revoked_at timestamptz;
  v_binding_jkt text;
  v_inserted_token_id uuid;
  v_consumed_at timestamptz;
  v_consumed_jkt text;
  v_active_token_id uuid;
  v_active_issued_at timestamptz;
  v_active_expires_at timestamptz;
begin
  if p_proof_jkt is null or p_proof_jkt !~ '^[A-Za-z0-9_-]{43}$'
    or p_next_token_id is null
    or p_next_issued_at is null
    or p_next_issued_at < v_now - interval '15 seconds'
    or p_next_issued_at > v_now + interval '1 second'
    or p_next_expires_at is null
    or p_next_expires_at <= v_now
    or p_next_expires_at > v_now + interval '5 minutes'
    or p_next_expires_at <= p_next_issued_at
    or p_next_expires_at > p_next_issued_at + interval '5 minutes'
    or ((p_presented_token_id is null) <> (p_presented_expires_at is null))
    or (p_presented_expires_at is not null and
      (p_presented_expires_at <= v_now or p_presented_expires_at > v_now + interval '5 minutes'))
  then
    raise exception 'invalid cookie rotation request';
  end if;

  select b.revoked_at, b.jkt
    into v_binding_revoked_at, v_binding_jkt
    from public.bindings as b
    join public.projects as p on p.id = b.project_id
   where b.project_id = p_project_id
     and b.session_id = p_session_id
     and p.owner_id = p_user_id
   for update of b;

  if not found or v_binding_revoked_at is not null then
    return jsonb_build_object('status', 'revoked');
  end if;
  delete from public.tether_refresh_tokens
   where project_id = p_project_id
     and session_id = p_session_id
     and expires_at < v_now - interval '1 day';

  if v_binding_jkt <> p_proof_jkt then
    if p_presented_token_id is not null then
      select t.consumed_at, t.consumed_jkt
        into v_consumed_at, v_consumed_jkt
        from public.tether_refresh_tokens as t
       where t.project_id = p_project_id
         and t.session_id = p_session_id
         and t.token_id = p_presented_token_id
       for update;

      if found and v_consumed_at is not null and v_consumed_jkt is distinct from p_proof_jkt then
        update public.bindings
           set revoked_at = coalesce(revoked_at, v_now)
         where project_id = p_project_id
           and session_id = p_session_id;

        update public.tether_refresh_tokens
           set consumed_at = coalesce(consumed_at, v_now),
               consumed_jkt = coalesce(consumed_jkt, p_proof_jkt)
         where project_id = p_project_id
           and session_id = p_session_id
           and consumed_at is null;

        insert into public.events (project_id, session_id, type, reason_code)
        values (p_project_id, p_session_id, 'request_blocked', 'REFRESH_REUSE');
        return jsonb_build_object('status', 'reuse');
      end if;
    end if;
    return jsonb_build_object('status', 'key-mismatch');
  end if;

  if p_presented_token_id is not null then
    insert into public.tether_refresh_tokens (
      project_id, session_id, token_id, expires_at, consumed_at, consumed_jkt
    ) values (
      p_project_id, p_session_id, p_presented_token_id, p_presented_expires_at, v_now, p_proof_jkt
    )
    on conflict (project_id, session_id, token_id) do nothing
    returning token_id into v_inserted_token_id;

    if v_inserted_token_id is null then
      select t.consumed_at, t.consumed_jkt
        into v_consumed_at, v_consumed_jkt
        from public.tether_refresh_tokens as t
       where t.project_id = p_project_id
         and t.session_id = p_session_id
         and t.token_id = p_presented_token_id
       for update;

      if v_consumed_at is not null then
        if v_consumed_at >= v_now - interval '10 seconds'
          and v_consumed_jkt = p_proof_jkt
        then
          select t.token_id, t.issued_at, t.expires_at
            into v_active_token_id, v_active_issued_at, v_active_expires_at
            from public.tether_refresh_tokens as t
           where t.project_id = p_project_id
             and t.session_id = p_session_id
             and t.consumed_at is null
             and t.expires_at > v_now
           for update;

          if found then
            return jsonb_build_object(
              'status', 'retry',
              'token', jsonb_build_object(
                'tokenId', v_active_token_id,
                'issuedAt', floor(extract(epoch from v_active_issued_at))::bigint,
                'expiresAt', floor(extract(epoch from v_active_expires_at))::bigint
              )
            );
          end if;
        end if;

        update public.bindings
           set revoked_at = coalesce(revoked_at, v_now)
         where project_id = p_project_id
           and session_id = p_session_id;

        update public.tether_refresh_tokens
           set consumed_at = coalesce(consumed_at, v_now),
               consumed_jkt = coalesce(consumed_jkt, p_proof_jkt)
         where project_id = p_project_id
           and session_id = p_session_id
           and consumed_at is null;

        insert into public.events (project_id, session_id, type, reason_code)
        values (p_project_id, p_session_id, 'request_blocked', 'REFRESH_REUSE');
        return jsonb_build_object('status', 'reuse');
      end if;

      update public.tether_refresh_tokens
         set consumed_at = v_now, consumed_jkt = p_proof_jkt
       where project_id = p_project_id
         and session_id = p_session_id
         and token_id = p_presented_token_id;
    end if;
  end if;

  update public.tether_refresh_tokens
     set consumed_at = coalesce(consumed_at, v_now),
         consumed_jkt = coalesce(consumed_jkt, p_proof_jkt)
   where project_id = p_project_id
     and session_id = p_session_id
     and consumed_at is null;

  insert into public.tether_refresh_tokens (
    project_id, session_id, token_id, issued_at, expires_at
  ) values (
    p_project_id, p_session_id, p_next_token_id, p_next_issued_at, p_next_expires_at
  );

  return jsonb_build_object('status', 'rotated');
end;
$$;

revoke all on function public.rotate_tether_cookie(
  uuid, uuid, uuid, text, uuid, timestamptz, uuid, timestamptz, timestamptz
) from public, anon, authenticated;
grant execute on function public.rotate_tether_cookie(
  uuid, uuid, uuid, text, uuid, timestamptz, uuid, timestamptz, timestamptz
) to service_role;

comment on function public.rotate_tether_cookie(
  uuid, uuid, uuid, text, uuid, timestamptz, uuid, timestamptz, timestamptz
) is
  'Atomically rotates a cookie ticket. Same-key retries within ten seconds receive the currently active ticket; later same-key reuse or a different-key replay of a consumed ticket revokes the binding and writes REFRESH_REUSE.';
