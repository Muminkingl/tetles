begin;

select plan(11);

insert into auth.users (id, aud, role, email, encrypted_password, created_at, updated_at)
values ('30000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'rotation@example.test', '', now(), now())
on conflict (id) do nothing;

insert into public.projects (id, owner_id, name)
values ('30000000-0000-4000-8000-000000000010', '30000000-0000-4000-8000-000000000001', 'Rotation test')
on conflict (id) do nothing;

insert into public.bindings (project_id, session_id, jkt)
values
  ('30000000-0000-4000-8000-000000000010', '30000000-0000-4000-8000-000000000011', repeat('A', 43)),
  ('30000000-0000-4000-8000-000000000010', '30000000-0000-4000-8000-000000000012', repeat('B', 43)),
  ('30000000-0000-4000-8000-000000000010', '30000000-0000-4000-8000-000000000013', repeat('D', 43))
on conflict (project_id, session_id) do nothing;

create temporary table rotation_test_state (
  issued_at timestamptz not null,
  expires_at timestamptz not null
) on commit drop;
insert into rotation_test_state values (
  date_trunc('second', clock_timestamp()),
  date_trunc('second', clock_timestamp()) + interval '5 minutes'
);

create temporary table rotation_test_results (result jsonb not null) on commit drop;
insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000011',
  repeat('A', 43),
  '30000000-0000-4000-8000-000000000101',
  (select expires_at from rotation_test_state),
  '30000000-0000-4000-8000-000000000102',
  (select issued_at from rotation_test_state),
  (select expires_at from rotation_test_state)
);

select is((select result->>'status' from rotation_test_results), 'rotated', 'first use rotates the ticket');

truncate rotation_test_results;
insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000011',
  repeat('A', 43),
  '30000000-0000-4000-8000-000000000101',
  (select expires_at from rotation_test_state),
  '30000000-0000-4000-8000-000000000103',
  (select issued_at from rotation_test_state),
  (select expires_at from rotation_test_state)
);

select is((select result->>'status' from rotation_test_results), 'retry', 'same-key duplicate inside grace is an idempotent retry');
select is((select result#>>'{token,tokenId}' from rotation_test_results), '30000000-0000-4000-8000-000000000102', 'retry returns the original replacement ticket');

update public.tether_refresh_tokens
   set consumed_at = clock_timestamp() - interval '11 seconds'
 where project_id = '30000000-0000-4000-8000-000000000010'
   and session_id = '30000000-0000-4000-8000-000000000011'
   and token_id = '30000000-0000-4000-8000-000000000101';

truncate rotation_test_results;
insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000011',
  repeat('A', 43),
  '30000000-0000-4000-8000-000000000101',
  (select expires_at from rotation_test_state),
  '30000000-0000-4000-8000-000000000104',
  date_trunc('second', clock_timestamp()),
  date_trunc('second', clock_timestamp()) + interval '5 minutes'
);

select is((select result->>'status' from rotation_test_results), 'reuse', 'reuse after the grace period is rejected');
select ok((select revoked_at is not null from public.bindings
  where project_id = '30000000-0000-4000-8000-000000000010'
    and session_id = '30000000-0000-4000-8000-000000000011'), 'later reuse revokes the binding');
select is((select count(*)::integer from public.events
  where project_id = '30000000-0000-4000-8000-000000000010'
    and session_id = '30000000-0000-4000-8000-000000000011'
    and reason_code = 'REFRESH_REUSE'), 1, 'later reuse writes one REFRESH_REUSE event');

truncate rotation_test_results;
insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000012',
  repeat('C', 43),
  null,
  null,
  '30000000-0000-4000-8000-000000000105',
  date_trunc('second', clock_timestamp()),
  date_trunc('second', clock_timestamp()) + interval '5 minutes'
);

select is((select result->>'status' from rotation_test_results), 'key-mismatch', 'a proof from a different key cannot rotate a session');
select ok((select revoked_at is null from public.bindings
  where project_id = '30000000-0000-4000-8000-000000000010'
    and session_id = '30000000-0000-4000-8000-000000000012'), 'a rejected different key does not cause a denial-of-service revocation');

insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000013',
  repeat('D', 43),
  null,
  null,
  '30000000-0000-4000-8000-000000000201',
  (select issued_at from rotation_test_state),
  (select expires_at from rotation_test_state)
);

select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000013',
  repeat('D', 43),
  '30000000-0000-4000-8000-000000000201',
  (select expires_at from rotation_test_state),
  '30000000-0000-4000-8000-000000000202',
  (select issued_at from rotation_test_state),
  (select expires_at from rotation_test_state)
);

truncate rotation_test_results;
insert into rotation_test_results
select public.rotate_tether_cookie(
  '30000000-0000-4000-8000-000000000010',
  '30000000-0000-4000-8000-000000000001',
  '30000000-0000-4000-8000-000000000013',
  repeat('C', 43),
  '30000000-0000-4000-8000-000000000201',
  (select expires_at from rotation_test_state),
  '30000000-0000-4000-8000-000000000203',
  (select issued_at from rotation_test_state),
  (select expires_at from rotation_test_state)
);

select is((select result->>'status' from rotation_test_results), 'reuse', 'a different key reusing a consumed ticket is revoked immediately');
select ok((select revoked_at is not null from public.bindings
  where project_id = '30000000-0000-4000-8000-000000000010'
    and session_id = '30000000-0000-4000-8000-000000000013'), 'different-key reuse revokes the binding');
select is((select count(*)::integer from public.events
  where project_id = '30000000-0000-4000-8000-000000000010'
    and session_id = '30000000-0000-4000-8000-000000000013'
    and reason_code = 'REFRESH_REUSE'), 1, 'different-key reuse is audited');

select * from finish();
rollback;
