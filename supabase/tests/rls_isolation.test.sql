begin;

select plan(12);

insert into auth.users (id, aud, role, email, encrypted_password, created_at, updated_at)
values
  ('10000000-0000-4000-8000-000000000001', 'authenticated', 'authenticated', 'rls-a@example.test', '', now(), now()),
  ('20000000-0000-4000-8000-000000000002', 'authenticated', 'authenticated', 'rls-b@example.test', '', now(), now())
on conflict (id) do nothing;

insert into public.projects (id, owner_id, name)
values
  ('10000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000001', 'RLS A'),
  ('20000000-0000-4000-8000-000000000020', '20000000-0000-4000-8000-000000000002', 'RLS B')
on conflict (id) do nothing;

insert into public.api_keys (id, project_id, key_hash, prefix)
values
  ('10000000-0000-4000-8000-000000000011', '10000000-0000-4000-8000-000000000010', repeat('a', 64), 'tth_live_a'),
  ('20000000-0000-4000-8000-000000000021', '20000000-0000-4000-8000-000000000020', repeat('b', 64), 'tth_live_b')
on conflict (id) do nothing;

insert into public.bindings (project_id, session_id, jkt)
values
  ('10000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000012', repeat('A', 43)),
  ('20000000-0000-4000-8000-000000000020', '20000000-0000-4000-8000-000000000022', repeat('B', 43))
on conflict (project_id, session_id) do nothing;

insert into public.events (id, project_id, session_id, type, reason_code)
values
  ('10000000-0000-4000-8000-000000000013', '10000000-0000-4000-8000-000000000010', '10000000-0000-4000-8000-000000000012', 'request_blocked', 'PROOF_REPLAY'),
  ('20000000-0000-4000-8000-000000000023', '20000000-0000-4000-8000-000000000020', '20000000-0000-4000-8000-000000000022', 'request_blocked', 'PROOF_STALE')
on conflict (id) do nothing;

set local role authenticated;
select set_config('request.jwt.claim.sub', '10000000-0000-4000-8000-000000000001', true);
select is((select count(*)::integer from public.projects), 1, 'User A sees only their project');
select is((select count(*)::integer from public.api_keys), 1, 'User A sees only their project key metadata');
select is((select count(*)::integer from public.bindings), 1, 'User A sees only their project bindings');
select is((select count(*)::integer from public.events), 1, 'User A sees only their events');
select is((select count(*)::integer from public.events where project_id = '20000000-0000-4000-8000-000000000020'), 0, 'User A cannot read User B events');

select set_config('request.jwt.claim.sub', '20000000-0000-4000-8000-000000000002', true);
select is((select count(*)::integer from public.projects), 1, 'User B sees only their project');
select is((select count(*)::integer from public.api_keys), 1, 'User B sees only their project key metadata');
select is((select count(*)::integer from public.bindings), 1, 'User B sees only their project bindings');
select is((select count(*)::integer from public.events), 1, 'User B sees only their events');
select is((select count(*)::integer from public.events where project_id = '10000000-0000-4000-8000-000000000010'), 0, 'User B cannot read User A events');
select ok(not has_column_privilege('authenticated', 'public.api_keys', 'key_hash', 'SELECT'), 'Users cannot read API key hashes');
select ok(not has_table_privilege('authenticated', 'public.events', 'INSERT'), 'Users cannot insert audit events');

reset role;
select * from finish();
rollback;
