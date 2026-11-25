-- Daily phone reminders (Web Push) for players who haven't registered for
-- the open prize tournament.
--
-- Security model (also in SECURITY.md):
--   * Players only see and delete their own subscriptions. Saving goes
--     through save_push_subscription(), max 5 devices per player.
--   * Endpoints must be on a known push service (Google, Mozilla, Microsoft,
--     Apple). Our server POSTs to these URLs, so anything else would let
--     someone make our server call arbitrary addresses (SSRF).
--   * The daily job doesn't use the service-role key. It calls two functions
--     that check a shared secret; only its SHA-256 hash is stored here, in a
--     private table the API can't reach.
--   * Pushes carry no data: the phone asks our site what to show.

create table private.app_settings (
  key text primary key,
  value text not null
);
alter table private.app_settings enable row level security;
revoke all on table private.app_settings from public, anon, authenticated;

create table public.push_subscriptions (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  endpoint text not null,
  p256dh text not null,
  auth text not null,
  created_at timestamptz not null default now(),
  last_sent_at timestamptz,
  constraint push_subscriptions_endpoint_key unique (endpoint),
  constraint push_subscriptions_endpoint_check check (
    char_length(endpoint) <= 1000
    and endpoint ~ '^https://(fcm\.googleapis\.com|updates\.push\.services\.mozilla\.com|[a-z0-9-]+\.notify\.windows\.com|web\.push\.apple\.com|[a-z0-9-]+\.push\.apple\.com)/[A-Za-z0-9._~:/?#@!$&''()*+,;=%-]+$'
  ),
  constraint push_subscriptions_keys_check check (
    p256dh ~ '^[A-Za-z0-9_-]{80,100}={0,2}$' and auth ~ '^[A-Za-z0-9_-]{16,30}={0,2}$'
  )
);
create index push_subscriptions_user_idx on public.push_subscriptions (user_id);

alter table public.push_subscriptions enable row level security;
revoke all on table public.push_subscriptions from public, anon, authenticated;
grant select (id, endpoint, created_at, last_sent_at) on table public.push_subscriptions to authenticated;
grant delete on table public.push_subscriptions to authenticated;

create policy "Players see their own devices"
  on public.push_subscriptions for select to authenticated
  using (user_id = (select auth.uid()));

create policy "Players remove their own devices"
  on public.push_subscriptions for delete to authenticated
  using (user_id = (select auth.uid()));

-- Save this phone for reminders. If the phone was linked to another account
-- (shared phone), it moves to whoever is signed in now.
create function public.save_push_subscription(push_endpoint text, key_p256dh text, key_auth text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid())) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  if (select count(*) from public.push_subscriptions
      where user_id = (select auth.uid()) and endpoint <> push_endpoint) >= 5 then
    raise exception 'too_many_devices' using errcode = 'PT429';
  end if;
  insert into public.push_subscriptions (user_id, endpoint, p256dh, auth)
  values ((select auth.uid()), push_endpoint, key_p256dh, key_auth)
  on conflict (endpoint) do update
    set user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, last_sent_at = null;
end;
$$;

revoke all on function public.save_push_subscription(text, text, text) from public, anon;
grant execute on function public.save_push_subscription(text, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- The daily job (Vercel Cron → /api/cron/reminders)
-- ---------------------------------------------------------------------------
create function private.check_cron_secret(candidate text)
returns void
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  expected text;
begin
  select value into expected from private.app_settings where key = 'cron_secret_sha256';
  if expected is null
     or candidate is null
     or char_length(candidate) < 32
     or encode(sha256(convert_to(candidate, 'UTF8')), 'hex') <> expected then
    raise exception 'bad_secret' using errcode = '42501';
  end if;
end;
$$;
revoke all on function private.check_cron_secret(text) from public;

-- Devices to remind today: players not registered for the newest open prize
-- tournament, not reminded in the last 20 hours. Marks them as reminded.
create function public.due_push_reminders(cron_secret text)
returns table (push_endpoint text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  open_event uuid;
begin
  perform private.check_cron_secret(cron_secret);
  select t.id into open_event
    from public.tournaments t
    where t.kind = 'tournament' and t.status = 'open'
    order by t.created_at desc
    limit 1;
  if open_event is null then
    return;
  end if;
  return query
    update public.push_subscriptions ps
      set last_sent_at = now()
      where (ps.last_sent_at is null or ps.last_sent_at < now() - interval '20 hours')
        and not exists (
          select 1 from public.tournament_entries e
          where e.tournament_id = open_event and e.user_id = ps.user_id
        )
      returning ps.endpoint;
end;
$$;

-- The push service said this device is gone (404/410): forget it.
create function public.forget_push_subscription(cron_secret text, gone_endpoint text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.check_cron_secret(cron_secret);
  delete from public.push_subscriptions where endpoint = gone_endpoint;
end;
$$;

-- The job runs without a login, as `anon`, so anon may call these two;
-- both refuse to do anything without the secret.
revoke all on function public.due_push_reminders(text) from public;
revoke all on function public.forget_push_subscription(text, text) from public;
grant execute on function public.due_push_reminders(text) to anon;
grant execute on function public.forget_push_subscription(text, text) to anon;
