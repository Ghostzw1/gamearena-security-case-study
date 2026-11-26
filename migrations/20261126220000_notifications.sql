-- Phone notifications (owner, 2026-11-26).
--   * Match reminders 5 hours and 1 hour before a tournament or room starts,
--     for players who registered (on by default, can be switched off).
--   * Room alerts: "a new room is open" for players who switch them on.
--     Several rooms at once arrive as one alert that lets the player choose.
--
-- Pushes stay empty (no personal data passes through the push services).
-- When one arrives, the phone asks our site for its own messages
-- (take_my_notifications, signed in, RLS), so the text never leaves our site
-- except to that player's phone.
--
-- Timing: Supabase's scheduler (pg_cron + pg_net) knocks on /api/cron/notify
-- every 10 minutes. That knock carries no secret and can't do harm: the site
-- then calls queue_due_reminders with CRON_SECRET, which works at most once
-- every 5 minutes and only queues what is due, once per player and message.

-- 1. What each player wants.
create table public.notification_prefs (
  user_id uuid primary key default auth.uid() references public.profiles (id) on delete cascade,
  match_reminders boolean not null default true,
  room_alerts boolean not null default false,
  updated_at timestamptz not null default now()
);
alter table public.notification_prefs enable row level security;
revoke all on table public.notification_prefs from public, anon, authenticated;
grant select on table public.notification_prefs to authenticated;
grant insert (match_reminders, room_alerts) on table public.notification_prefs to authenticated;
grant update (match_reminders, room_alerts) on table public.notification_prefs to authenticated;

create policy "Players see their own notification settings"
  on public.notification_prefs for select to authenticated
  using (user_id = (select auth.uid()));
create policy "Players create their own notification settings"
  on public.notification_prefs for insert to authenticated
  with check (user_id = (select auth.uid()));
create policy "Players change their own notification settings"
  on public.notification_prefs for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create function private.limit_pref_writes()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user = 'authenticated' then
    perform private.hit_limit('notification_prefs', 20, interval '1 minute');
  end if;
  new.updated_at := now();
  return new;
end;
$$;
revoke all on function private.limit_pref_writes() from public;
create trigger notification_prefs_limit
  before insert or update on public.notification_prefs
  for each row execute function private.limit_pref_writes();

-- 2. The messages.
create table public.notifications (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  kind text not null,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  title text not null,
  body text not null,
  url text not null,
  created_at timestamptz not null default now(),
  pushed_at timestamptz,
  shown_at timestamptz,
  constraint notifications_kind_check check (kind in ('match_5h', 'match_1h', 'room')),
  constraint notifications_text_check check (char_length(title) between 1 and 80 and char_length(body) between 1 and 200),
  constraint notifications_url_check check (char_length(url) <= 200 and url ~ '^/codm/tournaments(/[a-z0-9-]+)?$'),
  constraint notifications_once unique (user_id, kind, tournament_id)
);
create index notifications_unpushed_idx on public.notifications (created_at) where pushed_at is null;
create index notifications_user_idx on public.notifications (user_id, shown_at);

alter table public.notifications enable row level security;
revoke all on table public.notifications from public, anon, authenticated;
grant select on table public.notifications to authenticated;
create policy "Players see their own notifications"
  on public.notifications for select to authenticated
  using (user_id = (select auth.uid()));

-- "Warzone Unleashed S2"
create function private.event_label(t public.tournaments)
returns text
language sql
immutable
set search_path = ''
as $$
  select left(t.name || coalesce(' S' || t.season::text, ''), 60)
$$;

-- 3. Server only: queue the match reminders that are due. Returns false when
--    it already ran in the last 5 minutes (so a flood of knocks does nothing).
create function public.queue_due_reminders(cron_secret text)
returns boolean
language plpgsql
security definer
set search_path = ''
as $$
declare
  last_run timestamptz;
begin
  perform private.check_cron_secret(cron_secret);
  select value::timestamptz into last_run from private.app_settings where key = 'notify_last_run';
  if last_run is not null and last_run > now() - interval '5 minutes' then
    return false;
  end if;
  insert into private.app_settings (key, value) values ('notify_last_run', now()::text)
  on conflict (key) do update set value = excluded.value;

  -- 5 hours before (or as soon as possible after registering late, while
  -- more than an hour is left).
  insert into public.notifications (user_id, kind, tournament_id, title, body, url)
  select e.user_id, 'match_5h', t.id,
    private.event_label(t),
    'Starts at ' || to_char(t.starts_at at time zone 'Africa/Harare', 'HH24:MI') || ' (CAT/SAST), in about '
      || ceil(extract(epoch from t.starts_at - now()) / 3600)::int || ' hours. Get ready.',
    '/codm/tournaments/' || t.slug
  from public.tournaments t
  join public.tournament_entries e on e.tournament_id = t.id and e.status in ('pending', 'approved')
  where t.status in ('upcoming', 'open', 'live')
    and t.starts_at > now() + interval '1 hour'
    and t.starts_at <= now() + interval '5 hours'
    and coalesce((select np.match_reminders from public.notification_prefs np where np.user_id = e.user_id), true)
    and exists (select 1 from public.push_subscriptions ps where ps.user_id = e.user_id)
  on conflict (user_id, kind, tournament_id) do nothing;

  -- 1 hour before.
  insert into public.notifications (user_id, kind, tournament_id, title, body, url)
  select e.user_id, 'match_1h', t.id,
    private.event_label(t),
    'Starts at ' || to_char(t.starts_at at time zone 'Africa/Harare', 'HH24:MI') || ' (CAT/SAST), in '
      || greatest(1, ceil(extract(epoch from t.starts_at - now()) / 60))::int || ' minutes. Open the app for the room details.',
    '/codm/tournaments/' || t.slug
  from public.tournaments t
  join public.tournament_entries e on e.tournament_id = t.id and e.status in ('pending', 'approved')
  where t.status in ('upcoming', 'open', 'live')
    and t.starts_at > now()
    and t.starts_at <= now() + interval '1 hour'
    and coalesce((select np.match_reminders from public.notification_prefs np where np.user_id = e.user_id), true)
    and exists (select 1 from public.push_subscriptions ps where ps.user_id = e.user_id)
  on conflict (user_id, kind, tournament_id) do nothing;
  return true;
end;
$$;

-- 4. Server only: the phones that have new messages. Marks them sent, so
--    each message causes one push at most. Old unsent ones are skipped.
create function public.take_due_pushes(cron_secret text)
returns table (push_endpoint text)
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.check_cron_secret(cron_secret);
  return query
    with due as (
      update public.notifications n
      set pushed_at = now()
      where n.pushed_at is null and n.created_at > now() - interval '6 hours'
      returning n.user_id
    )
    select distinct ps.endpoint
    from public.push_subscriptions ps
    where ps.user_id in (select user_id from due);
end;
$$;

-- 5. Player (the phone, signed in): my new messages. Marks them shown.
create function public.take_my_notifications()
returns table (kind text, title text, body text, url text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := auth.uid();
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  perform private.hit_limit('take_notifications', 60, interval '1 minute');
  return query
    with taken as (
      update public.notifications n
      set shown_at = now()
      where n.user_id = me and n.shown_at is null and n.created_at > now() - interval '1 day'
      returning n.kind, n.title, n.body, n.url, n.created_at
    )
    select taken.kind, taken.title, taken.body, taken.url from taken order by taken.created_at desc;
end;
$$;

-- 6. Room creator: tell everyone who wants room alerts. Only for your own
--    room, within 15 minutes of making it, at most 3 times an hour.
create function public.queue_room_alert(t uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := auth.uid();
  room public.tournaments;
  n integer;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  select * into room from public.tournaments where id = t;
  if room.id is null or room.kind <> 'scrim' or room.created_by is distinct from me then
    raise exception 'not_your_room' using errcode = '42501';
  end if;
  if room.created_at < now() - interval '15 minutes' or room.status = 'completed' then
    raise exception 'too_late' using errcode = 'PT409';
  end if;
  perform private.hit_limit('room_alert', 3, interval '1 hour');
  insert into public.notifications (user_id, kind, tournament_id, title, body, url)
  select np.user_id, 'room', room.id,
    'New room: ' || private.event_label(room),
    (case room.mode when 'mp' then 'Multiplayer' else 'Battle royale' end) || ' · '
      || (case room.format when 'solo' then 'Solo' when 'duo' then 'Duos' else 'Squads' end)
      || coalesce(' · starts ' || to_char(room.starts_at at time zone 'Africa/Harare', 'HH24:MI'), '')
      || '. Tap to join and get the room code.',
    '/codm/tournaments/' || room.slug
  from public.notification_prefs np
  where np.room_alerts
    and np.user_id <> me
    and exists (select 1 from public.push_subscriptions ps where ps.user_id = np.user_id)
  on conflict (user_id, kind, tournament_id) do nothing;
  get diagnostics n = row_count;
  return n;
end;
$$;

revoke all on function private.event_label(public.tournaments) from public;
revoke all on function public.queue_due_reminders(text) from public;
revoke all on function public.take_due_pushes(text) from public;
revoke all on function public.take_my_notifications() from public, anon;
revoke all on function public.queue_room_alert(uuid) from public, anon;
-- The scheduled job and the server run without a login (anon); both
-- functions refuse to do anything without the secret.
grant execute on function public.queue_due_reminders(text) to anon, authenticated;
grant execute on function public.take_due_pushes(text) to anon, authenticated;
grant execute on function public.take_my_notifications() to authenticated;
grant execute on function public.queue_room_alert(uuid) to authenticated;

-- 7. The timer: every 10 minutes, knock on the site (Supabase only; skipped
--    where pg_cron isn't available, e.g. the test database).
do $do$
begin
  if exists (select 1 from pg_available_extensions where name = 'pg_cron')
     and exists (select 1 from pg_available_extensions where name = 'pg_net') then
    create extension if not exists pg_cron;
    create extension if not exists pg_net with schema extensions;
    execute $sql$
      select cron.schedule(
        'gamearena-notify',
        '*/10 * * * *',
        $job$select net.http_post(
          url := 'https://gamearena-beige.vercel.app/api/cron/notify',
          headers := '{"Content-Type": "application/json"}'::jsonb,
          body := '{}'::jsonb,
          timeout_milliseconds := 20000
        )$job$
      )
    $sql$;
  end if;
end;
$do$;
