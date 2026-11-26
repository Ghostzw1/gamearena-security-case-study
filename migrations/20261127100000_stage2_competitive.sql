-- Stage 2: competitive core (docs/MASTER-DIRECTIVE.md §05, §09, §14.5, §15;
-- plan in docs/AUDIT-2026-11-26.md).
--
-- 1. audit_log: every host/admin change to tournaments, entries, staff,
--    results, check-ins and disputes is written by triggers in the same
--    transaction (CLAUDE.md: "Every admin, host or moderator change writes an
--    audit_log row in the same transaction"). Admins read everything; hosts
--    read their own tournaments' rows. Nobody writes it directly.
-- 2. Full status machine: draft · upcoming · open · closed · checkin · live ·
--    completed · cancelled ("Full" is derived from the counts). Drafts are
--    hidden from players. Host moves:
--      draft    → upcoming | open | cancelled
--      upcoming → draft | open | live | cancelled
--      open     → upcoming | closed | checkin | live | completed | cancelled
--      closed   → open | checkin | live | cancelled
--      checkin  → closed | live | cancelled
--      live     → completed
--    completed and cancelled are final for hosts; admins can correct anything.
-- 3. Check-in: tournament_entries.checked_in_at, set by the player
--    (check_in) while check-in is open, or by the host (host_check_in).
-- 4. Result disputes: a registered player questions a result with a reason;
--    the host or an admin upholds or rejects it with a written answer.
--    Withdrawals stay deletions (so a withdrawn entry can never grant access
--    to rooms or chats), and the audit log keeps the record ("entry.withdrawn").

-- 1. Audit log ---------------------------------------------------------------
create table public.audit_log (
  id bigint generated always as identity primary key,
  at timestamptz not null default now(),
  actor uuid,
  actor_admin boolean not null default false,
  action text not null,
  -- No foreign key on purpose: the record must outlive a deleted tournament.
  tournament_id uuid,
  target uuid,
  detail jsonb not null default '{}'::jsonb,
  constraint audit_log_action_check check (action ~ '^[a-z_]+\.[a-z_]+$')
);
create index audit_log_tournament_idx on public.audit_log (tournament_id, at desc);
create index audit_log_at_idx on public.audit_log (at desc);

alter table public.audit_log enable row level security;
revoke all on table public.audit_log from public, anon, authenticated;
grant select on table public.audit_log to authenticated;
create policy "Admins see the whole audit log, hosts their tournaments"
  on public.audit_log for select to authenticated
  using (private.is_admin() or (tournament_id is not null and private.is_host(tournament_id)));

create function private.audit(p_action text, p_tournament uuid, p_target uuid, p_detail jsonb)
returns void
language sql
security definer
set search_path = ''
as $$
  insert into public.audit_log (actor, actor_admin, action, tournament_id, target, detail)
  values ((select auth.uid()), private.is_admin(), p_action, p_tournament, p_target, coalesce(p_detail, '{}'::jsonb));
$$;
revoke all on function private.audit(text, uuid, uuid, jsonb) from public;

create function private.audit_tournaments()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  changes jsonb := '{}'::jsonb;
begin
  if tg_op = 'INSERT' then
    perform private.audit('tournament.created', new.id, null,
      jsonb_build_object('kind', new.kind, 'name', new.name, 'status', new.status));
    return new;
  end if;
  if tg_op = 'DELETE' then
    perform private.audit('tournament.deleted', old.id, null,
      jsonb_build_object('kind', old.kind, 'name', old.name, 'status', old.status));
    return old;
  end if;
  if new.status is distinct from old.status then changes := changes || jsonb_build_object('status', jsonb_build_array(old.status, new.status)); end if;
  if new.sponsor_name is distinct from old.sponsor_name then changes := changes || jsonb_build_object('sponsor_name', jsonb_build_array(old.sponsor_name, new.sponsor_name)); end if;
  if new.sponsor_status is distinct from old.sponsor_status then changes := changes || jsonb_build_object('sponsor_status', jsonb_build_array(old.sponsor_status, new.sponsor_status)); end if;
  if new.entry_fee_usd_cents is distinct from old.entry_fee_usd_cents then changes := changes || jsonb_build_object('entry_fee_usd_cents', jsonb_build_array(old.entry_fee_usd_cents, new.entry_fee_usd_cents)); end if;
  if new.prize_1_usd_cents is distinct from old.prize_1_usd_cents
     or new.prize_2_usd_cents is distinct from old.prize_2_usd_cents
     or new.prize_3_usd_cents is distinct from old.prize_3_usd_cents then
    changes := changes || jsonb_build_object('prizes', jsonb_build_array(
      jsonb_build_array(old.prize_1_usd_cents, old.prize_2_usd_cents, old.prize_3_usd_cents),
      jsonb_build_array(new.prize_1_usd_cents, new.prize_2_usd_cents, new.prize_3_usd_cents)));
  end if;
  if new.max_players is distinct from old.max_players then changes := changes || jsonb_build_object('max_players', jsonb_build_array(old.max_players, new.max_players)); end if;
  if new.starts_at is distinct from old.starts_at then changes := changes || jsonb_build_object('starts_at', jsonb_build_array(old.starts_at, new.starts_at)); end if;
  if new.requires_approval is distinct from old.requires_approval then changes := changes || jsonb_build_object('requires_approval', jsonb_build_array(old.requires_approval, new.requires_approval)); end if;
  if changes <> '{}'::jsonb then
    perform private.audit('tournament.changed', new.id, null, changes);
  end if;
  return new;
end;
$$;
revoke all on function private.audit_tournaments() from public;
create trigger tournaments_audit
  after insert or update or delete on public.tournaments
  for each row execute function private.audit_tournaments();

create function private.audit_entries()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    perform private.audit('entry.registered', new.tournament_id, new.user_id, jsonb_build_object('status', new.status));
  elsif tg_op = 'DELETE' then
    perform private.audit(
      case when old.user_id = (select auth.uid()) then 'entry.withdrawn' else 'entry.removed' end,
      old.tournament_id, old.user_id, jsonb_build_object('status', old.status));
    return old;
  else
    if new.status is distinct from old.status then
      perform private.audit('entry.' || new.status, new.tournament_id, new.user_id, jsonb_build_object('from', old.status));
    end if;
    if new.checked_in_at is distinct from old.checked_in_at then
      perform private.audit(case when new.checked_in_at is null then 'entry.check_in_cleared' else 'entry.checked_in' end,
        new.tournament_id, new.user_id, jsonb_build_object('by_self', new.user_id = (select auth.uid())));
    end if;
  end if;
  return new;
end;
$$;
revoke all on function private.audit_entries() from public;

create function private.audit_staff()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'DELETE' then
    perform private.audit('staff.removed', old.tournament_id, old.user_id, jsonb_build_object('role', old.role));
    return old;
  end if;
  perform private.audit(case when tg_op = 'INSERT' then 'staff.added' else 'staff.changed' end,
    new.tournament_id, new.user_id, jsonb_build_object('role', new.role));
  return new;
end;
$$;
revoke all on function private.audit_staff() from public;
create trigger tournament_staff_audit
  after insert or update or delete on public.tournament_staff
  for each row execute function private.audit_staff();

create function private.audit_results()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  r public.match_results;
begin
  r := case when tg_op = 'DELETE' then old else new end;
  -- Player claims are evidence, not decisions: log what hosts, streamers and
  -- admins do to results.
  if r.reporter_role in ('host', 'streamer') or private.is_admin() then
    perform private.audit(
      case tg_op when 'INSERT' then 'result.saved' when 'UPDATE' then 'result.changed' else 'result.deleted' end,
      r.tournament_id, coalesce(r.squad_id, r.player_id),
      jsonb_build_object('match', r.match_no, 'role', r.reporter_role, 'placement', r.placement, 'kills', r.kills)
        || case when tg_op = 'UPDATE' then jsonb_build_object('was', jsonb_build_array(old.placement, old.kills)) else '{}'::jsonb end);
  end if;
  return r;
end;
$$;
revoke all on function private.audit_results() from public;
create trigger match_results_audit
  after insert or update or delete on public.match_results
  for each row execute function private.audit_results();

-- 2. Status machine ------------------------------------------------------------
alter table public.tournaments drop constraint tournaments_status_check;
alter table public.tournaments add constraint tournaments_status_check
  check (status in ('draft', 'upcoming', 'open', 'closed', 'checkin', 'live', 'completed', 'cancelled'));

create or replace function private.guard_status_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status is distinct from old.status and not private.is_admin()
     and (old.status, new.status) not in (
       ('draft', 'upcoming'), ('draft', 'open'), ('draft', 'cancelled'),
       ('upcoming', 'draft'), ('upcoming', 'open'), ('upcoming', 'live'), ('upcoming', 'cancelled'),
       ('open', 'upcoming'), ('open', 'closed'), ('open', 'checkin'), ('open', 'live'), ('open', 'completed'), ('open', 'cancelled'),
       ('closed', 'open'), ('closed', 'checkin'), ('closed', 'live'), ('closed', 'cancelled'),
       ('checkin', 'closed'), ('checkin', 'live'), ('checkin', 'cancelled'),
       ('live', 'completed')
     ) then
    raise exception 'bad_status_change' using errcode = 'PT409';
  end if;
  return new;
end;
$$;

-- Drafts are only visible to their hosts and admins (visitors can't run the
-- host check, so they get their own simple rule).
alter policy "Everyone can see tournaments and rooms" on public.tournaments
  using (status <> 'draft');
create policy "Hosts and admins see drafts"
  on public.tournaments for select to authenticated
  using (private.is_host(id) or private.is_admin());

-- Players can withdraw until the match starts (also while registration is
-- closed or check-in is open).
alter policy "Players withdraw before the start, hosts remove players" on public.tournament_entries
  using (
    (user_id = (select auth.uid()) and exists (
      select 1 from public.tournaments t where t.id = tournament_id and t.status in ('upcoming', 'open', 'closed', 'checkin')
    ))
    or private.is_host(tournament_id)
    or private.is_admin()
  );

-- Cancelled rooms don't count towards the 3-room limit.
create or replace function private.limit_rooms()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.kind = 'scrim' then
    new.requires_approval := false;
    if (
      select count(*) from public.tournaments
      where created_by = new.created_by and kind = 'scrim' and status not in ('completed', 'cancelled')
    ) >= 3 then
      raise exception 'too_many_rooms' using errcode = 'PT429';
    end if;
  end if;
  return new;
end;
$$;

-- 3. Check-in --------------------------------------------------------------------
alter table public.tournament_entries add column checked_in_at timestamptz;

create trigger tournament_entries_audit
  after insert or update or delete on public.tournament_entries
  for each row execute function private.audit_entries();

-- Player: "I'm here." Only while check-in is open, only for an approved entry.
create function public.check_in(t uuid)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  e public.tournament_entries;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  perform private.hit_limit('check_in', 10, interval '1 minute');
  if not exists (select 1 from public.tournaments where id = t and status = 'checkin') then
    raise exception 'check_in_closed' using errcode = 'PT409';
  end if;
  select * into e from public.tournament_entries where tournament_id = t and user_id = me;
  if e.user_id is null then
    raise exception 'register_first' using errcode = 'PT409';
  end if;
  if e.status <> 'approved' then
    raise exception 'not_approved' using errcode = 'PT409';
  end if;
  if e.checked_in_at is null then
    update public.tournament_entries set checked_in_at = now() where tournament_id = t and user_id = me
    returning checked_in_at into e.checked_in_at;
  end if;
  return e.checked_in_at;
end;
$$;

-- Host or admin: mark a player present (or clear it) during check-in or the match.
create function public.host_check_in(t uuid, player uuid, present boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not (private.is_host(t) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tournaments where id = t and status in ('checkin', 'live')) then
    raise exception 'check_in_closed' using errcode = 'PT409';
  end if;
  update public.tournament_entries
  set checked_in_at = case when present then coalesce(checked_in_at, now()) else null end
  where tournament_id = t and user_id = player and status = 'approved';
  if not found then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
end;
$$;
revoke all on function public.check_in(uuid) from public, anon;
revoke all on function public.host_check_in(uuid, uuid, boolean) from public, anon;
grant execute on function public.check_in(uuid) to authenticated;
grant execute on function public.host_check_in(uuid, uuid, boolean) to authenticated;

-- 4. Result disputes ----------------------------------------------------------------
create table public.result_disputes (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  match_no integer not null,
  squad_id uuid references public.squads (id) on delete cascade,
  player_id uuid references public.profiles (id) on delete cascade,
  raised_by uuid not null references public.profiles (id) on delete cascade,
  reason text not null,
  status text not null default 'open',
  resolution text,
  resolved_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  resolved_at timestamptz,
  constraint result_disputes_match_check check (match_no between 1 and 10),
  constraint result_disputes_subject_check check ((squad_id is null) <> (player_id is null)),
  constraint result_disputes_status_check check (status in ('open', 'upheld', 'rejected')),
  constraint result_disputes_reason_check check (char_length(reason) between 10 and 500 and private.clean_text(reason)),
  constraint result_disputes_resolution_check check (
    resolution is null or (char_length(resolution) between 3 and 500 and private.clean_text(resolution))
  ),
  constraint result_disputes_resolved_check check ((status = 'open') = (resolved_at is null))
);
create unique index result_disputes_one_open_key
  on public.result_disputes (tournament_id, match_no, coalesce(squad_id, player_id), raised_by)
  where status = 'open';
create index result_disputes_tournament_idx on public.result_disputes (tournament_id, status);

alter table public.result_disputes enable row level security;
revoke all on table public.result_disputes from public, anon, authenticated;
grant select on table public.result_disputes to authenticated;
create policy "Players see their own disputes, hosts and admins see the event's"
  on public.result_disputes for select to authenticated
  using (raised_by = (select auth.uid()) or private.is_host(tournament_id) or private.is_admin());

create function private.audit_disputes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if tg_op = 'INSERT' then
    perform private.audit('dispute.opened', new.tournament_id, coalesce(new.squad_id, new.player_id), jsonb_build_object('dispute', new.id, 'match', new.match_no));
  elsif new.status is distinct from old.status then
    perform private.audit('dispute.' || new.status, new.tournament_id, coalesce(new.squad_id, new.player_id), jsonb_build_object('dispute', new.id, 'match', new.match_no));
  end if;
  return new;
end;
$$;
revoke all on function private.audit_disputes() from public;
create trigger result_disputes_audit
  after insert or update on public.result_disputes
  for each row execute function private.audit_disputes();

-- Player: question a result. Registered (approved) players of that event only,
-- once the matches have started; one open dispute per result per player; 5 an hour.
create function public.open_dispute(t uuid, match integer, subject_squad uuid, subject_player uuid, why text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  new_id bigint;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tournaments where id = t and status in ('live', 'completed')) then
    raise exception 'no_results_yet' using errcode = 'PT409';
  end if;
  if not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = me and status = 'approved') then
    raise exception 'players_only' using errcode = '42501';
  end if;
  if (subject_squad is null) = (subject_player is null) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  if subject_squad is not null and not exists (select 1 from public.squads where id = subject_squad and tournament_id = t) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  if subject_player is not null and not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = subject_player) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  perform private.hit_limit('dispute', 5, interval '1 hour');
  insert into public.result_disputes (tournament_id, match_no, squad_id, player_id, raised_by, reason)
  values (t, match, subject_squad, subject_player, me, btrim(why))
  returning id into new_id;
  return new_id;
end;
$$;

-- Host or admin: decide, with a written answer the player can read.
create function public.resolve_dispute(dispute bigint, upheld boolean, answer text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  d public.result_disputes;
begin
  select * into d from public.result_disputes where id = dispute for update;
  if d.id is null then
    raise exception 'unknown_dispute' using errcode = 'PT404';
  end if;
  if not (private.is_host(d.tournament_id) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if d.status <> 'open' then
    raise exception 'already_decided' using errcode = 'PT409';
  end if;
  update public.result_disputes
  set status = case when upheld then 'upheld' else 'rejected' end,
      resolution = btrim(answer), resolved_by = (select auth.uid()), resolved_at = now()
  where id = dispute;
end;
$$;

-- Public: how many open disputes each result has (no names, no reasons).
create function public.open_dispute_counts(t uuid)
returns table (match_no integer, squad_id uuid, player_id uuid, open_disputes integer)
language sql
stable
security definer
set search_path = ''
as $$
  select d.match_no, d.squad_id, d.player_id, count(*)::integer
  from public.result_disputes d
  where d.tournament_id = t and d.status = 'open'
  group by d.match_no, d.squad_id, d.player_id;
$$;
revoke all on function public.open_dispute(uuid, integer, uuid, uuid, text) from public, anon;
revoke all on function public.resolve_dispute(bigint, boolean, text) from public, anon;
revoke all on function public.open_dispute_counts(uuid) from public;
grant execute on function public.open_dispute(uuid, integer, uuid, uuid, text) to authenticated;
grant execute on function public.resolve_dispute(bigint, boolean, text) to authenticated;
grant execute on function public.open_dispute_counts(uuid) to anon, authenticated;

-- Event cards: drafts stay off the public list.
create or replace function public.event_cards()
returns table (
  id uuid, slug text, kind text, name text, season integer, status text, format text, mode text,
  sponsor_name text, sponsor_status text, banner text, starts_at timestamptz, matches integer, max_players integer,
  entry_fee_usd_cents integer, prize_1_usd_cents integer, prize_2_usd_cents integer, prize_3_usd_cents integer,
  players integer, pending integer,
  host_username text, host_avatar text, host_tag text, created_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
  select t.id, t.slug, t.kind, t.name, t.season, t.status, t.format, t.mode,
    t.sponsor_name, t.sponsor_status, t.banner, t.starts_at, t.matches, t.max_players,
    t.entry_fee_usd_cents, t.prize_1_usd_cents, t.prize_2_usd_cents, t.prize_3_usd_cents,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'approved')::integer,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'pending')::integer,
    h.username, h.avatar_id, h.clan_tag, t.created_at
  from public.tournaments t
  left join lateral (
    select p.username, p.avatar_id, p.clan_tag
    from public.tournament_staff s
    join public.profiles p on p.id = s.user_id
    where s.tournament_id = t.id and s.role = 'host'
    order by s.added_at
    limit 1
  ) h on true
  where t.game = 'codm' and t.status <> 'draft'
  order by t.created_at desc
  limit 100;
$$;

-- Reminders also reach events whose registration is closed or check-in is open;
-- cancelled rooms send no alerts.
create or replace function public.queue_due_reminders(cron_secret text)
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
  where t.status in ('upcoming', 'open', 'closed', 'checkin', 'live')
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
  where t.status in ('upcoming', 'open', 'closed', 'checkin', 'live')
    and t.starts_at > now()
    and t.starts_at <= now() + interval '1 hour'
    and coalesce((select np.match_reminders from public.notification_prefs np where np.user_id = e.user_id), true)
    and exists (select 1 from public.push_subscriptions ps where ps.user_id = e.user_id)
  on conflict (user_id, kind, tournament_id) do nothing;
  return true;
end;
$$;

create or replace function public.queue_room_alert(t uuid)
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
  if room.created_at < now() - interval '15 minutes' or room.status in ('completed', 'cancelled') then
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
