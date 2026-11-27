-- Social directive v4, Stage 5: competitive integration (v3 Phase 2 items
-- that weren't built yet). Payments stay off.
--
-- 1. Final results. A finished event's results become final when the host or
--    an admin locks them, or by themselves once the dispute window
--    (app_config.dispute_window_hours, default 24) has passed with no open
--    dispute. Final results can't be changed except by an admin with a
--    written reason (audited). Disputes close at the same moment.
--    Monthly boards, profile history and achievements count final results only.
-- 2. Rooms: once anyone has checked in, the room ID and password are shown
--    only to checked-in players (and staff).
-- 3. Match evidence: end-of-match screenshots in a private bucket. Our server
--    checks the file, strips its metadata and computes SHA-256; staff verify
--    it; a public receipt shows the hash, the status, and who verified it (by
--    role) and when. No image is ever public.
-- 4. Penalty log: warning, temporary or permanent ban, disqualification,
--    prize forfeit. Admins only (two-step), audited; players see their own.
-- 5. Review flags for admins (rules only; a human decides, never an automatic ban).
-- 6. Payouts recorded by hand (admins, two-step), a public Winners list with
--    masked references, and the winner can confirm receipt.
-- 7. Team chats: every team in an event gets its own chat automatically.
--
-- Existing completed events: their completion time is taken from their last
-- update, so they become final after the window like any other event.
-- Rollback: drop the objects created here and restore check_match_result,
-- result_board, player_history, player_achievements, the monthly boards and
-- the room policy from their previous migrations.

-- 1. Final results ------------------------------------------------------------------
alter table public.app_config
  add column dispute_window_hours integer not null default 24,
  add constraint app_config_dispute_window_check check (dispute_window_hours between 1 and 168);

alter table public.tournaments
  add column completed_at timestamptz,
  add column results_locked_at timestamptz,
  add column results_locked_by uuid references public.profiles (id) on delete set null;

alter table public.tournaments disable trigger user;
update public.tournaments set completed_at = updated_at where status = 'completed';
alter table public.tournaments enable trigger user;

-- completed_at and the lock are set by the database only.
create function private.guard_result_lock_fields()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status = 'completed' and old.status is distinct from 'completed' then
    new.completed_at := now();
  elsif new.status <> 'completed' then
    new.completed_at := null;
  else
    new.completed_at := old.completed_at;
  end if;
  if coalesce(current_setting('ga.lock_results', true), '') <> 'on' then
    new.results_locked_at := case when new.status = 'completed' then old.results_locked_at end;
    new.results_locked_by := case when new.status = 'completed' then old.results_locked_by end;
  end if;
  return new;
end;
$$;
revoke all on function private.guard_result_lock_fields() from public;
create trigger tournaments_result_lock_fields
  before update on public.tournaments
  for each row execute function private.guard_result_lock_fields();

create function private.dispute_window() returns interval
language sql stable security definer set search_path = ''
as $$
  select make_interval(hours => coalesce((select c.dispute_window_hours from public.app_config c limit 1), 24));
$$;
revoke all on function private.dispute_window() from public;

create function private.results_final(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tournaments x
    where x.id = t and x.status = 'completed'
      and (x.results_locked_at is not null
           or (x.completed_at <= now() - private.dispute_window()
               and not exists (select 1 from public.result_disputes d where d.tournament_id = t and d.status = 'open')))
  );
$$;
revoke all on function private.results_final(uuid) from public;
grant execute on function private.results_final(uuid) to anon, authenticated;

-- Where an event's results stand (for the event page).
create function public.results_state(t uuid)
returns table (final boolean, locked_at timestamptz, completed_at timestamptz, window_ends_at timestamptz, open_disputes integer)
language sql
stable
security definer
set search_path = ''
as $$
  select private.results_final(x.id), x.results_locked_at, x.completed_at,
    x.completed_at + private.dispute_window(),
    (select count(*) from public.result_disputes d where d.tournament_id = x.id and d.status = 'open')::integer
  from public.tournaments x
  where x.id = t and x.status <> 'draft';
$$;

-- Host (after the dispute window) or admin (any time after the event ends):
-- lock the results. Open disputes must be answered first.
create function public.lock_results(t uuid)
returns timestamptz
language plpgsql
security definer
set search_path = ''
as $$
declare
  x public.tournaments;
begin
  select * into x from public.tournaments where id = t;
  if x.id is null or not (private.is_host(t) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if x.status <> 'completed' then
    raise exception 'not_finished' using errcode = 'PT409';
  end if;
  if x.results_locked_at is not null then
    return x.results_locked_at;
  end if;
  if exists (select 1 from public.result_disputes d where d.tournament_id = t and d.status = 'open') then
    raise exception 'open_disputes' using errcode = 'PT409';
  end if;
  if not private.is_admin() and x.completed_at > now() - private.dispute_window() then
    raise exception 'dispute_window_open' using errcode = 'PT409';
  end if;
  perform set_config('ga.lock_results', 'on', true);
  update public.tournaments set results_locked_at = now(), results_locked_by = (select auth.uid()) where id = t;
  perform set_config('ga.lock_results', '', true);
  perform private.audit('results.locked', t, null, '{}'::jsonb);
  return now();
end;
$$;

-- Final results only change through an admin, with a reason.
create or replace function private.check_match_result()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  tour public.tournaments;
  who text;
begin
  select * into tour from public.tournaments where id = new.tournament_id;
  if new.match_no > tour.matches then
    raise exception 'no_such_match' using errcode = 'PT422';
  end if;
  if private.results_final(new.tournament_id) and coalesce(current_setting('ga.result_fix', true), '') <> 'on' then
    raise exception 'results_locked' using errcode = 'PT409';
  end if;

  if private.is_host(new.tournament_id) or private.is_admin() then
    who := 'host';
  elsif private.is_staff(new.tournament_id) then
    who := 'streamer';
  else
    who := 'player';
  end if;

  if not (tour.status = 'live' or (tour.status = 'completed' and who = 'host')) then
    raise exception 'results_closed' using errcode = 'PT409';
  end if;
  if who = 'player' and not private.is_approved_entrant(new.tournament_id) then
    raise exception 'not_approved' using errcode = '42501';
  end if;

  if tour.format = 'solo' then
    if new.player_id is null or not exists (
      select 1 from public.tournament_entries where tournament_id = new.tournament_id and user_id = new.player_id
    ) then
      raise exception 'not_in_tournament' using errcode = 'PT422';
    end if;
    if who = 'player' and new.player_id <> (select auth.uid()) then
      raise exception 'not_your_result' using errcode = '42501';
    end if;
  else
    if new.squad_id is null or not exists (
      select 1 from public.squads where id = new.squad_id and tournament_id = new.tournament_id
    ) then
      raise exception 'unknown_squad' using errcode = 'PT422';
    end if;
    if who = 'player' and not exists (
      select 1 from public.tournament_entries
      where tournament_id = new.tournament_id and user_id = (select auth.uid()) and squad_id = new.squad_id
    ) then
      raise exception 'not_your_result' using errcode = '42501';
    end if;
  end if;

  new.reporter_role := who;
  if tg_op = 'UPDATE' then
    new.updated_at := now();
  end if;
  return new;
end;
$$;

-- Deleting a final result is refused too (unless the event, team or player is
-- itself being deleted).
create function private.guard_final_result_delete()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if coalesce(current_setting('ga.result_fix', true), '') <> 'on'
     and exists (select 1 from public.tournaments where id = old.tournament_id)
     and (old.squad_id is null or exists (select 1 from public.squads where id = old.squad_id))
     and (old.player_id is null or exists (select 1 from public.profiles where id = old.player_id))
     and private.results_final(old.tournament_id) then
    raise exception 'results_locked' using errcode = 'PT409';
  end if;
  return old;
end;
$$;
revoke all on function private.guard_final_result_delete() from public;
create trigger match_results_final_delete
  before delete on public.match_results
  for each row execute function private.guard_final_result_delete();

-- No new disputes once results are final.
create function private.guard_dispute_final()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if private.results_final(new.tournament_id) then
    raise exception 'results_locked' using errcode = 'PT409';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_dispute_final() from public;
create trigger result_disputes_final
  before insert on public.result_disputes
  for each row execute function private.guard_dispute_final();

-- Admin: correct a final result, with a written reason (audited).
create function public.correct_final_result(t uuid, match integer, subject uuid, subject_is_squad boolean, p_placement integer, p_kills integer, reason text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  why text := btrim(reason);
  existing bigint;
begin
  perform private.require_admin();
  if not private.results_final(t) then
    raise exception 'not_final' using errcode = 'PT409';
  end if;
  if why is null or char_length(why) not between 10 and 300 or not private.clean_text(why) then
    raise exception 'reason_required' using errcode = '22023';
  end if;
  perform set_config('ga.result_fix', 'on', true);
  select id into existing from public.match_results
  where tournament_id = t and match_no = match and reporter_id = me
    and coalesce(squad_id, player_id) = subject;
  if existing is null then
    insert into public.match_results (tournament_id, match_no, squad_id, player_id, placement, kills)
    values (t, match, case when subject_is_squad then subject end, case when subject_is_squad then null else subject end, p_placement, p_kills);
  else
    update public.match_results set placement = p_placement, kills = p_kills where id = existing;
  end if;
  perform set_config('ga.result_fix', '', true);
  perform private.audit('result.corrected', t, subject,
    jsonb_build_object('match', match, 'placement', p_placement, 'kills', p_kills, 'reason', why));
end;
$$;

-- 2. Penalties first (results need them for disqualifications) --------------------------
alter table public.tournament_entries drop constraint tournament_entries_status_check;
alter table public.tournament_entries
  add constraint tournament_entries_status_check check (status in ('pending', 'approved', 'rejected', 'disqualified'));

create table public.penalty_log (
  id bigint generated always as identity primary key,
  user_id uuid not null references public.profiles (id) on delete cascade,
  kind text not null,
  tournament_id uuid references public.tournaments (id) on delete set null,
  reason text not null,
  issued_by uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  ends_at timestamptz,
  constraint penalty_log_kind_check check (kind in ('warning', 'temp_ban', 'perm_ban', 'disqualification', 'prize_forfeit')),
  constraint penalty_log_reason_check check (char_length(reason) between 5 and 300 and private.clean_text(reason)),
  constraint penalty_log_event_check check (kind not in ('disqualification', 'prize_forfeit') or tournament_id is not null),
  constraint penalty_log_ends_check check ((kind = 'temp_ban') = (ends_at is not null))
);
create index penalty_log_user_idx on public.penalty_log (user_id, created_at desc);
alter table public.penalty_log enable row level security;
revoke all on table public.penalty_log from public, anon, authenticated;
grant select on table public.penalty_log to authenticated;
create policy "Players see their own record; admins see all"
  on public.penalty_log for select to authenticated
  using (user_id = (select auth.uid()) or private.is_admin());

create function public.issue_penalty(player uuid, p_kind text, t uuid, reason text, days integer)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  new_id bigint;
  why text := btrim(reason);
  ends timestamptz := case when p_kind = 'temp_ban' then now() + make_interval(days => days) end;
begin
  perform private.require_admin();
  if not exists (select 1 from public.profiles where id = player) then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
  if p_kind = 'temp_ban' and (days is null or days not between 1 and 365) then
    raise exception 'bad_days' using errcode = '22023';
  end if;
  if p_kind in ('disqualification', 'prize_forfeit')
     and not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = player) then
    raise exception 'not_in_tournament' using errcode = 'PT404';
  end if;
  insert into public.penalty_log (user_id, kind, tournament_id, reason, issued_by, ends_at)
  values (player, p_kind, case when p_kind in ('disqualification', 'prize_forfeit') then t end, why, me, ends)
  returning id into new_id;
  if p_kind in ('temp_ban', 'perm_ban') then
    insert into public.chat_bans (user_id, reason, banned_by, banned_until)
    values (player, left(why, 200), me, ends)
    on conflict (user_id) do update set reason = excluded.reason, banned_by = excluded.banned_by, banned_until = excluded.banned_until;
  elsif p_kind = 'disqualification' then
    update public.tournament_entries set status = 'disqualified', checked_in_at = null where tournament_id = t and user_id = player;
  end if;
  perform private.audit('penalty.issued', case when p_kind in ('disqualification', 'prize_forfeit') then t end, player,
    jsonb_build_object('kind', p_kind, 'penalty', new_id, 'days', days));
  return new_id;
end;
$$;

-- Results of disqualified players (and their teams) don't count.
create or replace function public.result_board(t uuid)
returns table (
  match_no integer, squad_id uuid, player_id uuid, label text,
  placement integer, kills integer, points integer, status text, reports integer, last_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
  with r as (
    select m.match_no, m.squad_id, m.player_id, m.reporter_role, m.placement, m.kills, m.updated_at
    from public.match_results m
    where m.tournament_id = t
      and not exists (
        select 1 from public.tournament_entries e
        where e.tournament_id = t and e.status = 'disqualified'
          and ((m.player_id is not null and e.user_id = m.player_id) or (m.squad_id is not null and e.squad_id = m.squad_id))
      )
  ),
  judged as (
    select
      r.match_no, r.squad_id, r.player_id,
      (array_agg(r.placement order by r.updated_at desc) filter (where r.reporter_role = 'host'))[1] as host_place,
      (array_agg(r.kills order by r.updated_at desc) filter (where r.reporter_role = 'host'))[1] as host_kills,
      count(distinct (r.placement, r.kills)) filter (where r.reporter_role = 'streamer') as streamer_versions,
      min(r.placement) filter (where r.reporter_role = 'streamer') as stream_place,
      min(r.kills) filter (where r.reporter_role = 'streamer') as stream_kills,
      count(distinct (r.placement, r.kills)) as versions,
      count(*) as reports,
      max(r.updated_at) as last_at
    from r
    group by r.match_no, r.squad_id, r.player_id
  ),
  final as (
    select j.*,
      case when j.host_place is not null then j.host_place
           when j.streamer_versions = 1 then j.stream_place end as f_place,
      case when j.host_place is not null then j.host_kills
           when j.streamer_versions = 1 then j.stream_kills end as f_kills
    from judged j
  )
  select
    f.match_no, f.squad_id, f.player_id,
    coalesce(s.name, p.username) as label,
    f.f_place, f.f_kills,
    case when f.f_place is null then 0 else private.placement_points(f.f_place) + f.f_kills end,
    case
      when f.f_place is not null and f.versions = 1 then 'verified'
      when f.f_place is not null then 'check'
      when f.streamer_versions > 1 then 'disputed'
      else 'pending'
    end,
    f.reports::integer,
    f.last_at
  from final f
  left join public.squads s on s.id = f.squad_id
  left join public.profiles p on p.id = f.player_id
  order by f.match_no, 7 desc;
$$;

-- History says whether each event's results are final; achievements count final results only.
drop function public.player_history(uuid);
create function public.player_history(player uuid)
returns table (
  tournament_id uuid, slug text, name text, season integer, kind text, status text, played_at timestamptz,
  team text, rank integer, teams integer, points integer, kills integer, wins integer, matches integer, final boolean
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not private.can_see_details(player) then
    return;
  end if;
  return query
    select t.id, t.slug, t.name, t.season, t.kind, t.status, coalesce(t.starts_at, t.created_at),
      sq.name, st.rank, st.teams, coalesce(st.points, 0), coalesce(st.kills, 0), coalesce(st.wins, 0), coalesce(st.counted, 0),
      private.results_final(t.id)
    from public.tournament_entries e
    join public.tournaments t on t.id = e.tournament_id
    left join public.squads sq on sq.id = e.squad_id
    left join lateral (
      select r.rank, r.teams, r.points, r.kills, r.wins, r.counted
      from (
        select s.squad_id, s.player_id, s.points, s.kills, s.wins, s.counted,
          (row_number() over (order by s.points desc, s.kills desc, s.wins desc))::integer as rank,
          (count(*) over ())::integer as teams
        from public.tournament_standings(t.id) s
        where s.counted > 0
      ) r
      where (e.squad_id is not null and r.squad_id = e.squad_id)
         or (e.squad_id is null and r.player_id = e.user_id)
    ) st on true
    where e.user_id = player and e.status = 'approved' and t.status in ('live', 'completed')
    order by coalesce(t.starts_at, t.created_at) desc;
end;
$$;
revoke all on function public.player_history(uuid) from public;
grant execute on function public.player_history(uuid) to anon, authenticated;

create or replace function public.player_achievements(player uuid)
returns table (code text, earned_at timestamptz, tournament_slug text)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if not private.can_see_details(player) then
    return;
  end if;
  return query
    with h as (select * from public.player_history(player)),
    played as (select * from h where h.matches > 0 and h.final order by h.played_at)
    select 'first_tournament'::text, x.played_at, x.slug
      from (select h.played_at, h.slug from h order by h.played_at limit 1) x
    union all
    select 'first_win', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.final and h.wins > 0 order by h.played_at limit 1) x
    union all
    select 'podium', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.final and h.rank <= 3 and h.teams >= 3 order by h.played_at limit 1) x
    union all
    select 'champion', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.final and h.rank = 1 and h.teams >= 3 order by h.played_at limit 1) x
    union all
    select 'active', x.played_at, x.slug
      from (select p.played_at, p.slug from played p offset 4 limit 1) x
    union all
    select 'contributor', x.created_at, null::text
      from (select i.created_at from public.ideas i where i.user_id = player and i.status in ('planned', 'building', 'released') order by i.created_at limit 1) x;
end;
$$;

-- Monthly boards: events whose results are final, by the month they finished.
create or replace function public.monthly_player_board(board text)
returns table (
  user_id uuid, username text, avatar_id text, clan_tag text,
  points integer, wins integer, team_kills integer, events integer
)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if board not in ('tournament', 'scrim') then
    raise exception 'bad_board' using errcode = '22023';
  end if;
  return query
    with b as (
      select ev.id as tid, rb.*
      from public.tournaments ev
      cross join lateral public.result_board(ev.id) rb
      where ev.kind = board and ev.game = 'codm'
        and private.results_final(ev.id)
        and ev.completed_at >= date_trunc('month', now())
        and rb.placement is not null
    ),
    credits as (
      select coalesce(en.user_id, b.player_id) as uid, b.tid, b.points, b.placement, b.kills
      from b
      left join public.tournament_entries en on en.squad_id = b.squad_id
    )
    select c.uid, p.username, p.avatar_id, p.clan_tag,
      sum(c.points)::integer,
      (count(*) filter (where c.placement = 1))::integer,
      sum(c.kills)::integer,
      count(distinct c.tid)::integer
    from credits c
    join public.profiles p on p.id = c.uid
    group by c.uid, p.username, p.avatar_id, p.clan_tag
    order by 5 desc, 6 desc
    limit 50;
end;
$$;

create or replace function public.monthly_clan_board(board text)
returns table (clan_id uuid, name text, tag text, points integer, wins integer, events integer)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  if board not in ('tournament', 'scrim') then
    raise exception 'bad_board' using errcode = '22023';
  end if;
  return query
    select c.id, c.name, c.tag,
      sum(rb.points)::integer,
      (count(*) filter (where rb.placement = 1))::integer,
      count(distinct ev.id)::integer
    from public.tournaments ev
    cross join lateral public.result_board(ev.id) rb
    join public.squads s on s.id = rb.squad_id
    join public.chat_channels c on c.id = s.clan_id
    where ev.kind = board and ev.game = 'codm'
      and private.results_final(ev.id)
      and ev.completed_at >= date_trunc('month', now())
      and rb.placement is not null
    group by c.id, c.name, c.tag
    order by 4 desc, 5 desc
    limit 50;
end;
$$;

-- 3. Rooms: checked-in players only, once check-in has been used ---------------------
create function private.can_see_room(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_staff(t) or private.is_admin()
    or exists (
      select 1 from public.tournament_entries e
      where e.tournament_id = t and e.user_id = (select auth.uid()) and e.status = 'approved'
        and (e.checked_in_at is not null
             or not exists (select 1 from public.tournament_entries x where x.tournament_id = t and x.checked_in_at is not null))
    );
$$;
revoke all on function private.can_see_room(uuid) from public;
grant execute on function private.can_see_room(uuid) to authenticated;
alter policy "Players in the event and its staff see the room" on public.tournament_rooms
  using (private.can_see_room(tournament_id));

-- 4. Match evidence ----------------------------------------------------------------------
create table public.match_evidence (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  match_no integer not null,
  squad_id uuid references public.squads (id) on delete cascade,
  player_id uuid references public.profiles (id) on delete cascade,
  uploader_id uuid references public.profiles (id) on delete set null,
  path text not null,
  sha256 text not null,
  size_bytes integer not null,
  mime text not null,
  status text not null default 'submitted',
  verified_by uuid references public.profiles (id) on delete set null,
  verified_role text,
  verified_at timestamptz,
  created_at timestamptz not null default now(),
  constraint match_evidence_match_check check (match_no between 1 and 10),
  constraint match_evidence_subject_check check ((squad_id is null) <> (player_id is null)),
  constraint match_evidence_path_check check (path ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}\.(jpg|png|webp)$'),
  constraint match_evidence_path_key unique (path),
  constraint match_evidence_sha_check check (sha256 ~ '^[0-9a-f]{64}$'),
  constraint match_evidence_size_check check (size_bytes between 1 and 5242880),
  constraint match_evidence_mime_check check (mime in ('image/jpeg', 'image/png', 'image/webp')),
  constraint match_evidence_status_check check (status in ('submitted', 'verified', 'rejected')),
  constraint match_evidence_verified_check check ((status = 'submitted') = (verified_at is null)),
  constraint match_evidence_role_check check (verified_role is null or verified_role in ('host', 'streamer', 'admin'))
);
create index match_evidence_tournament_idx on public.match_evidence (tournament_id, match_no);
alter table public.match_evidence enable row level security;
revoke all on table public.match_evidence from public, anon, authenticated;
grant select on table public.match_evidence to authenticated;
create policy "Uploaders, the event's staff and admins see evidence"
  on public.match_evidence for select to authenticated
  using (uploader_id = (select auth.uid()) or private.is_staff(tournament_id) or private.is_admin());

insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('match-evidence', 'match-evidence', false, 5242880, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update
  set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

create function private.can_see_evidence_file(p text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.match_evidence m
    where m.path = p and (private.is_staff(m.tournament_id) or private.is_admin())
  );
$$;
revoke all on function private.can_see_evidence_file(text) from public;
grant execute on function private.can_see_evidence_file(text) to authenticated;

create policy "Evidence: upload into your own folder"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'match-evidence' and (storage.foldername(name))[1] = (select auth.uid())::text);
create policy "Evidence: the uploader, the event's staff and admins open it"
  on storage.objects for select to authenticated
  using (bucket_id = 'match-evidence' and ((storage.foldername(name))[1] = (select auth.uid())::text or private.can_see_evidence_file(name)));
create policy "Evidence: delete your own unsent uploads"
  on storage.objects for delete to authenticated
  using (bucket_id = 'match-evidence' and (storage.foldername(name))[1] = (select auth.uid())::text
         and not exists (select 1 from public.match_evidence m where m.path = name));

-- Attach a checked screenshot to a result. Called by our server after it
-- checked the file and computed its SHA-256 from the stored bytes.
create function public.add_match_evidence(t uuid, match integer, subject uuid, subject_is_squad boolean, p_path text, p_sha256 text, p_size integer, p_mime text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  tour public.tournaments;
  new_id bigint;
  sq uuid := case when subject_is_squad then subject end;
  pl uuid := case when subject_is_squad then null else subject end;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  select * into tour from public.tournaments where id = t;
  if tour.id is null or tour.status not in ('live', 'completed') or match is null or match < 1 or match > tour.matches then
    raise exception 'results_closed' using errcode = 'PT409';
  end if;
  if private.results_final(t) then
    raise exception 'results_locked' using errcode = 'PT409';
  end if;
  if not (private.is_staff(t) or private.is_admin()) then
    if tour.format = 'solo' then
      if subject_is_squad or pl <> me or not private.is_approved_entrant(t) then
        raise exception 'not_your_result' using errcode = '42501';
      end if;
    elsif not subject_is_squad or not exists (
      select 1 from public.tournament_entries where tournament_id = t and user_id = me and squad_id = sq and status = 'approved'
    ) then
      raise exception 'not_your_result' using errcode = '42501';
    end if;
  end if;
  if (subject_is_squad and not exists (select 1 from public.squads where id = sq and tournament_id = t))
     or (not subject_is_squad and not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = pl)) then
    raise exception 'bad_subject' using errcode = '22023';
  end if;
  if split_part(p_path, '/', 1) <> me::text
     or not exists (select 1 from storage.objects o where o.bucket_id = 'match-evidence' and o.name = p_path) then
    raise exception 'not_your_upload' using errcode = '42501';
  end if;
  if (select count(*) from public.match_evidence where tournament_id = t and match_no = match and uploader_id = me
        and coalesce(squad_id, player_id) = subject) >= 3 then
    raise exception 'too_many_screenshots' using errcode = 'PT429';
  end if;
  perform private.hit_limit('evidence', 20, interval '1 hour');
  insert into public.match_evidence (tournament_id, match_no, squad_id, player_id, uploader_id, path, sha256, size_bytes, mime)
  values (t, match, sq, pl, me, p_path, lower(p_sha256), p_size, p_mime)
  returning id into new_id;
  return new_id;
end;
$$;

-- Staff: accept or reject a screenshot (audited).
create function public.review_evidence(evidence bigint, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  ev public.match_evidence;
  role text;
begin
  select * into ev from public.match_evidence where id = evidence;
  if ev.id is null then
    raise exception 'unknown_evidence' using errcode = 'PT404';
  end if;
  role := case when private.is_host(ev.tournament_id) then 'host'
               when private.is_admin() then 'admin'
               when private.is_staff(ev.tournament_id) then 'streamer' end;
  if role is null then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if ev.uploader_id = (select auth.uid()) and role <> 'admin' then
    raise exception 'own_evidence' using errcode = '42501';
  end if;
  update public.match_evidence
  set status = case when accept then 'verified' else 'rejected' end,
      verified_by = (select auth.uid()), verified_role = role, verified_at = now()
  where id = evidence;
  perform private.audit('evidence.reviewed', ev.tournament_id, coalesce(ev.squad_id, ev.player_id),
    jsonb_build_object('evidence', evidence, 'accepted', accept, 'match', ev.match_no, 'sha256', ev.sha256));
end;
$$;

-- The event's screenshots for its staff (newest first).
create function public.event_evidence(t uuid)
returns table (id bigint, match_no integer, subject text, uploader text, path text, sha256 text, status text, verified_role text, created_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select m.id, m.match_no, coalesce(s.name, p.username), u.username, m.path, m.sha256, m.status, m.verified_role, m.created_at
  from public.match_evidence m
  left join public.squads s on s.id = m.squad_id
  left join public.profiles p on p.id = m.player_id
  left join public.profiles u on u.id = m.uploader_id
  where m.tournament_id = t and (private.is_staff(t) or private.is_admin())
  order by m.created_at desc
  limit 200;
$$;

-- Public receipt: proof a screenshot exists and wasn't changed (no image, no uploader).
create function public.evidence_receipt(evidence bigint)
returns table (id bigint, event_name text, event_slug text, match_no integer, subject text, sha256 text, size_bytes integer, mime text,
               uploaded_at timestamptz, status text, verified_role text, verified_at timestamptz, results_final boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select m.id, t.name, t.slug, m.match_no, coalesce(s.name, p.username), m.sha256, m.size_bytes, m.mime,
    m.created_at, m.status, m.verified_role, m.verified_at, private.results_final(t.id)
  from public.match_evidence m
  join public.tournaments t on t.id = m.tournament_id
  left join public.squads s on s.id = m.squad_id
  left join public.profiles p on p.id = m.player_id
  where m.id = evidence and t.status <> 'draft';
$$;

-- My own screenshots for an event (so players see what they sent and its status).
create function public.my_evidence(t uuid)
returns table (id bigint, match_no integer, status text, created_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select m.id, m.match_no, m.status, m.created_at
  from public.match_evidence m
  where m.tournament_id = t and m.uploader_id = (select auth.uid())
  order by m.created_at desc;
$$;

-- 5. Review flags (rules only; a human decides) -------------------------------------------
create function public.admin_review_flags()
returns table (kind text, player_id uuid, username text, username_key text, detail text, since timestamptz)
language plpgsql
stable
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  return query
    -- A new account (under 30 days old) placing top 3 in its first finished event.
    with recent as (
      select t.id, t.completed_at from public.tournaments t
      where t.status = 'completed' and t.completed_at > now() - interval '60 days'
    ),
    ranked as (
      select r.id as tid, r.completed_at, s.squad_id, s.player_id,
        row_number() over (partition by r.id order by s.points desc, s.kills desc, s.wins desc) as rk
      from recent r cross join lateral public.tournament_standings(r.id) s
      where s.counted > 0
    ),
    podium as (
      select distinct coalesce(e.user_id, k.player_id) as uid, k.tid, k.completed_at
      from ranked k
      left join public.tournament_entries e on e.squad_id = k.squad_id and e.tournament_id = k.tid
      where k.rk <= 3
    )
    select 'new_account_podium'::text, p.id, p.username, p.username_key,
      'Account ' || greatest(0, extract(day from (d.completed_at - p.created_at))::integer) || ' days old at its first event, finished top 3',
      d.completed_at
    from podium d
    join public.profiles p on p.id = d.uid
    where p.created_at > d.completed_at - interval '30 days'
      and not exists (
        select 1 from public.tournament_entries e2 join public.tournaments t2 on t2.id = e2.tournament_id
        where e2.user_id = p.id and e2.status = 'approved' and t2.status = 'completed' and t2.completed_at < d.completed_at
      )
    union all
    -- One WhatsApp number on several accounts (the number itself is not shown).
    select 'shared_whatsapp', p.id, p.username, p.username_key,
      'Same WhatsApp number as ' || (g.n - 1) || ' other account' || case when g.n > 2 then 's' else '' end,
      p.created_at
    from (select c.whatsapp_number, count(*) n from public.profile_contacts c where c.whatsapp_number is not null group by 1 having count(*) > 1) g
    join public.profile_contacts c on c.whatsapp_number = g.whatsapp_number
    join public.profiles p on p.id = c.id
    union all
    -- Three or more different players reported the same player.
    select 'repeated_reports', p.id, p.username, p.username_key,
      count(distinct r.reporter_id) || ' players reported them', min(r.created_at)
    from public.content_reports r
    join public.profiles p on p.id = r.target
    where r.kind = 'player' and r.status = 'open'
    group by p.id, p.username, p.username_key
    having count(distinct r.reporter_id) >= 3
    order by 6 desc;
end;
$$;

-- 6. Payouts, recorded by hand ----------------------------------------------------------------
create table public.payouts (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete restrict,
  place integer not null,
  recipient_id uuid references public.profiles (id) on delete set null,
  amount_minor integer not null,
  currency text not null default 'USD',
  method text not null,
  reference_masked text not null,
  status text not null default 'sent',
  note text,
  sent_by uuid references public.profiles (id) on delete set null,
  sent_at timestamptz not null default now(),
  confirmed_at timestamptz,
  constraint payouts_place_check check (place between 1 and 10),
  constraint payouts_amount_check check (amount_minor between 1 and 10000000),
  constraint payouts_currency_check check (currency ~ '^[A-Z]{3}$'),
  constraint payouts_method_check check (method in ('ecocash', 'onemoney', 'bank', 'cash', 'other')),
  constraint payouts_reference_check check (reference_masked ~ '^•••• [A-Za-z0-9]{2,4}$'),
  constraint payouts_status_check check (status in ('pending', 'sent', 'confirmed', 'failed')),
  constraint payouts_confirmed_check check ((status = 'confirmed') = (confirmed_at is not null)),
  constraint payouts_note_check check (note is null or (char_length(note) between 2 and 200 and private.clean_text(note)))
);
create index payouts_tournament_idx on public.payouts (tournament_id, place);
alter table public.payouts enable row level security;
revoke all on table public.payouts from public, anon, authenticated;
grant select on table public.payouts to authenticated;
create policy "Winners see their own payouts; admins see all"
  on public.payouts for select to authenticated
  using (recipient_id = (select auth.uid()) or private.is_admin());

create function public.record_payout(t uuid, p_place integer, recipient uuid, p_amount_minor integer, p_currency text, p_method text, reference_last text, p_note text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_id bigint;
begin
  perform private.require_admin();
  if not private.results_final(t) then
    raise exception 'results_not_final' using errcode = 'PT409';
  end if;
  if not exists (select 1 from public.tournament_entries where tournament_id = t and user_id = recipient and status = 'approved') then
    raise exception 'not_a_player' using errcode = 'PT404';
  end if;
  if exists (select 1 from public.penalty_log where user_id = recipient and tournament_id = t and kind = 'prize_forfeit') then
    raise exception 'prize_forfeited' using errcode = 'PT409';
  end if;
  insert into public.payouts (tournament_id, place, recipient_id, amount_minor, currency, method, reference_masked, note, sent_by)
  values (t, p_place, recipient, p_amount_minor, upper(coalesce(p_currency, 'USD')), p_method,
          '•••• ' || right(regexp_replace(coalesce(reference_last, ''), '[^A-Za-z0-9]', '', 'g'), 4),
          nullif(btrim(p_note), ''), (select auth.uid()))
  returning id into new_id;
  perform private.audit('payout.recorded', t, recipient,
    jsonb_build_object('payout', new_id, 'place', p_place, 'amount_minor', p_amount_minor, 'currency', upper(coalesce(p_currency, 'USD')), 'method', p_method));
  return new_id;
end;
$$;

create function public.set_payout_status(payout bigint, p_status text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.payouts;
begin
  perform private.require_admin();
  select * into p from public.payouts where id = payout;
  if p.id is null then
    raise exception 'unknown_payout' using errcode = 'PT404';
  end if;
  if p_status not in ('pending', 'sent', 'failed') then
    raise exception 'bad_status' using errcode = '22023';
  end if;
  update public.payouts set status = p_status, confirmed_at = null where id = payout;
  perform private.audit('payout.status', p.tournament_id, p.recipient_id, jsonb_build_object('payout', payout, 'from', p.status, 'to', p_status));
end;
$$;

-- The winner: "I received it."
create function public.confirm_payout(payout bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  update public.payouts set status = 'confirmed', confirmed_at = now()
  where id = payout and recipient_id = (select auth.uid()) and status = 'sent';
  if not found then
    raise exception 'unknown_payout' using errcode = 'PT404';
  end if;
end;
$$;

-- Public Winners list: paid prizes only, references masked.
create function public.winners()
returns table (event_name text, event_slug text, season integer, place integer, winner text, winner_key text, clan_tag text,
               amount_minor integer, currency text, method text, reference_masked text, status text, sent_at timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select t.name, t.slug, t.season, p.place, coalesce(r.username, 'Deleted account'), r.username_key, r.clan_tag,
    p.amount_minor, p.currency, p.method, p.reference_masked, p.status, p.sent_at
  from public.payouts p
  join public.tournaments t on t.id = p.tournament_id
  left join public.profiles r on r.id = p.recipient_id
  where p.status in ('sent', 'confirmed')
  order by p.sent_at desc, p.place
  limit 100;
$$;

-- 7. Team chats --------------------------------------------------------------------------------
alter table public.squads add column chat_id uuid references public.chat_channels (id) on delete set null;

create function private.sync_team_chat()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  old_squad uuid := case when tg_op in ('UPDATE', 'DELETE') and old.status = 'approved' then old.squad_id end;
  new_squad uuid := case when tg_op in ('INSERT', 'UPDATE') and new.status = 'approved' then new.squad_id end;
  who uuid := case when tg_op = 'DELETE' then old.user_id else new.user_id end;
  sq public.squads;
  cid uuid;
begin
  if old_squad is not null and old_squad is distinct from new_squad then
    delete from public.group_members g using public.squads s
    where s.id = old_squad and g.channel_id = s.chat_id and g.user_id = who;
  end if;
  if new_squad is not null and new_squad is distinct from old_squad then
    select * into sq from public.squads where id = new_squad;
    cid := sq.chat_id;
    if cid is null then
      insert into public.chat_channels (kind, name, owner_id, approved)
      values ('squad', 'Team ' || left(sq.name, 19), coalesce(sq.captain_id, who), true)
      returning id into cid;
      update public.squads set chat_id = cid where id = sq.id;
    end if;
    insert into public.group_members (channel_id, user_id) values (cid, who) on conflict do nothing;
  end if;
  return null;
end;
$$;
revoke all on function private.sync_team_chat() from public;
create trigger tournament_entries_team_chat
  after insert or delete or update of squad_id, status on public.tournament_entries
  for each row execute function private.sync_team_chat();

create function private.drop_team_chat()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if old.chat_id is not null then
    delete from public.chat_channels where id = old.chat_id and kind = 'squad';
  end if;
  return old;
end;
$$;
revoke all on function private.drop_team_chat() from public;
create trigger squads_drop_team_chat
  after delete on public.squads
  for each row execute function private.drop_team_chat();

-- Teams in events that haven't finished get their chat now.
do $$
declare
  e record;
  cid uuid;
begin
  for e in select te.user_id, s.id as sid, s.name, s.captain_id
           from public.tournament_entries te
           join public.squads s on s.id = te.squad_id
           join public.tournaments t on t.id = te.tournament_id
           where te.status = 'approved' and t.status not in ('completed', 'cancelled')
           order by s.id, te.created_at
  loop
    select chat_id into cid from public.squads where id = e.sid;
    if cid is null then
      insert into public.chat_channels (kind, name, owner_id, approved)
      values ('squad', 'Team ' || left(e.name, 19), coalesce(e.captain_id, e.user_id), true)
      returning id into cid;
      update public.squads set chat_id = cid where id = e.sid;
    end if;
    insert into public.group_members (channel_id, user_id) values (cid, e.user_id) on conflict do nothing;
  end loop;
end;
$$;

-- 8. Permissions ---------------------------------------------------------------------------------
revoke all on function public.results_state(uuid) from public;
revoke all on function public.lock_results(uuid) from public, anon;
revoke all on function public.correct_final_result(uuid, integer, uuid, boolean, integer, integer, text) from public, anon;
revoke all on function public.issue_penalty(uuid, text, uuid, text, integer) from public, anon;
revoke all on function public.add_match_evidence(uuid, integer, uuid, boolean, text, text, integer, text) from public, anon;
revoke all on function public.review_evidence(bigint, boolean) from public, anon;
revoke all on function public.event_evidence(uuid) from public, anon;
revoke all on function public.evidence_receipt(bigint) from public;
revoke all on function public.my_evidence(uuid) from public, anon;
revoke all on function public.admin_review_flags() from public, anon;
revoke all on function public.record_payout(uuid, integer, uuid, integer, text, text, text, text) from public, anon;
revoke all on function public.set_payout_status(bigint, text) from public, anon;
revoke all on function public.confirm_payout(bigint) from public, anon;
revoke all on function public.winners() from public;
grant execute on function public.results_state(uuid) to anon, authenticated;
grant execute on function public.lock_results(uuid) to authenticated;
grant execute on function public.correct_final_result(uuid, integer, uuid, boolean, integer, integer, text) to authenticated;
grant execute on function public.issue_penalty(uuid, text, uuid, text, integer) to authenticated;
grant execute on function public.add_match_evidence(uuid, integer, uuid, boolean, text, text, integer, text) to authenticated;
grant execute on function public.review_evidence(bigint, boolean) to authenticated;
grant execute on function public.event_evidence(uuid) to authenticated;
grant execute on function public.evidence_receipt(bigint) to anon, authenticated;
grant execute on function public.my_evidence(uuid) to authenticated;
grant execute on function public.admin_review_flags() to authenticated;
grant execute on function public.record_payout(uuid, integer, uuid, integer, text, text, text, text) to authenticated;
grant execute on function public.set_payout_status(bigint, text) to authenticated;
grant execute on function public.confirm_payout(bigint) to authenticated;
grant execute on function public.winners() to anon, authenticated;
