-- Sponsored community events, approvals, streamer slots, event reports,
-- event chats, the top-10 rule, permanent country chats, approved clans with
-- tags, the ideas board and admin-editable settings.
--
-- Security model (also in SECURITY.md):
--   * GameArena's own tournaments (kind 'tournament', paid entry) are the
--     only ones on the GameArena prize leaderboard. Sponsored community
--     tournaments ('community') and scrims have their own boards and chats.
--   * Registration can need the host's approval. Only approved players (and
--     staff) see the player list, the room and the event chat.
--   * Streamers book a slot; only approved streamers become staff (can send
--     results and reports).
--   * Clans need an admin's approval; one clan per player; joining needs the
--     clan master's approval. The clan tag shown before usernames is kept by
--     the database, players can't set it.
--   * Country chat choice is permanent (only an admin can reset it).
--   * Settings (prize shares, minimum players, top-10 rule…) live in one row
--     only admins can change.

-- Multi-line text check (rules): newlines/tabs allowed, other hidden characters not.
create function private.clean_multiline(t text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select private.clean_text(translate(t, chr(10) || chr(13) || chr(9), ''));
$$;
revoke all on function private.clean_multiline(text) from public;
grant execute on function private.clean_multiline(text) to authenticated;

-- ---------------------------------------------------------------------------
-- Admin settings ("parameters")
-- ---------------------------------------------------------------------------
create table public.app_config (
  id boolean primary key default true,
  prize_share_1 integer not null default 50,
  prize_share_2 integer not null default 25,
  prize_share_3 integer not null default 15,
  default_entry_usd_cents integer not null default 200,
  default_min_players integer not null default 20,
  top10_rule boolean not null default true,
  reminders_enabled boolean not null default true,
  updated_at timestamptz not null default now(),
  constraint app_config_single_row check (id),
  constraint app_config_shares_check check (
    prize_share_1 between 0 and 100 and prize_share_2 between 0 and 100 and prize_share_3 between 0 and 100
    and prize_share_1 + prize_share_2 + prize_share_3 <= 100
  ),
  constraint app_config_entry_check check (default_entry_usd_cents between 0 and 5000),
  constraint app_config_min_players_check check (default_min_players between 0 and 400)
);
insert into public.app_config default values;

create trigger app_config_touch_updated_at
  before update on public.app_config
  for each row execute function private.touch_updated_at();

alter table public.app_config enable row level security;
revoke all on table public.app_config from public, anon, authenticated;
grant select on table public.app_config to anon, authenticated;
grant update (
  prize_share_1, prize_share_2, prize_share_3, default_entry_usd_cents,
  default_min_players, top10_rule, reminders_enabled
) on table public.app_config to authenticated;

create policy "Everyone can read the settings"
  on public.app_config for select to anon, authenticated
  using (true);

create policy "Only admins change the settings"
  on public.app_config for update to authenticated
  using (private.is_admin())
  with check (private.is_admin());

-- ---------------------------------------------------------------------------
-- Events: official (paid), community (sponsored, run by others), scrims
-- ---------------------------------------------------------------------------
alter table public.tournaments drop constraint tournaments_kind_check;
alter table public.tournaments
  add constraint tournaments_kind_check check (kind in ('tournament', 'community', 'scrim'));
alter table public.tournaments drop constraint tournaments_scrims_are_free;
-- Only GameArena's own tournaments take entry fees. Scrims have no prizes.
alter table public.tournaments
  add constraint tournaments_entry_fee_official_only check (kind = 'tournament' or entry_fee_usd_cents = 0),
  add constraint tournaments_scrims_are_free check (
    kind <> 'scrim' or (prize_1_usd_cents = 0 and prize_2_usd_cents = 0 and prize_3_usd_cents = 0)
  );

alter table public.tournaments
  add column sponsor_name text,
  add column rules text,
  add column match_times timestamptz[] not null default '{}',
  add column min_players integer not null default 0,
  add column banner text not null default 'codm-hero',
  add column requires_approval boolean not null default true;

alter table public.tournaments
  add constraint tournaments_sponsor_check check (
    sponsor_name is null or (char_length(sponsor_name) between 2 and 40 and sponsor_name = btrim(sponsor_name) and private.clean_text(sponsor_name))
  ),
  add constraint tournaments_rules_check check (
    rules is null or (char_length(rules) <= 3000 and private.clean_multiline(rules))
  ),
  add constraint tournaments_match_times_check check (cardinality(match_times) <= 10),
  add constraint tournaments_min_players_check check (min_players between 0 and 400),
  add constraint tournaments_banner_check check (banner in ('codm-hero', 'hub-hero', 'codm', 'pubgm', 'freefire'));

grant insert (sponsor_name, rules, match_times, min_players, banner, requires_approval)
  on table public.tournaments to authenticated;
grant update (sponsor_name, rules, match_times, min_players, banner, requires_approval)
  on table public.tournaments to authenticated;

-- Hosts can't touch money, the season, the sponsor or the refund threshold.
create or replace function private.guard_tournament_update()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_admin() and (
    new.entry_fee_usd_cents is distinct from old.entry_fee_usd_cents
    or new.prize_1_usd_cents is distinct from old.prize_1_usd_cents
    or new.prize_2_usd_cents is distinct from old.prize_2_usd_cents
    or new.prize_3_usd_cents is distinct from old.prize_3_usd_cents
    or new.season is distinct from old.season
    or new.sponsor_name is distinct from old.sponsor_name
    or new.min_players is distinct from old.min_players
  ) then
    raise exception 'admins_only' using errcode = '42501';
  end if;
  if new.format is distinct from old.format
    and exists (select 1 from public.tournament_entries where tournament_id = old.id) then
    raise exception 'format_locked' using errcode = 'PT409';
  end if;
  return new;
end;
$$;

-- Rooms (scrims) are open: anyone who joins is in straight away. Also keeps
-- the 3-rooms-per-player limit.
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
      where created_by = new.created_by and kind = 'scrim' and status <> 'completed'
    ) >= 3 then
      raise exception 'too_many_rooms' using errcode = 'PT429';
    end if;
  end if;
  return new;
end;
$$;

-- Players create scrims (always free, no approval needed by default);
-- admins create official and community tournaments.
alter policy "Players create free rooms, admins create tournaments" on public.tournaments
  with check (
    created_by = (select auth.uid())
    and (kind = 'scrim' or private.is_admin())
    and exists (select 1 from public.profiles where id = (select auth.uid()))
  );

-- Warzone Unleashed is a sponsored community tournament run by its own host.
-- (The host guard is paused for this one-off data change.)
alter table public.tournaments disable trigger tournaments_guard_update;
update public.tournaments
  set kind = 'community', entry_fee_usd_cents = 0, sponsor_name = 'GameArena',
      rules = 'Squads of 4. 2 battle royale matches. No hacks, mods or teaming with other squads. Screenshot your end-of-match screen. The host''s decision is final.'
  where slug in ('warzone-unleashed-s1', 'warzone-unleashed-s2');
update public.tournaments set requires_approval = false where kind = 'scrim';
alter table public.tournaments enable trigger tournaments_guard_update;

-- ---------------------------------------------------------------------------
-- Registration approval
-- ---------------------------------------------------------------------------
alter table public.tournament_entries
  add column status text not null default 'approved',
  add constraint tournament_entries_status_check check (status in ('pending', 'approved', 'rejected'));

create function private.set_entry_status()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  new.status := case
    when (select requires_approval from public.tournaments where id = new.tournament_id) then 'pending'
    else 'approved'
  end;
  return new;
end;
$$;
revoke all on function private.set_entry_status() from public;

create trigger tournament_entries_status
  before insert on public.tournament_entries
  for each row execute function private.set_entry_status();

create function private.is_approved_entrant(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tournament_entries
    where tournament_id = t and user_id = (select auth.uid()) and status = 'approved'
  );
$$;
revoke all on function private.is_approved_entrant(uuid) from public;
grant execute on function private.is_approved_entrant(uuid) to authenticated;

-- The player list is for approved players and staff only.
drop policy "Signed-in players can see who entered" on public.tournament_entries;
create policy "Approved players and staff see the list"
  on public.tournament_entries for select to authenticated
  using (
    user_id = (select auth.uid())
    or private.is_approved_entrant(tournament_id)
    or private.is_staff(tournament_id)
    or private.is_admin()
  );

alter policy "Players in the event and its staff see the room" on public.tournament_rooms
  using (private.is_approved_entrant(tournament_id) or private.is_staff(tournament_id) or private.is_admin());

-- Host: approve / reject one player, or approve everyone waiting.
create function public.set_entry_status(t uuid, player uuid, new_status text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not (private.is_host(t) or private.is_admin()) then
    raise exception 'hosts_only' using errcode = '42501';
  end if;
  if new_status not in ('pending', 'approved', 'rejected') then
    raise exception 'bad_status' using errcode = '22023';
  end if;
  update public.tournament_entries set status = new_status where tournament_id = t and user_id = player;
end;
$$;

create function public.approve_all_entries(t uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  n integer;
begin
  if not (private.is_host(t) or private.is_admin()) then
    raise exception 'hosts_only' using errcode = '42501';
  end if;
  update public.tournament_entries set status = 'approved' where tournament_id = t and status = 'pending';
  get diagnostics n = row_count;
  return n;
end;
$$;

-- Counts for lists (visitors included): approved and waiting.
drop function public.tournament_counts();
create function public.tournament_counts()
returns table (tournament_id uuid, players integer, pending integer, squads integer)
language sql
stable
security definer
set search_path = ''
as $$
  select t.id,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'approved')::integer,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id and e.status = 'pending')::integer,
    (select count(*) from public.squads s where s.tournament_id = t.id)::integer
  from public.tournaments t;
$$;

-- Live prize pool for GameArena's own tournaments: entries × fee, split by
-- the shares in app_config. (Counts approved entries until payments go live;
-- then only paid entries are approved.)
create function public.prize_pool(t uuid)
returns table (players integer, pool_usd_cents integer, prize_1 integer, prize_2 integer, prize_3 integer, min_players integer)
language sql
stable
security definer
set search_path = ''
as $$
  with ev as (select * from public.tournaments where id = t and kind = 'tournament'),
  n as (select count(*)::integer as c from public.tournament_entries e where e.tournament_id = t and e.status = 'approved'),
  cfg as (select * from public.app_config limit 1)
  select n.c, n.c * ev.entry_fee_usd_cents,
    (n.c * ev.entry_fee_usd_cents * cfg.prize_share_1 / 100)::integer,
    (n.c * ev.entry_fee_usd_cents * cfg.prize_share_2 / 100)::integer,
    (n.c * ev.entry_fee_usd_cents * cfg.prize_share_3 / 100)::integer,
    ev.min_players
  from ev, n, cfg;
$$;

-- ---------------------------------------------------------------------------
-- Event chats (one per tournament / scrim, for approved players + staff)
-- ---------------------------------------------------------------------------
alter table public.chat_channels drop constraint chat_channels_kind_check;
alter table public.chat_channels
  add constraint chat_channels_kind_check check (kind in ('community', 'clan', 'country', 'event'));
alter table public.chat_channels
  add column tournament_id uuid references public.tournaments (id) on delete cascade,
  add column approved boolean not null default true;
alter table public.chat_channels
  add constraint chat_channels_event_check check ((kind = 'event') = (tournament_id is not null)),
  add constraint chat_channels_clan_tag_required check (kind <> 'clan' or tag is not null);
create unique index chat_channels_event_key on public.chat_channels (tournament_id) where kind = 'event';
-- New clans wait for an admin.
alter table public.chat_channels alter column approved set default false;
update public.chat_channels set approved = true;

create or replace function private.can_read_channel(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
      select 1 from public.chat_channels c
      where c.id = target
        and (
          c.kind = 'community'
          or (c.kind = 'clan' and c.approved and exists (
            select 1 from public.clan_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
          or (c.kind = 'country' and exists (
            select 1 from public.country_chat_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
          or (c.kind = 'event' and (private.is_approved_entrant(c.tournament_id) or private.is_staff(c.tournament_id)))
        )
    )
    or private.is_admin();
$$;

-- Pending clans are only visible to their owner and admins.
alter policy "Signed-in players can browse channels and clans" on public.chat_channels
  using (kind <> 'clan' or approved or owner_id = (select auth.uid()) or private.is_admin());

create function private.add_event_chat()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.chat_channels (game, kind, slug, name, description, owner_id, tournament_id, approved)
  values (
    new.game, 'event', 'ev-' || left(new.slug, 37),
    btrim(left(new.name, 24)),
    'Chat for players and staff of this event.',
    null, new.id, true
  );
  return new;
end;
$$;
revoke all on function private.add_event_chat() from public;

create trigger tournaments_add_event_chat
  after insert on public.tournaments
  for each row execute function private.add_event_chat();

insert into public.chat_channels (game, kind, slug, name, description, owner_id, tournament_id, approved)
select t.game, 'event', 'ev-' || left(t.slug, 37), btrim(left(t.name, 24)),
  'Chat for players and staff of this event.', null, t.id, true
from public.tournaments t;

-- ---------------------------------------------------------------------------
-- Streamer slots
-- ---------------------------------------------------------------------------
create table public.stream_requests (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  platform text not null,
  channel_url text not null,
  match_no integer,
  note text,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  constraint stream_requests_one_per_event unique (tournament_id, user_id),
  constraint stream_requests_platform_check check (platform in ('tiktok', 'twitch', 'youtube', 'facebook', 'kick')),
  constraint stream_requests_url_check check (
    char_length(channel_url) <= 200
    and channel_url ~ '^https://(www\.|m\.)?(tiktok\.com|twitch\.tv|youtube\.com|youtu\.be|facebook\.com|fb\.gg|kick\.com)/[A-Za-z0-9@._~/?=&%-]+$'
  ),
  constraint stream_requests_match_check check (match_no is null or match_no between 1 and 10),
  constraint stream_requests_note_check check (note is null or (char_length(note) <= 200 and private.clean_text(note))),
  constraint stream_requests_status_check check (status in ('pending', 'approved', 'rejected'))
);

alter table public.stream_requests enable row level security;
revoke all on table public.stream_requests from public, anon, authenticated;
grant select on table public.stream_requests to authenticated;
grant insert (tournament_id, platform, channel_url, match_no, note) on table public.stream_requests to authenticated;
grant delete on table public.stream_requests to authenticated;

create policy "Approved streams are public; requests are for the streamer and host"
  on public.stream_requests for select to authenticated
  using (status = 'approved' or user_id = (select auth.uid()) or private.is_host(tournament_id) or private.is_admin());

create policy "Streamers book a slot for themselves"
  on public.stream_requests for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.profiles where id = (select auth.uid()))
    and exists (select 1 from public.tournaments t where t.id = tournament_id and t.status <> 'completed')
  );

create policy "Streamers cancel their own booking"
  on public.stream_requests for delete to authenticated
  using (user_id = (select auth.uid()) or private.is_host(tournament_id) or private.is_admin());

-- Host approves a streamer: they become staff (can send results + reports).
create function public.review_stream_request(request_id bigint, approve boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  req public.stream_requests;
begin
  select * into req from public.stream_requests where id = request_id;
  if not found then
    raise exception 'unknown_request' using errcode = 'PT404';
  end if;
  if not (private.is_host(req.tournament_id) or private.is_admin()) then
    raise exception 'hosts_only' using errcode = '42501';
  end if;
  update public.stream_requests set status = case when approve then 'approved' else 'rejected' end where id = request_id;
  if approve then
    insert into public.tournament_staff (tournament_id, user_id, role, added_by)
    values (req.tournament_id, req.user_id, 'streamer', (select auth.uid()))
    on conflict (tournament_id, user_id) do nothing;
  else
    delete from public.tournament_staff
      where tournament_id = req.tournament_id and user_id = req.user_id and role = 'streamer';
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- Event reports (hacking, teaming, wrong results…)
-- ---------------------------------------------------------------------------
create table public.event_reports (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reason text not null,
  match_no integer,
  suspect text,
  details text,
  status text not null default 'open',
  resolved_by uuid references public.profiles (id) on delete set null,
  resolved_at timestamptz,
  created_at timestamptz not null default now(),
  constraint event_reports_reason_check check (reason in ('hacking', 'teaming', 'wrong_result', 'abuse', 'other')),
  constraint event_reports_match_check check (match_no is null or match_no between 1 and 10),
  constraint event_reports_suspect_check check (suspect is null or (char_length(suspect) <= 60 and private.clean_text(suspect))),
  constraint event_reports_details_check check (details is null or (char_length(details) <= 500 and private.clean_text(details))),
  constraint event_reports_status_check check (status in ('open', 'resolved', 'dismissed'))
);
create index event_reports_tournament_idx on public.event_reports (tournament_id, status);

alter table public.event_reports enable row level security;
revoke all on table public.event_reports from public, anon, authenticated;
grant select on table public.event_reports to authenticated;
grant insert (tournament_id, reason, match_no, suspect, details) on table public.event_reports to authenticated;

create policy "Reporters, hosts and admins see reports"
  on public.event_reports for select to authenticated
  using (reporter_id = (select auth.uid()) or private.is_host(tournament_id) or private.is_admin());

create policy "Approved players and staff can report"
  on public.event_reports for insert to authenticated
  with check (
    reporter_id = (select auth.uid())
    and (private.is_approved_entrant(tournament_id) or private.is_staff(tournament_id) or private.is_admin())
  );

create function private.limit_event_reports()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select count(*) from public.event_reports
      where tournament_id = new.tournament_id and reporter_id = new.reporter_id) >= 10 then
    raise exception 'too_many_reports' using errcode = 'PT429';
  end if;
  return new;
end;
$$;
revoke all on function private.limit_event_reports() from public;

create trigger event_reports_limit
  before insert on public.event_reports
  for each row execute function private.limit_event_reports();

create function public.resolve_event_report(report_id bigint, outcome text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  t uuid;
begin
  if outcome not in ('resolved', 'dismissed', 'open') then
    raise exception 'bad_outcome' using errcode = '22023';
  end if;
  select tournament_id into t from public.event_reports where id = report_id;
  if t is null then
    raise exception 'unknown_report' using errcode = 'PT404';
  end if;
  if not (private.is_host(t) or private.is_admin()) then
    raise exception 'hosts_only' using errcode = '42501';
  end if;
  update public.event_reports
    set status = outcome,
        resolved_by = case when outcome = 'open' then null else (select auth.uid()) end,
        resolved_at = case when outcome = 'open' then null else now() end
    where id = report_id;
end;
$$;

-- ---------------------------------------------------------------------------
-- Top-10 rule + approval in squads (GameArena's own tournaments)
-- ---------------------------------------------------------------------------
-- This month's top 10 on the GameArena prize leaderboard.
create function private.is_top10(player uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce((select top10_rule from public.app_config limit 1), true)
    and player in (select b.user_id from public.monthly_player_board('tournament') b limit 10);
$$;
revoke all on function private.is_top10(uuid) from public;

create or replace function public.join_squad(squad_code text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  sq public.squads;
  tour public.tournaments;
  entry public.tournament_entries;
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid())) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  select * into sq from public.squads where code = upper(btrim(squad_code)) and not is_random;
  if not found then
    raise exception 'unknown_code' using errcode = 'PT404';
  end if;
  select * into tour from public.tournaments where id = sq.tournament_id;
  if tour.status <> 'open' then
    raise exception 'registration_closed' using errcode = 'PT409';
  end if;
  if (select count(*) from public.tournament_entries where squad_id = sq.id) >= private.squad_size(tour.format) then
    raise exception 'squad_full' using errcode = 'PT409';
  end if;
  -- Fair play: two of this month's top 10 can't team up in GameArena tournaments.
  if tour.kind = 'tournament' and private.is_top10((select auth.uid())) and exists (
    select 1 from public.tournament_entries e
    where e.squad_id = sq.id and private.is_top10(e.user_id)
  ) then
    raise exception 'top10_together' using errcode = 'PT409';
  end if;

  select * into entry from public.tournament_entries where tournament_id = tour.id and user_id = (select auth.uid());
  if found then
    if entry.squad_id = sq.id then
      return sq.name;
    end if;
    if entry.squad_id is not null then
      raise exception 'already_in_squad' using errcode = 'PT409';
    end if;
    update public.tournament_entries set squad_id = sq.id, team_mode = 'fixed'
      where tournament_id = tour.id and user_id = (select auth.uid());
  else
    insert into public.tournament_entries (tournament_id, user_id, team_mode, squad_id)
    values (tour.id, (select auth.uid()), 'fixed', sq.id);
  end if;
  return sq.name;
end;
$$;

-- Random squads: approved players only; top-10 players spread across squads.
create or replace function public.make_random_squads(t uuid)
returns integer
language plpgsql
security definer
set search_path = ''
as $$
declare
  tour public.tournaments;
  size integer;
  n integer;
  made integer := 0;
  player record;
  target uuid;
  made_ids uuid[] := '{}';
  spread boolean;
begin
  if not (private.is_host(t) or private.is_admin()) then
    raise exception 'hosts_only' using errcode = '42501';
  end if;
  select * into tour from public.tournaments where id = t;
  if tour.format = 'solo' then
    raise exception 'solo_event' using errcode = 'PT422';
  end if;
  if tour.status = 'completed' then
    raise exception 'event_finished' using errcode = 'PT409';
  end if;
  size := private.squad_size(tour.format);
  spread := tour.kind = 'tournament';
  select count(*) into n from public.squads where tournament_id = t and is_random;

  for player in
    select e.user_id, (spread and private.is_top10(e.user_id)) as top
    from public.tournament_entries e
    where e.tournament_id = t and e.team_mode = 'random' and e.squad_id is null and e.status = 'approved'
    order by 2 desc, random()
  loop
    -- First squad made in this run with space (and, for a top-10 player,
    -- no other top-10 player in it).
    select s.id into target
      from unnest(made_ids) with ordinality as s(id, ord)
      where (select count(*) from public.tournament_entries x where x.squad_id = s.id) < size
        and not (player.top and exists (
          select 1 from public.tournament_entries x where x.squad_id = s.id and private.is_top10(x.user_id)
        ))
      order by s.ord
      limit 1;
    if target is null then
      n := n + 1;
      insert into public.squads (tournament_id, name, is_random, captain_id)
      values (t, 'Random ' || n, true, player.user_id)
      returning id into target;
      made_ids := made_ids || target;
      made := made + 1;
    end if;
    update public.tournament_entries set squad_id = target
      where tournament_id = t and user_id = player.user_id;
    target := null;
  end loop;
  return made;
end;
$$;

-- Results: players must be approved to report.
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

-- ---------------------------------------------------------------------------
-- Country chat: one, forever (an admin can reset a mistake)
-- ---------------------------------------------------------------------------
create or replace function public.join_country_chat(target_slug text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  chan public.chat_channels;
  mine public.country_chat_members;
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid())) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  select * into chan from public.chat_channels where slug = target_slug and kind = 'country';
  if not found then
    raise exception 'unknown_country_chat' using errcode = 'PT404';
  end if;
  select * into mine from public.country_chat_members where user_id = (select auth.uid());
  if found then
    if mine.channel_id = chan.id then
      return chan.slug;
    end if;
    raise exception 'country_locked' using errcode = 'PT409';
  end if;
  insert into public.country_chat_members (user_id, channel_id) values ((select auth.uid()), chan.id);
  return chan.slug;
end;
$$;

create function public.admin_reset_country_chat(player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  delete from public.country_chat_members where user_id = player;
end;
$$;

-- ---------------------------------------------------------------------------
-- Clans: admin approval, one clan per player, join requests, tags
-- ---------------------------------------------------------------------------
create unique index clan_members_one_clan_per_player on public.clan_members (user_id);
drop policy "Players can join a clan" on public.clan_members;
revoke insert on table public.clan_members from authenticated;

alter table public.profiles add column clan_tag text;
alter table public.profiles add constraint profiles_clan_tag_check check (clan_tag is null or clan_tag ~ '^[A-Z0-9]{2,5}$');

-- Keep profiles.clan_tag in step with the (approved) clan a player is in.
create function private.sync_clan_tag(player uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  update public.profiles p
    set clan_tag = (
      select c.tag from public.clan_members m
      join public.chat_channels c on c.id = m.channel_id
      where m.user_id = player and c.kind = 'clan' and c.approved
      limit 1
    )
    where p.id = player;
$$;
revoke all on function private.sync_clan_tag(uuid) from public;

create function private.after_clan_membership()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.sync_clan_tag(coalesce(new.user_id, old.user_id));
  return null;
end;
$$;
revoke all on function private.after_clan_membership() from public;

create trigger clan_members_sync_tag
  after insert or delete on public.clan_members
  for each row execute function private.after_clan_membership();

create function private.after_clan_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  m record;
begin
  if new.kind = 'clan' and (new.approved is distinct from old.approved or new.tag is distinct from old.tag) then
    for m in select user_id from public.clan_members where channel_id = new.id loop
      perform private.sync_clan_tag(m.user_id);
    end loop;
  end if;
  return null;
end;
$$;
revoke all on function private.after_clan_change() from public;

create trigger chat_channels_sync_tag
  after update on public.chat_channels
  for each row execute function private.after_clan_change();

-- Friendly error when a clan owner is already in another clan.
create or replace function private.add_clan_owner()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.kind = 'clan' then
    if exists (select 1 from public.clan_members where user_id = new.owner_id) then
      raise exception 'already_in_clan' using errcode = 'PT409';
    end if;
    insert into public.clan_members (channel_id, user_id, role)
    values (new.id, new.owner_id, 'owner');
  end if;
  return new;
end;
$$;

create table public.clan_join_requests (
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  message text,
  created_at timestamptz not null default now(),
  primary key (channel_id, user_id),
  constraint clan_join_requests_message_check check (message is null or (char_length(message) <= 140 and private.clean_text(message)))
);

alter table public.clan_join_requests enable row level security;
revoke all on table public.clan_join_requests from public, anon, authenticated;
grant select on table public.clan_join_requests to authenticated;
grant insert (channel_id, message) on table public.clan_join_requests to authenticated;
grant delete on table public.clan_join_requests to authenticated;

create policy "Requester, clan master and admins see requests"
  on public.clan_join_requests for select to authenticated
  using (
    user_id = (select auth.uid())
    or exists (select 1 from public.chat_channels c where c.id = channel_id and c.owner_id = (select auth.uid()))
    or private.is_admin()
  );

create policy "Players ask to join an approved clan"
  on public.clan_join_requests for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and not private.is_banned()
    and exists (select 1 from public.chat_channels c where c.id = channel_id and c.kind = 'clan' and c.approved)
    and not exists (select 1 from public.clan_members m where m.channel_id = clan_join_requests.channel_id and m.user_id = (select auth.uid()))
  );

create policy "Requester cancels, clan master or admin declines"
  on public.clan_join_requests for delete to authenticated
  using (
    user_id = (select auth.uid())
    or exists (select 1 from public.chat_channels c where c.id = channel_id and c.owner_id = (select auth.uid()))
    or private.is_admin()
  );

-- Clan master (or admin) accepts: the player leaves their old clan and joins.
create function public.accept_clan_request(clan uuid, player uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not (
    exists (select 1 from public.chat_channels where id = clan and kind = 'clan' and owner_id = (select auth.uid()))
    or private.is_admin()
  ) then
    raise exception 'clan_master_only' using errcode = '42501';
  end if;
  if not exists (select 1 from public.clan_join_requests where channel_id = clan and user_id = player) then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
  if exists (select 1 from public.chat_channels where kind = 'clan' and owner_id = player and id <> clan) then
    raise exception 'owns_clan' using errcode = 'PT409';
  end if;
  delete from public.clan_members where user_id = player and role = 'member';
  insert into public.clan_members (channel_id, user_id, role) values (clan, player, 'member');
  delete from public.clan_join_requests where user_id = player;
end;
$$;

-- Admin: approve a new clan (after checking it really exists) or turn it down.
create function public.review_clan(clan uuid, approve boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.require_admin();
  if approve then
    update public.chat_channels set approved = true where id = clan and kind = 'clan';
  else
    delete from public.chat_channels where id = clan and kind = 'clan';
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- Ideas board: players post ideas, everyone votes 👍 / 👎
-- ---------------------------------------------------------------------------
create table public.ideas (
  id bigint generated always as identity primary key,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  body text not null,
  status text not null default 'open',
  created_at timestamptz not null default now(),
  constraint ideas_body_check check (char_length(body) between 5 and 300 and body = btrim(body) and private.clean_text(body)),
  constraint ideas_status_check check (status in ('open', 'planned', 'done', 'declined'))
);

create table public.idea_votes (
  idea_id bigint not null references public.ideas (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  vote smallint not null,
  primary key (idea_id, user_id),
  constraint idea_votes_vote_check check (vote in (-1, 1))
);

alter table public.ideas enable row level security;
revoke all on table public.ideas from public, anon, authenticated;
grant select on table public.ideas to authenticated;
grant insert (body) on table public.ideas to authenticated;
grant delete on table public.ideas to authenticated;
grant update (status) on table public.ideas to authenticated;

create policy "Signed-in players read ideas"
  on public.ideas for select to authenticated
  using (true);
create policy "Players post ideas as themselves"
  on public.ideas for insert to authenticated
  with check (user_id = (select auth.uid()) and not private.is_banned());
create policy "Authors and admins delete ideas"
  on public.ideas for delete to authenticated
  using (user_id = (select auth.uid()) or private.is_admin());
create policy "Admins set an idea's status"
  on public.ideas for update to authenticated
  using (private.is_admin())
  with check (private.is_admin());

create function private.limit_ideas()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select count(*) from public.ideas
      where user_id = new.user_id and created_at > now() - interval '1 day') >= 3 then
    raise exception 'too_many_ideas' using errcode = 'PT429';
  end if;
  return new;
end;
$$;
revoke all on function private.limit_ideas() from public;

create trigger ideas_limit
  before insert on public.ideas
  for each row execute function private.limit_ideas();

alter table public.idea_votes enable row level security;
revoke all on table public.idea_votes from public, anon, authenticated;
grant select on table public.idea_votes to authenticated;

create policy "Players see their own votes"
  on public.idea_votes for select to authenticated
  using (user_id = (select auth.uid()));

-- Vote 1 (👍), -1 (👎) or 0 (take the vote back).
create function public.vote_idea(idea bigint, v integer)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not exists (select 1 from public.profiles where id = (select auth.uid())) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  if v not in (-1, 0, 1) then
    raise exception 'bad_vote' using errcode = '22023';
  end if;
  if not exists (select 1 from public.ideas where id = idea) then
    raise exception 'unknown_idea' using errcode = 'PT404';
  end if;
  if v = 0 then
    delete from public.idea_votes where idea_id = idea and user_id = (select auth.uid());
  else
    insert into public.idea_votes (idea_id, user_id, vote) values (idea, (select auth.uid()), v)
    on conflict (idea_id, user_id) do update set vote = excluded.vote;
  end if;
end;
$$;

-- The board: ideas with 👍/👎 counts, the author and my own vote.
create function public.idea_board()
returns table (
  id bigint, body text, status text, created_at timestamptz,
  author text, author_tag text, up integer, down integer, my_vote integer, mine boolean
)
language sql
stable
security definer
set search_path = ''
as $$
  select i.id, i.body, i.status, i.created_at, p.username, p.clan_tag,
    (count(v.*) filter (where v.vote = 1))::integer,
    (count(v.*) filter (where v.vote = -1))::integer,
    coalesce(max(v.vote) filter (where v.user_id = (select auth.uid())), 0)::integer,
    i.user_id = (select auth.uid())
  from public.ideas i
  join public.profiles p on p.id = i.user_id
  left join public.idea_votes v on v.idea_id = i.id
  group by i.id, p.username, p.clan_tag
  order by (count(v.*) filter (where v.vote = 1)) - (count(v.*) filter (where v.vote = -1)) desc, i.created_at desc
  limit 200;
$$;

-- ---------------------------------------------------------------------------
-- Leaderboard shows clan tags; reminders cover sponsored events too
-- ---------------------------------------------------------------------------
drop function public.monthly_player_board(text);
create function public.monthly_player_board(board text)
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
        and rb.placement is not null
        and rb.last_at >= date_trunc('month', now())
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

create or replace function public.due_push_reminders(cron_secret text)
returns table (push_endpoint text)
language plpgsql
security definer
set search_path = ''
as $$
declare
  open_event uuid;
begin
  perform private.check_cron_secret(cron_secret);
  if not coalesce((select reminders_enabled from public.app_config limit 1), true) then
    return;
  end if;
  select t.id into open_event
    from public.tournaments t
    where t.kind in ('tournament', 'community') and t.status = 'open'
    order by (t.kind = 'tournament') desc, t.created_at desc
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

-- ---------------------------------------------------------------------------
-- Function permissions
-- ---------------------------------------------------------------------------
revoke all on function public.set_entry_status(uuid, uuid, text) from public, anon;
revoke all on function public.approve_all_entries(uuid) from public, anon;
revoke all on function public.review_stream_request(bigint, boolean) from public, anon;
revoke all on function public.resolve_event_report(bigint, text) from public, anon;
revoke all on function public.admin_reset_country_chat(uuid) from public, anon;
revoke all on function public.accept_clan_request(uuid, uuid) from public, anon;
revoke all on function public.review_clan(uuid, boolean) from public, anon;
revoke all on function public.vote_idea(bigint, integer) from public, anon;
revoke all on function public.idea_board() from public, anon;
grant execute on function public.set_entry_status(uuid, uuid, text) to authenticated;
grant execute on function public.approve_all_entries(uuid) to authenticated;
grant execute on function public.review_stream_request(bigint, boolean) to authenticated;
grant execute on function public.resolve_event_report(bigint, text) to authenticated;
grant execute on function public.admin_reset_country_chat(uuid) to authenticated;
grant execute on function public.accept_clan_request(uuid, uuid) to authenticated;
grant execute on function public.review_clan(uuid, boolean) to authenticated;
grant execute on function public.vote_idea(bigint, integer) to authenticated;
grant execute on function public.idea_board() to authenticated;

revoke all on function public.tournament_counts() from public;
revoke all on function public.prize_pool(uuid) from public;
revoke all on function public.monthly_player_board(text) from public;
grant execute on function public.tournament_counts() to anon, authenticated;
grant execute on function public.prize_pool(uuid) to anon, authenticated;
grant execute on function public.monthly_player_board(text) to anon, authenticated;
