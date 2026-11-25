-- Tournaments (prize events run by hosts), scrims/rooms (free, made by
-- players), squads (random or fixed), the results bot, CODM UIDs and
-- country chats.
--
-- Security model (also in SECURITY.md):
--   * RLS on every new table. Visitors can read tournaments and the public
--     standings / leaderboards, nothing else.
--   * Only admins create prize tournaments and hand out host rights ("the
--     ruling stick"). Hosts add streamers, open/start/finish their event,
--     make random squads and enter results. Only admins change money columns.
--   * Scrims (rooms) are always free: a CHECK keeps entry fee and prizes at 0.
--   * Squad join codes can't be read from the table; members get theirs from
--     my_squad(). Squads are only made or joined through functions.
--   * WhatsApp numbers: squadmates can now see each other's (CLAUDE.md: only
--     reveal them to confirmed teammates, enforced by RLS).
--   * UIDs are private unless the player ticks "show to everyone". Hosts and
--     streamers of an event the player entered, and squadmates, can see them
--     (they need them to invite players into the CODM room).
--   * Results: the database decides who is reporting (player / streamer /
--     host). Players can only report their own squad. The host's numbers win;
--     anything that disagrees is flagged for a check.
--   * Country chats: you read only the country chat you joined (admins: all).

-- ---------------------------------------------------------------------------
-- Shared helpers
-- ---------------------------------------------------------------------------

-- No control, zero-width or text-direction characters.
create function private.clean_text(t text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select t !~ '[[:cntrl:]\u200B-\u200F\u202A-\u202E\u2060-\u2069\uFEFF]';
$$;

-- Players per team for a format.
create function private.squad_size(fmt text)
returns integer
language sql
immutable
set search_path = ''
as $$
  select case fmt when 'solo' then 1 when 'duo' then 2 else 4 end;
$$;

-- Battle royale placement points (kills add 1 point each on top).
create function private.placement_points(place integer)
returns integer
language sql
immutable
set search_path = ''
as $$
  select case
    when place = 1 then 15
    when place = 2 then 12
    when place = 3 then 10
    when place = 4 then 8
    when place = 5 then 6
    when place = 6 then 4
    when place = 7 then 2
    when place between 8 and 10 then 1
    else 0
  end;
$$;

-- ---------------------------------------------------------------------------
-- Country chats
-- ---------------------------------------------------------------------------
alter table public.chat_channels drop constraint chat_channels_kind_check;
alter table public.chat_channels
  add constraint chat_channels_kind_check check (kind in ('community', 'clan', 'country'));
alter table public.chat_channels drop constraint chat_channels_clan_owner_check;
alter table public.chat_channels
  add constraint chat_channels_clan_owner_check check (kind <> 'clan' or owner_id is not null);
alter table public.chat_channels add column country_code text;
alter table public.chat_channels
  add constraint chat_channels_country_check check (
    (kind = 'country') = (country_code is not null)
    and (country_code is null or country_code ~ '^[A-Z]{2}$')
  );
create unique index chat_channels_country_key on public.chat_channels (game, country_code) where kind = 'country';

-- One country chat per player.
create table public.country_chat_members (
  user_id uuid primary key default auth.uid() references public.profiles (id) on delete cascade,
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  joined_at timestamptz not null default now()
);
create index country_chat_members_channel_idx on public.country_chat_members (channel_id);

alter table public.country_chat_members enable row level security;
revoke all on table public.country_chat_members from public, anon, authenticated;
grant select on table public.country_chat_members to authenticated;

create policy "Players see their own country chat"
  on public.country_chat_members for select to authenticated
  using (user_id = (select auth.uid()) or private.is_admin());

-- Reading a channel: community for all, clans for members, a country chat
-- only if it's the one you joined. Admins read everything.
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
          or (c.kind = 'clan' and exists (
            select 1 from public.clan_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
          or (c.kind = 'country' and exists (
            select 1 from public.country_chat_members m
            where m.channel_id = target and m.user_id = (select auth.uid())
          ))
        )
    )
    or private.is_admin();
$$;

-- Join (or switch to) a country chat. Switching is allowed once a week.
create function public.join_country_chat(target_slug text)
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
    if mine.joined_at > now() - interval '7 days' and not private.is_admin() then
      raise exception 'country_locked' using errcode = 'PT409';
    end if;
    update public.country_chat_members
      set channel_id = chan.id, joined_at = now()
      where user_id = (select auth.uid());
  else
    insert into public.country_chat_members (user_id, channel_id) values ((select auth.uid()), chan.id);
  end if;
  return chan.slug;
end;
$$;

-- Countries on (or next to) CODM's South African server.
insert into public.chat_channels (game, kind, slug, name, description, owner_id, country_code) values
  ('codm', 'country', 'codm-za', 'South Africa', 'CODM players in South Africa.', null, 'ZA'),
  ('codm', 'country', 'codm-zw', 'Zimbabwe', 'CODM players in Zimbabwe.', null, 'ZW'),
  ('codm', 'country', 'codm-zm', 'Zambia', 'CODM players in Zambia.', null, 'ZM'),
  ('codm', 'country', 'codm-bw', 'Botswana', 'CODM players in Botswana.', null, 'BW'),
  ('codm', 'country', 'codm-na', 'Namibia', 'CODM players in Namibia.', null, 'NA'),
  ('codm', 'country', 'codm-mz', 'Mozambique', 'CODM players in Mozambique.', null, 'MZ'),
  ('codm', 'country', 'codm-mw', 'Malawi', 'CODM players in Malawi.', null, 'MW'),
  ('codm', 'country', 'codm-ls', 'Lesotho', 'CODM players in Lesotho.', null, 'LS'),
  ('codm', 'country', 'codm-sz', 'Eswatini', 'CODM players in Eswatini.', null, 'SZ'),
  ('codm', 'country', 'codm-ao', 'Angola', 'CODM players in Angola.', null, 'AO');

-- ---------------------------------------------------------------------------
-- Tournaments and scrims
-- ---------------------------------------------------------------------------
create table public.tournaments (
  id uuid primary key default gen_random_uuid(),
  slug text not null default substr(replace(gen_random_uuid()::text, '-', ''), 1, 10),
  game text not null default 'codm',
  kind text not null default 'scrim',
  name text not null,
  season integer,
  mode text not null default 'br',
  format text not null default 'squad',
  status text not null default 'open',
  starts_at timestamptz,
  matches integer not null default 2,
  max_players integer not null default 100,
  entry_fee_usd_cents integer not null default 0,
  prize_1_usd_cents integer not null default 0,
  prize_2_usd_cents integer not null default 0,
  prize_3_usd_cents integer not null default 0,
  description text,
  whatsapp_group_url text,
  created_by uuid default auth.uid() references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),

  constraint tournaments_slug_key unique (slug),
  constraint tournaments_slug_check check (slug ~ '^[a-z0-9-]{3,40}$'),
  constraint tournaments_game_check check (game in ('codm', 'pubgm', 'freefire', 'efootball', 'chess')),
  constraint tournaments_kind_check check (kind in ('tournament', 'scrim')),
  constraint tournaments_name_check check (
    char_length(name) between 3 and 40 and name = btrim(name) and private.clean_text(name)
  ),
  constraint tournaments_season_check check (season is null or season between 1 and 99),
  constraint tournaments_mode_check check (mode in ('br', 'mp')),
  constraint tournaments_format_check check (format in ('solo', 'duo', 'squad')),
  constraint tournaments_status_check check (status in ('upcoming', 'open', 'live', 'completed')),
  constraint tournaments_matches_check check (matches between 1 and 10),
  constraint tournaments_max_players_check check (max_players between 2 and 400),
  constraint tournaments_money_check check (
    entry_fee_usd_cents between 0 and 5000
    and prize_1_usd_cents between 0 and 10000000
    and prize_2_usd_cents between 0 and 10000000
    and prize_3_usd_cents between 0 and 10000000
  ),
  -- Scrims are free: no entry fee, no prizes.
  constraint tournaments_scrims_are_free check (
    kind = 'tournament'
    or (entry_fee_usd_cents = 0 and prize_1_usd_cents = 0 and prize_2_usd_cents = 0 and prize_3_usd_cents = 0)
  ),
  constraint tournaments_description_check check (
    description is null or (char_length(description) <= 500 and private.clean_text(description))
  ),
  constraint tournaments_whatsapp_check check (
    whatsapp_group_url is null or whatsapp_group_url ~ '^https://chat\.whatsapp\.com/[A-Za-z0-9]{10,40}$'
  )
);
create index tournaments_kind_status_idx on public.tournaments (kind, status);

create trigger tournaments_touch_updated_at
  before update on public.tournaments
  for each row execute function private.touch_updated_at();

-- Who runs an event: hosts (full control) and streamers (can report results).
create table public.tournament_staff (
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  role text not null,
  added_by uuid references public.profiles (id) on delete set null,
  added_at timestamptz not null default now(),
  primary key (tournament_id, user_id),
  constraint tournament_staff_role_check check (role in ('host', 'streamer'))
);
create index tournament_staff_user_idx on public.tournament_staff (user_id);

create table public.squads (
  id uuid primary key default gen_random_uuid(),
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  name text not null,
  code text not null default upper(substr(replace(gen_random_uuid()::text, '-', ''), 1, 8)),
  is_random boolean not null default false,
  clan_id uuid references public.chat_channels (id) on delete set null,
  captain_id uuid references public.profiles (id) on delete set null,
  created_at timestamptz not null default now(),
  constraint squads_code_key unique (code),
  constraint squads_name_check check (
    char_length(name) between 2 and 24 and name = btrim(name) and private.clean_text(name)
  )
);
create unique index squads_name_key on public.squads (tournament_id, lower(name));

create table public.tournament_entries (
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  team_mode text not null default 'random',
  squad_id uuid references public.squads (id) on delete set null,
  created_at timestamptz not null default now(),
  primary key (tournament_id, user_id),
  constraint tournament_entries_team_mode_check check (team_mode in ('random', 'fixed'))
);
create index tournament_entries_user_idx on public.tournament_entries (user_id);
create index tournament_entries_squad_idx on public.tournament_entries (squad_id);

-- CODM room ID / password: only players in the event and its staff see it.
create table public.tournament_rooms (
  tournament_id uuid primary key references public.tournaments (id) on delete cascade,
  room_info text not null,
  updated_at timestamptz not null default now(),
  constraint tournament_rooms_info_check check (
    char_length(room_info) between 1 and 200 and private.clean_text(room_info)
  )
);

create trigger tournament_rooms_touch_updated_at
  before update on public.tournament_rooms
  for each row execute function private.touch_updated_at();

-- What players, streamers and hosts report after each match.
create table public.match_results (
  id bigint generated always as identity primary key,
  tournament_id uuid not null references public.tournaments (id) on delete cascade,
  match_no integer not null,
  squad_id uuid references public.squads (id) on delete cascade,
  player_id uuid references public.profiles (id) on delete cascade,
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reporter_role text not null default 'player',
  placement integer not null,
  kills integer not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  constraint match_results_match_check check (match_no between 1 and 10),
  constraint match_results_role_check check (reporter_role in ('player', 'streamer', 'host')),
  constraint match_results_placement_check check (placement between 1 and 150),
  constraint match_results_kills_check check (kills between 0 and 99),
  constraint match_results_one_subject_check check ((squad_id is null) <> (player_id is null))
);
create unique index match_results_one_report_key
  on public.match_results (tournament_id, match_no, reporter_id, coalesce(squad_id, player_id));
create index match_results_tournament_idx on public.match_results (tournament_id, match_no);

-- Public CODM UIDs (opt-in).
create table public.player_uids (
  user_id uuid primary key default auth.uid() references public.profiles (id) on delete cascade,
  codm_uid text not null,
  is_public boolean not null default false,
  updated_at timestamptz not null default now(),
  constraint player_uids_uid_check check (codm_uid ~ '^[0-9]{5,25}$')
);

create trigger player_uids_touch_updated_at
  before update on public.player_uids
  for each row execute function private.touch_updated_at();

-- ---------------------------------------------------------------------------
-- Access helpers (used by RLS)
-- ---------------------------------------------------------------------------
create function private.is_host(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tournament_staff
    where tournament_id = t and user_id = (select auth.uid()) and role = 'host'
  );
$$;

create function private.is_staff(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tournament_staff where tournament_id = t and user_id = (select auth.uid())
  );
$$;

create function private.is_entrant(t uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.tournament_entries where tournament_id = t and user_id = (select auth.uid())
  );
$$;

-- Same squad as me in any event.
create function private.is_squadmate(other uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.tournament_entries a
    join public.tournament_entries b on b.squad_id = a.squad_id
    where a.user_id = (select auth.uid()) and b.user_id = other and a.squad_id is not null
  );
$$;

-- I host or stream an event this player entered.
create function private.runs_event_of(other uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.tournament_entries e
    join public.tournament_staff s on s.tournament_id = e.tournament_id
    where e.user_id = other and s.user_id = (select auth.uid())
  );
$$;

revoke all on function private.clean_text(text) from public;
revoke all on function private.squad_size(text) from public;
revoke all on function private.placement_points(integer) from public;
revoke all on function private.is_host(uuid) from public;
revoke all on function private.is_staff(uuid) from public;
revoke all on function private.is_entrant(uuid) from public;
revoke all on function private.is_squadmate(uuid) from public;
revoke all on function private.runs_event_of(uuid) from public;
grant execute on function private.clean_text(text) to authenticated;
grant execute on function private.squad_size(text) to authenticated;
grant execute on function private.placement_points(integer) to authenticated;
grant execute on function private.is_host(uuid) to authenticated;
grant execute on function private.is_staff(uuid) to authenticated;
grant execute on function private.is_entrant(uuid) to authenticated;
grant execute on function private.is_squadmate(uuid) to authenticated;
grant execute on function private.runs_event_of(uuid) to authenticated;

-- ---------------------------------------------------------------------------
-- RLS: tournaments
-- ---------------------------------------------------------------------------
alter table public.tournaments enable row level security;
revoke all on table public.tournaments from public, anon, authenticated;
grant select on table public.tournaments to anon, authenticated;
grant insert (
  kind, name, season, mode, format, status, starts_at, matches, max_players,
  entry_fee_usd_cents, prize_1_usd_cents, prize_2_usd_cents, prize_3_usd_cents,
  description, whatsapp_group_url
) on table public.tournaments to authenticated;
grant update (
  name, season, mode, format, status, starts_at, matches, max_players,
  entry_fee_usd_cents, prize_1_usd_cents, prize_2_usd_cents, prize_3_usd_cents,
  description, whatsapp_group_url
) on table public.tournaments to authenticated;
grant delete on table public.tournaments to authenticated;

create policy "Everyone can see tournaments and rooms"
  on public.tournaments for select to anon, authenticated
  using (true);

create policy "Players create free rooms, admins create tournaments"
  on public.tournaments for insert to authenticated
  with check (
    created_by = (select auth.uid())
    and (kind = 'scrim' or private.is_admin())
    and exists (select 1 from public.profiles where id = (select auth.uid()))
  );

create policy "Hosts and admins edit events"
  on public.tournaments for update to authenticated
  using (private.is_host(id) or private.is_admin())
  with check (private.is_host(id) or private.is_admin());

create policy "Admins delete events, players delete their own rooms"
  on public.tournaments for delete to authenticated
  using (private.is_admin() or (kind = 'scrim' and created_by = (select auth.uid())));

-- Hosts can't touch money or the season; format is locked once players join.
create function private.guard_tournament_update()
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

create trigger tournaments_guard_update
  before update on public.tournaments
  for each row execute function private.guard_tournament_update();

-- At most 3 unfinished rooms per player (anti-spam).
create function private.limit_rooms()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.kind = 'scrim' and (
    select count(*) from public.tournaments
    where created_by = new.created_by and kind = 'scrim' and status <> 'completed'
  ) >= 3 then
    raise exception 'too_many_rooms' using errcode = 'PT429';
  end if;
  return new;
end;
$$;

create trigger tournaments_limit_rooms
  before insert on public.tournaments
  for each row execute function private.limit_rooms();

-- Whoever creates an event hosts it.
create function private.add_creator_as_host()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.created_by is not null then
    insert into public.tournament_staff (tournament_id, user_id, role, added_by)
    values (new.id, new.created_by, 'host', new.created_by);
  end if;
  return new;
end;
$$;

create trigger tournaments_add_creator_as_host
  after insert on public.tournaments
  for each row execute function private.add_creator_as_host();

-- ---------------------------------------------------------------------------
-- RLS: staff, squads, entries, rooms
-- ---------------------------------------------------------------------------
alter table public.tournament_staff enable row level security;
revoke all on table public.tournament_staff from public, anon, authenticated;
grant select on table public.tournament_staff to authenticated;

create policy "Signed-in players can see who runs an event"
  on public.tournament_staff for select to authenticated
  using (true);

alter table public.squads enable row level security;
revoke all on table public.squads from public, anon, authenticated;
-- Everything except the join code.
grant select (id, tournament_id, name, is_random, clan_id, captain_id, created_at)
  on table public.squads to authenticated;

create policy "Signed-in players can see squads"
  on public.squads for select to authenticated
  using (true);

alter table public.tournament_entries enable row level security;
revoke all on table public.tournament_entries from public, anon, authenticated;
grant select on table public.tournament_entries to authenticated;
grant insert (tournament_id, team_mode) on table public.tournament_entries to authenticated;
grant delete on table public.tournament_entries to authenticated;

create policy "Signed-in players can see who entered"
  on public.tournament_entries for select to authenticated
  using (true);

create policy "Players register themselves while registration is open"
  on public.tournament_entries for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.profiles where id = (select auth.uid()))
    and exists (select 1 from public.tournaments t where t.id = tournament_id and t.status = 'open')
  );

create policy "Players withdraw before the start, hosts remove players"
  on public.tournament_entries for delete to authenticated
  using (
    (user_id = (select auth.uid()) and exists (
      select 1 from public.tournaments t where t.id = tournament_id and t.status in ('upcoming', 'open')
    ))
    or private.is_host(tournament_id)
    or private.is_admin()
  );

-- Event full?
create function private.check_entry_capacity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if (select count(*) from public.tournament_entries where tournament_id = new.tournament_id)
     >= (select max_players from public.tournaments where id = new.tournament_id) then
    raise exception 'tournament_full' using errcode = 'PT409';
  end if;
  return new;
end;
$$;

create trigger tournament_entries_capacity
  before insert on public.tournament_entries
  for each row execute function private.check_entry_capacity();

-- After someone leaves: delete empty squads, pass the captaincy on.
create function private.tidy_squad(target uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  next_captain uuid;
begin
  if target is null then
    return;
  end if;
  select user_id into next_captain
    from public.tournament_entries where squad_id = target order by created_at limit 1;
  if next_captain is null then
    delete from public.squads where id = target;
  else
    update public.squads set captain_id = next_captain
      where id = target
        and (captain_id is null or not exists (
          select 1 from public.tournament_entries where squad_id = target and user_id = captain_id
        ));
  end if;
end;
$$;

create function private.after_entry_removed()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  perform private.tidy_squad(old.squad_id);
  return old;
end;
$$;

create trigger tournament_entries_tidy
  after delete on public.tournament_entries
  for each row execute function private.after_entry_removed();

alter table public.tournament_rooms enable row level security;
revoke all on table public.tournament_rooms from public, anon, authenticated;
grant select on table public.tournament_rooms to authenticated;
grant insert (tournament_id, room_info) on table public.tournament_rooms to authenticated;
grant update (room_info) on table public.tournament_rooms to authenticated;

create policy "Players in the event and its staff see the room"
  on public.tournament_rooms for select to authenticated
  using (private.is_entrant(tournament_id) or private.is_staff(tournament_id) or private.is_admin());

create policy "Hosts set the room"
  on public.tournament_rooms for insert to authenticated
  with check (private.is_host(tournament_id) or private.is_admin());

create policy "Hosts change the room"
  on public.tournament_rooms for update to authenticated
  using (private.is_host(tournament_id) or private.is_admin())
  with check (private.is_host(tournament_id) or private.is_admin());

-- ---------------------------------------------------------------------------
-- RLS: UIDs, results, squadmates' WhatsApp
-- ---------------------------------------------------------------------------
alter table public.player_uids enable row level security;
revoke all on table public.player_uids from public, anon, authenticated;
grant select on table public.player_uids to authenticated;
grant insert (codm_uid, is_public) on table public.player_uids to authenticated;
grant update (codm_uid, is_public) on table public.player_uids to authenticated;
grant delete on table public.player_uids to authenticated;

create policy "UIDs: public ones, your own, squadmates and event staff"
  on public.player_uids for select to authenticated
  using (
    is_public
    or user_id = (select auth.uid())
    or private.is_squadmate(user_id)
    or private.runs_event_of(user_id)
    or private.is_admin()
  );

create policy "Players add their own UID"
  on public.player_uids for insert to authenticated
  with check (user_id = (select auth.uid()));

create policy "Players change their own UID"
  on public.player_uids for update to authenticated
  using (user_id = (select auth.uid()))
  with check (user_id = (select auth.uid()));

create policy "Players remove their own UID"
  on public.player_uids for delete to authenticated
  using (user_id = (select auth.uid()));

create policy "Squadmates can see each other's WhatsApp"
  on public.profile_contacts for select to authenticated
  using (private.is_squadmate(id));

alter table public.match_results enable row level security;
revoke all on table public.match_results from public, anon, authenticated;
grant select on table public.match_results to authenticated;
grant insert (tournament_id, match_no, squad_id, player_id, placement, kills)
  on table public.match_results to authenticated;
grant update (placement, kills) on table public.match_results to authenticated;
grant delete on table public.match_results to authenticated;

create policy "Signed-in players can see every report"
  on public.match_results for select to authenticated
  using (true);

create policy "Players report as themselves"
  on public.match_results for insert to authenticated
  with check (reporter_id = (select auth.uid()));

create policy "Players fix their own reports"
  on public.match_results for update to authenticated
  using (reporter_id = (select auth.uid()))
  with check (reporter_id = (select auth.uid()));

create policy "Players delete their own reports, hosts delete any"
  on public.match_results for delete to authenticated
  using (reporter_id = (select auth.uid()) or private.is_host(tournament_id) or private.is_admin());

-- The results bot's rules for every report.
create function private.check_match_result()
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

create trigger match_results_check
  before insert or update on public.match_results
  for each row execute function private.check_match_result();

-- ---------------------------------------------------------------------------
-- Squad functions
-- ---------------------------------------------------------------------------
create function public.create_squad(t uuid, squad_name text, clan uuid default null)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  tour public.tournaments;
  entry public.tournament_entries;
  made public.squads;
begin
  select * into tour from public.tournaments where id = t;
  if not found then
    raise exception 'unknown_tournament' using errcode = 'PT404';
  end if;
  if tour.status <> 'open' then
    raise exception 'registration_closed' using errcode = 'PT409';
  end if;
  if tour.format = 'solo' then
    raise exception 'solo_event' using errcode = 'PT422';
  end if;
  select * into entry from public.tournament_entries where tournament_id = t and user_id = (select auth.uid());
  if not found then
    raise exception 'register_first' using errcode = 'PT409';
  end if;
  if entry.squad_id is not null then
    raise exception 'already_in_squad' using errcode = 'PT409';
  end if;
  if clan is not null and not exists (
    select 1 from public.clan_members where channel_id = clan and user_id = (select auth.uid())
  ) then
    raise exception 'not_in_clan' using errcode = '42501';
  end if;
  if lower(btrim(squad_name)) like 'random%' then
    raise exception 'name_reserved' using errcode = 'PT422';
  end if;

  begin
    insert into public.squads (tournament_id, name, clan_id, captain_id)
    values (t, btrim(squad_name), clan, (select auth.uid()))
    returning * into made;
  exception when unique_violation then
    raise exception 'squad_name_taken' using errcode = 'PT409';
  end;

  update public.tournament_entries set squad_id = made.id, team_mode = 'fixed'
    where tournament_id = t and user_id = (select auth.uid());
  return made.code;
end;
$$;

-- Join a squad with its code. Registers you for the event if needed.
create function public.join_squad(squad_code text)
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
    -- capacity trigger still runs
    insert into public.tournament_entries (tournament_id, user_id, team_mode, squad_id)
    values (tour.id, (select auth.uid()), 'fixed', sq.id);
  end if;
  return sq.name;
end;
$$;

create function public.leave_squad(t uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  old_squad uuid;
begin
  if not exists (select 1 from public.tournaments where id = t and status = 'open') then
    raise exception 'registration_closed' using errcode = 'PT409';
  end if;
  select squad_id into old_squad from public.tournament_entries
    where tournament_id = t and user_id = (select auth.uid());
  update public.tournament_entries set squad_id = null, team_mode = 'random'
    where tournament_id = t and user_id = (select auth.uid());
  perform private.tidy_squad(old_squad);
end;
$$;

-- My squad in an event, with the join code (fixed squads only).
create function public.my_squad(t uuid)
returns table (squad_id uuid, name text, code text, is_random boolean, captain_id uuid)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.name, case when s.is_random then null else s.code end, s.is_random, s.captain_id
  from public.tournament_entries e
  join public.squads s on s.id = e.squad_id
  where e.tournament_id = t and e.user_id = (select auth.uid());
$$;

-- Host button: put everyone who chose "random" into squads.
create function public.make_random_squads(t uuid)
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
  in_squad integer := 0;
  current_squad uuid;
  player record;
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
  select count(*) into n from public.squads where tournament_id = t and is_random;

  for player in
    select user_id from public.tournament_entries
    where tournament_id = t and team_mode = 'random' and squad_id is null
    order by random()
  loop
    if current_squad is null or in_squad = size then
      n := n + 1;
      insert into public.squads (tournament_id, name, is_random, captain_id)
      values (t, 'Random ' || n, true, player.user_id)
      returning id into current_squad;
      made := made + 1;
      in_squad := 0;
    end if;
    update public.tournament_entries set squad_id = current_squad
      where tournament_id = t and user_id = player.user_id;
    in_squad := in_squad + 1;
  end loop;
  return made;
end;
$$;

-- ---------------------------------------------------------------------------
-- Staff ("the ruling stick")
-- ---------------------------------------------------------------------------
-- Admins add hosts and streamers; hosts add streamers.
create function public.add_tournament_staff(t uuid, player_username text, staff_role text)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  target public.profiles;
begin
  if staff_role not in ('host', 'streamer') then
    raise exception 'bad_role' using errcode = '22023';
  end if;
  if not (private.is_admin() or (private.is_host(t) and staff_role = 'streamer')) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not exists (select 1 from public.tournaments where id = t) then
    raise exception 'unknown_tournament' using errcode = 'PT404';
  end if;
  select * into target from public.profiles where lower(username) = lower(btrim(player_username));
  if not found then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
  -- A host can't demote another host.
  if not private.is_admin() and exists (
    select 1 from public.tournament_staff where tournament_id = t and user_id = target.id and role = 'host'
  ) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  insert into public.tournament_staff (tournament_id, user_id, role, added_by)
  values (t, target.id, staff_role, (select auth.uid()))
  on conflict (tournament_id, user_id) do update set role = excluded.role, added_by = excluded.added_by;
  return target.username;
end;
$$;

-- Admins remove anyone; hosts remove streamers.
create function public.remove_tournament_staff(t uuid, target uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $$
begin
  if private.is_admin() then
    delete from public.tournament_staff where tournament_id = t and user_id = target;
  elsif private.is_host(t) then
    delete from public.tournament_staff where tournament_id = t and user_id = target and role = 'streamer';
  else
    raise exception 'not_allowed' using errcode = '42501';
  end if;
end;
$$;

-- ---------------------------------------------------------------------------
-- Results bot: checks reports against each other and calculates points
-- ---------------------------------------------------------------------------
-- One row per team (or solo player) per match:
--   verified = host/streamer numbers and nobody disagrees
--   check    = counted with the host's (or the streamers') numbers, but
--              someone reported something different
--   disputed = streamers disagree and no host has decided: not counted yet
--   pending  = only the players' own claim so far: not counted yet
create function public.result_board(t uuid)
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

create function public.tournament_standings(t uuid)
returns table (
  squad_id uuid, player_id uuid, label text,
  points integer, kills integer, wins integer, counted integer, waiting integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select
    b.squad_id, b.player_id, min(b.label),
    sum(b.points)::integer,
    coalesce(sum(b.kills), 0)::integer,
    (count(*) filter (where b.placement = 1))::integer,
    (count(*) filter (where b.placement is not null))::integer,
    (count(*) filter (where b.placement is null))::integer
  from public.result_board(t) b
  group by b.squad_id, b.player_id
  order by 4 desc, 5 desc, 6 desc;
$$;

-- Players and squads per event (for the list, visitors included).
create function public.tournament_counts()
returns table (tournament_id uuid, players integer, squads integer)
language sql
stable
security definer
set search_path = ''
as $$
  select t.id,
    (select count(*) from public.tournament_entries e where e.tournament_id = t.id)::integer,
    (select count(*) from public.squads s where s.tournament_id = t.id)::integer
  from public.tournaments t;
$$;

-- This month's leaderboard. board = 'tournament' (prize) or 'scrim' (free,
-- separate, never mixed). Every squad member gets the squad's points.
create function public.monthly_player_board(board text)
returns table (
  user_id uuid, username text, avatar_id text,
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
    select c.uid, p.username, p.avatar_id,
      sum(c.points)::integer,
      (count(*) filter (where c.placement = 1))::integer,
      sum(c.kills)::integer,
      count(distinct c.tid)::integer
    from credits c
    join public.profiles p on p.id = c.uid
    group by c.uid, p.username, p.avatar_id
    order by 4 desc, 5 desc
    limit 50;
end;
$$;

create function public.monthly_clan_board(board text)
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
      and rb.placement is not null
      and rb.last_at >= date_trunc('month', now())
    group by c.id, c.name, c.tag
    order by 4 desc, 5 desc
    limit 50;
end;
$$;

-- ---------------------------------------------------------------------------
-- Function permissions (Supabase gives anon EXECUTE by default: take it back)
-- ---------------------------------------------------------------------------
revoke all on function public.join_country_chat(text) from public, anon;
revoke all on function public.create_squad(uuid, text, uuid) from public, anon;
revoke all on function public.join_squad(text) from public, anon;
revoke all on function public.leave_squad(uuid) from public, anon;
revoke all on function public.my_squad(uuid) from public, anon;
revoke all on function public.make_random_squads(uuid) from public, anon;
revoke all on function public.add_tournament_staff(uuid, text, text) from public, anon;
revoke all on function public.remove_tournament_staff(uuid, uuid) from public, anon;
grant execute on function public.join_country_chat(text) to authenticated;
grant execute on function public.create_squad(uuid, text, uuid) to authenticated;
grant execute on function public.join_squad(text) to authenticated;
grant execute on function public.leave_squad(uuid) to authenticated;
grant execute on function public.my_squad(uuid) to authenticated;
grant execute on function public.make_random_squads(uuid) to authenticated;
grant execute on function public.add_tournament_staff(uuid, text, text) to authenticated;
grant execute on function public.remove_tournament_staff(uuid, uuid) to authenticated;

-- Public read-only boards (visitors can see standings and leaderboards).
revoke all on function public.result_board(uuid) from public;
revoke all on function public.tournament_standings(uuid) from public;
revoke all on function public.tournament_counts() from public;
revoke all on function public.monthly_player_board(text) from public;
revoke all on function public.monthly_clan_board(text) from public;
grant execute on function public.result_board(uuid) to anon, authenticated;
grant execute on function public.tournament_standings(uuid) to anon, authenticated;
grant execute on function public.tournament_counts() to anon, authenticated;
grant execute on function public.monthly_player_board(text) to anon, authenticated;
grant execute on function public.monthly_clan_board(text) to anon, authenticated;

revoke all on function private.guard_tournament_update() from public;
revoke all on function private.limit_rooms() from public;
revoke all on function private.add_creator_as_host() from public;
revoke all on function private.check_entry_capacity() from public;
revoke all on function private.tidy_squad(uuid) from public;
revoke all on function private.after_entry_removed() from public;
revoke all on function private.check_match_result() from public;

-- ---------------------------------------------------------------------------
-- Warzone Unleashed: Season 1 is done, Season 2 is open
-- ---------------------------------------------------------------------------
insert into public.tournaments (
  slug, kind, name, season, mode, format, status, matches, max_players,
  entry_fee_usd_cents, prize_1_usd_cents, prize_2_usd_cents, prize_3_usd_cents, description
) values
  ('warzone-unleashed-s1', 'tournament', 'Warzone Unleashed', 1, 'br', 'squad', 'completed', 2, 100,
   200, 10000, 5000, 3000, 'Season 1 is complete. Thank you to every squad that dropped in.'),
  ('warzone-unleashed-s2', 'tournament', 'Warzone Unleashed', 2, 'br', 'squad', 'open', 2, 100,
   200, 10000, 5000, 3000, 'The biggest CODM battle royale on GameArena. Squads of 4, 2 matches, top 3 squads win.');
