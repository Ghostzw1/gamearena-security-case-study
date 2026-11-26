-- Stage 1: stabilization (docs/MASTER-DIRECTIVE.md §05, §06; audit
-- docs/AUDIT-2026-11-26.md §4). Four defects:
--
-- 1. Sponsor truth. "Sponsored by X" must only show when the sponsor is
--    confirmed. New sponsor_status (none / pending / confirmed), admin-only.
--    Warzone Unleashed S1/S2 said "Sponsored by GameArena" although that isn't
--    confirmed (owner, 2026-11-26) → pending, name removed.
-- 2. Fake prizes or sponsors on new events. Players can create rooms
--    (scrims), and the old update guard didn't cover inserts, so a room could
--    be created through the API with a prize, entry fee or sponsor. Now only
--    admins can set those, on insert as on update.
-- 3. Capacity race. "Event full?" counted then inserted without a lock, so two
--    players could take the last place at once; rejected entries also took
--    places. Now the tournament row is locked first and only pending and
--    approved entries count.
-- 4. Status changes. Hosts could move an event to any status (completed →
--    open). Now only these moves are allowed for hosts; admins can still correct:
--      upcoming → open | live
--      open     → upcoming | live | completed
--      live     → completed

-- 1. Sponsor status ---------------------------------------------------------
alter table public.tournaments add column sponsor_status text not null default 'none';

alter table public.tournaments disable trigger tournaments_guard_update;
update public.tournaments set sponsor_status = 'confirmed' where sponsor_name is not null;
update public.tournaments set sponsor_status = 'pending', sponsor_name = null
  where slug in ('warzone-unleashed-s1', 'warzone-unleashed-s2');
alter table public.tournaments enable trigger tournaments_guard_update;

alter table public.tournaments add constraint tournaments_sponsor_status_check check (
  sponsor_status in ('none', 'pending', 'confirmed')
  and (sponsor_status <> 'confirmed' or sponsor_name is not null)
);
grant insert (sponsor_status) on table public.tournaments to authenticated;
grant update (sponsor_status) on table public.tournaments to authenticated;

-- Update guard: same as before, plus sponsor_status.
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
    or new.sponsor_status is distinct from old.sponsor_status
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

-- 2. Insert guard: money and sponsors are admin-only when an event is created too.
create function private.guard_tournament_insert()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if not private.is_admin() and (
    coalesce(new.entry_fee_usd_cents, 0) <> 0
    or coalesce(new.prize_1_usd_cents, 0) <> 0
    or coalesce(new.prize_2_usd_cents, 0) <> 0
    or coalesce(new.prize_3_usd_cents, 0) <> 0
    or new.sponsor_name is not null
    or new.sponsor_status <> 'none'
  ) then
    raise exception 'admins_only' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_tournament_insert() from public;
create trigger tournaments_guard_insert
  before insert on public.tournaments
  for each row execute function private.guard_tournament_insert();

-- 3. Capacity, locked -------------------------------------------------------
create or replace function private.check_entry_capacity()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  cap integer;
begin
  -- Lock the event row: registrations for the same event wait for each other,
  -- so two players can't both take the last place.
  select max_players into cap from public.tournaments where id = new.tournament_id for update;
  if (
    select count(*) from public.tournament_entries
    where tournament_id = new.tournament_id and status in ('pending', 'approved')
  ) >= cap then
    raise exception 'tournament_full' using errcode = 'PT409';
  end if;
  return new;
end;
$$;

-- 4. Status moves -----------------------------------------------------------
create function private.guard_status_change()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status is distinct from old.status and not private.is_admin()
     and (old.status, new.status) not in (
       ('upcoming', 'open'), ('upcoming', 'live'),
       ('open', 'upcoming'), ('open', 'live'), ('open', 'completed'),
       ('live', 'completed')
     ) then
    raise exception 'bad_status_change' using errcode = 'PT409';
  end if;
  return new;
end;
$$;
revoke all on function private.guard_status_change() from public;
create trigger tournaments_guard_status
  before update of status on public.tournaments
  for each row execute function private.guard_status_change();

-- Event cards carry the sponsor status (return type changes → recreate).
drop function public.event_cards();
create function public.event_cards()
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
  where t.game = 'codm'
  order by t.created_at desc
  limit 100;
$$;
revoke all on function public.event_cards() from public;
grant execute on function public.event_cards() to anon, authenticated;
