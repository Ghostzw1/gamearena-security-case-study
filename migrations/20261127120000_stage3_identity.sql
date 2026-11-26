-- Stage 3: player identity (docs/MASTER-DIRECTIVE.md §07, §08).
--
-- * Profiles get a short bio and a visibility choice:
--     everyone : anyone, also people without an account (good for WhatsApp links)
--     players  : signed-in players only (default)
--     private  : name and avatar only; history, stats and achievements hidden
--   The player themself and admins always see everything.
-- * History, stats and achievements are computed live from the authoritative
--   records (approved entries + confirmed results via tournament_standings):
--   nothing is stored, so nothing can be fabricated or drift. Player claims
--   that no host or streamer confirmed never count.
-- * Achievements and their conditions (shown in the app too):
--     first_tournament : played (approved) in a tournament or room that went live
--     first_win        : a confirmed 1st place in any match
--     podium           : top 3 in a completed event with at least 3 teams
--     champion         : 1st in a completed event with at least 3 teams
--     active           : confirmed results in 5 or more events
--     contributor      : one of their ideas was planned or released
-- * search_players: find players by name (signed-in, rate-limited); the name
--   key ignores symbols and fancy letters, so "ghost" finds "꧁𝕲𝖍𝖔𝖘𝖙꧂".

alter table public.profiles
  add column bio text,
  add column profile_visibility text not null default 'players',
  add constraint profiles_bio_check check (
    bio is null or (char_length(bio) between 1 and 160 and bio = btrim(bio) and private.clean_text(bio))
  ),
  add constraint profiles_visibility_check check (profile_visibility in ('everyone', 'players', 'private'));
grant insert (bio, profile_visibility), update (bio, profile_visibility) on table public.profiles to authenticated;

-- May the caller see this player's details (bio, history, stats, achievements)?
create function private.can_see_details(player uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select coalesce(
    (select auth.uid()) = player
    or private.is_admin()
    or (select case p.profile_visibility
                 when 'everyone' then true
                 when 'players' then (select auth.uid()) is not null
                 else false
               end
        from public.profiles p where p.id = player),
    false)
$$;
revoke all on function private.can_see_details(uuid) from public;

-- The profile card. Visitors only get "everyone" profiles; a private (or,
-- for visitors, players-only) profile comes back "limited": name and avatar only.
create function public.player_card(player_key text)
returns table (
  id uuid, username text, username_key text, avatar_id text, clan_tag text, limited boolean,
  country text, bio text, codm_ign text, codm_uid text, member_since timestamptz, visibility text, is_me boolean
)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, p.username, p.username_key, p.avatar_id, p.clan_tag,
    not private.can_see_details(p.id),
    case when private.can_see_details(p.id) then p.country end,
    case when private.can_see_details(p.id) then p.bio end,
    case when private.can_see_details(p.id) then p.codm_ign end,
    case when private.can_see_details(p.id) then (select u.codm_uid from public.player_uids u where u.user_id = p.id and u.is_public) end,
    case when private.can_see_details(p.id) then p.created_at end,
    case when (select auth.uid()) = p.id then p.profile_visibility end,
    coalesce((select auth.uid()) = p.id, false)
  from public.profiles p
  where p.username_key = private.username_key(player_key)
    and char_length(private.username_key(player_key)) >= 2
    -- Visitors only see profiles the player opened to everyone.
    and ((select auth.uid()) is not null or p.profile_visibility = 'everyone');
$$;

-- Every event the player was approved for that went live, with the team's
-- confirmed totals and rank (only teams with confirmed results are ranked).
create function public.player_history(player uuid)
returns table (
  tournament_id uuid, slug text, name text, season integer, kind text, status text, played_at timestamptz,
  team text, rank integer, teams integer, points integer, kills integer, wins integer, matches integer
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
      sq.name, st.rank, st.teams, coalesce(st.points, 0), coalesce(st.kills, 0), coalesce(st.wins, 0), coalesce(st.counted, 0)
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

create function public.player_achievements(player uuid)
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
    played as (select * from h where h.matches > 0 order by h.played_at)
    select 'first_tournament'::text, x.played_at, x.slug
      from (select h.played_at, h.slug from h order by h.played_at limit 1) x
    union all
    select 'first_win', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.wins > 0 order by h.played_at limit 1) x
    union all
    select 'podium', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.status = 'completed' and h.rank <= 3 and h.teams >= 3 order by h.played_at limit 1) x
    union all
    select 'champion', x.played_at, x.slug
      from (select h.played_at, h.slug from h where h.status = 'completed' and h.rank = 1 and h.teams >= 3 order by h.played_at limit 1) x
    union all
    select 'active', x.played_at, x.slug
      from (select p.played_at, p.slug from played p offset 4 limit 1) x
    union all
    select 'contributor', x.created_at, null::text
      from (select i.created_at from public.ideas i where i.user_id = player and i.status in ('planned', 'done') order by i.created_at limit 1) x;
end;
$$;

-- Find players by name (signed-in only).
create function public.search_players(q text)
returns table (username text, username_key text, avatar_id text, clan_tag text)
language plpgsql
stable
security definer
set search_path = ''
as $$
declare
  k text := private.username_key(q);
begin
  if (select auth.uid()) is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if char_length(k) < 2 then
    return;
  end if;
  return query
    select p.username, p.username_key, p.avatar_id, p.clan_tag
    from public.profiles p
    where p.username_key like '%' || k || '%'
    order by (p.username_key like k || '%') desc, char_length(p.username_key), p.username_key
    limit 20;
end;
$$;

revoke all on function public.player_card(text) from public;
revoke all on function public.player_history(uuid) from public;
revoke all on function public.player_achievements(uuid) from public;
revoke all on function public.search_players(text) from public, anon;
grant execute on function public.player_card(text) to anon, authenticated;
grant execute on function public.player_history(uuid) to anon, authenticated;
grant execute on function public.player_achievements(uuid) to anon, authenticated;
grant execute on function public.search_players(text) to authenticated;
