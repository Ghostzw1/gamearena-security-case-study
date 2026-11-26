-- Usernames with symbols (owner, 2026-11-26): players can use the symbols and
-- fancy letters they use in CODM (亗, ꧁ ꧂, ★, 𝕲𝖍𝖔𝖘𝖙 …) in their GameArena name.
--
-- Safety:
--   * still 3–20 characters, no spaces, no control, hidden or text-direction
--     characters (Trojan Source, blank names), no combining marks (glitch text),
--   * no < > " ' ` / \ [ ] @ ([ ] is kept for clan tags, @ for mentions),
--   * at least 2 normal letters or numbers once fancy letters are turned back
--     into plain ones, so every name can be typed and found,
--   * one "key" per name: NFKD, look-alike letters mapped to Latin, letters
--     and numbers only, lower case. Two names
--     with the same key can't both exist, so "★Ghost★" or "𝕲𝖍𝖔𝖘𝖙" can't pose
--     as "Ghost".
-- Hidden characters appear only as \uXXXX escapes, never typed raw.
--
-- Also: a general per-player rate limit (private.hit_limit) and at most 20
-- profile changes a minute, now that avatars save on every tap.

-- 1. The name key and the rule.
create function private.username_key(u text)
returns text
language sql
immutable
parallel safe
set search_path = ''
as $$
  -- NFKD turns fancy letters into plain ones; translate() maps look-alike
  -- letters (list from lib/username.ts, LOOKALIKE_PAIRS); the rest is removed.
  select lower(regexp_replace(
    translate(normalize(coalesce(u, ''), NFKD), 'АВЕЅІЈКМНОРСТУХҮҺӀԀԚԜӇҜӾаеѕіјорсухүһӏԁԛԝΑΒΕΖΗΙΚΜΝΟΡΤΥΧαοικνρτυχϲϳØøĐđÐðŁłƁƇƈƦƧƨıȷɌɍŦŧĦħɡ¥€ᴀʙᴄᴅᴇꜰɢʜɪᴊᴋʟᴍɴᴏᴘʀꜱᴛᴜᴠᴡʏᴢᎪᏴᏟᎬᏀᎻᎫᏦᏞᎷᏢᏚᎢᏙᎳᏃ卂乃匚ᗪ乇卄丨几ㄖ卩尺丂ㄒㄩᐯ山ㄚ乙爪ㄥ', 'ABESIJKMHOPCTYXYHIDQWHKXaesijopcyxyhldqwABEZHIKMNOPTYXaoikvptuxcjOoDdDdLlBCcRSsijRrTtHhgYEabcdefghijklmnoprstuvwyzABCEGHJKLMPSTVWZABCDEHINOPRSTUVWYZML'),
    '[^A-Za-z0-9]', '', 'g'))
$$;

create function private.is_valid_username(u text)
returns boolean
language sql
immutable
parallel safe
set search_path = ''
as $$
  select u is not null
    and char_length(u) between 3 and 20
    and u !~ '[[:space:][:cntrl:]]'
    and u !~ '[<>"''`/\\\[\]@]'
    and u !~ '[\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\u2800\u3164\uFE00-\uFE0F\uFEFF\uFFA0]'
    and u !~ '[\u0300-\u036F\u1AB0-\u1AFF\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]'
    and char_length(private.username_key(u)) >= 2
$$;

grant execute on function private.username_key(text) to anon, authenticated;
grant execute on function private.is_valid_username(text) to anon, authenticated;

alter table public.profiles drop constraint profiles_username_check;
alter table public.profiles add constraint profiles_username_check check (private.is_valid_username(username));
alter table public.profiles add column username_key text generated always as (private.username_key(username)) stored;
drop index if exists public.profiles_username_lower_key;
create unique index profiles_username_key_key on public.profiles (username_key);

-- 2. "Is this name free?" (sign-up form, works before signing in).
create or replace function public.is_username_available(candidate text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.is_valid_username(candidate)
    and not exists (
      select 1 from public.profiles where username_key = private.username_key(candidate)
    )
$$;

-- 3. Admins and hosts add staff by typing the name: fancy letters and symbols
--    don't have to be typed exactly ("ghost" finds "꧁𝕲𝖍𝖔𝖘𝖙꧂").
create or replace function public.add_tournament_staff(t uuid, player_username text, staff_role text)
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
  select * into target from public.profiles
  where username_key = private.username_key(btrim(player_username)) and char_length(private.username_key(btrim(player_username))) >= 2;
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

-- Admin tools: find a player by name the same forgiving way.
create function public.admin_find_player(player_name text)
returns table (id uuid, username text)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, p.username from public.profiles p
  where private.is_admin()
    and char_length(private.username_key(btrim(player_name))) >= 2
    and p.username_key = private.username_key(btrim(player_name))
$$;
revoke all on function public.admin_find_player(text) from public, anon;
grant execute on function public.admin_find_player(text) to authenticated;

-- 4. A general rate limit for writes players can trigger.
create table private.rate_counters (
  user_id uuid not null,
  bucket text not null,
  window_start timestamptz not null,
  hits integer not null,
  primary key (user_id, bucket)
);
alter table private.rate_counters enable row level security;
revoke all on table private.rate_counters from public, anon, authenticated;

-- Counts one hit for the signed-in player; PT429 once `p_max` is passed
-- inside the window. Called from triggers and functions, never directly.
create function private.hit_limit(p_bucket text, p_max integer, p_per interval)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := auth.uid();
  n integer;
begin
  if me is null then
    return;
  end if;
  insert into private.rate_counters as rc (user_id, bucket, window_start, hits)
  values (me, p_bucket, now(), 1)
  on conflict (user_id, bucket) do update
    set hits = case when rc.window_start < now() - p_per then 1 else rc.hits + 1 end,
        window_start = case when rc.window_start < now() - p_per then now() else rc.window_start end
  returning hits into n;
  if n > p_max then
    raise exception 'rate_limited' using errcode = 'PT429';
  end if;
end;
$$;
revoke all on function private.hit_limit(text, integer, interval) from public;
grant execute on function private.hit_limit(text, integer, interval) to authenticated;

-- Profile changes made by the player themself (not by database functions).
create function private.limit_profile_updates()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user = 'authenticated' then
    perform private.hit_limit('profile_update', 20, interval '1 minute');
  end if;
  return new;
end;
$$;
revoke all on function private.limit_profile_updates() from public;
create trigger profiles_limit_updates
  before update on public.profiles
  for each row execute function private.limit_profile_updates();
