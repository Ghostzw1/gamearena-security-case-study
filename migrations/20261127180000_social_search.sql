-- Social directive v4, Stage 1: one search for players and clans (Part 5.3).
--
-- Why: players need to find each other and clans from one box at the top of
-- Home and Discover. It tolerates typos ("dynasti" finds DYNASTY) using the
-- built-in pg_trgm extension (no search service), runs on the server, is
-- rate-limited, signed-in only, and never shows players either side blocked.
-- Results are grouped by kind with the best match first.
--
-- Rollback: drop function public.search_all(text); drop index
-- profiles_username_key_trgm; drop index chat_channels_clan_name_trgm;
-- (leave the extension: other things may use it).

create schema if not exists extensions;
create extension if not exists pg_trgm with schema extensions;

create index if not exists profiles_username_key_trgm
  on public.profiles using gin (username_key extensions.gin_trgm_ops);
create index if not exists chat_channels_clan_name_trgm
  on public.chat_channels using gin (lower(name) extensions.gin_trgm_ops) where kind = 'clan';

create function public.search_all(q text)
returns table (kind text, key text, title text, subtitle text, avatar_id text, tag text, score real)
language plpgsql
volatile
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  k text := private.username_key(left(coalesce(q, ''), 40));
  t text := lower(btrim(left(coalesce(q, ''), 40)));
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if char_length(k) < 2 and char_length(t) < 2 then
    return;
  end if;
  perform private.hit_limit('search', 60, interval '1 minute');
  return query
    (select 'player'::text, p.username_key, p.username, null::text, p.avatar_id, p.clan_tag,
        (greatest(extensions.similarity(p.username_key, k),
                  case when p.username_key like '%' || k || '%' then 0.6 else 0 end)
         + case when p.username_key like k || '%' then 0.3 else 0 end)::real as s
     from public.profiles p
     where char_length(k) >= 2
       and p.username_key is not null
       and (p.username_key like '%' || k || '%' or extensions.similarity(p.username_key, k) > 0.3)
       and p.id <> me
       and not private.blocked_either(p.id, me)
     order by s desc, char_length(p.username_key)
     limit 10)
    union all
    (select 'clan'::text, c.slug, c.name,
        (select count(*) from public.clan_members m where m.channel_id = c.id)::text || ' members',
        null::text, c.tag,
        (greatest(extensions.similarity(lower(c.name), t),
                  case when lower(c.name) like '%' || t || '%' then 0.6 else 0 end,
                  case when lower(coalesce(c.tag, '')) = t then 1 else 0 end))::real as s
     from public.chat_channels c
     where c.kind = 'clan' and c.approved
       and (lower(c.name) like '%' || t || '%' or lower(coalesce(c.tag, '')) = t or extensions.similarity(lower(c.name), t) > 0.3)
     order by s desc, c.name
     limit 10);
end;
$$;
revoke all on function public.search_all(text) from public, anon;
grant execute on function public.search_all(text) to authenticated;
