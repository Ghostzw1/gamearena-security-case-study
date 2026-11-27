-- Social v4 Stage 3 follow-up: squad_board says whether each post is still
-- live (open and not ended), so pages don't need the clock to show the
-- "I need players" form or an "Ended" label. Same rules otherwise.

drop function public.squad_board();
create function public.squad_board()
returns table (
  id bigint, mode text, region text, rank text, needed integer, filled integer, voice text, when_kind text,
  starts_at timestamptz, body text, created_at timestamptz, expires_at timestamptz, status text,
  author text, author_key text, author_tag text, author_avatar text,
  mine boolean, my_request text, pending integer, chat_slug text, live boolean
)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.mode, s.region, s.rank, s.needed,
    (select count(*) from public.squad_post_requests r where r.post_id = s.id and r.status = 'accepted')::integer,
    s.voice, s.when_kind, s.starts_at, s.body, s.created_at, s.expires_at, s.status,
    p.username, p.username_key, p.clan_tag, p.avatar_id,
    s.author_id = (select auth.uid()),
    (select r.status from public.squad_post_requests r where r.post_id = s.id and r.user_id = (select auth.uid())),
    case when s.author_id = (select auth.uid())
      then (select count(*) from public.squad_post_requests r where r.post_id = s.id and r.status = 'pending')::integer
      else 0 end,
    -- The squad chat, only for people in it.
    (select c.slug from public.chat_channels c where c.id = s.chat_id and private.is_group_member(c.id)),
    -- Still open and not ended yet (the page can't use the clock itself).
    s.status = 'open' and s.expires_at > now()
  from public.squad_posts s
  join public.profiles p on p.id = s.author_id
  where (select auth.uid()) is not null
    and ((s.status = 'open' and s.expires_at > now()) or s.author_id = (select auth.uid())
         or exists (select 1 from public.squad_post_requests r where r.post_id = s.id and r.user_id = (select auth.uid()) and r.status = 'accepted'))
    and not private.blocked_either(s.author_id, (select auth.uid()))
  order by s.author_id = (select auth.uid()) desc, s.starts_at, s.created_at desc
  limit 100;
$$;
revoke all on function public.squad_board() from public, anon;
grant execute on function public.squad_board() to authenticated;
