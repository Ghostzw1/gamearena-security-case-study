-- Social directive v4, Stage 4: content and discovery (Parts 8.2, 8.3).
--
-- Why: players need a reason to open GameArena on a day without a
-- tournament: their friends' and clan's posts. This adds posts (text and one
-- photo), comments, reactions (a small fixed set), the Home feed (newest
-- first from your network, pinned official announcements on top), "Popular
-- this week" (public posts with the most comments and reactions over 7 days,
-- computed in SQL, called what it is), opt-in posts for verified
-- achievements (each points at the result that earned it), official
-- announcements (admins, labelled and audited), reports for posts and
-- comments, and "people you may know" (real mutual-friend counts).
--
-- Privacy: a post is public (signed-in players), friends or clan. Blocked
-- players never see each other's posts or comments. Photos live in a private
-- bucket and are served with short signed links to people who can see the
-- post. Phone numbers are refused in posts and comments; links are allowed
-- and rendered with rel="nofollow ugc noopener" (Part 11).
--
-- Rollback: drop the functions created here, tables post_reactions,
-- post_comments, posts, the post-media bucket and its policies; restore the
-- report functions and notification checks from 20261127170000 / 20261127200000.

-- 1. Posts --------------------------------------------------------------------------
create table public.posts (
  id bigint generated always as identity primary key,
  author_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  kind text not null default 'post',
  body text,
  visibility text not null default 'public',
  game text not null default 'codm',
  media_path text,
  achievement_code text,
  tournament_slug text,
  pinned boolean not null default false,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  constraint posts_kind_check check (kind in ('post', 'achievement', 'announcement')),
  constraint posts_visibility_check check (visibility in ('public', 'friends', 'clan')),
  constraint posts_game_check check (game = 'codm'),
  -- Line breaks are fine in posts; other control and hidden characters aren't.
  constraint posts_body_check check (body is null or (char_length(body) between 1 and 500 and private.clean_text(replace(body, E'\n', ' ')))),
  constraint posts_media_check check (media_path is null or media_path ~ '^[0-9a-f-]{36}/[0-9a-f-]{36}\.(jpg|png|webp)$'),
  constraint posts_content_check check (body is not null or media_path is not null or kind = 'achievement'),
  constraint posts_achievement_check check ((kind = 'achievement') = (achievement_code is not null))
);
create index posts_author_idx on public.posts (author_id, created_at desc);
create index posts_recent_idx on public.posts (created_at desc) where deleted_at is null;
create unique index posts_one_share_per_achievement on public.posts (author_id, achievement_code) where kind = 'achievement' and deleted_at is null;

create function private.can_see_post(post bigint)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.posts p
    where p.id = post and p.deleted_at is null
      and (
        p.author_id = (select auth.uid())
        or private.is_admin()
        or ((select auth.uid()) is not null
            and not private.blocked_either(p.author_id, (select auth.uid()))
            and (
              p.kind = 'announcement' or p.visibility = 'public'
              or (p.visibility = 'friends' and private.are_friends(p.author_id, (select auth.uid())))
              or (p.visibility = 'clan' and private.share_clan(p.author_id, (select auth.uid())))
            ))
      )
  );
$$;
revoke all on function private.can_see_post(bigint) from public;
grant execute on function private.can_see_post(bigint) to authenticated;

alter table public.posts enable row level security;
revoke all on table public.posts from public, anon, authenticated;
grant select on table public.posts to authenticated;
create policy "Players see the posts they're allowed to"
  on public.posts for select to authenticated
  using (private.can_see_post(id));

-- No phone numbers in posts (links are allowed, rendered safely).
create function private.refuse_phones(t text)
returns void
language plpgsql
immutable
set search_path = ''
as $$
begin
  if t is not null and regexp_replace(t, '[[:space:].()-]', '', 'g') ~ '[0-9]{9,}' then
    raise exception 'no_phone_numbers' using errcode = 'PT422';
  end if;
end;
$$;
revoke all on function private.refuse_phones(text) from public;

create function public.create_post(p_body text, p_visibility text, p_media text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  new_id bigint;
  body text := nullif(btrim(p_body), '');
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  -- A photo must be your own upload in the post-media bucket.
  if nullif(p_media, '') is not null and (
    split_part(p_media, '/', 1) <> me::text
    or not exists (select 1 from storage.objects o where o.bucket_id = 'post-media' and o.name = p_media)
  ) then
    raise exception 'not_your_upload' using errcode = '42501';
  end if;
  perform private.refuse_phones(body);
  -- 10 posts a day; 3 for accounts younger than 24 hours.
  perform private.hit_limit('post',
    case when (select p.created_at from public.profiles p where p.id = me) > now() - interval '24 hours' then 3 else 10 end,
    interval '1 day');
  insert into public.posts (author_id, kind, body, visibility, media_path)
  values (me, 'post', body, coalesce(p_visibility, 'public'), nullif(p_media, ''))
  returning id into new_id;
  return new_id;
end;
$$;

-- Delete your own post (admins: any, audited). Returns the photo path so the
-- server can remove the file too.
create function public.delete_post(post bigint)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.posts;
begin
  select * into p from public.posts where id = post and deleted_at is null;
  if p.id is null or not (p.author_id = (select auth.uid()) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  -- The photo path stays on the row (nobody can open it once the post is
  -- deleted); the app removes the author's file from storage.
  update public.posts set deleted_at = now() where id = post;
  if p.author_id <> (select auth.uid()) then
    perform private.audit('post.deleted', null, p.author_id, jsonb_build_object('post', post));
  end if;
  return p.media_path;
end;
$$;

-- Admin: an official GameArena announcement (labelled), optionally pinned.
create function public.create_announcement(p_body text, p_pinned boolean)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  new_id bigint;
begin
  perform private.require_admin();
  insert into public.posts (author_id, kind, body, visibility, pinned)
  values ((select auth.uid()), 'announcement', nullif(btrim(p_body), ''), 'public', coalesce(p_pinned, false))
  returning id into new_id;
  perform private.audit('post.announced', null, null, jsonb_build_object('post', new_id, 'pinned', p_pinned));
  return new_id;
end;
$$;

-- Opt-in: share one of your verified achievements (it must really be yours,
-- computed from confirmed results; it points at the tournament that earned it).
create function public.share_achievement(code text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  a record;
  new_id bigint;
begin
  select * into a from public.player_achievements(me) x where x.code = share_achievement.code limit 1;
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  if a.code is null then
    raise exception 'not_earned' using errcode = 'PT409';
  end if;
  if exists (select 1 from public.posts p where p.author_id = me and p.kind = 'achievement'
             and p.achievement_code = a.code and p.deleted_at is null) then
    raise exception 'already_shared' using errcode = 'PT409';
  end if;
  perform private.hit_limit('post', 10, interval '1 day');
  insert into public.posts (author_id, kind, visibility, achievement_code, tournament_slug)
  values (me, 'achievement', 'public', a.code, a.tournament_slug)
  returning id into new_id;
  return new_id;
end;
$$;

-- 2. Comments and reactions ---------------------------------------------------------
create table public.post_comments (
  id bigint generated always as identity primary key,
  post_id bigint not null references public.posts (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  constraint post_comments_body_check check (char_length(body) between 1 and 300 and body = btrim(body) and private.clean_text(body))
);
create index post_comments_post_idx on public.post_comments (post_id, created_at);
alter table public.post_comments enable row level security;
revoke all on table public.post_comments from public, anon, authenticated;
grant select on table public.post_comments to authenticated;
create policy "Comments on posts you can see, from people you haven't blocked"
  on public.post_comments for select to authenticated
  using (deleted_at is null and private.can_see_post(post_id) and not private.blocked_either(user_id, (select auth.uid())));

create table public.post_reactions (
  post_id bigint not null references public.posts (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  emoji text not null,
  created_at timestamptz not null default now(),
  primary key (post_id, user_id),
  constraint post_reactions_emoji_check check (emoji in ('fire', 'gg', 'laugh', 'trophy'))
);
alter table public.post_reactions enable row level security;
revoke all on table public.post_reactions from public, anon, authenticated;
grant select on table public.post_reactions to authenticated;
create policy "Reactions on posts you can see"
  on public.post_reactions for select to authenticated
  using (private.can_see_post(post_id));

create function public.add_comment(post bigint, p_body text)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  new_id bigint;
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  if private.is_banned() then
    raise exception 'banned' using errcode = '42501';
  end if;
  if not private.can_see_post(post) then
    raise exception 'no_post' using errcode = 'PT404';
  end if;
  perform private.refuse_phones(p_body);
  perform private.hit_limit('post_comment', 20, interval '10 minutes');
  insert into public.post_comments (post_id, user_id, body) values (post, me, btrim(p_body)) returning id into new_id;
  return new_id;
end;
$$;

create function public.delete_comment(comment bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  c public.post_comments;
begin
  select * into c from public.post_comments where id = comment and deleted_at is null;
  if c.id is null or not (
    c.user_id = (select auth.uid())
    or exists (select 1 from public.posts p where p.id = c.post_id and p.author_id = (select auth.uid()))
    or private.is_admin()
  ) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  update public.post_comments set deleted_at = now() where id = comment;
end;
$$;

-- React with one of 4 (or null to take it back). One reaction per player per post.
create function public.react_to_post(post bigint, p_emoji text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if me is null or not private.can_see_post(post) then
    raise exception 'no_post' using errcode = 'PT404';
  end if;
  perform private.hit_limit('reaction', 60, interval '1 minute');
  if p_emoji is null then
    delete from public.post_reactions where post_id = post and user_id = me;
  else
    insert into public.post_reactions (post_id, user_id, emoji) values (post, me, p_emoji)
    on conflict (post_id, user_id) do update set emoji = excluded.emoji, created_at = now();
  end if;
end;
$$;

-- 3. Notifications: comments on your post (one per post until read) ------------------
alter table public.notifications drop constraint notifications_kind_check;
alter table public.notifications add constraint notifications_kind_check check (kind in (
  'match_5h', 'match_1h', 'room', 'friend_request', 'friend_accepted', 'message',
  'entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled',
  'squad_request', 'squad_answered', 'clan_announcement', 'clan_invite', 'post_comment'
));
alter table public.notifications drop constraint notifications_url_check;
alter table public.notifications add constraint notifications_url_check check (
  char_length(url) <= 200
  and url ~ '^/((codm|chats|compete|discover|players|notifications|me|posts)(/[a-z0-9-]+)*)?(#[a-z0-9-]+)?$'
);

-- Comment alerts follow the "Friends and social" phone setting.
create or replace function private.notify(p_user uuid, p_kind text, p_tournament uuid, p_ref text, p_title text, p_body text, p_url text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  np public.notification_prefs;
  push boolean;
begin
  select * into np from public.notification_prefs where user_id = p_user;
  push := case
    when np.user_id is null then true
    when p_kind = 'message' then np.message_alerts
    when p_kind in ('friend_request', 'friend_accepted', 'post_comment') then np.social_alerts
    when p_kind in ('squad_request', 'squad_answered') then np.squad_alerts
    when p_kind in ('clan_announcement', 'clan_invite') then np.clan_alerts
    when p_kind in ('entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled') then np.tournament_alerts
    else true
  end;
  if p_tournament is null then
    insert into public.notifications (user_id, kind, tournament_id, ref, title, body, url, pushed_at)
    values (p_user, p_kind, null, p_ref, left(p_title, 80), left(p_body, 200), p_url, case when push then null else now() end)
    on conflict (user_id, kind, ref) where tournament_id is null do nothing;
  else
    insert into public.notifications (user_id, kind, tournament_id, ref, title, body, url, pushed_at)
    values (p_user, p_kind, p_tournament, p_ref, left(p_title, 80), left(p_body, 200), p_url, case when push then null else now() end)
    on conflict (user_id, kind, tournament_id) do nothing;
  end if;
end;
$$;

create function private.notify_post_comment()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.posts;
  who public.profiles;
begin
  select * into p from public.posts where id = new.post_id;
  if p.author_id = new.user_id then
    return new;
  end if;
  select * into who from public.profiles where id = new.user_id;
  perform private.notify(p.author_id, 'post_comment', null, 'pc:' || p.id,
    'New comment', who.username || ' commented on your post.', '/posts/' || p.id);
  return new;
end;
$$;
revoke all on function private.notify_post_comment() from public;
create trigger post_comments_notify
  after insert on public.post_comments
  for each row execute function private.notify_post_comment();

-- Opening your post clears its comment notification, so the next comment
-- notifies you again.
create function public.mark_post_seen(post bigint)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.notifications
  where user_id = (select auth.uid()) and kind = 'post_comment' and ref = 'pc:' || post;
$$;

-- 4. The feed ---------------------------------------------------------------------------
-- Rows for any list of posts (feed, popular, a profile, one post).
create function private.post_rows(ids bigint[])
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, p.kind, p.author_id, a.username, a.username_key, a.clan_tag, a.avatar_id,
    p.body, p.visibility, p.media_path, p.achievement_code, p.tournament_slug, p.pinned, p.created_at,
    coalesce((select jsonb_object_agg(x.emoji, x.n) from (
      select r.emoji, count(*) n from public.post_reactions r where r.post_id = p.id group by r.emoji) x), '{}'::jsonb),
    (select r.emoji from public.post_reactions r where r.post_id = p.id and r.user_id = (select auth.uid())),
    (select count(*) from public.post_comments c where c.post_id = p.id and c.deleted_at is null
       and not private.blocked_either(c.user_id, (select auth.uid())))::integer
  from public.posts p
  join public.profiles a on a.id = p.author_id
  where p.id = any(ids) and private.can_see_post(p.id);
$$;
revoke all on function private.post_rows(bigint[]) from public;

-- Your network: you, your friends and your clan, plus official announcements.
-- Newest first, 20 at a time (cursor: created_at of the last one you saw).
create function public.home_feed(p_before timestamptz, p_limit integer)
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.* from private.post_rows(array(
    select p.id from public.posts p
    where p.deleted_at is null
      and p.created_at < coalesce(p_before, 'infinity'::timestamptz)
      and not (p.kind = 'announcement' and p.pinned)
      and private.can_see_post(p.id)
      and (p.author_id = (select auth.uid())
           or p.kind = 'announcement'
           or private.are_friends(p.author_id, (select auth.uid()))
           or private.share_clan(p.author_id, (select auth.uid())))
    order by p.created_at desc
    limit least(greatest(coalesce(p_limit, 20), 1), 50)
  )) r
  order by r.created_at desc;
$$;

-- Pinned official announcements (shown on top of Home).
create function public.pinned_posts()
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.* from private.post_rows(array(
    select p.id from public.posts p
    where p.deleted_at is null and p.kind = 'announcement' and p.pinned
    order by p.created_at desc limit 3
  )) r
  order by r.created_at desc;
$$;

-- "Popular this week": public posts from the last 7 days with the most
-- comments and reactions. Exactly that, nothing hidden.
create function public.popular_posts()
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.* from private.post_rows(array(
    select p.id from public.posts p
    where p.deleted_at is null and p.visibility = 'public' and p.created_at > now() - interval '7 days'
      and private.can_see_post(p.id)
      and ((select count(*) from public.post_reactions x where x.post_id = p.id)
           + (select count(*) from public.post_comments c where c.post_id = p.id and c.deleted_at is null)) > 0
    order by (select count(*) from public.post_reactions x where x.post_id = p.id)
           + (select count(*) from public.post_comments c where c.post_id = p.id and c.deleted_at is null) desc,
             p.created_at desc
    limit 20
  )) r
  order by r.comments + (select coalesce(sum(v::integer), 0) from jsonb_each_text(r.reactions) e(k, v)) desc, r.created_at desc;
$$;

-- One player's posts you're allowed to see (their profile).
create function public.player_posts(player uuid, p_before timestamptz)
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.* from private.post_rows(array(
    select p.id from public.posts p
    where p.author_id = player and p.deleted_at is null and private.can_see_post(p.id)
      and p.created_at < coalesce(p_before, 'infinity'::timestamptz)
    order by p.created_at desc limit 20
  )) r
  order by r.created_at desc;
$$;

create function public.post_detail(post bigint)
returns table (
  id bigint, kind text, author_id uuid, author text, author_key text, author_tag text, author_avatar text,
  body text, visibility text, media_path text, achievement_code text, tournament_slug text, pinned boolean,
  created_at timestamptz, reactions jsonb, my_reaction text, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.* from private.post_rows(array[post]) r;
$$;

create function public.post_thread(post bigint)
returns table (id bigint, body text, created_at timestamptz, author text, author_key text, author_tag text, author_avatar text, mine boolean, can_delete boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select c.id, c.body, c.created_at, a.username, a.username_key, a.clan_tag, a.avatar_id,
    c.user_id = (select auth.uid()),
    c.user_id = (select auth.uid()) or p.author_id = (select auth.uid()) or private.is_admin()
  from public.post_comments c
  join public.posts p on p.id = c.post_id
  join public.profiles a on a.id = c.user_id
  where c.post_id = post and c.deleted_at is null and private.can_see_post(post)
    and not private.blocked_either(c.user_id, (select auth.uid()))
  order by c.created_at
  limit 200;
$$;

-- 5. People you may know (real counts: mutual friends; clan mates) ----------------------
create function public.suggested_players()
returns table (username text, username_key text, avatar_id text, clan_tag text, mutual_friends integer, same_clan boolean)
language sql
stable
security definer
set search_path = ''
as $$
  with me as (select (select auth.uid()) id),
  my_friends as (
    select case when f.low = me.id then f.high else f.low end friend
    from public.friendships f, me where f.status = 'accepted' and me.id in (f.low, f.high)
  ),
  candidates as (
    select case when f.low = mf.friend then f.high else f.low end player, count(*) mutual
    from public.friendships f join my_friends mf on mf.friend in (f.low, f.high)
    where f.status = 'accepted'
    group by 1
    union all
    select m2.user_id, 0 from public.clan_members m1
    join public.clan_members m2 on m2.channel_id = m1.channel_id
    join me on m1.user_id = me.id
  ),
  scored as (select player, max(mutual) mutual from candidates group by player)
  select p.username, p.username_key, p.avatar_id, p.clan_tag, s.mutual::integer, private.share_clan(p.id, (select auth.uid()))
  from scored s join public.profiles p on p.id = s.player, me
  where s.player <> me.id
    and not exists (select 1 from public.friendships f where least(me.id, s.player) = f.low and greatest(me.id, s.player) = f.high)
    and not private.blocked_either(me.id, s.player)
  order by s.mutual desc, p.username_key
  limit 10;
$$;

-- 6. Photos for posts: a private bucket, served with signed links ----------------------
insert into storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
values ('post-media', 'post-media', false, 3145728, array['image/jpeg', 'image/png', 'image/webp'])
on conflict (id) do update
  set public = false, file_size_limit = excluded.file_size_limit, allowed_mime_types = excluded.allowed_mime_types;

create function private.can_see_post_media(path text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (select 1 from public.posts p where p.media_path = path and private.can_see_post(p.id));
$$;
revoke all on function private.can_see_post_media(text) from public;
grant execute on function private.can_see_post_media(text) to authenticated;

create policy "Post media: upload into your own folder"
  on storage.objects for insert to authenticated
  with check (bucket_id = 'post-media' and (storage.foldername(name))[1] = (select auth.uid())::text and not private.is_banned());
create policy "Post media: open photos of posts you can see"
  on storage.objects for select to authenticated
  using (bucket_id = 'post-media' and ((storage.foldername(name))[1] = (select auth.uid())::text or private.can_see_post_media(name)));
create policy "Post media: delete your own uploads"
  on storage.objects for delete to authenticated
  using (bucket_id = 'post-media' and (storage.foldername(name))[1] = (select auth.uid())::text);

-- 7. Reports for posts and comments --------------------------------------------------------
alter table public.content_reports drop constraint content_reports_kind_check;
alter table public.content_reports drop constraint content_reports_subject_check;
alter table public.content_reports
  add constraint content_reports_kind_check check (kind in ('squad_post', 'idea', 'idea_comment', 'player', 'clan', 'post', 'post_comment')),
  add constraint content_reports_subject_check check (
    (kind in ('squad_post', 'idea', 'idea_comment', 'post', 'post_comment') and ref is not null and target is null)
    or (kind in ('player', 'clan') and target is not null and ref is null)
  );
alter policy "Players report what they can see" on public.content_reports
  with check (
    reporter_id = (select auth.uid())
    and case kind
      when 'squad_post' then exists (select 1 from public.squad_posts s where s.id = ref)
      when 'idea' then exists (select 1 from public.ideas i where i.id = ref)
      when 'idea_comment' then exists (select 1 from public.idea_comments c where c.id = ref)
      when 'post' then private.can_see_post(ref)
      when 'post_comment' then exists (select 1 from public.post_comments c where c.id = ref and c.deleted_at is null and private.can_see_post(c.post_id))
      when 'player' then target <> (select auth.uid()) and exists (select 1 from public.profiles p where p.id = target)
      when 'clan' then exists (select 1 from public.chat_channels c where c.id = target and c.kind = 'clan')
      else false
    end
  );

create or replace function private.report_subject(p_kind text, p_ref bigint, p_target uuid)
returns table (owner_id uuid, preview text)
language sql
stable
security definer
set search_path = ''
as $$
  select s.author_id, left(coalesce(s.body, s.availability, 'Squad post (' || s.mode || ', ' || s.region || ')'), 300)
    from public.squad_posts s where p_kind = 'squad_post' and s.id = p_ref
  union all
  select i.user_id, left(i.body, 300) from public.ideas i where p_kind = 'idea' and i.id = p_ref
  union all
  select c.user_id, left(c.body, 300) from public.idea_comments c where p_kind = 'idea_comment' and c.id = p_ref
  union all
  select p.author_id, left(coalesce(p.body, '(photo)'), 300) from public.posts p where p_kind = 'post' and p.id = p_ref
  union all
  select c.user_id, left(c.body, 300) from public.post_comments c where p_kind = 'post_comment' and c.id = p_ref
  union all
  select p.id, p.username from public.profiles p where p_kind = 'player' and p.id = p_target
  union all
  select c.owner_id, coalesce('[' || c.tag || '] ', '') || c.name || coalesce(': ' || c.description, '')
    from public.chat_channels c where p_kind = 'clan' and c.id = p_target and c.kind = 'clan';
$$;

revoke all on function public.create_post(text, text, text) from public, anon;
revoke all on function public.delete_post(bigint) from public, anon;
revoke all on function public.create_announcement(text, boolean) from public, anon;
revoke all on function public.share_achievement(text) from public, anon;
revoke all on function public.add_comment(bigint, text) from public, anon;
revoke all on function public.delete_comment(bigint) from public, anon;
revoke all on function public.react_to_post(bigint, text) from public, anon;
revoke all on function public.home_feed(timestamptz, integer) from public, anon;
revoke all on function public.pinned_posts() from public, anon;
revoke all on function public.popular_posts() from public, anon;
revoke all on function public.player_posts(uuid, timestamptz) from public, anon;
revoke all on function public.post_detail(bigint) from public, anon;
revoke all on function public.post_thread(bigint) from public, anon;
revoke all on function public.suggested_players() from public, anon;
grant execute on function public.create_post(text, text, text) to authenticated;
grant execute on function public.delete_post(bigint) to authenticated;
grant execute on function public.create_announcement(text, boolean) to authenticated;
grant execute on function public.share_achievement(text) to authenticated;
grant execute on function public.add_comment(bigint, text) to authenticated;
grant execute on function public.delete_comment(bigint) to authenticated;
grant execute on function public.react_to_post(bigint, text) to authenticated;
grant execute on function public.home_feed(timestamptz, integer) to authenticated;
grant execute on function public.pinned_posts() to authenticated;
grant execute on function public.popular_posts() to authenticated;
grant execute on function public.player_posts(uuid, timestamptz) to authenticated;
grant execute on function public.post_detail(bigint) to authenticated;
grant execute on function public.post_thread(bigint) to authenticated;
grant execute on function public.suggested_players() to authenticated;

-- Removing a reported post or comment hides it (soft delete; the row stays
-- for the audit trail). Same rules as before for the other kinds.
create or replace function public.resolve_content_report(
  p_kind text, p_decision text, p_note text default null, p_ref bigint default null, p_target uuid default null, p_ban_days integer default null
)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  subj record;
  note text := nullif(btrim(p_note), '');
begin
  perform private.require_admin();
  if p_decision not in ('dismissed', 'removed', 'banned') then
    raise exception 'bad_decision' using errcode = '22023';
  end if;
  if p_decision = 'removed' and p_kind = 'player' then
    raise exception 'bad_decision' using errcode = '22023';
  end if;
  if p_ban_days is not null and (p_ban_days < 1 or p_ban_days > 365) then
    raise exception 'bad_ban_days' using errcode = '22023';
  end if;
  select * into subj from private.report_subject(p_kind, p_ref, p_target);

  update public.content_reports
     set status = case when p_decision = 'dismissed' then 'dismissed' else 'resolved' end,
         decision = p_decision, decision_note = note, resolved_by = me, resolved_at = now()
   where kind = p_kind and coalesce(ref::text, target::text) = coalesce(p_ref::text, p_target::text) and status = 'open';
  if not found then
    raise exception 'no_open_reports' using errcode = 'PT404';
  end if;

  if p_decision in ('removed', 'banned') then
    case p_kind
      when 'squad_post' then update public.squad_posts set status = 'closed' where id = p_ref;
      when 'idea' then delete from public.ideas where id = p_ref;
      when 'idea_comment' then delete from public.idea_comments where id = p_ref;
      when 'post' then update public.posts set deleted_at = coalesce(deleted_at, now()) where id = p_ref;
      when 'post_comment' then update public.post_comments set deleted_at = coalesce(deleted_at, now()) where id = p_ref;
      when 'clan' then update public.chat_channels set approved = false where id = p_target and kind = 'clan';
      else null;
    end case;
  end if;
  if p_decision = 'banned' then
    if subj.owner_id is null then
      raise exception 'no_owner' using errcode = 'PT404';
    end if;
    insert into public.chat_bans (user_id, reason, banned_by, banned_until)
    values (subj.owner_id, coalesce(note, 'Broke the community rules'), me,
            case when p_ban_days is null then null else now() + make_interval(days => p_ban_days) end)
    on conflict (user_id) do update
      set reason = excluded.reason, banned_by = excluded.banned_by, banned_until = excluded.banned_until;
  end if;

  perform private.audit('content_report.resolved', null, subj.owner_id,
    jsonb_build_object('kind', p_kind, 'ref', p_ref, 'target', p_target, 'decision', p_decision, 'ban_days', p_ban_days));
end;
$$;

revoke all on function public.mark_post_seen(bigint) from public, anon;
grant execute on function public.mark_post_seen(bigint) to authenticated;
