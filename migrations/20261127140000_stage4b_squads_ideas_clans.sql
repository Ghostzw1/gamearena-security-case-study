-- Stage 4b: squad finder, Ideas Board, clan announcements
-- (docs/MASTER-DIRECTIVE.md §10.3, §10.4, §11, §15).
--
-- Squad finder: "looking for players" posts (mode, region, rank, roles, how many, when, a
-- short text) that expire after 7 days (max 14). Players ask to join with a
-- short message; the author accepts (you become friends, so you can message
-- each other) or declines. Limits: 2 open posts per player, 3 new posts a
-- day, 10 join requests an hour; blocked players can't ask each other.
-- Posts can be reported (content_reports, admins read them).
-- Ideas Board: categories, comments (10 per 10 minutes), statuses
-- submitted · review · planned · building · released · declined with an
-- optional note from the team (e.g. why it was declined); status changes are
-- written to the audit log.
-- Clans: the clan master can pin an announcement; members are notified.

-- 1. Squad finder ------------------------------------------------------------
create table public.squad_posts (
  id bigint generated always as identity primary key,
  author_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  game text not null default 'codm',
  mode text not null,
  region text not null,
  rank text not null default 'any',
  needed integer not null,
  roles text[] not null default '{}',
  availability text,
  body text,
  status text not null default 'open',
  created_at timestamptz not null default now(),
  expires_at timestamptz not null default now() + interval '7 days',
  constraint squad_posts_game_check check (game = 'codm'),
  constraint squad_posts_mode_check check (mode in ('br', 'mp')),
  constraint squad_posts_region_check check (region in ('ANY', 'ZA', 'ZW', 'ZM', 'BW', 'NA', 'MZ', 'MW', 'LS', 'SZ', 'AO')),
  constraint squad_posts_rank_check check (rank in ('any', 'rookie', 'veteran', 'elite', 'pro', 'master', 'grandmaster', 'legendary')),
  constraint squad_posts_needed_check check (needed between 1 and 4),
  constraint squad_posts_roles_check check (
    cardinality(roles) <= 6 and roles <@ array['slayer', 'sniper', 'support', 'igl', 'anchor', 'objective']::text[]
  ),
  constraint squad_posts_availability_check check (
    availability is null or (char_length(availability) between 2 and 60 and private.clean_text(availability))
  ),
  constraint squad_posts_body_check check (body is null or (char_length(body) between 2 and 300 and private.clean_text(body))),
  constraint squad_posts_status_check check (status in ('open', 'closed')),
  constraint squad_posts_expiry_check check (expires_at <= created_at + interval '14 days')
);
create index squad_posts_open_idx on public.squad_posts (status, expires_at desc);

create table public.squad_post_requests (
  post_id bigint not null references public.squad_posts (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  message text,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  primary key (post_id, user_id),
  constraint squad_post_requests_status_check check (status in ('pending', 'accepted', 'declined')),
  constraint squad_post_requests_message_check check (message is null or (char_length(message) between 2 and 140 and private.clean_text(message)))
);

alter table public.squad_posts enable row level security;
alter table public.squad_post_requests enable row level security;
revoke all on table public.squad_posts from public, anon, authenticated;
revoke all on table public.squad_post_requests from public, anon, authenticated;
grant select on table public.squad_posts to authenticated;
grant select on table public.squad_post_requests to authenticated;
create policy "Players see open posts, authors their own"
  on public.squad_posts for select to authenticated
  using ((status = 'open' and expires_at > now()) or author_id = (select auth.uid()) or private.is_admin());
create policy "Requests: the asker and the post's author"
  on public.squad_post_requests for select to authenticated
  using (
    user_id = (select auth.uid())
    or exists (select 1 from public.squad_posts p where p.id = post_id and p.author_id = (select auth.uid()))
  );

create function public.create_squad_post(
  p_mode text, p_region text, p_rank text, p_needed integer, p_roles text[], p_availability text, p_body text, p_days integer
)
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
  if (select count(*) from public.squad_posts where author_id = me and status = 'open' and expires_at > now()) >= 2 then
    raise exception 'too_many_posts' using errcode = 'PT429';
  end if;
  perform private.hit_limit('squad_post', 3, interval '1 day');
  insert into public.squad_posts (author_id, mode, region, rank, needed, roles, availability, body, expires_at)
  values (me, p_mode, p_region, coalesce(p_rank, 'any'), p_needed, coalesce(p_roles, '{}'),
          nullif(btrim(p_availability), ''), nullif(btrim(p_body), ''),
          now() + make_interval(days => least(greatest(coalesce(p_days, 7), 1), 14)))
  returning id into new_id;
  return new_id;
end;
$$;

create function public.close_squad_post(post bigint)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  author uuid;
begin
  update public.squad_posts set status = 'closed'
  where id = post and (author_id = (select auth.uid()) or private.is_admin())
  returning author_id into author;
  if author is null then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if author <> (select auth.uid()) then
    perform private.audit('squad_post.closed', null, author, jsonb_build_object('post', post));
  end if;
end;
$$;

-- Take back a request that hasn't been answered yet.
create function public.cancel_join_request(post bigint)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.squad_post_requests where post_id = post and user_id = (select auth.uid()) and status = 'pending';
$$;

create function public.request_to_join(post bigint, note text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  p public.squad_posts;
begin
  if me is null or not exists (select 1 from public.profiles where id = me) then
    raise exception 'profile_required' using errcode = '42501';
  end if;
  select * into p from public.squad_posts where id = post;
  if p.id is null or p.status <> 'open' or p.expires_at <= now() then
    raise exception 'post_closed' using errcode = 'PT409';
  end if;
  if p.author_id = me then
    raise exception 'own_post' using errcode = 'PT409';
  end if;
  if private.blocked_either(me, p.author_id) then
    raise exception 'blocked' using errcode = 'PT409';
  end if;
  perform private.hit_limit('squad_request', 10, interval '1 hour');
  insert into public.squad_post_requests (post_id, user_id, message) values (post, me, nullif(btrim(note), ''));
end;
$$;

-- The author answers. Accepting makes you friends, so you can message each other.
create function public.answer_join_request(post bigint, player uuid, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if not exists (select 1 from public.squad_posts where id = post and author_id = me) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  update public.squad_post_requests set status = case when accept then 'accepted' else 'declined' end
  where post_id = post and user_id = player and status = 'pending';
  if not found then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
  if accept and not private.blocked_either(me, player) then
    insert into public.friendships (low, high, requested_by, status, accepted_at)
    values (least(me, player), greatest(me, player), me, 'accepted', now())
    on conflict (low, high) do update set status = 'accepted', accepted_at = coalesce(public.friendships.accepted_at, now());
  end if;
end;
$$;

-- The board: open posts, newest first, without players either side blocked.
create function public.squad_board()
returns table (
  id bigint, mode text, region text, rank text, needed integer, roles text[], availability text, body text,
  created_at timestamptz, expires_at timestamptz, status text,
  author text, author_key text, author_tag text, author_avatar text,
  mine boolean, my_request text, pending integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select s.id, s.mode, s.region, s.rank, s.needed, s.roles, s.availability, s.body,
    s.created_at, s.expires_at, s.status,
    p.username, p.username_key, p.clan_tag, p.avatar_id,
    s.author_id = (select auth.uid()),
    (select r.status from public.squad_post_requests r where r.post_id = s.id and r.user_id = (select auth.uid())),
    case when s.author_id = (select auth.uid())
      then (select count(*) from public.squad_post_requests r where r.post_id = s.id and r.status = 'pending')::integer
      else 0 end
  from public.squad_posts s
  join public.profiles p on p.id = s.author_id
  where (select auth.uid()) is not null
    and ((s.status = 'open' and s.expires_at > now()) or s.author_id = (select auth.uid()))
    and not private.blocked_either(s.author_id, (select auth.uid()))
  order by s.author_id = (select auth.uid()) desc, s.created_at desc
  limit 100;
$$;

-- Who asked to join one of my posts.
create function public.squad_requests(post bigint)
returns table (
  user_id uuid, username text, username_key text, avatar_id text, clan_tag text,
  message text, status text, created_at timestamptz
)
language sql
stable
security definer
set search_path = ''
as $$
  select r.user_id, p.username, p.username_key, p.avatar_id, p.clan_tag, r.message, r.status, r.created_at
  from public.squad_post_requests r
  join public.squad_posts s on s.id = r.post_id
  join public.profiles p on p.id = r.user_id
  where r.post_id = post and s.author_id = (select auth.uid())
  order by r.status = 'pending' desc, r.created_at;
$$;

-- Reports for content outside chat (squad posts now; more kinds later).
create table public.content_reports (
  id bigint generated always as identity primary key,
  kind text not null,
  ref bigint not null,
  reporter_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  reason text not null,
  status text not null default 'open',
  created_at timestamptz not null default now(),
  constraint content_reports_kind_check check (kind in ('squad_post')),
  constraint content_reports_reason_check check (reason in ('spam', 'abuse', 'scam', 'misleading', 'other')),
  constraint content_reports_status_check check (status in ('open', 'resolved', 'dismissed')),
  constraint content_reports_once unique (kind, ref, reporter_id)
);
alter table public.content_reports enable row level security;
revoke all on table public.content_reports from public, anon, authenticated;
grant select on table public.content_reports to authenticated;
grant insert (kind, ref, reason) on table public.content_reports to authenticated;
create policy "Admins read reports, players their own"
  on public.content_reports for select to authenticated
  using (private.is_admin() or reporter_id = (select auth.uid()));
create policy "Players report as themselves"
  on public.content_reports for insert to authenticated
  with check (reporter_id = (select auth.uid()) and exists (select 1 from public.squad_posts p where p.id = ref and kind = 'squad_post'));

create function private.limit_content_reports()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user = 'authenticated' then
    perform private.hit_limit('content_report', 10, interval '1 hour');
  end if;
  return new;
end;
$$;
revoke all on function private.limit_content_reports() from public;
create trigger content_reports_limit
  before insert on public.content_reports
  for each row execute function private.limit_content_reports();

-- Squad finder notifications.
alter table public.notifications drop constraint notifications_kind_check;
alter table public.notifications add constraint notifications_kind_check check (kind in (
  'match_5h', 'match_1h', 'room', 'friend_request', 'friend_accepted', 'message',
  'entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled',
  'squad_request', 'squad_answered', 'clan_announcement'
));

create function private.notify_squad_requests()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  p public.squad_posts;
  who public.profiles;
begin
  select * into p from public.squad_posts where id = new.post_id;
  if tg_op = 'INSERT' then
    select * into who from public.profiles where id = new.user_id;
    perform private.notify(p.author_id, 'squad_request', null, 'sq:' || p.id || ':' || new.user_id,
      'Someone wants to join', who.username || ' asked to join your squad post.', '/codm/community/squads');
  elsif new.status <> old.status and new.status in ('accepted', 'declined') then
    select * into who from public.profiles where id = p.author_id;
    perform private.notify(new.user_id, 'squad_answered', null, 'sq:' || p.id,
      case when new.status = 'accepted' then 'You''re in the squad' else 'Squad request declined' end,
      case when new.status = 'accepted' then who.username || ' accepted you. You''re friends now: send them a message.'
           else who.username || ' found other players this time.' end,
      case when new.status = 'accepted' then '/codm/community' else '/codm/community/squads' end);
  end if;
  return new;
end;
$$;
revoke all on function private.notify_squad_requests() from public;
create trigger squad_post_requests_notify
  after insert or update on public.squad_post_requests
  for each row execute function private.notify_squad_requests();

-- 2. Ideas Board -------------------------------------------------------------------
alter table public.ideas drop constraint ideas_status_check;
update public.ideas set status = case status when 'open' then 'submitted' when 'done' then 'released' else status end;
alter table public.ideas alter column status set default 'submitted';
alter table public.ideas
  add constraint ideas_status_check check (status in ('submitted', 'review', 'planned', 'building', 'released', 'declined')),
  add column category text not null default 'other',
  add column status_note text,
  add constraint ideas_category_check check (category in ('tournaments', 'community', 'app', 'games', 'other')),
  add constraint ideas_status_note_check check (status_note is null or (char_length(status_note) between 2 and 200 and private.clean_text(status_note)));
grant insert (category) on table public.ideas to authenticated;
grant update (status_note) on table public.ideas to authenticated;

create table public.idea_comments (
  id bigint generated always as identity primary key,
  idea_id bigint not null references public.ideas (id) on delete cascade,
  user_id uuid not null default auth.uid() references public.profiles (id) on delete cascade,
  body text not null,
  created_at timestamptz not null default now(),
  constraint idea_comments_body_check check (char_length(body) between 2 and 300 and body = btrim(body) and private.clean_text(body))
);
create index idea_comments_idea_idx on public.idea_comments (idea_id, created_at);
alter table public.idea_comments enable row level security;
revoke all on table public.idea_comments from public, anon, authenticated;
grant select on table public.idea_comments to authenticated;
grant insert (idea_id, body) on table public.idea_comments to authenticated;
grant delete on table public.idea_comments to authenticated;
create policy "Signed-in players read comments"
  on public.idea_comments for select to authenticated using (true);
create policy "Players comment as themselves"
  on public.idea_comments for insert to authenticated
  with check (user_id = (select auth.uid()) and not private.is_banned() and exists (select 1 from public.profiles where id = (select auth.uid())));
create policy "Authors and admins delete comments"
  on public.idea_comments for delete to authenticated
  using (user_id = (select auth.uid()) or private.is_admin());

create function private.limit_idea_comments()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if current_user = 'authenticated' then
    perform private.hit_limit('idea_comment', 10, interval '10 minutes');
  end if;
  return new;
end;
$$;
revoke all on function private.limit_idea_comments() from public;
create trigger idea_comments_limit
  before insert on public.idea_comments
  for each row execute function private.limit_idea_comments();

create function private.audit_ideas()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status is distinct from old.status or new.status_note is distinct from old.status_note then
    perform private.audit('idea.status', null, new.user_id,
      jsonb_build_object('idea', new.id, 'status', jsonb_build_array(old.status, new.status)));
  end if;
  return new;
end;
$$;
revoke all on function private.audit_ideas() from public;
create trigger ideas_audit
  after update on public.ideas
  for each row execute function private.audit_ideas();

drop function public.idea_board();
create function public.idea_board()
returns table (
  id bigint, body text, status text, category text, status_note text, created_at timestamptz,
  author text, author_key text, author_tag text, up integer, down integer, my_vote integer, mine boolean, comments integer
)
language sql
stable
security definer
set search_path = ''
as $$
  select i.id, i.body, i.status, i.category, i.status_note, i.created_at, p.username, p.username_key, p.clan_tag,
    (count(v.*) filter (where v.vote = 1))::integer,
    (count(v.*) filter (where v.vote = -1))::integer,
    coalesce(max(v.vote) filter (where v.user_id = (select auth.uid())), 0)::integer,
    i.user_id = (select auth.uid()),
    (select count(*) from public.idea_comments c where c.idea_id = i.id)::integer
  from public.ideas i
  join public.profiles p on p.id = i.user_id
  left join public.idea_votes v on v.idea_id = i.id
  group by i.id, p.username, p.username_key, p.clan_tag
  order by (count(v.*) filter (where v.vote = 1)) - (count(v.*) filter (where v.vote = -1)) desc, i.created_at desc
  limit 200;
$$;
revoke all on function public.idea_board() from public, anon;
grant execute on function public.idea_board() to authenticated;

-- Contributor achievement: planned, being built or released.
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
      from (select i.created_at from public.ideas i where i.user_id = player and i.status in ('planned', 'building', 'released') order by i.created_at limit 1) x;
end;
$$;

-- One idea's comments, oldest first.
create function public.idea_thread(idea bigint)
returns table (id bigint, body text, created_at timestamptz, author text, author_key text, author_tag text, mine boolean)
language sql
stable
security definer
set search_path = ''
as $$
  select c.id, c.body, c.created_at, p.username, p.username_key, p.clan_tag, c.user_id = (select auth.uid())
  from public.idea_comments c
  join public.profiles p on p.id = c.user_id
  where c.idea_id = idea and (select auth.uid()) is not null
  order by c.created_at
  limit 100;
$$;

-- 3. Clan announcements -------------------------------------------------------------
-- In their own table so only people who can read the clan chat (members,
-- admins) see them; the clan list itself is browsable by everyone.
create table public.clan_announcements (
  channel_id uuid primary key references public.chat_channels (id) on delete cascade,
  body text not null,
  posted_by uuid references public.profiles (id) on delete set null,
  posted_at timestamptz not null default now(),
  constraint clan_announcements_body_check check (char_length(body) between 2 and 300 and private.clean_text(body))
);
alter table public.clan_announcements enable row level security;
revoke all on table public.clan_announcements from public, anon, authenticated;
grant select on table public.clan_announcements to authenticated;
create policy "Clan members read their clan's announcement"
  on public.clan_announcements for select to authenticated
  using (private.can_read_channel(channel_id));

create function public.set_clan_announcement(clan uuid, text_body text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  c public.chat_channels;
  msg text := nullif(btrim(text_body), '');
begin
  select * into c from public.chat_channels where id = clan and kind = 'clan';
  if c.id is null or not (c.owner_id = (select auth.uid()) or private.is_admin()) then
    raise exception 'not_allowed' using errcode = '42501';
  end if;
  if not c.approved then
    raise exception 'clan_not_approved' using errcode = 'PT409';
  end if;
  perform private.hit_limit('clan_announcement', 5, interval '1 hour');
  if c.owner_id <> (select auth.uid()) then
    perform private.audit('clan.announcement', null, c.owner_id, jsonb_build_object('clan', c.id, 'cleared', msg is null));
  end if;
  if msg is null then
    delete from public.clan_announcements where channel_id = clan;
  else
    insert into public.clan_announcements (channel_id, body, posted_by) values (clan, msg, (select auth.uid()))
    on conflict (channel_id) do update set body = excluded.body, posted_by = excluded.posted_by, posted_at = now();
  end if;
  if msg is not null then
    perform private.notify(m.user_id, 'clan_announcement', null, 'cl:' || c.id || ':' || extract(epoch from now())::bigint,
      coalesce('[' || c.tag || '] ', '') || c.name, left(msg, 160), '/codm/chat/' || c.slug)
    from public.clan_members m where m.channel_id = clan and m.user_id <> (select auth.uid());
  end if;
end;
$$;

revoke all on function public.create_squad_post(text, text, text, integer, text[], text, text, integer) from public, anon;
revoke all on function public.close_squad_post(bigint) from public, anon;
revoke all on function public.request_to_join(bigint, text) from public, anon;
revoke all on function public.answer_join_request(bigint, uuid, boolean) from public, anon;
revoke all on function public.set_clan_announcement(uuid, text) from public, anon;
grant execute on function public.create_squad_post(text, text, text, integer, text[], text, text, integer) to authenticated;
grant execute on function public.close_squad_post(bigint) to authenticated;
grant execute on function public.request_to_join(bigint, text) to authenticated;
grant execute on function public.answer_join_request(bigint, uuid, boolean) to authenticated;
grant execute on function public.set_clan_announcement(uuid, text) to authenticated;
revoke all on function public.squad_board() from public, anon;
revoke all on function public.cancel_join_request(bigint) from public, anon;
grant execute on function public.cancel_join_request(bigint) to authenticated;
revoke all on function public.squad_requests(bigint) from public, anon;
revoke all on function public.idea_thread(bigint) from public, anon;
grant execute on function public.squad_board() to authenticated;
grant execute on function public.squad_requests(bigint) to authenticated;
grant execute on function public.idea_thread(bigint) to authenticated;
