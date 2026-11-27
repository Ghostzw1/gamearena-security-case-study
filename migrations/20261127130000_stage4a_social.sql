-- Stage 4a: friends, private messages and the in-app notification list
-- (docs/MASTER-DIRECTIVE.md §10.1, §10.2, §12).
--
-- Friends: one row per pair (low < high), pending → accepted. Requests need
-- no block either way; blocking someone ends the friendship. 20 requests an hour.
-- Private messages: a chat channel of kind 'dm' between two friends. It reuses
-- chat (realtime, content filter, rate limit, media, reports). Only the two
-- members can read it: unlike other chats, admins can't, except messages that
-- were reported (through admin_open_reports). Posting needs the friendship to
-- still stand and no block either way.
-- Notifications: the existing table becomes the in-app list too (read_at,
-- unread counts), with social and tournament events written by triggers:
-- friend requests/acceptances, a new private message (once until you read
-- the conversation), registration approved/rejected, dispute answered,
-- check-in open, tournament cancelled. Phone pushes for them follow
-- notification_prefs.social_alerts (on by default).

-- 1. Friends -------------------------------------------------------------------
create table public.friendships (
  low uuid not null references public.profiles (id) on delete cascade,
  high uuid not null references public.profiles (id) on delete cascade,
  requested_by uuid not null references public.profiles (id) on delete cascade,
  status text not null default 'pending',
  created_at timestamptz not null default now(),
  accepted_at timestamptz,
  primary key (low, high),
  constraint friendships_order_check check (low < high),
  constraint friendships_requester_check check (requested_by in (low, high)),
  constraint friendships_status_check check (status in ('pending', 'accepted')),
  constraint friendships_accepted_check check ((status = 'accepted') = (accepted_at is not null))
);
create index friendships_high_idx on public.friendships (high);
alter table public.friendships enable row level security;
revoke all on table public.friendships from public, anon, authenticated;
grant select on table public.friendships to authenticated;
create policy "Players see their own friendships"
  on public.friendships for select to authenticated
  using ((select auth.uid()) in (low, high));

create function private.blocked_either(a uuid, b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.user_blocks
    where (blocker_id = a and blocked_id = b) or (blocker_id = b and blocked_id = a)
  )
$$;

create function private.are_friends(a uuid, b uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.friendships
    where low = least(a, b) and high = greatest(a, b) and status = 'accepted'
  )
$$;

-- Send a request (or accept theirs, if they already asked you).
create function public.send_friend_request(target uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  f public.friendships;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if target is null or target = me or not exists (select 1 from public.profiles where id = target) then
    raise exception 'unknown_player' using errcode = 'PT404';
  end if;
  if not exists (select 1 from public.profiles where id = me) then
    raise exception 'profile_required' using errcode = 'PT409';
  end if;
  if private.blocked_either(me, target) then
    raise exception 'blocked' using errcode = 'PT409';
  end if;
  select * into f from public.friendships where low = least(me, target) and high = greatest(me, target) for update;
  if f.low is not null then
    if f.status = 'accepted' then
      return 'friends';
    end if;
    if f.requested_by = target then
      update public.friendships set status = 'accepted', accepted_at = now() where low = f.low and high = f.high;
      return 'friends';
    end if;
    return 'requested';
  end if;
  perform private.hit_limit('friend_request', 20, interval '1 hour');
  insert into public.friendships (low, high, requested_by) values (least(me, target), greatest(me, target), me);
  return 'requested';
end;
$$;

-- Accept or decline a request someone sent you.
create function public.respond_friend_request(other uuid, accept boolean)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if accept then
    update public.friendships set status = 'accepted', accepted_at = now()
    where low = least(me, other) and high = greatest(me, other) and status = 'pending' and requested_by = other;
  else
    delete from public.friendships
    where low = least(me, other) and high = greatest(me, other) and status = 'pending' and requested_by = other;
  end if;
  if not found then
    raise exception 'no_request' using errcode = 'PT404';
  end if;
end;
$$;

-- Unfriend, or take back your own request.
create function public.remove_friend(other uuid)
returns void
language sql
security definer
set search_path = ''
as $$
  delete from public.friendships
  where low = least((select auth.uid()), other) and high = greatest((select auth.uid()), other);
$$;

-- Blocking ends the friendship.
create function private.unfriend_on_block()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  delete from public.friendships
  where low = least(new.blocker_id, new.blocked_id) and high = greatest(new.blocker_id, new.blocked_id);
  return new;
end;
$$;
revoke all on function private.unfriend_on_block() from public;
create trigger user_blocks_unfriend
  after insert on public.user_blocks
  for each row execute function private.unfriend_on_block();

-- My friends and requests, with their public names.
create function public.my_friends()
returns table (other_id uuid, username text, username_key text, avatar_id text, clan_tag text, status text, incoming boolean, since timestamptz)
language sql
stable
security definer
set search_path = ''
as $$
  select p.id, p.username, p.username_key, p.avatar_id, p.clan_tag, f.status,
    f.status = 'pending' and f.requested_by <> (select auth.uid()),
    coalesce(f.accepted_at, f.created_at)
  from public.friendships f
  join public.profiles p on p.id = case when f.low = (select auth.uid()) then f.high else f.low end
  where (select auth.uid()) in (f.low, f.high)
  order by f.status desc, p.username_key;
$$;

-- 2. Private messages -----------------------------------------------------------
alter table public.chat_channels drop constraint chat_channels_kind_check;
alter table public.chat_channels
  add constraint chat_channels_kind_check check (kind in ('community', 'clan', 'country', 'event', 'dm')),
  add column dm_low uuid references public.profiles (id) on delete cascade,
  add column dm_high uuid references public.profiles (id) on delete cascade;
alter table public.chat_channels add constraint chat_channels_dm_check check (
  (kind = 'dm') = (dm_low is not null and dm_high is not null) and (dm_low is null or dm_low < dm_high)
);
create unique index chat_channels_dm_key on public.chat_channels (dm_low, dm_high) where kind = 'dm';

create table public.dm_reads (
  channel_id uuid not null references public.chat_channels (id) on delete cascade,
  user_id uuid not null references public.profiles (id) on delete cascade,
  last_read_at timestamptz not null default now(),
  primary key (channel_id, user_id)
);
alter table public.dm_reads enable row level security;
revoke all on table public.dm_reads from public, anon, authenticated;
grant select on table public.dm_reads to authenticated;
create policy "Players see their own read marks"
  on public.dm_reads for select to authenticated
  using (user_id = (select auth.uid()));

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
          or (c.kind = 'dm' and (select auth.uid()) in (c.dm_low, c.dm_high))
        )
    )
    -- Admins read every chat except private messages.
    or (private.is_admin() and not exists (select 1 from public.chat_channels c where c.id = target and c.kind = 'dm'));
$$;

-- Posting in a private conversation also needs the friendship to stand and no block.
create or replace function private.can_post(target uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select private.can_read_channel(target)
    and not private.is_banned()
    and exists (select 1 from public.profiles where id = (select auth.uid()))
    and not exists (
      select 1 from public.chat_channels c
      where c.id = target and c.kind = 'dm'
        and (not private.are_friends(c.dm_low, c.dm_high) or private.blocked_either(c.dm_low, c.dm_high))
    );
$$;

-- Private conversations are only listed for their two members.
alter policy "Signed-in players can browse channels and clans" on public.chat_channels
  using (
    (kind <> 'clan' or approved or owner_id = (select auth.uid()) or private.is_admin())
    and (kind <> 'dm' or (select auth.uid()) in (dm_low, dm_high))
  );

-- Open (or create) the conversation with a friend. Returns its address.
create function public.open_dm(other uuid)
returns text
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  found_slug text;
begin
  if me is null then
    raise exception 'sign_in_first' using errcode = '42501';
  end if;
  if not private.are_friends(me, other) then
    raise exception 'friends_only' using errcode = 'PT409';
  end if;
  if private.blocked_either(me, other) then
    raise exception 'blocked' using errcode = 'PT409';
  end if;
  select slug into found_slug from public.chat_channels
  where kind = 'dm' and dm_low = least(me, other) and dm_high = greatest(me, other);
  if found_slug is null then
    insert into public.chat_channels (kind, name, owner_id, dm_low, dm_high, approved)
    values ('dm', 'Direct message', null, least(me, other), greatest(me, other), true)
    returning slug into found_slug;
  end if;
  return found_slug;
end;
$$;

-- My conversations: who, the last message, how many I haven't read.
create function public.my_conversations()
returns table (
  slug text, other_id uuid, username text, username_key text, avatar_id text, clan_tag text,
  last_body text, last_at timestamptz, unread integer, can_reply boolean
)
language sql
stable
security definer
set search_path = ''
as $$
  select c.slug, p.id, p.username, p.username_key, p.avatar_id, p.clan_tag,
    lm.body, lm.created_at,
    (select count(*) from public.chat_messages m
      where m.channel_id = c.id and m.user_id <> (select auth.uid()) and m.deleted_at is null
        and m.created_at > coalesce((select r.last_read_at from public.dm_reads r where r.channel_id = c.id and r.user_id = (select auth.uid())), '-infinity'::timestamptz))::integer,
    private.are_friends(c.dm_low, c.dm_high) and not private.blocked_either(c.dm_low, c.dm_high)
  from public.chat_channels c
  join public.profiles p on p.id = case when c.dm_low = (select auth.uid()) then c.dm_high else c.dm_low end
  left join lateral (
    select m.body, m.created_at from public.chat_messages m
    where m.channel_id = c.id and m.deleted_at is null
      and not exists (select 1 from public.user_blocks b where b.blocker_id = (select auth.uid()) and b.blocked_id = m.user_id)
    order by m.created_at desc limit 1
  ) lm on true
  where c.kind = 'dm' and (select auth.uid()) in (c.dm_low, c.dm_high)
  order by coalesce(lm.created_at, c.created_at) desc;
$$;

-- 3. Notifications: the in-app list ------------------------------------------------
alter table public.notifications
  alter column tournament_id drop not null,
  add column ref text,
  add column read_at timestamptz;
alter table public.notifications drop constraint notifications_kind_check;
alter table public.notifications add constraint notifications_kind_check check (kind in (
  'match_5h', 'match_1h', 'room', 'friend_request', 'friend_accepted', 'message',
  'entry_approved', 'entry_rejected', 'dispute_answered', 'checkin_open', 'event_cancelled'
));
alter table public.notifications drop constraint notifications_url_check;
alter table public.notifications add constraint notifications_url_check check (
  char_length(url) <= 200 and url ~ '^/codm(/[a-z0-9-]+)*(#[a-z0-9-]+)?$'
);
alter table public.notifications add constraint notifications_ref_check check (
  ref is null or (char_length(ref) <= 80 and ref ~ '^[a-z0-9:-]+$')
);
-- Events without a tournament are de-duplicated by their reference.
create unique index notifications_ref_once on public.notifications (user_id, kind, ref) where tournament_id is null;
create index notifications_inbox_idx on public.notifications (user_id, created_at desc);

alter table public.notification_prefs add column social_alerts boolean not null default true;
grant insert (social_alerts), update (social_alerts) on table public.notification_prefs to authenticated;

-- Write one notification. Phone pushes for social events follow the
-- player's social_alerts choice (in-app it always shows).
create function private.notify(p_user uuid, p_kind text, p_tournament uuid, p_ref text, p_title text, p_body text, p_url text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  push boolean := coalesce((select np.social_alerts from public.notification_prefs np where np.user_id = p_user), true);
begin
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
revoke all on function private.notify(uuid, text, uuid, text, text, text, text) from public;

create function private.notify_friendships()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  other uuid;
  who public.profiles;
begin
  if tg_op = 'INSERT' and new.status = 'pending' then
    other := case when new.requested_by = new.low then new.high else new.low end;
    select * into who from public.profiles where id = new.requested_by;
    perform private.notify(other, 'friend_request', null, 'u:' || new.requested_by::text,
      'Friend request', who.username || ' wants to be friends.', '/codm/community');
  elsif tg_op = 'UPDATE' and new.status = 'accepted' and old.status = 'pending' then
    other := case when new.requested_by = new.low then new.high else new.low end;
    select * into who from public.profiles where id = other;
    perform private.notify(new.requested_by, 'friend_accepted', null, 'u:' || other::text,
      'You''re friends now', who.username || ' accepted your request. Say hi!', '/codm/community');
  end if;
  return new;
end;
$$;
revoke all on function private.notify_friendships() from public;
create trigger friendships_notify
  after insert or update on public.friendships
  for each row execute function private.notify_friendships();

-- A new private message: one notification per conversation until it's read.
create function private.notify_dm()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  c public.chat_channels;
  who public.profiles;
  other uuid;
begin
  select * into c from public.chat_channels where id = new.channel_id;
  if c.kind <> 'dm' then
    return new;
  end if;
  other := case when c.dm_low = new.user_id then c.dm_high else c.dm_low end;
  select * into who from public.profiles where id = new.user_id;
  perform private.notify(other, 'message', null, 'c:' || c.id::text,
    'New message', who.username || ' sent you a message.', '/codm/chat/' || c.slug);
  return new;
end;
$$;
revoke all on function private.notify_dm() from public;
create trigger chat_messages_notify_dm
  after insert on public.chat_messages
  for each row execute function private.notify_dm();

-- Reading a conversation: mark it read and clear its notification.
create function public.mark_dm_read(conversation text)
returns void
language plpgsql
security definer
set search_path = ''
as $$
declare
  me uuid := (select auth.uid());
  c public.chat_channels;
begin
  select * into c from public.chat_channels where slug = conversation and kind = 'dm';
  if c.id is null or me is null or me not in (c.dm_low, c.dm_high) then
    raise exception 'unknown_conversation' using errcode = 'PT404';
  end if;
  insert into public.dm_reads (channel_id, user_id, last_read_at) values (c.id, me, now())
  on conflict (channel_id, user_id) do update set last_read_at = excluded.last_read_at;
  delete from public.notifications where user_id = me and kind = 'message' and ref = 'c:' || c.id::text;
end;
$$;

-- Registration decisions, dispute answers, check-in and cancellations.
create function private.notify_entries()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  t public.tournaments;
begin
  if new.status is distinct from old.status and new.status in ('approved', 'rejected') then
    select * into t from public.tournaments where id = new.tournament_id;
    perform private.notify(new.user_id, 'entry_' || new.status, t.id, null,
      private.event_label(t),
      case when new.status = 'approved' then 'You''re in! The host approved your registration.' else 'The host didn''t approve your registration.' end,
      '/codm/tournaments/' || t.slug);
  end if;
  return new;
end;
$$;
revoke all on function private.notify_entries() from public;
create trigger tournament_entries_notify
  after update of status on public.tournament_entries
  for each row execute function private.notify_entries();

create function private.notify_disputes()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
declare
  t public.tournaments;
begin
  if new.status <> 'open' and old.status = 'open' then
    select * into t from public.tournaments where id = new.tournament_id;
    perform private.notify(new.raised_by, 'dispute_answered', null, 'd:' || new.id::text,
      private.event_label(t),
      case when new.status = 'upheld' then 'Your dispute was upheld: ' else 'Your dispute was answered: ' end || left(new.resolution, 120),
      '/codm/tournaments/' || t.slug);
  end if;
  return new;
end;
$$;
revoke all on function private.notify_disputes() from public;
create trigger result_disputes_notify
  after update on public.result_disputes
  for each row execute function private.notify_disputes();

create function private.notify_status()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  if new.status = 'checkin' and old.status is distinct from 'checkin' then
    perform private.notify(e.user_id, 'checkin_open', new.id, null, private.event_label(new),
      'Check-in is open. Tap Check in so the host knows you''re there.', '/codm/tournaments/' || new.slug)
    from public.tournament_entries e where e.tournament_id = new.id and e.status = 'approved';
  elsif new.status = 'cancelled' and old.status is distinct from 'cancelled' then
    perform private.notify(e.user_id, 'event_cancelled', new.id, null, private.event_label(new),
      'This tournament was cancelled by its host.', '/codm/tournaments/' || new.slug)
    from public.tournament_entries e where e.tournament_id = new.id and e.status in ('pending', 'approved');
  end if;
  return new;
end;
$$;
revoke all on function private.notify_status() from public;
create trigger tournaments_notify_status
  after update of status on public.tournaments
  for each row execute function private.notify_status();

-- The list itself.
create function public.mark_notifications_read()
returns void
language sql
security definer
set search_path = ''
as $$
  update public.notifications set read_at = now()
  where user_id = (select auth.uid()) and read_at is null;
$$;

create function public.my_unread_counts()
returns table (notifications integer, messages integer)
language sql
stable
security definer
set search_path = ''
as $$
  select
    (select count(*) from public.notifications n where n.user_id = (select auth.uid()) and n.read_at is null and n.created_at > now() - interval '30 days')::integer,
    (select coalesce(sum(c.unread), 0) from public.my_conversations() c)::integer;
$$;

revoke all on function public.send_friend_request(uuid) from public, anon;
revoke all on function public.respond_friend_request(uuid, boolean) from public, anon;
revoke all on function public.remove_friend(uuid) from public, anon;
revoke all on function public.my_friends() from public, anon;
revoke all on function public.open_dm(uuid) from public, anon;
revoke all on function public.my_conversations() from public, anon;
revoke all on function public.mark_dm_read(text) from public, anon;
revoke all on function public.mark_notifications_read() from public, anon;
revoke all on function public.my_unread_counts() from public, anon;
revoke all on function private.blocked_either(uuid, uuid) from public;
revoke all on function private.are_friends(uuid, uuid) from public;
grant execute on function private.blocked_either(uuid, uuid) to authenticated;
grant execute on function private.are_friends(uuid, uuid) to authenticated;
grant execute on function public.send_friend_request(uuid) to authenticated;
grant execute on function public.respond_friend_request(uuid, boolean) to authenticated;
grant execute on function public.remove_friend(uuid) to authenticated;
grant execute on function public.my_friends() to authenticated;
grant execute on function public.open_dm(uuid) to authenticated;
grant execute on function public.my_conversations() to authenticated;
grant execute on function public.mark_dm_read(text) to authenticated;
grant execute on function public.mark_notifications_read() to authenticated;
grant execute on function public.my_unread_counts() to authenticated;
